from __future__ import annotations

import os
import pwd
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.jsonio import read_json
from alt_deploy.vault import VaultHealthChecker
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.payloads import provision_request

ALL_HEALTHY_CHECKS = {
    "vault_file_exists": True,
    "password_file_exists": True,
    "vault_file_owner": True,
    "password_file_owner": True,
    "vault_file_mode": True,
    "password_file_mode": True,
    "vault_header": True,
    "decryptable": True,
    "variable_present": True,
    "yescrypt_format": True,
}


def _healthy_checker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[VaultHealthChecker, dict[str, Path]]:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()
    settings = replace(
        sandbox.settings,
        service_user=pwd.getpwuid(os.getuid()).pw_name,
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_VAULT",
        str(assets["ansible_vault"]),
    )
    return VaultHealthChecker(settings), assets


def _expected_checks(*false_keys: str) -> dict[str, bool]:
    checks = dict(ALL_HEALTHY_CHECKS)
    for key in false_keys:
        checks[key] = False
    return checks


def test_sandbox_configures_vault_boundary(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()

    assert set(assets) == {
        "vault_file",
        "password_file",
        "ansible_vault",
    }
    assert assets["vault_file"].read_text(encoding="utf-8").startswith(
        "$ANSIBLE_VAULT;"
    )
    assert stat.S_IMODE(assets["vault_file"].stat().st_mode) == 0o600
    assert stat.S_IMODE(assets["password_file"].stat().st_mode) == 0o600
    assert assets["ansible_vault"].stat().st_mode & 0o111

    for path in assets.values():
        path.relative_to(sandbox.root)
        assert path.is_file()


def test_sandbox_writes_provision_request(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    request_path = sandbox.write_provision_request()

    assert request_path.relative_to(sandbox.root)
    assert read_json(request_path) == provision_request()


def test_healthy_vault_builds_all_true_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    checker, _ = _healthy_checker(monkeypatch, tmp_path)

    assert checker._build_checks() == ALL_HEALTHY_CHECKS


def test_vault_checks_do_not_depend_on_caller_euid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    checker, _ = _healthy_checker(monkeypatch, tmp_path)
    expected = checker._build_checks()

    monkeypatch.setattr(
        "alt_deploy.vault.os.geteuid",
        lambda: os.getuid() + 10000,
    )

    assert checker._build_checks() == expected


def test_missing_service_user_fails_owner_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    checker, _ = _healthy_checker(monkeypatch, tmp_path)
    checker = VaultHealthChecker(
        replace(
            checker.settings,
            service_user="or2b1-user-does-not-exist",
        )
    )

    checks = checker._build_checks()

    assert checks["vault_file_owner"] is False
    assert checks["password_file_owner"] is False
    assert checks["decryptable"] is False

    with pytest.raises(ControlError) as exc:
        checker.check()

    assert exc.value.code == "vault_unhealthy"
    assert exc.value.details["checks"] == checks


def test_invalid_mode_prevents_decrypt_attempt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    checker, assets = _healthy_checker(monkeypatch, tmp_path)
    assets["vault_file"].chmod(0o644)
    called = False

    def fake_decrypt() -> str:
        nonlocal called
        called = True
        return "vault_employee_password_hash: '$y$must-not-be-read'"

    monkeypatch.setattr(checker, "_decrypt", fake_decrypt)

    checks = checker._build_checks()

    assert called is False
    assert checks["vault_file_mode"] is False
    assert checks["decryptable"] is False
    assert checks["variable_present"] is False
    assert checks["yescrypt_format"] is False


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        (
            "vault_file_missing",
            _expected_checks(
                "vault_file_exists",
                "vault_file_owner",
                "vault_file_mode",
                "vault_header",
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "password_file_missing",
            _expected_checks(
                "password_file_exists",
                "password_file_owner",
                "password_file_mode",
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "invalid_header",
            _expected_checks(
                "vault_header",
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "decrypt_unavailable",
            _expected_checks(
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "decrypt_timeout",
            _expected_checks(
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "decrypt_nonzero",
            _expected_checks(
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "variable_missing",
            _expected_checks(
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "yescrypt_invalid",
            _expected_checks("yescrypt_format"),
        ),
        (
            "vault_mode_invalid",
            _expected_checks(
                "vault_file_mode",
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "password_mode_invalid",
            _expected_checks(
                "password_file_mode",
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "vault_owner_invalid",
            _expected_checks(
                "vault_file_owner",
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
        (
            "password_owner_invalid",
            _expected_checks(
                "password_file_owner",
                "decryptable",
                "variable_present",
                "yescrypt_format",
            ),
        ),
    ],
)
def test_vault_check_matrix_is_safe_and_exact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
    expected: dict[str, bool],
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()
    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_VAULT",
        str(assets["ansible_vault"]),
    )

    if case == "vault_file_missing":
        assets["vault_file"].unlink()
    elif case == "password_file_missing":
        assets["password_file"].unlink()
    elif case == "invalid_header":
        assets["vault_file"].write_text(
            "not-an-ansible-vault\n",
            encoding="utf-8",
        )
    elif case == "decrypt_unavailable":
        monkeypatch.setenv(
            "ALT_DEPLOY_ANSIBLE_VAULT",
            str(sandbox.root / "bin" / "missing-ansible-vault"),
        )
    elif case == "decrypt_timeout":
        def timeout_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        monkeypatch.setattr(
            "alt_deploy.vault.subprocess.run",
            timeout_run,
        )
    elif case == "decrypt_nonzero":
        assets["ansible_vault"].write_text(
            (
                "#!/bin/sh\n"
                "printf '%s\\n' 'decrypt-stderr-marker' >&2\n"
                "exit 3\n"
            ),
            encoding="utf-8",
        )
    elif case == "variable_missing":
        assets["ansible_vault"].write_text(
            "#!/bin/sh\nprintf '%s\\n' 'other_variable: value'\n",
            encoding="utf-8",
        )
    elif case == "yescrypt_invalid":
        assets["ansible_vault"].write_text(
            (
                "#!/bin/sh\n"
                "printf '%s\\n' "
                "\"vault_employee_password_hash: 'not-yescrypt'\"\n"
            ),
            encoding="utf-8",
        )
    elif case == "vault_mode_invalid":
        assets["vault_file"].chmod(0o644)
    elif case == "password_mode_invalid":
        assets["password_file"].chmod(0o644)
    elif case in {"vault_owner_invalid", "password_owner_invalid"}:
        original_owned_by = VaultHealthChecker._owned_by
        invalid_path = assets[
            "vault_file"
            if case == "vault_owner_invalid"
            else "password_file"
        ]

        def owned_by(path: Path, expected_uid: int | None) -> bool:
            if path == invalid_path:
                return False
            return original_owned_by(path, expected_uid)

        monkeypatch.setattr(
            VaultHealthChecker,
            "_owned_by",
            staticmethod(owned_by),
        )
    else:
        raise AssertionError(f"Unhandled test case: {case}")

    result = run_json_cli(
        ["vault", "check"],
        settings=sandbox.settings,
    )

    assert result.exit_code == 7
    assert result.payload["error"]["code"] == "vault_unhealthy"
    assert result.payload["error"]["details"]["checks"] == expected

    serialized = result.stdout + result.stderr
    for forbidden in (
        "test-only-passphrase",
        "$y$test-only-hash",
        "vault_employee_password_hash",
        "decrypt-stderr-marker",
        "not-yescrypt",
    ):
        assert forbidden not in serialized
