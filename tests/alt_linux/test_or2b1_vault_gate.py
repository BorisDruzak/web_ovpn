from __future__ import annotations

import os
import pwd
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.jsonio import read_json
from alt_deploy.vault import VaultHealthChecker
from support.controller_sandbox import make_controller_sandbox
from support.payloads import provision_request


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

    assert checker._build_checks() == {
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
