from __future__ import annotations

from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import read_json
from alt_deploy.vault import VaultHealthChecker
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.outcomes import get_outcome
from support.payloads import TEST_MACHINE_UUID

PREVIEW_CASES = (
    ("provision-vault-file-missing", "vault_file_missing"),
    (
        "provision-vault-password-file-missing",
        "password_file_missing",
    ),
    ("provision-vault-header-invalid", "invalid_header"),
    ("provision-vault-decrypt-failed", "decrypt_nonzero"),
    ("provision-vault-variable-missing", "variable_missing"),
    ("provision-vault-yescrypt-invalid", "yescrypt_invalid"),
    ("provision-vault-mode-invalid", "vault_mode_invalid"),
    ("provision-vault-owner-invalid", "vault_owner_invalid"),
)

START_CASES = (
    "decrypt_nonzero",
    "vault_mode_invalid",
    "vault_owner_invalid",
)


def _apply_failure_case(
    monkeypatch: pytest.MonkeyPatch,
    *,
    case: str,
    sandbox,
    assets: dict[str, Path],
) -> None:
    if case == "vault_file_missing":
        assets["vault_file"].unlink()
    elif case == "password_file_missing":
        assets["password_file"].unlink()
    elif case == "invalid_header":
        assets["vault_file"].write_text(
            "not-an-ansible-vault\n",
            encoding="utf-8",
        )
    elif case == "decrypt_nonzero":
        assets["ansible_vault"].write_text(
            "#!/bin/sh\nprintf '%s\\n' 'hidden-decrypt-error' >&2\nexit 3\n",
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
    elif case == "vault_owner_invalid":
        original_owned_by = VaultHealthChecker._owned_by

        def owned_by(path: Path, expected_uid: int | None) -> bool:
            if path == assets["vault_file"]:
                return False
            return original_owned_by(path, expected_uid)

        monkeypatch.setattr(
            VaultHealthChecker,
            "_owned_by",
            staticmethod(owned_by),
        )
    else:
        raise AssertionError(f"Unhandled test case: {case}")


@pytest.mark.parametrize(("scenario_id", "case"), PREVIEW_CASES)
def test_preview_uses_same_vault_health_matrix_and_does_not_mutate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario_id: str,
    case: str,
) -> None:
    outcome = get_outcome(scenario_id)
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()
    request_path = sandbox.write_provision_request()
    registration_path = sandbox.register_machine(preflight_ok=True)
    registration_before = read_json(registration_path)

    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_VAULT",
        str(assets["ansible_vault"]),
    )
    _apply_failure_case(
        monkeypatch,
        case=case,
        sandbox=sandbox,
        assets=assets,
    )

    vault_result = run_json_cli(
        ["vault", "check"],
        settings=sandbox.settings,
    )
    preview_result = run_json_cli(
        [
            "provision",
            "preview",
            TEST_MACHINE_UUID,
            "--vars-file",
            str(request_path),
        ],
        settings=sandbox.settings,
    )

    vault_checks = vault_result.payload["error"]["details"]["checks"]

    assert preview_result.exit_code == outcome.command_exit_code
    assert preview_result.payload["error"]["code"] == outcome.error_code
    assert preview_result.payload["error"]["details"]["checks"] == (
        vault_checks
    )

    details = preview_result.payload["error"]["details"]
    if case == "vault_file_missing":
        assert details["missing"] == [str(assets["vault_file"])]
        assert "path" not in details
    elif case == "password_file_missing":
        assert details["missing"] == [str(assets["password_file"])]
        assert "path" not in details
    elif case == "invalid_header":
        assert details["path"] == str(assets["vault_file"])
        assert "missing" not in details
    else:
        assert "missing" not in details
        assert "path" not in details

    assert read_json(registration_path) == registration_before
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None

    serialized = preview_result.stdout + preview_result.stderr
    for forbidden in (
        "test-only-passphrase",
        "$y$test-only-hash",
        "vault_employee_password_hash",
        "hidden-decrypt-error",
        "not-yescrypt",
    ):
        assert forbidden not in serialized


@pytest.mark.parametrize("case", START_CASES)
def test_start_vault_failure_occurs_before_job_and_launcher(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()
    request_path = sandbox.write_provision_request()
    registration_path = sandbox.register_machine(preflight_ok=True)
    registration_before = read_json(registration_path)

    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_VAULT",
        str(assets["ansible_vault"]),
    )
    monkeypatch.setattr("alt_deploy.provision.os.geteuid", lambda: 0)

    def forbidden_launch(self, job_id: str) -> str:
        raise AssertionError("launcher must not be called")

    monkeypatch.setattr(
        "alt_deploy.provision.SystemdLauncher.launch",
        forbidden_launch,
    )
    _apply_failure_case(
        monkeypatch,
        case=case,
        sandbox=sandbox,
        assets=assets,
    )

    result = run_json_cli(
        [
            "provision",
            "start",
            TEST_MACHINE_UUID,
            "--vars-file",
            str(request_path),
        ],
        settings=sandbox.settings,
    )

    assert result.exit_code == 4
    assert result.payload["error"]["code"] == "vault_not_configured"
    assert read_json(registration_path) == registration_before
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None


def test_preview_is_retryable_after_yescrypt_is_corrected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    assets = sandbox.configure_vault_boundary()
    request_path = sandbox.write_provision_request()
    sandbox.register_machine(preflight_ok=True)

    monkeypatch.setenv(
        "ALT_DEPLOY_ANSIBLE_VAULT",
        str(assets["ansible_vault"]),
    )
    _apply_failure_case(
        monkeypatch,
        case="yescrypt_invalid",
        sandbox=sandbox,
        assets=assets,
    )

    failed = run_json_cli(
        [
            "provision",
            "preview",
            TEST_MACHINE_UUID,
            "--vars-file",
            str(request_path),
        ],
        settings=sandbox.settings,
    )

    assets["ansible_vault"].write_text(
        (
            "#!/bin/sh\n"
            "printf '%s\\n' "
            "\"vault_employee_password_hash: '\\$y\\$corrected'\"\n"
        ),
        encoding="utf-8",
    )

    succeeded = run_json_cli(
        [
            "provision",
            "preview",
            TEST_MACHINE_UUID,
            "--vars-file",
            str(request_path),
        ],
        settings=sandbox.settings,
    )

    assert failed.exit_code == 4
    assert failed.payload["error"]["code"] == "vault_not_configured"
    assert succeeded.exit_code == 0
    assert succeeded.payload["status"] == "ok"
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None
