from __future__ import annotations

import re
from dataclasses import asdict
from pathlib import Path

import pytest

from alt_deploy.job_stages import CANONICAL_STAGES
from alt_deploy.jsonio import read_json
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.outcomes import PROVEN_OPERATIONAL_OUTCOMES, get_outcome
from support.payloads import (
    SECOND_TEST_MACHINE_UUID,
    TEST_MACHINE_UUID,
    assignment_payload,
    machine_registration_payload,
    provision_request,
    successful_provision_result,
)

EXPECTED_SCENARIO_IDS = {
    "provision-start-root-required",
    "provision-start-launch-failed",
    "reconcile-worker-not-started-created",
    "reconcile-worker-lost-employee",
    "reconcile-result-recovered",
    "preflight-ssh-timeout",
    "preflight-ssh-unreachable",
    "preflight-ssh-host-key-mismatch",
    "preflight-ssh-authentication-failed",
    "preflight-sudo-unavailable",
    "preflight-ansible-failed",
    "provision-vault-file-missing",
    "provision-vault-password-file-missing",
    "provision-vault-header-invalid",
    "provision-vault-decrypt-failed",
    "provision-vault-variable-missing",
    "provision-vault-yescrypt-invalid",
    "provision-vault-mode-invalid",
    "provision-vault-owner-invalid",
    "provision-stage-helper-missing",
    "provision-stage-helper-not-executable",
    "controller-permissions-unhealthy",
    "controller-permissions-repair-root-required",
    "controller-permissions-repair-blocked",
    "controller-permissions-repair-failed",
    "controller-permissions-repaired",
}

PREFLIGHT_FAILURE_KINDS = {
    "ssh_timeout",
    "ssh_unreachable",
    "ssh_host_key_mismatch",
    "ssh_authentication_failed",
    "sudo_unavailable",
    "ansible_failed",
}


def test_payload_factories_return_independent_mappings() -> None:
    first = provision_request()
    second = provision_request()

    assert first == second
    assert first is not second
    first["employee_login"] = "changed"
    assert second["employee_login"] == "i-ivanov"


def test_payload_factories_use_test_identifiers() -> None:
    assert machine_registration_payload()["uuid"] == TEST_MACHINE_UUID
    assert provision_request()["machine_uuid"] == TEST_MACHINE_UUID
    assert assignment_payload(job_id="job-test")["machine_uuid"] == (
        TEST_MACHINE_UUID
    )
    assert successful_provision_result(
        job_id="job-test"
    )["machine_uuid"] == TEST_MACHINE_UUID
    assert SECOND_TEST_MACHINE_UUID != TEST_MACHINE_UUID


def test_successful_result_has_complete_verification_contract() -> None:
    result = successful_provision_result(job_id="job-test")

    assert result["verification"] == {
        "hostname": True,
        "employee_exists": True,
        "employee_not_wheel": True,
        "employee_no_sudo": True,
        "ansible_sudo": True,
        "lightdm_hides_ansible": True,
        "lightdm_shows_employee": True,
        "lightdm_autologin_disabled": True,
    }


def test_controller_sandbox_keeps_paths_under_root(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    paths = (
        sandbox.settings.registration_root,
        sandbox.settings.state_root,
        sandbox.settings.jobs_dir,
        sandbox.settings.assignments_dir,
        sandbox.settings.lock_file,
        sandbox.settings.ansible_project_dir,
        sandbox.settings.known_hosts_file,
        sandbox.settings.private_key_file,
        sandbox.settings.ansible_playbook_path,
        sandbox.settings.systemd_run_path,
        sandbox.settings.worker_path,
        sandbox.settings.job_stage_helper_path,
        sandbox.settings.workstationctl_path,
    )

    for path in paths:
        path.relative_to(sandbox.root)


def test_controller_sandbox_registers_machine(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    path = sandbox.register_machine(state="ready", preflight_ok=True)
    payload = read_json(path)

    assert path.parent.name == "ready"
    assert payload["status"] == "awaiting_assignment"
    assert payload["preflight"]["status"] == "ok"


def test_controller_sandbox_installs_requested_assets(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)

    assert not sandbox.settings.job_stage_helper_path.exists()
    assert not sandbox.settings.ansible_playbook_path.exists()

    sandbox.install_fake_stage_helper()
    sandbox.install_fake_ansible_playbook()
    vault_file, password_file = sandbox.configure_fake_vault()

    assert sandbox.settings.job_stage_helper_path.stat().st_mode & 0o111
    assert sandbox.settings.ansible_playbook_path.stat().st_mode & 0o111
    assert vault_file.read_text(encoding="utf-8").startswith(
        "$ANSIBLE_VAULT;"
    )
    assert password_file.stat().st_mode & 0o077 == 0


def test_run_json_cli_captures_success_payload(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.register_machine()

    result = run_json_cli(
        ["machines", "list"],
        settings=sandbox.settings,
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.payload["status"] == "ok"
    assert result.payload["machines"][0]["uuid"] == TEST_MACHINE_UUID


def test_run_json_cli_preserves_error_exit_code(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    result = run_json_cli(
        [
            "machines",
            "show",
            "00000000-0000-0000-0000-000000000000",
        ],
        settings=sandbox.settings,
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert result.payload["error"]["code"] == "machine_not_found"


def test_proven_outcome_catalog_has_exact_scenarios() -> None:
    assert {
        item.scenario_id for item in PROVEN_OPERATIONAL_OUTCOMES
    } == EXPECTED_SCENARIO_IDS


def test_catalog_contains_twenty_six_proven_outcomes() -> None:
    assert len(PROVEN_OPERATIONAL_OUTCOMES) == 26


def test_proven_outcome_catalog_is_consistent() -> None:
    scenario_ids = [
        item.scenario_id for item in PROVEN_OPERATIONAL_OUTCOMES
    ]
    assert len(scenario_ids) == len(set(scenario_ids))

    for item in PROVEN_OPERATIONAL_OUTCOMES:
        assert re.fullmatch(
            r"[a-z0-9]+(?:-[a-z0-9]+)*",
            item.scenario_id,
        )
        assert item.boundary in {
            "authorization",
            "launcher",
            "reconciliation",
            "result_recovery",
            "preflight",
            "vault_gate",
            "worker_configuration",
            "permission_audit",
            "permission_repair_authorization",
            "permission_repair_safety",
            "permission_repair_execution",
            "permission_repair",
        }
        assert item.job_state in {
            None,
            "queued",
            "running",
            "successful",
            "failed",
        }
        assert item.job_stage in {None, *CANONICAL_STAGES}
        assert item.required_evidence
        assert len(item.required_evidence) == len(
            set(item.required_evidence)
        )

        if item.job_state == "successful":
            assert item.job_stage == "complete"
        if item.job_state == "failed":
            assert item.job_stage != "complete"
            assert item.assignment_created is False

        if item.boundary == "preflight":
            assert item.error_code == "preflight_failed"
            assert item.command_exit_code == 5
            assert item.job_state is None
            assert item.job_stage is None
            assert item.assignment_created is False
            assert item.retryable is True
            assert item.failure_kind in PREFLIGHT_FAILURE_KINDS
        elif item.boundary == "vault_gate":
            assert item.error_code == "vault_not_configured"
            assert item.command_exit_code == 4
            assert item.job_state is None
            assert item.job_stage is None
            assert item.assignment_created is False
            assert item.retryable is True
            assert item.failure_kind is None
        elif item.boundary == "worker_configuration":
            assert item.error_code == "provision_not_configured"
            assert item.command_exit_code == 1
            assert item.job_state == "failed"
            assert item.job_stage == "connecting"
            assert item.assignment_created is False
            assert item.retryable is True
            assert item.failure_kind is None
        elif item.boundary in {
            "permission_audit",
            "permission_repair_authorization",
            "permission_repair_safety",
            "permission_repair_execution",
            "permission_repair",
        }:
            expected = {
                "permission_audit": (
                    "controller_permissions_unhealthy",
                    8,
                    True,
                ),
                "permission_repair_authorization": (
                    "root_required",
                    3,
                    True,
                ),
                "permission_repair_safety": (
                    "controller_permissions_repair_blocked",
                    9,
                    True,
                ),
                "permission_repair_execution": (
                    "controller_permissions_repair_failed",
                    10,
                    True,
                ),
                "permission_repair": (None, 0, None),
            }
            error_code, exit_code, retryable = expected[item.boundary]
            assert item.error_code == error_code
            assert item.command_exit_code == exit_code
            assert item.job_state is None
            assert item.job_stage is None
            assert item.assignment_created is False
            assert item.retryable is retryable
            assert item.failure_kind is None
        else:
            assert item.failure_kind is None


def test_preflight_outcomes_have_expected_failure_kinds() -> None:
    expected = {
        "preflight-ssh-timeout": "ssh_timeout",
        "preflight-ssh-unreachable": "ssh_unreachable",
        "preflight-ssh-host-key-mismatch": "ssh_host_key_mismatch",
        "preflight-ssh-authentication-failed": (
            "ssh_authentication_failed"
        ),
        "preflight-sudo-unavailable": "sudo_unavailable",
        "preflight-ansible-failed": "ansible_failed",
    }

    assert {
        scenario_id: get_outcome(scenario_id).failure_kind
        for scenario_id in expected
    } == expected


def test_outcome_metadata_contains_no_secret_names() -> None:
    serialized = repr(
        [asdict(item) for item in PROVEN_OPERATIONAL_OUTCOMES]
    ).lower()

    for forbidden in (
        "password_value",
        "password_content",
        "private_key",
        "vault_employee_password_hash",
        "secret_value",
        "api_token",
    ):
        assert forbidden not in serialized


def test_get_outcome_fails_closed() -> None:
    with pytest.raises(KeyError, match="unknown-scenario"):
        get_outcome("unknown-scenario")
