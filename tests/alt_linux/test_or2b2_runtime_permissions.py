from __future__ import annotations

from pathlib import Path

import pytest

from alt_deploy.ansible import AnsibleController
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from support.controller_sandbox import make_controller_sandbox
from support.outcomes import PROVEN_OPERATIONAL_OUTCOMES, get_outcome
from support.payloads import provision_request


OR2B2_SCENARIO_IDS = {
    "provision-stage-helper-missing",
    "provision-stage-helper-not-executable",
    "controller-permissions-unhealthy",
    "controller-permissions-repair-root-required",
    "controller-permissions-repair-blocked",
    "controller-permissions-repair-failed",
    "controller-permissions-repaired",
}


def _prepare_validation_boundary(
    tmp_path: Path,
    *,
    helper_mode: int | None,
) -> tuple[AnsibleController, object, Path, Path]:
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.install_fake_ansible_playbook()

    sandbox.settings.private_key_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    sandbox.settings.private_key_file.write_text(
        "test-only-key\n",
        encoding="utf-8",
    )
    sandbox.settings.known_hosts_file.write_text(
        "test-only-host\n",
        encoding="utf-8",
    )

    provision_playbook = (
        sandbox.settings.ansible_project_dir
        / "playbooks"
        / "02-provision-account.yml"
    )
    provision_playbook.parent.mkdir(parents=True, exist_ok=True)
    provision_playbook.write_text("---\n", encoding="utf-8")

    helper = sandbox.settings.job_stage_helper_path
    if helper_mode is not None:
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper.chmod(helper_mode)

    job = JobRepository(sandbox.settings).create(provision_request())
    return (
        AnsibleController(sandbox.settings),
        job,
        helper,
        sandbox.settings.private_key_file,
    )


def test_or2b2_outcomes_are_registered() -> None:
    actual = {
        item.scenario_id for item in PROVEN_OPERATIONAL_OUTCOMES
    }
    assert OR2B2_SCENARIO_IDS <= actual


def test_catalog_contains_twenty_six_proven_outcomes() -> None:
    assert len(PROVEN_OPERATIONAL_OUTCOMES) == 26


def test_or2b2_outcome_contracts_are_exact() -> None:
    expected = {
        "provision-stage-helper-missing": (
            "worker_configuration",
            "provision_not_configured",
            1,
            "failed",
            "connecting",
            False,
            True,
        ),
        "provision-stage-helper-not-executable": (
            "worker_configuration",
            "provision_not_configured",
            1,
            "failed",
            "connecting",
            False,
            True,
        ),
        "controller-permissions-unhealthy": (
            "permission_audit",
            "controller_permissions_unhealthy",
            8,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repair-root-required": (
            "permission_repair_authorization",
            "root_required",
            3,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repair-blocked": (
            "permission_repair_safety",
            "controller_permissions_repair_blocked",
            9,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repair-failed": (
            "permission_repair_execution",
            "controller_permissions_repair_failed",
            10,
            None,
            None,
            False,
            True,
        ),
        "controller-permissions-repaired": (
            "permission_repair",
            None,
            0,
            None,
            None,
            False,
            None,
        ),
    }

    for scenario_id, contract in expected.items():
        outcome = get_outcome(scenario_id)
        assert (
            outcome.boundary,
            outcome.error_code,
            outcome.command_exit_code,
            outcome.job_state,
            outcome.job_stage,
            outcome.assignment_created,
            outcome.retryable,
        ) == contract
        assert outcome.failure_kind is None


def test_stage_helper_validation_reports_missing_only(
    tmp_path: Path,
) -> None:
    controller, job, helper, _ = _prepare_validation_boundary(
        tmp_path,
        helper_mode=None,
    )

    with pytest.raises(ControlError) as caught:
        controller._validate_provision_files(job)

    assert caught.value.code == "provision_not_configured"
    assert caught.value.exit_code == 7
    assert caught.value.details == {
        "missing": [
            {
                "name": "job_stage_helper",
                "path": str(helper),
            }
        ]
    }


def test_stage_helper_validation_reports_not_executable(
    tmp_path: Path,
) -> None:
    controller, job, helper, _ = _prepare_validation_boundary(
        tmp_path,
        helper_mode=0o644,
    )

    with pytest.raises(ControlError) as caught:
        controller._validate_provision_files(job)

    assert caught.value.code == "provision_not_configured"
    assert caught.value.exit_code == 7
    assert caught.value.details == {
        "not_executable": [
            {
                "name": "job_stage_helper",
                "path": str(helper),
            }
        ]
    }


def test_stage_helper_validation_accepts_executable(
    tmp_path: Path,
) -> None:
    controller, job, _, _ = _prepare_validation_boundary(
        tmp_path,
        helper_mode=0o755,
    )

    controller._validate_provision_files(job)


def test_stage_helper_validation_reports_mixed_nonempty_keys(
    tmp_path: Path,
) -> None:
    controller, job, helper, private_key = _prepare_validation_boundary(
        tmp_path,
        helper_mode=0o644,
    )
    private_key.unlink()

    with pytest.raises(ControlError) as caught:
        controller._validate_provision_files(job)

    assert caught.value.details == {
        "missing": [
            {
                "name": "private_key",
                "path": str(private_key),
            }
        ],
        "not_executable": [
            {
                "name": "job_stage_helper",
                "path": str(helper),
            }
        ],
    }
