from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import TextIO

import pytest

from alt_deploy.ansible import AnsibleController
from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json
from alt_deploy.models import JobRecord
from alt_deploy.worker import run_job
from support.controller_sandbox import (
    ControllerSandbox,
    make_controller_sandbox,
)
from support.outcomes import PROVEN_OPERATIONAL_OUTCOMES, get_outcome
from support.payloads import (
    TEST_MACHINE_UUID,
    provision_request,
    successful_provision_result,
)


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
) -> tuple[
    ControllerSandbox,
    AnsibleController,
    JobRecord,
    Path,
    Path,
    Path,
]:
    sandbox = make_controller_sandbox(tmp_path)
    registration_path = sandbox.register_machine(preflight_ok=True)
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
        sandbox,
        AnsibleController(sandbox.settings),
        job,
        helper,
        sandbox.settings.private_key_file,
        registration_path,
    )


def _launch_job(sandbox: ControllerSandbox, job: JobRecord) -> None:
    JobStageManager(sandbox.settings).advance(
        job.job_id,
        "launching",
        updates={
            "systemd_unit": f"alt-provision-{job.job_id}.service",
        },
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
    _, controller, job, helper, _, _ = _prepare_validation_boundary(
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
    _, controller, job, helper, _, _ = _prepare_validation_boundary(
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
    _, controller, job, _, _, _ = _prepare_validation_boundary(
        tmp_path,
        helper_mode=0o755,
    )

    controller._validate_provision_files(job)


def test_stage_helper_validation_reports_mixed_nonempty_keys(
    tmp_path: Path,
) -> None:
    _, controller, job, helper, private_key, _ = (
        _prepare_validation_boundary(
            tmp_path,
            helper_mode=0o644,
        )
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


@pytest.mark.parametrize(
    ("scenario_id", "helper_mode"),
    [
        ("provision-stage-helper-missing", None),
        ("provision-stage-helper-not-executable", 0o644),
    ],
)
def test_worker_stage_helper_failure_preserves_connecting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario_id: str,
    helper_mode: int | None,
) -> None:
    outcome = get_outcome(scenario_id)
    sandbox, controller, job, _, _, registration_path = (
        _prepare_validation_boundary(
            tmp_path,
            helper_mode=helper_mode,
        )
    )
    jobs = JobRepository(sandbox.settings)
    assignments = AssignmentRepository(sandbox.settings)
    _launch_job(sandbox, job)
    registration_before = registration_path.read_bytes()

    def unexpected_subprocess(*args: object, **kwargs: object) -> object:
        pytest.fail("Ansible subprocess must not run")

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        unexpected_subprocess,
    )

    result_code = run_job(
        job.job_id,
        sandbox.settings,
        controller,
    )
    stored = jobs.get(job.job_id)

    assert result_code == outcome.command_exit_code
    assert stored.state == outcome.job_state
    assert stored.stage == outcome.job_stage
    assert stored.status["finished_at"]
    assert stored.status["error"].startswith(
        "provision_not_configured:"
    )
    assert assignments.get(TEST_MACHINE_UUID) is None
    assert not (stored.job_dir / "result.json").exists()
    assert registration_path.read_bytes() == registration_before


def test_retry_after_helper_fix_uses_real_controller_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox, first_controller, first, helper, _, _ = (
        _prepare_validation_boundary(
            tmp_path,
            helper_mode=0o644,
        )
    )
    jobs = JobRepository(sandbox.settings)
    assignments = AssignmentRepository(sandbox.settings)
    _launch_job(sandbox, first)

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        lambda *args, **kwargs: pytest.fail(
            "Ansible subprocess must not run before helper repair"
        ),
    )
    assert run_job(
        first.job_id,
        sandbox.settings,
        first_controller,
    ) == 1

    helper.chmod(0o755)
    second = jobs.create(provision_request())
    _launch_job(sandbox, second)

    def fake_run(
        command: list[str],
        *,
        shell: bool,
        text: bool,
        stdout: TextIO,
        stderr: int,
        timeout: int,
        check: bool,
        cwd: Path,
        env: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        assert os.access(helper, os.X_OK)
        result_argument = next(
            item
            for item in command
            if item.startswith("provision_result_file=")
        )
        result_path = Path(result_argument.split("=", 1)[1])
        atomic_write_json(
            result_path,
            successful_provision_result(job_id=second.job_id),
        )
        manager = JobStageManager(sandbox.settings)
        for stage in (
            "identity",
            "employee",
            "login_screen",
            "verifying",
        ):
            manager.advance(second.job_id, stage)
        stdout.write("PLAY RECAP\n")
        stdout.flush()
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(
        "alt_deploy.ansible.subprocess.run",
        fake_run,
    )

    assert run_job(
        second.job_id,
        sandbox.settings,
        AnsibleController(sandbox.settings),
    ) == 0

    stored_first = jobs.get(first.job_id)
    stored_second = jobs.get(second.job_id)
    assignment = assignments.get(TEST_MACHINE_UUID)

    assert stored_first.state == "failed"
    assert stored_first.stage == "connecting"
    assert stored_second.state == "successful"
    assert stored_second.stage == "complete"
    assert assignment is not None
    assert assignment["job_id"] == second.job_id
