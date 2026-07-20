from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json
from alt_deploy.provision import ProvisionPlanner, ProvisionRequest
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.outcomes import get_outcome
from support.payloads import (
    TEST_MACHINE_UUID,
    provision_request,
    successful_provision_result,
)


class FailingLauncher:
    def launch(self, job_id: str) -> str:
        raise ControlError(
            code="job_launch_failed",
            message="Unable to launch transient provision service",
            exit_code=6,
            details={"stderr": "systemd-run failed"},
        )


def _systemctl_result(
    command,
    *,
    unit_name: str,
    load_state: str,
    active_state: str,
    sub_state: str,
):
    assert command == [
        "/usr/bin/systemctl",
        "show",
        unit_name,
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--no-pager",
    ]
    return subprocess.CompletedProcess(
        command,
        0,
        stdout=(
            f"LoadState={load_state}\n"
            f"ActiveState={active_state}\n"
            f"SubState={sub_state}\n"
        ),
        stderr="",
    )


def _advance_to_stage(
    settings,
    job_id: str,
    target: str,
    *,
    unit_name: str | None = None,
):
    manager = JobStageManager(settings)

    for stage in (
        "launching",
        "validating",
        "connecting",
        "identity",
        "employee",
        "login_screen",
        "verifying",
        "recording",
    ):
        current = manager.jobs.get(job_id)
        if current.stage == target:
            return current

        updates = None
        if stage == "launching" and unit_name is not None:
            updates = {"systemd_unit": unit_name}
        elif stage == "validating":
            updates = {
                "state": "running",
                "started_at": current.updated_at,
            }

        manager.advance(job_id, stage, updates=updates)
        if stage == target:
            return manager.jobs.get(job_id)

    raise AssertionError(f"Unable to advance {job_id} to {target}")


def test_or1_provision_start_requires_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = get_outcome("provision-start-root-required")
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.install_fake_stage_helper()
    sandbox.configure_fake_vault()
    sandbox.register_machine(preflight_ok=True)

    request_path = tmp_path / "request.json"
    request_path.write_text(
        json.dumps(provision_request()),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 1000,
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

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["error"]["code"] == outcome.error_code
    assert JobRepository(sandbox.settings).list() == []
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None


def test_or1_launch_failure_is_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = get_outcome("provision-start-launch-failed")
    sandbox = make_controller_sandbox(tmp_path)
    sandbox.install_fake_stage_helper()
    sandbox.configure_fake_vault()
    sandbox.register_machine(preflight_ok=True)

    monkeypatch.setattr(
        "alt_deploy.provision.os.geteuid",
        lambda: 0,
    )
    monkeypatch.setattr(
        "alt_deploy.provision.os.chown",
        lambda path, uid, gid: None,
    )

    request = ProvisionRequest.from_mapping(
        provision_request(),
        expected_uuid=TEST_MACHINE_UUID,
    )
    planner = ProvisionPlanner(
        sandbox.settings,
        launcher=FailingLauncher(),
    )

    with pytest.raises(ControlError) as exc:
        planner.start(TEST_MACHINE_UUID, request)

    assert exc.value.code == outcome.error_code
    assert exc.value.exit_code == outcome.command_exit_code

    jobs = JobRepository(sandbox.settings).list()
    assert len(jobs) == 1
    assert jobs[0].state == outcome.job_state
    assert jobs[0].stage == outcome.job_stage
    assert [
        item["stage"] for item in jobs[0].status["stage_history"]
    ] == ["created", "launching"]
    assert jobs[0].status["finished_at"]
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is None


def test_or1_reconcile_marks_missing_running_worker_failed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("reconcile-worker-lost-employee")
    sandbox = make_controller_sandbox(tmp_path)
    settings = sandbox.settings
    jobs = JobRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    running = _advance_to_stage(
        settings,
        created.job_id,
        "employee",
        unit_name=unit_name,
    )

    def fake_systemctl(
        command,
        *,
        shell,
        text,
        capture_output,
        timeout,
        check,
    ):
        assert shell is False
        assert text is True
        assert capture_output is True
        assert timeout == 15
        assert check is False
        return _systemctl_result(
            command,
            unit_name=unit_name,
            load_state="not-found",
            active_state="inactive",
            sub_state="dead",
        )

    monkeypatch.setattr(subprocess, "run", fake_systemctl)
    result = run_json_cli(
        ["jobs", "reconcile"],
        settings=settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["reconciliation"]["changed"] == [
        {
            "job_id": running.job_id,
            "previous_state": "running",
            "state": "failed",
            "action": "worker_lost",
        }
    ]
    reconciled = jobs.get(running.job_id)
    assert reconciled.state == outcome.job_state
    assert reconciled.stage == outcome.job_stage
    assert reconciled.status["error_code"] == outcome.error_code
    assert not (reconciled.job_dir / "result.json").exists()
    assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None


def test_or1_reconcile_marks_unlaunched_queue_retryable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("reconcile-worker-not-started-created")
    sandbox = make_controller_sandbox(tmp_path)
    settings = sandbox.settings
    jobs = JobRepository(settings)
    queued = jobs.create(provision_request())

    def fail_if_systemctl_runs(*args, **kwargs):
        raise AssertionError(
            "queued job without unit must not query systemd"
        )

    monkeypatch.setattr(subprocess, "run", fail_if_systemctl_runs)
    result = run_json_cli(
        ["jobs", "reconcile"],
        settings=settings,
    )

    assert result.exit_code == outcome.command_exit_code
    assert result.payload["reconciliation"]["changed"] == [
        {
            "job_id": queued.job_id,
            "previous_state": "queued",
            "state": "failed",
            "action": "queued_recoverable",
            "retryable": True,
        }
    ]
    reconciled = jobs.get(queued.job_id)
    assert reconciled.state == outcome.job_state
    assert reconciled.stage == outcome.job_stage
    assert reconciled.status["error_code"] == outcome.error_code
    assert reconciled.status["retryable"] is outcome.retryable
    assert reconciled.status["finished_at"]
    assert AssignmentRepository(settings).get(TEST_MACHINE_UUID) is None


def test_or1_reconcile_recovers_validated_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outcome = get_outcome("reconcile-result-recovered")
    sandbox = make_controller_sandbox(tmp_path)
    settings = sandbox.settings
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    running = _advance_to_stage(
        settings,
        created.job_id,
        "recording",
        unit_name=unit_name,
    )
    result_payload = successful_provision_result(
        job_id=running.job_id
    )
    atomic_write_json(running.job_dir / "result.json", result_payload)

    def fake_systemctl(
        command,
        *,
        shell,
        text,
        capture_output,
        timeout,
        check,
    ):
        assert shell is False
        assert text is True
        assert capture_output is True
        assert timeout == 15
        assert check is False
        return _systemctl_result(
            command,
            unit_name=unit_name,
            load_state="not-found",
            active_state="inactive",
            sub_state="dead",
        )

    monkeypatch.setattr(subprocess, "run", fake_systemctl)
    cli_result = run_json_cli(
        ["jobs", "reconcile"],
        settings=settings,
    )

    assert cli_result.exit_code == outcome.command_exit_code
    assert cli_result.payload["reconciliation"]["changed"] == [
        {
            "job_id": running.job_id,
            "previous_state": "running",
            "state": "successful",
            "action": "result_recovered",
        }
    ]
    recovered = jobs.get(running.job_id)
    assert recovered.state == outcome.job_state
    assert recovered.stage == outcome.job_stage
    assert [
        item["stage"]
        for item in recovered.status["stage_history"]
    ][-2:] == ["recording", "complete"]
    assert recovered.status["result_file"] == str(
        running.job_dir / "result.json"
    )
    assert assignments.get(running.machine_uuid) == result_payload
