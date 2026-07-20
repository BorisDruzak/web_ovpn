from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.job_reconcile import JobReconciler
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json

from test_jobs import provision_request
from test_registry_cli import make_settings
from test_worker import successful_result


def missing_unit_result(
    command: list[str],
    unit_name: str,
) -> subprocess.CompletedProcess[str]:
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
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
        ),
        stderr="",
    )


def advance_to_employee(
    settings,
    job_id: str,
    unit_name: str,
) -> None:
    manager = JobStageManager(settings)
    manager.advance(
        job_id,
        "launching",
        updates={"systemd_unit": unit_name},
    )
    manager.advance(
        job_id,
        "validating",
        updates={
            "state": "running",
            "started_at": "2026-07-18T12:00:00+00:00",
        },
    )
    for stage in (
        "connecting",
        "identity",
        "employee",
    ):
        manager.advance(job_id, stage)


def test_reconcile_worker_loss_preserves_employee_stage(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    advance_to_employee(settings, created.job_id, unit_name)
    running = jobs.get(created.job_id)

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
        return missing_unit_result(command, unit_name)

    monkeypatch.setattr(
        "alt_deploy.job_reconcile.subprocess.run",
        fake_systemctl,
    )

    result = JobReconciler(settings).reconcile()

    assert result["changed"] == [
        {
            "job_id": running.job_id,
            "previous_state": "running",
            "state": "failed",
            "action": "worker_lost",
        }
    ]

    reconciled = jobs.get(running.job_id)
    assert reconciled.state == "failed"
    assert reconciled.stage == "employee"
    assert reconciled.status["error_code"] == "worker_lost"
    assert [
        item["stage"]
        for item in reconciled.status["stage_history"]
    ][-1] == "employee"


def test_reconcile_unlaunched_queue_preserves_created_stage(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    queued = jobs.create(provision_request())

    def fail_if_systemctl_runs(*args, **kwargs):
        raise AssertionError(
            "Queued job without a unit must not query systemd"
        )

    monkeypatch.setattr(
        "alt_deploy.job_reconcile.subprocess.run",
        fail_if_systemctl_runs,
    )

    result = JobReconciler(settings).reconcile()

    assert result["changed"] == [
        {
            "job_id": queued.job_id,
            "previous_state": "queued",
            "state": "failed",
            "action": "queued_recoverable",
            "retryable": True,
        }
    ]

    reconciled = jobs.get(queued.job_id)
    assert reconciled.state == "failed"
    assert reconciled.stage == "created"
    assert reconciled.status["error_code"] == (
        "worker_not_started"
    )
    assert reconciled.status["retryable"] is True
    assert "systemd_unit" not in reconciled.status
    assert [
        item["stage"]
        for item in reconciled.status["stage_history"]
    ][-1] == "created"


def test_reconcile_missing_queued_unit_preserves_launching_stage(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    queued = JobStageManager(
        settings,
        repository=jobs,
    ).advance(
        created.job_id,
        "launching",
        updates={"systemd_unit": unit_name},
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
        return missing_unit_result(command, unit_name)

    monkeypatch.setattr(
        "alt_deploy.job_reconcile.subprocess.run",
        fake_systemctl,
    )

    result = JobReconciler(settings).reconcile()

    assert result["changed"] == [
        {
            "job_id": queued.job_id,
            "previous_state": "queued",
            "state": "failed",
            "action": "queued_recoverable",
            "retryable": True,
        }
    ]

    reconciled = jobs.get(queued.job_id)
    assert reconciled.state == "failed"
    assert reconciled.stage == "launching"
    assert reconciled.status["error_code"] == (
        "worker_not_started"
    )
    assert reconciled.status["retryable"] is True
    assert reconciled.status["systemd_unit"] == unit_name
    assert [
        item["stage"]
        for item in reconciled.status["stage_history"]
    ][-1] == "launching"


def test_reconcile_rejects_result_before_recording(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    advance_to_employee(settings, created.job_id, unit_name)

    manager = JobStageManager(settings)
    manager.advance(created.job_id, "login_screen")
    manager.advance(created.job_id, "verifying")
    running = jobs.get(created.job_id)

    atomic_write_json(
        running.job_dir / "result.json",
        successful_result(running.job_id),
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
        return missing_unit_result(command, unit_name)

    monkeypatch.setattr(
        "alt_deploy.job_reconcile.subprocess.run",
        fake_systemctl,
    )

    with pytest.raises(ControlError) as exc:
        JobReconciler(settings).reconcile()

    assert exc.value.code == "job_reconcile_invalid_stage"

    unchanged = jobs.get(running.job_id)
    assert unchanged.state == "running"
    assert unchanged.stage == "verifying"
    assert [
        item["stage"]
        for item in unchanged.status["stage_history"]
    ][-1] == "verifying"
    assert assignments.get(running.machine_uuid) is None


def test_reconcile_recovers_recording_result_through_stage_manager(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    advance_to_employee(settings, created.job_id, unit_name)

    manager = JobStageManager(settings)
    for stage in (
        "login_screen",
        "verifying",
        "recording",
    ):
        manager.advance(created.job_id, stage)

    running = jobs.get(created.job_id)
    result_payload = successful_result(running.job_id)
    result_path = running.job_dir / "result.json"
    atomic_write_json(result_path, result_payload)

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
        return missing_unit_result(command, unit_name)

    monkeypatch.setattr(
        "alt_deploy.job_reconcile.subprocess.run",
        fake_systemctl,
    )

    reconciliation = JobReconciler(settings).reconcile()

    assert reconciliation["changed"] == [
        {
            "job_id": running.job_id,
            "previous_state": "running",
            "state": "successful",
            "action": "result_recovered",
        }
    ]

    recovered = jobs.get(running.job_id)
    assert recovered.state == "successful"
    assert recovered.stage == "complete"
    assert [
        item["stage"]
        for item in recovered.status["stage_history"]
    ][-2:] == ["recording", "complete"]
    assert recovered.status["finished_at"] == (
        result_payload["completed_at"]
    )
    assert recovered.status["result_file"] == str(result_path)
    assert assignments.get(running.machine_uuid) == result_payload
