from __future__ import annotations

import subprocess
from pathlib import Path

from alt_deploy.job_reconcile import JobReconciler
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository

from test_jobs import provision_request
from test_registry_cli import make_settings


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
