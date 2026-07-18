from __future__ import annotations

import subprocess
from pathlib import Path

from alt_deploy.job_reconcile import JobReconciler
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository

from test_jobs import provision_request
from test_registry_cli import make_settings


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
        assert command == [
            "/usr/bin/systemctl",
            "show",
            unit_name,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--no-pager",
        ]
        assert shell is False
        assert text is True
        assert capture_output is True
        assert timeout == 15
        assert check is False
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
