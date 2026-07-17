from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

from alt_deploy.cli import main
from alt_deploy.jobs import JobRepository

from test_jobs import provision_request
from test_registry_cli import make_settings


def test_jobs_reconcile_marks_missing_running_worker_failed(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"

    running = jobs.update(
        created.job_id,
        state="running",
        stage="ansible",
        started_at="2026-07-17T12:00:00+00:00",
        systemd_unit=unit_name,
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

    monkeypatch.setattr(subprocess, "run", fake_systemctl)

    stdout = io.StringIO()
    rc = main(
        ["--json", "jobs", "reconcile"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    payload = json.loads(stdout.getvalue())
    assert payload == {
        "status": "ok",
        "reconciliation": {
            "status": "ok",
            "checked": 1,
            "changed": [
                {
                    "job_id": running.job_id,
                    "previous_state": "running",
                    "state": "failed",
                    "action": "worker_lost",
                }
            ],
        },
    }

    reconciled = jobs.get(running.job_id)
    assert reconciled.state == "failed"
    assert reconciled.stage == "reconcile"
    assert reconciled.status["error_code"] == "worker_lost"
    assert reconciled.status["finished_at"]
    assert not (reconciled.job_dir / "result.json").exists()
