from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

from alt_deploy.cli import main
from alt_deploy.jobs import JobRepository

from test_jobs import provision_request
from test_registry_cli import make_settings


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
            "unchanged": [],
        },
    }

    reconciled = jobs.get(running.job_id)
    assert reconciled.state == "failed"
    assert reconciled.stage == "reconcile"
    assert reconciled.status["error_code"] == "worker_lost"
    assert reconciled.status["finished_at"]
    assert not (reconciled.job_dir / "result.json").exists()


def test_jobs_reconcile_reports_genuinely_running_worker(
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
    status_before = dict(running.status)

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
            load_state="loaded",
            active_state="active",
            sub_state="running",
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
            "changed": [],
            "unchanged": [
                {
                    "job_id": running.job_id,
                    "state": "running",
                    "action": "still_running",
                    "systemd_unit": unit_name,
                    "load_state": "loaded",
                    "active_state": "active",
                    "sub_state": "running",
                }
            ],
        },
    }

    after = jobs.get(running.job_id)
    assert after.status == status_before


def test_jobs_reconcile_marks_unlaunched_queue_retryable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    queued = jobs.create(provision_request())

    def fail_if_systemctl_runs(*args, **kwargs):
        raise AssertionError("queued job without unit must not query systemd")

    monkeypatch.setattr(subprocess, "run", fail_if_systemctl_runs)

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
                    "job_id": queued.job_id,
                    "previous_state": "queued",
                    "state": "failed",
                    "action": "queued_recoverable",
                    "retryable": True,
                }
            ],
            "unchanged": [],
        },
    }

    reconciled = jobs.get(queued.job_id)
    assert reconciled.state == "failed"
    assert reconciled.stage == "reconcile"
    assert reconciled.status["error_code"] == "worker_not_started"
    assert reconciled.status["retryable"] is True
    assert reconciled.status["finished_at"]
    assert "systemd_unit" not in reconciled.status
