from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.cli import main
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json

from test_jobs import provision_request
from test_registry_cli import make_settings
from test_worker import successful_result


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

        manager.advance(
            job_id,
            stage,
            updates=updates,
        )

        if stage == target:
            return manager.jobs.get(job_id)

    raise AssertionError(
        f"Unable to advance {job_id} to {target}"
    )


def test_jobs_reconcile_marks_missing_running_worker_failed(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
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
    assert reconciled.stage == "employee"
    assert reconciled.status["error_code"] == "worker_lost"
    assert reconciled.status["finished_at"]
    assert [
        item["stage"]
        for item in reconciled.status["stage_history"]
    ][-1] == "employee"
    assert not (reconciled.job_dir / "result.json").exists()


def test_jobs_reconcile_reports_genuinely_running_worker(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    running = _advance_to_stage(
        settings,
        created.job_id,
        "employee",
        unit_name=unit_name,
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
        raise AssertionError(
            "queued job without unit must not query systemd"
        )

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
    assert reconciled.stage == "created"
    assert reconciled.status["error_code"] == "worker_not_started"
    assert reconciled.status["retryable"] is True
    assert reconciled.status["finished_at"]
    assert "systemd_unit" not in reconciled.status


def test_jobs_reconcile_marks_queued_missing_unit_retryable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    created = jobs.create(provision_request())
    unit_name = f"alt-provision-{created.job_id}.service"
    queued = _advance_to_stage(
        settings,
        created.job_id,
        "launching",
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
    assert reconciled.stage == "launching"
    assert reconciled.status["error_code"] == "worker_not_started"
    assert reconciled.status["retryable"] is True
    assert reconciled.status["finished_at"]
    assert reconciled.status["systemd_unit"] == unit_name


def test_jobs_reconcile_recovers_validated_result_after_interruption(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
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
    result = successful_result(running.job_id)
    atomic_write_json(running.job_dir / "result.json", result)

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
                    "state": "successful",
                    "action": "result_recovered",
                }
            ],
            "unchanged": [],
        },
    }

    recovered = jobs.get(running.job_id)
    assert recovered.state == "successful"
    assert recovered.stage == "complete"
    assert [
        item["stage"]
        for item in recovered.status["stage_history"]
    ][-2:] == ["recording", "complete"]
    assert recovered.status["finished_at"] == result["completed_at"]
    assert recovered.status["result_file"] == str(
        running.job_dir / "result.json"
    )
    assert assignments.get(running.machine_uuid) == result
