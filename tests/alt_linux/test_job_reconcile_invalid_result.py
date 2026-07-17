from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.cli import main
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json

from test_jobs import provision_request
from test_registry_cli import make_settings
from test_worker import successful_result


def _missing_unit_result(command, unit_name: str):
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


def _install_missing_unit(monkeypatch, unit_name: str) -> None:
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
        return _missing_unit_result(command, unit_name)

    monkeypatch.setattr(subprocess, "run", fake_systemctl)


def _running_job(settings):
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
    return jobs, running, unit_name


def _assert_rejected_payload(payload, job_id: str) -> None:
    assert payload == {
        "status": "ok",
        "reconciliation": {
            "status": "ok",
            "checked": 1,
            "changed": [
                {
                    "job_id": job_id,
                    "previous_state": "running",
                    "state": "failed",
                    "action": "result_rejected",
                    "retryable": True,
                    "error_code": "invalid_provision_result",
                }
            ],
            "unchanged": [],
        },
    }


def _assert_rejected_state(
    jobs: JobRepository,
    assignments: AssignmentRepository,
    running,
    result_path: Path,
) -> None:
    rejected = jobs.get(running.job_id)
    assert rejected.state == "failed"
    assert rejected.stage == "reconcile"
    assert rejected.status["error_code"] == "invalid_provision_result"
    assert rejected.status["retryable"] is True
    assert rejected.status["finished_at"]
    assert assignments.get(running.machine_uuid) is None
    assert result_path.is_file()


def test_jobs_reconcile_rejects_invalid_result_without_assignment(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    assignments = AssignmentRepository(settings)
    jobs, running, unit_name = _running_job(settings)

    result = successful_result(running.job_id)
    result["verification"]["hostname"] = False
    result_path = running.job_dir / "result.json"
    atomic_write_json(result_path, result)

    _install_missing_unit(monkeypatch, unit_name)

    stdout = io.StringIO()
    rc = main(
        ["--json", "jobs", "reconcile"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    _assert_rejected_payload(json.loads(stdout.getvalue()), running.job_id)
    _assert_rejected_state(jobs, assignments, running, result_path)


def test_jobs_reconcile_rejects_malformed_result_json(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    assignments = AssignmentRepository(settings)
    jobs, running, unit_name = _running_job(settings)

    result_path = running.job_dir / "result.json"
    result_path.write_text('{"verification": ', encoding="utf-8")

    _install_missing_unit(monkeypatch, unit_name)

    stdout = io.StringIO()
    rc = main(
        ["--json", "jobs", "reconcile"],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    _assert_rejected_payload(json.loads(stdout.getvalue()), running.job_id)
    _assert_rejected_state(jobs, assignments, running, result_path)
