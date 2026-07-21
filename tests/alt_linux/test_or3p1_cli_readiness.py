from __future__ import annotations

import json
from pathlib import Path

from alt_deploy.job_stages import CANONICAL_STAGES, JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json
from support.cli import run_json_cli
from support.controller_sandbox import make_controller_sandbox
from support.payloads import provision_request


def test_jobs_active_returns_empty_safe_summary(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)

    result = run_json_cli(["jobs", "active"], settings=sandbox.settings)

    assert result.exit_code == 0
    assert result.payload == {
        "status": "ok",
        "active_jobs": [],
        "count": 0,
    }


def test_jobs_active_filters_terminal_jobs_and_redacts_payload(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    jobs = JobRepository(sandbox.settings)
    stages = JobStageManager(sandbox.settings)

    queued = jobs.create(provision_request())

    running = jobs.create(provision_request())
    stages.advance(running.job_id, "launching")
    stages.advance(
        running.job_id,
        "validating",
        updates={"state": "running"},
    )

    successful = jobs.create(provision_request())
    stages.advance(successful.job_id, "launching")
    stages.advance(
        successful.job_id,
        "validating",
        updates={"state": "running"},
    )
    for stage in CANONICAL_STAGES[3:]:
        updates = {"state": "successful"} if stage == "complete" else None
        stages.advance(successful.job_id, stage, updates=updates)

    failed = jobs.create(provision_request())
    jobs.update(
        failed.job_id,
        state="failed",
        error="synthetic terminal failure",
    )

    result = run_json_cli(["jobs", "active"], settings=sandbox.settings)

    assert result.exit_code == 0
    assert result.payload["count"] == 2
    assert [
        item["job_id"] for item in result.payload["active_jobs"]
    ] == [running.job_id, queued.job_id]
    assert [
        item["state"] for item in result.payload["active_jobs"]
    ] == ["running", "queued"]
    assert all(
        set(item)
        == {
            "job_id",
            "machine_uuid",
            "state",
            "stage",
            "created_at",
        }
        for item in result.payload["active_jobs"]
    )

    serialized = json.dumps(result.payload, ensure_ascii=False)
    assert "employee_full_name" not in serialized
    assert "Иванов" not in serialized
    assert "ansible_output" not in serialized
    assert "result" not in serialized
    assert "synthetic terminal failure" not in serialized


def test_jobs_active_fails_closed_for_malformed_real_job(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    job_dir = (
        sandbox.settings.jobs_dir
        / "job-20260721T120000Z-deadbeef"
    )
    job_dir.mkdir(parents=True)
    atomic_write_json(
        job_dir / "request.json",
        provision_request(),
    )
    atomic_write_json(job_dir / "status.json", {})

    result = run_json_cli(["jobs", "active"], settings=sandbox.settings)

    assert result.exit_code == 4
    assert result.payload["error"]["code"] in {
        "job_invalid",
        "job_stage_history_invalid",
    }
    assert "active_jobs" not in result.payload
    assert "count" not in result.payload
