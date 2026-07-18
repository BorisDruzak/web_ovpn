from __future__ import annotations

from pathlib import Path

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.worker import run_job

from test_provision_preview import (
    prepare_preview_environment,
    valid_request,
)
from test_registry_cli import MACHINE_UUID
from test_worker import FailingController


def test_worker_failure_preserves_connecting_stage(
    tmp_path: Path,
) -> None:
    settings = prepare_preview_environment(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    job = jobs.create(valid_request())

    JobStageManager(settings).advance(
        job.job_id,
        "launching",
        updates={
            "systemd_unit": (
                f"alt-provision-{job.job_id}.service"
            )
        },
    )

    result_code = run_job(
        job.job_id,
        settings,
        FailingController(),
    )

    assert result_code == 1

    stored_job = jobs.get(job.job_id)

    assert stored_job.state == "failed"
    assert stored_job.stage == "connecting"
    assert [
        item["stage"]
        for item in stored_job.status["stage_history"]
    ] == [
        "created",
        "launching",
        "validating",
        "connecting",
    ]
    assert stored_job.status["started_at"]
    assert stored_job.status["finished_at"]
    assert len(stored_job.status["error"]) <= 10000
    assert assignments.get(MACHINE_UUID) is None
