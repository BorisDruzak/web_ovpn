from __future__ import annotations

import io
import json
from pathlib import Path

from alt_deploy.job_stage_helper import main
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository

from test_jobs import provision_request
from test_registry_cli import make_settings


def test_helper_advances_allowlisted_stage(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    manager = JobStageManager(settings)
    manager.advance(job.job_id, "launching")
    manager.advance(
        job.job_id,
        "validating",
        updates={
            "state": "running",
            "started_at": "2026-07-18T12:00:00+00:00",
        },
    )
    manager.advance(job.job_id, "connecting")

    stdout = io.StringIO()
    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "identity",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    payload = json.loads(stdout.getvalue())
    assert payload == {
        "status": "ok",
        "job_id": job.job_id,
        "stage": "identity",
        "changed": True,
    }


def test_helper_repeated_stage_reports_no_change(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    manager = JobStageManager(settings)
    manager.advance(job.job_id, "launching")

    before = (
        job.job_dir / "status.json"
    ).read_bytes()
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "launching",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 0
    assert json.loads(stdout.getvalue())["changed"] is False
    assert (
        job.job_dir / "status.json"
    ).read_bytes() == before


def test_helper_rejects_invalid_transition_as_json(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "identity",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 4
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == (
        "invalid_job_stage_transition"
    )


def test_helper_rejects_unknown_stage_as_json(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(
        provision_request()
    )
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            job.job_id,
            "--stage",
            "arbitrary-stage",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 4
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == (
        "invalid_job_stage_transition"
    )
    assert set(payload["error"]) <= {
        "code",
        "message",
        "details",
    }


def test_helper_rejects_unknown_job_as_json(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    stdout = io.StringIO()

    rc = main(
        [
            "--job-id",
            "job-20260718T120000Z-deadbeef",
            "--stage",
            "launching",
        ],
        settings=settings,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert rc == 3
    payload = json.loads(stdout.getvalue())
    assert payload["error"]["code"] == "job_not_found"
