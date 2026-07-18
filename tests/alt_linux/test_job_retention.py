from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.job_retention import JobRetentionManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json, read_json

from test_jobs import assignment_payload, provision_request
from test_registry_cli import make_settings


def _set_status(
    job,
    *,
    state: str,
    stage: str,
    created_at: str | None = None,
    finished_at: str | None = None,
) -> None:
    status = read_json(job.job_dir / "status.json")
    status["state"] = state
    status["stage"] = stage

    if created_at is not None:
        status["created_at"] = created_at
        status["updated_at"] = created_at

    if finished_at is not None:
        status["finished_at"] = finished_at
        status["updated_at"] = finished_at

    atomic_write_json(job.job_dir / "status.json", status)


def test_cleanup_dry_run_classifies_jobs_without_mutation(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    now = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)

    expired = jobs.create(provision_request())
    _set_status(
        expired,
        state="successful",
        stage="complete",
        finished_at=(now - timedelta(days=120)).isoformat(),
    )
    expired_log = expired.job_dir / "ansible.log"
    expired_log.write_text("expired log\n", encoding="utf-8")

    archivable = jobs.create(provision_request())
    _set_status(
        archivable,
        state="failed",
        stage="ansible",
        finished_at=(now - timedelta(days=30)).isoformat(),
    )
    archivable_log = archivable.job_dir / "ansible.log"
    archivable_log.write_text("archive me\n", encoding="utf-8")

    recent = jobs.create(provision_request())
    _set_status(
        recent,
        state="successful",
        stage="complete",
        finished_at=(now - timedelta(days=5)).isoformat(),
    )

    active = jobs.create(provision_request())
    _set_status(
        active,
        state="queued",
        stage="created",
        created_at=(now - timedelta(days=400)).isoformat(),
    )

    assignment = assignment_payload(job_id=expired.job_id)
    assignments.write(expired.machine_uuid, assignment)

    report = JobRetentionManager(settings).cleanup(
        apply=False,
        now=now,
        retention_days=90,
        archive_after_days=14,
    )

    assert report["status"] == "ok"
    assert report["dry_run"] is True
    assert report["policy"] == {
        "retention_days": 90,
        "archive_after_days": 14,
    }
    assert report["checked"] == 4

    actions = {
        item["job_id"]: item
        for item in report["actions"]
    }
    assert actions == {
        expired.job_id: {
            "job_id": expired.job_id,
            "state": "successful",
            "action": "delete_job",
            "age_days": 120,
        },
        archivable.job_id: {
            "job_id": archivable.job_id,
            "state": "failed",
            "action": "archive_log",
            "age_days": 30,
        },
    }

    skipped = {
        item["job_id"]: item["reason"]
        for item in report["skipped"]
    }
    assert skipped == {
        recent.job_id: "retained",
        active.job_id: "active_job",
    }

    assert expired.job_dir.is_dir()
    assert archivable.job_dir.is_dir()
    assert recent.job_dir.is_dir()
    assert active.job_dir.is_dir()
    assert expired_log.read_text(encoding="utf-8") == "expired log\n"
    assert archivable_log.read_text(encoding="utf-8") == "archive me\n"
    assert not (archivable.job_dir / "ansible.log.gz").exists()
    assert assignments.get(expired.machine_uuid) == assignment
