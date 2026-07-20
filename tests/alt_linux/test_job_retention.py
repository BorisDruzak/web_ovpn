from __future__ import annotations

import gzip
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.job_retention import JobRetentionManager
from alt_deploy.job_stages import JobStageManager
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import atomic_write_json, read_json

from test_jobs import assignment_payload, provision_request
from test_registry_cli import make_settings


def _advance_to_stage(
    settings,
    job_id: str,
    target: str,
) -> None:
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
            return

        updates = None
        if stage == "validating":
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
            return

    raise AssertionError(
        f"Unable to advance {job_id} to {target}"
    )


def _finish_job(
    settings,
    job_id: str,
    *,
    state: str,
    finished_at: str,
) -> None:
    manager = JobStageManager(settings)

    if state == "successful":
        _advance_to_stage(
            settings,
            job_id,
            "recording",
        )
        current = manager.jobs.get(job_id)
        manager.advance(
            job_id,
            "complete",
            updates={
                "state": "successful",
                "finished_at": finished_at,
                "result_file": str(
                    current.job_dir / "result.json"
                ),
            },
        )
        return

    if state != "failed":
        raise AssertionError(
            f"Unsupported terminal fixture state: {state}"
        )

    _advance_to_stage(
        settings,
        job_id,
        "verifying",
    )
    manager.jobs.update(
        job_id,
        state="failed",
        finished_at=finished_at,
        error="fixture failure",
    )


def _set_created_at(
    job,
    created_at: str,
) -> None:
    status = read_json(
        job.job_dir / "status.json"
    )
    status["created_at"] = created_at
    atomic_write_json(
        job.job_dir / "status.json",
        status,
    )


def test_cleanup_dry_run_classifies_jobs_without_mutation(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    now = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)

    expired = jobs.create(provision_request())
    _finish_job(
        settings,
        expired.job_id,
        state="successful",
        finished_at=(now - timedelta(days=120)).isoformat(),
    )
    expired_log = expired.job_dir / "ansible.log"
    expired_log.write_text("expired log\n", encoding="utf-8")

    archivable = jobs.create(provision_request())
    _finish_job(
        settings,
        archivable.job_id,
        state="failed",
        finished_at=(now - timedelta(days=30)).isoformat(),
    )
    archivable_log = archivable.job_dir / "ansible.log"
    archivable_log.write_text("archive me\n", encoding="utf-8")

    recent = jobs.create(provision_request())
    _finish_job(
        settings,
        recent.job_id,
        state="successful",
        finished_at=(now - timedelta(days=5)).isoformat(),
    )

    active = jobs.create(provision_request())
    _set_created_at(
        active,
        (now - timedelta(days=400)).isoformat(),
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


def test_cleanup_apply_archives_log_atomically_and_idempotently(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    now = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)

    archivable = jobs.create(provision_request())
    _finish_job(
        settings,
        archivable.job_id,
        state="failed",
        finished_at=(now - timedelta(days=30)).isoformat(),
    )
    log_path = archivable.job_dir / "ansible.log"
    log_content = "first line\nsecond line\n"
    log_path.write_text(log_content, encoding="utf-8")

    active = jobs.create(provision_request())
    _advance_to_stage(
        settings,
        active.job_id,
        "validating",
    )
    _set_created_at(
        active,
        (now - timedelta(days=400)).isoformat(),
    )
    active_log = active.job_dir / "ansible.log"
    active_log.write_text("active log\n", encoding="utf-8")

    assignment = assignment_payload(job_id=archivable.job_id)
    assignments.write(archivable.machine_uuid, assignment)

    report = JobRetentionManager(settings).cleanup(
        apply=True,
        now=now,
        retention_days=90,
        archive_after_days=14,
    )

    assert report["status"] == "ok"
    assert report["dry_run"] is False
    assert report["checked"] == 2
    assert report["actions"] == [
        {
            "job_id": archivable.job_id,
            "state": "failed",
            "action": "archive_log",
            "age_days": 30,
            "applied": True,
        }
    ]
    assert report["skipped"] == [
        {
            "job_id": active.job_id,
            "state": "running",
            "reason": "active_job",
        }
    ]

    archive_path = archivable.job_dir / "ansible.log.gz"
    assert archivable.job_dir.is_dir()
    assert not log_path.exists()
    assert archive_path.is_file()
    assert stat.S_IMODE(archive_path.stat().st_mode) == 0o600
    with gzip.open(archive_path, "rt", encoding="utf-8") as handle:
        assert handle.read() == log_content

    assert active.job_dir.is_dir()
    assert active_log.read_text(encoding="utf-8") == "active log\n"
    assert assignments.get(archivable.machine_uuid) == assignment

    second = JobRetentionManager(settings).cleanup(
        apply=True,
        now=now,
        retention_days=90,
        archive_after_days=14,
    )

    assert second["actions"] == []
    assert {
        item["job_id"]: item["reason"]
        for item in second["skipped"]
    } == {
        archivable.job_id: "retained",
        active.job_id: "active_job",
    }
    assert archive_path.is_file()
    assert assignments.get(archivable.machine_uuid) == assignment


def test_cleanup_apply_deletes_expired_job_without_following_symlinks(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    assignments = AssignmentRepository(settings)
    now = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)

    expired = jobs.create(provision_request())
    _finish_job(
        settings,
        expired.job_id,
        state="successful",
        finished_at=(now - timedelta(days=120)).isoformat(),
    )

    outside_target = tmp_path / "outside-target"
    outside_target.mkdir()
    outside_file = outside_target / "keep.txt"
    outside_file.write_text("must survive\n", encoding="utf-8")
    (expired.job_dir / "outside-link").symlink_to(
        outside_target,
        target_is_directory=True,
    )

    outside_job = tmp_path / "outside-job"
    outside_job.mkdir()
    outside_job_file = outside_job / "keep.txt"
    outside_job_file.write_text("outside job survives\n", encoding="utf-8")
    unsafe_job_id = "job-20200101T000000Z-deadbeef"
    unsafe_job_link = settings.jobs_dir / unsafe_job_id
    unsafe_job_link.symlink_to(
        outside_job,
        target_is_directory=True,
    )

    assignment = assignment_payload(job_id=expired.job_id)
    assignments.write(expired.machine_uuid, assignment)

    report = JobRetentionManager(settings).cleanup(
        apply=True,
        now=now,
        retention_days=90,
        archive_after_days=14,
    )

    assert report["status"] == "ok"
    assert report["dry_run"] is False
    assert report["checked"] == 1
    assert report["actions"] == [
        {
            "job_id": expired.job_id,
            "state": "successful",
            "action": "delete_job",
            "age_days": 120,
            "applied": True,
        }
    ]
    assert report["skipped"] == [
        {
            "job_id": unsafe_job_id,
            "state": "",
            "reason": "unsafe_job_entry",
        }
    ]

    assert not expired.job_dir.exists()
    assert outside_file.read_text(encoding="utf-8") == "must survive\n"
    assert unsafe_job_link.is_symlink()
    assert outside_job_file.read_text(encoding="utf-8") == (
        "outside job survives\n"
    )
    assert assignments.get(expired.machine_uuid) == assignment


def test_cleanup_fails_closed_on_malformed_real_job(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    jobs = JobRepository(settings)
    job = jobs.create(provision_request())
    status = read_json(job.job_dir / "status.json")
    status.pop("stage_history")
    atomic_write_json(job.job_dir / "status.json", status)

    with pytest.raises(ControlError) as exc:
        JobRetentionManager(settings).cleanup(
            apply=False,
            now=datetime(
                2026,
                7,
                18,
                12,
                0,
                tzinfo=timezone.utc,
            ),
        )

    assert exc.value.code == "job_stage_history_invalid"
    assert job.job_dir.is_dir()
