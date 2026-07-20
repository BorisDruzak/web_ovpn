from __future__ import annotations

import gzip
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings
from .errors import ControlError
from .jobs import (
    ACTIVE_STATES,
    JOB_ID_RE,
    JobRepository,
)
from .locks import exclusive_lock
from .models import JobRecord


TERMINAL_STATES = {
    "successful",
    "failed",
}


class JobRetentionManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.jobs = JobRepository(settings)

    @staticmethod
    def _terminal_timestamp(job: JobRecord) -> datetime:
        for field_name in (
            "finished_at",
            "updated_at",
            "created_at",
        ):
            value = str(job.status.get(field_name) or "").strip()
            if not value:
                continue

            try:
                timestamp = datetime.fromisoformat(value)
            except ValueError:
                continue

            if timestamp.tzinfo is None:
                continue

            return timestamp.astimezone(timezone.utc)

        raise ControlError(
            code="job_cleanup_invalid_timestamp",
            message="Terminal job has no valid retention timestamp",
            exit_code=4,
            details={"job_id": job.job_id},
        )

    @staticmethod
    def _validate_policy(
        retention_days: int,
        archive_after_days: int,
    ) -> None:
        if retention_days < 1:
            raise ControlError(
                code="invalid_job_retention_policy",
                message="Job retention period must be positive",
                exit_code=4,
            )

        if archive_after_days < 1:
            raise ControlError(
                code="invalid_job_retention_policy",
                message="Log archive period must be positive",
                exit_code=4,
            )

        if archive_after_days >= retention_days:
            raise ControlError(
                code="invalid_job_retention_policy",
                message=(
                    "Log archive period must be shorter than "
                    "job retention period"
                ),
                exit_code=4,
            )

    def _classify(
        self,
        job: JobRecord,
        *,
        now: datetime,
        retention_days: int,
        archive_after_days: int,
    ) -> tuple[dict[str, object] | None, dict[str, object] | None]:
        if job.state in ACTIVE_STATES:
            return None, {
                "job_id": job.job_id,
                "state": job.state,
                "reason": "active_job",
            }

        if job.state not in TERMINAL_STATES:
            return None, {
                "job_id": job.job_id,
                "state": job.state,
                "reason": "unsupported_state",
            }

        terminal_at = self._terminal_timestamp(job)
        age_days = max(0, (now - terminal_at).days)

        if age_days >= retention_days:
            return {
                "job_id": job.job_id,
                "state": job.state,
                "action": "delete_job",
                "age_days": age_days,
            }, None

        log_path = job.job_dir / "ansible.log"
        archive_path = job.job_dir / "ansible.log.gz"
        if (
            age_days >= archive_after_days
            and log_path.is_file()
            and not log_path.is_symlink()
            and not archive_path.exists()
        ):
            return {
                "job_id": job.job_id,
                "state": job.state,
                "action": "archive_log",
                "age_days": age_days,
            }, None

        return None, {
            "job_id": job.job_id,
            "state": job.state,
            "reason": "retained",
        }

    @staticmethod
    def _archive_log(job: JobRecord) -> None:
        log_path = job.job_dir / "ansible.log"
        archive_path = job.job_dir / "ansible.log.gz"
        temporary_path = job.job_dir / (
            f".ansible.log.gz.{os.getpid()}.tmp"
        )

        try:
            log_stat = log_path.lstat()
        except OSError as exc:
            raise ControlError(
                code="job_log_archive_failed",
                message="Unable to inspect provision job log",
                exit_code=6,
                details={"job_id": job.job_id},
            ) from exc

        if not stat.S_ISREG(log_stat.st_mode):
            raise ControlError(
                code="job_log_archive_unsafe",
                message="Provision job log is not a regular file",
                exit_code=4,
                details={"job_id": job.job_id},
            )

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            output_fd = os.open(
                temporary_path,
                flags,
                0o600,
            )
            try:
                with log_path.open("rb") as source:
                    with os.fdopen(output_fd, "wb") as raw_output:
                        output_fd = -1
                        with gzip.GzipFile(
                            filename="",
                            mode="wb",
                            fileobj=raw_output,
                            mtime=0,
                        ) as compressed:
                            shutil.copyfileobj(source, compressed)
                        raw_output.flush()
                        os.fsync(raw_output.fileno())
            finally:
                if output_fd >= 0:
                    os.close(output_fd)

            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, archive_path)
            log_path.unlink()
        except OSError as exc:
            raise ControlError(
                code="job_log_archive_failed",
                message="Unable to archive provision job log",
                exit_code=6,
                details={"job_id": job.job_id},
            ) from exc
        finally:
            temporary_path.unlink(missing_ok=True)

    def _unsafe_job_entries(self) -> list[dict[str, object]]:
        if not self.settings.jobs_dir.exists():
            return []

        skipped: list[dict[str, object]] = []
        for entry in sorted(self.settings.jobs_dir.glob("job-*")):
            if not JOB_ID_RE.fullmatch(entry.name):
                continue

            try:
                entry_stat = entry.lstat()
            except OSError:
                skipped.append(
                    {
                        "job_id": entry.name,
                        "state": "",
                        "reason": "unsafe_job_entry",
                    }
                )
                continue

            if not stat.S_ISDIR(entry_stat.st_mode):
                skipped.append(
                    {
                        "job_id": entry.name,
                        "state": "",
                        "reason": "unsafe_job_entry",
                    }
                )

        return skipped

    @classmethod
    def _remove_entry_no_follow(
        cls,
        path: Path,
        *,
        require_directory: bool = False,
    ) -> None:
        entry_stat = path.lstat()

        if require_directory and not stat.S_ISDIR(entry_stat.st_mode):
            raise ControlError(
                code="job_cleanup_delete_unsafe",
                message="Provision job path is not a real directory",
                exit_code=4,
                details={"job_id": path.name},
            )

        if stat.S_ISDIR(entry_stat.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    child = path / entry.name
                    if entry.is_dir(follow_symlinks=False):
                        cls._remove_entry_no_follow(child)
                    else:
                        child.unlink()
            path.rmdir()
            return

        path.unlink()

    def _delete_job(self, job: JobRecord) -> None:
        expected_path = self.settings.jobs_dir / job.job_id
        if (
            not JOB_ID_RE.fullmatch(job.job_id)
            or job.job_dir != expected_path
            or job.job_dir.parent != self.settings.jobs_dir
        ):
            raise ControlError(
                code="job_cleanup_delete_unsafe",
                message="Provision job path is outside the jobs root",
                exit_code=4,
                details={"job_id": job.job_id},
            )

        try:
            self._remove_entry_no_follow(
                job.job_dir,
                require_directory=True,
            )
        except ControlError:
            raise
        except OSError as exc:
            raise ControlError(
                code="job_cleanup_delete_failed",
                message="Unable to delete expired provision job",
                exit_code=6,
                details={"job_id": job.job_id},
            ) from exc

    def cleanup(
        self,
        *,
        apply: bool = False,
        now: datetime | None = None,
        retention_days: int = 90,
        archive_after_days: int = 14,
    ) -> dict[str, object]:
        self._validate_policy(
            retention_days,
            archive_after_days,
        )

        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None:
            raise ControlError(
                code="invalid_job_cleanup_time",
                message="Job cleanup time must include a timezone",
                exit_code=4,
            )
        current_time = current_time.astimezone(timezone.utc)

        with exclusive_lock(self.settings.lock_file):
            unsafe_entries = self._unsafe_job_entries()
            jobs = self.jobs.list()
            actions: list[dict[str, object]] = []
            skipped: list[dict[str, object]] = list(unsafe_entries)

            for job in jobs:
                action, skip = self._classify(
                    job,
                    now=current_time,
                    retention_days=retention_days,
                    archive_after_days=archive_after_days,
                )
                if action is not None:
                    if apply:
                        if action["action"] == "archive_log":
                            self._archive_log(job)
                        elif action["action"] == "delete_job":
                            self._delete_job(job)
                        action = {
                            **action,
                            "applied": True,
                        }
                    actions.append(action)
                if skip is not None:
                    skipped.append(skip)

        return {
            "status": "ok",
            "dry_run": not apply,
            "policy": {
                "retention_days": retention_days,
                "archive_after_days": archive_after_days,
            },
            "checked": len(jobs),
            "actions": actions,
            "skipped": skipped,
        }
