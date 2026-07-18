from __future__ import annotations

from datetime import datetime, timezone

from .config import Settings
from .errors import ControlError
from .jobs import ACTIVE_STATES, JobRepository
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

        if apply:
            raise ControlError(
                code="job_cleanup_apply_not_implemented",
                message="Mutating job cleanup is not implemented yet",
                exit_code=4,
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
            jobs = self.jobs.list()
            actions: list[dict[str, object]] = []
            skipped: list[dict[str, object]] = []

            for job in jobs:
                action, skip = self._classify(
                    job,
                    now=current_time,
                    retention_days=retention_days,
                    archive_after_days=archive_after_days,
                )
                if action is not None:
                    actions.append(action)
                if skip is not None:
                    skipped.append(skip)

        return {
            "status": "ok",
            "dry_run": True,
            "policy": {
                "retention_days": retention_days,
                "archive_after_days": archive_after_days,
            },
            "checked": len(jobs),
            "actions": actions,
            "skipped": skipped,
        }
