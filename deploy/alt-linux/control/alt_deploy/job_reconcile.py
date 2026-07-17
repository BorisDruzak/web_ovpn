from __future__ import annotations

import subprocess

from .config import Settings
from .errors import ControlError
from .jobs import ACTIVE_STATES, JobRepository, utc_now
from .models import JobRecord


SYSTEMCTL_PATH = "/usr/bin/systemctl"
RUNNING_UNIT_STATES = {
    "active",
    "activating",
    "reloading",
}


class JobReconciler:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.jobs = JobRepository(settings)

    @staticmethod
    def _expected_unit(job: JobRecord) -> str:
        return f"alt-provision-{job.job_id}.service"

    def _unit_state(self, job: JobRecord) -> dict[str, str]:
        expected_unit = self._expected_unit(job)
        recorded_unit = str(
            job.status.get("systemd_unit") or ""
        ).strip()

        if recorded_unit != expected_unit:
            raise ControlError(
                code="job_reconcile_invalid_unit",
                message=(
                    "Provision job has an invalid systemd unit"
                ),
                exit_code=4,
                details={"job_id": job.job_id},
            )

        command = [
            SYSTEMCTL_PATH,
            "show",
            expected_unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--no-pager",
        ]

        try:
            completed = subprocess.run(
                command,
                shell=False,
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ControlError(
                code="job_reconcile_systemd_failed",
                message="Unable to query provision worker state",
                exit_code=6,
                details={"job_id": job.job_id},
            ) from exc
        except OSError as exc:
            raise ControlError(
                code="job_reconcile_systemd_failed",
                message="Unable to query provision worker state",
                exit_code=6,
                details={"job_id": job.job_id},
            ) from exc

        if completed.returncode != 0:
            raise ControlError(
                code="job_reconcile_systemd_failed",
                message="Unable to query provision worker state",
                exit_code=6,
                details={"job_id": job.job_id},
            )

        properties: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                properties[key] = value

        required = {"LoadState", "ActiveState", "SubState"}
        if not required.issubset(properties):
            raise ControlError(
                code="job_reconcile_systemd_failed",
                message="Provision worker state is incomplete",
                exit_code=6,
                details={"job_id": job.job_id},
            )

        return properties

    def _reconcile_running(
        self,
        job: JobRecord,
        unit_state: dict[str, str],
    ) -> dict[str, str] | None:
        if (job.job_dir / "result.json").exists():
            return None

        if unit_state["LoadState"] != "not-found":
            return None

        previous_state = job.state
        self.jobs.update(
            job.job_id,
            state="failed",
            stage="reconcile",
            finished_at=utc_now(),
            error_code="worker_lost",
            error=(
                "Provision worker disappeared before producing "
                "a result"
            ),
        )

        return {
            "job_id": job.job_id,
            "previous_state": previous_state,
            "state": "failed",
            "action": "worker_lost",
        }

    def reconcile(self) -> dict[str, object]:
        active_jobs = [
            job
            for job in self.jobs.list()
            if job.state in ACTIVE_STATES
        ]
        changed: list[dict[str, str]] = []

        for job in active_jobs:
            unit_state = self._unit_state(job)

            if job.state == "running":
                change = self._reconcile_running(
                    job,
                    unit_state,
                )
                if change is not None:
                    changed.append(change)

        return {
            "status": "ok",
            "checked": len(active_jobs),
            "changed": changed,
        }
