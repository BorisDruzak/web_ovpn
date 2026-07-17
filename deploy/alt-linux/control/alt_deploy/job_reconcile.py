from __future__ import annotations

import subprocess

from .assignments import AssignmentRepository
from .config import Settings
from .errors import ControlError
from .jobs import ACTIVE_STATES, JobRepository, utc_now
from .jsonio import read_json
from .locks import exclusive_lock
from .models import JobRecord
from .worker import _validate_result


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
        self.assignments = AssignmentRepository(settings)

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

    def _reconcile_queued(
        self,
        job: JobRecord,
    ) -> dict[str, object] | None:
        recorded_unit = str(
            job.status.get("systemd_unit") or ""
        ).strip()
        if recorded_unit:
            return None

        previous_state = job.state
        self.jobs.update(
            job.job_id,
            state="failed",
            stage="reconcile",
            finished_at=utc_now(),
            error_code="worker_not_started",
            retryable=True,
            error=(
                "Provision job was queued but no worker unit "
                "was recorded"
            ),
        )

        return {
            "job_id": job.job_id,
            "previous_state": previous_state,
            "state": "failed",
            "action": "queued_recoverable",
            "retryable": True,
        }

    def _recover_result(
        self,
        job: JobRecord,
        unit_state: dict[str, str],
    ) -> dict[str, object] | None:
        result_path = job.job_dir / "result.json"
        if not result_path.is_file():
            return None

        if unit_state["ActiveState"] in RUNNING_UNIT_STATES:
            return None

        try:
            result = _validate_result(
                job,
                read_json(result_path),
            )
        except ControlError as exc:
            if exc.code != "invalid_provision_result":
                raise

            previous_state = job.state
            self.jobs.update(
                job.job_id,
                state="failed",
                stage="reconcile",
                finished_at=utc_now(),
                error_code=exc.code,
                retryable=True,
                error=(
                    f"{exc.code}: {exc.message}"
                )[-10000:],
            )

            return {
                "job_id": job.job_id,
                "previous_state": previous_state,
                "state": "failed",
                "action": "result_rejected",
                "retryable": True,
                "error_code": exc.code,
            }

        self.assignments.write(job.machine_uuid, result)

        previous_state = job.state
        self.jobs.update(
            job.job_id,
            state="successful",
            stage="complete",
            finished_at=str(result["completed_at"]),
            result_file=str(result_path),
        )

        return {
            "job_id": job.job_id,
            "previous_state": previous_state,
            "state": "successful",
            "action": "result_recovered",
        }

    def _reconcile_running(
        self,
        job: JobRecord,
        unit_state: dict[str, str],
    ) -> dict[str, object] | None:
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

    def _still_running(
        self,
        job: JobRecord,
        unit_state: dict[str, str],
    ) -> dict[str, object] | None:
        if unit_state["ActiveState"] not in RUNNING_UNIT_STATES:
            return None

        return {
            "job_id": job.job_id,
            "state": job.state,
            "action": "still_running",
            "systemd_unit": self._expected_unit(job),
            "load_state": unit_state["LoadState"],
            "active_state": unit_state["ActiveState"],
            "sub_state": unit_state["SubState"],
        }

    def _reconcile_unlocked(self) -> dict[str, object]:
        active_jobs = [
            job
            for job in self.jobs.list()
            if job.state in ACTIVE_STATES
        ]
        changed: list[dict[str, object]] = []
        unchanged: list[dict[str, object]] = []

        for job in active_jobs:
            if job.state == "queued":
                change = self._reconcile_queued(job)
                if change is not None:
                    changed.append(change)
                    continue

            unit_state = self._unit_state(job)

            if job.state == "running":
                recovered = self._recover_result(
                    job,
                    unit_state,
                )
                if recovered is not None:
                    changed.append(recovered)
                    continue

                change = self._reconcile_running(
                    job,
                    unit_state,
                )
                if change is not None:
                    changed.append(change)
                    continue

                running = self._still_running(
                    job,
                    unit_state,
                )
                if running is not None:
                    unchanged.append(running)

        return {
            "status": "ok",
            "checked": len(active_jobs),
            "changed": changed,
            "unchanged": unchanged,
        }

    def reconcile(self) -> dict[str, object]:
        with exclusive_lock(self.settings.lock_file):
            return self._reconcile_unlocked()
