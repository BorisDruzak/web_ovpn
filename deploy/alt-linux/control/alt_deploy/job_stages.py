from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .assignments import assert_safe_payload
from .config import Settings
from .errors import ControlError
from .jsonio import atomic_write_json

if TYPE_CHECKING:
    from .jobs import JobRepository
    from .models import JobRecord


CANONICAL_STAGES: tuple[str, ...] = (
    "created",
    "launching",
    "validating",
    "connecting",
    "identity",
    "employee",
    "login_screen",
    "verifying",
    "recording",
    "complete",
)

STAGE_INDEX = {
    stage: index
    for index, stage in enumerate(CANONICAL_STAGES)
}

FORWARD_UPDATE_FIELDS = frozenset(
    {
        "state",
        "started_at",
        "finished_at",
        "systemd_unit",
        "result_file",
    }
)

TERMINAL_STATES = frozenset(
    {
        "successful",
        "failed",
    }
)

Clock = Callable[[], str]


def _invalid(
    job_id: str,
    message: str,
) -> ControlError:
    return ControlError(
        code="job_stage_history_invalid",
        message=message,
        exit_code=4,
        details={"job_id": job_id},
    )


def _parse_timestamp(
    value: object,
    *,
    job_id: str,
) -> datetime:
    text = str(value or "").strip()

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise _invalid(
            job_id,
            "Provision job stage timestamp is invalid",
        ) from exc

    if parsed.tzinfo is None:
        raise _invalid(
            job_id,
            "Provision job stage timestamp has no timezone",
        )

    return parsed.astimezone(timezone.utc)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initial_stage_history(
    entered_at: str,
) -> list[dict[str, str]]:
    parsed = _parse_timestamp(
        entered_at,
        job_id="new-job",
    )
    return [
        {
            "stage": "created",
            "entered_at": parsed.isoformat(),
        }
    ]


def validate_job_stage_status(
    status: Mapping[str, object],
    *,
    job_id: str,
) -> None:
    state = str(status.get("state") or "").strip()
    stage = str(status.get("stage") or "").strip()
    history = status.get("stage_history")

    if stage not in STAGE_INDEX:
        raise _invalid(
            job_id,
            "Provision job stage is unknown",
        )

    if not isinstance(history, list) or not history:
        raise _invalid(
            job_id,
            "Provision job stage history is missing or empty",
        )

    previous_time: datetime | None = None
    observed_stages: list[str] = []

    for index, raw_item in enumerate(history):
        if (
            not isinstance(raw_item, dict)
            or set(raw_item) != {"stage", "entered_at"}
        ):
            raise _invalid(
                job_id,
                "Provision job stage history item is invalid",
            )

        item_stage = str(raw_item["stage"] or "").strip()

        if (
            index >= len(CANONICAL_STAGES)
            or item_stage != CANONICAL_STAGES[index]
        ):
            raise _invalid(
                job_id,
                "Provision job stage history is not contiguous",
            )

        entered_at = _parse_timestamp(
            raw_item["entered_at"],
            job_id=job_id,
        )

        if (
            previous_time is not None
            and entered_at < previous_time
        ):
            raise _invalid(
                job_id,
                "Provision job stage timestamps move backwards",
            )

        observed_stages.append(item_stage)
        previous_time = entered_at

    if stage != observed_stages[-1]:
        raise _invalid(
            job_id,
            "Provision job stage does not match stage history",
        )

    if state == "queued" and stage not in {
        "created",
        "launching",
    }:
        raise _invalid(
            job_id,
            "Queued job has an invalid stage",
        )

    if state == "running" and not (
        STAGE_INDEX["validating"]
        <= STAGE_INDEX[stage]
        <= STAGE_INDEX["recording"]
    ):
        raise _invalid(
            job_id,
            "Running job has an invalid stage",
        )

    if (
        state == "successful"
        and stage != "complete"
    ):
        raise _invalid(
            job_id,
            "Successful job is not complete",
        )

    if state == "failed" and stage == "complete":
        raise _invalid(
            job_id,
            "Failed job cannot be complete",
        )

    if state not in {
        "queued",
        "running",
        "successful",
        "failed",
    }:
        raise _invalid(
            job_id,
            "Provision job state is unknown",
        )


class JobStageManager:
    def __init__(
        self,
        settings: Settings,
        *,
        clock: Clock | None = None,
        repository: JobRepository | None = None,
    ) -> None:
        if repository is None:
            from .jobs import JobRepository

            repository = JobRepository(settings)

        self.settings = settings
        self.clock = clock or _utc_now
        self.jobs = repository

    def advance_unlocked(
        self,
        job_id: str,
        next_stage: str,
        *,
        updates: Mapping[str, object] | None = None,
    ) -> JobRecord:
        job = self.jobs.get(job_id)

        if next_stage not in STAGE_INDEX:
            raise ControlError(
                code="invalid_job_stage_transition",
                message="Provision job stage is unknown",
                exit_code=4,
                details={
                    "job_id": job.job_id,
                    "stage": next_stage,
                },
            )

        if next_stage == job.stage:
            return job

        if (
            next_stage in STAGE_INDEX
            and STAGE_INDEX[next_stage]
            != STAGE_INDEX[job.stage] + 1
        ):
            raise ControlError(
                code="invalid_job_stage_transition",
                message=(
                    "Provision job stage transition "
                    "is not the immediate next step"
                ),
                exit_code=4,
                details={
                    "job_id": job.job_id,
                    "current_stage": job.stage,
                    "requested_stage": next_stage,
                },
            )

        entered_at = _parse_timestamp(
            self.clock(),
            job_id=job.job_id,
        ).isoformat()
        history = deepcopy(job.status["stage_history"])
        history.append(
            {
                "stage": next_stage,
                "entered_at": entered_at,
            }
        )

        status_payload = dict(job.status)
        status_payload.update(dict(updates or {}))
        status_payload["stage"] = next_stage
        status_payload["stage_history"] = history
        status_payload["job_id"] = job.job_id
        status_payload["machine_uuid"] = job.machine_uuid
        status_payload["created_at"] = job.created_at
        status_payload["updated_at"] = entered_at

        assert_safe_payload(status_payload)
        validate_job_stage_status(
            status_payload,
            job_id=job.job_id,
        )
        atomic_write_json(
            job.job_dir / "status.json",
            status_payload,
        )
        return self.jobs.get(job.job_id)

    def advance(
        self,
        job_id: str,
        next_stage: str,
        *,
        updates: Mapping[str, object] | None = None,
    ) -> JobRecord:
        return self.advance_unlocked(
            job_id,
            next_stage,
            updates=updates,
        )
