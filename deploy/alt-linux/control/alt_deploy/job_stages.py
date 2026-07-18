from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone

from .errors import ControlError


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
