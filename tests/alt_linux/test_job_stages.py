from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.job_stages import (
    CANONICAL_STAGES,
    initial_stage_history,
    validate_job_stage_status,
)
from alt_deploy.jobs import JobRepository
from alt_deploy.jsonio import read_json

from test_jobs import provision_request
from test_registry_cli import make_settings


JOB_ID = "job-20260718T120000Z-a1b2c3d4"
MACHINE_UUID = "53b03180-5d78-11f0-bd95-f027db877a00"
CREATED_AT = "2026-07-18T12:00:00+00:00"


def valid_status() -> dict[str, object]:
    return {
        "job_id": JOB_ID,
        "machine_uuid": MACHINE_UUID,
        "state": "queued",
        "stage": "created",
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
        "stage_history": [
            {
                "stage": "created",
                "entered_at": CREATED_AT,
            }
        ],
    }


def status_at(*, state: str, stage: str) -> dict[str, object]:
    entered_at = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
    stage_index = CANONICAL_STAGES.index(stage)
    history = [
        {
            "stage": stage_name,
            "entered_at": (
                entered_at + timedelta(seconds=index)
            ).isoformat(),
        }
        for index, stage_name in enumerate(
            CANONICAL_STAGES[: stage_index + 1]
        )
    ]
    status = valid_status()
    status.update(
        state=state,
        stage=stage,
        stage_history=history,
        updated_at=history[-1]["entered_at"],
    )
    return status


def assert_invalid(status: dict[str, object]) -> None:
    with pytest.raises(ControlError) as exc:
        validate_job_stage_status(status, job_id=JOB_ID)

    assert exc.value.code == "job_stage_history_invalid"


def test_canonical_stage_order_is_stable() -> None:
    assert CANONICAL_STAGES == (
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


def test_initial_history_normalizes_timezone_to_utc() -> None:
    history = initial_stage_history("2026-07-18T17:00:00+05:00")

    assert history == [
        {
            "stage": "created",
            "entered_at": "2026-07-18T12:00:00+00:00",
        }
    ]


def test_valid_created_status_is_accepted() -> None:
    validate_job_stage_status(valid_status(), job_id=JOB_ID)


@pytest.mark.parametrize("history_kind", ["missing", "empty"])
def test_missing_or_empty_stage_history_is_rejected(
    history_kind: str,
) -> None:
    status = valid_status()

    if history_kind == "missing":
        status.pop("stage_history")
    else:
        status["stage_history"] = []

    assert_invalid(status)


def test_stage_timestamp_without_timezone_is_rejected() -> None:
    status = valid_status()
    status["stage_history"] = [
        {
            "stage": "created",
            "entered_at": "2026-07-18T12:00:00",
        }
    ]

    assert_invalid(status)


def test_unknown_stage_is_rejected() -> None:
    status = valid_status()
    status.update(
        state="running",
        stage="unknown",
        stage_history=[
            {
                "stage": "created",
                "entered_at": CREATED_AT,
            },
            {
                "stage": "unknown",
                "entered_at": "2026-07-18T12:00:01+00:00",
            },
        ],
    )

    assert_invalid(status)


def test_stage_history_gap_is_rejected() -> None:
    status = valid_status()
    status.update(
        state="running",
        stage="validating",
        stage_history=[
            {
                "stage": "created",
                "entered_at": CREATED_AT,
            },
            {
                "stage": "validating",
                "entered_at": "2026-07-18T12:00:01+00:00",
            },
        ],
    )

    assert_invalid(status)


def test_repeated_stage_is_rejected() -> None:
    status = valid_status()
    status.update(
        stage="launching",
        stage_history=[
            {
                "stage": "created",
                "entered_at": CREATED_AT,
            },
            {
                "stage": "launching",
                "entered_at": "2026-07-18T12:00:01+00:00",
            },
            {
                "stage": "launching",
                "entered_at": "2026-07-18T12:00:02+00:00",
            },
        ],
    )

    assert_invalid(status)


def test_current_stage_must_match_last_history_entry() -> None:
    status = valid_status()
    status["stage"] = "launching"

    assert_invalid(status)


def test_decreasing_stage_timestamp_is_rejected() -> None:
    status = valid_status()
    status.update(
        stage="launching",
        stage_history=[
            {
                "stage": "created",
                "entered_at": "2026-07-18T12:00:02+00:00",
            },
            {
                "stage": "launching",
                "entered_at": "2026-07-18T12:00:01+00:00",
            },
        ],
    )

    assert_invalid(status)


@pytest.mark.parametrize(
    ("state", "stage"),
    [
        ("queued", "validating"),
        ("running", "launching"),
        ("successful", "recording"),
        ("failed", "complete"),
    ],
)
def test_invalid_state_stage_combination_is_rejected(
    state: str,
    stage: str,
) -> None:
    status = status_at(state=state, stage=stage)

    assert_invalid(deepcopy(status))


def test_new_job_has_created_stage_history(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    job = JobRepository(settings).create(provision_request())

    status = read_json(job.job_dir / "status.json")

    assert status["state"] == "queued"
    assert status["stage"] == "created"
    assert status["stage_history"] == [
        {
            "stage": "created",
            "entered_at": status["created_at"],
        }
    ]
