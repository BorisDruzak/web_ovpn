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
from alt_deploy.jsonio import atomic_write_json, read_json

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


def test_malformed_real_job_is_not_hidden_by_get_or_list(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    status = read_json(job.job_dir / "status.json")
    status.pop("stage_history")
    atomic_write_json(job.job_dir / "status.json", status)

    with pytest.raises(ControlError) as exc:
        repository.get(job.job_id)

    assert exc.value.code == "job_stage_history_invalid"

    with pytest.raises(ControlError) as exc:
        repository.list()

    assert exc.value.code == "job_stage_history_invalid"


@pytest.mark.parametrize(
    "fields",
    [
        {"stage": "launching"},
        {"stage_history": []},
    ],
)
def test_repository_update_rejects_direct_stage_fields(
    tmp_path: Path,
    fields: dict[str, object],
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    with pytest.raises(ControlError) as exc:
        repository.update(job.job_id, **fields)

    assert exc.value.code == "job_stage_update_forbidden"
    assert status_path.read_bytes() == before


def test_repository_update_validates_result_before_write(
    tmp_path: Path,
) -> None:
    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    with pytest.raises(ControlError) as exc:
        repository.update(job.job_id, state="successful")

    assert exc.value.code == "job_stage_history_invalid"
    assert status_path.read_bytes() == before


def test_stage_manager_advances_one_stage_atomically(
    tmp_path: Path,
) -> None:
    from alt_deploy.job_stages import JobStageManager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    entered_at = (
        datetime.fromisoformat(job.created_at)
        .astimezone(timezone.utc)
        + timedelta(seconds=1)
    ).isoformat()
    manager = JobStageManager(
        settings,
        clock=lambda: entered_at,
        repository=repository,
    )
    unit = f"alt-provision-{job.job_id}.service"

    launched = manager.advance(
        job.job_id,
        "launching",
        updates={"systemd_unit": unit},
    )

    assert launched.state == "queued"
    assert launched.stage == "launching"
    assert launched.status["systemd_unit"] == unit
    assert launched.status["stage_history"] == [
        {
            "stage": "created",
            "entered_at": job.created_at,
        },
        {
            "stage": "launching",
            "entered_at": entered_at,
        },
    ]
    assert read_json(job.job_dir / "status.json") == launched.status


def test_repeated_current_stage_is_byte_identical_noop(
    tmp_path: Path,
) -> None:
    from alt_deploy.job_stages import JobStageManager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(settings, repository=repository)
    manager.advance(job.job_id, "launching")

    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    repeated = manager.advance(
        job.job_id,
        "launching",
        updates={"state": "running"},
    )

    assert repeated.state == "queued"
    assert repeated.stage == "launching"
    assert status_path.read_bytes() == before


def test_stage_manager_rejects_skipped_transition(
    tmp_path: Path,
) -> None:
    from alt_deploy.job_stages import JobStageManager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    with pytest.raises(ControlError) as exc:
        JobStageManager(
            settings,
            repository=repository,
        ).advance(job.job_id, "validating")

    assert exc.value.code == "invalid_job_stage_transition"
    assert status_path.read_bytes() == before
    assert repository.get(job.job_id).stage == "created"


def test_stage_manager_rejects_unknown_stage(
    tmp_path: Path,
) -> None:
    from alt_deploy.job_stages import JobStageManager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    with pytest.raises(ControlError) as exc:
        JobStageManager(
            settings,
            repository=repository,
        ).advance(job.job_id, "unknown")

    assert exc.value.code == "invalid_job_stage_transition"
    assert status_path.read_bytes() == before
    assert repository.get(job.job_id).stage == "created"


def test_terminal_job_rejects_repeated_stage(
    tmp_path: Path,
) -> None:
    from alt_deploy.job_stages import JobStageManager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    manager = JobStageManager(settings, repository=repository)
    manager.advance(job.job_id, "launching")
    repository.update(
        job.job_id,
        state="failed",
        finished_at="2026-07-18T12:01:00+00:00",
        error="launch failed",
    )

    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    with pytest.raises(ControlError) as exc:
        manager.advance(job.job_id, "launching")

    assert exc.value.code == "job_stage_terminal"
    assert status_path.read_bytes() == before


def test_stage_manager_rejects_unapproved_update_fields(
    tmp_path: Path,
) -> None:
    from alt_deploy.job_stages import JobStageManager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    status_path = job.job_dir / "status.json"
    before = status_path.read_bytes()

    with pytest.raises(ControlError) as exc:
        JobStageManager(
            settings,
            repository=repository,
        ).advance(
            job.job_id,
            "launching",
            updates={"error": "not allowed"},
        )

    assert exc.value.code == "invalid_job_stage_update"
    assert status_path.read_bytes() == before


def test_stage_manager_uses_common_controller_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import contextmanager

    from alt_deploy.job_stages import JobStageManager

    settings = make_settings(tmp_path)
    repository = JobRepository(settings)
    job = repository.create(provision_request())
    locked_paths: list[Path] = []

    @contextmanager
    def fake_lock(path: Path):
        locked_paths.append(path)
        yield

    monkeypatch.setattr(
        "alt_deploy.job_stages.exclusive_lock",
        fake_lock,
    )

    JobStageManager(
        settings,
        repository=repository,
    ).advance(
        job.job_id,
        "launching",
    )

    assert locked_paths == [settings.lock_file]
