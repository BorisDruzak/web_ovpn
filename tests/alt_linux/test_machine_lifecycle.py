from __future__ import annotations

from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.machine_lifecycle import MachineLifecycleGuard
from alt_deploy.registration_records import (
    load_registration_candidate,
)
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_MAC,
    TEST_MACHINE_UUID,
    registration_payload,
    write_registration,
)
from support.payloads import provision_request


def assignment_payload() -> dict[str, object]:
    return {
        "machine_uuid": TEST_MACHINE_UUID,
        "employee_login": "test-user",
        "employee_full_name": "Тестовый Пользователь",
        "final_hostname": "alt-lifecycle-test",
        "profile": "standard",
        "job_id": "job-test",
        "completed_at": "2026-07-21T12:30:00+00:00",
        "verification": {"hostname": True},
    }


def test_discovery_collects_all_states(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    for state, generation in (
        (
            "pending",
            "reg-11111111111111111111111111111111",
        ),
        (
            "ready",
            "reg-22222222222222222222222222222222",
        ),
        (
            "failed",
            "reg-33333333333333333333333333333333",
        ),
    ):
        write_registration(
            sandbox.settings,
            state,
            registration_payload(
                registration_id=generation,
                status=(
                    "awaiting_assignment"
                    if state == "ready"
                    else state
                ),
            ),
        )

    snapshot = MachineLifecycleGuard(
        sandbox.settings
    ).snapshot_for_removal(TEST_MACHINE_UUID)

    assert [
        item.registration_state
        for item in snapshot.candidates
    ] == ["pending", "ready", "failed"]
    assert snapshot.identity.machine_uuid == TEST_MACHINE_UUID
    assert snapshot.identity.machine_key == TEST_MACHINE_UUID
    assert snapshot.identity.mac == TEST_MACHINE_MAC


def test_discovery_accepts_machine_key_lookup(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )

    candidates = MachineLifecycleGuard(
        sandbox.settings
    ).discover(TEST_MACHINE_UUID.upper())

    assert len(candidates) == 1
    assert candidates[0].machine_key == TEST_MACHINE_UUID


def test_assigned_machine_is_blocked(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    AssignmentRepository(sandbox.settings).write(
        TEST_MACHINE_UUID,
        assignment_payload(),
    )

    guard = MachineLifecycleGuard(sandbox.settings)
    snapshot = guard.snapshot_for_removal(TEST_MACHINE_UUID)

    with pytest.raises(ControlError) as exc:
        guard.assert_removal_allowed(snapshot)

    assert exc.value.code == "machine_assigned"
    assert exc.value.details == {
        "machine_uuid": TEST_MACHINE_UUID
    }


def test_busy_machine_exposes_safe_fields(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    job = JobRepository(sandbox.settings).create(
        provision_request()
    )

    guard = MachineLifecycleGuard(sandbox.settings)
    snapshot = guard.snapshot_for_removal(TEST_MACHINE_UUID)

    with pytest.raises(ControlError) as exc:
        guard.assert_removal_allowed(snapshot)

    assert exc.value.code == "machine_busy"
    assert exc.value.details == {
        "job_id": job.job_id,
        "state": "queued",
        "stage": "created",
    }


def test_exact_malformed_filename_fails_closed(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    exact = (
        sandbox.settings.registration_root
        / "ready"
        / f"{TEST_MACHINE_UUID}.json"
    )
    exact.parent.mkdir(parents=True)
    exact.write_text("{broken\n", encoding="utf-8")

    with pytest.raises(ControlError) as exc:
        MachineLifecycleGuard(
            sandbox.settings
        ).discover(TEST_MACHINE_UUID)

    assert exc.value.code == "machine_record_invalid"


def test_unrelated_malformed_record_does_not_mask_match(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    unrelated = (
        sandbox.settings.registration_root
        / "failed"
        / "unrelated.json"
    )
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("{broken\n", encoding="utf-8")
    matching = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )

    candidates = MachineLifecycleGuard(
        sandbox.settings
    ).discover(TEST_MACHINE_UUID)

    assert [candidate.path for candidate in candidates] == [
        matching
    ]


def test_conflicting_mac_fails_closed(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(
            registration_id=(
                "reg-11111111111111111111111111111111"
            ),
        ),
    )
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(
            mac="00:11:22:33:44:55",
            registration_id=(
                "reg-22222222222222222222222222222222"
            ),
            status="awaiting_assignment",
        ),
    )

    with pytest.raises(ControlError) as exc:
        MachineLifecycleGuard(
            sandbox.settings
        ).discover(TEST_MACHINE_UUID)

    assert exc.value.code == "machine_identity_conflict"


def test_duplicate_generation_fails_closed(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )

    with pytest.raises(ControlError) as exc:
        MachineLifecycleGuard(
            sandbox.settings
        ).discover(TEST_MACHINE_UUID)

    assert exc.value.code == "machine_identity_conflict"


def test_generation_active_requires_same_source_generation(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    path = write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    candidate = load_registration_candidate(path, "pending")
    guard = MachineLifecycleGuard(sandbox.settings)

    assert guard.generation_is_active(
        path,
        "pending",
        candidate.generation.value,
    ) is True

    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(
            registration_id=(
                "reg-22222222222222222222222222222222"
            )
        ),
    )

    assert guard.generation_is_active(
        path,
        "pending",
        candidate.generation.value,
    ) is False
