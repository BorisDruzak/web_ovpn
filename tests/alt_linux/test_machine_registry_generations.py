from __future__ import annotations

from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.registry import MachineRepository
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_UUID,
    commit_candidate_without_cleanup,
    registration_payload,
    write_registration,
)


def test_committed_old_generation_is_hidden(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    commit_candidate_without_cleanup(
        sandbox.settings,
        source,
        "ready",
    )

    assert MachineRepository(sandbox.settings).list() == []


def test_new_generation_is_visible_after_old_archive(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(
            registration_id=(
                "reg-11111111111111111111111111111111"
            ),
            status="awaiting_assignment",
        ),
    )
    commit_candidate_without_cleanup(
        sandbox.settings,
        source,
        "ready",
    )
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(
            registration_id=(
                "reg-22222222222222222222222222222222"
            ),
        ),
    )

    machines = MachineRepository(sandbox.settings).list()

    assert len(machines) == 1
    assert machines[0].raw["registration_id"] == (
        "reg-22222222222222222222222222222222"
    )
    assert machines[0].registration_state == "pending"


def test_legacy_generation_is_hidden_by_exact_fingerprint(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(
            registration_id=None,
            status="awaiting_assignment",
        ),
    )
    commit_candidate_without_cleanup(
        sandbox.settings,
        source,
        "ready",
    )

    assert MachineRepository(sandbox.settings).list() == []


def test_malformed_archive_state_fails_registry_closed(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    transaction_root = (
        sandbox.settings.archive_transactions_dir
    )
    transaction_root.mkdir(parents=True)
    invalid = (
        transaction_root
        / "archive-20260721T120000Z-11111111"
    )
    invalid.mkdir()
    (invalid / "transaction.json").write_text(
        "{broken\n",
        encoding="utf-8",
    )

    with pytest.raises(ControlError) as exc:
        MachineRepository(sandbox.settings).list()

    assert exc.value.code == "machine_archive_invalid"


def test_uncommitted_archive_does_not_hide_active_generation(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )

    machines = MachineRepository(sandbox.settings).list()

    assert len(machines) == 1
    assert machines[0].uuid == TEST_MACHINE_UUID
