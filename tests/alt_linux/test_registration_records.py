from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.registration_records import (
    MAX_REGISTRATION_RECORD_BYTES,
    load_registration_candidate,
    registration_generation,
)
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_UUID,
    TEST_REGISTRATION_ID,
    registration_payload,
    write_registration,
)


def test_settings_derive_archive_paths(tmp_path: Path) -> None:
    settings = make_controller_sandbox(tmp_path).settings

    assert settings.machine_archives_dir == (
        settings.state_root / "machine-archives"
    )
    assert settings.archive_transactions_dir == (
        settings.state_root
        / "machine-archives"
        / ".transactions"
    )


def test_registration_generation_prefers_valid_registration_id() -> None:
    result = registration_generation(
        {"registration_id": TEST_REGISTRATION_ID},
        (
            b'{"registration_id":'
            b'"reg-11111111111111111111111111111111"}\n'
        ),
    )

    assert result.value == TEST_REGISTRATION_ID
    assert result.legacy is False


def test_registration_generation_uses_exact_legacy_bytes() -> None:
    compact = registration_generation(
        {"machine_key": "a"},
        b'{"machine_key":"a"}\n',
    )
    spaced = registration_generation(
        {"machine_key": "a"},
        b'{ "machine_key": "a" }\n',
    )

    assert compact.value.startswith("legacy-sha256:")
    assert spaced.value.startswith("legacy-sha256:")
    assert compact.value != spaced.value
    assert compact.legacy is True


def test_invalid_registration_id_is_rejected() -> None:
    with pytest.raises(ControlError) as exc:
        registration_generation(
            {"registration_id": "reg-not-hex"},
            b'{"registration_id":"reg-not-hex"}\n',
        )

    assert exc.value.code == "machine_record_invalid"


def test_ready_directory_accepts_awaiting_assignment(
    tmp_path: Path,
) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    path = write_registration(
        settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )

    candidate = load_registration_candidate(path, "ready")

    assert candidate.registration_state == "ready"
    assert candidate.status == "awaiting_assignment"
    assert candidate.machine_uuid == TEST_MACHINE_UUID
    assert candidate.machine_key == TEST_MACHINE_UUID
    assert candidate.mac == "c0:9b:f4:62:54:e5"
    assert candidate.raw_bytes == path.read_bytes()


def test_candidate_normalizes_identity_values(tmp_path: Path) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    payload = registration_payload(
        machine_uuid=TEST_MACHINE_UUID.upper(),
        machine_key=TEST_MACHINE_UUID.upper(),
        mac="C0:9B:F4:62:54:E5",
    )
    path = write_registration(settings, "pending", payload)

    candidate = load_registration_candidate(path, "pending")

    assert candidate.machine_uuid == TEST_MACHINE_UUID
    assert candidate.machine_key == TEST_MACHINE_UUID
    assert candidate.mac == "c0:9b:f4:62:54:e5"


def test_candidate_rejects_symlink(tmp_path: Path) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    target = write_registration(
        settings,
        "ready",
        registration_payload(),
    )
    link = settings.registration_root / "ready" / "linked.json"
    link.symlink_to(target)

    with pytest.raises(ControlError) as exc:
        load_registration_candidate(link, "ready")

    assert exc.value.code == "machine_record_unsafe"


@pytest.mark.parametrize(
    "raw_text",
    ["[]\n", "{broken\n", '"text"\n'],
)
def test_candidate_rejects_invalid_json_shape(
    tmp_path: Path,
    raw_text: str,
) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    path = (
        settings.registration_root
        / "ready"
        / f"{TEST_MACHINE_UUID}.json"
    )
    path.parent.mkdir(parents=True)
    path.write_text(raw_text, encoding="utf-8")

    with pytest.raises(ControlError) as exc:
        load_registration_candidate(path, "ready")

    assert exc.value.code == "machine_record_invalid"


def test_candidate_rejects_missing_identity(tmp_path: Path) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    path = write_registration(
        settings,
        "pending",
        {
            "machine_key": "",
            "uuid": "",
            "hostname": "alt-lifecycle-test",
            "ip": "192.0.2.56",
            "mac": "c0:9b:f4:62:54:e5",
            "registered_at": "2026-07-21T12:00:00+00:00",
            "status": "pending",
        },
        filename="missing.json",
    )

    with pytest.raises(ControlError) as exc:
        load_registration_candidate(path, "pending")

    assert exc.value.code == "machine_record_invalid"


def test_candidate_rejects_oversized_record(tmp_path: Path) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    path = (
        settings.registration_root
        / "pending"
        / f"{TEST_MACHINE_UUID}.json"
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(b"x" * (MAX_REGISTRATION_RECORD_BYTES + 1))

    with pytest.raises(ControlError) as exc:
        load_registration_candidate(path, "pending")

    assert exc.value.code == "machine_record_unsafe"


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="FIFO creation is unavailable",
)
def test_candidate_rejects_fifo(tmp_path: Path) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    path = (
        settings.registration_root
        / "pending"
        / f"{TEST_MACHINE_UUID}.json"
    )
    path.parent.mkdir(parents=True)
    os.mkfifo(path)

    with pytest.raises(ControlError) as exc:
        load_registration_candidate(path, "pending")

    assert exc.value.code == "machine_record_unsafe"


def test_candidate_rejects_unknown_state_directory(
    tmp_path: Path,
) -> None:
    settings = make_controller_sandbox(tmp_path).settings
    path = write_registration(
        settings,
        "ready",
        registration_payload(),
    )

    with pytest.raises(ControlError) as exc:
        load_registration_candidate(path, "archived")

    assert exc.value.code == "machine_record_invalid"


def test_exclusive_lock_rejects_symlink_before_body(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.lock"
    target.touch()
    link = tmp_path / "controller.lock"
    link.symlink_to(target)
    entered = False

    with pytest.raises(ControlError) as exc:
        with exclusive_lock(link):
            entered = True

    assert exc.value.code == "controller_lock_unsafe"
    assert entered is False


def test_exclusive_lock_creates_private_regular_file(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "state" / "workstationctl.lock"

    with exclusive_lock(lock_path):
        assert lock_path.is_file()

    metadata = lock_path.stat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
