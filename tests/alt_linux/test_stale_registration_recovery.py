from __future__ import annotations

import hashlib
from pathlib import Path

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.stale_registration_recovery import (
    StaleRegistrationRecoveryService,
)
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_UUID,
    registration_payload,
    write_registration,
)


def test_recovery_documentation_forbids_direct_json_edit() -> None:
    readme = (
        Path(__file__).resolve().parents[2]
        / "deploy"
        / "alt-linux"
        / "README.md"
    ).read_text(encoding="utf-8")
    assert "recover-stale-registration" in readme
    assert "Do not edit registration JSON directly" in readme


def assignment_payload() -> dict[str, object]:
    return {
        "machine_uuid": TEST_MACHINE_UUID,
        "employee_login": "test-user",
        "employee_full_name": "Test User",
        "final_hostname": "alt-test",
        "profile": "standard",
        "job_id": "job-test",
        "completed_at": "2026-07-21T12:30:00+00:00",
        "verification": {"hostname": True},
    }


def test_preview_and_apply_archive_exact_legacy_failed_record(
    tmp_path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "failed",
        registration_payload(status="awaiting_assignment"),
    )
    original = source.read_bytes()
    AssignmentRepository(sandbox.settings).write(
        TEST_MACHINE_UUID,
        assignment_payload(),
    )

    service = StaleRegistrationRecoveryService(sandbox.settings)
    preview = service.preview(TEST_MACHINE_UUID)

    assert preview.to_public_dict()["record_sha256"] == hashlib.sha256(
        original
    ).hexdigest()
    assert source.exists()

    result = service.apply(
        TEST_MACHINE_UUID,
        "Clear legacy failed registration",
    )

    archive = (
        sandbox.settings.machine_archives_dir
        / result.recovery_id
        / "records"
        / "failed.json"
    )
    assert archive.read_bytes() == original
    assert not source.exists()
    assert AssignmentRepository(sandbox.settings).get(
        TEST_MACHINE_UUID
    ) is not None


def test_apply_archives_legacy_ready_awaiting_record(tmp_path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    AssignmentRepository(sandbox.settings).write(
        TEST_MACHINE_UUID,
        assignment_payload(),
    )
    original = source.read_bytes()

    result = StaleRegistrationRecoveryService(
        sandbox.settings
    ).apply(TEST_MACHINE_UUID, "Clear legacy ready registration")

    archive = (
        sandbox.settings.machine_archives_dir
        / result.recovery_id
        / "records"
        / "ready.json"
    )
    assert archive.read_bytes() == original
    assert not source.exists()
