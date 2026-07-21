from __future__ import annotations

import getpass
import os
from pathlib import Path

import pytest

from alt_deploy.assignments import AssignmentRepository
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.machine_archive import MachineArchiveService
from alt_deploy.registry import MachineRepository
from support.controller_sandbox import make_controller_sandbox
from support.lifecycle_fixtures import (
    TEST_MACHINE_UUID,
    registration_payload,
    snapshot_tree,
    write_registration,
)
from support.payloads import provision_request


def operator_env() -> dict[str, str]:
    return {
        "SUDO_UID": str(os.getuid()),
        "SUDO_USER": getpass.getuser(),
    }


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


def test_preview_is_read_only(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    before = snapshot_tree(sandbox.root)

    preview = MachineArchiveService(
        sandbox.settings
    ).preview(TEST_MACHINE_UUID)

    assert preview.to_public_dict() == {
        "machine_uuid": TEST_MACHINE_UUID,
        "machine_key": TEST_MACHINE_UUID,
        "source_states": ["pending"],
        "record_count": 1,
        "assignment_present": False,
        "active_job": None,
        "action": "archive_registration_records",
    }
    assert snapshot_tree(sandbox.root) == before


def test_apply_archives_exact_bytes(tmp_path: Path) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    original = source.read_bytes()

    result = MachineArchiveService(
        sandbox.settings
    ).apply(
        TEST_MACHINE_UUID,
        "Переустановка тестовой машины",
        operator_env=operator_env(),
    )

    assert result.result == "archived"
    assert not source.exists()
    archived = (
        sandbox.settings.machine_archives_dir
        / result.archive_id
        / "records"
        / "ready.json"
    )
    assert archived.read_bytes() == original
    assert MachineRepository(sandbox.settings).list() == []


@pytest.mark.parametrize(
    "reason",
    ["", "   ", "bad\nreason", "x" * 501],
)
def test_invalid_reason_changes_nothing(
    tmp_path: Path,
    reason: str,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    before = snapshot_tree(sandbox.root)

    with pytest.raises(ControlError) as exc:
        MachineArchiveService(
            sandbox.settings
        ).apply(
            TEST_MACHINE_UUID,
            reason,
            operator_env=operator_env(),
        )

    assert exc.value.code == "invalid_archive_reason"
    assert snapshot_tree(sandbox.root) == before


def test_untrusted_sudo_identity_falls_back_safely(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )

    result = MachineArchiveService(
        sandbox.settings
    ).apply(
        TEST_MACHINE_UUID,
        "Identity fallback test",
        operator_env={
            "SUDO_UID": "999999",
            "SUDO_USER": "invented-user",
        },
    )

    manifest = (
        sandbox.settings.machine_archives_dir
        / result.archive_id
        / "manifest.json"
    )
    payload = __import__("json").loads(
        manifest.read_text(encoding="utf-8")
    )
    assert payload["operator_uid"] == os.getuid()
    assert payload["operator_username"] != "invented-user"


def test_assigned_machine_changes_nothing(tmp_path: Path) -> None:
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
    before = snapshot_tree(sandbox.root)

    with pytest.raises(ControlError) as exc:
        MachineArchiveService(
            sandbox.settings
        ).apply(
            TEST_MACHINE_UUID,
            "Assigned blocker test",
            operator_env=operator_env(),
        )

    assert exc.value.code == "machine_assigned"
    assert snapshot_tree(sandbox.root) == before


def test_busy_machine_changes_nothing_and_redacts(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    job = JobRepository(sandbox.settings).create(
        provision_request()
    )
    before = snapshot_tree(sandbox.root)

    with pytest.raises(ControlError) as exc:
        MachineArchiveService(
            sandbox.settings
        ).apply(
            TEST_MACHINE_UUID,
            "Busy blocker test",
            operator_env=operator_env(),
        )

    assert exc.value.code == "machine_busy"
    assert exc.value.details == {
        "job_id": job.job_id,
        "state": "queued",
        "stage": "created",
    }
    assert snapshot_tree(sandbox.root) == before


def test_copy_failure_leaves_source_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    service = MachineArchiveService(sandbox.settings)

    def fail_copy(transaction, candidates):
        raise ControlError(
            code="machine_archive_failed",
            message="Synthetic copy failure",
            exit_code=6,
        )

    monkeypatch.setattr(
        service.archives,
        "copy_and_verify",
        fail_copy,
    )

    with pytest.raises(ControlError) as exc:
        service.apply(
            TEST_MACHINE_UUID,
            "Test copy failure",
            operator_env=operator_env(),
        )

    assert exc.value.code == "machine_archive_failed"
    assert source.is_file()
    assert len(MachineRepository(sandbox.settings).list()) == 1


def test_postcommit_failure_hides_generation_and_reuses_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    service = MachineArchiveService(sandbox.settings)
    original_cleanup = service.archives.cleanup_sources
    failed_once = False

    def fail_once(transaction):
        nonlocal failed_once
        if not failed_once:
            failed_once = True
            raise ControlError(
                code="machine_archive_cleanup_required",
                message="Synthetic cleanup failure",
                exit_code=4,
                details={
                    "archive_id": transaction.archive_id
                },
            )
        return original_cleanup(transaction)

    monkeypatch.setattr(
        service.archives,
        "cleanup_sources",
        fail_once,
    )

    with pytest.raises(ControlError) as exc:
        service.apply(
            TEST_MACHINE_UUID,
            "Postcommit recovery test",
            operator_env=operator_env(),
        )

    archive_id = exc.value.details["archive_id"]
    assert exc.value.code == "machine_archive_cleanup_required"
    assert MachineRepository(sandbox.settings).list() == []

    recovered = service.apply(
        TEST_MACHINE_UUID,
        "Postcommit recovery test",
        operator_env=operator_env(),
    )

    assert recovered.result == "archived"
    assert recovered.archive_id == archive_id


def test_completed_repeat_returns_already_archived(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    service = MachineArchiveService(sandbox.settings)

    first = service.apply(
        TEST_MACHINE_UUID,
        "Initial archive",
        operator_env=operator_env(),
    )
    before = snapshot_tree(
        sandbox.settings.machine_archives_dir
    )
    second = service.apply(
        TEST_MACHINE_UUID,
        "Repeated archive",
        operator_env=operator_env(),
    )

    assert second.to_public_dict() == {
        "result": "already_archived",
        "archive_id": first.archive_id,
        "machine_uuid": TEST_MACHINE_UUID,
        "machine_key": TEST_MACHINE_UUID,
        "source_states": ["ready"],
    }
    assert snapshot_tree(
        sandbox.settings.machine_archives_dir
    ) == before


def test_preview_reports_completed_archive_without_mutation(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    service = MachineArchiveService(sandbox.settings)
    service.apply(
        TEST_MACHINE_UUID,
        "Initial archive",
        operator_env=operator_env(),
    )
    before = snapshot_tree(sandbox.root)

    preview = service.preview(TEST_MACHINE_UUID)

    assert preview.action == "already_archived"
    assert preview.source_states == ("ready",)
    assert preview.record_count == 0
    assert snapshot_tree(sandbox.root) == before


def test_newer_generation_at_source_path_is_not_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    source = write_registration(
        sandbox.settings,
        "pending",
        registration_payload(),
    )
    service = MachineArchiveService(sandbox.settings)
    original_cleanup = service.archives.cleanup_sources

    def block_cleanup(transaction):
        raise ControlError(
            code="machine_archive_cleanup_required",
            message="Synthetic cleanup failure",
            exit_code=4,
            details={"archive_id": transaction.archive_id},
        )

    monkeypatch.setattr(
        service.archives,
        "cleanup_sources",
        block_cleanup,
    )
    with pytest.raises(ControlError):
        service.apply(
            TEST_MACHINE_UUID,
            "Generate committed archive",
            operator_env=operator_env(),
        )

    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(
            registration_id=(
                "reg-22222222222222222222222222222222"
            )
        ),
    )
    monkeypatch.setattr(
        service.archives,
        "cleanup_sources",
        original_cleanup,
    )

    with pytest.raises(ControlError) as exc:
        service.apply(
            TEST_MACHINE_UUID,
            "Resume cleanup",
            operator_env=operator_env(),
        )

    assert exc.value.code == "machine_archive_cleanup_required"
    assert source.is_file()


def test_later_generation_creates_new_archive_id(
    tmp_path: Path,
) -> None:
    sandbox = make_controller_sandbox(tmp_path)
    write_registration(
        sandbox.settings,
        "ready",
        registration_payload(status="awaiting_assignment"),
    )
    service = MachineArchiveService(sandbox.settings)
    first = service.apply(
        TEST_MACHINE_UUID,
        "First generation",
        operator_env=operator_env(),
    )
    write_registration(
        sandbox.settings,
        "pending",
        registration_payload(
            registration_id=(
                "reg-22222222222222222222222222222222"
            )
        ),
    )

    second = service.apply(
        TEST_MACHINE_UUID,
        "Second generation",
        operator_env=operator_env(),
    )

    assert second.result == "archived"
    assert second.archive_id != first.archive_id
