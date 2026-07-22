from __future__ import annotations

from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from alt_deploy_backup.restore_journal import RestoreJournal
from support.backup_restore_sandbox import BackupSandbox


def test_restore_journal_rejects_skipped_phase(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    journal = RestoreJournal.create(
        sandbox.settings,
        "backup-20260722T120000Z-11111111",
    )

    with pytest.raises(BackupError) as error:
        journal.transition("prepared", "installed", {})

    assert error.value.code == "restore_staging_failed"
    assert journal.phase == "prepared"


def test_staging_failure_does_not_change_production(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    before = sandbox.production_snapshot()
    journal = sandbox.prepare_restore(backup_id)

    with pytest.raises(BackupError) as error:
        sandbox.restore_service(
            fail_stage_component="registration_state"
        ).stage(backup_id, journal)

    assert error.value.code == "restore_staging_failed"
    assert sandbox.production_snapshot() == before
    assert not list(sandbox.root.rglob(".alt-deploy-*-stage-*"))


def test_copy_path_streams_regular_file_without_bulk_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    source = sandbox.root / "large-source.bin"
    destination = sandbox.root / "large-copy.bin"
    source.write_bytes(b"streaming-block" * 400_000)

    def reject_bulk_read(*args: object, **kwargs: object) -> bytes:
        del args, kwargs
        raise AssertionError("bulk read is forbidden for restore copy")

    monkeypatch.setattr(
        "alt_deploy_backup.restore.read_regular_bytes",
        reject_bulk_read,
    )
    sandbox.restore_service()._copy_path(source, destination)

    assert destination.read_bytes() == source.read_bytes()


def test_pre_restore_generation_covers_all_six_components(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    transaction = sandbox.prepare_restore(backup_id)

    snapshot = sandbox.restore_service().create_pre_restore_snapshot(
        transaction
    )

    assert set(snapshot.components) == {
        "runtime",
        "systemd",
        "ansible",
        "controller_state",
        "registration_state",
        "deployment_assets",
    }
    assert len(snapshot.manifest_sha256) == 64
    assert snapshot.root.is_dir()


def test_pre_restore_snapshot_allocation_retries_collision(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    transaction = sandbox.prepare_restore(backup_id)
    service = sandbox.restore_service()

    first = service.create_pre_restore_snapshot(transaction)
    second = service.create_pre_restore_snapshot(transaction)

    assert first.root != second.root
    assert first.root.is_dir()
    assert second.root.is_dir()


def test_staging_uses_same_filesystem_siblings(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    transaction = sandbox.prepare_restore(backup_id)

    staged = sandbox.restore_service().stage(backup_id, transaction)

    assert len(staged.paths) >= 6
    for path in staged.paths:
        if path.staged_path is not None:
            assert path.staged_path.parent == path.production_path.parent
            assert (
                path.staged_path.lstat().st_dev
                == path.production_path.parent.lstat().st_dev
            )


def test_partial_original_move_failure_self_reverses(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.mutate_every_production_component()
    before = sandbox.production_snapshot()

    with pytest.raises(BackupError) as error:
        sandbox.restore_service(fail_move_after=2).restore(backup_id)

    assert error.value.code == "restore_staging_failed"
    assert sandbox.production_snapshot() == before
    assert sandbox.latest_restore_phase() == "services_stopped"


def test_restore_replaces_all_components_and_uses_backup_unit_state(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    expected = sandbox.production_snapshot()
    expected_units = sandbox.managed_unit_snapshot()
    sandbox.mutate_every_production_component()

    result = sandbox.restore_service().restore(backup_id)

    assert result.phase == "committed"
    assert result.rollback_performed is False
    assert result.cleanup_complete is True
    assert sandbox.production_snapshot() == expected
    assert sandbox.managed_unit_snapshot() == expected_units
    assert sandbox.latest_restore_phase() == "committed"
    assert set(sandbox.health_probe_urls) == {
        "http://127.0.0.1:8087/",
        "http://127.0.0.1:8088/health",
    }


def test_post_commit_cleanup_failure_never_rolls_back(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    expected = sandbox.production_snapshot()
    sandbox.mutate_every_production_component()

    result = sandbox.restore_service(fail_cleanup=True).restore(backup_id)

    assert result.phase == "committed"
    assert result.cleanup_complete is False
    assert result.rollback_performed is False
    assert sandbox.production_snapshot() == expected
    assert sandbox.latest_restore_phase() == "committed"


def test_health_failure_rolls_back_to_pre_restore_generation(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.mutate_every_production_component()
    before = sandbox.production_snapshot()

    with pytest.raises(BackupError) as error:
        sandbox.restore_service(
            fail_health_check="ansible_syntax"
        ).restore(backup_id)

    assert error.value.code == "restore_health_check_failed"
    assert sandbox.production_snapshot() == before
    assert sandbox.latest_restore_phase() == "rolled_back"


def test_failed_rollback_stops_maintenance_units(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.mutate_every_production_component()

    with pytest.raises(BackupError) as error:
        sandbox.restore_service(
            fail_health_check="runtime_syntax",
            fail_rollback=True,
        ).restore(backup_id)

    assert error.value.code == "restore_manual_recovery_required"
    assert sandbox.maintenance_units_are_stopped()
    assert sandbox.latest_restore_phase() == "manual_recovery_required"


def test_restore_removes_path_recorded_absent(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    sandbox.remove_runtime_api_before_backup()
    backup_id = sandbox.repository().create().backup_id
    sandbox.repository().verify(backup_id, write_evidence=True)
    sandbox.rehearsal_service().rehearse(backup_id)
    sandbox.settings.runtime_api_root.mkdir(parents=True)
    (sandbox.settings.runtime_api_root / "new.py").write_text(
        "print('new')\n",
        encoding="utf-8",
    )

    result = sandbox.restore_service().restore(backup_id)

    assert result.phase == "committed"
    assert not sandbox.settings.runtime_api_root.exists()
