from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from alt_deploy_backup.archive import ArchiveInspection, ArchiveMember
from alt_deploy_backup.components import component_specs
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


def test_restore_journal_accepts_durable_move_progress(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    journal = RestoreJournal.create(
        sandbox.settings,
        "backup-20260722T120000Z-11111111",
    )
    journal.transition("prepared", "staged", {"paths": []})
    journal.transition("staged", "services_stopped", {})
    journal.transition(
        "services_stopped",
        "originals_moving",
        {"paths": []},
    )
    journal.record_phase({"paths": [{"processed": True}]})
    journal.transition(
        "originals_moving",
        "rolled_back",
        {"proof": "content_digests_match"},
    )

    assert journal.phase == "rolled_back"


def test_restore_journal_accepts_pre_mutation_abort(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    journal = RestoreJournal.create(
        sandbox.settings,
        "backup-20260722T120000Z-11111111",
    )
    journal.transition("prepared", "staged", {"paths": []})

    journal.transition("staged", "aborted", {"production_changed": False})

    assert journal.phase == "aborted"


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
    assert sandbox.latest_restore_phase() == "rolled_back"


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


def test_restore_staging_failure_records_terminal_aborted(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    before = sandbox.production_snapshot()
    before_units = sandbox.managed_unit_snapshot()

    with pytest.raises(BackupError) as error:
        sandbox.restore_service(
            fail_stage_component="registration_state"
        ).restore(backup_id)

    assert error.value.code == "restore_staging_failed"
    assert sandbox.production_snapshot() == before
    assert sandbox.managed_unit_snapshot() == before_units
    assert sandbox.latest_restore_phase() == "aborted"


def test_partial_move_rollback_failure_requires_manual_recovery(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.mutate_every_production_component()

    with pytest.raises(BackupError) as error:
        sandbox.restore_service(
            fail_move_after=2,
            fail_rollback=True,
        ).restore(backup_id)

    assert error.value.code == "restore_manual_recovery_required"
    assert sandbox.latest_restore_phase() == "manual_recovery_required"
    assert sandbox.maintenance_units_are_stopped()


def test_recover_rolls_back_interrupted_original_moves(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.mutate_every_production_component()
    before = sandbox.production_snapshot()

    with pytest.raises(RuntimeError, match="simulated restore interruption"):
        sandbox.restore_service(
            interrupt_move_after=2
        ).restore(backup_id)

    restore_id = sandbox.latest_restore_id()
    assert restore_id is not None
    assert sandbox.latest_restore_phase() == "originals_moving"

    result = sandbox.restore_service().recover(restore_id)

    assert result.phase == "rolled_back"
    assert result.rollback_performed is True
    assert sandbox.production_snapshot() == before
    assert sandbox.latest_restore_phase() == "rolled_back"


def test_recover_is_idempotent_after_rollback(tmp_path: Path) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    backup_id = sandbox.create_rehearsed_backup()
    sandbox.mutate_every_production_component()

    with pytest.raises(RuntimeError, match="simulated restore interruption"):
        sandbox.restore_service(
            interrupt_move_after=1
        ).restore(backup_id)

    restore_id = sandbox.latest_restore_id()
    assert restore_id is not None
    first = sandbox.restore_service().recover(restore_id)
    second = sandbox.restore_service().recover(restore_id)

    assert first.phase == "rolled_back"
    assert second.phase == "rolled_back"
    assert second.rollback_performed is True


def test_restore_capacity_failure_precedes_journal_and_service_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    service = sandbox.restore_service()
    backup_id = "backup-20260722T120000Z-11111111"
    verified = SimpleNamespace()
    calls: list[object] = []

    monkeypatch.setattr(
        service.repository,
        "assert_rehearsed_eligibility",
        lambda selected: None,
    )
    monkeypatch.setattr(
        service.repository.quiescence,
        "assert_quiescent",
        lambda: None,
    )
    monkeypatch.setattr(
        service,
        "_assert_eligibility_unlocked",
        lambda selected: verified,
    )

    def reject_capacity(selected: object) -> None:
        calls.append(selected)
        raise BackupError(
            code="restore_staging_failed",
            message="Insufficient free space for restore",
            exit_code=4,
        )

    monkeypatch.setattr(
        service,
        "_assert_restore_capacity",
        reject_capacity,
        raising=False,
    )
    monkeypatch.setattr(
        service.repository.systemd,
        "capture",
        lambda: (_ for _ in ()).throw(
            AssertionError("service state inspected before capacity")
        ),
    )

    with pytest.raises(BackupError) as error:
        service.restore(backup_id)

    assert error.value.code == "restore_staging_failed"
    assert calls == [verified]
    assert not (
        sandbox.settings.backup_root / ".restore-transactions"
    ).exists()


def test_restore_capacity_groups_one_probe_per_filesystem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    service = sandbox.restore_service()
    specifications = component_specs(sandbox.settings)
    records: list[object] = []
    inspections: dict[str, ArchiveInspection] = {}

    for specification in specifications:
        path_records: list[object] = []
        members: list[ArchiveMember] = []
        for source in specification.paths:
            logical = service.repository.archive_engine._logical_path(
                source
            )
            path_records.append(
                SimpleNamespace(absolute_path=logical, present=True)
            )
            members.append(
                ArchiveMember(
                    name=(
                        f"{specification.namespace}/"
                        f"{logical.lstrip('/')}"
                    ),
                    kind="regular",
                    size=1024,
                    mode=0o600,
                    uid=sandbox.settings.expected_root_uid,
                    gid=sandbox.settings.expected_root_gid,
                    link_name=None,
                )
            )
        records.append(
            SimpleNamespace(
                filename=specification.filename,
                namespace=specification.namespace,
                paths=tuple(path_records),
            )
        )
        inspections[specification.filename] = ArchiveInspection(
            members=tuple(members),
            total_size=sum(member.size for member in members),
        )

    verified = SimpleNamespace(
        path=tmp_path / "bundle",
        manifest=SimpleNamespace(components=tuple(records)),
    )
    monkeypatch.setattr(
        service.repository.archive_engine,
        "inspect",
        lambda specification, path: inspections[path.name],
    )
    monkeypatch.setattr(
        service.repository,
        "_source_paths",
        lambda specifications: (),
    )
    monkeypatch.setattr(
        "alt_deploy_backup.restore.source_inventory",
        lambda paths: (),
        raising=False,
    )
    monkeypatch.setattr(
        service,
        "_capacity_device",
        lambda path: 7,
        raising=False,
    )
    probes: list[Path] = []

    def no_free_space(path: str | Path):
        probes.append(Path(path))
        return shutil._ntuple_diskusage(1024, 1024, 0)

    monkeypatch.setattr(shutil, "disk_usage", no_free_space)

    with pytest.raises(BackupError) as error:
        service._assert_restore_capacity(verified)

    assert error.value.code == "restore_staging_failed"
    assert len(probes) == 1
