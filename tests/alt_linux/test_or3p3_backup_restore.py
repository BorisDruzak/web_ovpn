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


RESTORE_BACKUP_ID = "backup-20260722T120000Z-11111111"


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


def test_loopback_health_uses_allowlisted_static_health_endpoint(
    tmp_path: Path,
) -> None:
    sandbox = BackupSandbox.create(tmp_path)
    manifest = SimpleNamespace(
        systemd_units=(
            SimpleNamespace(
                name="alt-deploy-http.service",
                load_state="loaded",
                active_state="active",
            ),
            SimpleNamespace(
                name="alt-deploy-register.service",
                load_state="loaded",
                active_state="active",
            ),
        )
    )

    checks = sandbox.restore_service()._loopback_health(manifest)

    assert checks == ("http_loopback", "registration_loopback")
    assert sandbox.health_probe_urls == [
        "http://127.0.0.1:8087/health",
        "http://127.0.0.1:8088/health",
    ]


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
        "http://127.0.0.1:8087/health",
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


class _RecordingGuard:
    def __init__(
        self,
        *,
        failed_rollout: bool = False,
        fail_complete: bool = False,
    ) -> None:
        self.failed_rollout = failed_rollout
        self.fail_complete = fail_complete
        self.events: list[str] = []

    def authorize_restore_unlocked(self, journal: RestoreJournal) -> None:
        self.events.append(f"authorize:{journal.phase}")

    def complete_restore_unlocked(self, journal: RestoreJournal) -> None:
        self.events.append(f"complete:{journal.phase}")
        if self.fail_complete:
            raise BackupError(
                code="backup_rollout_state_invalid",
                message="Injected guard cleanup failure",
                exit_code=6,
            )

    def revoke_restore_unlocked(self, journal: RestoreJournal) -> None:
        self.events.append(f"revoke:{journal.phase}")

    def has_matching_rollout_marker_unlocked(
        self,
        journal: RestoreJournal,
    ) -> bool:
        self.events.append(f"marker:{journal.phase}")
        return self.failed_rollout


def _lightweight_restore_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    guard: _RecordingGuard,
    *,
    fail_activation: bool = False,
):
    from contextlib import nullcontext

    from alt_deploy_backup.restore import (
        PreRestoreGeneration,
        StagedGeneration,
    )
    from alt_deploy_backup.systemd import UnitState

    sandbox = BackupSandbox.create(tmp_path)
    sandbox.settings.backup_root.mkdir(parents=True, mode=0o700)
    sandbox.settings.private_state_root.mkdir(parents=True, mode=0o700)
    sandbox.settings.lifecycle_lock.parent.mkdir(parents=True, exist_ok=True)
    sandbox.settings.lifecycle_lock.write_bytes(b"")
    sandbox.settings.lifecycle_lock.chmod(0o600)
    states = tuple(
        UnitState(
            name=name,
            load_state="loaded",
            enabled_state="enabled" if not name.endswith(".service") else "static",
            active_state=(
                "inactive"
                if name == "alt-deploy-process.service"
                else "active"
            ),
            sub_state=("dead" if name == "alt-deploy-process.service" else "running"),
            failed=False,
        )
        for name in (
            "alt-deploy-http.service",
            "alt-deploy-register.service",
            "alt-deploy-process.path",
            "alt-deploy-process.service",
        )
    )
    manifest = SimpleNamespace(
        secret_identities=(),
        systemd_units=states,
    )
    verified = SimpleNamespace(manifest=manifest)
    service = sandbox.restore_service(guard_state=guard)

    monkeypatch.setattr(
        service.repository,
        "assert_rehearsed_eligibility",
        lambda backup_id: None,
    )
    monkeypatch.setattr(
        service.repository.quiescence,
        "assert_quiescent",
        lambda: None,
    )
    monkeypatch.setattr(
        service.repository.secrets,
        "assert_matches",
        lambda expected: None,
    )
    monkeypatch.setattr(
        service,
        "_assert_eligibility_unlocked",
        lambda backup_id: verified,
    )
    monkeypatch.setattr(
        service,
        "_assert_restore_capacity",
        lambda selected: None,
    )
    monkeypatch.setattr(service.repository.systemd, "capture", lambda: states)
    monkeypatch.setattr(
        service.repository.systemd,
        "stop_maintenance",
        lambda: None,
    )
    activations: list[bool] = []

    def restore_units(
        selected: object,
        *,
        activate_health_services: bool,
    ) -> None:
        activations.append(activate_health_services)
        if fail_activation and len(activations) == 1:
            raise BackupError(
                code="restore_health_check_failed",
                message="Injected activation failure",
                exit_code=4,
            )

    monkeypatch.setattr(
        service.repository.systemd,
        "restore",
        restore_units,
    )

    def snapshot(journal: RestoreJournal) -> PreRestoreGeneration:
        root = (
            sandbox.settings.backup_root
            / "pre-restore-test"
            / journal.restore_id
        )
        root.mkdir(parents=True)
        return PreRestoreGeneration(
            root=root,
            components=(),
            manifest_sha256="1" * 64,
        )

    def stage(
        backup_id: str,
        journal: RestoreJournal,
    ) -> StagedGeneration:
        extracted = journal.directory / "extracted"
        extracted.mkdir()
        journal.transition("prepared", "staged", {"paths": []})
        return StagedGeneration(
            backup_id=backup_id,
            restore_id=journal.restore_id,
            extracted_root=extracted,
            paths=(),
            manifest=manifest,
        )

    monkeypatch.setattr(service, "create_pre_restore_snapshot", snapshot)
    monkeypatch.setattr(service, "stage", stage)
    monkeypatch.setattr(
        service,
        "_staged_lifecycle_lock",
        lambda staged: nullcontext(),
    )
    monkeypatch.setattr(
        service,
        "_move_originals",
        lambda staged, journal, moving: (),
    )
    monkeypatch.setattr(service, "_install_staged", lambda staged: None)
    monkeypatch.setattr(service, "_daemon_reload", lambda: None)
    monkeypatch.setattr(
        service,
        "_pre_activation_health",
        lambda selected: (),
    )
    monkeypatch.setattr(service, "_loopback_health", lambda selected: ())
    monkeypatch.setattr(service, "_cleanup_after_commit", lambda staged: True)
    monkeypatch.setattr(
        service,
        "_cleanup_recovery_paths",
        lambda paths, journal: True,
    )
    return sandbox, service, activations


def test_restore_commits_before_guard_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _RecordingGuard()
    _, service, activations = _lightweight_restore_service(
        tmp_path,
        monkeypatch,
        guard,
    )

    result = service.restore(RESTORE_BACKUP_ID)

    assert result.phase == "committed"
    assert guard.events == [
        "authorize:daemon_reloaded",
        "complete:committed",
    ]
    assert activations == [True]


def test_committed_restore_guard_cleanup_failure_stops_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _RecordingGuard(fail_complete=True)
    sandbox, service, _ = _lightweight_restore_service(
        tmp_path,
        monkeypatch,
        guard,
    )
    stops: list[str] = []
    monkeypatch.setattr(
        service.repository.systemd,
        "stop_maintenance",
        lambda: stops.append("stopped"),
    )

    with pytest.raises(BackupError) as error:
        service.restore(RESTORE_BACKUP_ID)

    assert error.value.code == "backup_rollout_state_invalid"
    assert stops == ["stopped", "stopped"]
    assert sandbox.latest_restore_phase() == "committed"


def test_restore_rollback_preserves_failed_rollout_guard_and_stops_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _RecordingGuard(failed_rollout=True)
    sandbox, service, activations = _lightweight_restore_service(
        tmp_path,
        monkeypatch,
        guard,
        fail_activation=True,
    )

    with pytest.raises(BackupError) as error:
        service.restore(RESTORE_BACKUP_ID)

    assert error.value.code == "restore_health_check_failed"
    assert activations == [True, False]
    assert guard.events == [
        "authorize:daemon_reloaded",
        "marker:daemon_reloaded",
        "revoke:daemon_reloaded",
    ]
    assert sandbox.latest_restore_phase() == "rolled_back"


def test_recover_committed_finishes_guard_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _RecordingGuard()
    sandbox, service, _ = _lightweight_restore_service(
        tmp_path,
        monkeypatch,
        guard,
    )
    journal = RestoreJournal.create(
        sandbox.settings,
        RESTORE_BACKUP_ID,
    )
    journal.transition("prepared", "staged", {"paths": []})
    journal.transition("staged", "services_stopped", {})
    journal.transition("services_stopped", "originals_moving", {})
    journal.transition("originals_moving", "originals_moved", {})
    journal.transition("originals_moved", "installed", {})
    journal.transition("installed", "daemon_reloaded", {})
    journal.transition("daemon_reloaded", "health_checked", {})
    journal.transition("health_checked", "committed", {})
    monkeypatch.setattr(
        service,
        "_staged_paths_from_journal",
        lambda selected: (),
    )

    result = service.recover(journal.restore_id)

    assert result.phase == "committed"
    assert guard.events == ["complete:committed"]
