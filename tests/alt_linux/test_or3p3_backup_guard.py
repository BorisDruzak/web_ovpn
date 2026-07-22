from __future__ import annotations

import json
import shutil
import stat
from pathlib import Path

import pytest

from alt_deploy_backup.errors import BackupError
from alt_deploy_backup.guard import GuardState
from alt_deploy_backup.restore_journal import RestoreJournal
from support.backup_sandbox import BackupSandbox


BACKUP_ID = "backup-20260722T120000Z-11111111"


def _guard(tmp_path: Path) -> tuple[BackupSandbox, GuardState]:
    sandbox = BackupSandbox.create(tmp_path)
    for path in (
        sandbox.settings.backup_root,
        sandbox.settings.private_state_root,
    ):
        path.mkdir(parents=True, mode=0o700)
        path.chmod(0o700)
    return sandbox, GuardState(sandbox.settings)


def _journal(sandbox: BackupSandbox) -> RestoreJournal:
    return RestoreJournal.create(sandbox.settings, BACKUP_ID)


def _commit_journal(journal: RestoreJournal) -> None:
    journal.transition("prepared", "staged", {})
    journal.transition("staged", "services_stopped", {})
    journal.transition("services_stopped", "originals_moving", {})
    journal.transition("originals_moving", "originals_moved", {})
    journal.transition("originals_moved", "installed", {})
    journal.transition("installed", "daemon_reloaded", {})
    journal.transition("daemon_reloaded", "health_checked", {})
    journal.transition("health_checked", "committed", {})


def test_guard_allows_clean_state(tmp_path: Path) -> None:
    _, guard = _guard(tmp_path)

    guard.assert_control_plane_allowed()


def test_rollout_marker_blocks_until_exact_ephemeral_authorization(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    guard.begin_rollout(BACKUP_ID)

    with pytest.raises(BackupError) as error:
        guard.assert_control_plane_allowed()

    assert error.value.code == "backup_guard_blocked"
    guard.authorize_rollout(BACKUP_ID)
    guard.assert_control_plane_allowed()

    shutil.rmtree(sandbox.settings.guard_runtime_root)
    with pytest.raises(BackupError) as reboot_error:
        guard.assert_control_plane_allowed()
    assert reboot_error.value.code == "backup_guard_blocked"


def test_rollout_completion_removes_marker_then_permit_idempotently(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    guard.begin_rollout(BACKUP_ID)
    guard.authorize_rollout(BACKUP_ID)

    guard.complete_rollout(BACKUP_ID)
    guard.complete_rollout(BACKUP_ID)

    assert not sandbox.settings.rollout_marker.exists()
    assert not sandbox.settings.rollout_permit.exists()
    guard.assert_control_plane_allowed()


def test_nonterminal_restore_requires_exact_restore_permit(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    journal = _journal(sandbox)

    with pytest.raises(BackupError) as error:
        guard.assert_control_plane_allowed()
    assert error.value.code == "backup_guard_blocked"

    guard.authorize_restore_unlocked(journal)
    guard.assert_control_plane_allowed()
    guard.revoke_restore_unlocked(journal)

    with pytest.raises(BackupError):
        guard.assert_control_plane_allowed()


def test_manual_recovery_journal_always_blocks_control_plane(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    journal = _journal(sandbox)
    guard.authorize_restore_unlocked(journal)
    journal.transition(
        "prepared",
        "manual_recovery_required",
        {"services_stopped": True},
    )

    with pytest.raises(BackupError) as error:
        guard.assert_control_plane_allowed()

    assert error.value.code == "backup_guard_blocked"


def test_restore_authorization_replaces_matching_rollout_permit(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    guard.begin_rollout(BACKUP_ID)
    guard.authorize_rollout(BACKUP_ID)
    journal = _journal(sandbox)

    guard.authorize_restore_unlocked(journal)

    assert not sandbox.settings.rollout_permit.exists()
    assert sandbox.settings.restore_permit.is_file()
    guard.assert_control_plane_allowed()


def test_restore_completion_requires_committed_journal_and_clears_marker(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    guard.begin_rollout(BACKUP_ID)
    journal = _journal(sandbox)
    guard.authorize_restore_unlocked(journal)

    with pytest.raises(BackupError) as error:
        guard.complete_restore_unlocked(journal)
    assert error.value.code == "backup_rollout_state_invalid"
    assert sandbox.settings.rollout_marker.is_file()

    _commit_journal(journal)
    guard.complete_restore_unlocked(journal)

    assert not sandbox.settings.rollout_marker.exists()
    assert not sandbox.settings.restore_permit.exists()
    guard.assert_control_plane_allowed()


def test_restore_rollback_preserves_rollout_marker_and_revokes_permit(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    guard.begin_rollout(BACKUP_ID)
    journal = _journal(sandbox)
    guard.authorize_restore_unlocked(journal)

    guard.revoke_restore_unlocked(journal)

    assert sandbox.settings.rollout_marker.is_file()
    assert not sandbox.settings.restore_permit.exists()
    with pytest.raises(BackupError):
        guard.assert_control_plane_allowed()


def test_malformed_or_stale_guard_state_fails_closed(tmp_path: Path) -> None:
    sandbox, guard = _guard(tmp_path)
    sandbox.settings.rollout_marker.write_text("{}", encoding="utf-8")
    sandbox.settings.rollout_marker.chmod(0o600)

    with pytest.raises(BackupError) as malformed:
        guard.assert_control_plane_allowed()
    assert malformed.value.code == "backup_guard_blocked"

    sandbox.settings.rollout_marker.unlink()
    sandbox.settings.guard_runtime_root.mkdir(parents=True, mode=0o700)
    sandbox.settings.rollout_permit.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "rollout",
                "backup_id": BACKUP_ID,
                "marker_sha256": "0" * 64,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    sandbox.settings.rollout_permit.chmod(0o600)

    with pytest.raises(BackupError) as stale:
        guard.assert_control_plane_allowed()
    assert stale.value.code == "backup_guard_blocked"


def test_rollout_permit_requires_exact_marker_digest(tmp_path: Path) -> None:
    sandbox, guard = _guard(tmp_path)
    guard.begin_rollout(BACKUP_ID)
    sandbox.settings.guard_runtime_root.mkdir(parents=True, mode=0o700)
    sandbox.settings.rollout_permit.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "rollout",
                "backup_id": BACKUP_ID,
                "marker_sha256": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    sandbox.settings.rollout_permit.chmod(0o600)

    with pytest.raises(BackupError) as error:
        guard.authorize_rollout(BACKUP_ID)

    assert error.value.code == "backup_rollout_state_invalid"
    assert error.value.message == "Guard permit values are invalid"


def test_restore_authorization_rejects_terminal_journal(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    journal = _journal(sandbox)
    _commit_journal(journal)

    with pytest.raises(BackupError) as error:
        guard.authorize_restore_unlocked(journal)

    assert error.value.code == "backup_rollout_state_invalid"
    assert not sandbox.settings.restore_permit.exists()


def test_guard_files_are_private_root_state(tmp_path: Path) -> None:
    sandbox, guard = _guard(tmp_path)
    guard.begin_rollout(BACKUP_ID)
    guard.authorize_rollout(BACKUP_ID)

    assert stat.S_IMODE(sandbox.settings.rollout_marker.stat().st_mode) == 0o600
    assert stat.S_IMODE(sandbox.settings.rollout_permit.stat().st_mode) == 0o600
    assert (
        stat.S_IMODE(
            sandbox.settings.guard_runtime_root.stat().st_mode
        )
        == 0o700
    )


def test_guard_rejects_symlinked_runtime_state_even_when_empty(
    tmp_path: Path,
) -> None:
    sandbox, guard = _guard(tmp_path)
    outside = tmp_path / "outside-runtime"
    outside.mkdir()
    sandbox.settings.guard_runtime_root.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    sandbox.settings.guard_runtime_root.symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(BackupError) as error:
        guard.assert_control_plane_allowed()

    assert error.value.code == "backup_guard_blocked"


def test_guard_cli_exposes_only_exact_rollout_operations(
    tmp_path: Path,
) -> None:
    sandbox, _ = _guard(tmp_path)

    clean = sandbox.run_cli("guard", effective_uid=0)
    started = sandbox.run_cli(
        "rollout-begin",
        BACKUP_ID,
        effective_uid=0,
    )

    assert json.loads(clean.stdout)["result"] == "control_plane_allowed"
    assert json.loads(started.stdout) == {
        "status": "ok",
        "result": "rollout_started",
        "backup_id": BACKUP_ID,
    }
    assert sandbox.settings.rollout_marker.is_file()


def test_guard_systemd_unit_is_required_by_all_control_plane_units() -> None:
    repository = Path(__file__).resolve().parents[2]
    guard_unit = (
        repository
        / "deploy"
        / "alt-linux"
        / "backup"
        / "alt-deploy-guard.service"
    ).read_text(encoding="utf-8")

    assert "Type=oneshot" in guard_unit
    assert "ExecStart=/usr/local/sbin/alt-deploy-backup guard" in guard_unit
    assert "RemainAfterExit" not in guard_unit
    assert "ReadWritePaths=/var/log/alt-deploy-backup.log" in guard_unit

    for name in (
        "alt-deploy-http.service",
        "alt-deploy-register.service",
        "alt-deploy-process.path",
        "alt-deploy-process.service",
    ):
        unit = (
            repository / "deploy" / "alt-linux" / "systemd" / name
        ).read_text(encoding="utf-8")
        assert "Requires=alt-deploy-guard.service" in unit
        assert "After=alt-deploy-guard.service" in unit
