from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from .errors import BackupError
from .fs import (
    assert_safe_parents,
    fsync_directory,
    read_regular_bytes,
    validate_private_directory,
)
from .jsonio import atomic_write_json
from .locks import exclusive_operation_lock
from .manifest import BACKUP_ID_RE
from .restore_journal import RESTORE_ID_RE, RestoreJournal
from .settings import BackupSettings


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_RESTORE_PHASES = frozenset({"aborted", "committed", "rolled_back"})
_ACTIVE_RESTORE_PHASES = frozenset(
    {
        "prepared",
        "staged",
        "services_stopped",
        "originals_moving",
        "originals_moved",
        "installed",
        "daemon_reloaded",
        "health_checked",
    }
)


def _blocked(message: str) -> BackupError:
    return BackupError(
        code="backup_guard_blocked",
        message=message,
        exit_code=7,
    )


def _state_error(message: str) -> BackupError:
    return BackupError(
        code="backup_rollout_state_invalid",
        message=message,
        exit_code=6,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GuardState:
    def __init__(self, settings: BackupSettings) -> None:
        self.settings = settings

    def _private_file_metadata(
        self,
        path: Path,
        error: Callable[[str], BackupError],
    ) -> os.stat_result:
        try:
            assert_safe_parents(path)
            metadata = path.lstat()
        except (OSError, BackupError) as exc:
            raise error("Guard state cannot be inspected") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != self.settings.expected_root_uid
            or metadata.st_gid != self.settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise error("Guard state metadata is unsafe")
        return metadata

    def _read_json(
        self,
        path: Path,
        error: Callable[[str], BackupError],
    ) -> tuple[dict[str, object], bytes] | None:
        try:
            assert_safe_parents(path)
        except BackupError as exc:
            raise error("Guard state path is unsafe") from exc
        if not path.exists() and not path.is_symlink():
            return None
        self._private_file_metadata(path, error)
        try:
            raw = read_regular_bytes(path, max_bytes=64 * 1024)
            payload = json.loads(raw.decode("utf-8"))
        except (BackupError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise error("Guard state JSON is invalid") from exc
        if not isinstance(payload, dict):
            raise error("Guard state JSON is invalid")
        return payload, raw

    def _ensure_runtime_root(
        self,
        error: Callable[[str], BackupError],
    ) -> None:
        root = self.settings.guard_runtime_root
        try:
            assert_safe_parents(root)
            if not root.exists() and not root.is_symlink():
                parent = root.parent
                if not parent.exists() and not parent.is_symlink():
                    if not self.settings.test_mode:
                        raise error("Guard runtime parent is missing")
                    parent.mkdir(parents=True, mode=0o755)
                try:
                    parent_metadata = parent.lstat()
                except OSError as exc:
                    raise error("Guard runtime parent is unsafe") from exc
                if (
                    not stat.S_ISDIR(parent_metadata.st_mode)
                    or stat.S_ISLNK(parent_metadata.st_mode)
                    or parent_metadata.st_uid
                    != self.settings.expected_root_uid
                    or parent_metadata.st_gid
                    != self.settings.expected_root_gid
                    or stat.S_IMODE(parent_metadata.st_mode) & 0o022
                ):
                    raise error("Guard runtime parent is unsafe")
                root.mkdir(mode=0o700)
                os.chown(
                    root,
                    self.settings.expected_root_uid,
                    self.settings.expected_root_gid,
                )
                os.chmod(root, 0o700)
                fsync_directory(parent)
            validate_private_directory(
                root,
                uid=self.settings.expected_root_uid,
                gid=self.settings.expected_root_gid,
                mode=0o700,
            )
        except BackupError as exc:
            if exc.code in {
                "backup_guard_blocked",
                "backup_rollout_state_invalid",
            }:
                raise
            raise error("Guard runtime root is unsafe") from exc
        except OSError as exc:
            raise error("Guard runtime root cannot be created") from exc

    def _write_json(
        self,
        path: Path,
        payload: dict[str, object],
        error: Callable[[str], BackupError],
    ) -> None:
        if path.parent == self.settings.guard_runtime_root:
            self._ensure_runtime_root(error)
        else:
            try:
                validate_private_directory(
                    path.parent,
                    uid=self.settings.expected_root_uid,
                    gid=self.settings.expected_root_gid,
                    mode=0o700,
                )
            except BackupError as exc:
                raise error("Guard private state root is unsafe") from exc
        if path.exists() or path.is_symlink():
            self._private_file_metadata(path, error)
        try:
            atomic_write_json(path, payload, mode=0o600)
            os.chown(
                path,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.chmod(path, 0o600)
            fsync_directory(path.parent)
        except (BackupError, OSError) as exc:
            raise error("Guard state cannot be written") from exc

    def _remove_file(
        self,
        path: Path,
        error: Callable[[str], BackupError],
    ) -> None:
        if not path.exists() and not path.is_symlink():
            return
        self._private_file_metadata(path, error)
        try:
            path.unlink()
            fsync_directory(path.parent)
        except (OSError, BackupError) as exc:
            raise error("Guard state cannot be removed") from exc

    def _marker(
        self,
        error: Callable[[str], BackupError],
    ) -> tuple[str, str] | None:
        result = self._read_json(self.settings.rollout_marker, error)
        if result is None:
            return None
        payload, raw = result
        if set(payload) != {
            "schema_version",
            "backup_id",
            "started_at",
        }:
            raise error("Rollout marker schema is invalid")
        backup_id = payload.get("backup_id")
        started_at = payload.get("started_at")
        if (
            payload.get("schema_version") != 1
            or not isinstance(backup_id, str)
            or not BACKUP_ID_RE.fullmatch(backup_id)
            or not isinstance(started_at, str)
            or not started_at
            or len(started_at) > 100
        ):
            raise error("Rollout marker values are invalid")
        return backup_id, hashlib.sha256(raw).hexdigest()

    def _permit(
        self,
        path: Path,
        kind: str,
        error: Callable[[str], BackupError],
    ) -> dict[str, object] | None:
        result = self._read_json(path, error)
        if result is None:
            return None
        payload, _ = result
        expected = {
            "schema_version",
            "kind",
            "backup_id",
            "marker_sha256",
        }
        if kind == "restore":
            expected.add("restore_id")
        if set(payload) != expected:
            raise error("Guard permit schema is invalid")
        backup_id = payload.get("backup_id")
        marker_hash = payload.get("marker_sha256")
        marker_hash_valid = (
            isinstance(marker_hash, str)
            and _DIGEST_RE.fullmatch(marker_hash) is not None
        )
        if (
            payload.get("schema_version") != 1
            or payload.get("kind") != kind
            or not isinstance(backup_id, str)
            or not BACKUP_ID_RE.fullmatch(backup_id)
            or (kind == "rollout" and not marker_hash_valid)
            or (
                kind == "restore"
                and marker_hash is not None
                and not marker_hash_valid
            )
        ):
            raise error("Guard permit values are invalid")
        if kind == "restore":
            restore_id = payload.get("restore_id")
            if (
                not isinstance(restore_id, str)
                or not RESTORE_ID_RE.fullmatch(restore_id)
            ):
                raise error("Guard restore permit is invalid")
        return payload

    def _blocking_journals(
        self,
        error: Callable[[str], BackupError],
    ) -> tuple[RestoreJournal, ...]:
        try:
            validate_private_directory(
                self.settings.backup_root,
                uid=self.settings.expected_root_uid,
                gid=self.settings.expected_root_gid,
                mode=0o700,
            )
        except BackupError as exc:
            raise error("Backup root is unsafe for guard evaluation") from exc
        root = self.settings.backup_root / ".restore-transactions"
        if not root.exists() and not root.is_symlink():
            return ()
        try:
            validate_private_directory(
                root,
                uid=self.settings.expected_root_uid,
                gid=self.settings.expected_root_gid,
                mode=0o700,
            )
            children = sorted(root.iterdir(), key=lambda item: item.name)
        except (BackupError, OSError) as exc:
            raise error("Restore transaction root is unsafe") from exc
        blocking: list[RestoreJournal] = []
        expected_error_code = error("").code
        for child in children:
            if not RESTORE_ID_RE.fullmatch(child.name):
                raise error("Restore transaction entry is invalid")
            try:
                validate_private_directory(
                    child,
                    uid=self.settings.expected_root_uid,
                    gid=self.settings.expected_root_gid,
                    mode=0o700,
                )
                self._private_file_metadata(
                    child / "journal.json",
                    error,
                )
                journal = RestoreJournal.load(
                    self.settings,
                    child.name,
                )
            except BackupError as exc:
                if exc.code == expected_error_code:
                    raise
                raise error("Restore transaction journal is invalid") from exc
            if journal.phase not in _SAFE_RESTORE_PHASES:
                blocking.append(journal)
        return tuple(blocking)

    @staticmethod
    def _rollout_matches(
        permit: dict[str, object],
        marker: tuple[str, str],
    ) -> bool:
        return (
            permit.get("backup_id") == marker[0]
            and permit.get("marker_sha256") == marker[1]
        )

    @staticmethod
    def _restore_matches(
        permit: dict[str, object],
        journal: RestoreJournal,
        marker: tuple[str, str] | None,
    ) -> bool:
        return (
            permit.get("restore_id") == journal.restore_id
            and permit.get("backup_id") == journal.backup_id
            and permit.get("marker_sha256")
            == (marker[1] if marker is not None else None)
        )

    def assert_control_plane_allowed(self) -> None:
        marker = self._marker(_blocked)
        rollout = self._permit(
            self.settings.rollout_permit,
            "rollout",
            _blocked,
        )
        restore = self._permit(
            self.settings.restore_permit,
            "restore",
            _blocked,
        )
        journals = self._blocking_journals(_blocked)
        if len(journals) > 1 or (rollout is not None and restore is not None):
            raise _blocked("Conflicting guard state blocks the control plane")
        if restore is not None:
            if (
                len(journals) == 1
                and journals[0].phase != "manual_recovery_required"
                and self._restore_matches(restore, journals[0], marker)
            ):
                return
            raise _blocked("Restore guard authorization is stale")
        if rollout is not None:
            if (
                marker is not None
                and not journals
                and self._rollout_matches(rollout, marker)
            ):
                return
            raise _blocked("Rollout guard authorization is stale")
        if marker is not None or journals:
            raise _blocked("Unfinished ALT deployment operation blocks startup")

    def begin_rollout(self, backup_id: str) -> None:
        if not BACKUP_ID_RE.fullmatch(backup_id):
            raise _state_error("Rollback backup identifier is invalid")
        with exclusive_operation_lock(self.settings):
            if self._marker(_state_error) is not None:
                raise _state_error("A rollout is already active")
            if self._blocking_journals(_state_error):
                raise _state_error("An unfinished restore blocks rollout")
            if (
                self._permit(
                    self.settings.rollout_permit,
                    "rollout",
                    _state_error,
                )
                is not None
                or self._permit(
                    self.settings.restore_permit,
                    "restore",
                    _state_error,
                )
                is not None
            ):
                raise _state_error("Stale guard authorization blocks rollout")
            self._write_json(
                self.settings.rollout_marker,
                {
                    "schema_version": 1,
                    "backup_id": backup_id,
                    "started_at": _utc_now(),
                },
                _state_error,
            )

    def authorize_rollout(self, backup_id: str) -> None:
        with exclusive_operation_lock(self.settings):
            marker = self._marker(_state_error)
            if marker is None or marker[0] != backup_id:
                raise _state_error("Rollout marker does not match")
            if self._blocking_journals(_state_error):
                raise _state_error("An unfinished restore blocks rollout")
            if self._permit(
                self.settings.restore_permit,
                "restore",
                _state_error,
            ) is not None:
                raise _state_error("Restore authorization blocks rollout")
            existing = self._permit(
                self.settings.rollout_permit,
                "rollout",
                _state_error,
            )
            if existing is not None:
                if self._rollout_matches(existing, marker):
                    return
                raise _state_error("Rollout authorization is stale")
            self._write_json(
                self.settings.rollout_permit,
                {
                    "schema_version": 1,
                    "kind": "rollout",
                    "backup_id": backup_id,
                    "marker_sha256": marker[1],
                },
                _state_error,
            )

    def revoke_rollout(self, backup_id: str) -> None:
        with exclusive_operation_lock(self.settings):
            permit = self._permit(
                self.settings.rollout_permit,
                "rollout",
                _state_error,
            )
            if permit is None:
                return
            if permit.get("backup_id") != backup_id:
                raise _state_error("Rollout authorization does not match")
            self._remove_file(self.settings.rollout_permit, _state_error)

    def complete_rollout(self, backup_id: str) -> None:
        with exclusive_operation_lock(self.settings):
            marker = self._marker(_state_error)
            permit = self._permit(
                self.settings.rollout_permit,
                "rollout",
                _state_error,
            )
            if marker is None:
                if permit is None:
                    return
                if permit.get("backup_id") != backup_id:
                    raise _state_error("Rollout authorization does not match")
                self._remove_file(self.settings.rollout_permit, _state_error)
                return
            if marker[0] != backup_id:
                raise _state_error("Rollout marker does not match")
            if permit is None or not self._rollout_matches(permit, marker):
                raise _state_error("Rollout completion is not authorized")
            self._remove_file(self.settings.rollout_marker, _state_error)
            self._remove_file(self.settings.rollout_permit, _state_error)

    def has_matching_rollout_marker_unlocked(
        self,
        journal: RestoreJournal,
    ) -> bool:
        marker = self._marker(_state_error)
        if marker is None:
            return False
        if marker[0] != journal.backup_id:
            raise _state_error("Restore backup does not match rollout marker")
        return True

    def authorize_restore_unlocked(self, journal: RestoreJournal) -> None:
        if journal.phase not in _ACTIVE_RESTORE_PHASES:
            raise _state_error("Restore phase cannot be authorized")
        marker = self._marker(_state_error)
        if marker is not None and marker[0] != journal.backup_id:
            raise _state_error("Restore backup does not match rollout marker")
        rollout = self._permit(
            self.settings.rollout_permit,
            "rollout",
            _state_error,
        )
        if rollout is not None:
            if marker is None or not self._rollout_matches(rollout, marker):
                raise _state_error("Rollout authorization is stale")
            self._remove_file(self.settings.rollout_permit, _state_error)
        existing = self._permit(
            self.settings.restore_permit,
            "restore",
            _state_error,
        )
        if existing is not None:
            if self._restore_matches(existing, journal, marker):
                return
            raise _state_error("Restore authorization is stale")
        self._write_json(
            self.settings.restore_permit,
            {
                "schema_version": 1,
                "kind": "restore",
                "restore_id": journal.restore_id,
                "backup_id": journal.backup_id,
                "marker_sha256": marker[1] if marker is not None else None,
            },
            _state_error,
        )

    def revoke_restore_unlocked(self, journal: RestoreJournal) -> None:
        permit = self._permit(
            self.settings.restore_permit,
            "restore",
            _state_error,
        )
        if permit is None:
            return
        if (
            permit.get("restore_id") != journal.restore_id
            or permit.get("backup_id") != journal.backup_id
        ):
            raise _state_error("Restore authorization does not match")
        self._remove_file(self.settings.restore_permit, _state_error)

    def complete_restore_unlocked(self, journal: RestoreJournal) -> None:
        if journal.phase != "committed":
            raise _state_error("Restore is not durably committed")
        marker = self._marker(_state_error)
        if marker is not None and marker[0] != journal.backup_id:
            raise _state_error("Committed restore does not match rollout marker")
        permit = self._permit(
            self.settings.restore_permit,
            "restore",
            _state_error,
        )
        if permit is not None:
            if (
                permit.get("restore_id") != journal.restore_id
                or permit.get("backup_id") != journal.backup_id
                or (
                    marker is not None
                    and permit.get("marker_sha256") != marker[1]
                )
            ):
                raise _state_error("Restore authorization does not match")
        if marker is not None:
            self._remove_file(self.settings.rollout_marker, _state_error)
        if permit is not None:
            self._remove_file(self.settings.restore_permit, _state_error)
