from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .errors import BackupError
from .fs import fsync_directory, read_regular_bytes
from .jsonio import atomic_write_json
from .manifest import BACKUP_ID_RE
from .settings import BackupSettings


RESTORE_ID_RE = __import__("re").compile(
    r"^restore-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)
_FORWARD = {
    "prepared": "staged",
    "staged": "services_stopped",
    "services_stopped": "originals_moving",
    "originals_moving": "originals_moved",
    "originals_moved": "installed",
    "installed": "daemon_reloaded",
    "daemon_reloaded": "health_checked",
    "health_checked": "committed",
}
_PRE_MUTATION = frozenset(
    {"prepared", "staged", "services_stopped"}
)
_AFTER_MUTATION = frozenset(
    {
        "originals_moving",
        "originals_moved",
        "installed",
        "daemon_reloaded",
        "health_checked",
    }
)
_TERMINAL = frozenset(
    {
        "aborted",
        "committed",
        "rolled_back",
        "manual_recovery_required",
    }
)


def terminal_phases() -> frozenset[str]:
    return _TERMINAL


def _error(message: str) -> BackupError:
    return BackupError(
        code="restore_staging_failed",
        message=message,
        exit_code=4,
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_evidence(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        raise _error("Restore journal evidence is too deeply nested")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if len(value) > 4096:
            raise _error("Restore journal evidence value is too large")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > 10_000:
            raise _error("Restore journal evidence collection is too large")
        return [
            _safe_evidence(item, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, Mapping):
        if len(value) > 10_000:
            raise _error("Restore journal evidence object is too large")
        result: dict[str, object] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if any(
                forbidden in lowered
                for forbidden in (
                    "password",
                    "private_key",
                    "secret",
                    "vault_value",
                )
            ):
                raise _error("Restore journal evidence key is prohibited")
            result[key] = _safe_evidence(item, depth=depth + 1)
        return result
    raise _error("Restore journal evidence type is invalid")


@dataclass
class RestoreJournal:
    settings: BackupSettings
    restore_id: str
    backup_id: str
    directory: Path
    phase: str
    created_at: str
    updated_at: str
    evidence: dict[str, object]

    @property
    def path(self) -> Path:
        return self.directory / "journal.json"

    @classmethod
    def create(
        cls,
        settings: BackupSettings,
        backup_id: str,
    ) -> "RestoreJournal":
        if not BACKUP_ID_RE.fullmatch(backup_id):
            raise _error("Restore backup identifier is invalid")
        transactions = settings.backup_root / ".restore-transactions"
        if not transactions.exists() and not transactions.is_symlink():
            try:
                transactions.mkdir(mode=0o700)
                os.chown(
                    transactions,
                    settings.expected_root_uid,
                    settings.expected_root_gid,
                )
                os.chmod(transactions, 0o700)
                fsync_directory(transactions.parent)
            except (OSError, BackupError) as exc:
                raise _error(
                    "Restore transaction root cannot be created"
                ) from exc
        try:
            metadata = transactions.lstat()
        except OSError as exc:
            raise _error(
                "Restore transaction root cannot be inspected"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != settings.expected_root_uid
            or metadata.st_gid != settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise _error("Restore transaction root is unsafe")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory: Path | None = None
        restore_id = ""
        for _ in range(20):
            restore_id = f"restore-{timestamp}-{secrets.token_hex(4)}"
            candidate = transactions / restore_id
            try:
                candidate.mkdir(mode=0o700)
                os.chown(
                    candidate,
                    settings.expected_root_uid,
                    settings.expected_root_gid,
                )
                os.chmod(candidate, 0o700)
                fsync_directory(transactions)
                directory = candidate
                break
            except FileExistsError:
                continue
            except (OSError, BackupError) as exc:
                raise _error(
                    "Restore transaction cannot be created"
                ) from exc
        if directory is None:
            raise _error("Restore identifier allocation failed")
        timestamp_text = _utc_now()
        journal = cls(
            settings=settings,
            restore_id=restore_id,
            backup_id=backup_id,
            directory=directory,
            phase="prepared",
            created_at=timestamp_text,
            updated_at=timestamp_text,
            evidence={},
        )
        journal._write()
        return journal

    @classmethod
    def load(
        cls,
        settings: BackupSettings,
        restore_id: str,
    ) -> "RestoreJournal":
        if not RESTORE_ID_RE.fullmatch(restore_id):
            raise _error("Restore identifier is invalid")
        directory = (
            settings.backup_root
            / ".restore-transactions"
            / restore_id
        )
        raw = read_regular_bytes(
            directory / "journal.json",
            max_bytes=16 * 1024 * 1024,
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _error("Restore journal JSON is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "restore_id",
            "backup_id",
            "phase",
            "created_at",
            "updated_at",
            "evidence",
        }:
            raise _error("Restore journal schema is invalid")
        if (
            payload.get("schema_version") != 1
            or payload.get("restore_id") != restore_id
            or not BACKUP_ID_RE.fullmatch(
                str(payload.get("backup_id") or "")
            )
            or payload.get("phase")
            not in (set(_FORWARD) | set(_FORWARD.values()) | _TERMINAL)
            or not isinstance(payload.get("evidence"), dict)
        ):
            raise _error("Restore journal values are invalid")
        return cls(
            settings=settings,
            restore_id=restore_id,
            backup_id=str(payload["backup_id"]),
            directory=directory,
            phase=str(payload["phase"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            evidence=dict(payload["evidence"]),
        )

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "restore_id": self.restore_id,
            "backup_id": self.backup_id,
            "phase": self.phase,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence": dict(self.evidence),
        }

    def _write(self) -> None:
        atomic_write_json(self.path, self._payload(), mode=0o600)
        try:
            os.chown(
                self.path,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.chmod(self.path, 0o600)
            fsync_directory(self.directory)
        except (OSError, BackupError) as exc:
            raise _error(
                "Restore journal cannot be synchronized"
            ) from exc

    def transition(
        self,
        expected: str,
        target: str,
        evidence: Mapping[str, object],
    ) -> None:
        if self.phase != expected:
            raise _error("Restore journal phase changed unexpectedly")
        allowed = _FORWARD.get(expected) == target
        if target == "aborted":
            allowed = expected in _PRE_MUTATION
        elif target == "rolled_back":
            allowed = expected in _AFTER_MUTATION
        elif target == "manual_recovery_required":
            allowed = expected not in _TERMINAL
        if not allowed:
            raise _error("Restore journal phase transition is invalid")
        safe = _safe_evidence(evidence)
        if not isinstance(safe, dict):
            raise _error("Restore journal transition evidence is invalid")
        self.phase = target
        self.updated_at = _utc_now()
        self.evidence[target] = safe
        self._write()

    def record_phase(self, evidence: Mapping[str, object]) -> None:
        if self.phase in _TERMINAL:
            raise _error("Restore terminal journal cannot be updated")
        safe = _safe_evidence(evidence)
        if not isinstance(safe, dict):
            raise _error("Restore journal phase evidence is invalid")
        self.updated_at = _utc_now()
        self.evidence[self.phase] = safe
        self._write()
