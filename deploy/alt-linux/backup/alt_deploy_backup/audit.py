from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone

from .errors import BackupError
from .fs import assert_safe_parents
from .settings import BackupSettings


_ALLOWED_FIELDS = frozenset(
    {
        "phase",
        "error_code",
        "unit",
        "check",
        "units",
        "checks",
        "status",
        "result",
    }
)


def _invalid(message: str) -> BackupError:
    return BackupError(
        code="backup_preflight_failed",
        message=message,
        exit_code=6,
    )


def _bounded(value: object) -> bool:
    if value is None or isinstance(value, (bool, int)):
        return True
    if isinstance(value, str):
        return len(value) <= 500
    if isinstance(value, (list, tuple)):
        return all(isinstance(item, str) and len(item) <= 500 for item in value)
    return False


class AuditLog:
    def __init__(
        self,
        settings: BackupSettings,
        *,
        operation_id: str,
        command: str,
        backup_id: str | None,
    ) -> None:
        self.settings = settings
        self.operation_id = operation_id
        self.command = command
        self.backup_id = backup_id

    def _ensure_parent(self) -> None:
        parent = self.settings.log_file.parent
        if not parent.exists() and not parent.is_symlink():
            if not self.settings.test_mode:
                raise _invalid("Backup audit parent is missing")
            parent.mkdir(parents=True, mode=0o700)
        assert_safe_parents(self.settings.log_file)
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise _invalid("Backup audit parent is unsafe") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.settings.expected_root_uid
            or metadata.st_gid != self.settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) & 0o002
        ):
            raise _invalid("Backup audit parent metadata is unsafe")

    def write(self, event: str, **safe_fields: object) -> None:
        if not event or len(event) > 500:
            raise _invalid("Backup audit event is invalid")
        if set(safe_fields) - _ALLOWED_FIELDS:
            raise _invalid("Backup audit field is not allowed")
        if not all(_bounded(value) for value in safe_fields.values()):
            raise _invalid("Backup audit value is invalid")

        payload: dict[str, object] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "operation_id": self.operation_id,
            "command": self.command,
            "backup_id": self.backup_id,
        }
        payload.update(safe_fields)
        data = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True)
            + "\n"
        ).encode("utf-8")

        self._ensure_parent()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.settings.log_file, flags, 0o600)
        except OSError as exc:
            raise _invalid("Backup audit log cannot be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise _invalid("Backup audit log is not a regular file")
            try:
                os.fchown(
                    descriptor,
                    self.settings.expected_root_uid,
                    self.settings.expected_root_gid,
                )
                os.fchmod(descriptor, 0o600)
            except OSError as exc:
                raise _invalid("Backup audit metadata cannot be enforced") from exc
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written < 1:
                    raise _invalid("Backup audit write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
