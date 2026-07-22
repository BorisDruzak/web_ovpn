from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path

from .errors import BackupError
from .fs import assert_safe_parents, fsync_directory


def _unsafe(message: str) -> BackupError:
    return BackupError(
        code="backup_source_unsafe",
        message=message,
        exit_code=4,
    )


def _encoded(payload: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            dict(payload),
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def atomic_write_json(
    path: Path,
    payload: Mapping[str, object],
    *,
    mode: int = 0o600,
) -> None:
    assert_safe_parents(path)
    try:
        parent_metadata = path.parent.lstat()
    except OSError as exc:
        raise _unsafe("JSON destination parent cannot be inspected") from exc
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise _unsafe("JSON destination parent is unsafe")

    if path.exists() or path.is_symlink():
        try:
            existing = path.lstat()
        except OSError as exc:
            raise _unsafe("JSON destination cannot be inspected") from exc
        if not stat.S_ISREG(existing.st_mode):
            raise _unsafe("JSON destination is not a regular file")

    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, mode)
        os.fchmod(descriptor, mode)
        data = _encoded(payload)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written < 1:
                raise _unsafe("JSON write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except BackupError:
        raise
    except OSError as exc:
        raise _unsafe("JSON destination cannot be written safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
