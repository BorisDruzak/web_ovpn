from __future__ import annotations

import errno
import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import BackupError
from .fs import assert_safe_parents
from .settings import BackupSettings


def _lock_error(code: str, message: str) -> BackupError:
    return BackupError(code=code, message=message, exit_code=6)


def _ensure_operation_parent(settings: BackupSettings) -> None:
    parent = settings.operation_lock.parent
    if not parent.exists() and not parent.is_symlink():
        if not settings.test_mode:
            raise _lock_error(
                "backup_source_unsafe",
                "Backup operation lock parent is missing",
            )
        parent.mkdir(parents=True, mode=0o700)
    assert_safe_parents(settings.operation_lock)
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise _lock_error(
            "backup_source_unsafe",
            "Backup operation lock parent is unsafe",
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != settings.expected_root_uid
        or metadata.st_gid != settings.expected_root_gid
        or stat.S_IMODE(metadata.st_mode) & 0o002
    ):
        raise _lock_error(
            "backup_source_unsafe",
            "Backup operation lock parent metadata is unsafe",
        )


@contextmanager
def _flock(
    path: Path,
    *,
    non_blocking: bool,
    error_code: str,
    expected_uid: int,
    expected_gid: int,
    create: bool,
    enforce_metadata: bool,
) -> Iterator[None]:
    flags = os.O_RDWR
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise _lock_error(
            error_code,
            "Backup lock cannot be opened safely",
        ) from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise _lock_error(
                error_code,
                "Backup lock is not a regular file",
            )
        if enforce_metadata:
            try:
                os.fchown(descriptor, expected_uid, expected_gid)
                os.fchmod(descriptor, 0o600)
            except OSError as exc:
                raise _lock_error(
                    error_code,
                    "Backup lock metadata cannot be enforced",
                ) from exc
            metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise _lock_error(
                error_code,
                "Backup lock metadata is unsafe",
            )

        operation = fcntl.LOCK_EX
        if non_blocking:
            operation |= fcntl.LOCK_NB
        try:
            fcntl.flock(descriptor, operation)
        except OSError as exc:
            if non_blocking and exc.errno in {
                errno.EACCES,
                errno.EAGAIN,
            }:
                raise _lock_error(
                    "backup_lock_busy",
                    "Another backup operation is active",
                ) from exc
            raise _lock_error(
                error_code,
                "Backup lock cannot be acquired",
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


@contextmanager
def exclusive_operation_lock(
    settings: BackupSettings,
) -> Iterator[None]:
    _ensure_operation_parent(settings)
    with _flock(
        settings.operation_lock,
        non_blocking=True,
        error_code="backup_lock_busy",
        expected_uid=settings.expected_root_uid,
        expected_gid=settings.expected_root_gid,
        create=True,
        enforce_metadata=True,
    ):
        yield


@contextmanager
def exclusive_lifecycle_lock(
    settings: BackupSettings,
) -> Iterator[None]:
    assert_safe_parents(settings.lifecycle_lock)
    with _flock(
        settings.lifecycle_lock,
        non_blocking=False,
        error_code="controller_lock_unsafe",
        expected_uid=settings.expected_service_uid,
        expected_gid=settings.expected_service_gid,
        create=False,
        enforce_metadata=False,
    ):
        yield
