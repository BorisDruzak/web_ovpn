from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import ControlError
from .jsonio import ensure_private_dir


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    ensure_private_dir(path.parent)

    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ControlError(
            code="controller_lock_unsafe",
            message=(
                "Controller lifecycle lock cannot be opened safely"
            ),
            exit_code=6,
        ) from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ControlError(
                code="controller_lock_unsafe",
                message=(
                    "Controller lifecycle lock is not a regular file"
                ),
                exit_code=6,
            )

        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)

        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
