from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

from .jsonio import ensure_private_dir


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    ensure_private_dir(path.parent)

    with path.open("a+", encoding="utf-8") as handle:
        os.chmod(path, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
