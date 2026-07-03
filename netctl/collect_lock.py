from __future__ import annotations

import os
from pathlib import Path

from .db import db_path_from_url


def collect_lock_path(db_url: str) -> Path:
    return db_path_from_url(db_url).with_suffix(".lock")


class CollectLock:
    def __init__(self, db_url: str) -> None:
        self.path = collect_lock_path(db_url)
        self.fd: int | None = None

    def __enter__(self) -> "CollectLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RuntimeError("collection already running") from exc
        os.write(self.fd, str(os.getpid()).encode("ascii"))
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
