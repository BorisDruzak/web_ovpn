from __future__ import annotations

import os
import threading
from pathlib import Path

from .db import db_path_from_url

try:
    import fcntl
except ImportError:  # pragma: no cover - collection fails closed without /proc on Windows.
    fcntl = None


_RECOVERY_GUARD = threading.Lock()


def collect_lock_path(db_url: str) -> Path:
    return db_path_from_url(db_url).with_suffix(".lock")


def _process_start_time(pid: int) -> str | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    except (FileNotFoundError, PermissionError, OSError, UnicodeDecodeError):
        return None
    return fields[21] if len(fields) > 21 and fields[21].isdigit() else None


def _read_owner(path: Path) -> tuple[int, str | None] | None:
    try:
        fields = path.read_text(encoding="ascii").split()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    if len(fields) not in (1, 2) or not all(field.isdigit() for field in fields):
        return None
    pid = int(fields[0])
    if pid <= 0:
        return None
    return pid, fields[1] if len(fields) == 2 else None


def _is_live_owner(pid: int, start_time: str | None) -> bool:
    observed = _process_start_time(pid)
    return observed is not None and (start_time is None or observed == start_time)


def _acquire_recovery_guard(path: Path) -> int:
    if not _RECOVERY_GUARD.acquire(blocking=False):
        raise BlockingIOError
    fd: int | None = None
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR)
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except Exception:
        if fd is not None:
            os.close(fd)
        _RECOVERY_GUARD.release()
        raise


def _release_recovery_guard(fd: int) -> None:
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
        _RECOVERY_GUARD.release()


class CollectLock:
    def __init__(self, db_url: str) -> None:
        self.path = collect_lock_path(db_url)
        self.fd: int | None = None

    def __enter__(self) -> "CollectLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            guard_fd = _acquire_recovery_guard(
                self.path.with_name(f"{self.path.name}.recovery")
            )
        except (BlockingIOError, OSError) as exc:
            raise RuntimeError("collection already running") from exc
        try:
            start_time = _process_start_time(os.getpid())
            if start_time is None:
                raise RuntimeError("collection already running")

            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError as exc:
                owner = _read_owner(self.path)
                if owner is not None and _is_live_owner(*owner):
                    raise RuntimeError("collection already running") from exc
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
                try:
                    self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                except FileExistsError as retry_exc:
                    raise RuntimeError("collection already running") from retry_exc
            os.write(self.fd, f"{os.getpid()} {start_time}\n".encode("ascii"))
            return self
        finally:
            _release_recovery_guard(guard_fd)

    def __exit__(self, exc_type, exc, tb) -> None:
        own_stat = None
        if self.fd is not None:
            own_stat = os.fstat(self.fd)
            os.close(self.fd)
            self.fd = None
        try:
            if own_stat is not None and os.path.samestat(own_stat, self.path.stat()):
                self.path.unlink()
        except FileNotFoundError:
            pass
