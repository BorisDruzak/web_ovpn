from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from .errors import ControlError
from .jsonio import ensure_private_dir


_HELD=ContextVar('native_lifecycle_flocks',default=())


def assert_owned(path: Path) -> None:
    """Prove this process still owns the exact acquired Linux flock/inode."""
    try:
        path=Path(path).absolute()
        leases=[v for v in _HELD.get() if v[0]==path and v[2]==os.getpid()]
        if len(leases)!=1:raise ValueError
        _,descriptor,pid,device,inode=leases[0]
        for ancestor in path.parents:
            if not stat.S_ISDIR(ancestor.lstat().st_mode):raise ValueError
        current=path.lstat();opened=os.fstat(descriptor)
        if (not stat.S_ISREG(current.st_mode) or (current.st_dev,current.st_ino)!=(device,inode)
                or (opened.st_dev,opened.st_ino)!=(device,inode) or opened.st_uid!=os.geteuid()
                or stat.S_IMODE(opened.st_mode)!=0o600 or opened.st_nlink!=1):raise ValueError
        lines=Path('/proc/self/fdinfo/'+str(descriptor)).read_text().splitlines()
        for line in lines:
            parts=line.split()
            if len(parts)<9 or parts[0]!='lock:' or parts[2:5]!=['FLOCK','ADVISORY','WRITE']:continue
            major,minor,number=parts[6].split(':')
            if (int(parts[5])==pid and int(major,16)==os.major(device) and int(minor,16)==os.minor(device)
                    and int(number)==inode and parts[7:9]==['0','EOF']):return
        raise ValueError
    except Exception:
        raise ControlError('controller_lifecycle_not_owned','The current process does not own the native lifecycle lock',6) from None


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    # An idle waiter must not alter a generation already held for backup.
    # chmod of an unchanged mode still updates ctime before flock is acquired.
    if not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
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

        if stat.S_IMODE(metadata.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        token=_HELD.set((*_HELD.get(),(Path(path).absolute(),descriptor,os.getpid(),metadata.st_dev,metadata.st_ino)))
        try:
            yield
        finally:
            _HELD.reset(token)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
