"""Stable admission flock outside the replaceable controller-state generation."""
from contextlib import contextmanager
import errno
import fcntl
import os
import stat

from .ad_directory import fail


@contextmanager
def admission_guard(state_root, *, maintenance=False):
    path = state_root.parent/'alt-deploy-setup-admission.lock'
    for ancestor in path.parents:
        if not stat.S_ISDIR(ancestor.lstat().st_mode):
            raise fail('setup_state_unsafe', 'Admission guard ancestry is unsafe')
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid not in (0, os.geteuid()) or parent.st_mode & 0o022:
        raise fail('setup_state_unsafe', 'Admission guard parent is unsafe')
    # Only root (production) or the owner of a synthetic state parent creates it.
    if not path.exists() and parent.st_uid == os.geteuid():
        try:
            created = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        except FileExistsError:
            pass
        else:
            os.fchmod(created, 0o644)
            os.fsync(created)
            os.close(created)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != parent.st_uid or stat.S_IMODE(info.st_mode) != 0o644:
            raise fail('setup_state_unsafe', 'Admission guard must be a protected regular file')
        # Admission fails promptly, including callers already holding lifecycle.
        # No blocked waiter may retain a lock on the old state directory inode.
        operation = fcntl.LOCK_EX if maintenance else fcntl.LOCK_SH | fcntl.LOCK_NB
        try:
            fcntl.flock(fd, operation)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise fail('setup_controller_maintenance', 'Controller maintenance blocks new admission') from exc
            raise
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
