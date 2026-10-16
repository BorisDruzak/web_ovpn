#!/usr/bin/python3
"""Keep the approved standalone RPM from enabling a vendor update channel."""
from pathlib import Path
import json
import os
import stat
import tempfile

ACTIVE = b'rpm [yandex-browser] https://repo.yandex.ru/yandex-browser/alt x86_64 yandex-browser\n'
DISABLED = b'# Disabled by managed browser artifact policy: ' + ACTIVE


def disable(*, root=Path('/'), owner=0):
    target = root/'etc/apt/sources.list.d/yandex-browser.list'
    if not target.exists() and not target.is_symlink():
        return False
    for directory in (root, root/'etc', root/'etc/apt', target.parent):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('Unsafe browser repository ancestry')
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o7022 or info.st_size > 4096:
        raise ValueError('Unsafe browser repository file')
    with os.fdopen(os.open(target, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError('Browser repository changed during inspection')
        content = stream.read(4097)
    if content == DISABLED:
        return False
    if content != ACTIVE:
        raise ValueError('Unexpected browser repository content')
    fd, temporary = tempfile.mkstemp(prefix='.managed-browser-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(DISABLED); stream.flush(); os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
        current = target.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or target.read_bytes() != content:
            raise ValueError('Browser repository changed before replacement')
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return True


if __name__ == '__main__':
    print(json.dumps({'changed': disable()}))
