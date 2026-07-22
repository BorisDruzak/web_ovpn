from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import BackupError


@dataclass(frozen=True)
class InventoryEntry:
    path: str
    kind: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _unsafe(message: str) -> BackupError:
    return BackupError(
        code="backup_source_unsafe",
        message=message,
        exit_code=4,
    )


def assert_safe_parents(path: Path) -> None:
    absolute = path.absolute()
    for parent in absolute.parents:
        if parent == Path("/"):
            break
        if not parent.exists() and not parent.is_symlink():
            continue
        try:
            metadata = parent.lstat()
        except OSError as exc:
            raise _unsafe("Backup path parent cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
            metadata.st_mode
        ):
            raise _unsafe("Backup path parent is unsafe")


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _unsafe("Backup directory cannot be synchronized") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise _unsafe("Backup directory synchronization failed") from exc
    finally:
        os.close(descriptor)


def read_regular_bytes(
    path: Path,
    *,
    max_bytes: int | None = None,
) -> bytes:
    assert_safe_parents(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise _unsafe("Backup source cannot be inspected") from exc
    if not stat.S_ISREG(before.st_mode):
        raise _unsafe("Backup source is not a regular file")
    if max_bytes is not None and before.st_size > max_bytes:
        raise _unsafe("Backup source exceeds the size limit")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _unsafe("Backup source cannot be opened safely") from exc

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise _unsafe("Backup source changed during safe open")

        chunks: list[bytes] = []
        length = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            length += len(chunk)
            if max_bytes is not None and length > max_bytes:
                raise _unsafe("Backup source exceeds the size limit")
            chunks.append(chunk)

        after = os.fstat(descriptor)
        data = b"".join(chunks)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or len(data) != after.st_size
        ):
            raise _unsafe("Backup source changed while being read")
        return data
    finally:
        os.close(descriptor)


def validate_private_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    assert_safe_parents(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _unsafe("Private backup directory cannot be inspected") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise _unsafe("Private backup path is not a directory")
    if (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise _unsafe("Private backup directory metadata is invalid")


def _contained(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False


def _inventory_entry(
    path: Path,
    kind: str,
    metadata: os.stat_result,
) -> InventoryEntry:
    return InventoryEntry(
        path=str(path.absolute()),
        kind=kind,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def source_inventory(paths: Sequence[Path]) -> tuple[InventoryEntry, ...]:
    entries: dict[str, InventoryEntry] = {}

    def walk(path: Path, resolved_root: Path) -> None:
        assert_safe_parents(path)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise _unsafe("Backup inventory path cannot be inspected") from exc

        if stat.S_ISLNK(metadata.st_mode):
            try:
                raw_target = Path(os.readlink(path))
            except OSError as exc:
                raise _unsafe("Backup symlink cannot be read") from exc
            target = (
                raw_target
                if raw_target.is_absolute()
                else path.parent / raw_target
            ).resolve(strict=False)
            if not _contained(target, resolved_root):
                raise _unsafe("Backup symlink escapes its source root")
            entry = _inventory_entry(path, "symlink", metadata)
            entries[entry.path] = entry
            return

        if stat.S_ISREG(metadata.st_mode):
            entry = _inventory_entry(path, "regular", metadata)
            entries[entry.path] = entry
            return

        if not stat.S_ISDIR(metadata.st_mode):
            raise _unsafe("Backup inventory contains a special file")

        entry = _inventory_entry(path, "directory", metadata)
        entries[entry.path] = entry
        try:
            children = sorted(path.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise _unsafe("Backup directory cannot be enumerated") from exc
        for child in children:
            walk(child, resolved_root)

    for source in sorted(paths, key=lambda item: str(item.absolute())):
        absolute = source.absolute()
        assert_safe_parents(absolute)
        try:
            metadata = absolute.lstat()
        except OSError as exc:
            raise _unsafe("Backup source root cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise _unsafe("Backup source root is unsafe")
        if stat.S_ISREG(metadata.st_mode):
            resolved_root = absolute.parent.resolve(strict=True)
        elif stat.S_ISDIR(metadata.st_mode):
            resolved_root = absolute.resolve(strict=True)
        else:
            raise _unsafe("Backup source root is unsafe")
        walk(absolute, resolved_root)

    return tuple(entries[key] for key in sorted(entries))
