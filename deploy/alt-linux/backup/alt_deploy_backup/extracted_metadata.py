from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath

from .archive import ArchiveEngine, ArchiveMember
from .components import ComponentSpec
from .errors import BackupError


def _failure(message: str) -> BackupError:
    return BackupError(
        code="backup_rehearsal_failed",
        message=message,
        exit_code=4,
    )


def _path(root: Path, member: ArchiveMember) -> Path:
    target = root.joinpath(*PurePosixPath(member.name).parts)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise _failure("Extracted metadata path escapes its root") from exc
    return target


def _kind(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _failure("Extracted archive member cannot be inspected") from exc
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    if stat.S_ISREG(metadata.st_mode):
        return "regular"
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    raise _failure("Extracted archive member type is unsafe")


def apply_archive_metadata(
    engine: ArchiveEngine,
    spec: ComponentSpec,
    archive_path: Path,
    extraction_root: Path,
) -> None:
    inspection = engine.inspect(spec, archive_path)
    non_directories = [
        member for member in inspection.members if member.kind != "directory"
    ]
    directories = sorted(
        (
            member
            for member in inspection.members
            if member.kind == "directory"
        ),
        key=lambda item: len(PurePosixPath(item.name).parts),
        reverse=True,
    )
    for member in (*non_directories, *directories):
        target = _path(extraction_root, member)
        actual_kind = _kind(target)
        expected_kind = (
            "regular" if member.kind == "hardlink" else member.kind
        )
        if actual_kind != expected_kind:
            raise _failure("Extracted archive member kind changed")
        try:
            os.chown(
                target,
                member.uid,
                member.gid,
                follow_symlinks=False,
            )
            if member.kind != "symlink":
                os.chmod(
                    target,
                    member.mode & 0o1777,
                    follow_symlinks=False,
                )
        except OSError as exc:
            raise _failure(
                "Extracted archive ownership cannot be restored"
            ) from exc
