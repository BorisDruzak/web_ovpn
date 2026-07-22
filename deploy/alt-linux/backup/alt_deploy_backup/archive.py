from __future__ import annotations

import grp
import hashlib
import os
import pwd
import secrets
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .components import ComponentSpec
from .errors import BackupError
from .fs import (
    assert_safe_parents,
    fsync_directory,
    source_inventory,
)
from .manifest import ComponentRecord, PathRecord
from .settings import BackupSettings


_MAX_ARCHIVE_MEMBERS = 200_000
_MAX_MEMBER_SIZE = 64 * 1024 * 1024 * 1024
_MAX_TOTAL_SIZE = 1024 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    kind: str
    size: int
    mode: int
    uid: int
    gid: int
    link_name: str | None


@dataclass(frozen=True)
class ArchiveInspection:
    members: tuple[ArchiveMember, ...]
    total_size: int


def _component_error(message: str) -> BackupError:
    return BackupError(
        code="backup_component_failed",
        message=message,
        exit_code=4,
    )


def _integrity_error(message: str) -> BackupError:
    return BackupError(
        code="backup_integrity_failed",
        message=message,
        exit_code=4,
    )


def _safe_owner(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _safe_group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


class ArchiveEngine:
    def __init__(self, settings: BackupSettings):
        self.settings = settings

    def _root_prefix(self) -> Path:
        try:
            root = self.settings.backup_root.parents[2]
        except IndexError as exc:
            raise _component_error(
                "Backup root cannot determine the controller root"
            ) from exc
        return root

    def _logical_path(self, path: Path) -> str:
        root = self._root_prefix()
        absolute = path.absolute()
        if root == Path("/"):
            return str(absolute)
        try:
            relative = absolute.relative_to(root)
        except ValueError as exc:
            raise _component_error(
                "Component path is outside the controller root"
            ) from exc
        return "/" + relative.as_posix()

    def _relative_source(self, path: Path) -> str:
        root = self._root_prefix()
        absolute = path.absolute()
        try:
            relative = absolute.relative_to(root)
        except ValueError as exc:
            raise _component_error(
                "Component source is outside the controller root"
            ) from exc
        text = relative.as_posix()
        if not text or text == "." or text.startswith("../"):
            raise _component_error("Component source name is invalid")
        return text

    @staticmethod
    def _present(path: Path) -> bool:
        return path.exists() or path.is_symlink()

    def _path_record(self, path: Path) -> PathRecord:
        logical = self._logical_path(path)
        if not self._present(path):
            return PathRecord(
                absolute_path=logical,
                present=False,
                uid=None,
                gid=None,
                owner=None,
                group=None,
                mode=None,
                kind="absent",
            )
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise _component_error(
                "Component source metadata cannot be read"
            ) from exc
        if stat.S_ISDIR(metadata.st_mode):
            kind = "directory"
        elif stat.S_ISREG(metadata.st_mode):
            kind = "regular"
        else:
            raise _component_error(
                "Component source root is not a regular file or directory"
            )
        return PathRecord(
            absolute_path=logical,
            present=True,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            owner=_safe_owner(metadata.st_uid),
            group=_safe_group(metadata.st_gid),
            mode=stat.S_IMODE(metadata.st_mode),
            kind=kind,
        )

    @staticmethod
    def _write_all(descriptor: int, raw: bytes) -> None:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise _component_error(
                    "Component file-list write made no progress"
                )
            offset += written

    def _create_file_list(
        self,
        spec: ComponentSpec,
        directory: Path,
    ) -> tuple[Path, tuple[Path, ...]]:
        present = tuple(path for path in spec.paths if self._present(path))
        list_path = directory / (
            f".{spec.name}.{os.getpid()}.{secrets.token_hex(4)}.files"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(list_path, flags, 0o600)
        except OSError as exc:
            raise _component_error(
                "Component file list cannot be created safely"
            ) from exc
        try:
            for path in present:
                entry = self._relative_source(path).encode("utf-8") + b"\0"
                self._write_all(descriptor, entry)
            os.fsync(descriptor)
        except (OSError, UnicodeEncodeError) as exc:
            raise _component_error(
                "Component file list cannot be written"
            ) from exc
        finally:
            os.close(descriptor)
        return list_path, present

    def _capture_argv(
        self,
        spec: ComponentSpec,
        list_path: Path,
    ) -> list[str]:
        arguments = [
            str(self.settings.tar_path),
            "--create",
            "--format=pax",
            "--numeric-owner",
            "--acls",
            "--xattrs",
            "--hard-dereference",
            "--null",
            "--verbatim-files-from",
            f"--directory={self._root_prefix()}",
            f"--transform=flags=r;s,^,{spec.namespace}/,",
        ]
        for excluded in spec.excludes:
            arguments.append(
                f"--exclude={self._relative_source(excluded)}"
            )
        arguments.append(f"--files-from={list_path}")
        arguments.append("--file=-")
        return arguments

    def _run_capture_pipeline(
        self,
        spec: ComponentSpec,
        list_path: Path,
        temporary: Path,
    ) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except OSError as exc:
            raise _component_error(
                "Temporary component archive cannot be created"
            ) from exc
        tar_process: subprocess.Popen[bytes] | None = None
        zstd_process: subprocess.Popen[bytes] | None = None
        try:
            tar_process = subprocess.Popen(
                self._capture_argv(spec, list_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            if tar_process.stdout is None:
                raise _component_error(
                    "Archive capture pipe is unavailable"
                )
            zstd_process = subprocess.Popen(
                [str(self.settings.zstd_path), "-q", "-c"],
                stdin=tar_process.stdout,
                stdout=descriptor,
                stderr=subprocess.DEVNULL,
            )
            tar_process.stdout.close()
            zstd_code = zstd_process.wait()
            tar_code = tar_process.wait()
            if tar_code != 0 or zstd_code != 0:
                raise _component_error(
                    "Component archive command failed"
                )
            os.fsync(descriptor)
        except OSError as exc:
            raise _component_error(
                "Component archive command cannot run"
            ) from exc
        finally:
            if tar_process is not None and tar_process.poll() is None:
                tar_process.kill()
                tar_process.wait()
            if zstd_process is not None and zstd_process.poll() is None:
                zstd_process.kill()
                zstd_process.wait()
            os.close(descriptor)

    @staticmethod
    def _file_digest(path: Path) -> tuple[int, str]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise _component_error(
                "Component archive cannot be opened safely"
            ) from exc
        digest = hashlib.sha256()
        size = 0
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise _component_error(
                    "Component archive is not a regular file"
                )
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
                or size != after.st_size
            ):
                raise _component_error(
                    "Component archive changed while hashing"
                )
        finally:
            os.close(descriptor)
        return size, digest.hexdigest()

    def capture(
        self,
        spec: ComponentSpec,
        destination: Path,
    ) -> ComponentRecord:
        assert_safe_parents(destination)
        try:
            parent = destination.parent.lstat()
        except OSError as exc:
            raise _component_error(
                "Component destination parent is unavailable"
            ) from exc
        if not stat.S_ISDIR(parent.st_mode):
            raise _component_error(
                "Component destination parent is unsafe"
            )
        if destination.exists() or destination.is_symlink():
            raise _component_error(
                "Component destination already exists"
            )

        present_paths = tuple(
            path for path in spec.paths if self._present(path)
        )
        before = source_inventory(present_paths)
        list_path, _ = self._create_file_list(
            spec,
            destination.parent,
        )
        temporary = destination.parent / (
            f".{destination.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        )
        try:
            self._run_capture_pipeline(spec, list_path, temporary)
            after = source_inventory(present_paths)
            if after != before:
                raise _component_error(
                    "Component sources changed during capture"
                )
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            fsync_directory(destination.parent)
            size, digest = self._file_digest(destination)
            return ComponentRecord(
                name=spec.name,
                filename=spec.filename,
                namespace=spec.namespace,
                size_bytes=size,
                sha256=digest,
                paths=tuple(
                    self._path_record(path)
                    for path in spec.paths
                ),
                archive_format="tar.zst",
            )
        except BackupError:
            raise
        except OSError as exc:
            raise _component_error(
                "Component archive publication failed"
            ) from exc
        finally:
            for path in (list_path, temporary):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _open_decompressor(
        self,
        archive_path: Path,
    ) -> tuple[int, subprocess.Popen[bytes]]:
        assert_safe_parents(archive_path)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(archive_path, flags)
        except OSError as exc:
            raise _integrity_error(
                "Component archive cannot be opened safely"
            ) from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise _integrity_error(
                "Component archive is not a regular file"
            )
        try:
            process = subprocess.Popen(
                [str(self.settings.zstd_path), "-d", "-q", "-c"],
                stdin=descriptor,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            os.close(descriptor)
            raise _integrity_error(
                "Component archive decompressor cannot run"
            ) from exc
        os.close(descriptor)
        if process.stdout is None:
            process.kill()
            process.wait()
            raise _integrity_error(
                "Component decompression pipe is unavailable"
            )
        return metadata.st_size, process

    @staticmethod
    def _canonical_member_name(member: tarfile.TarInfo) -> str:
        raw = member.name
        if member.isdir() and raw.endswith("/"):
            raw = raw[:-1]
        if not raw or raw == "." or raw.startswith("/"):
            raise _integrity_error("Archive member path is unsafe")
        pieces = raw.split("/")
        if any(piece in {"", ".", ".."} for piece in pieces):
            raise _integrity_error("Archive member path is unsafe")
        return PurePosixPath(*pieces).as_posix()

    @staticmethod
    def _member_kind(member: tarfile.TarInfo) -> str:
        if member.isdir():
            return "directory"
        if member.isreg():
            return "regular"
        if member.issym():
            return "symlink"
        if member.islnk():
            return "hardlink"
        raise _integrity_error(
            "Archive contains an unsupported special file"
        )

    @staticmethod
    def _resolve_link_target(
        member_name: str,
        link_name: str,
        namespace: str,
    ) -> str:
        if not link_name or link_name.startswith("/"):
            raise _integrity_error("Archive link target is unsafe")
        base = list(PurePosixPath(member_name).parent.parts)
        for piece in link_name.split("/"):
            if piece in {"", "."}:
                continue
            if piece == "..":
                if len(base) <= 1:
                    raise _integrity_error(
                        "Archive link escapes its namespace"
                    )
                base.pop()
                continue
            base.append(piece)
        if not base or base[0] != namespace:
            raise _integrity_error(
                "Archive link escapes its namespace"
            )
        return PurePosixPath(*base).as_posix()

    def _validated_member(
        self,
        spec: ComponentSpec,
        member: tarfile.TarInfo,
    ) -> ArchiveMember:
        name = self._canonical_member_name(member)
        parts = PurePosixPath(name).parts
        if not parts or parts[0] != spec.namespace:
            raise _integrity_error(
                "Archive member is outside its component namespace"
            )
        kind = self._member_kind(member)
        if member.size < 0 or member.size > _MAX_MEMBER_SIZE:
            raise _integrity_error("Archive member size is unsafe")
        if kind != "regular" and member.size != 0:
            raise _integrity_error(
                "Archive non-regular member has an invalid size"
            )
        link_name: str | None = None
        if kind in {"symlink", "hardlink"}:
            link_name = member.linkname
            self._resolve_link_target(
                name,
                member.linkname,
                spec.namespace,
            )
        return ArchiveMember(
            name=name,
            kind=kind,
            size=member.size,
            mode=member.mode & 0o7777,
            uid=member.uid,
            gid=member.gid,
            link_name=link_name,
        )

    def inspect(
        self,
        spec: ComponentSpec,
        archive_path: Path,
    ) -> ArchiveInspection:
        _, process = self._open_decompressor(archive_path)
        members: list[ArchiveMember] = []
        names: set[str] = set()
        total_size = 0
        try:
            try:
                with tarfile.open(
                    fileobj=process.stdout,
                    mode="r|",
                ) as stream:
                    for raw_member in stream:
                        if len(members) >= _MAX_ARCHIVE_MEMBERS:
                            raise _integrity_error(
                                "Archive contains too many members"
                            )
                        member = self._validated_member(
                            spec,
                            raw_member,
                        )
                        if member.name in names:
                            raise _integrity_error(
                                "Archive contains duplicate members"
                            )
                        names.add(member.name)
                        total_size += member.size
                        if total_size > _MAX_TOTAL_SIZE:
                            raise _integrity_error(
                                "Archive expanded size is unsafe"
                            )
                        members.append(member)
            except (tarfile.TarError, OSError) as exc:
                raise _integrity_error(
                    "Component tar stream is invalid"
                ) from exc
        finally:
            process.stdout.close()
        return_code = process.wait()
        if return_code != 0:
            raise _integrity_error(
                "Component zstd stream is invalid"
            )
        return ArchiveInspection(
            members=tuple(members),
            total_size=total_size,
        )

    @staticmethod
    def _prepare_destination(destination: Path) -> Path:
        assert_safe_parents(destination)
        if destination.exists() or destination.is_symlink():
            try:
                metadata = destination.lstat()
            except OSError as exc:
                raise _integrity_error(
                    "Rehearsal destination cannot be inspected"
                ) from exc
            if not stat.S_ISDIR(metadata.st_mode):
                raise _integrity_error(
                    "Rehearsal destination is unsafe"
                )
            try:
                if any(destination.iterdir()):
                    raise _integrity_error(
                        "Rehearsal destination is not empty"
                    )
            except OSError as exc:
                raise _integrity_error(
                    "Rehearsal destination cannot be enumerated"
                ) from exc
        else:
            destination.mkdir(parents=True, mode=0o700)
        resolved = destination.resolve(strict=True)
        if resolved != destination.absolute():
            raise _integrity_error(
                "Rehearsal destination contains a symlink"
            )
        return resolved

    @staticmethod
    def _ensure_parent(root: Path, target: Path) -> None:
        relative = target.relative_to(root)
        current = root
        for piece in relative.parts[:-1]:
            current = current / piece
            if current.exists() or current.is_symlink():
                try:
                    metadata = current.lstat()
                except OSError as exc:
                    raise _integrity_error(
                        "Extracted parent cannot be inspected"
                    ) from exc
                if not stat.S_ISDIR(metadata.st_mode):
                    raise _integrity_error(
                        "Extracted parent is unsafe"
                    )
            else:
                current.mkdir(mode=0o700)

    @staticmethod
    def _destination_path(root: Path, name: str) -> Path:
        target = root.joinpath(*PurePosixPath(name).parts)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise _integrity_error(
                "Extracted member escapes destination"
            ) from exc
        return target

    @staticmethod
    def _extract_regular(
        stream: tarfile.TarFile,
        raw_member: tarfile.TarInfo,
        member: ArchiveMember,
        target: Path,
    ) -> None:
        source = stream.extractfile(raw_member)
        if source is None:
            raise _integrity_error(
                "Archive regular member has no data"
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                target,
                flags,
                member.mode & 0o1777,
            )
        except OSError as exc:
            raise _integrity_error(
                "Rehearsal file cannot be created safely"
            ) from exc
        written_total = 0
        try:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                written_total += len(chunk)
                if written_total > member.size:
                    raise _integrity_error(
                        "Archive member exceeds declared size"
                    )
                offset = 0
                while offset < len(chunk):
                    written = os.write(descriptor, chunk[offset:])
                    if written < 1:
                        raise _integrity_error(
                            "Rehearsal file write made no progress"
                        )
                    offset += written
            if written_total != member.size:
                raise _integrity_error(
                    "Archive member size does not match"
                )
            os.fchmod(descriptor, member.mode & 0o1777)
            os.fsync(descriptor)
        finally:
            source.close()
            os.close(descriptor)

    def extract_for_rehearsal(
        self,
        spec: ComponentSpec,
        archive_path: Path,
        destination: Path,
    ) -> None:
        inspection = self.inspect(spec, archive_path)
        expected = list(inspection.members)
        root = self._prepare_destination(destination)
        _, process = self._open_decompressor(archive_path)
        index = 0
        try:
            try:
                with tarfile.open(
                    fileobj=process.stdout,
                    mode="r|",
                ) as stream:
                    for raw_member in stream:
                        member = self._validated_member(spec, raw_member)
                        if index >= len(expected) or member != expected[index]:
                            raise _integrity_error(
                                "Archive changed between inspection and extraction"
                            )
                        index += 1
                        target = self._destination_path(root, member.name)
                        self._ensure_parent(root, target)
                        if member.kind == "directory":
                            if target.exists() or target.is_symlink():
                                metadata = target.lstat()
                                if not stat.S_ISDIR(metadata.st_mode):
                                    raise _integrity_error(
                                        "Archive directory conflicts with a file"
                                    )
                            else:
                                target.mkdir(mode=0o700)
                            target.chmod(member.mode & 0o1777)
                        elif member.kind == "regular":
                            self._extract_regular(
                                stream,
                                raw_member,
                                member,
                                target,
                            )
                        elif member.kind == "symlink":
                            if target.exists() or target.is_symlink():
                                raise _integrity_error(
                                    "Archive link destination already exists"
                                )
                            assert member.link_name is not None
                            os.symlink(member.link_name, target)
                        elif member.kind == "hardlink":
                            assert member.link_name is not None
                            resolved_name = self._resolve_link_target(
                                member.name,
                                member.link_name,
                                spec.namespace,
                            )
                            source = self._destination_path(
                                root,
                                resolved_name,
                            )
                            try:
                                source_metadata = source.lstat()
                            except OSError as exc:
                                raise _integrity_error(
                                    "Archive hardlink source is unavailable"
                                ) from exc
                            if not stat.S_ISREG(source_metadata.st_mode):
                                raise _integrity_error(
                                    "Archive hardlink source is unsafe"
                                )
                            try:
                                os.link(
                                    source,
                                    target,
                                    follow_symlinks=False,
                                )
                            except OSError as exc:
                                raise _integrity_error(
                                    "Archive hardlink cannot be created"
                                ) from exc
                if index != len(expected):
                    raise _integrity_error(
                        "Archive member count changed during extraction"
                    )
            except (tarfile.TarError, OSError) as exc:
                raise _integrity_error(
                    "Component extraction stream is invalid"
                ) from exc
        finally:
            process.stdout.close()
        if process.wait() != 0:
            raise _integrity_error(
                "Component extraction zstd stream is invalid"
            )
