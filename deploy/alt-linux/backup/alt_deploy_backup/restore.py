from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .archive import ArchiveInspection
from .bundle_management import BundleManager, _VerifiedBundle
from .components import ComponentSpec, component_specs
from .errors import BackupError
from .extracted_metadata import apply_archive_metadata
from .fs import (
    assert_safe_parents,
    fsync_directory,
    read_regular_bytes,
    source_inventory,
)
from .guard import GuardState
from .locks import exclusive_lifecycle_lock, exclusive_operation_lock
from .manifest import BackupManifest
from .repository import BackupRepository
from .restore_journal import RestoreJournal, terminal_phases
from .state_validation import StateValidator
from .systemd import UnitState


@dataclass(frozen=True)
class StagedPath:
    component: str
    absolute_path: str
    production_path: Path
    staged_path: Path | None
    rollback_path: Path
    present: bool


@dataclass(frozen=True)
class StagedGeneration:
    backup_id: str
    restore_id: str
    extracted_root: Path
    paths: tuple[StagedPath, ...]
    manifest: BackupManifest


@dataclass(frozen=True)
class PreRestoreGeneration:
    root: Path
    components: tuple[str, ...]
    manifest_sha256: str


@dataclass(frozen=True)
class RestoreResult:
    backup_id: str
    phase: str
    services_restored: bool
    rollback_performed: bool
    cleanup_complete: bool


def _staging(message: str) -> BackupError:
    return BackupError(
        code="restore_staging_failed",
        message=message,
        exit_code=4,
    )


def _health(message: str) -> BackupError:
    return BackupError(
        code="restore_health_check_failed",
        message=message,
        exit_code=4,
    )


def _manual(restore_id: str) -> BackupError:
    return BackupError(
        code="restore_manual_recovery_required",
        message="Restore requires manual recovery",
        exit_code=6,
        details={"restore_id": restore_id},
    )


def _is_unsupported_metadata_error(exc: OSError) -> bool:
    return exc.errno in {
        errno.ENOTSUP,
        getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
        errno.ENOSYS,
    }


_CAPACITY_MARGIN_BYTES = 64 * 1024 * 1024


class RestoreService:
    def __init__(
        self,
        repository: BackupRepository,
        *,
        state_validator: StateValidator | None = None,
        fail_stage_component: str | None = None,
        fail_health_check: str | None = None,
        fail_rollback: bool = False,
        fail_move_after: int | None = None,
        interrupt_move_after: int | None = None,
        fail_cleanup: bool = False,
        health_probe: Callable[[str], bytes] | None = None,
        guard_state: GuardState | None = None,
    ) -> None:
        self.repository = repository
        self.settings = repository.settings
        self.state_validator = state_validator or StateValidator()
        self.fail_stage_component = fail_stage_component
        self.fail_health_check = fail_health_check
        self.fail_rollback = fail_rollback
        self.fail_move_after = fail_move_after
        self.interrupt_move_after = interrupt_move_after
        self.fail_cleanup = fail_cleanup
        self.health_probe = health_probe or self._default_health_probe
        self.guard = guard_state or GuardState(self.settings)

    def _manager(self) -> BundleManager:
        return BundleManager(self.repository)

    def _assert_eligibility_unlocked(self, backup_id: str):
        manager = self._manager()
        verified = manager._verify_bundle(backup_id)
        evidence_verified, rehearsed = manager._evidence_state(verified)
        if not evidence_verified:
            raise BackupError(
                code="backup_not_verified",
                message="Backup verification evidence is missing or stale",
                exit_code=4,
            )
        if not rehearsed:
            raise BackupError(
                code="backup_not_rehearsed",
                message="Backup rehearsal evidence is missing or stale",
                exit_code=4,
            )
        return verified

    @staticmethod
    def _archive_path_regular_bytes(
        inspection: ArchiveInspection,
        namespace: str,
        absolute_path: str,
    ) -> int:
        root = f"{namespace}/{absolute_path.lstrip('/')}"
        members = inspection.members
        return sum(
            member.size
            for member in members
            if member.kind == "regular"
            and (
                member.name == root
                or member.name.startswith(root + "/")
            )
        )

    @staticmethod
    def _capacity_device(path: Path) -> int:
        try:
            assert_safe_parents(path)
            metadata = path.lstat()
        except (OSError, BackupError) as exc:
            raise _staging(
                "Restore capacity path cannot be inspected"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise _staging("Restore capacity path is unsafe")
        return metadata.st_dev

    def _assert_restore_capacity(
        self,
        verified: _VerifiedBundle,
    ) -> None:
        requirements: dict[int, int] = {}
        probes: dict[int, Path] = {}

        def add(path: Path, amount: int) -> None:
            device = self._capacity_device(path)
            requirements[device] = requirements.get(device, 0) + max(
                0,
                amount,
            )
            probes.setdefault(device, path)

        specs = component_specs(self.settings)
        manifest = verified.manifest
        bundle_path = verified.path
        total_expanded = 0
        for spec, record in zip(
            specs,
            manifest.components,
            strict=True,
        ):
            inspection = self.repository.archive_engine.inspect(
                spec,
                bundle_path / record.filename,
            )
            total_expanded += inspection.total_size
            for path_record in record.paths:
                if not path_record.present:
                    continue
                production = self.repository._controller_path(
                    path_record.absolute_path
                )
                restored_bytes = self._archive_path_regular_bytes(
                    inspection,
                    record.namespace,
                    path_record.absolute_path,
                )
                add(production.parent, restored_bytes * 2)

        try:
            current_inventory = source_inventory(
                self.repository._source_paths(specs)
            )
        except BackupError as exc:
            raise _staging(
                "Current restore generation cannot be measured"
            ) from exc
        current_regular_bytes = sum(
            entry.size
            for entry in current_inventory
            if entry.kind == "regular"
        )
        add(
            self.settings.backup_root,
            (total_expanded * 2) + (current_regular_bytes * 2),
        )

        for device, raw_required in requirements.items():
            required = raw_required + _CAPACITY_MARGIN_BYTES
            try:
                free = shutil.disk_usage(probes[device]).free
            except OSError as exc:
                raise _staging(
                    "Restore free space cannot be inspected"
                ) from exc
            if free < required:
                raise _staging("Insufficient free space for restore")

    def prepare_restore(self, backup_id: str) -> RestoreJournal:
        self.repository.assert_rehearsed_eligibility(backup_id)
        self.repository.quiescence.assert_quiescent()
        with exclusive_operation_lock(self.settings):
            verified = self._assert_eligibility_unlocked(backup_id)
            self.repository.quiescence.assert_quiescent()
            self._assert_restore_capacity(verified)
            pre_states = self.repository.systemd.capture()
            journal = RestoreJournal.create(self.settings, backup_id)
            journal.record_phase(
                {"pre_states": self._serialize_states(pre_states)}
            )
            return journal

    @staticmethod
    def _write_all(descriptor: int, raw: bytes) -> None:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise _staging("Restore write made no progress")
            offset += written

    @staticmethod
    def _list_xattrs(path: Path) -> tuple[str, ...]:
        if not hasattr(os, "listxattr"):
            return ()
        try:
            return tuple(
                sorted(os.listxattr(path, follow_symlinks=False))
            )
        except OSError as exc:
            if _is_unsupported_metadata_error(exc):
                return ()
            raise _staging("Restore xattrs cannot be inspected") from exc

    def _copy_xattrs(self, source: Path, destination: Path) -> None:
        if not hasattr(os, "getxattr") or not hasattr(os, "setxattr"):
            return
        for name in self._list_xattrs(source):
            try:
                value = os.getxattr(
                    source,
                    name,
                    follow_symlinks=False,
                )
                os.setxattr(
                    destination,
                    name,
                    value,
                    follow_symlinks=False,
                )
            except OSError as exc:
                if _is_unsupported_metadata_error(exc):
                    raise _staging(
                        "Restore filesystem cannot preserve source xattrs"
                    ) from exc
                raise _staging("Restore xattr copy failed") from exc

    @staticmethod
    def _open_source_regular(path: Path) -> tuple[int, os.stat_result]:
        assert_safe_parents(path)
        try:
            before = path.lstat()
        except OSError as exc:
            raise _staging("Restore source cannot be inspected") from exc
        if not stat.S_ISREG(before.st_mode):
            raise _staging("Restore source is not a regular file")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise _staging("Restore source cannot be opened safely") from exc
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            os.close(descriptor)
            raise _staging("Restore source changed during safe open")
        return descriptor, opened

    @staticmethod
    def _assert_stable_source(
        descriptor: int,
        before: os.stat_result,
        transferred: int,
    ) -> None:
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or transferred != after.st_size
        ):
            raise _staging("Restore source changed while being read")

    def _copy_regular(self, source: Path, destination: Path) -> None:
        source_fd, metadata = self._open_source_regular(source)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            destination_fd = os.open(destination, flags, 0o600)
        except OSError as exc:
            os.close(source_fd)
            raise _staging("Restore destination cannot be created") from exc
        completed = False
        transferred = 0
        try:
            os.fchown(
                destination_fd,
                metadata.st_uid,
                metadata.st_gid,
            )
            os.fchmod(
                destination_fd,
                stat.S_IMODE(metadata.st_mode) & 0o1777,
            )
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                transferred += len(chunk)
                self._write_all(destination_fd, chunk)
            self._assert_stable_source(
                source_fd,
                metadata,
                transferred,
            )
            os.fsync(destination_fd)
            completed = True
        except OSError as exc:
            raise _staging("Restore file streaming copy failed") from exc
        finally:
            os.close(source_fd)
            os.close(destination_fd)
            if not completed:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass
        try:
            self._copy_xattrs(source, destination)
            os.utime(
                destination,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                follow_symlinks=False,
            )
            fsync_directory(destination.parent)
        except (OSError, BackupError) as exc:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise _staging(
                "Restore file metadata synchronization failed"
            ) from exc

    def _copy_path(
        self,
        source: Path,
        destination: Path,
        *,
        hardlinks: dict[tuple[int, int], Path] | None = None,
    ) -> None:
        assert_safe_parents(destination)
        if destination.exists() or destination.is_symlink():
            raise _staging("Restore staging destination already exists")
        try:
            metadata = source.lstat()
        except OSError as exc:
            raise _staging("Restore staging source cannot be inspected") from exc
        links = {} if hardlinks is None else hardlinks
        if stat.S_ISDIR(metadata.st_mode):
            completed = False
            try:
                destination.mkdir(mode=0o700)
                os.chown(
                    destination,
                    metadata.st_uid,
                    metadata.st_gid,
                    follow_symlinks=False,
                )
                for child in sorted(
                    source.iterdir(),
                    key=lambda item: item.name,
                ):
                    self._copy_path(
                        child,
                        destination / child.name,
                        hardlinks=links,
                    )
                self._copy_xattrs(source, destination)
                os.chmod(
                    destination,
                    stat.S_IMODE(metadata.st_mode) & 0o1777,
                    follow_symlinks=False,
                )
                os.utime(
                    destination,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                    follow_symlinks=False,
                )
                fsync_directory(destination)
                completed = True
            except (OSError, BackupError) as exc:
                raise _staging("Restore directory staging failed") from exc
            finally:
                if not completed and (
                    destination.exists() or destination.is_symlink()
                ):
                    try:
                        self._remove_path(
                            destination,
                            boundary=destination.parent,
                        )
                    except BackupError:
                        pass
            return
        if stat.S_ISREG(metadata.st_mode):
            key = (metadata.st_dev, metadata.st_ino)
            existing = links.get(key)
            if existing is not None:
                try:
                    os.link(
                        existing,
                        destination,
                        follow_symlinks=False,
                    )
                    fsync_directory(destination.parent)
                    return
                except OSError as exc:
                    if exc.errno != errno.EXDEV:
                        raise _staging(
                            "Restore hardlink copy failed"
                        ) from exc
            self._copy_regular(source, destination)
            links[key] = destination
            return
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(source)
                os.symlink(target, destination)
                os.chown(
                    destination,
                    metadata.st_uid,
                    metadata.st_gid,
                    follow_symlinks=False,
                )
                self._copy_xattrs(source, destination)
                os.utime(
                    destination,
                    ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                    follow_symlinks=False,
                )
                fsync_directory(destination.parent)
            except (OSError, BackupError) as exc:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass
                raise _staging("Restore link staging failed") from exc
            return
        raise _staging("Restore staging source contains a special file")

    def _remove_path(
        self,
        path: Path,
        *,
        boundary: Path | None = None,
        expected_device: int | None = None,
    ) -> None:
        absolute = path.absolute()
        root = (boundary or path.parent).absolute()
        try:
            absolute.relative_to(root)
        except ValueError as exc:
            raise _staging("Restore cleanup target escapes its boundary") from exc
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _staging("Restore cleanup target cannot be inspected") from exc
        device = metadata.st_dev if expected_device is None else expected_device
        if metadata.st_dev != device:
            raise _staging("Restore cleanup crossed a filesystem boundary")
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(
            metadata.st_mode
        ):
            try:
                children = list(path.iterdir())
            except OSError as exc:
                raise _staging(
                    "Restore cleanup directory cannot be enumerated"
                ) from exc
            for child in children:
                self._remove_path(
                    child,
                    boundary=root,
                    expected_device=device,
                )
            try:
                path.rmdir()
            except OSError as exc:
                raise _staging("Restore cleanup directory cannot be removed") from exc
        else:
            try:
                path.unlink()
            except OSError as exc:
                raise _staging("Restore cleanup file cannot be removed") from exc
        fsync_directory(path.parent)

    def _extract_generation(
        self,
        backup_id: str,
        transaction: RestoreJournal,
    ) -> tuple[Path, BackupManifest]:
        verified = self._assert_eligibility_unlocked(backup_id)
        extracted_root = transaction.directory / "extracted"
        if extracted_root.exists() or extracted_root.is_symlink():
            raise _staging("Restore extraction root already exists")
        try:
            extracted_root.mkdir(mode=0o700)
            os.chown(
                extracted_root,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.chmod(extracted_root, 0o700)
            fsync_directory(extracted_root.parent)
        except (OSError, BackupError) as exc:
            raise _staging("Restore extraction root cannot be created") from exc
        try:
            for spec in component_specs(self.settings):
                temporary = extracted_root / f".extract-{spec.name}"
                archive_path = verified.path / spec.filename
                temporary.mkdir(mode=0o700)
                self.repository.archive_engine.extract_for_rehearsal(
                    spec,
                    archive_path,
                    temporary,
                )
                apply_archive_metadata(
                    self.repository.archive_engine,
                    spec,
                    archive_path,
                    temporary,
                )
                os.replace(
                    temporary / spec.namespace,
                    extracted_root / spec.namespace,
                )
                temporary.rmdir()
                fsync_directory(extracted_root)
            self.state_validator.validate_tree(
                extracted_root,
                verified.manifest,
            )
            return extracted_root, verified.manifest
        except (OSError, BackupError) as exc:
            try:
                self._remove_path(
                    extracted_root,
                    boundary=transaction.directory,
                )
            except BackupError:
                pass
            if isinstance(exc, BackupError) and exc.code == "restore_staging_failed":
                raise
            raise _staging("Restore component extraction failed") from exc

    @staticmethod
    def _stage_path_name(restore_id: str, final_path: Path) -> str:
        suffix = final_path.name or "root"
        return f".alt-deploy-{restore_id}-stage-{suffix}"

    @staticmethod
    def _rollback_path_name(restore_id: str, final_path: Path) -> str:
        suffix = final_path.name or "root"
        return f".alt-deploy-{restore_id}-rollback-{suffix}"

    def _insert_live_vault(
        self,
        staged_ansible: Path,
        expected_identities: Sequence[object],
    ) -> None:
        self.repository.secrets.assert_matches(expected_identities)
        destination = staged_ansible / "group_vars" / "vault.yml"
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._copy_path(self.settings.vault_file, destination)

    def stage(
        self,
        backup_id: str,
        transaction: RestoreJournal,
    ) -> StagedGeneration:
        if (
            transaction.phase != "prepared"
            or transaction.backup_id != backup_id
        ):
            raise _staging("Restore transaction is not prepared")
        created: list[Path] = []
        extracted_root: Path | None = None
        try:
            extracted_root, manifest = self._extract_generation(
                backup_id,
                transaction,
            )
            staged_paths: list[StagedPath] = []
            hardlinks: dict[tuple[int, int], Path] = {}
            for component in manifest.components:
                if self.fail_stage_component == component.name:
                    raise _staging("Injected restore staging failure")
                for record in component.paths:
                    production = self.repository._controller_path(
                        record.absolute_path
                    )
                    assert_safe_parents(production)
                    parent = production.parent
                    try:
                        parent_metadata = parent.lstat()
                    except OSError as exc:
                        raise _staging(
                            "Restore production parent cannot be inspected"
                        ) from exc
                    if (
                        not stat.S_ISDIR(parent_metadata.st_mode)
                        or stat.S_ISLNK(parent_metadata.st_mode)
                    ):
                        raise _staging("Restore production parent is unsafe")
                    staged = parent / self._stage_path_name(
                        transaction.restore_id,
                        production,
                    )
                    rollback = parent / self._rollback_path_name(
                        transaction.restore_id,
                        production,
                    )
                    if any(
                        candidate.exists() or candidate.is_symlink()
                        for candidate in (staged, rollback)
                    ):
                        raise _staging("Restore sibling path already exists")
                    staged_value: Path | None = None
                    if record.present:
                        source = (
                            extracted_root
                            / component.namespace
                            / record.absolute_path.lstrip("/")
                        )
                        self._copy_path(
                            source,
                            staged,
                            hardlinks=hardlinks,
                        )
                        created.append(staged)
                        staged_value = staged
                        if component.name == "ansible":
                            self._insert_live_vault(
                                staged,
                                manifest.secret_identities,
                            )
                    staged_paths.append(
                        StagedPath(
                            component=component.name,
                            absolute_path=record.absolute_path,
                            production_path=production,
                            staged_path=staged_value,
                            rollback_path=rollback,
                            present=record.present,
                        )
                    )
            transaction.transition(
                "prepared",
                "staged",
                {
                    "paths": [
                        {
                            "component": path.component,
                            "absolute_path": path.absolute_path,
                            "present": path.present,
                        }
                        for path in staged_paths
                    ]
                },
            )
            return StagedGeneration(
                backup_id=backup_id,
                restore_id=transaction.restore_id,
                extracted_root=extracted_root,
                paths=tuple(staged_paths),
                manifest=manifest,
            )
        except (BackupError, OSError) as exc:
            for path in reversed(created):
                try:
                    self._remove_path(path, boundary=path.parent)
                except BackupError:
                    pass
            if extracted_root is not None:
                try:
                    self._remove_path(
                        extracted_root,
                        boundary=transaction.directory,
                    )
                except BackupError:
                    pass
            if isinstance(exc, BackupError):
                raise
            raise _staging("Restore staging failed") from exc

    def create_pre_restore_snapshot(
        self,
        transaction: RestoreJournal,
    ) -> PreRestoreGeneration:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        parent: Path | None = None
        for _ in range(20):
            candidate = self.settings.backup_root / (
                f"pre-restore-{timestamp}-{secrets.token_hex(4)}"
            )
            try:
                (candidate / transaction.restore_id).mkdir(
                    parents=True,
                    mode=0o700,
                )
                parent = candidate
                break
            except FileExistsError:
                continue
            except OSError as exc:
                raise _staging(
                    "Pre-restore snapshot root cannot be created"
                ) from exc
        if parent is None:
            raise _staging("Pre-restore snapshot allocation failed")
        root = parent / transaction.restore_id
        try:
            for path in (parent, root):
                os.chown(
                    path,
                    self.settings.expected_root_uid,
                    self.settings.expected_root_gid,
                )
                os.chmod(path, 0o700)
            fsync_directory(parent.parent)
        except (OSError, BackupError) as exc:
            try:
                self._remove_path(parent, boundary=parent.parent)
            except BackupError:
                pass
            raise _staging(
                "Pre-restore snapshot metadata cannot be established"
            ) from exc
        records: list[dict[str, object]] = []
        try:
            for spec in component_specs(self.settings):
                record = self.repository.archive_engine.capture(
                    spec,
                    root / spec.filename,
                )
                records.append(
                    {
                        "name": record.name,
                        "filename": record.filename,
                        "size_bytes": record.size_bytes,
                        "sha256": record.sha256,
                    }
                )
            payload = {
                "schema_version": 1,
                "restore_id": transaction.restore_id,
                "backup_id": transaction.backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "components": records,
                "systemd_units": [
                    asdict(state)
                    for state in self.repository.systemd.capture()
                ],
                "secret_identities": [
                    asdict(identity)
                    for identity in self.repository.secrets.capture()
                ],
            }
            raw = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8")
            self.repository._write_private_bytes(
                root / "pre-restore-manifest.json",
                raw,
            )
            return PreRestoreGeneration(
                root=root,
                components=tuple(
                    str(record["name"])
                    for record in records
                ),
                manifest_sha256=hashlib.sha256(raw).hexdigest(),
            )
        except (BackupError, OSError):
            try:
                self._remove_path(parent, boundary=parent.parent)
            except BackupError:
                pass
            raise

    @staticmethod
    def _hash_regular(path: Path) -> bytes:
        descriptor, metadata = RestoreService._open_source_regular(path)
        digest = hashlib.sha256()
        transferred = 0
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                transferred += len(chunk)
                digest.update(chunk)
            RestoreService._assert_stable_source(
                descriptor,
                metadata,
                transferred,
            )
            return digest.digest()
        finally:
            os.close(descriptor)

    def _tree_digest(self, path: Path) -> str:
        digest = hashlib.sha256()

        def add(current: Path, relative: str) -> None:
            if not current.exists() and not current.is_symlink():
                digest.update(f"absent:{relative}\n".encode())
                return
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise _staging(
                    "Production path cannot be inspected for proof"
                ) from exc
            mode = stat.S_IMODE(metadata.st_mode)
            digest.update(
                (
                    f"{relative}:{metadata.st_uid}:"
                    f"{metadata.st_gid}:{mode}:"
                ).encode()
            )
            if stat.S_ISDIR(metadata.st_mode):
                digest.update(b"directory\n")
                for child in sorted(
                    current.iterdir(),
                    key=lambda item: item.name,
                ):
                    add(child, f"{relative}/{child.name}")
            elif stat.S_ISREG(metadata.st_mode):
                digest.update(b"regular:")
                digest.update(self._hash_regular(current))
                digest.update(b"\n")
            elif stat.S_ISLNK(metadata.st_mode):
                digest.update(b"symlink:")
                digest.update(os.readlink(current).encode("utf-8"))
                digest.update(b"\n")
            else:
                raise _staging(
                    "Production path contains a special file"
                )
            for name in self._list_xattrs(current):
                try:
                    value = os.getxattr(
                        current,
                        name,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise _staging(
                        "Production xattr proof cannot be read"
                    ) from exc
                digest.update(name.encode("utf-8"))
                digest.update(hashlib.sha256(value).digest())

        add(path, path.name or "/")
        return digest.hexdigest()

    @contextmanager
    def _staged_lifecycle_lock(
        self,
        staged: StagedGeneration,
    ) -> Iterator[None]:
        state = next(
            (
                path
                for path in staged.paths
                if path.absolute_path == "/var/lib/alt-deploy"
            ),
            None,
        )
        if state is None or state.staged_path is None:
            raise _staging(
                "Staged controller lifecycle lock is unavailable"
            )
        lock_path = state.staged_path / "workstationctl.lock"
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(lock_path, flags)
        except OSError as exc:
            raise _staging(
                "Staged lifecycle lock cannot be opened"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise _staging("Staged lifecycle lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _daemon_reload(self) -> None:
        try:
            result = subprocess.run(
                [str(self.settings.systemctl_path), "daemon-reload"],
                check=False,
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _health("systemd daemon-reload failed") from exc
        if result.returncode != 0:
            raise _health("systemd daemon-reload failed")

    def _compile_python_root(self, root: Path) -> None:
        if not root.exists():
            return
        for path in sorted(root.rglob("*.py")):
            raw = read_regular_bytes(
                path,
                max_bytes=64 * 1024 * 1024,
            )
            try:
                compile(raw.decode("utf-8"), str(path), "exec")
            except (UnicodeDecodeError, SyntaxError) as exc:
                raise _health(
                    "Restored runtime Python syntax is invalid"
                ) from exc

    def _run_health_command(
        self,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        name: str,
    ) -> None:
        if self.fail_health_check == name:
            raise _health(f"Injected restore health failure: {name}")
        try:
            result = subprocess.run(
                arguments,
                cwd=cwd,
                env=env,
                check=False,
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _health(
                f"Restore health check failed: {name}"
            ) from exc
        if (
            result.returncode != 0
            or len(result.stdout) > 1024 * 1024
            or len(result.stderr) > 1024 * 1024
        ):
            raise _health(f"Restore health check failed: {name}")

    def _pre_activation_health(
        self,
        manifest: BackupManifest,
    ) -> tuple[str, ...]:
        if self.fail_health_check == "runtime_syntax":
            raise _health(
                "Injected restore health failure: runtime_syntax"
            )
        self._compile_python_root(self.settings.runtime_control_root)
        self._compile_python_root(self.settings.runtime_api_root)

        for path in (
            self.settings.workstationctl_path,
            self.settings.worker_path,
            self.settings.stage_helper_path,
            self.settings.bootstrap_root / "bootstrap.sh",
            self.settings.bootstrap_root / "alt-bootstrap-register",
        ):
            if not path.exists():
                continue
            raw = read_regular_bytes(
                path,
                max_bytes=16 * 1024 * 1024,
            )
            lines = raw.splitlines()
            if lines and b"sh" in lines[0]:
                self._run_health_command(
                    ["/bin/bash", "-n", str(path)],
                    name="shell_syntax",
                )

        units = [
            self.settings.systemd_root / state.name
            for state in manifest.systemd_units
            if state.load_state != "not-found"
        ]
        if units:
            self._run_health_command(
                [
                    str(self.settings.systemd_analyze_path),
                    "verify",
                    *[str(path) for path in units],
                ],
                name="systemd_units",
            )

        for playbook in sorted(
            (self.settings.ansible_root / "playbooks").glob("*.yml")
        ):
            environment = os.environ.copy()
            environment["ANSIBLE_CONFIG"] = str(
                self.settings.ansible_root / "ansible.cfg"
            )
            self._run_health_command(
                [
                    str(self.settings.ansible_playbook_path),
                    "--syntax-check",
                    "--inventory",
                    "localhost,",
                    "--vault-password-file",
                    str(self.settings.vault_password_file),
                    "--extra-vars",
                    f"@{self.settings.vault_file}",
                    str(playbook),
                ],
                cwd=self.settings.ansible_root,
                env=environment,
                name="ansible_syntax",
            )

        if self.fail_health_check == "state_validation":
            raise _health(
                "Injected restore health failure: state_validation"
            )
        self.state_validator._validate_jobs(
            self.settings.controller_state_root / "jobs"
        )
        self.state_validator._validate_assignments(
            self.settings.controller_state_root / "assignments"
        )
        self.state_validator._validate_registrations(
            self.settings.registration_root
        )
        self.state_validator._validate_machine_archives(
            self.settings.controller_state_root / "machine-archives"
        )
        self.repository.secrets.assert_matches(
            manifest.secret_identities
        )
        self.repository.quiescence.assert_quiescent()
        return (
            "runtime_syntax",
            "shell_syntax",
            "systemd_units",
            "ansible_syntax",
            "state_validation",
            "secret_identities",
            "quiescence",
        )

    @staticmethod
    def _default_health_probe(url: str) -> bytes:
        request = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(
                request,
                timeout=5,
            ) as response:
                if response.status != 200:
                    raise _health("Loopback health endpoint returned an error")
                body = response.read(64 * 1024 + 1)
        except (
            OSError,
            urllib.error.URLError,
            urllib.error.HTTPError,
        ) as exc:
            if isinstance(exc, BackupError):
                raise
            raise _health("Loopback health endpoint is unavailable") from exc
        if len(body) > 64 * 1024:
            raise _health("Loopback health response is too large")
        return body

    def _loopback_health(
        self,
        manifest: BackupManifest,
    ) -> tuple[str, ...]:
        by_name = {state.name: state for state in manifest.systemd_units}
        checks: list[str] = []
        http = by_name["alt-deploy-http.service"]
        if http.load_state != "not-found" and http.active_state == "active":
            if self.fail_health_check == "http_loopback":
                raise _health(
                    "Injected restore health failure: http_loopback"
                )
            self.health_probe(
                "http://127.0.0.1:8087/bootstrap/bootstrap.sh"
            )
            checks.append("http_loopback")
        registration = by_name["alt-deploy-register.service"]
        if (
            registration.load_state != "not-found"
            and registration.active_state == "active"
        ):
            if self.fail_health_check == "registration_loopback":
                raise _health(
                    "Injected restore health failure: registration_loopback"
                )
            raw = self.health_probe(
                "http://127.0.0.1:8088/health"
            )
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise _health(
                    "Registration health response is invalid"
                ) from exc
            if payload != {"status": "ok"}:
                raise _health(
                    "Registration health response is unhealthy"
                )
            checks.append("registration_loopback")
        return tuple(checks)

    @staticmethod
    def _serialize_states(
        states: Sequence[UnitState],
    ) -> list[dict[str, object]]:
        return [asdict(state) for state in states]

    @staticmethod
    def _deserialize_states(raw: object) -> tuple[UnitState, ...]:
        if not isinstance(raw, list) or len(raw) != 4:
            raise _staging("Restore journal service state is invalid")
        expected_keys = {
            "name",
            "load_state",
            "enabled_state",
            "active_state",
            "sub_state",
            "failed",
        }
        states: list[UnitState] = []
        for item in raw:
            if not isinstance(item, dict) or set(item) != expected_keys:
                raise _staging("Restore journal service state is invalid")
            if not all(
                isinstance(item[key], str)
                for key in expected_keys - {"failed"}
            ) or type(item["failed"]) is not bool:
                raise _staging("Restore journal service state is invalid")
            states.append(
                UnitState(
                    name=item["name"],
                    load_state=item["load_state"],
                    enabled_state=item["enabled_state"],
                    active_state=item["active_state"],
                    sub_state=item["sub_state"],
                    failed=item["failed"],
                )
            )
        return tuple(states)

    def _journal_pre_states(
        self,
        journal: RestoreJournal,
    ) -> tuple[UnitState, ...]:
        prepared = journal.evidence.get("prepared")
        if not isinstance(prepared, dict):
            raise _manual(journal.restore_id)
        try:
            return self._deserialize_states(prepared.get("pre_states"))
        except BackupError as exc:
            raise _manual(journal.restore_id) from exc

    def _expected_staged_policy(
        self,
    ) -> tuple[tuple[str, str], ...]:
        expected: list[tuple[str, str]] = []
        for spec in component_specs(self.settings):
            for source in spec.paths:
                expected.append(
                    (
                        spec.name,
                        self.repository.archive_engine._logical_path(source),
                    )
                )
        return tuple(expected)

    def _staged_paths_from_journal(
        self,
        journal: RestoreJournal,
    ) -> tuple[StagedPath, ...]:
        staged = journal.evidence.get("staged")
        if not isinstance(staged, dict) or set(staged) != {"paths"}:
            raise _manual(journal.restore_id)
        raw_paths = staged.get("paths")
        expected = self._expected_staged_policy()
        if not isinstance(raw_paths, list) or len(raw_paths) != len(expected):
            raise _manual(journal.restore_id)
        result: list[StagedPath] = []
        for raw, (expected_component, expected_path) in zip(
            raw_paths,
            expected,
            strict=True,
        ):
            if not isinstance(raw, dict) or set(raw) != {
                "component",
                "absolute_path",
                "present",
            }:
                raise _manual(journal.restore_id)
            present = raw.get("present")
            if (
                raw.get("component") != expected_component
                or raw.get("absolute_path") != expected_path
                or type(present) is not bool
            ):
                raise _manual(journal.restore_id)
            production = self.repository._controller_path(expected_path)
            staged_path = (
                production.parent
                / self._stage_path_name(journal.restore_id, production)
                if present
                else None
            )
            result.append(
                StagedPath(
                    component=expected_component,
                    absolute_path=expected_path,
                    production_path=production,
                    staged_path=staged_path,
                    rollback_path=(
                        production.parent
                        / self._rollback_path_name(
                            journal.restore_id,
                            production,
                        )
                    ),
                    present=present,
                )
            )
        return tuple(result)

    def _moving_evidence(
        self,
        journal: RestoreJournal,
        paths: Sequence[StagedPath],
    ) -> tuple[dict[str, object], list[dict[str, object]]]:
        raw = journal.evidence.get("originals_moving")
        if not isinstance(raw, dict) or set(raw) != {
            "paths",
            "pre_restore_root",
            "pre_restore_manifest_sha256",
        }:
            raise _manual(journal.restore_id)
        raw_paths = raw.get("paths")
        if not isinstance(raw_paths, list) or len(raw_paths) != len(paths):
            raise _manual(journal.restore_id)
        digest_re = __import__("re").compile(r"^[0-9a-f]{64}$")
        validated: list[dict[str, object]] = []
        for item, path in zip(raw_paths, paths, strict=True):
            if not isinstance(item, dict) or set(item) != {
                "component",
                "absolute_path",
                "present",
                "previously_present",
                "processed",
                "moved",
                "pre_digest",
            }:
                raise _manual(journal.restore_id)
            if (
                item.get("component") != path.component
                or item.get("absolute_path") != path.absolute_path
                or item.get("present") != path.present
                or type(item.get("previously_present")) is not bool
                or type(item.get("processed")) is not bool
                or type(item.get("moved")) is not bool
                or not isinstance(item.get("pre_digest"), str)
                or not digest_re.fullmatch(str(item.get("pre_digest")))
            ):
                raise _manual(journal.restore_id)
            if item["moved"] and (
                not item["processed"] or not item["previously_present"]
            ):
                raise _manual(journal.restore_id)
            validated.append(dict(item))
        root = raw.get("pre_restore_root")
        manifest_hash = raw.get("pre_restore_manifest_sha256")
        if (
            not isinstance(root, str)
            or not root
            or root.startswith("/")
            or ".." in Path(root).parts
            or not isinstance(manifest_hash, str)
            or not digest_re.fullmatch(manifest_hash)
        ):
            raise _manual(journal.restore_id)
        return dict(raw), validated

    def _initial_moving_evidence(
        self,
        staged: StagedGeneration,
        snapshot: PreRestoreGeneration,
        pre_digests: Mapping[str, str],
    ) -> dict[str, object]:
        relative_snapshot = snapshot.root.relative_to(
            self.settings.backup_root
        )
        return {
            "pre_restore_root": relative_snapshot.as_posix(),
            "pre_restore_manifest_sha256": snapshot.manifest_sha256,
            "paths": [
                {
                    "component": path.component,
                    "absolute_path": path.absolute_path,
                    "present": path.present,
                    "previously_present": (
                        path.production_path.exists()
                        or path.production_path.is_symlink()
                    ),
                    "processed": False,
                    "moved": False,
                    "pre_digest": pre_digests[path.absolute_path],
                }
                for path in staged.paths
            ],
        }

    def _move_originals(
        self,
        staged: StagedGeneration,
        journal: RestoreJournal,
        moving: dict[str, object],
    ) -> tuple[dict[str, object], ...]:
        raw_paths = moving.get("paths")
        if not isinstance(raw_paths, list):
            raise _staging("Restore move plan is invalid")
        moved_count = 0
        evidence: list[dict[str, object]] = []
        for path, raw in zip(staged.paths, raw_paths, strict=True):
            if not isinstance(raw, dict):
                raise _staging("Restore move plan is invalid")
            if bool(raw["previously_present"]):
                try:
                    os.replace(
                        path.production_path,
                        path.rollback_path,
                    )
                    fsync_directory(path.production_path.parent)
                except (OSError, BackupError) as exc:
                    raise _staging(
                        "Current production path cannot be moved"
                    ) from exc
                raw["moved"] = True
                moved_count += 1
            raw["processed"] = True
            journal.record_phase(moving)
            evidence.append(
                {
                    "absolute_path": path.absolute_path,
                    "previously_present": bool(
                        raw["previously_present"]
                    ),
                }
            )
            if (
                self.interrupt_move_after is not None
                and moved_count >= self.interrupt_move_after
            ):
                raise RuntimeError("simulated restore interruption")
            if (
                self.fail_move_after is not None
                and moved_count >= self.fail_move_after
            ):
                raise _staging("Injected partial original move failure")
        return tuple(evidence)

    def _install_staged(self, staged: StagedGeneration) -> None:
        for path in staged.paths:
            if not path.present:
                continue
            if path.staged_path is None:
                raise _staging("Expected staged path is missing")
            try:
                os.replace(
                    path.staged_path,
                    path.production_path,
                )
                fsync_directory(path.production_path.parent)
            except (OSError, BackupError) as exc:
                raise _staging("Staged path cannot be installed") from exc

    def _rollback(
        self,
        paths: Sequence[StagedPath],
        journal: RestoreJournal,
        pre_states: Sequence[UnitState],
    ) -> None:
        self.repository.systemd.stop_maintenance()
        if self.fail_rollback:
            raise _manual(journal.restore_id)
        try:
            _, progress = self._moving_evidence(journal, paths)
            for path, item in reversed(
                tuple(zip(paths, progress, strict=True))
            ):
                production_exists = (
                    path.production_path.exists()
                    or path.production_path.is_symlink()
                )
                rollback_exists = (
                    path.rollback_path.exists()
                    or path.rollback_path.is_symlink()
                )
                if bool(item["previously_present"]):
                    if rollback_exists:
                        if production_exists:
                            self._remove_path(
                                path.production_path,
                                boundary=path.production_path.parent,
                            )
                        os.replace(
                            path.rollback_path,
                            path.production_path,
                        )
                        fsync_directory(path.production_path.parent)
                    elif not production_exists:
                        raise _manual(journal.restore_id)
                else:
                    if rollback_exists:
                        raise _manual(journal.restore_id)
                    if production_exists:
                        self._remove_path(
                            path.production_path,
                            boundary=path.production_path.parent,
                        )

            self._daemon_reload()
            failed_rollout = (
                self.guard.has_matching_rollout_marker_unlocked(journal)
            )
            self.repository.systemd.restore(
                pre_states,
                activate_health_services=not failed_rollout,
            )
            for path, item in zip(paths, progress, strict=True):
                if self._tree_digest(path.production_path) != item["pre_digest"]:
                    raise _manual(journal.restore_id)
            self.guard.revoke_restore_unlocked(journal)
            journal.transition(
                journal.phase,
                "rolled_back",
                {
                    "proof": "content_digests_match",
                    "services_restored": not failed_rollout,
                },
            )
        except (OSError, BackupError) as exc:
            if isinstance(exc, BackupError) and exc.code == (
                "restore_manual_recovery_required"
            ):
                raise
            raise _manual(journal.restore_id) from exc

    def _cleanup_after_commit(self, staged: StagedGeneration) -> bool:
        if self.fail_cleanup:
            return False
        try:
            for path in staged.paths:
                for candidate in (
                    path.rollback_path,
                    path.staged_path,
                ):
                    if candidate is not None and (
                        candidate.exists() or candidate.is_symlink()
                    ):
                        self._remove_path(
                            candidate,
                            boundary=candidate.parent,
                        )
            if staged.extracted_root.exists():
                self._remove_path(
                    staged.extracted_root,
                    boundary=staged.extracted_root.parent,
                )
            return True
        except BackupError:
            return False

    def _cleanup_before_mutation(self, staged: StagedGeneration) -> None:
        for path in staged.paths:
            if path.staged_path is not None and (
                path.staged_path.exists() or path.staged_path.is_symlink()
            ):
                self._remove_path(
                    path.staged_path,
                    boundary=path.staged_path.parent,
                )
        if staged.extracted_root.exists():
            self._remove_path(
                staged.extracted_root,
                boundary=staged.extracted_root.parent,
            )

    def _cleanup_recovery_paths(
        self,
        paths: Sequence[StagedPath],
        journal: RestoreJournal,
    ) -> bool:
        try:
            for path in paths:
                for candidate in (path.staged_path, path.rollback_path):
                    if candidate is not None and (
                        candidate.exists() or candidate.is_symlink()
                    ):
                        self._remove_path(
                            candidate,
                            boundary=candidate.parent,
                        )
            extracted = journal.directory / "extracted"
            if extracted.exists() or extracted.is_symlink():
                self._remove_path(
                    extracted,
                    boundary=journal.directory,
                )
            return True
        except BackupError:
            return False

    def _record_manual_recovery(
        self,
        journal: RestoreJournal,
    ) -> None:
        try:
            self.guard.revoke_restore_unlocked(journal)
        except BackupError:
            pass
        if journal.phase not in terminal_phases():
            try:
                journal.transition(
                    journal.phase,
                    "manual_recovery_required",
                    {"services_stopped": True},
                )
            except BackupError:
                pass
        self.repository.systemd.stop_maintenance()

    def restore(self, backup_id: str) -> RestoreResult:
        self.repository.assert_rehearsed_eligibility(backup_id)
        self.repository.quiescence.assert_quiescent()
        with exclusive_operation_lock(self.settings):
            verified = self._assert_eligibility_unlocked(backup_id)
            self._assert_restore_capacity(verified)
            pre_states = self.repository.systemd.capture()
            journal = RestoreJournal.create(self.settings, backup_id)
            journal.record_phase(
                {"pre_states": self._serialize_states(pre_states)}
            )
            staged: StagedGeneration | None = None
            committed = False
            try:
                self.repository.systemd.stop_maintenance()
                with exclusive_lifecycle_lock(self.settings):
                    verified = self._assert_eligibility_unlocked(
                        backup_id
                    )
                    self.repository.secrets.assert_matches(
                        verified.manifest.secret_identities
                    )
                    self.repository.quiescence.assert_quiescent()
                    snapshot = self.create_pre_restore_snapshot(journal)
                    journal.record_phase(
                        {
                            "pre_states": self._serialize_states(pre_states),
                            "pre_restore_root": str(
                                snapshot.root.relative_to(
                                    self.settings.backup_root
                                )
                            ),
                            "pre_restore_manifest_sha256": (
                                snapshot.manifest_sha256
                            ),
                        }
                    )
                    staged = self.stage(backup_id, journal)
                    journal.transition(
                        "staged",
                        "services_stopped",
                        {
                            "pre_restore_root": str(
                                snapshot.root.relative_to(
                                    self.settings.backup_root
                                )
                            ),
                            "pre_restore_manifest_sha256": (
                                snapshot.manifest_sha256
                            ),
                        },
                    )
                    pre_digests = {
                        path.absolute_path: self._tree_digest(
                            path.production_path
                        )
                        for path in staged.paths
                    }
                    moving = self._initial_moving_evidence(
                        staged,
                        snapshot,
                        pre_digests,
                    )
                    journal.transition(
                        "services_stopped",
                        "originals_moving",
                        moving,
                    )
                    with self._staged_lifecycle_lock(staged):
                        moved = self._move_originals(
                            staged,
                            journal,
                            moving,
                        )
                        journal.transition(
                            "originals_moving",
                            "originals_moved",
                            {"paths": list(moved)},
                        )
                        self._install_staged(staged)
                        journal.transition(
                            "originals_moved",
                            "installed",
                            {"path_count": len(staged.paths)},
                        )
                        self._daemon_reload()
                        journal.transition(
                            "installed",
                            "daemon_reloaded",
                            {},
                        )
                        pre_checks = self._pre_activation_health(
                            staged.manifest
                        )
                        self.guard.authorize_restore_unlocked(journal)
                        self.repository.systemd.restore(
                            staged.manifest.systemd_units,
                            activate_health_services=True,
                        )
                        loopback_checks = self._loopback_health(
                            staged.manifest
                        )
                        journal.transition(
                            "daemon_reloaded",
                            "health_checked",
                            {
                                "checks": list(
                                    (*pre_checks, *loopback_checks)
                                )
                            },
                        )
                        journal.transition(
                            "health_checked",
                            "committed",
                            {"services_restored": True},
                        )
                        committed = True
                        self.guard.complete_restore_unlocked(journal)
                cleanup_complete = self._cleanup_after_commit(staged)
                return RestoreResult(
                    backup_id=backup_id,
                    phase="committed",
                    services_restored=True,
                    rollback_performed=False,
                    cleanup_complete=cleanup_complete,
                )
            except BackupError as original:
                if committed or journal.phase == "committed":
                    self.repository.systemd.stop_maintenance()
                    raise original
                if journal.phase in {
                    "originals_moving",
                    "originals_moved",
                    "installed",
                    "daemon_reloaded",
                    "health_checked",
                }:
                    try:
                        paths = (
                            staged.paths
                            if staged is not None
                            else self._staged_paths_from_journal(journal)
                        )
                        self._rollback(paths, journal, pre_states)
                        self._cleanup_recovery_paths(paths, journal)
                    except BackupError:
                        self._record_manual_recovery(journal)
                        raise _manual(journal.restore_id)
                    raise original

                if staged is not None:
                    try:
                        self._cleanup_before_mutation(staged)
                    except BackupError:
                        pass
                failed_rollout = (
                    self.guard.has_matching_rollout_marker_unlocked(journal)
                )
                self.repository.systemd.restore(
                    pre_states,
                    activate_health_services=not failed_rollout,
                )
                self.guard.revoke_restore_unlocked(journal)
                journal.transition(
                    journal.phase,
                    "aborted",
                    {"production_changed": False},
                )
                raise

    def recover(self, restore_id: str) -> RestoreResult:
        with exclusive_operation_lock(self.settings):
            journal = RestoreJournal.load(self.settings, restore_id)
            if journal.phase == "manual_recovery_required":
                self.repository.systemd.stop_maintenance()
                raise _manual(journal.restore_id)
            if journal.phase == "committed":
                try:
                    self.guard.complete_restore_unlocked(journal)
                except BackupError:
                    self.repository.systemd.stop_maintenance()
                    raise
                paths: tuple[StagedPath, ...] = ()
                if "staged" in journal.evidence:
                    paths = self._staged_paths_from_journal(journal)
                cleanup_complete = self._cleanup_recovery_paths(
                    paths,
                    journal,
                )
                return RestoreResult(
                    backup_id=journal.backup_id,
                    phase="committed",
                    services_restored=True,
                    rollback_performed=False,
                    cleanup_complete=cleanup_complete,
                )
            if journal.phase == "rolled_back":
                self.guard.revoke_restore_unlocked(journal)
                failed_rollout = (
                    self.guard.has_matching_rollout_marker_unlocked(journal)
                )
                if failed_rollout:
                    self.repository.systemd.stop_maintenance()
                return RestoreResult(
                    backup_id=journal.backup_id,
                    phase="rolled_back",
                    services_restored=not failed_rollout,
                    rollback_performed=True,
                    cleanup_complete=True,
                )
            if journal.phase == "aborted":
                self.guard.revoke_restore_unlocked(journal)
                failed_rollout = (
                    self.guard.has_matching_rollout_marker_unlocked(journal)
                )
                if failed_rollout:
                    self.repository.systemd.stop_maintenance()
                return RestoreResult(
                    backup_id=journal.backup_id,
                    phase="aborted",
                    services_restored=not failed_rollout,
                    rollback_performed=False,
                    cleanup_complete=True,
                )

            try:
                pre_states = self._journal_pre_states(journal)
            except BackupError:
                self._record_manual_recovery(journal)
                raise _manual(journal.restore_id)

            self.repository.systemd.stop_maintenance()
            if journal.phase in {"prepared", "staged", "services_stopped"}:
                paths: tuple[StagedPath, ...] = ()
                if "staged" in journal.evidence:
                    try:
                        paths = self._staged_paths_from_journal(journal)
                    except BackupError:
                        self._record_manual_recovery(journal)
                        raise _manual(journal.restore_id)
                cleanup_complete = self._cleanup_recovery_paths(
                    paths,
                    journal,
                )
                try:
                    failed_rollout = (
                        self.guard.has_matching_rollout_marker_unlocked(
                            journal
                        )
                    )
                    self.repository.systemd.restore(
                        pre_states,
                        activate_health_services=not failed_rollout,
                    )
                    self.guard.revoke_restore_unlocked(journal)
                    journal.transition(
                        journal.phase,
                        "aborted",
                        {"production_changed": False},
                    )
                except BackupError:
                    self._record_manual_recovery(journal)
                    raise _manual(journal.restore_id)
                return RestoreResult(
                    backup_id=journal.backup_id,
                    phase="aborted",
                    services_restored=True,
                    rollback_performed=False,
                    cleanup_complete=cleanup_complete,
                )

            try:
                paths = self._staged_paths_from_journal(journal)
                self._rollback(paths, journal, pre_states)
                cleanup_complete = self._cleanup_recovery_paths(
                    paths,
                    journal,
                )
            except BackupError:
                self._record_manual_recovery(journal)
                raise _manual(journal.restore_id)
            return RestoreResult(
                backup_id=journal.backup_id,
                phase="rolled_back",
                services_restored=True,
                rollback_performed=True,
                cleanup_complete=cleanup_complete,
            )
