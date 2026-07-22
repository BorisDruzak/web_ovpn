from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .archive import ArchiveEngine
from .components import ComponentSpec, component_specs
from .errors import BackupError
from .fs import (
    assert_safe_parents,
    fsync_directory,
    read_regular_bytes,
    source_inventory,
    validate_private_directory,
)
from .locks import exclusive_lifecycle_lock, exclusive_operation_lock
from .manifest import (
    SCHEMA_VERSION,
    BackupManifest,
    ComponentRecord,
    ControllerRecord,
    PreflightRecord,
    parse_manifest,
)
from .quiescence import QuiescenceChecker
from .secrets import SecretIdentityProvider
from .settings import BackupSettings
from .systemd import SystemdManager


@dataclass(frozen=True)
class CreateResult:
    backup_id: str
    manifest_sha256: str
    component_count: int
    services_restored: bool


def _preflight(message: str) -> BackupError:
    return BackupError(
        code="backup_preflight_failed",
        message=message,
        exit_code=4,
    )


def _component_failure(message: str) -> BackupError:
    return BackupError(
        code="backup_component_failed",
        message=message,
        exit_code=4,
    )


def _integrity_failure(message: str) -> BackupError:
    return BackupError(
        code="backup_integrity_failed",
        message=message,
        exit_code=4,
    )


class BackupRepository:
    def __init__(
        self,
        settings: BackupSettings,
        *,
        archive_engine: ArchiveEngine | None = None,
        systemd_manager: SystemdManager | None = None,
        quiescence_checker: QuiescenceChecker | None = None,
        secret_provider: SecretIdentityProvider | None = None,
    ) -> None:
        self.settings = settings
        self.archive_engine = archive_engine or ArchiveEngine(settings)
        self.systemd = systemd_manager or SystemdManager(settings)
        self.quiescence = quiescence_checker or QuiescenceChecker(
            settings,
            systemd_manager=self.systemd,
        )
        self.secrets = secret_provider or SecretIdentityProvider(settings)

    def _controller_root(self) -> Path:
        try:
            return self.settings.backup_root.parents[2]
        except IndexError as exc:
            raise _preflight("Controller root cannot be derived") from exc

    def _controller_path(self, absolute_path: str) -> Path:
        root = self._controller_root()
        if root == Path("/"):
            return Path(absolute_path)
        return root / absolute_path.lstrip("/")

    def _validate_roots(self) -> None:
        for path in (
            self.settings.backup_root,
            self.settings.private_state_root,
        ):
            validate_private_directory(
                path,
                uid=self.settings.expected_root_uid,
                gid=self.settings.expected_root_gid,
                mode=0o700,
            )

        log_parent = self.settings.log_file.parent
        assert_safe_parents(self.settings.log_file)
        try:
            metadata = log_parent.lstat()
        except OSError as exc:
            raise _preflight("Backup log parent cannot be inspected") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.settings.expected_root_uid
            or metadata.st_gid != self.settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise _preflight("Backup log parent metadata is unsafe")

    def _validate_commands(self) -> None:
        commands = (
            self.settings.tar_path,
            self.settings.zstd_path,
            self.settings.systemctl_path,
            self.settings.systemd_analyze_path,
            self.settings.ansible_playbook_path,
            self.settings.ssh_keygen_path,
        )
        for command in commands:
            try:
                metadata = command.lstat()
            except OSError as exc:
                raise _preflight("Required backup command is missing") from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or not os.access(command, os.X_OK)
            ):
                raise _preflight("Required backup command is unsafe")

    def _source_paths(self, specs: Sequence[ComponentSpec]) -> tuple[Path, ...]:
        unique: dict[str, Path] = {}
        for spec in specs:
            for path in spec.paths:
                if path.exists() or path.is_symlink():
                    unique[str(path.absolute())] = path
        return tuple(unique[key] for key in sorted(unique))

    def _check_disk_space(self, paths: Sequence[Path]) -> None:
        inventory = source_inventory(paths)
        source_bytes = sum(
            entry.size for entry in inventory if entry.kind == "regular"
        )
        required = max(64 * 1024 * 1024, source_bytes * 2)
        try:
            free = shutil.disk_usage(self.settings.backup_root).free
        except OSError as exc:
            raise _preflight("Backup free space cannot be inspected") from exc
        if free < required:
            raise _preflight("Insufficient free space for backup")

    def _allocate_backup_id(self) -> tuple[str, Path, Path]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for _ in range(20):
            backup_id = f"backup-{timestamp}-{secrets.token_hex(4)}"
            temporary = self.settings.backup_root / f".creating-{backup_id}"
            published = self.settings.backup_root / backup_id
            if any(
                path.exists() or path.is_symlink()
                for path in (temporary, published)
            ):
                continue
            try:
                temporary.mkdir(mode=0o700)
            except FileExistsError:
                continue
            except OSError as exc:
                raise _preflight(
                    "Temporary backup directory cannot be created"
                ) from exc
            try:
                os.chown(
                    temporary,
                    self.settings.expected_root_uid,
                    self.settings.expected_root_gid,
                )
                os.chmod(temporary, 0o700)
                fsync_directory(self.settings.backup_root)
            except OSError as exc:
                self._remove_temporary(temporary)
                raise _preflight(
                    "Temporary backup directory metadata is invalid"
                ) from exc
            return backup_id, temporary, published
        raise _preflight("Unable to allocate a unique backup identifier")

    def _remove_temporary(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError:
            return
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return
        shutil.rmtree(path, ignore_errors=True)
        try:
            fsync_directory(path.parent)
        except BackupError:
            pass

    def _write_private_bytes(self, path: Path, raw: bytes) -> None:
        temporary = path.parent / (
            f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except OSError as exc:
            raise _component_failure("Backup metadata cannot be created") from exc
        try:
            os.fchown(
                descriptor,
                self.settings.expected_root_uid,
                self.settings.expected_root_gid,
            )
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written < 1:
                    raise _component_failure(
                        "Backup metadata write made no progress"
                    )
                offset += written
            os.fsync(descriptor)
        except OSError as exc:
            raise _component_failure("Backup metadata write failed") from exc
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, path)
            fsync_directory(path.parent)
        except (OSError, BackupError) as exc:
            temporary.unlink(missing_ok=True)
            raise _component_failure("Backup metadata publication failed") from exc

    @staticmethod
    def _sha256_file(path: Path) -> tuple[int, str]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise _integrity_failure(
                "Backup component cannot be opened safely"
            ) from exc
        digest = hashlib.sha256()
        size = 0
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise _integrity_failure(
                    "Backup component is not a regular file"
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
                raise _integrity_failure(
                    "Backup component changed while hashing"
                )
        finally:
            os.close(descriptor)
        return size, digest.hexdigest()

    def _read_optional_text(
        self,
        absolute_path: str,
        *,
        maximum: int,
    ) -> str | None:
        path = self._controller_path(absolute_path)
        if not path.exists() and not path.is_symlink():
            return None
        raw = read_regular_bytes(path, max_bytes=maximum)
        try:
            return raw.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise _preflight("Controller metadata is not UTF-8") from exc

    def _controller_record(self) -> ControllerRecord:
        hostname = self._read_optional_text("/etc/hostname", maximum=1024)
        if not hostname:
            raise _preflight("Controller hostname is unavailable")
        machine_id = self._read_optional_text(
            "/etc/machine-id",
            maximum=1024,
        )
        os_release = self._read_optional_text(
            "/etc/os-release",
            maximum=64 * 1024,
        )
        if os_release is None:
            raise _preflight("Controller OS metadata is unavailable")
        values: dict[str, str] = {}
        for line in os_release.splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"'", '"'}
            ):
                value = value[1:-1]
            values[key] = value
        os_id = values.get("ID", "")
        os_version_id = values.get("VERSION_ID", "")
        os_pretty_name = values.get("PRETTY_NAME", "")
        if not os_id or not os_version_id or not os_pretty_name:
            raise _preflight("Controller OS metadata is incomplete")
        repository_commit = self._read_optional_text(
            "/opt/alt-deploy-control/.repository-commit",
            maximum=1024,
        )
        return ControllerRecord(
            hostname=hostname,
            machine_id=machine_id or None,
            os_id=os_id,
            os_version_id=os_version_id,
            os_pretty_name=os_pretty_name,
            repository_commit=repository_commit or None,
        )

    def _validate_temporary_bundle(
        self,
        temporary: Path,
        manifest: BackupManifest,
        specs: Sequence[ComponentSpec],
    ) -> str:
        manifest_path = temporary / "manifest.json"
        raw = read_regular_bytes(manifest_path, max_bytes=16 * 1024 * 1024)
        parsed = parse_manifest(raw)
        if parsed.to_dict() != manifest.to_dict():
            raise _integrity_failure("Temporary manifest changed after creation")
        by_name = {record.name: record for record in parsed.components}
        for spec in specs:
            record = by_name[spec.name]
            archive_path = temporary / spec.filename
            size, digest = self._sha256_file(archive_path)
            if size != record.size_bytes or digest != record.sha256:
                raise _integrity_failure(
                    "Temporary component hash or size does not match"
                )
            self.archive_engine.inspect(spec, archive_path)
        return hashlib.sha256(raw).hexdigest()

    def create(self) -> CreateResult:
        with exclusive_operation_lock(self.settings):
            self._validate_roots()
            self._validate_commands()
            specs = component_specs(self.settings)
            source_paths = self._source_paths(specs)
            self._check_disk_space(source_paths)
            secret_identities = self.secrets.capture()
            self.quiescence.assert_quiescent()
            original_states = self.systemd.capture()
            services_stopped = False
            temporary: Path | None = None
            published: Path | None = None
            result: CreateResult | None = None
            try:
                self.systemd.stop_maintenance()
                services_stopped = True
                with exclusive_lifecycle_lock(self.settings):
                    self.secrets.assert_matches(secret_identities)
                    self.quiescence.assert_quiescent()
                    before = source_inventory(source_paths)
                    backup_id, temporary, published = self._allocate_backup_id()
                    component_records: list[ComponentRecord] = []
                    for spec in specs:
                        component_records.append(
                            self.archive_engine.capture(
                                spec,
                                temporary / spec.filename,
                            )
                        )
                    after = source_inventory(source_paths)
                    if after != before:
                        raise _component_failure(
                            "Controller sources changed during backup capture"
                        )
                    manifest = BackupManifest(
                        schema_version=SCHEMA_VERSION,
                        utility_version=__version__,
                        backup_id=backup_id,
                        created_at=datetime.now(timezone.utc).isoformat(),
                        controller=self._controller_record(),
                        components=tuple(component_records),
                        systemd_units=tuple(original_states),
                        secret_identities=tuple(secret_identities),
                        preflight=PreflightRecord(
                            active_jobs_empty=True,
                            transient_units_empty=True,
                            pending_registration_empty=True,
                            processor_inactive=True,
                            secrets_valid=True,
                            sources_safe=True,
                            disk_space_sufficient=True,
                        ),
                        restore_order=tuple(spec.name for spec in specs),
                    )
                    self._write_private_bytes(
                        temporary / "manifest.json",
                        manifest.to_bytes(),
                    )
                    manifest_sha256 = self._validate_temporary_bundle(
                        temporary,
                        manifest,
                        specs,
                    )
                    try:
                        os.replace(temporary, published)
                        temporary = None
                        fsync_directory(self.settings.backup_root)
                    except (OSError, BackupError) as exc:
                        raise _component_failure(
                            "Backup bundle publication failed"
                        ) from exc
                    result = CreateResult(
                        backup_id=backup_id,
                        manifest_sha256=manifest_sha256,
                        component_count=len(component_records),
                        services_restored=True,
                    )
            finally:
                if temporary is not None:
                    self._remove_temporary(temporary)
                if services_stopped:
                    self.systemd.restore(
                        original_states,
                        activate_health_services=True,
                    )
            if result is None:
                raise _component_failure("Backup creation did not complete")
            return result

    def verify(self, backup_id: str, *, write_evidence: bool):
        from .bundle_management import BundleManager

        return BundleManager(self).verify(
            backup_id,
            write_evidence=write_evidence,
        )

    def list(self):
        from .bundle_management import BundleManager

        return BundleManager(self).list()

    def delete(self, backup_id: str):
        from .bundle_management import BundleManager

        return BundleManager(self).delete(backup_id)

    def assert_rehearsed_eligibility(self, backup_id: str):
        from .bundle_management import BundleManager

        return BundleManager(self).assert_rehearsed_eligibility(backup_id)
