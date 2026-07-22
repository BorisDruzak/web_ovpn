from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__
from .components import component_specs
from .errors import BackupError
from .fs import fsync_directory, read_regular_bytes
from .locks import exclusive_operation_lock
from .manifest import (
    BACKUP_ID_RE,
    SCHEMA_VERSION,
    BackupManifest,
    RehearsalEvidence,
    VerificationEvidence,
    parse_manifest,
    parse_rehearsal_evidence,
    parse_verification_evidence,
)

if TYPE_CHECKING:
    from .repository import BackupRepository


_BASE_FILES = frozenset(
    {
        "manifest.json",
        "runtime.tar.zst",
        "systemd.tar.zst",
        "ansible.tar.zst",
        "controller-state.tar.zst",
        "registration-state.tar.zst",
        "deployment-assets.tar.zst",
    }
)
_OPTIONAL_FILES = frozenset({"verification.json", "rehearsal.json"})


@dataclass(frozen=True)
class VerifyResult:
    backup_id: str
    manifest_sha256: str
    component_count: int
    evidence_written: bool


@dataclass(frozen=True)
class BackupSummary:
    backup_id: str
    created_at: str | None
    size_bytes: int
    manifest_sha256: str | None
    valid: bool
    verified: bool
    rehearsed: bool
    compatible: bool
    error_code: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "size_bytes": self.size_bytes,
            "manifest_sha256": self.manifest_sha256,
            "valid": self.valid,
            "verified": self.verified,
            "rehearsed": self.rehearsed,
            "compatible": self.compatible,
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class DeleteResult:
    backup_id: str
    deleted_bytes: int


@dataclass(frozen=True)
class EligibilityResult:
    backup_id: str
    manifest_sha256: str
    verification_sha256: str


@dataclass(frozen=True)
class _VerifiedBundle:
    path: Path
    manifest: BackupManifest
    manifest_raw: bytes
    manifest_sha256: str
    component_hashes: dict[str, str]


def _not_found() -> BackupError:
    return BackupError(
        code="backup_not_found",
        message="Backup bundle was not found",
        exit_code=3,
    )


def _integrity(message: str) -> BackupError:
    return BackupError(
        code="backup_integrity_failed",
        message=message,
        exit_code=4,
    )


def _delete_unsafe(message: str) -> BackupError:
    return BackupError(
        code="backup_delete_unsafe",
        message=message,
        exit_code=4,
    )


class BundleManager:
    def __init__(self, repository: BackupRepository) -> None:
        self.repository = repository
        self.settings = repository.settings

    def _bundle_path(self, backup_id: str) -> Path:
        if not isinstance(backup_id, str) or not BACKUP_ID_RE.fullmatch(backup_id):
            raise _not_found()
        path = self.settings.backup_root / backup_id
        if path.parent != self.settings.backup_root or path.name != backup_id:
            raise _not_found()
        return path

    def _validate_directory(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise _not_found() from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != self.settings.expected_root_uid
            or metadata.st_gid != self.settings.expected_root_gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise _integrity("Backup bundle directory metadata is unsafe")

    def _top_level(self, path: Path) -> dict[str, Path]:
        try:
            children = list(path.iterdir())
        except OSError as exc:
            raise _integrity("Backup bundle cannot be enumerated") from exc
        if len(children) != len({child.name for child in children}):
            raise _integrity("Backup bundle contains duplicate entries")
        by_name = {child.name: child for child in children}
        names = set(by_name)
        if not _BASE_FILES.issubset(names) or names - (_BASE_FILES | _OPTIONAL_FILES):
            raise _integrity("Backup bundle top-level entries are invalid")
        for child in children:
            try:
                metadata = child.lstat()
            except OSError as exc:
                raise _integrity("Backup bundle entry cannot be inspected") from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.settings.expected_root_uid
                or metadata.st_gid != self.settings.expected_root_gid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise _integrity("Backup bundle file metadata is unsafe")
        return by_name

    def _expected_member_root(self, namespace: str, absolute_path: str) -> str:
        return f"{namespace}/{absolute_path.lstrip('/')}"

    def _verify_bundle(self, backup_id: str) -> _VerifiedBundle:
        path = self._bundle_path(backup_id)
        self._validate_directory(path)
        entries = self._top_level(path)
        manifest_raw = read_regular_bytes(
            entries["manifest.json"],
            max_bytes=16 * 1024 * 1024,
        )
        manifest = parse_manifest(manifest_raw)
        if manifest.backup_id != backup_id:
            raise _integrity("Manifest backup identifier does not match")
        if (
            manifest.schema_version != SCHEMA_VERSION
            or manifest.utility_version != __version__
        ):
            raise _integrity("Backup utility or schema version is incompatible")

        self.repository.secrets.assert_matches(manifest.secret_identities)
        specs = component_specs(self.settings)
        if tuple(record.name for record in manifest.components) != tuple(
            spec.name for spec in specs
        ):
            raise _integrity("Manifest component order is invalid")

        component_hashes: dict[str, str] = {}
        for spec, record in zip(specs, manifest.components, strict=True):
            expected_paths = tuple(
                self.repository.archive_engine._logical_path(source)
                for source in spec.paths
            )
            actual_paths = tuple(item.absolute_path for item in record.paths)
            if actual_paths != expected_paths:
                raise _integrity("Manifest component paths do not match policy")

            archive_path = entries[record.filename]
            size, digest = self.repository._sha256_file(archive_path)
            if size != record.size_bytes or digest != record.sha256:
                raise _integrity("Backup component hash or size does not match")
            component_hashes[record.filename] = digest
            inspection = self.repository.archive_engine.inspect(spec, archive_path)
            names = {member.name for member in inspection.members}
            for path_record in record.paths:
                root = self._expected_member_root(
                    record.namespace,
                    path_record.absolute_path,
                )
                present_in_archive = any(
                    name == root or name.startswith(root + "/")
                    for name in names
                )
                if path_record.present != present_in_archive:
                    raise _integrity(
                        "Backup component path presence does not match manifest"
                    )

        return _VerifiedBundle(
            path=path,
            manifest=manifest,
            manifest_raw=manifest_raw,
            manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
            component_hashes=component_hashes,
        )

    def verify(
        self,
        backup_id: str,
        *,
        write_evidence: bool,
    ) -> VerifyResult:
        with exclusive_operation_lock(self.settings):
            verified = self._verify_bundle(backup_id)
            if write_evidence:
                evidence = VerificationEvidence(
                    schema_version=SCHEMA_VERSION,
                    utility_version=__version__,
                    backup_id=backup_id,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    manifest_sha256=verified.manifest_sha256,
                    component_hashes=verified.component_hashes,
                    secret_identities=verified.manifest.secret_identities,
                    passed_checks=(
                        "bundle_layout",
                        "manifest",
                        "component_hashes",
                        "archive_members",
                        "path_presence",
                        "secret_identities",
                    ),
                    status="ok",
                )
                self.repository._write_private_bytes(
                    verified.path / "verification.json",
                    evidence.to_bytes(),
                )
            return VerifyResult(
                backup_id=backup_id,
                manifest_sha256=verified.manifest_sha256,
                component_count=len(verified.manifest.components),
                evidence_written=write_evidence,
            )

    def _evidence_state(
        self,
        verified: _VerifiedBundle,
    ) -> tuple[bool, bool]:
        verification_path = verified.path / "verification.json"
        if not verification_path.is_file() or verification_path.is_symlink():
            return False, False
        try:
            verification_raw = read_regular_bytes(
                verification_path,
                max_bytes=4 * 1024 * 1024,
            )
            verification = parse_verification_evidence(verification_raw)
        except BackupError:
            return False, False
        verification_ok = (
            verification.status == "ok"
            and verification.schema_version == SCHEMA_VERSION
            and verification.utility_version == __version__
            and verification.backup_id == verified.manifest.backup_id
            and verification.manifest_sha256 == verified.manifest_sha256
            and verification.component_hashes == verified.component_hashes
            and verification.secret_identities
            == verified.manifest.secret_identities
        )
        if not verification_ok:
            return False, False

        rehearsal_path = verified.path / "rehearsal.json"
        if not rehearsal_path.is_file() or rehearsal_path.is_symlink():
            return True, False
        try:
            rehearsal = parse_rehearsal_evidence(
                read_regular_bytes(
                    rehearsal_path,
                    max_bytes=4 * 1024 * 1024,
                )
            )
        except BackupError:
            return True, False
        rehearsed = (
            rehearsal.status == "ok"
            and rehearsal.schema_version == SCHEMA_VERSION
            and rehearsal.utility_version == __version__
            and rehearsal.backup_id == verified.manifest.backup_id
            and rehearsal.manifest_sha256 == verified.manifest_sha256
            and rehearsal.verification_sha256
            == hashlib.sha256(verification_raw).hexdigest()
            and rehearsal.secret_identities
            == verified.manifest.secret_identities
        )
        return True, rehearsed

    def list(self) -> tuple[BackupSummary, ...]:
        with exclusive_operation_lock(self.settings):
            try:
                children = sorted(
                    self.settings.backup_root.iterdir(),
                    key=lambda item: item.name,
                )
            except OSError as exc:
                raise _integrity("Backup root cannot be enumerated") from exc
            summaries: list[BackupSummary] = []
            for path in children:
                if not BACKUP_ID_RE.fullmatch(path.name):
                    continue
                try:
                    verified = self._verify_bundle(path.name)
                    evidence_verified, rehearsed = self._evidence_state(verified)
                    summaries.append(
                        BackupSummary(
                            backup_id=path.name,
                            created_at=verified.manifest.created_at,
                            size_bytes=sum(
                                component.size_bytes
                                for component in verified.manifest.components
                            ),
                            manifest_sha256=verified.manifest_sha256,
                            valid=True,
                            verified=evidence_verified,
                            rehearsed=rehearsed,
                            compatible=True,
                            error_code=None,
                        )
                    )
                except BackupError as exc:
                    summaries.append(
                        BackupSummary(
                            backup_id=path.name,
                            created_at=None,
                            size_bytes=0,
                            manifest_sha256=None,
                            valid=False,
                            verified=False,
                            rehearsed=False,
                            compatible=False,
                            error_code=exc.code,
                        )
                    )
            return tuple(summaries)

    def _active_restore_reference(self, backup_id: str) -> bool:
        root = self.settings.backup_root / ".restore-transactions"
        if not root.exists() and not root.is_symlink():
            return False
        try:
            metadata = root.lstat()
        except OSError:
            return True
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return True
        try:
            journals = list(root.glob("*/journal.json"))
        except OSError:
            return True
        for journal in journals:
            try:
                raw = read_regular_bytes(journal, max_bytes=1024 * 1024)
                payload = json.loads(raw.decode("utf-8"))
            except (BackupError, UnicodeDecodeError, json.JSONDecodeError):
                return True
            if not isinstance(payload, dict):
                return True
            if payload.get("backup_id") == backup_id and payload.get("phase") not in {
                "committed",
                "rolled_back",
            }:
                return True
        return False

    def _delete_tree(self, path: Path) -> int:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise _delete_unsafe("Backup deletion target cannot be inspected") from exc
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            try:
                children = list(path.iterdir())
            except OSError as exc:
                raise _delete_unsafe("Backup deletion target cannot be enumerated") from exc
            total = sum(self._delete_tree(child) for child in children)
            try:
                path.rmdir()
            except OSError as exc:
                raise _delete_unsafe("Backup directory cannot be removed") from exc
            return total
        size = metadata.st_size
        try:
            path.unlink()
        except OSError as exc:
            raise _delete_unsafe("Backup file cannot be removed") from exc
        return size

    def delete(self, backup_id: str) -> DeleteResult:
        with exclusive_operation_lock(self.settings):
            path = self._bundle_path(backup_id)
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise _not_found() from exc
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != self.settings.expected_root_uid
                or metadata.st_gid != self.settings.expected_root_gid
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise _delete_unsafe("Backup deletion target is unsafe")
            if self._active_restore_reference(backup_id):
                raise _delete_unsafe("Backup is referenced by an active restore")
            deleted_bytes = self._delete_tree(path)
            fsync_directory(self.settings.backup_root)
            return DeleteResult(
                backup_id=backup_id,
                deleted_bytes=deleted_bytes,
            )

    def assert_rehearsed_eligibility(
        self,
        backup_id: str,
    ) -> EligibilityResult:
        with exclusive_operation_lock(self.settings):
            verified = self._verify_bundle(backup_id)
            evidence_verified, rehearsed = self._evidence_state(verified)
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
            verification_raw = read_regular_bytes(
                verified.path / "verification.json",
                max_bytes=4 * 1024 * 1024,
            )
            return EligibilityResult(
                backup_id=backup_id,
                manifest_sha256=verified.manifest_sha256,
                verification_sha256=hashlib.sha256(
                    verification_raw
                ).hexdigest(),
            )
