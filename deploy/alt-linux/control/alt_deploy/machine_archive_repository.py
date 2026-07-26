from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .errors import ControlError
from .registration_records import (
    ACTIVE_REGISTRATION_STATES,
    MachineIdentity,
    RegistrationCandidate,
    load_registration_candidate,
)

ARCHIVE_SCHEMA_VERSION = 1
ARCHIVE_ID_RE = re.compile(
    r"^archive-\d{8}T\d{6}Z-[0-9a-f]{8}$"
)
TRANSACTION_PHASES = frozenset(
    {
        "prepared",
        "copied",
        "committed",
        "cleaned",
        "aborted",
    }
)
AUDIT_KEYS = frozenset(
    {
        "reason",
        "operator_uid",
        "operator_username",
        "archived_at",
    }
)
ALLOWED_ARCHIVE_CHILDREN = frozenset(
    {
        "transaction.json",
        "manifest.json",
        "commit.json",
        "records",
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ArchiveRecordPlan:
    state: str
    source_path: Path
    archive_name: str
    generation: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ArchiveTransaction:
    archive_id: str
    directory: Path
    phase: str
    machine_key: str
    machine_uuid: str
    audit: dict[str, object]
    record_plans: tuple[ArchiveRecordPlan, ...]
    archive_context: str | None = None


class MachineArchiveRepository:
    def __init__(self, settings: Settings):
        self.settings = settings
        try:
            account = pwd.getpwnam(settings.service_user)
        except KeyError as exc:
            raise ControlError(
                code="machine_archive_failed",
                message="Archive service account does not exist",
                exit_code=6,
            ) from exc
        self.service_uid = account.pw_uid
        self.service_gid = account.pw_gid

    @staticmethod
    def _invalid(message: str) -> ControlError:
        return ControlError(
            code="machine_archive_invalid",
            message=message,
            exit_code=4,
        )

    @staticmethod
    def _failed(message: str) -> ControlError:
        return ControlError(
            code="machine_archive_failed",
            message=message,
            exit_code=6,
        )

    @staticmethod
    def _cleanup_required(archive_id: str) -> ControlError:
        return ControlError(
            code="machine_archive_cleanup_required",
            message="Machine archive cleanup is incomplete",
            exit_code=4,
            details={"archive_id": archive_id},
        )

    @staticmethod
    def _encoded_json(payload: Mapping[str, object]) -> bytes:
        return (
            json.dumps(
                dict(payload),
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")

    def _fsync_directory(self, path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise self._failed(
                "Archive directory cannot be synchronized"
            ) from exc
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise self._failed(
                "Archive directory synchronization failed"
            ) from exc
        finally:
            os.close(descriptor)

    def _validate_directory(
        self,
        path: Path,
        *,
        expected_mode: int | None = None,
    ) -> os.stat_result:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise self._invalid(
                "Archive directory cannot be inspected safely"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise self._invalid(
                "Archive state contains a non-directory object"
            )
        if expected_mode is not None:
            mode = stat.S_IMODE(metadata.st_mode)
            if mode != expected_mode:
                raise self._invalid(
                    "Archive directory permissions are invalid"
                )
        return metadata

    def _ensure_private_directory(self, path: Path) -> None:
        if path.exists() or path.is_symlink():
            metadata = self._validate_directory(path)
            try:
                os.chmod(path, 0o700, follow_symlinks=False)
                os.chown(
                    path,
                    self.service_uid,
                    self.service_gid,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise self._failed(
                    "Archive directory permissions cannot be enforced"
                ) from exc
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise self._invalid(
                    "Archive state contains an unsafe directory"
                )
            return

        parent = path.parent
        if parent != path and not parent.exists():
            self._ensure_private_directory(parent)
        elif parent != path:
            self._validate_directory(parent)

        try:
            path.mkdir(mode=0o700)
            os.chown(
                path,
                self.service_uid,
                self.service_gid,
                follow_symlinks=False,
            )
            self._fsync_directory(parent)
        except FileExistsError:
            self._validate_directory(path)
        except OSError as exc:
            raise self._failed(
                "Archive directory cannot be created"
            ) from exc

    def _ensure_roots(self) -> None:
        self._ensure_private_directory(self.settings.state_root)
        self._ensure_private_directory(
            self.settings.machine_archives_dir
        )
        self._ensure_private_directory(
            self.settings.archive_transactions_dir
        )

    def _read_regular_bytes(
        self,
        path: Path,
        *,
        invalid_code: bool = True,
    ) -> bytes:
        error_factory = self._invalid if invalid_code else self._failed
        try:
            before = path.lstat()
        except OSError as exc:
            raise error_factory(
                "Archive file cannot be inspected safely"
            ) from exc
        if not stat.S_ISREG(before.st_mode):
            raise error_factory(
                "Archive state contains a non-regular file"
            )

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise error_factory(
                "Archive file cannot be opened safely"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise error_factory(
                    "Archive file changed during safe open"
                )
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
            data = b"".join(chunks)
            if (
                after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino
                or after.st_size != opened.st_size
                or len(data) != after.st_size
            ):
                raise error_factory(
                    "Archive file changed while being read"
                )
            return data
        finally:
            os.close(descriptor)

    def _read_json(self, path: Path) -> dict[str, Any]:
        raw = self._read_regular_bytes(path)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._invalid(
                "Archive JSON is invalid"
            ) from exc
        if not isinstance(payload, dict):
            raise self._invalid(
                "Archive JSON must contain an object"
            )
        return payload

    def _durable_create(
        self,
        path: Path,
        data: bytes,
        *,
        mode: int = 0o600,
    ) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, mode)
        except OSError as exc:
            raise self._failed(
                "Archive file cannot be created safely"
            ) from exc
        try:
            os.fchmod(descriptor, mode)
            os.fchown(
                descriptor,
                self.service_uid,
                self.service_gid,
            )
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written < 1:
                    raise self._failed(
                        "Archive file write made no progress"
                    )
                offset += written
            os.fsync(descriptor)
        except OSError as exc:
            raise self._failed(
                "Archive file write failed"
            ) from exc
        finally:
            os.close(descriptor)
        self._fsync_directory(path.parent)

    def _durable_replace_json(
        self,
        path: Path,
        payload: Mapping[str, object],
    ) -> None:
        if path.exists() or path.is_symlink():
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise self._invalid(
                    "Archive journal cannot be inspected safely"
                ) from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise self._invalid(
                    "Archive journal is not a regular file"
                )

        temporary = (
            path.parent
            / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        )
        try:
            self._durable_create(
                temporary,
                self._encoded_json(payload),
            )
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        except ControlError:
            raise
        except OSError as exc:
            raise self._failed(
                "Archive journal replacement failed"
            ) from exc
        finally:
            temporary.unlink(missing_ok=True)

    def _validate_audit(
        self,
        audit: Mapping[str, object],
        *,
        invalid: bool = False,
    ) -> dict[str, object]:
        factory = self._invalid if invalid else self._failed
        if set(audit) != AUDIT_KEYS:
            raise factory("Archive audit fields are invalid")
        reason = audit.get("reason")
        operator_uid = audit.get("operator_uid")
        operator_username = audit.get("operator_username")
        archived_at = audit.get("archived_at")
        if (
            not isinstance(reason, str)
            or not reason
            or type(operator_uid) is not int
            or operator_uid < 0
            or not isinstance(operator_username, str)
            or not operator_username
            or not isinstance(archived_at, str)
            or not archived_at
        ):
            raise factory("Archive audit values are invalid")
        return {
            "reason": reason,
            "operator_uid": operator_uid,
            "operator_username": operator_username,
            "archived_at": archived_at,
        }

    def allocate_archive_id(self) -> str:
        self._ensure_roots()
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        for _ in range(20):
            archive_id = (
                f"archive-{timestamp}-{secrets.token_hex(4)}"
            )
            if not (
                self.settings.machine_archives_dir / archive_id
            ).exists() and not (
                self.settings.archive_transactions_dir / archive_id
            ).exists():
                return archive_id
        raise self._failed(
            "Unable to allocate a unique archive ID"
        )

    def _transaction_payload(
        self,
        transaction: ArchiveTransaction,
        *,
        phase: str | None = None,
    ) -> dict[str, object]:
        active_phase = phase or transaction.phase
        payload: dict[str, object] = {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "archive_id": transaction.archive_id,
            "machine_key": transaction.machine_key,
            "machine_uuid": transaction.machine_uuid,
            "phase": active_phase,
            "audit": dict(transaction.audit),
            "planned_sources": [
                {
                    "state": plan.state,
                    "source_path": str(plan.source_path),
                    "archive_name": plan.archive_name,
                    "generation": plan.generation,
                    "size": plan.size,
                    "sha256": plan.sha256,
                }
                for plan in transaction.record_plans
            ],
            "updated_at": utc_now(),
        }
        if transaction.archive_context is not None:
            payload["archive_context"] = transaction.archive_context
        return payload

    def prepare(
        self,
        identity: MachineIdentity,
        candidates: Sequence[RegistrationCandidate],
        audit: Mapping[str, object],
        *,
        archive_context: str | None = None,
    ) -> ArchiveTransaction:
        if not candidates:
            raise self._failed(
                "Archive preparation requires registration records"
            )
        validated_audit = self._validate_audit(audit)
        if (
            archive_context is not None
            and archive_context != "stale_registration_recovery"
        ):
            raise self._invalid("Archive context is invalid")
        states: set[str] = set()
        initial_plans: list[ArchiveRecordPlan] = []
        for candidate in candidates:
            if candidate.registration_state in states:
                raise ControlError(
                    code="machine_identity_conflict",
                    message=(
                        "Multiple registration records exist in one state"
                    ),
                    exit_code=4,
                )
            states.add(candidate.registration_state)
            initial_plans.append(
                ArchiveRecordPlan(
                    state=candidate.registration_state,
                    source_path=candidate.path,
                    archive_name=(
                        f"{candidate.registration_state}.json"
                    ),
                    generation=candidate.generation.value,
                    size=len(candidate.raw_bytes),
                    sha256=hashlib.sha256(
                        candidate.raw_bytes
                    ).hexdigest(),
                )
            )

        archive_id = self.allocate_archive_id()
        directory = (
            self.settings.archive_transactions_dir / archive_id
        )
        try:
            directory.mkdir(mode=0o700)
            os.chown(
                directory,
                self.service_uid,
                self.service_gid,
                follow_symlinks=False,
            )
            records = directory / "records"
            records.mkdir(mode=0o700)
            os.chown(
                records,
                self.service_uid,
                self.service_gid,
                follow_symlinks=False,
            )
            self._fsync_directory(
                self.settings.archive_transactions_dir
            )
        except OSError as exc:
            raise self._failed(
                "Archive transaction cannot be created"
            ) from exc

        transaction = ArchiveTransaction(
            archive_id=archive_id,
            directory=directory,
            phase="prepared",
            machine_key=identity.machine_key,
            machine_uuid=identity.machine_uuid,
            audit=validated_audit,
            record_plans=tuple(initial_plans),
            archive_context=archive_context,
        )
        self._durable_create(
            directory / "transaction.json",
            self._encoded_json(
                self._transaction_payload(transaction)
            ),
        )
        return transaction

    def copy_and_verify(
        self,
        transaction: ArchiveTransaction,
        candidates: Sequence[RegistrationCandidate],
    ) -> ArchiveTransaction:
        if transaction.phase != "prepared":
            raise self._invalid(
                "Archive transaction is not prepared"
            )
        candidate_by_state = {
            candidate.registration_state: candidate
            for candidate in candidates
        }
        if len(candidate_by_state) != len(candidates):
            raise ControlError(
                code="machine_identity_conflict",
                message=(
                    "Multiple registration records exist in one state"
                ),
                exit_code=4,
            )

        verified_plans: list[ArchiveRecordPlan] = []
        for planned in transaction.record_plans:
            candidate = candidate_by_state.get(planned.state)
            if candidate is None:
                raise self._invalid(
                    "Archive candidate set changed"
                )
            current = load_registration_candidate(
                planned.source_path,
                planned.state,
            )
            if (
                current.generation.value != planned.generation
                or current.raw_bytes != candidate.raw_bytes
            ):
                raise self._failed(
                    "Registration record changed before archive copy"
                )

            destination = (
                transaction.directory
                / "records"
                / planned.archive_name
            )
            self._durable_create(
                destination,
                current.raw_bytes,
            )
            copied = self._read_regular_bytes(
                destination,
                invalid_code=False,
            )
            digest = hashlib.sha256(copied).hexdigest()
            if (
                copied != current.raw_bytes
                or len(copied) != len(current.raw_bytes)
            ):
                raise self._failed(
                    "Archived record verification failed"
                )
            verified_plans.append(
                ArchiveRecordPlan(
                    state=planned.state,
                    source_path=planned.source_path,
                    archive_name=planned.archive_name,
                    generation=planned.generation,
                    size=len(copied),
                    sha256=digest,
                )
            )

        copied_transaction = replace(
            transaction,
            phase="copied",
            record_plans=tuple(verified_plans),
        )
        manifest = {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "archive_id": transaction.archive_id,
            "machine_uuid": transaction.machine_uuid,
            "machine_key": transaction.machine_key,
            "archived_at": transaction.audit["archived_at"],
            "reason": transaction.audit["reason"],
            "operator_uid": transaction.audit["operator_uid"],
            "operator_username": transaction.audit[
                "operator_username"
            ],
            "source_states": [
                plan.state for plan in verified_plans
            ],
            "registration_generations": [
                plan.generation for plan in verified_plans
            ],
            "records": [
                {
                    "state": plan.state,
                    "filename": plan.archive_name,
                    "size": plan.size,
                    "sha256": plan.sha256,
                }
                for plan in verified_plans
            ],
            "commit_phase": "committed",
        }
        if transaction.archive_context is not None:
            manifest["archive_context"] = transaction.archive_context
        self._durable_create(
            transaction.directory / "manifest.json",
            self._encoded_json(manifest),
        )
        self._durable_replace_json(
            transaction.directory / "transaction.json",
            self._transaction_payload(
                copied_transaction,
                phase="copied",
            ),
        )
        return copied_transaction

    def commit(
        self,
        transaction: ArchiveTransaction,
    ) -> ArchiveTransaction:
        if transaction.phase != "copied":
            raise self._invalid(
                "Archive transaction is not copied"
            )
        manifest_path = transaction.directory / "manifest.json"
        manifest_bytes = self._read_regular_bytes(manifest_path)
        manifest = self._read_json(manifest_path)
        if (
            manifest.get("archive_id") != transaction.archive_id
            or manifest.get("machine_key")
            != transaction.machine_key
            or manifest.get("machine_uuid")
            != transaction.machine_uuid
        ):
            raise self._invalid(
                "Archive manifest identity is invalid"
            )
        commit_payload = {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "archive_id": transaction.archive_id,
            "machine_uuid": transaction.machine_uuid,
            "machine_key": transaction.machine_key,
            "registration_generations": [
                plan.generation
                for plan in transaction.record_plans
            ],
            "committed_at": utc_now(),
            "manifest_sha256": hashlib.sha256(
                manifest_bytes
            ).hexdigest(),
        }
        self._durable_create(
            transaction.directory / "commit.json",
            self._encoded_json(commit_payload),
        )
        committed = replace(
            transaction,
            phase="committed",
        )
        self._durable_replace_json(
            transaction.directory / "transaction.json",
            self._transaction_payload(
                committed,
                phase="committed",
            ),
        )
        return committed

    def cleanup_sources(
        self,
        transaction: ArchiveTransaction,
    ) -> ArchiveTransaction:
        if transaction.phase not in {
            "committed",
            "cleaned",
        }:
            raise self._invalid(
                "Archive transaction is not committed"
            )
        if transaction.phase == "cleaned":
            return transaction

        for plan in transaction.record_plans:
            source = plan.source_path
            if not source.exists() and not source.is_symlink():
                continue
            try:
                current = load_registration_candidate(
                    source,
                    plan.state,
                )
            except ControlError as exc:
                raise self._cleanup_required(
                    transaction.archive_id
                ) from exc
            digest = hashlib.sha256(
                current.raw_bytes
            ).hexdigest()
            if (
                current.generation.value != plan.generation
                or len(current.raw_bytes) != plan.size
                or digest != plan.sha256
            ):
                raise self._cleanup_required(
                    transaction.archive_id
                )
            try:
                source.unlink()
                self._fsync_directory(source.parent)
            except OSError as exc:
                raise self._cleanup_required(
                    transaction.archive_id
                ) from exc

        cleaned = replace(
            transaction,
            phase="cleaned",
        )
        self._durable_replace_json(
            transaction.directory / "transaction.json",
            self._transaction_payload(
                cleaned,
                phase="cleaned",
            ),
        )
        return cleaned

    def finalize(
        self,
        transaction: ArchiveTransaction,
    ) -> Path:
        if transaction.phase != "cleaned":
            raise self._invalid(
                "Archive transaction is not cleaned"
            )
        destination = (
            self.settings.machine_archives_dir
            / transaction.archive_id
        )
        if destination.exists() or destination.is_symlink():
            raise self._invalid(
                "Completed archive destination already exists"
            )
        try:
            os.replace(transaction.directory, destination)
            self._fsync_directory(
                self.settings.machine_archives_dir
            )
        except OSError as exc:
            raise self._failed(
                "Archive transaction cannot be finalized"
            ) from exc
        return destination

    def _validate_directory_children(
        self,
        directory: Path,
    ) -> None:
        self._validate_directory(directory)
        try:
            children = list(directory.iterdir())
        except OSError as exc:
            raise self._invalid(
                "Archive directory cannot be enumerated"
            ) from exc
        for child in children:
            if child.name not in ALLOWED_ARCHIVE_CHILDREN:
                raise self._invalid(
                    "Archive directory contains an unexpected object"
                )
            if child.name == "records":
                self._validate_directory(child)
                for record in child.iterdir():
                    if record.name not in {
                        f"{state}.json"
                        for state in ACTIVE_REGISTRATION_STATES
                    }:
                        raise self._invalid(
                            "Archive records contain an unexpected object"
                        )
                    metadata = record.lstat()
                    if not stat.S_ISREG(metadata.st_mode):
                        raise self._invalid(
                            "Archive record is not a regular file"
                        )
            else:
                metadata = child.lstat()
                if not stat.S_ISREG(metadata.st_mode):
                    raise self._invalid(
                        "Archive state file is not regular"
                    )

    def _parse_record_plans(
        self,
        payload: Mapping[str, object],
    ) -> tuple[ArchiveRecordPlan, ...]:
        raw_plans = payload.get("planned_sources")
        if not isinstance(raw_plans, list):
            raise self._invalid(
                "Archive transaction source plan is invalid"
            )
        plans: list[ArchiveRecordPlan] = []
        states: set[str] = set()
        for raw in raw_plans:
            if not isinstance(raw, dict):
                raise self._invalid(
                    "Archive transaction source entry is invalid"
                )
            state_value = raw.get("state")
            source_value = raw.get("source_path")
            archive_name = raw.get("archive_name")
            generation = raw.get("generation")
            size = raw.get("size")
            sha256 = raw.get("sha256")
            if (
                not isinstance(state_value, str)
                or state_value not in ACTIVE_REGISTRATION_STATES
                or state_value in states
                or not isinstance(source_value, str)
                or not source_value
                or archive_name != f"{state_value}.json"
                or not isinstance(generation, str)
                or not generation
                or type(size) is not int
                or size < 0
                or not isinstance(sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
            ):
                raise self._invalid(
                    "Archive transaction source values are invalid"
                )
            states.add(state_value)
            plans.append(
                ArchiveRecordPlan(
                    state=state_value,
                    source_path=Path(source_value),
                    archive_name=archive_name,
                    generation=generation,
                    size=size,
                    sha256=sha256,
                )
            )
        if not plans:
            raise self._invalid(
                "Archive transaction has no record plan"
            )
        return tuple(plans)

    def _load_transaction(
        self,
        directory: Path,
    ) -> ArchiveTransaction:
        self._validate_directory_children(directory)
        payload = self._read_json(
            directory / "transaction.json"
        )
        archive_id = payload.get("archive_id")
        machine_key = payload.get("machine_key")
        machine_uuid = payload.get("machine_uuid")
        phase = payload.get("phase")
        schema_version = payload.get("schema_version")
        audit = payload.get("audit")
        archive_context = payload.get("archive_context")
        if (
            schema_version != ARCHIVE_SCHEMA_VERSION
            or not isinstance(archive_id, str)
            or not ARCHIVE_ID_RE.fullmatch(archive_id)
            or archive_id != directory.name
            or not isinstance(machine_key, str)
            or not machine_key
            or not isinstance(machine_uuid, str)
            or not machine_uuid
            or not isinstance(phase, str)
            or phase not in TRANSACTION_PHASES
            or not isinstance(audit, dict)
            or (
                archive_context is not None
                and (
                    not isinstance(archive_context, str)
                    or archive_context
                    != "stale_registration_recovery"
                )
            )
        ):
            raise self._invalid(
                "Archive transaction identity is invalid"
            )
        validated_audit = self._validate_audit(
            audit,
            invalid=True,
        )
        plans = self._parse_record_plans(payload)
        transaction = ArchiveTransaction(
            archive_id=archive_id,
            directory=directory,
            phase=phase,
            machine_key=machine_key,
            machine_uuid=machine_uuid,
            audit=validated_audit,
            record_plans=plans,
            archive_context=archive_context,
        )

        commit_path = directory / "commit.json"
        commit_exists = commit_path.exists() or commit_path.is_symlink()
        manifest_path = directory / "manifest.json"
        manifest_exists = (
            manifest_path.exists() or manifest_path.is_symlink()
        )

        if phase in {"copied", "committed", "cleaned"} and not manifest_exists:
            raise self._invalid(
                "Archive manifest is missing"
            )
        if phase in {"committed", "cleaned"} and not commit_exists:
            raise self._invalid(
                "Archive commit marker is missing"
            )
        if commit_exists:
            self._validate_commit(transaction)
            if phase == "copied":
                transaction = replace(
                    transaction,
                    phase="committed",
                )
        return transaction

    def _validate_commit(
        self,
        transaction: ArchiveTransaction,
    ) -> None:
        manifest_path = transaction.directory / "manifest.json"
        manifest_bytes = self._read_regular_bytes(manifest_path)
        manifest = self._read_json(manifest_path)
        commit = self._read_json(
            transaction.directory / "commit.json"
        )
        expected_generations = [
            plan.generation
            for plan in transaction.record_plans
        ]
        if (
            manifest.get("schema_version")
            != ARCHIVE_SCHEMA_VERSION
            or manifest.get("archive_id")
            != transaction.archive_id
            or manifest.get("machine_key")
            != transaction.machine_key
            or manifest.get("machine_uuid")
            != transaction.machine_uuid
            or manifest.get("registration_generations")
            != expected_generations
            or commit.get("schema_version")
            != ARCHIVE_SCHEMA_VERSION
            or commit.get("archive_id")
            != transaction.archive_id
            or commit.get("machine_key")
            != transaction.machine_key
            or commit.get("machine_uuid")
            != transaction.machine_uuid
            or commit.get("registration_generations")
            != expected_generations
            or commit.get("manifest_sha256")
            != hashlib.sha256(manifest_bytes).hexdigest()
        ):
            raise self._invalid(
                "Archive commit evidence is invalid"
            )

    def _transaction_directories(self) -> list[Path]:
        root = self.settings.archive_transactions_dir
        if not root.exists() and not root.is_symlink():
            return []
        self._validate_directory(root)
        result: list[Path] = []
        for path in sorted(root.iterdir()):
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise self._invalid(
                    "Archive transaction root contains an unsafe object"
                )
            result.append(path)
        return result

    def _completed_directories(self) -> list[Path]:
        root = self.settings.machine_archives_dir
        if not root.exists() and not root.is_symlink():
            return []
        self._validate_directory(root)
        result: list[Path] = []
        for path in sorted(root.iterdir()):
            if path.name == ".transactions":
                self._validate_directory(path)
                continue
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise self._invalid(
                    "Archive root contains an unsafe object"
                )
            result.append(path)
        return result

    def committed_generation_index(self) -> dict[str, str]:
        index: dict[str, str] = {}
        directories = (
            self._completed_directories()
            + self._transaction_directories()
        )
        for directory in directories:
            transaction = self._load_transaction(directory)
            commit_path = directory / "commit.json"
            if not (commit_path.exists() or commit_path.is_symlink()):
                continue
            for plan in transaction.record_plans:
                existing = index.get(plan.generation)
                if (
                    existing is not None
                    and existing != transaction.archive_id
                ):
                    raise self._invalid(
                        "A registration generation has conflicting archives"
                    )
                index[plan.generation] = transaction.archive_id
        return index

    def find_resumable(
        self,
        identifier: str,
    ) -> ArchiveTransaction | None:
        normalized = identifier.strip().lower()
        matches: list[ArchiveTransaction] = []
        for directory in self._transaction_directories():
            transaction = self._load_transaction(directory)
            commit_path = directory / "commit.json"
            if not (commit_path.exists() or commit_path.is_symlink()):
                continue
            if transaction.phase == "cleaned":
                continue
            if normalized in {
                transaction.machine_key.lower(),
                transaction.machine_uuid.lower(),
            }:
                matches.append(transaction)
        if len(matches) > 1:
            raise self._invalid(
                "Multiple resumable archives match one machine"
            )
        return matches[0] if matches else None

    def find_latest_completed(
        self,
        identifier: str,
    ) -> dict[str, Any] | None:
        normalized = identifier.strip().lower()
        matches: list[dict[str, Any]] = []
        for directory in self._completed_directories():
            transaction = self._load_transaction(directory)
            if transaction.phase != "cleaned":
                raise self._invalid(
                    "Completed archive is not cleaned"
                )
            if normalized not in {
                transaction.machine_key.lower(),
                transaction.machine_uuid.lower(),
            }:
                continue
            manifest = self._read_json(
                directory / "manifest.json"
            )
            matches.append(manifest)
        if not matches:
            return None
        return max(
            matches,
            key=lambda payload: (
                str(payload.get("archived_at") or ""),
                str(payload.get("archive_id") or ""),
            ),
        )
