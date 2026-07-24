from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .assignments import AssignmentRepository
from .config import Settings
from .errors import ControlError
from .jobs import JobRepository
from .locks import exclusive_lock
from .machine_archive import (
    resolve_operator_identity,
    validate_archive_reason,
)


@dataclass(frozen=True)
class RecoveryPreview:
    machine_uuid: str
    machine_key: str
    source_state: str
    record_sha256: str
    assignment_present: bool

    def to_public_dict(self) -> dict[str, object]:
        return {
            "machine_uuid": self.machine_uuid,
            "machine_key": self.machine_key,
            "source_state": self.source_state,
            "record_sha256": self.record_sha256,
            "assignment_present": self.assignment_present,
            "action": "recover_stale_registration",
        }


@dataclass(frozen=True)
class RecoveryResult:
    result: str
    recovery_id: str
    machine_uuid: str
    machine_key: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "result": self.result,
            "recovery_id": self.recovery_id,
            "machine_uuid": self.machine_uuid,
            "machine_key": self.machine_key,
        }


class StaleRegistrationRecoveryService:
    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def _error(code: str, message: str, *, exit_code: int = 4) -> ControlError:
        return ControlError(code=code, message=message, exit_code=exit_code)

    @staticmethod
    def _read_regular(path: Path) -> bytes:
        try:
            before = path.lstat()
        except OSError as exc:
            raise StaleRegistrationRecoveryService._error(
                "stale_registration_invalid",
                "Stale registration cannot be inspected",
            ) from exc
        if not stat.S_ISREG(before.st_mode):
            raise StaleRegistrationRecoveryService._error(
                "stale_registration_invalid",
                "Stale registration is not a regular file",
            )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise StaleRegistrationRecoveryService._error(
                "stale_registration_invalid",
                "Stale registration cannot be opened safely",
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise StaleRegistrationRecoveryService._error(
                    "stale_registration_invalid",
                    "Stale registration changed while opening",
                )
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _candidate(self, identifier: str) -> tuple[Path, dict[str, object], bytes]:
        normalized = identifier.strip().lower()
        if not normalized or "/" in normalized or "\\" in normalized:
            raise self._error("machine_not_found", "Machine not found", exit_code=3)
        paths = []
        for state in ("failed", "ready"):
            path = self.settings.registration_root / state / f"{normalized}.json"
            if os.path.lexists(path):
                paths.append(path)
        if not paths:
            raise self._error("machine_not_found", "Machine not found", exit_code=3)
        if len(paths) != 1:
            raise self._error(
                "stale_registration_not_recoverable",
                "Registration identifier exists in multiple lifecycle states",
            )
        path = paths[0]
        raw = self._read_regular(path)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._error(
                "stale_registration_invalid",
                "Stale registration JSON is invalid",
            ) from exc
        if not isinstance(payload, dict):
            raise self._error(
                "stale_registration_invalid",
                "Stale registration JSON is not an object",
            )
        machine_uuid = str(payload.get("uuid") or "").strip().lower()
        machine_key = str(payload.get("machine_key") or "").strip().lower()
        status = str(payload.get("status") or "").strip().lower()
        if (
            not machine_uuid
            or not machine_key
            or path.stem not in {machine_uuid, machine_key}
            or normalized not in {machine_uuid, machine_key}
            or status != "awaiting_assignment"
        ):
            raise self._error(
                "stale_registration_not_recoverable",
                "Registration is not the approved legacy stale-state conflict",
            )
        return path, payload, raw

    def _assert_lifecycle(self, machine_uuid: str) -> None:
        try:
            AssignmentRepository(self.settings).get(machine_uuid)
        except ControlError as exc:
            raise self._error(
                "stale_registration_not_recoverable",
                "Recovery requires an existing assignment",
            ) from exc
        if JobRepository(self.settings).active_for_machine(machine_uuid):
            raise self._error(
                "machine_busy",
                "Active provision job blocks stale registration recovery",
            )

    def _completed(self, identifier: str) -> RecoveryResult | None:
        root = self.settings.machine_archives_dir
        if not root.is_dir() or root.is_symlink():
            return None
        normalized = identifier.strip().lower()
        for directory in root.iterdir():
            manifest_path = directory / "manifest.json"
            if not directory.is_dir() or directory.is_symlink() or not manifest_path.is_file():
                continue
            try:
                manifest = json.loads(self._read_regular(manifest_path).decode("utf-8"))
            except (ControlError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(manifest, dict) or manifest.get("kind") != "stale_registration_recovery":
                continue
            if normalized not in {
                str(manifest.get("machine_uuid") or "").lower(),
                str(manifest.get("machine_key") or "").lower(),
            }:
                continue
            return RecoveryResult(
                result="already_recovered",
                recovery_id=directory.name,
                machine_uuid=str(manifest["machine_uuid"]),
                machine_key=str(manifest["machine_key"]),
            )
        return None

    @staticmethod
    def _write_new(path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def preview(self, identifier: str) -> RecoveryPreview:
        path, payload, raw = self._candidate(identifier)
        machine_uuid = str(payload["uuid"]).lower()
        self._assert_lifecycle(machine_uuid)
        return RecoveryPreview(
            machine_uuid=machine_uuid,
            machine_key=str(payload["machine_key"]).lower(),
            source_state=path.parent.name,
            record_sha256=hashlib.sha256(raw).hexdigest(),
            assignment_present=True,
        )

    def apply(
        self,
        identifier: str,
        reason: str,
        *,
        operator_env: Mapping[str, str] | None = None,
    ) -> RecoveryResult:
        validated_reason = validate_archive_reason(reason)
        with exclusive_lock(self.settings.lock_file):
            completed = self._completed(identifier)
            if completed is not None:
                return completed
            path, payload, raw = self._candidate(identifier)
            machine_uuid = str(payload["uuid"]).lower()
            machine_key = str(payload["machine_key"]).lower()
            self._assert_lifecycle(machine_uuid)
            root = self.settings.machine_archives_dir
            root.mkdir(parents=True, exist_ok=True)
            recovery_id = "recovery-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(4)
            directory = root / recovery_id
            directory.mkdir(mode=0o700)
            records = directory / "records"
            records.mkdir(mode=0o700)
            source_state = path.parent.name
            self._write_new(records / f"{source_state}.json", raw)
            operator_uid, operator_username = resolve_operator_identity(
                dict(operator_env or os.environ)
            )
            manifest = {
                "kind": "stale_registration_recovery",
                "machine_uuid": machine_uuid,
                "machine_key": machine_key,
                "source_state": source_state,
                "source_name": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "reason": validated_reason,
                "operator_uid": operator_uid,
                "operator_username": operator_username,
                "recovered_at": datetime.now(timezone.utc).isoformat(),
            }
            self._write_new(
                directory / "manifest.json",
                (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
            )
            self._fsync_directory(records)
            self._fsync_directory(directory)
            path.unlink()
            self._fsync_directory(path.parent)
            self._fsync_directory(root)
            return RecoveryResult(
                result="recovered",
                recovery_id=recovery_id,
                machine_uuid=machine_uuid,
                machine_key=machine_key,
            )
