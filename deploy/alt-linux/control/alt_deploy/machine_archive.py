from __future__ import annotations

import os
import pwd
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

from .config import Settings
from .errors import ControlError
from .locks import exclusive_lock
from .machine_archive_repository import (
    MachineArchiveRepository,
    utc_now,
)
from .machine_lifecycle import MachineLifecycleGuard


@dataclass(frozen=True)
class ArchivePreview:
    machine_uuid: str
    machine_key: str
    source_states: tuple[str, ...]
    record_count: int
    assignment_present: bool
    active_job: dict[str, str] | None
    action: str = "archive_registration_records"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "machine_uuid": self.machine_uuid,
            "machine_key": self.machine_key,
            "source_states": list(self.source_states),
            "record_count": self.record_count,
            "assignment_present": self.assignment_present,
            "active_job": self.active_job,
            "action": self.action,
        }


@dataclass(frozen=True)
class ArchiveResult:
    result: str
    archive_id: str
    machine_uuid: str
    machine_key: str
    source_states: tuple[str, ...]

    def to_public_dict(self) -> dict[str, object]:
        return {
            "result": self.result,
            "archive_id": self.archive_id,
            "machine_uuid": self.machine_uuid,
            "machine_key": self.machine_key,
            "source_states": list(self.source_states),
        }


def validate_archive_reason(reason: str) -> str:
    normalized = reason.strip()
    invalid = (
        not normalized
        or len(normalized) > 500
        or any(
            unicodedata.category(character).startswith("C")
            for character in normalized
        )
    )
    if invalid:
        raise ControlError(
            code="invalid_archive_reason",
            message="Archive reason is invalid",
            exit_code=4,
        )
    return normalized


def _account_name_for_uid(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def resolve_operator_identity(
    environ: Mapping[str, str],
) -> tuple[int, str]:
    sudo_uid_text = str(
        environ.get("SUDO_UID") or ""
    ).strip()
    sudo_user = str(
        environ.get("SUDO_USER") or ""
    ).strip()

    if sudo_uid_text.isdecimal() and sudo_user:
        sudo_uid = int(sudo_uid_text)
        try:
            account = pwd.getpwnam(sudo_user)
        except KeyError:
            account = None
        if account is not None and account.pw_uid == sudo_uid:
            return sudo_uid, account.pw_name

    real_uid = os.getuid()
    real_name = _account_name_for_uid(real_uid)
    if real_name is not None:
        return real_uid, real_name

    effective_uid = os.geteuid()
    effective_name = _account_name_for_uid(effective_uid)
    if effective_name is not None:
        return effective_uid, effective_name

    return effective_uid, str(effective_uid)


class MachineArchiveService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.archives = MachineArchiveRepository(settings)
        self.guard = MachineLifecycleGuard(settings)

    @staticmethod
    def _states_from_manifest(
        manifest: Mapping[str, object],
    ) -> tuple[str, ...]:
        raw_states = manifest.get("source_states")
        if not isinstance(raw_states, list) or not all(
            isinstance(state, str)
            for state in raw_states
        ):
            raise ControlError(
                code="machine_archive_invalid",
                message=(
                    "Completed archive source states are invalid"
                ),
                exit_code=4,
            )
        return tuple(raw_states)

    def preview(self, identifier: str) -> ArchivePreview:
        snapshot = self.guard.snapshot_for_removal(identifier)
        self.guard.assert_removal_allowed(snapshot)

        if snapshot.candidates:
            return ArchivePreview(
                machine_uuid=snapshot.identity.machine_uuid,
                machine_key=snapshot.identity.machine_key,
                source_states=tuple(
                    candidate.registration_state
                    for candidate in snapshot.candidates
                ),
                record_count=len(snapshot.candidates),
                assignment_present=False,
                active_job=None,
            )

        completed = self.archives.find_latest_completed(
            identifier
        )
        if completed is None:
            raise ControlError(
                code="machine_not_found",
                message=(
                    f"Machine not found: "
                    f"{identifier.strip().lower()}"
                ),
                exit_code=3,
            )
        return ArchivePreview(
            machine_uuid=str(
                completed.get("machine_uuid") or ""
            ),
            machine_key=str(
                completed.get("machine_key") or ""
            ),
            source_states=self._states_from_manifest(
                completed
            ),
            record_count=0,
            assignment_present=False,
            active_job=None,
            action="already_archived",
        )

    def _result_from_completed(
        self,
        completed: Mapping[str, object],
    ) -> ArchiveResult:
        archive_id = str(
            completed.get("archive_id") or ""
        )
        machine_uuid = str(
            completed.get("machine_uuid") or ""
        )
        machine_key = str(
            completed.get("machine_key") or ""
        )
        if not archive_id or not machine_uuid or not machine_key:
            raise ControlError(
                code="machine_archive_invalid",
                message="Completed archive identity is invalid",
                exit_code=4,
            )
        return ArchiveResult(
            result="already_archived",
            archive_id=archive_id,
            machine_uuid=machine_uuid,
            machine_key=machine_key,
            source_states=self._states_from_manifest(
                completed
            ),
        )

    @staticmethod
    def _result_from_transaction(
        transaction,
    ) -> ArchiveResult:
        return ArchiveResult(
            result="archived",
            archive_id=transaction.archive_id,
            machine_uuid=transaction.machine_uuid,
            machine_key=transaction.machine_key,
            source_states=tuple(
                plan.state
                for plan in transaction.record_plans
            ),
        )

    def apply(
        self,
        identifier: str,
        reason: str,
        *,
        operator_env: Mapping[str, str] | None = None,
    ) -> ArchiveResult:
        validated_reason = validate_archive_reason(reason)
        operator_uid, operator_username = (
            resolve_operator_identity(
                dict(operator_env or os.environ)
            )
        )
        normalized = identifier.strip().lower()

        with exclusive_lock(self.settings.lock_file):
            resumable = self.archives.find_resumable(
                normalized
            )
            if resumable is not None:
                cleaned = self.archives.cleanup_sources(
                    resumable
                )
                self.archives.finalize(cleaned)
                return self._result_from_transaction(
                    cleaned
                )

            snapshot = self.guard.snapshot_for_removal(
                normalized
            )
            if not snapshot.candidates:
                completed = self.archives.find_latest_completed(
                    normalized
                )
                if completed is None:
                    raise ControlError(
                        code="machine_not_found",
                        message=(
                            f"Machine not found: {normalized}"
                        ),
                        exit_code=3,
                    )
                return self._result_from_completed(completed)

            self.guard.assert_removal_allowed(snapshot)
            transaction = self.archives.prepare(
                snapshot.identity,
                snapshot.candidates,
                {
                    "reason": validated_reason,
                    "operator_uid": operator_uid,
                    "operator_username": operator_username,
                    "archived_at": utc_now(),
                },
            )
            copied = self.archives.copy_and_verify(
                transaction,
                snapshot.candidates,
            )
            committed = self.archives.commit(copied)
            cleaned = self.archives.cleanup_sources(
                committed
            )
            self.archives.finalize(cleaned)
            return self._result_from_transaction(cleaned)
