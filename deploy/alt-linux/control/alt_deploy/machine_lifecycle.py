from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path

from .assignments import AssignmentRepository
from .config import Settings
from .errors import ControlError
from .jobs import JobRecord, JobRepository
from .machine_archive_repository import (
    ArchiveTransaction,
    MachineArchiveRepository,
)
from .registration_records import (
    ACTIVE_REGISTRATION_STATES,
    MachineIdentity,
    RegistrationCandidate,
    load_registration_candidate,
)

STATE_ORDER = {
    state: index
    for index, state in enumerate(ACTIVE_REGISTRATION_STATES)
}


@dataclass(frozen=True)
class MachineLifecycleSnapshot:
    identity: MachineIdentity
    candidates: tuple[RegistrationCandidate, ...]
    assignment: dict[str, object] | None
    active_job: JobRecord | None
    completed_archive_id: str | None
    cleanup_archive_id: str | None


@dataclass(frozen=True)
class RegistrationLifecycleSnapshot:
    identity: MachineIdentity
    candidates: tuple[RegistrationCandidate, ...]
    assignment: dict[str, object] | None
    active_job: JobRecord | None
    cleanup_archive_id: str | None


class MachineLifecycleGuard:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.assignments = AssignmentRepository(settings)
        self.jobs = JobRepository(settings)
        self.archives = MachineArchiveRepository(settings)

    @staticmethod
    def _normalize_identifier(identifier: str) -> str:
        normalized = identifier.strip().lower()
        if not normalized:
            raise ControlError(
                code="machine_not_found",
                message="Machine not found",
                exit_code=3,
            )
        return normalized

    @staticmethod
    def _identity_from_candidate(
        candidate: RegistrationCandidate,
    ) -> MachineIdentity:
        return MachineIdentity(
            machine_key=candidate.machine_key,
            machine_uuid=candidate.machine_uuid,
            mac=candidate.mac,
        )

    @staticmethod
    def _candidate_matches_identifier(
        candidate: RegistrationCandidate,
        identifier: str,
    ) -> bool:
        return identifier in {
            candidate.machine_key,
            candidate.machine_uuid,
        }

    def _load_exact_candidates(
        self,
        identifier: str,
    ) -> dict[Path, RegistrationCandidate]:
        result: dict[Path, RegistrationCandidate] = {}
        for state in ACTIVE_REGISTRATION_STATES:
            path = (
                self.settings.registration_root
                / state
                / f"{identifier}.json"
            )
            if not path.exists() and not path.is_symlink():
                continue
            candidate = load_registration_candidate(path, state)
            if not self._candidate_matches_identifier(
                candidate,
                identifier,
            ):
                raise ControlError(
                    code="machine_identity_conflict",
                    message=(
                        "Registration filename conflicts with "
                        "record identity"
                    ),
                    exit_code=4,
                )
            result[path] = candidate
        return result

    def _scan_valid_candidates(
        self,
        exact: dict[Path, RegistrationCandidate],
    ) -> tuple[RegistrationCandidate, ...]:
        loaded = dict(exact)
        for state in ACTIVE_REGISTRATION_STATES:
            directory = self.settings.registration_root / state
            if not directory.exists():
                continue
            try:
                directory_metadata = directory.lstat()
            except OSError:
                continue
            if not stat.S_ISDIR(directory_metadata.st_mode):
                continue
            for path in sorted(directory.glob("*.json")):
                if path in loaded:
                    continue
                try:
                    metadata = path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                try:
                    loaded[path] = load_registration_candidate(
                        path,
                        state,
                    )
                except ControlError:
                    # A malformed non-exact record cannot be attributed
                    # safely to the selected machine.
                    continue
        return tuple(loaded.values())

    @staticmethod
    def _validate_identity_set(
        candidates: tuple[RegistrationCandidate, ...],
        identity: MachineIdentity,
    ) -> tuple[RegistrationCandidate, ...]:
        states: set[str] = set()
        generations: set[str] = set()
        for candidate in candidates:
            if (
                candidate.machine_key != identity.machine_key
                or candidate.machine_uuid != identity.machine_uuid
                or (
                    identity.mac
                    and candidate.mac
                    and candidate.mac != identity.mac
                )
                or candidate.registration_state in states
                or candidate.generation.value in generations
            ):
                raise ControlError(
                    code="machine_identity_conflict",
                    message=(
                        "Registration records have conflicting identity"
                    ),
                    exit_code=4,
                )
            states.add(candidate.registration_state)
            generations.add(candidate.generation.value)
        return tuple(
            sorted(
                candidates,
                key=lambda item: STATE_ORDER[
                    item.registration_state
                ],
            )
        )

    def discover(
        self,
        identifier: str,
    ) -> tuple[RegistrationCandidate, ...]:
        normalized = self._normalize_identifier(identifier)
        exact = self._load_exact_candidates(normalized)
        loaded = self._scan_valid_candidates(exact)
        initial = tuple(
            candidate
            for candidate in loaded
            if self._candidate_matches_identifier(
                candidate,
                normalized,
            )
        )
        if not initial:
            return ()

        identity = self._identity_from_candidate(initial[0])
        related = tuple(
            candidate
            for candidate in loaded
            if (
                candidate.machine_uuid == identity.machine_uuid
                or candidate.machine_key == identity.machine_key
            )
        )
        return self._validate_identity_set(
            related,
            identity,
        )

    def _find_resumable(
        self,
        *identifiers: str,
    ) -> ArchiveTransaction | None:
        matches: dict[str, ArchiveTransaction] = {}
        for identifier in identifiers:
            normalized = identifier.strip().lower()
            if not normalized:
                continue
            transaction = self.archives.find_resumable(
                normalized
            )
            if transaction is not None:
                matches[transaction.archive_id] = transaction
        if len(matches) > 1:
            raise ControlError(
                code="machine_archive_invalid",
                message=(
                    "Multiple archive cleanup transactions match "
                    "one machine"
                ),
                exit_code=4,
            )
        return next(iter(matches.values()), None)

    def _find_completed(
        self,
        *identifiers: str,
    ) -> dict[str, object] | None:
        matches: dict[str, dict[str, object]] = {}
        for identifier in identifiers:
            normalized = identifier.strip().lower()
            if not normalized:
                continue
            completed = self.archives.find_latest_completed(
                normalized
            )
            if completed is not None:
                archive_id = str(
                    completed.get("archive_id") or ""
                )
                if not archive_id:
                    raise ControlError(
                        code="machine_archive_invalid",
                        message=(
                            "Completed archive has no identifier"
                        ),
                        exit_code=4,
                    )
                matches[archive_id] = completed
        if len(matches) > 1:
            identities = {
                (
                    str(value.get("machine_key") or ""),
                    str(value.get("machine_uuid") or ""),
                )
                for value in matches.values()
            }
            if len(identities) > 1:
                raise ControlError(
                    code="machine_archive_invalid",
                    message=(
                        "Conflicting completed archives match one machine"
                    ),
                    exit_code=4,
                )
        if not matches:
            return None
        return max(
            matches.values(),
            key=lambda value: (
                str(value.get("archived_at") or ""),
                str(value.get("archive_id") or ""),
            ),
        )

    @staticmethod
    def _identity_from_archive(
        payload: dict[str, object],
    ) -> MachineIdentity:
        machine_key = str(
            payload.get("machine_key") or ""
        ).strip().lower()
        machine_uuid = str(
            payload.get("machine_uuid") or machine_key
        ).strip().lower()
        if not machine_key or not machine_uuid:
            raise ControlError(
                code="machine_archive_invalid",
                message="Archive machine identity is invalid",
                exit_code=4,
            )
        return MachineIdentity(
            machine_key=machine_key,
            machine_uuid=machine_uuid,
            mac="",
        )

    def snapshot_for_removal(
        self,
        identifier: str,
    ) -> MachineLifecycleSnapshot:
        normalized = self._normalize_identifier(identifier)
        candidates = self.discover(normalized)
        resumable = self._find_resumable(normalized)
        completed = self._find_completed(normalized)

        if candidates:
            identity = self._identity_from_candidate(
                candidates[0]
            )
        elif resumable is not None:
            identity = MachineIdentity(
                machine_key=resumable.machine_key,
                machine_uuid=resumable.machine_uuid,
                mac="",
            )
        elif completed is not None:
            identity = self._identity_from_archive(completed)
        else:
            raise ControlError(
                code="machine_not_found",
                message=f"Machine not found: {normalized}",
                exit_code=3,
                details={"machine_uuid": normalized},
            )

        assignment = self.assignments.get(
            identity.machine_uuid
        )
        active_job = self.jobs.active_for_machine(
            identity.machine_uuid
        )

        return MachineLifecycleSnapshot(
            identity=identity,
            candidates=candidates,
            assignment=assignment,
            active_job=active_job,
            completed_archive_id=(
                str(completed.get("archive_id"))
                if completed is not None
                else None
            ),
            cleanup_archive_id=(
                resumable.archive_id
                if resumable is not None
                else None
            ),
        )

    def assert_removal_allowed(
        self,
        snapshot: MachineLifecycleSnapshot,
    ) -> None:
        if snapshot.assignment is not None:
            raise ControlError(
                code="machine_assigned",
                message="Machine has an active assignment",
                exit_code=4,
                details={
                    "machine_uuid": (
                        snapshot.identity.machine_uuid
                    )
                },
            )
        if snapshot.active_job is not None:
            raise ControlError(
                code="machine_busy",
                message="Machine has an active provision job",
                exit_code=4,
                details={
                    "job_id": snapshot.active_job.job_id,
                    "state": snapshot.active_job.state,
                    "stage": snapshot.active_job.stage,
                },
            )
        if snapshot.cleanup_archive_id is not None:
            raise ControlError(
                code="machine_archive_cleanup_required",
                message=(
                    "Machine archive cleanup is incomplete"
                ),
                exit_code=4,
                details={
                    "archive_id": snapshot.cleanup_archive_id
                },
            )

    def snapshot_for_registration(
        self,
        *,
        machine_key: str,
        machine_uuid: str,
        mac: str,
    ) -> RegistrationLifecycleSnapshot:
        normalized_key = machine_key.strip().lower()
        normalized_uuid = (
            machine_uuid.strip().lower() or normalized_key
        )
        normalized_mac = mac.strip().lower()
        candidates = self.discover(normalized_uuid)
        if not candidates and normalized_key != normalized_uuid:
            candidates = self.discover(normalized_key)

        if candidates:
            identity = self._identity_from_candidate(
                candidates[0]
            )
            for candidate in candidates:
                if (
                    candidate.machine_uuid != normalized_uuid
                    or candidate.machine_key != normalized_key
                    or (
                        normalized_mac
                        and candidate.mac
                        and candidate.mac != normalized_mac
                    )
                ):
                    raise ControlError(
                        code="machine_identity_conflict",
                        message=(
                            "Active registration conflicts with "
                            "the request identity"
                        ),
                        exit_code=4,
                    )
        else:
            identity = MachineIdentity(
                machine_key=normalized_key,
                machine_uuid=normalized_uuid,
                mac=normalized_mac,
            )

        resumable = self._find_resumable(
            normalized_uuid,
            normalized_key,
        )
        return RegistrationLifecycleSnapshot(
            identity=identity,
            candidates=candidates,
            assignment=self.assignments.get(
                identity.machine_uuid
            ),
            active_job=self.jobs.active_for_machine(
                identity.machine_uuid
            ),
            cleanup_archive_id=(
                resumable.archive_id
                if resumable is not None
                else None
            ),
        )

    def assert_registration_allowed(
        self,
        snapshot: RegistrationLifecycleSnapshot,
    ) -> None:
        if snapshot.assignment is not None:
            raise ControlError(
                code="machine_assigned",
                message="Machine has an active assignment",
                exit_code=4,
                details={
                    "machine_uuid": (
                        snapshot.identity.machine_uuid
                    )
                },
            )
        if snapshot.active_job is not None:
            raise ControlError(
                code="machine_busy",
                message="Machine has an active provision job",
                exit_code=4,
                details={
                    "job_id": snapshot.active_job.job_id,
                    "state": snapshot.active_job.state,
                    "stage": snapshot.active_job.stage,
                },
            )
        if snapshot.cleanup_archive_id is not None:
            raise ControlError(
                code="machine_archive_cleanup_required",
                message=(
                    "Machine archive cleanup is incomplete"
                ),
                exit_code=4,
                details={
                    "archive_id": snapshot.cleanup_archive_id
                },
            )

    def generation_is_committed(
        self,
        generation: str,
    ) -> bool:
        return generation in (
            self.archives.committed_generation_index()
        )

    def generation_is_active(
        self,
        path: Path,
        registration_state: str,
        generation: str,
    ) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        try:
            candidate = load_registration_candidate(
                path,
                registration_state,
            )
        except ControlError:
            return False
        if candidate.generation.value != generation:
            return False
        return not self.generation_is_committed(generation)
