from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from .assignments import AssignmentRepository
from .config import Settings
from .errors import ControlError
from .jobs import JobRepository
from .jsonio import atomic_write_json
from .machine_archive_repository import MachineArchiveRepository
from .models import MachineRecord
from .registration_records import load_registration_candidate


class MachineRepository:
    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def _sort_key(
        record: MachineRecord,
    ) -> tuple[datetime, int]:
        try:
            raw_timestamp = record.registered_at.replace(
                "Z",
                "+00:00",
            )
            timestamp = datetime.fromisoformat(
                raw_timestamp
            )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(
                    tzinfo=timezone.utc
                )

            timestamp = timestamp.astimezone(
                timezone.utc
            )
        except ValueError:
            timestamp = datetime.min.replace(
                tzinfo=timezone.utc
            )

        precedence = {
            "failed": 0,
            "ready": 1,
            "pending": 2,
        }.get(record.registration_state, -1)

        return timestamp, precedence

    def list(self) -> list[MachineRecord]:
        committed_generations = MachineArchiveRepository(
            self.settings
        ).committed_generation_index()
        selected: dict[str, MachineRecord] = {}

        for state in ("pending", "ready", "failed"):
            directory = (
                self.settings.registration_root / state
            )

            if not directory.exists():
                continue

            for path in sorted(
                directory.glob("*.json")
            ):
                try:
                    candidate = load_registration_candidate(
                        path,
                        state,
                    )
                except ControlError:
                    # Preserve the existing registry behavior for malformed
                    # unrelated active records. Archive-state failures occur
                    # before this loop and remain fail-closed.
                    continue

                if (
                    candidate.generation.value
                    in committed_generations
                ):
                    continue

                try:
                    record = MachineRecord.from_mapping(
                        candidate.payload,
                        registration_state=state,
                        record_path=path,
                    )
                except ValueError:
                    continue

                current = selected.get(
                    record.machine_key
                )

                if (
                    current is None
                    or self._sort_key(record)
                    > self._sort_key(current)
                ):
                    selected[record.machine_key] = record

        assignment_repository = AssignmentRepository(
            self.settings
        )
        job_repository = JobRepository(
            self.settings
        )

        enriched: list[MachineRecord] = []

        for record in selected.values():
            assignment = assignment_repository.get(
                record.uuid
            )
            active_job = (
                job_repository.active_for_machine(
                    record.uuid
                )
            )

            enriched.append(
                replace(
                    record,
                    status=(
                        "assigned"
                        if assignment is not None
                        else record.status
                    ),
                    assignment=assignment,
                    active_job=(
                        active_job.to_public_dict()
                        if active_job is not None
                        else None
                    ),
                )
            )

        return sorted(
            enriched,
            key=lambda item: (
                item.hostname,
                item.machine_key,
            ),
        )

    def get(
        self,
        machine_uuid: str,
    ) -> MachineRecord:
        normalized = machine_uuid.strip().lower()

        for record in self.list():
            if (
                record.uuid == normalized
                or record.machine_key == normalized
            ):
                return record

        raise ControlError(
            code="machine_not_found",
            message=f"Machine not found: {normalized}",
            exit_code=3,
            details={
                "machine_uuid": normalized,
            },
        )

    def persist_preflight(
        self,
        machine: MachineRecord,
        payload: dict[str, object],
        *,
        succeeded: bool,
    ) -> MachineRecord:
        record = dict(machine.raw)

        record["preflight"] = dict(payload)
        record["preflight_checked_at"] = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )
        record["status"] = (
            "awaiting_assignment"
            if succeeded
            else "preflight_failed"
        )

        atomic_write_json(
            machine.record_path,
            record,
        )

        return MachineRecord.from_mapping(
            record,
            registration_state=(
                machine.registration_state
            ),
            record_path=machine.record_path,
        )
