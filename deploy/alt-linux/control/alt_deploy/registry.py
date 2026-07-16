from __future__ import annotations

from datetime import datetime, timezone

from .config import Settings
from .errors import ControlError
from .jsonio import read_json
from .models import MachineRecord


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

            timestamp = timestamp.astimezone(timezone.utc)
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
                    record = MachineRecord.from_mapping(
                        read_json(path),
                        registration_state=state,
                        record_path=path,
                    )
                except (OSError, ValueError):
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

        return sorted(
            selected.values(),
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
