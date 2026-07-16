from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MachineRecord:
    machine_key: str
    uuid: str
    hostname: str
    ip: str
    mac: str
    registered_at: str
    registration_state: str
    status: str
    record_path: Path
    raw: dict[str, Any]
    assignment: dict[str, Any] | None = None
    active_job: dict[str, Any] | None = None

    @classmethod
    def from_mapping(
        cls,
        payload: dict[str, Any],
        *,
        registration_state: str,
        record_path: Path,
    ) -> "MachineRecord":
        machine_key = str(
            payload.get("machine_key") or ""
        ).strip().lower()

        machine_uuid = str(
            payload.get("uuid") or machine_key
        ).strip().lower()

        if not machine_key or not machine_uuid:
            raise ValueError(
                f"Machine identity missing in {record_path}"
            )

        return cls(
            machine_key=machine_key,
            uuid=machine_uuid,
            hostname=str(payload.get("hostname") or ""),
            ip=str(payload.get("ip") or ""),
            mac=str(payload.get("mac") or "").lower(),
            registered_at=str(
                payload.get("registered_at") or ""
            ),
            registration_state=registration_state,
            status=str(
                payload.get("status")
                or registration_state
            ),
            record_path=record_path,
            raw=dict(payload),
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "machine_key": self.machine_key,
            "uuid": self.uuid,
            "hostname": self.hostname,
            "ip": self.ip,
            "mac": self.mac,
            "registered_at": self.registered_at,
            "registration_state": self.registration_state,
            "status": self.status,
            "preflight": self.raw.get("preflight"),
            "assignment": self.assignment,
            "active_job": self.active_job,
        }


@dataclass(frozen=True)
class JobRecord:
    job_id: str
    machine_uuid: str
    state: str
    stage: str
    created_at: str
    updated_at: str
    job_dir: Path
    request: dict[str, Any]
    status: dict[str, Any]

    def to_public_dict(self) -> dict[str, Any]:
        payload = dict(self.status)

        payload["job_id"] = self.job_id
        payload["machine_uuid"] = self.machine_uuid
        payload["state"] = self.state
        payload["stage"] = self.stage
        payload["created_at"] = self.created_at
        payload["updated_at"] = self.updated_at

        return payload
