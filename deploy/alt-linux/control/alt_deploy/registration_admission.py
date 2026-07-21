from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Settings
from .errors import ControlError
from .jsonio import atomic_write_json
from .locks import exclusive_lock
from .machine_lifecycle import MachineLifecycleGuard
from .registration_records import RegistrationCandidate


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RegistrationRequest:
    hostname: str
    mac: str
    machine_uuid: str
    ip: str

    @property
    def machine_key(self) -> str:
        return self.machine_uuid or self.mac.replace(":", "")


@dataclass(frozen=True)
class RegistrationDecision:
    http_status: int
    payload: dict[str, object]


class RegistrationAdmissionService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.guard = MachineLifecycleGuard(settings)

    @staticmethod
    def _identity_matches(
        candidate: RegistrationCandidate,
        request: RegistrationRequest,
    ) -> bool:
        return (
            candidate.machine_key == request.machine_key
            and candidate.machine_uuid
            == (request.machine_uuid or request.machine_key)
            and (
                not request.mac
                or not candidate.mac
                or candidate.mac == request.mac
            )
        )

    @staticmethod
    def _already_registered(
        candidate: RegistrationCandidate,
    ) -> RegistrationDecision:
        payload: dict[str, object] = {
            "status": "already_registered",
            "machine_key": candidate.machine_key,
            "registration_state": (
                candidate.registration_state
            ),
        }
        if candidate.generation.legacy:
            payload["legacy"] = True
        else:
            payload["registration_id"] = (
                candidate.generation.value
            )
        return RegistrationDecision(
            http_status=200,
            payload=payload,
        )

    def admit(
        self,
        request: RegistrationRequest,
    ) -> RegistrationDecision:
        normalized = RegistrationRequest(
            hostname=request.hostname.strip().lower(),
            mac=request.mac.strip().lower(),
            machine_uuid=(
                request.machine_uuid.strip().lower()
            ),
            ip=request.ip.strip(),
        )

        with exclusive_lock(self.settings.lock_file):
            snapshot = self.guard.snapshot_for_registration(
                machine_key=normalized.machine_key,
                machine_uuid=normalized.machine_uuid,
                mac=normalized.mac,
            )
            self.guard.assert_registration_allowed(snapshot)

            if snapshot.candidates:
                candidate = snapshot.candidates[0]
                if not self._identity_matches(
                    candidate,
                    normalized,
                ):
                    raise ControlError(
                        code="machine_identity_conflict",
                        message=(
                            "Active registration conflicts with "
                            "the request identity"
                        ),
                        exit_code=4,
                    )
                return self._already_registered(candidate)

            registration_id = (
                f"reg-{secrets.token_hex(16)}"
            )
            record = {
                "machine_key": normalized.machine_key,
                "hostname": normalized.hostname,
                "ip": normalized.ip,
                "mac": normalized.mac,
                "uuid": normalized.machine_uuid,
                "registration_id": registration_id,
                "registered_at": utc_now(),
                "status": "pending",
            }
            destination = (
                self.settings.registration_root
                / "pending"
                / f"{normalized.machine_key}.json"
            )
            try:
                atomic_write_json(destination, record)
            except (OSError, ValueError) as exc:
                raise ControlError(
                    code="registration_storage_failed",
                    message=(
                        "Registration storage operation failed"
                    ),
                    exit_code=6,
                ) from exc

            return RegistrationDecision(
                http_status=201,
                payload={
                    "status": "registered",
                    "machine_key": normalized.machine_key,
                    "registration_id": registration_id,
                    "ip": normalized.ip,
                },
            )
