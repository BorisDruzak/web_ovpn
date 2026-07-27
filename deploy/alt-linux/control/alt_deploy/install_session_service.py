from __future__ import annotations

import ipaddress
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Settings
from .errors import ControlError
from .install_inventory import (
    canonical_inventory_bytes,
    inventory_sha256,
    parse_inventory,
)
from .install_policy import evaluate_policy, load_profile
from .install_session_auth import credential_sha256, generate_credential
from .install_session_repository import InstallSessionRepository


_ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.100.0/23"),
)


@dataclass(frozen=True)
class CreatedInstallSession:
    session_id: str
    credential: str
    state: str
    poll_after_seconds: int


class InstallSessionService:
    def __init__(
        self,
        settings: Settings,
        *,
        repository: InstallSessionRepository | None = None,
        clock: Callable[[], str] | None = None,
        credential_factory: Callable[[], str] = generate_credential,
        session_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository or InstallSessionRepository(settings)
        self.clock = clock or (
            lambda: datetime.now(timezone.utc).isoformat()
        )
        self.credential_factory = credential_factory
        self.session_id_factory = session_id_factory or self._session_id

    @staticmethod
    def _session_id() -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"install-{timestamp}-{secrets.token_hex(4)}"

    @staticmethod
    def _allowed_source(source_ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(parsed in network for network in _ALLOWED_NETWORKS)

    def create(
        self,
        inventory_payload: object,
        *,
        source_ip: str,
    ) -> CreatedInstallSession:
        if not self._allowed_source(source_ip):
            raise ControlError(
                code="install_session_source_forbidden",
                message="Install session source address is forbidden",
                exit_code=4,
            )
        inventory = parse_inventory(inventory_payload)
        profile = load_profile(
            self.settings.install_profile_root,
            "standard-office",
            1,
        )
        evaluate_policy(inventory, profile)
        session_id = self.session_id_factory()
        credential = self.credential_factory()
        now = self.clock()
        status = {
            "schema_version": 1,
            "session_id": session_id,
            "state": "awaiting_approval",
            "stage": "awaiting_approval",
            "stage_history": [
                {"stage": "session_created", "entered_at": now},
                {"stage": "inventory_validated", "entered_at": now},
                {"stage": "awaiting_approval", "entered_at": now},
            ],
            "inventory_sha256": inventory_sha256(inventory),
            "machine_uuid": inventory.machine.dmi_uuid,
            "agent_boot_id": inventory.agent.boot_id,
            "source_ip": source_ip,
            "created_at": now,
            "updated_at": now,
            "last_seen_at": now,
            "plan_revision": None,
            "cancelled_at": None,
            "cancel_reason": None,
        }
        self.repository.create(
            session_id=session_id,
            inventory_bytes=canonical_inventory_bytes(inventory),
            credential_sha256=credential_sha256(credential),
            status=status,
        )
        return CreatedInstallSession(
            session_id=session_id,
            credential=credential,
            state="awaiting_approval",
            poll_after_seconds=3,
        )
