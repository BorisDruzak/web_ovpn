from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from contextlib import nullcontext

from .config import Settings
from .errors import ControlError
from .install_inventory import (
    canonical_inventory_bytes,
    inventory_sha256,
    parse_inventory,
)
from .install_policy import evaluate_policy, load_profile
from .install_session_auth import (
    create_nonce_sha256,
    credential_sha256,
    generate_credential,
)
from .install_session_repository import InstallSessionRepository


_ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.100.0/23"),
)
_MAX_ACTIVE_SESSIONS = 100
_MAX_SESSIONS_PER_DMI_UUID = 5


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
        create_nonce: object,
    ) -> CreatedInstallSession:
        if not self._allowed_source(source_ip):
            raise ControlError(
                code="install_session_source_forbidden",
                message="Install session source address is forbidden",
                exit_code=4,
            )
        try:
            nonce_digest = create_nonce_sha256(create_nonce)
        except ValueError as exc:
            raise ControlError(
                code="install_session_create_nonce_invalid",
                message="Install session create nonce is invalid",
                exit_code=4,
            ) from exc
        inventory = parse_inventory(inventory_payload)
        inventory_digest = inventory_sha256(inventory)
        profile = load_profile(
            self.settings.install_profile_root,
            "standard-office",
            1,
        )
        evaluate_policy(inventory, profile)
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            existing = self.repository.find_status_by_create_nonce_sha256(
                nonce_digest
            )
            if existing is not None:
                if hmac.compare_digest(
                    str(existing.get("inventory_sha256", "")), inventory_digest
                ):
                    return CreatedInstallSession(
                        session_id=str(existing["session_id"]),
                        credential=str(create_nonce),
                        state=str(existing["state"]),
                        poll_after_seconds=3,
                    )
                raise ControlError(
                    code="install_session_create_nonce_mismatch",
                    message="Install session create nonce is bound to another inventory",
                    exit_code=4,
                )
            now = datetime.fromisoformat(self.clock()).astimezone(timezone.utc)
            active = [
                item for item in self.repository.list_statuses()
                if not self._expire_if_needed(item, now)
            ]
            if len(active) >= _MAX_ACTIVE_SESSIONS:
                raise ControlError(
                    code="install_session_quota_exceeded",
                    message="Active install session quota is exhausted",
                    exit_code=4,
                )
            if sum(
                item.get("machine_uuid") == inventory.machine.dmi_uuid
                for item in active
            ) >= _MAX_SESSIONS_PER_DMI_UUID:
                raise ControlError(
                    code="install_session_machine_quota_exceeded",
                    message="Install session machine quota is exhausted",
                    exit_code=4,
                )
            session_id = self.session_id_factory()
            credential = str(create_nonce)
            timestamp = now.isoformat()
            status = {
                "schema_version": 1,
                "session_id": session_id,
                "state": "awaiting_approval",
                "stage": "awaiting_approval",
                "stage_history": [
                    {"stage": "session_created", "entered_at": timestamp},
                    {"stage": "inventory_validated", "entered_at": timestamp},
                    {"stage": "awaiting_approval", "entered_at": timestamp},
                ],
                "inventory_sha256": inventory_digest,
                "machine_uuid": inventory.machine.dmi_uuid,
                "agent_boot_id": inventory.agent.boot_id,
                "source_ip": source_ip,
                "created_at": timestamp,
                "updated_at": timestamp,
                "last_seen_at": timestamp,
                "expires_at": (now + timedelta(minutes=30)).isoformat(),
                "expired_at": None,
                "plan_revision": None,
                "cancelled_at": None,
                "cancel_reason": None,
            }
            self.repository.create(
                session_id=session_id,
                inventory_bytes=canonical_inventory_bytes(inventory),
                credential_sha256=credential_sha256(credential),
                create_nonce_sha256=nonce_digest,
                status=status,
            )
        return CreatedInstallSession(
            session_id=session_id,
            credential=credential,
            state="awaiting_approval",
            poll_after_seconds=3,
        )

    def _expire_if_needed(
        self, status: dict[str, object], now: datetime
    ) -> bool:
        if status.get("state") in {"cancelled", "expired"}:
            return True
        value = status.get("expires_at")
        if not isinstance(value, str):
            return False
        try:
            expires_at = datetime.fromisoformat(value).astimezone(timezone.utc)
        except ValueError:
            return False
        if expires_at > now:
            return False
        updated = dict(status)
        timestamp = now.isoformat()
        updated.update({"state": "expired", "expired_at": timestamp, "updated_at": timestamp})
        self.repository.replace_status(
            str(status["session_id"]), updated, allow_lifecycle=True
        )
        return True
