from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from .config import Settings
from .errors import ControlError
from .install_session_repository import InstallSessionRepository


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9._+-]{1,63}$")


class ExecutionAuthorizationService:
    """Root-only, single-use authorization for the future V2 handoff.

    This class deliberately creates no installer artifact and executes no
    command.  It records the narrow authorization prerequisite that later
    bundle publication and agent handoff consume.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        repository: InstallSessionRepository | None = None,
        clock: Callable[[], str],
        euid: Callable[[], int] = lambda: getattr(os, "geteuid", lambda: 0)(),
    ) -> None:
        self.settings = settings
        self.repository = repository or InstallSessionRepository(settings)
        self.clock = clock
        self.euid = euid

    @staticmethod
    def _error(code: str, message: str) -> ControlError:
        return ControlError(code, message, 4)

    def _now(self) -> datetime:
        try:
            value = datetime.fromisoformat(self.clock())
        except ValueError as exc:
            raise self._error("execution_clock_invalid", "Execution clock is invalid") from exc
        if value.tzinfo is None:
            raise self._error("execution_clock_invalid", "Execution clock is invalid")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _bounded_text(value: object, *, code: str, description: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 256:
            raise ExecutionAuthorizationService._error(code, description)
        return value.strip()

    def _load_bound_plan(
        self,
        session_id: str,
        *,
        plan_sha256: object,
        inventory_sha256: object,
        disk_fingerprint_value: object,
        confirm_target: object,
        now: datetime,
    ) -> tuple[dict[str, object], str]:
        if not isinstance(plan_sha256, str) or not _SHA256_RE.fullmatch(plan_sha256):
            raise self._error("execution_plan_sha256_invalid", "Execution plan SHA-256 is invalid")
        if not isinstance(inventory_sha256, str) or not _SHA256_RE.fullmatch(inventory_sha256):
            raise self._error("execution_inventory_sha256_invalid", "Execution inventory SHA-256 is invalid")
        if not isinstance(disk_fingerprint_value, str) or not disk_fingerprint_value.startswith("sha256:") or not _SHA256_RE.fullmatch(disk_fingerprint_value[7:]):
            raise self._error("execution_disk_fingerprint_invalid", "Execution disk fingerprint is invalid")
        if not isinstance(confirm_target, str) or not _DEVICE_RE.fullmatch(confirm_target):
            raise self._error("execution_target_invalid", "Execution target acknowledgement is invalid")
        try:
            raw = self.repository.read_revision_file(session_id, "plan.json")
            plan = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ControlError) as exc:
            raise self._error("execution_plan_invalid", "Published execution plan is invalid") from exc
        if not isinstance(plan, dict):
            raise self._error("execution_plan_invalid", "Published execution plan is invalid")
        if hashlib.sha256(raw).hexdigest() != plan_sha256:
            raise self._error("execution_plan_mismatch", "Execution plan digest differs")
        target = plan.get("target_disk")
        expires_at = plan.get("expires_at")
        if (
            plan.get("inventory_sha256") != inventory_sha256
            or not isinstance(target, dict)
            or target.get("fingerprint") != disk_fingerprint_value
            or target.get("path") != confirm_target
            or not isinstance(expires_at, str)
        ):
            raise self._error("execution_plan_mismatch", "Execution authorization differs from plan")
        try:
            expiry = datetime.fromisoformat(expires_at).astimezone(timezone.utc)
        except ValueError as exc:
            raise self._error("execution_plan_invalid", "Published execution plan expiry is invalid") from exc
        if expiry <= now:
            raise self._error("execution_plan_expired", "Published execution plan is expired")
        return plan, confirm_target

    def authorize(
        self,
        session_id: str,
        *,
        plan_sha256: object,
        inventory_sha256: object,
        disk_fingerprint_value: object,
        confirm_target: object,
        reason: object,
    ) -> dict[str, object]:
        if self.euid() != 0:
            raise self._error("execution_root_required", "Execution authorization requires root")
        reason_text = self._bounded_text(
            reason,
            code="execution_reason_invalid",
            description="Execution authorization reason is invalid",
        )
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            status = self.repository.load_status(session_id)
            if status.get("state") in {"cancelled", "expired"}:
                raise self._error("execution_session_terminal", "Execution session is terminal")
            if status.get("state") != "plan_published":
                raise self._error("execution_plan_unavailable", "Execution plan is not published")
            agent_status = status.get("agent_status")
            if not isinstance(agent_status, dict) or agent_status.get("reported_stage") != "preflight_ready":
                raise self._error("execution_preflight_required", "Execution requires current preflight")
            if "execution" in status:
                raise self._error("execution_already_authorized", "Execution is already authorized")
            now = self._now()
            plan, target_disk = self._load_bound_plan(
                session_id,
                plan_sha256=plan_sha256,
                inventory_sha256=inventory_sha256,
                disk_fingerprint_value=disk_fingerprint_value,
                confirm_target=confirm_target,
                now=now,
            )
            updated = deepcopy(status)
            updated["execution"] = {
                "schema_version": 1,
                "state": "authorized",
                "authorized_at": now.isoformat(),
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "plan_sha256": plan_sha256,
                "inventory_sha256": inventory_sha256,
                "disk_fingerprint": disk_fingerprint_value,
                "target_disk": target_disk,
                "reason": reason_text,
                "profile_id": plan.get("profile_id"),
                "profile_version": plan.get("profile_version"),
            }
            updated["updated_at"] = now.isoformat()
            self.repository.replace_status(session_id, updated)
            return updated
