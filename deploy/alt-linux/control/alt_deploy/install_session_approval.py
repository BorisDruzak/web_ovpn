from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Callable
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from .config import Settings
from .errors import ControlError
from .install_fingerprint import disk_fingerprint
from .install_inventory import inventory_sha256 as calculate_inventory_sha256, parse_inventory
from .install_plan import (
    OperatorSelection,
    PlanRequest,
    build_install_plan,
    canonical_plan_bytes,
    plan_sha256,
)
from .install_policy import evaluate_policy, load_profile
from .install_session_repository import InstallSessionRepository
from .install_session_signing import (
    load_private_signer,
    public_key_metadata,
    sign_plan_bytes,
)


def _current_euid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1


def _with_install_session_lock(method: Callable[..., dict[str, object]]) -> Callable[..., dict[str, object]]:
    def wrapped(self: "InstallSessionApprovalService", *args: object, **kwargs: object) -> dict[str, object]:
        lock = nullcontext() if os.name == "nt" else __import__(
            "alt_deploy.locks", fromlist=["exclusive_lock"]
        ).exclusive_lock(self.settings.install_sessions_lock)
        with lock:
            return method(self, *args, **kwargs)
    return wrapped


class InstallSessionApprovalService:
    def __init__(
        self,
        settings: Settings,
        *,
        repository: InstallSessionRepository | None = None,
        clock: Callable[[], str],
        euid: Callable[[], int] = _current_euid,
    ) -> None:
        self.settings = settings
        self.repository = repository or InstallSessionRepository(settings)
        self.clock = clock
        self.euid = euid

    @_with_install_session_lock
    def approve(
        self,
        session_id: str,
        *,
        inventory_sha256: object,
        disk_fingerprint_value: object,
        reason: object,
    ) -> dict[str, object]:
        if self.euid() != 0:
            raise ControlError("install_session_root_required", "Install approval requires root", 4)
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 256:
            raise ControlError("install_session_reason_invalid", "Install approval reason is invalid", 4)
        status = self.repository.load_status(session_id)
        if status.get("state") == "plan_published":
            approval = self.repository.load_approval(session_id)
            if (
                approval.get("inventory_sha256") == inventory_sha256
                and approval.get("disk_fingerprint") == disk_fingerprint_value
                and approval.get("reason") == reason.strip()
            ):
                return status
            raise ControlError("install_session_approval_conflict", "Install session is already approved", 4)
        if status.get("state") != "awaiting_approval":
            raise ControlError("install_session_approval_conflict", "Install session is not awaiting approval", 4)
        try:
            inventory = parse_inventory(json.loads(self.repository.load_inventory_bytes(session_id)))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ControlError("install_session_inventory_invalid", "Install session inventory is invalid", 4) from exc
        if inventory_sha256 != status.get("inventory_sha256") or inventory_sha256 != calculate_inventory_sha256(inventory):
            raise ControlError("install_session_inventory_mismatch", "Install approval inventory hash does not match", 4)
        profile = load_profile(self.settings.install_profile_root, "standard-office", 1)
        evaluation = evaluate_policy(inventory, profile)
        actual_fingerprint = disk_fingerprint(evaluation.eligible_disk)
        if disk_fingerprint_value != actual_fingerprint:
            raise ControlError("install_session_disk_mismatch", "Install approval disk fingerprint does not match", 4)
        approved_at = datetime.fromisoformat(self.clock()).astimezone(timezone.utc)
        expires_at = approved_at + timedelta(minutes=30)
        plan = build_install_plan(
            inventory, profile, evaluation,
            OperatorSelection(evaluation.eligible_disk.path, actual_fingerprint, evaluation.route_interface.name, evaluation.route_interface.mac),
            PlanRequest(session_id, 1, f"alt-install-{session_id[-12:].lower()}", approved_at.isoformat(), expires_at.isoformat()),
        )
        plan_bytes = canonical_plan_bytes(plan)
        signer = load_private_signer(self.settings.install_signing_private_key)
        metadata = public_key_metadata(signer.public_key())
        signature = sign_plan_bytes(signer, plan_bytes)
        signature_document = {
            "schema_version": 1, "algorithm": "ed25519", "key_id": metadata["key_id"],
            "signed_file": "plan.json", "plan_sha256": plan_sha256(plan),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "created_at": approved_at.isoformat(),
        }
        self.repository.publish_revision(session_id, plan_bytes=plan_bytes, plan_sha256=plan_sha256(plan), signature=signature_document)
        self.repository.write_approval(session_id, {
            "schema_version": 1, "session_id": session_id, "revision": 1,
            "operator_uid": self.euid(), "operator_name": "root",
            "reason": reason.strip(), "inventory_sha256": inventory_sha256,
            "disk_fingerprint": actual_fingerprint, "profile_id": profile.profile_id,
            "profile_version": profile.profile_version, "approved_at": approved_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        })
        updated = deepcopy(status)
        history = list(updated["stage_history"])
        for stage in ("plan_built", "plan_signed", "published"):
            history.append({"stage": stage, "entered_at": approved_at.isoformat()})
        updated.update({"state": "plan_published", "stage": "published", "stage_history": history, "updated_at": approved_at.isoformat(), "plan_revision": 1})
        self.repository.replace_status(session_id, updated)
        return updated

    def preview(self, session_id: str) -> dict[str, object]:
        status = self.repository.load_status(session_id)
        try:
            inventory = parse_inventory(json.loads(self.repository.load_inventory_bytes(session_id)))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ControlError("install_session_inventory_invalid", "Install session inventory is invalid", 4) from exc
        profile = load_profile(self.settings.install_profile_root, "standard-office", 1)
        evaluation = evaluate_policy(inventory, profile)
        return {
            "session_id": status["session_id"], "inventory_sha256": status["inventory_sha256"],
            "profile": {"id": profile.profile_id, "version": profile.profile_version},
            "target_disk": {**evaluation.eligible_disk.to_dict(), "fingerprint": disk_fingerprint(evaluation.eligible_disk)},
            "network_interface": {"name": evaluation.route_interface.name, "mac": evaluation.route_interface.mac},
            "warning": "Approval authorizes whole-disk destruction in a later phase",
        }

    @_with_install_session_lock
    def cancel(self, session_id: str, *, reason: object) -> dict[str, object]:
        if self.euid() != 0:
            raise ControlError("install_session_root_required", "Install cancellation requires root", 4)
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 256:
            raise ControlError("install_session_reason_invalid", "Install cancellation reason is invalid", 4)
        status = self.repository.load_status(session_id)
        if status.get("state") == "cancelled":
            if status.get("cancel_reason") == reason.strip():
                return status
            raise ControlError("install_session_cancel_conflict", "Install session was cancelled with another reason", 4)
        now = datetime.fromisoformat(self.clock()).astimezone(timezone.utc).isoformat()
        updated = deepcopy(status)
        updated.update({"state": "cancelled", "cancelled_at": now, "cancel_reason": reason.strip(), "updated_at": now})
        self.repository.replace_status(session_id, updated)
        return updated
