from __future__ import annotations

import base64
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
from .install_session_state import InstallSessionStageManager
from .install_session_signing import (
    load_private_signer,
    load_public_verifier,
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
        if status.get("state") == "expired":
            raise ControlError("install_session_expired", "Install session is expired", 4)
        if status.get("state") != "awaiting_approval":
            raise ControlError("install_session_approval_conflict", "Install session is not awaiting approval", 4)
        approved_at = datetime.fromisoformat(self.clock()).astimezone(timezone.utc)
        expires_at_value = status.get("expires_at")
        if isinstance(expires_at_value, str) and datetime.fromisoformat(expires_at_value).astimezone(timezone.utc) <= approved_at:
            expired = deepcopy(status)
            timestamp = approved_at.isoformat()
            expired.update({"state": "expired", "expired_at": timestamp, "updated_at": timestamp})
            InstallSessionStageManager(self.repository, clock=self.clock).validate_status(expired)
            self.repository.replace_status(session_id, expired, allow_lifecycle=True)
            raise ControlError("install_session_expired", "Install session is expired", 4)
        # Artifact and status replacement cannot be one filesystem operation.
        # If a prior process died after publishing an artifact, status.json is
        # still authoritative and the retry removes only that partial output.
        if self.repository.has_partial_publication(session_id):
            self.repository.discard_partial_publication(session_id)
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
        expires_at = approved_at + timedelta(minutes=30)
        plan = build_install_plan(
            inventory, profile, evaluation,
            OperatorSelection(evaluation.eligible_disk.path, actual_fingerprint, evaluation.route_interface.name, evaluation.route_interface.mac),
            PlanRequest(session_id, 1, f"alt-install-{session_id[-12:].lower()}", approved_at.isoformat(), expires_at.isoformat()),
        )
        plan_bytes = canonical_plan_bytes(plan)
        try:
            signer = load_private_signer(
                self.settings.install_signing_private_key
            )
            verifier = load_public_verifier(
                self.settings.install_signing_public_key
            )
        except ValueError as exc:
            raise ControlError(
                "install_signing_key_invalid",
                "Install signing key material is invalid",
                4,
            ) from exc
        if public_key_metadata(signer.public_key()) != public_key_metadata(verifier):
            raise ControlError(
                "install_signing_key_mismatch",
                "Install signing keys do not match",
                4,
            )
        metadata = public_key_metadata(signer.public_key())
        signature = sign_plan_bytes(signer, plan_bytes)
        signature_document = {
            "schema_version": 1, "algorithm": "ed25519", "key_id": metadata["key_id"],
            "signed_file": "plan.json", "plan_sha256": plan_sha256(plan),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "created_at": approved_at.isoformat(),
        }
        approval = {
            "schema_version": 1, "session_id": session_id, "revision": 1,
            "operator_uid": self.euid(), "operator_name": "root",
            "reason": reason.strip(), "inventory_sha256": inventory_sha256,
            "disk_fingerprint": actual_fingerprint, "profile_id": profile.profile_id,
            "profile_version": profile.profile_version, "approved_at": approved_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        stages = InstallSessionStageManager(self.repository, clock=self.clock)
        updated = stages.advance_status(status, "plan_built")
        updated = stages.advance_status(updated, "plan_signed")
        updated = stages.advance_status(updated, "published")
        updated["state"] = "plan_published"
        updated["plan_revision"] = 1
        updated["updated_at"] = approved_at.isoformat()
        updated["expires_at"] = expires_at.isoformat()
        updated["expired_at"] = None
        stages.validate_status(updated)
        try:
            self.repository.publish_revision(
                session_id,
                plan_bytes=plan_bytes,
                plan_sha256=plan_sha256(plan),
                signature=signature_document,
            )
            self.repository.write_approval(session_id, approval)
            self.repository.replace_status(
                session_id, updated, allow_lifecycle=True
            )
        except ControlError as exc:
            if exc.code == "install_session_status_commit_uncertain":
                raise
            self.repository.discard_partial_publication(session_id)
            raise
        except Exception:
            self.repository.discard_partial_publication(session_id)
            raise
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
        stages = InstallSessionStageManager(self.repository, clock=self.clock)
        stages.validate_status(status)
        now = datetime.fromisoformat(self.clock()).astimezone(timezone.utc).isoformat()
        updated = deepcopy(status)
        updated.update({"state": "cancelled", "cancelled_at": now, "cancel_reason": reason.strip(), "updated_at": now})
        stages.validate_status(updated)
        self.repository.replace_status(
            session_id, updated, allow_lifecycle=True
        )
        return updated
