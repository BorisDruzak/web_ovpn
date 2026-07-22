from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from netopsctl.authorization import ACTION_SCOPES, request_digest, sign_envelope
from netopsctl.client import request as broker_request
from netopsctl.protocol import ProtocolError

from .config import get_settings


@dataclass
class NetworkControlError(Exception):
    message: str


def _private_key() -> Ed25519PrivateKey:
    path = get_settings().network_control_signing_key_path
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise NetworkControlError("network-control signing key is unavailable") from exc
    if len(raw) != 32:
        raise NetworkControlError("network-control signing key is invalid")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _authorization(
    action: str,
    payload: dict[str, Any],
    *,
    actor: str,
    session_id: str,
    authorization_id: str,
    plan_digest: str | None = None,
) -> tuple[dict[str, Any], str]:
    scope = ACTION_SCOPES.get(action)
    if scope is None:
        raise NetworkControlError("unsupported network-control action")
    now = datetime.now(UTC)
    envelope: dict[str, Any] = {
        "authorization_version": 1,
        "action": action,
        "principal_type": "api_principal",
        "principal_id": actor,
        "principal_name": actor,
        "session_id": session_id,
        "authorization_id": authorization_id,
        "scopes": [scope],
        "issued_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "nonce": str(uuid.uuid4()),
    }
    if action == "plan.create":
        envelope["request_digest"] = request_digest(payload)
    elif action not in {"status", "policy.list", "policy.reconcile", "plan.inspect"}:
        plan_key = payload.get("plan_key")
        if not isinstance(plan_key, str) or not plan_digest:
            raise NetworkControlError("network-control plan digest is unavailable")
        envelope["plan_id"] = plan_key
        envelope["plan_digest"] = plan_digest
    return envelope, sign_envelope(_private_key(), envelope)


def _send(
    action: str,
    payload: dict[str, Any],
    *,
    actor: str,
    session_id: str,
    authorization_id: str,
    plan_digest: str | None = None,
) -> dict[str, Any]:
    authorization, signature = _authorization(
        action, payload, actor=actor, session_id=session_id,
        authorization_id=authorization_id, plan_digest=plan_digest,
    )
    try:
        response = broker_request(
            str(get_settings().network_control_socket_path), action=action, payload=payload,
            authorization=authorization, signature=signature,
        )
    except (OSError, ProtocolError) as exc:
        raise NetworkControlError("network-control broker is unavailable") from exc
    if response.get("status") != "ok":
        raise NetworkControlError(str(response.get("error") or "network-control broker rejected the request"))
    data = response.get("data")
    if not isinstance(data, dict):
        raise NetworkControlError("network-control broker returned invalid data")
    return data


def run_network_control(
    action: str,
    payload: dict[str, Any],
    *,
    actor: str,
    session_id: str,
    authorization_id: str,
) -> dict[str, Any]:
    """Call the broker with a fresh signed, actor-bound authorization envelope."""
    plan_digest: str | None = None
    if action not in {"status", "policy.list", "policy.reconcile", "plan.create", "plan.inspect"}:
        plan_key = payload.get("plan_key")
        if not isinstance(plan_key, str):
            raise NetworkControlError("network-control action requires a plan key")
        inspected = _send(
            "plan.inspect", {"plan_key": plan_key}, actor=actor, session_id=session_id,
            authorization_id=f"{authorization_id}:inspect",
        )
        plan_digest = inspected.get("plan_digest") if isinstance(inspected.get("plan_digest"), str) else None
        if not plan_digest:
            raise NetworkControlError("network-control plan digest is unavailable")
    return _send(
        action, payload, actor=actor, session_id=session_id,
        authorization_id=authorization_id, plan_digest=plan_digest,
    )
