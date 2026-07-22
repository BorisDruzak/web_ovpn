from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .audit import canonical_json


ACTION_SCOPES = {
    "plan.create": "network.plan.create",
    "plan.inspect": "network.plan.read",
    "plan.approve": "network.plan.approve",
    "plan.apply": "network.plan.apply",
    "plan.verify": "network.plan.verify",
    "plan.rollback": "network.plan.rollback",
    "policy.list": "network.policy.read",
    "policy.reconcile": "network.policy.reconcile",
    "status": "network.status.read",
}
_BASE_FIELDS = {
    "authorization_version", "action", "principal_type", "principal_id", "principal_name",
    "session_id", "authorization_id", "scopes", "issued_at", "expires_at", "nonce",
}
_NO_PLAN_ACTIONS = frozenset({"status", "policy.list", "policy.reconcile", "plan.inspect"})


def canonical_envelope(envelope: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(envelope))


def request_digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(dict(payload))).hexdigest()


def sign_envelope(private_key: Ed25519PrivateKey, envelope: Mapping[str, Any]) -> str:
    return base64.urlsafe_b64encode(private_key.sign(canonical_envelope(envelope))).decode("ascii").rstrip("=")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("invalid authorization timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid authorization timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("authorization timestamp needs timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class VerifiedAuthorization:
    principal_type: str
    principal_id: str
    principal_name: str
    session_id: str
    authorization_id: str
    nonce: str
    expires_at: str


def verify_envelope(
    envelope: Mapping[str, Any],
    signature: str,
    public_key: bytes,
    *,
    action: str,
    payload: Mapping[str, Any],
    now: datetime | None = None,
) -> VerifiedAuthorization:
    if action not in ACTION_SCOPES or envelope.get("authorization_version") != 1 or envelope.get("action") != action:
        raise ValueError("authorization action is invalid")
    fields = set(envelope)
    expected_fields = _BASE_FIELDS | (
        {"request_digest"} if action == "plan.create" else set() if action in _NO_PLAN_ACTIONS else {"plan_id", "plan_digest"}
    )
    if fields != expected_fields:
        raise ValueError("authorization envelope schema mismatch")
    for key in ("principal_type", "principal_id", "principal_name", "session_id", "authorization_id", "nonce"):
        if not isinstance(envelope.get(key), str) or not str(envelope[key]).strip() or len(str(envelope[key])) > 255:
            raise ValueError("authorization principal is invalid")
    scopes = envelope.get("scopes")
    if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes) or ACTION_SCOPES[action] not in scopes:
        raise ValueError("authorization scope is missing")
    if action == "plan.create":
        if envelope.get("request_digest") != request_digest(payload):
            raise ValueError("authorization request digest mismatch")
    elif action not in _NO_PLAN_ACTIONS and (envelope.get("plan_id") != payload.get("plan_key") or not isinstance(envelope.get("plan_digest"), str)):
        raise ValueError("authorization plan binding mismatch")
    issued_at, expires_at = _parse_time(envelope["issued_at"]), _parse_time(envelope["expires_at"])
    now = datetime.now(UTC) if now is None else now.astimezone(UTC)
    if expires_at <= issued_at or expires_at - issued_at > timedelta(minutes=15) or now < issued_at - timedelta(seconds=30) or now >= expires_at:
        raise ValueError("authorization is expired or invalid")
    try:
        encoded = signature + "=" * (-len(signature) % 4)
        raw_signature = base64.urlsafe_b64decode(encoded.encode("ascii"))
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw_signature, canonical_envelope(envelope))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("authorization signature is invalid") from exc
    return VerifiedAuthorization(
        principal_type=str(envelope["principal_type"]), principal_id=str(envelope["principal_id"]),
        principal_name=str(envelope["principal_name"]), session_id=str(envelope["session_id"]),
        authorization_id=str(envelope["authorization_id"]), nonce=str(envelope["nonce"]),
        expires_at=str(envelope["expires_at"]),
    )
