from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _envelope(action: str = "plan.apply") -> dict[str, object]:
    now = datetime.now(UTC)
    base: dict[str, object] = {
        "authorization_version": 1, "action": action, "principal_type": "web_user",
        "principal_id": "42", "principal_name": "admin-2", "session_id": "session-1",
        "authorization_id": "authorization-1", "scopes": ["network.plan.apply"],
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"), "nonce": "nonce-1",
    }
    if action == "plan.create":
        base["scopes"] = ["network.plan.create"]
        base["request_digest"] = "sha256:placeholder"
    else:
        base["plan_id"] = "plan-1"
        base["plan_digest"] = "sha256:" + "a" * 64
    return base


def test_signed_envelope_binds_action_scope_and_payload() -> None:
    from netopsctl.authorization import request_digest, sign_envelope, verify_envelope

    private_key = Ed25519PrivateKey.generate()
    envelope = _envelope()
    signature = sign_envelope(private_key, envelope)
    verified = verify_envelope(envelope, signature, private_key.public_key().public_bytes_raw(), action="plan.apply", payload={"plan_key": "plan-1"})
    assert verified.principal_id == "42"
    missing_scope = _envelope()
    missing_scope["scopes"] = []
    with pytest.raises(ValueError, match="scope"):
        verify_envelope(missing_scope, sign_envelope(private_key, missing_scope), private_key.public_key().public_bytes_raw(), action="plan.apply", payload={"plan_key": "plan-1"})
    create = _envelope("plan.create")
    create["request_digest"] = request_digest({"plan": {"subject_key": "mac:AA"}})
    create_signature = sign_envelope(private_key, create)
    verify_envelope(create, create_signature, private_key.public_key().public_bytes_raw(), action="plan.create", payload={"plan": {"subject_key": "mac:AA"}})
    with pytest.raises(ValueError, match="digest"):
        verify_envelope(create, create_signature, private_key.public_key().public_bytes_raw(), action="plan.create", payload={"plan": {"subject_key": "mac:BB"}})


def test_signed_envelope_rejects_expiry_and_signature_from_other_key() -> None:
    from netopsctl.authorization import sign_envelope, verify_envelope

    private_key = Ed25519PrivateKey.generate()
    envelope = _envelope()
    envelope["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    signature = sign_envelope(private_key, envelope)
    with pytest.raises(ValueError, match="expired"):
        verify_envelope(envelope, signature, private_key.public_key().public_bytes_raw(), action="plan.apply", payload={"plan_key": "plan-1"})
    fresh = _envelope()
    signature = sign_envelope(private_key, fresh)
    with pytest.raises(ValueError, match="signature"):
        verify_envelope(fresh, signature, Ed25519PrivateKey.generate().public_key().public_bytes_raw(), action="plan.apply", payload={"plan_key": "plan-1"})
