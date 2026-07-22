from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _request(private_key, *, plan_key: str, plan_digest: str, nonce: str = "nonce-1"):
    from netopsctl.authorization import sign_envelope
    from netopsctl.protocol import BrokerRequest

    now = datetime.now(UTC)
    envelope = {
        "authorization_version": 1, "action": "plan.apply", "principal_type": "web_user",
        "principal_id": "42", "principal_name": "admin-2", "session_id": "session-1",
        "authorization_id": "authorization-1", "scopes": ["network.plan.apply"],
        "plan_id": plan_key, "plan_digest": plan_digest,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"), "nonce": nonce,
    }
    return BrokerRequest(str(uuid.uuid4()), "plan.apply", {"plan_key": plan_key}, envelope, sign_envelope(private_key, envelope))


def test_broker_authorization_binds_peer_key_plan_digest_and_single_use_nonce(tmp_path) -> None:
    from netopsctl.server import AuthenticatedPeer, authorize_broker_request
    from netopsctl.store import connect, create_change_plan, plan_digest

    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    private_key = Ed25519PrivateKey.generate()
    try:
        create_change_plan(conn, plan_key="plan-1", actor="web:42", reason="approved", subject_type="asset", subject_key="mac:AA", operation_type="internet_access_set", desired_state={}, resolved_targets=[], context_evidence_hash="a" * 64, precheck={}, rollback={})
        request = _request(private_key, plan_key="plan-1", plan_digest=plan_digest(conn, "plan-1"))
        peer = AuthenticatedPeer(uid=1001, gid=1001, pid=123, service_principal="openvpn-web", public_key=private_key.public_key().public_bytes_raw(), allowed_actions=frozenset({"plan.apply"}))
        assert authorize_broker_request(conn, request, peer).principal_id == "42"
        with pytest.raises(ValueError, match="replayed"):
            authorize_broker_request(conn, request, peer)
        wrong_peer = AuthenticatedPeer(uid=1002, gid=1002, pid=124, service_principal="other", public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw(), allowed_actions=frozenset({"plan.apply"}))
        with pytest.raises(ValueError, match="signature"):
            authorize_broker_request(conn, _request(private_key, plan_key="plan-1", plan_digest=plan_digest(conn, "plan-1"), nonce="nonce-2"), wrong_peer)
        with pytest.raises(ValueError, match="digest"):
            authorize_broker_request(conn, _request(private_key, plan_key="plan-1", plan_digest="sha256:" + "0" * 64, nonce="nonce-3"), peer)
    finally:
        conn.close()
