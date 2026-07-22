from __future__ import annotations

import uuid
import json
import socket
import struct
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


def test_broker_error_keeps_decoded_request_correlation_id(tmp_path, monkeypatch) -> None:
    import netopsctl.server as server_module
    from netopsctl.protocol import encode_response
    from netopsctl.server import AuthenticatedPeer, serve
    from netopsctl.store import connect

    class Connection:
        def __init__(self, payload: bytes):
            self.payload = payload
            self.sent = b""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getsockopt(self, *_args):
            return struct.pack("3i", 123, 1001, 1001)

        def recv(self, _size):
            return self.payload

        def sendall(self, value):
            self.sent = value

    class Listener:
        def __init__(self, connection):
            self.connection = connection
            self.used = False

        def accept(self):
            if self.used:
                raise StopIteration
            self.used = True
            return self.connection, None

    private_key = Ed25519PrivateKey.generate()
    request = _request(private_key, plan_key="plan-1", plan_digest="sha256:" + "a" * 64)
    payload = encode_response({
        "protocol_version": 2, "request_id": request.request_id, "action": request.action,
        "payload": request.payload, "authorization": request.authorization, "signature": "not-a-valid-signature",
    })
    connection = Connection(payload)
    peer = AuthenticatedPeer(1001, 1001, 0, "openvpn-web", private_key.public_key().public_bytes_raw(), frozenset({"plan.apply"}))
    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    monkeypatch.setattr(server_module, "peer_credentials", lambda _connection: (1001, 1001, 123))
    try:
        with pytest.raises(StopIteration):
            serve(Listener(connection), peers_by_uid={1001: peer}, conn=conn, service=None)
        assert json.loads(connection.sent)["request_id"] == request.request_id
    finally:
        conn.close()
