from __future__ import annotations

import os
import json
import socket
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .authorization import VerifiedAuthorization, verify_envelope
from .protocol import BrokerRequest, ProtocolError, decode_request, encode_response
from .store import connect, plan_digest


@dataclass(frozen=True)
class AuthenticatedPeer:
    uid: int
    gid: int
    pid: int
    service_principal: str
    public_key: bytes
    allowed_actions: frozenset[str]


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    """Return Linux SO_PEERCRED as uid, gid, pid before accepting any payload."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("SO_PEERCRED is required for netopsctl")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return uid, gid, pid


def authorize_broker_request(
    conn: Any,
    request: BrokerRequest,
    peer: AuthenticatedPeer,
    *,
    now: datetime | None = None,
) -> VerifiedAuthorization:
    if request.action not in peer.allowed_actions:
        raise ValueError("peer is not allowed to perform this action")
    verified = verify_envelope(
        request.authorization, request.signature, peer.public_key,
        action=request.action, payload=request.payload, now=now,
    )
    if request.action not in {"plan.create", "status", "policy.reconcile"}:
        if request.authorization.get("plan_digest") != plan_digest(conn, str(request.payload["plan_key"])):
            raise ValueError("authorization plan digest mismatch")
    timestamp = datetime.now(UTC) if now is None else now.astimezone(UTC)
    try:
        conn.execute(
            "INSERT INTO used_authorization_nonces (nonce, expires_at, consumed_at) VALUES (?, ?, ?)",
            (verified.nonce, verified.expires_at, timestamp.replace(microsecond=0).isoformat().replace("+00:00", "Z")),
        )
        conn.commit()
    except Exception as exc:
        raise ValueError("authorization nonce was replayed") from exc
    return verified


def handle(request: BrokerRequest) -> dict[str, Any]:
    """Dispatch only registered control-plane verbs; adapters are wired in later tasks."""
    if request.action == "status":
        return {"status": "ok", "request_id": request.request_id, "service": "netopsctl"}
    return {"status": "error", "request_id": request.request_id, "error": "action not yet enabled"}


def serve(listener: socket.socket, *, peers_by_uid: dict[int, AuthenticatedPeer], conn: Any) -> None:
    while True:
        connection, _ = listener.accept()
        with connection:
            try:
                uid, gid, pid = peer_credentials(connection)
                peer = peers_by_uid.get(uid)
                if peer is None or peer.gid != gid:
                    raise ProtocolError("untrusted local caller")
                data = connection.recv(16_385)
                request = decode_request(data)
                authorize_broker_request(conn, request, peer)
                response = handle(request)
            except (ProtocolError, ValueError, RuntimeError) as exc:
                response = {"status": "error", "request_id": "", "error": str(exc)}
            connection.sendall(encode_response(response))


def _socket_from_activation() -> socket.socket:
    listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    if listen_fds != 1:
        raise RuntimeError("netopsctl requires one systemd-activated socket")
    return socket.fromfd(3, socket.AF_UNIX, socket.SOCK_STREAM)


def _load_peers() -> dict[int, AuthenticatedPeer]:
    try:
        raw = json.loads(os.environ.get("NETOPSCTL_PEER_PRINCIPALS_JSON", "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("invalid NETOPSCTL_PEER_PRINCIPALS_JSON") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("invalid NETOPSCTL_PEER_PRINCIPALS_JSON")
    result: dict[int, AuthenticatedPeer] = {}
    for uid_raw, record in raw.items():
        if not isinstance(record, dict):
            raise RuntimeError("invalid netopsctl peer principal")
        try:
            uid, gid = int(uid_raw), int(record["gid"])
            service_principal = str(record["service_principal"])
            allowed_actions = frozenset(str(value) for value in record["allowed_actions"])
            public_key = open(str(record["public_key_file"]), "rb").read().strip()
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise RuntimeError("invalid netopsctl peer principal") from exc
        if uid < 0 or gid < 0 or not service_principal or len(public_key) != 32 or not allowed_actions:
            raise RuntimeError("invalid netopsctl peer principal")
        result[uid] = AuthenticatedPeer(uid, gid, 0, service_principal, public_key, allowed_actions)
    if not result:
        raise RuntimeError("at least one authenticated peer principal is required")
    return result


def main() -> None:
    db_url = os.environ.get("NETOPSCTL_DB_URL", "sqlite:////var/lib/netopsctl/netopsctl.sqlite")
    conn = connect(db_url)
    try:
        serve(_socket_from_activation(), peers_by_uid=_load_peers(), conn=conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
