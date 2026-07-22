from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .authorization import sign_envelope
from .client import request


def build_reconcile_request(
    private_key: Ed25519PrivateKey,
    *,
    principal_id: str,
    limit: int,
) -> tuple[dict[str, int], dict[str, object], str]:
    """Build the only operation the timer credential is permitted to request."""
    if not principal_id or not 1 <= limit <= 256:
        raise ValueError("invalid reconcile runner configuration")
    now = datetime.now(UTC).replace(microsecond=0)
    payload = {"limit": limit}
    envelope: dict[str, object] = {
        "authorization_version": 1,
        "action": "policy.reconcile",
        "principal_type": "service",
        "principal_id": principal_id,
        "principal_name": principal_id,
        "session_id": f"timer:{uuid.uuid4()}",
        "authorization_id": f"reconcile:{uuid.uuid4()}",
        "scopes": ["network.policy.reconcile"],
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "nonce": str(uuid.uuid4()),
    }
    return payload, envelope, sign_envelope(private_key, envelope)


def main() -> None:
    try:
        key_bytes = Path(os.environ["NETOPSCTL_RECONCILE_SIGNING_KEY_FILE"]).read_bytes()
        private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        principal_id = os.environ.get("NETOPSCTL_RECONCILE_PRINCIPAL_ID", "netopsctl-reconcile")
        limit = int(os.environ.get("NETOPSCTL_RECONCILE_LIMIT", "64"))
        payload, envelope, signature = build_reconcile_request(
            private_key, principal_id=principal_id, limit=limit,
        )
        response = request(
            os.environ.get("NETOPSCTL_SOCKET_PATH", "/run/netopsctl/netopsctl.sock"),
            action="policy.reconcile", payload=payload, authorization=envelope, signature=signature,
        )
    except (KeyError, OSError, ValueError) as exc:
        raise SystemExit(f"netopsctl reconcile runner failed: {exc}") from exc
    if response.get("status") != "ok":
        raise SystemExit("netopsctl reconcile runner was rejected by the broker")


if __name__ == "__main__":
    main()
