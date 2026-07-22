from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


GENESIS_HASH = "sha256:" + "0" * 64


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AuditSigner:
    key_id: str
    private_key: Ed25519PrivateKey

    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _event_hash(*, sequence: int, previous_hash: str, payload_hash: str, event_type: str, created_at: str) -> str:
    return _hash(canonical_json({
        "sequence": sequence, "previous_hash": previous_hash, "payload_hash": payload_hash,
        "event_type": event_type, "created_at": created_at,
    }))


def append_event(conn: sqlite3.Connection, signer: AuditSigner, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if not event_type or len(event_type) > 120:
        raise ValueError("invalid audit event type")
    if not isinstance(payload, Mapping):
        raise ValueError("audit payload must be an object")
    row = conn.execute("SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
    sequence = int(row["sequence"]) + 1 if row else 1
    previous_hash = str(row["event_hash"]) if row else GENESIS_HASH
    created_at = _now()
    payload_hash = _hash(canonical_json(dict(payload)))
    event_hash = _event_hash(
        sequence=sequence, previous_hash=previous_hash, payload_hash=payload_hash,
        event_type=event_type, created_at=created_at,
    )
    signature = signer.private_key.sign(event_hash.encode("ascii"))
    event_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO audit_events
           (sequence, event_id, event_type, created_at, payload_hash, previous_hash, event_hash, signer_key_id, signature)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (sequence, event_id, event_type, created_at, payload_hash, previous_hash, event_hash, signer.key_id, signature),
    )
    conn.commit()
    return {"sequence": sequence, "event_id": event_id, "event_hash": event_hash}


def verify_chain(conn: sqlite3.Connection, public_keys: Mapping[str, bytes]) -> dict[str, Any]:
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    rows = conn.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
    for row in rows:
        if int(row["sequence"]) != expected_sequence or str(row["previous_hash"]) != previous_hash:
            raise ValueError("audit chain sequence or previous hash mismatch")
        actual_hash = _event_hash(
            sequence=int(row["sequence"]), previous_hash=previous_hash, payload_hash=str(row["payload_hash"]),
            event_type=str(row["event_type"]), created_at=str(row["created_at"]),
        )
        if actual_hash != str(row["event_hash"]):
            raise ValueError("audit event hash mismatch")
        key = public_keys.get(str(row["signer_key_id"]))
        if key is None:
            raise ValueError("unknown audit signer key")
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(bytes(row["signature"]), actual_hash.encode("ascii"))
        except (ValueError, InvalidSignature) as exc:
            raise ValueError("invalid audit event signature") from exc
        previous_hash = actual_hash
        expected_sequence += 1
    return {"valid": True, "events": len(rows)}
