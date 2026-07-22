from __future__ import annotations

import base64
import json
import subprocess
from datetime import UTC, datetime
from typing import Any, Callable

from .audit import AuditSigner, canonical_json


def build_checkpoint(conn: Any, signer: AuditSigner, *, instance_id: str) -> dict[str, Any]:
    if not instance_id or len(instance_id) > 120:
        raise ValueError("invalid checkpoint instance id")
    row = conn.execute("SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
    payload: dict[str, Any] = {
        "instance_id": instance_id,
        "last_sequence": int(row["sequence"]) if row else 0,
        "chain_head": str(row["event_hash"]) if row else "sha256:" + "0" * 64,
        "key_id": signer.key_id,
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    payload["signature"] = base64.urlsafe_b64encode(
        signer.private_key.sign(canonical_json(payload))
    ).decode("ascii").rstrip("=")
    return payload


def deliver_checkpoint(
    checkpoint: dict[str, Any],
    *,
    host: str,
    identity_file: str,
    known_hosts: str,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    if not host or not identity_file or not known_hosts:
        raise ValueError("audit checkpoint destination is not configured")
    payload = canonical_json(checkpoint) + b"\n"
    try:
        runner(
            [
                "ssh", "-i", identity_file, "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
                f"netops-audit@{host}", "checkpoint",
            ],
            input=payload, timeout=20, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("audit checkpoint delivery failed") from exc
