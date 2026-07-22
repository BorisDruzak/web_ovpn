from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_signed_checkpoint_is_bound_to_current_audit_chain_and_delivered(tmp_path) -> None:
    from netopsctl.audit import AuditSigner, append_event
    from netopsctl.checkpoint import build_checkpoint, deliver_checkpoint
    from netopsctl.store import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    signer = AuditSigner("audit-test", Ed25519PrivateKey.generate())
    try:
        append_event(conn, signer, "plan.created", {"plan_key": "plan-1"})
        checkpoint = build_checkpoint(conn, signer, instance_id="test-netops")
        assert checkpoint["last_sequence"] == 1
        assert checkpoint["chain_head"].startswith("sha256:")
        sent: dict[str, object] = {}

        def runner(argv, *, input, timeout, check):
            sent["argv"] = argv
            sent["payload"] = json.loads(input.decode("utf-8"))
            return None

        deliver_checkpoint(
            checkpoint, host="192.0.2.56", identity_file="/run/credential/audit-ssh",
            known_hosts="/run/credential/known-hosts", runner=runner,
        )
        assert sent["payload"] == checkpoint
        assert "StrictHostKeyChecking=yes" in sent["argv"]
    finally:
        conn.close()
