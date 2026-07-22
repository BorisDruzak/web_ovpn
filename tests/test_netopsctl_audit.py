from __future__ import annotations


def test_audit_events_are_append_only_and_tamper_evident(tmp_path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from netopsctl.audit import AuditSigner, append_event, verify_chain
    from netopsctl.store import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netops.sqlite').as_posix()}")
    signer = AuditSigner("test-key", Ed25519PrivateKey.generate())
    try:
        append_event(conn, signer, "plan.created", {"plan_key": "plan-1"})
        append_event(conn, signer, "plan.approved", {"plan_key": "plan-1"})
        assert verify_chain(conn, {"test-key": signer.public_key_bytes()}) == {"valid": True, "events": 2}
        import sqlite3
        try:
            conn.execute("DELETE FROM audit_events")
        except sqlite3.IntegrityError:
            pass
        else:  # pragma: no cover - assertion communicates an invariant
            raise AssertionError("audit events must be append-only")
    finally:
        conn.close()
