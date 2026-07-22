from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_reconcile_runner_uses_its_own_scoped_signed_envelope() -> None:
    from netopsctl.authorization import verify_envelope
    from netopsctl.reconcile_runner import build_reconcile_request

    private_key = Ed25519PrivateKey.generate()
    payload, envelope, signature = build_reconcile_request(
        private_key, principal_id="netopsctl-reconcile", limit=7,
    )

    assert payload == {"limit": 7}
    assert envelope["scopes"] == ["network.policy.reconcile"]
    assert verify_envelope(
        envelope, signature, private_key.public_key().public_bytes_raw(),
        action="policy.reconcile", payload=payload,
    ).principal_id == "netopsctl-reconcile"
