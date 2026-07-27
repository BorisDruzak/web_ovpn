from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_session_signing import (
    load_private_signer,
    public_key_metadata,
    sign_plan_bytes,
    verify_plan_signature,
)


def test_ed25519_signature_rejects_a_mutated_plan(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "install-plan-ed25519.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    plan = b'{"schema_version":1}\n'

    signer = load_private_signer(key_path)
    metadata = public_key_metadata(signer.public_key())
    signature = sign_plan_bytes(signer, plan)

    assert metadata["algorithm"] == "ed25519"
    assert verify_plan_signature(
        signer.public_key(), plan, signature, metadata["key_id"]
    ) is True
    assert verify_plan_signature(
        signer.public_key(), b'{"schema_version":2}\n', signature, metadata["key_id"]
    ) is False
