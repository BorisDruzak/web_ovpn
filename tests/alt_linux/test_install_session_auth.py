from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_session_auth import (
    credential_sha256,
    generate_credential,
    verify_credential,
)


def test_generated_credential_verifies_only_against_its_hash() -> None:
    credential = generate_credential()
    stored_hash = credential_sha256(credential)

    assert len(credential) >= 43
    assert verify_credential(credential, stored_hash) is True
    assert verify_credential("wrong-credential", stored_hash) is False
