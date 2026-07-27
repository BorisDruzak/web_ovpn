from __future__ import annotations

import hashlib
import hmac
import secrets
import base64


def generate_credential() -> str:
    """Create the one-time agent credential with at least 256 bits of entropy."""
    return secrets.token_urlsafe(32)


def credential_sha256(credential: str) -> str:
    if not isinstance(credential, str) or not credential:
        raise ValueError("Install session credential is invalid")
    try:
        encoded = credential.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Install session credential is invalid") from exc
    return hashlib.sha256(encoded).hexdigest()


def create_nonce_sha256(create_nonce: object) -> str:
    """Validate and digest the agent-generated 32-byte replay nonce."""
    if not isinstance(create_nonce, str) or len(create_nonce) != 43:
        raise ValueError("Install session create nonce is invalid")
    try:
        raw = base64.b64decode(
            create_nonce + "=", altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Install session create nonce is invalid") from exc
    if (
        len(raw) != 32
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        != create_nonce
    ):
        raise ValueError("Install session create nonce is invalid")
    return hashlib.sha256(create_nonce.encode("ascii")).hexdigest()


def verify_credential(credential: str, expected_sha256: str) -> bool:
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        return False
    try:
        actual = credential_sha256(credential)
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected_sha256)
