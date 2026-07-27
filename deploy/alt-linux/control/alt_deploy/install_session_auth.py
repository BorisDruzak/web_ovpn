from __future__ import annotations

import hashlib
import hmac
import secrets


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


def verify_credential(credential: str, expected_sha256: str) -> bool:
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        return False
    try:
        actual = credential_sha256(credential)
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected_sha256)
