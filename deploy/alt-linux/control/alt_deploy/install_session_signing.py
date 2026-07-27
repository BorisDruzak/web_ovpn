from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def public_key_metadata(key: Ed25519PublicKey) -> dict[str, object]:
    raw = _public_key_bytes(key)
    return {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "public_key_b64": base64.b64encode(raw).decode("ascii"),
    }


def load_private_signer(path: Path) -> Ed25519PrivateKey:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Install signing private key is not a regular file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("Install signing private key permissions are invalid")
    if metadata.st_size < 1 or metadata.st_size > 4096:
        raise ValueError("Install signing private key size is invalid")
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("Install signing private key PEM is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Install signing private key algorithm is invalid")
    return key


def sign_plan_bytes(key: Ed25519PrivateKey, plan_bytes: bytes) -> bytes:
    if not isinstance(key, Ed25519PrivateKey) or not isinstance(plan_bytes, bytes):
        raise ValueError("Install plan signing input is invalid")
    return key.sign(plan_bytes)


def verify_plan_signature(
    key: Ed25519PublicKey,
    plan_bytes: bytes,
    signature: bytes,
    key_id: object,
) -> bool:
    if not isinstance(key, Ed25519PublicKey) or not isinstance(
        plan_bytes, bytes
    ) or not isinstance(signature, bytes):
        return False
    metadata = public_key_metadata(key)
    if key_id != metadata["key_id"]:
        return False
    try:
        key.verify(signature, plan_bytes)
    except InvalidSignature:
        return False
    return True
