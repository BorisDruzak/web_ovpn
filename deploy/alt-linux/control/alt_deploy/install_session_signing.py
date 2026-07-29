from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _is_actual_root() -> bool:
    return (
        os.name != "nt"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
    )


def _read_regular_file(
    path: Path,
    *,
    mode: int,
    maximum_size: int,
    root_owned: bool,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Install signing key cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Install signing key is not a regular file")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError("Install signing key permissions are invalid")
        if root_owned and _is_actual_root() and (
            metadata.st_uid != 0 or metadata.st_gid != 0
        ):
            raise ValueError("Install signing key ownership is invalid")
        if metadata.st_size < 1 or metadata.st_size > maximum_size:
            raise ValueError("Install signing key size is invalid")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


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


def _canonical_public_key_json(metadata: dict[str, object]) -> bytes:
    return (
        json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def load_private_signer(path: Path) -> Ed25519PrivateKey:
    raw = _read_regular_file(
        path, mode=0o600, maximum_size=4096, root_owned=True
    )
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("Install signing private key PEM is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Install signing private key algorithm is invalid")
    return key


def load_public_verifier(path: Path) -> Ed25519PublicKey:
    raw = _read_regular_file(
        path, mode=0o644, maximum_size=4096, root_owned=True
    )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Install signing public key JSON is invalid") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version", "algorithm", "key_id", "public_key_b64"
    }:
        raise ValueError("Install signing public key fields are invalid")
    if document.get("schema_version") != 1 or document.get("algorithm") != "ed25519":
        raise ValueError("Install signing public key metadata is invalid")
    value = document.get("public_key_b64")
    if not isinstance(value, str):
        raise ValueError("Install signing public key value is invalid")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(value, validate=True)
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Install signing public key value is invalid") from exc
    if document.get("key_id") != public_key_metadata(public_key)["key_id"]:
        raise ValueError("Install signing public key ID is invalid")
    if raw != _canonical_public_key_json(public_key_metadata(public_key)):
        raise ValueError("Install signing public key JSON is not canonical")
    return public_key


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
