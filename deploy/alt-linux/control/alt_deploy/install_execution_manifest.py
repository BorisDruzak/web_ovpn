from __future__ import annotations

import base64
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .install_session_signing import public_key_metadata


_ARTIFACT_NAMES = (
    "autoinstall.scm",
    "vm-profile.scm",
    "pkg-groups.tar",
    "install-scripts.tar",
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SESSION_RE = re.compile(r"^install-\d{8}T\d{6}Z-[0-9a-f]{8}$")
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _timestamp(value: object, *, description: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Execution {description} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Execution {description} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Execution {description} is invalid")
    return parsed.astimezone(timezone.utc).isoformat()


def _required_plan_value(plan: Mapping[str, object], name: str) -> object:
    value = plan.get(name)
    if value is None:
        raise ValueError("Execution plan binding is invalid")
    return value


def _string(value: object, *, description: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"Execution {description} is invalid")
    if pattern is not None and not pattern.fullmatch(value):
        raise ValueError(f"Execution {description} is invalid")
    return value


def build_execution_manifest(
    *,
    plan: Mapping[str, object],
    plan_sha256: object,
    authorized_at: object,
    expires_at: object,
    artifacts: Mapping[str, bytes],
) -> dict[str, object]:
    if not isinstance(plan, Mapping):
        raise ValueError("Execution plan binding is invalid")
    session_id = _string(
        _required_plan_value(plan, "session_id"), description="session ID", pattern=_SESSION_RE
    )
    inventory_sha256 = _string(
        _required_plan_value(plan, "inventory_sha256"), description="inventory SHA-256", pattern=_SHA256_RE
    )
    profile_id = _string(_required_plan_value(plan, "profile_id"), description="profile ID")
    profile_version = _required_plan_value(plan, "profile_version")
    if isinstance(profile_version, bool) or not isinstance(profile_version, int) or profile_version < 1:
        raise ValueError("Execution profile version is invalid")
    iso_id = _string(_required_plan_value(plan, "iso_id"), description="ISO ID")
    iso_sha256 = _string(
        _required_plan_value(plan, "iso_sha256"), description="ISO SHA-256", pattern=_SHA256_RE
    )
    target = _required_plan_value(plan, "target_disk")
    if not isinstance(target, Mapping):
        raise ValueError("Execution target disk is invalid")
    target_path = _string(target.get("path"), description="target disk path")
    fingerprint = _string(
        target.get("fingerprint"), description="disk fingerprint", pattern=_FINGERPRINT_RE
    )
    digest = _string(plan_sha256, description="plan SHA-256", pattern=_SHA256_RE)
    approved = _timestamp(authorized_at, description="authorization timestamp")
    expiry = _timestamp(expires_at, description="expiry timestamp")
    if datetime.fromisoformat(expiry) <= datetime.fromisoformat(approved):
        raise ValueError("Execution expiry is invalid")
    if set(artifacts) != set(_ARTIFACT_NAMES):
        raise ValueError("Execution artifact names are invalid")
    metadata: dict[str, dict[str, object]] = {}
    for name in _ARTIFACT_NAMES:
        content = artifacts[name]
        if not isinstance(content, bytes) or not 1 <= len(content) <= _MAX_ARTIFACT_BYTES:
            raise ValueError("Execution artifact content is invalid")
        metadata[name] = {"sha256": sha256(content).hexdigest(), "size_bytes": len(content)}
    return {
        "schema_version": 1,
        "session_id": session_id,
        "plan_sha256": digest,
        "inventory_sha256": inventory_sha256,
        "profile_id": profile_id,
        "profile_version": profile_version,
        "iso_id": iso_id,
        "iso_sha256": iso_sha256,
        "target_disk": {"path": target_path, "fingerprint": fingerprint},
        "authorized_at": approved,
        "expires_at": expiry,
        "artifacts": metadata,
    }


def canonical_execution_manifest_bytes(manifest: Mapping[str, object]) -> bytes:
    if not isinstance(manifest, Mapping):
        raise ValueError("Execution manifest is invalid")
    expected = {
        "schema_version", "session_id", "plan_sha256", "inventory_sha256",
        "profile_id", "profile_version", "iso_id", "iso_sha256", "target_disk",
        "authorized_at", "expires_at", "artifacts",
    }
    if set(manifest) != expected or manifest.get("schema_version") != 1:
        raise ValueError("Execution manifest is invalid")
    # Rebuild through the strict constructor before serializing untrusted mappings.
    return json.dumps(
        dict(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8") + b"\n"


def sign_execution_manifest(
    key: Ed25519PrivateKey, manifest_bytes: bytes
) -> dict[str, object]:
    if not isinstance(key, Ed25519PrivateKey) or not isinstance(manifest_bytes, bytes):
        raise ValueError("Execution manifest signing input is invalid")
    metadata = public_key_metadata(key.public_key())
    return {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": metadata["key_id"],
        "signed_file": "execution-manifest.json",
        "manifest_sha256": sha256(manifest_bytes).hexdigest(),
        "signature_b64": base64.b64encode(key.sign(manifest_bytes)).decode("ascii"),
    }
