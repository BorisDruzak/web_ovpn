from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from collections.abc import Mapping
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9._+-]{1,63}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ExecutionManifestV1:
    schema_version: int
    session_id: str
    plan_sha256: str
    inventory_sha256: str
    profile_id: str
    profile_version: int
    iso_id: str
    iso_sha256: str
    target_disk: str
    disk_fingerprint: str
    authorized_at: str
    expires_at: str
    artifacts: Mapping[str, Mapping[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "plan_sha256": self.plan_sha256,
            "inventory_sha256": self.inventory_sha256,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "iso_id": self.iso_id,
            "iso_sha256": self.iso_sha256,
            "target_disk": {
                "path": self.target_disk,
                "fingerprint": self.disk_fingerprint,
            },
            "authorized_at": self.authorized_at,
            "expires_at": self.expires_at,
            "artifacts": {
                name: dict(metadata)
                for name, metadata in self.artifacts.items()
            },
        }


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
) -> ExecutionManifestV1:
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
    return _manifest_from_mapping(
        {
            "schema_version": 1,
            "session_id": session_id,
            "plan_sha256": digest,
            "inventory_sha256": inventory_sha256,
            "profile_id": profile_id,
            "profile_version": profile_version,
            "iso_id": iso_id,
            "iso_sha256": iso_sha256,
            "target_disk": {
                "path": target_path,
                "fingerprint": fingerprint,
            },
            "authorized_at": approved,
            "expires_at": expiry,
            "artifacts": metadata,
        }
    )


def _manifest_from_mapping(
    manifest: Mapping[str, object],
) -> ExecutionManifestV1:
    expected = {
        "schema_version", "session_id", "plan_sha256", "inventory_sha256",
        "profile_id", "profile_version", "iso_id", "iso_sha256", "target_disk",
        "authorized_at", "expires_at", "artifacts",
    }
    if (
        set(manifest) != expected
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
    ):
        raise ValueError("Execution manifest is invalid")
    try:
        session_id = _string(
            manifest["session_id"],
            description="manifest session ID",
            pattern=_SESSION_RE,
        )
        plan_digest = _string(
            manifest["plan_sha256"],
            description="manifest plan SHA-256",
            pattern=_SHA256_RE,
        )
        inventory_digest = _string(
            manifest["inventory_sha256"],
            description="manifest inventory SHA-256",
            pattern=_SHA256_RE,
        )
        profile_id = _string(
            manifest["profile_id"],
            description="manifest profile ID",
            pattern=_IDENTIFIER_RE,
        )
        profile_version = manifest["profile_version"]
        if (
            isinstance(profile_version, bool)
            or not isinstance(profile_version, int)
            or profile_version < 1
        ):
            raise ValueError("Execution manifest profile version is invalid")
        iso_id = _string(
            manifest["iso_id"],
            description="manifest ISO ID",
            pattern=_IDENTIFIER_RE,
        )
        iso_digest = _string(
            manifest["iso_sha256"],
            description="manifest ISO SHA-256",
            pattern=_SHA256_RE,
        )
        target = manifest["target_disk"]
        if not isinstance(target, Mapping) or set(target) != {
            "path",
            "fingerprint",
        }:
            raise ValueError("Execution manifest target disk is invalid")
        target_path = _string(
            target["path"],
            description="manifest target disk",
            pattern=_DEVICE_RE,
        )
        fingerprint = _string(
            target["fingerprint"],
            description="manifest disk fingerprint",
            pattern=_FINGERPRINT_RE,
        )
        authorized_at = _timestamp(
            manifest["authorized_at"],
            description="manifest authorization timestamp",
        )
        expires_at = _timestamp(
            manifest["expires_at"],
            description="manifest expiry timestamp",
        )
        if (
            authorized_at != manifest["authorized_at"]
            or expires_at != manifest["expires_at"]
            or datetime.fromisoformat(expires_at)
            <= datetime.fromisoformat(authorized_at)
        ):
            raise ValueError("Execution manifest expiry is invalid")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Execution manifest is invalid") from exc
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(
        _ARTIFACT_NAMES
    ):
        raise ValueError("Execution manifest is invalid")
    validated_artifacts: dict[str, Mapping[str, object]] = {}
    for name in _ARTIFACT_NAMES:
        metadata = artifacts[name]
        if not isinstance(metadata, Mapping) or set(metadata) != {
            "sha256",
            "size_bytes",
        }:
            raise ValueError("Execution manifest is invalid")
        digest = metadata.get("sha256")
        size = metadata.get("size_bytes")
        if (
            not isinstance(digest, str)
            or not _SHA256_RE.fullmatch(digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= _MAX_ARTIFACT_BYTES
        ):
            raise ValueError("Execution manifest is invalid")
        validated_artifacts[name] = MappingProxyType(
            {"sha256": digest, "size_bytes": size}
        )
    return ExecutionManifestV1(
        schema_version=1,
        session_id=session_id,
        plan_sha256=plan_digest,
        inventory_sha256=inventory_digest,
        profile_id=profile_id,
        profile_version=profile_version,
        iso_id=iso_id,
        iso_sha256=iso_digest,
        target_disk=target_path,
        disk_fingerprint=fingerprint,
        authorized_at=authorized_at,
        expires_at=expires_at,
        artifacts=MappingProxyType(validated_artifacts),
    )


def canonical_execution_manifest_bytes(
    manifest: ExecutionManifestV1 | Mapping[str, object],
) -> bytes:
    if isinstance(manifest, ExecutionManifestV1):
        validated = _manifest_from_mapping(manifest.to_dict())
    elif isinstance(manifest, Mapping):
        validated = _manifest_from_mapping(manifest)
    else:
        raise ValueError("Execution manifest is invalid")
    return json.dumps(
        validated.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8") + b"\n"


def _object_without_duplicates(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Execution manifest is invalid")
        result[name] = value
    return result


def parse_execution_manifest_bytes(raw: bytes) -> ExecutionManifestV1:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1024 * 1024:
        raise ValueError("Execution manifest is invalid")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Execution manifest is invalid") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("Execution manifest is invalid")
    manifest = _manifest_from_mapping(payload)
    if canonical_execution_manifest_bytes(manifest) != raw:
        raise ValueError("Execution manifest is invalid")
    return manifest


def sign_execution_manifest(
    key: Ed25519PrivateKey, manifest_bytes: bytes
) -> dict[str, object]:
    if not isinstance(key, Ed25519PrivateKey) or not isinstance(manifest_bytes, bytes):
        raise ValueError("Execution manifest signing input is invalid")
    parse_execution_manifest_bytes(manifest_bytes)
    metadata = public_key_metadata(key.public_key())
    return {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": metadata["key_id"],
        "signed_file": "execution-manifest.json",
        "manifest_sha256": sha256(manifest_bytes).hexdigest(),
        "signature_b64": base64.b64encode(key.sign(manifest_bytes)).decode("ascii"),
    }


def _validate_signature(
    signature: Mapping[str, object],
) -> dict[str, object]:
    if set(signature) != {
        "schema_version",
        "algorithm",
        "key_id",
        "signed_file",
        "manifest_sha256",
        "signature_b64",
    }:
        raise ValueError("Execution manifest signature is invalid")
    key_id = signature.get("key_id")
    digest = signature.get("manifest_sha256")
    encoded = signature.get("signature_b64")
    if (
        type(signature.get("schema_version")) is not int
        or signature.get("schema_version") != 1
        or signature.get("algorithm") != "ed25519"
        or signature.get("signed_file") != "execution-manifest.json"
        or not isinstance(key_id, str)
        or not _FINGERPRINT_RE.fullmatch(key_id)
        or not isinstance(digest, str)
        or not _SHA256_RE.fullmatch(digest)
        or not isinstance(encoded, str)
    ):
        raise ValueError("Execution manifest signature is invalid")
    try:
        raw_signature = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Execution manifest signature is invalid") from exc
    if (
        len(raw_signature) != 64
        or base64.b64encode(raw_signature).decode("ascii") != encoded
    ):
        raise ValueError("Execution manifest signature is invalid")
    return {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": key_id,
        "signed_file": "execution-manifest.json",
        "manifest_sha256": digest,
        "signature_b64": encoded,
    }


def canonical_execution_signature_bytes(
    signature: Mapping[str, object],
) -> bytes:
    if not isinstance(signature, Mapping):
        raise ValueError("Execution manifest signature is invalid")
    validated = _validate_signature(signature)
    return (
        json.dumps(
            validated,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )


def parse_execution_signature_bytes(raw: bytes) -> dict[str, object]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 16 * 1024:
        raise ValueError("Execution manifest signature is invalid")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Execution manifest signature is invalid") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("Execution manifest signature is invalid")
    validated = _validate_signature(payload)
    if canonical_execution_signature_bytes(validated) != raw:
        raise ValueError("Execution manifest signature is invalid")
    return validated


def verify_execution_manifest_signature(
    key: Ed25519PublicKey,
    manifest_bytes: bytes,
    signature: Mapping[str, object],
) -> bool:
    if not isinstance(key, Ed25519PublicKey) or not isinstance(
        manifest_bytes, bytes
    ) or not isinstance(signature, Mapping):
        return False
    try:
        validated = _validate_signature(signature)
        parse_execution_manifest_bytes(manifest_bytes)
        raw_signature = base64.b64decode(
            str(validated["signature_b64"]), validate=True
        )
        if (
            validated["key_id"] != public_key_metadata(key)["key_id"]
            or validated["manifest_sha256"]
            != sha256(manifest_bytes).hexdigest()
        ):
            return False
        key.verify(raw_signature, manifest_bytes)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True
