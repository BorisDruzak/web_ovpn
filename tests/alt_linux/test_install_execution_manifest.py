from __future__ import annotations

# ruff: noqa: E402

from copy import deepcopy
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_execution_manifest import (
    build_execution_manifest,
    canonical_execution_manifest_bytes,
)
from alt_deploy import install_execution_manifest as manifest_module


def _plan() -> dict[str, object]:
    return {
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "inventory_sha256": "a" * 64,
        "profile_id": "standard-office",
        "profile_version": 1,
        "iso_id": "alt-kworkstation-11.4-install-x86_64",
        "iso_sha256": "b" * 64,
        "target_disk": {
            "path": "/dev/vda",
            "fingerprint": "sha256:" + "c" * 64,
        },
    }


def _artifacts() -> dict[str, bytes]:
    return {
        "autoinstall.scm": b"(fixture)\n",
        "vm-profile.scm": b"((fixture))\n",
        "pkg-groups.tar": b"pkg-groups-fixture",
        "install-scripts.tar": b"scripts-fixture",
    }


def test_canonical_manifest_rejects_an_unknown_nested_artifact_field() -> None:
    manifest = build_execution_manifest(
        plan=_plan(),
        plan_sha256="d" * 64,
        authorized_at="2026-07-29T12:02:00+00:00",
        expires_at="2026-07-29T12:07:00+00:00",
        artifacts=_artifacts(),
    )
    malformed = deepcopy(
        manifest.to_dict() if hasattr(manifest, "to_dict") else manifest
    )
    malformed["artifacts"]["pkg-groups.tar"]["unexpected"] = True

    with pytest.raises(ValueError, match="manifest"):
        canonical_execution_manifest_bytes(malformed)


def test_manifest_builder_returns_a_typed_target_and_canonical_bytes() -> None:
    manifest = build_execution_manifest(
        plan=_plan(),
        plan_sha256="d" * 64,
        authorized_at="2026-07-29T12:02:00+00:00",
        expires_at="2026-07-29T12:07:00+00:00",
        artifacts=_artifacts(),
    )

    assert type(manifest).__name__ == "ExecutionManifestV1"
    assert manifest.target_disk == "/dev/vda"
    assert canonical_execution_manifest_bytes(manifest).endswith(b"\n")


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("target_disk", "unexpected"), True),
        (("artifacts", "autoinstall.scm", "sha256"), "not-a-digest"),
        (("artifacts", "vm-profile.scm", "size_bytes"), True),
        (("target_disk", "path"), "../../dev/vda"),
        (("authorized_at",), "2026-07-29T12:02:00"),
    ],
)
def test_canonical_manifest_rejects_malformed_typed_fields(
    path: tuple[str, ...],
    value: object,
) -> None:
    manifest = build_execution_manifest(
        plan=_plan(),
        plan_sha256="d" * 64,
        authorized_at="2026-07-29T12:02:00+00:00",
        expires_at="2026-07-29T12:07:00+00:00",
        artifacts=_artifacts(),
    )
    malformed = deepcopy(
        manifest.to_dict() if hasattr(manifest, "to_dict") else manifest
    )
    target = malformed
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value

    with pytest.raises(ValueError, match="manifest"):
        canonical_execution_manifest_bytes(malformed)


def test_manifest_parser_accepts_only_its_exact_canonical_encoding() -> None:
    parser = getattr(manifest_module, "parse_execution_manifest_bytes", None)
    assert callable(parser), "strict execution manifest parser is missing"
    manifest = build_execution_manifest(
        plan=_plan(),
        plan_sha256="d" * 64,
        authorized_at="2026-07-29T12:02:00+00:00",
        expires_at="2026-07-29T12:07:00+00:00",
        artifacts=_artifacts(),
    )
    encoded = canonical_execution_manifest_bytes(manifest)

    parsed = parser(encoded)

    assert parsed == manifest
    with pytest.raises(ValueError, match="manifest"):
        parser(encoded + b" ")


def test_manifest_signature_is_canonical_and_rejects_tampering() -> None:
    encode_signature = getattr(
        manifest_module, "canonical_execution_signature_bytes", None
    )
    parse_signature = getattr(
        manifest_module, "parse_execution_signature_bytes", None
    )
    verify_signature = getattr(
        manifest_module, "verify_execution_manifest_signature", None
    )
    assert all(
        callable(item)
        for item in (encode_signature, parse_signature, verify_signature)
    ), "strict execution signature contract is missing"
    manifest = build_execution_manifest(
        plan=_plan(),
        plan_sha256="d" * 64,
        authorized_at="2026-07-29T12:02:00+00:00",
        expires_at="2026-07-29T12:07:00+00:00",
        artifacts=_artifacts(),
    )
    manifest_bytes = canonical_execution_manifest_bytes(manifest)
    private = Ed25519PrivateKey.generate()
    signature = manifest_module.sign_execution_manifest(
        private, manifest_bytes
    )
    signature_bytes = encode_signature(signature)

    parsed = parse_signature(signature_bytes)

    assert verify_signature(
        private.public_key(), manifest_bytes, parsed
    )
    assert not verify_signature(
        private.public_key(), manifest_bytes + b" ", parsed
    )
    with pytest.raises(ValueError, match="signature"):
        parse_signature(signature_bytes + b" ")
