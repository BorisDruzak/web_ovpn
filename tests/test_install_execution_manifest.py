from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.install_execution_manifest import (
    build_execution_manifest,
    canonical_execution_manifest_bytes,
    sign_execution_manifest,
)


def _plan() -> dict[str, object]:
    return {
        "session_id": "install-20260729T120000Z-a1b2c3d4",
        "inventory_sha256": "a" * 64,
        "profile_id": "standard-office",
        "profile_version": 1,
        "iso_id": "alt-kworkstation-11.4-install-x86_64",
        "iso_sha256": "b" * 64,
        "target_disk": {"path": "/dev/vda", "fingerprint": "sha256:" + "c" * 64},
    }


def _artifacts() -> dict[str, bytes]:
    return {
        "autoinstall.scm": b"(fixture)\n",
        "vm-profile.scm": b"((fixture))\n",
        "pkg-groups.tar": b"pkg-groups-fixture",
        "install-scripts.tar": b"scripts-fixture",
    }


def test_manifest_is_canonical_signed_and_binds_every_execution_artifact() -> None:
    plan = _plan()
    artifacts = _artifacts()
    manifest = build_execution_manifest(
        plan=plan,
        plan_sha256="d" * 64,
        authorized_at="2026-07-29T12:02:00+00:00",
        expires_at="2026-07-29T12:07:00+00:00",
        artifacts=artifacts,
    )
    encoded = canonical_execution_manifest_bytes(manifest)
    private = Ed25519PrivateKey.generate()
    signature = sign_execution_manifest(private, encoded)

    assert json.loads(encoded) == manifest
    assert manifest["artifacts"]["pkg-groups.tar"] == {
        "sha256": hashlib.sha256(artifacts["pkg-groups.tar"]).hexdigest(),
        "size_bytes": len(artifacts["pkg-groups.tar"]),
    }
    assert signature["signed_file"] == "execution-manifest.json"
    assert signature["manifest_sha256"] == hashlib.sha256(encoded).hexdigest()


def test_manifest_rejects_missing_extra_or_empty_artifacts() -> None:
    with pytest.raises(ValueError, match="artifact names"):
        build_execution_manifest(
            plan=_plan(), plan_sha256="d" * 64,
            authorized_at="2026-07-29T12:02:00+00:00",
            expires_at="2026-07-29T12:07:00+00:00",
            artifacts={"autoinstall.scm": b"x"},
        )
    with pytest.raises(ValueError, match="artifact content"):
        build_execution_manifest(
            plan=_plan(), plan_sha256="d" * 64,
            authorized_at="2026-07-29T12:02:00+00:00",
            expires_at="2026-07-29T12:07:00+00:00",
            artifacts={**_artifacts(), "pkg-groups.tar": b""},
        )
