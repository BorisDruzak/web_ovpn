from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "release"
RELEASE_BUILDER = RELEASE_ROOT / "build-managed-iso-release.sh"
RELEASE_CONTRACT = RELEASE_ROOT / "lib" / "release-contract.py"
RELEASE_RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "alt-install-production-release-pr5b.md"


def test_release_builder_declares_the_public_key_only_contract() -> None:
    assert RELEASE_BUILDER.is_file()
    assert RELEASE_CONTRACT.is_file()

    builder = RELEASE_BUILDER.read_text(encoding="utf-8")
    assert "--source-commit" in builder
    assert "--source-iso" in builder
    assert "--public-key" in builder
    assert "--release-id" in builder
    assert "--iso-dir" in builder
    assert "192.168.100.17:18090" in builder
    assert "18089" not in builder
    assert "install-plan-ed25519.pem" not in builder
    assert "flock -n" in builder


def test_release_contract_generates_a_sorted_canonical_index(tmp_path: Path) -> None:
    sidecar = tmp_path / "release.build-manifest.json"
    sidecar.write_text(
        json.dumps(
            {
                "build_id": "release-20260729T090000Z-deadbee",
                "controller_url": "http://192.168.100.17:18090",
                "format": "alt-install-agent-managed-iso-v1",
                "helper_sha256": "b" * 64,
                "managed_initrd_sha256": "c" * 64,
                "managed_iso_sha256": "d" * 64,
                "payload_manifest_sha256": "e" * 64,
                "public_key_id": "sha256:" + "f" * 64,
                "public_key_sha256": "a" * 64,
                "source_iso_sha256": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    index = tmp_path / "alt-install-agent-v1-releases.json"
    index.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "releases": [
                    {
                        "created_at": "2026-07-28T09:00:00Z",
                        "git_commit": "a" * 40,
                        "helper_sha256": "2" * 64,
                        "managed_iso_sha256": "3" * 64,
                        "public_key_id": "sha256:" + "4" * 64,
                        "release_id": "20260728T090000Z-c0ffee0",
                        "source_iso_sha256": "5" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "new-index.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(RELEASE_CONTRACT),
            "update-index",
            "--index",
            str(index),
            "--sidecar",
            str(sidecar),
            "--release-id",
            "20260729T090000Z-deadbee",
            "--commit",
            "b" * 40,
            "--created-at",
            "2026-07-29T09:00:00Z",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    rendered = output.read_bytes()
    document = json.loads(rendered)
    assert [entry["release_id"] for entry in document["releases"]] == [
        "20260728T090000Z-c0ffee0",
        "20260729T090000Z-deadbee",
    ]
    assert rendered == json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def test_release_contract_rejects_nonproduction_controller(tmp_path: Path) -> None:
    sidecar = tmp_path / "release.build-manifest.json"
    sidecar.write_text(
        json.dumps(
            {
                "build_id": "release-20260729T090000Z-deadbee",
                "controller_url": "http://192.168.100.17:18091",
                "format": "alt-install-agent-managed-iso-v1",
                "helper_sha256": "b" * 64,
                "managed_initrd_sha256": "c" * 64,
                "managed_iso_sha256": "d" * 64,
                "payload_manifest_sha256": "e" * 64,
                "public_key_id": "sha256:" + "f" * 64,
                "public_key_sha256": "a" * 64,
                "source_iso_sha256": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(RELEASE_CONTRACT),
            "update-index",
            "--index",
            str(tmp_path / "missing-index.json"),
            "--sidecar",
            str(sidecar),
            "--release-id",
            "20260729T090000Z-deadbee",
            "--commit",
            "b" * 40,
            "--created-at",
            "2026-07-29T09:00:00Z",
            "--output",
            str(tmp_path / "new-index.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "controller URL" in completed.stderr


def test_release_contract_rejects_sidecar_with_a_different_release_id(tmp_path: Path) -> None:
    sidecar = tmp_path / "release.build-manifest.json"
    sidecar.write_text(
        json.dumps(
            {
                "build_id": "release-20260729T090000Z-c0ffee0",
                "controller_url": "http://192.168.100.17:18090",
                "format": "alt-install-agent-managed-iso-v1",
                "helper_sha256": "b" * 64,
                "managed_initrd_sha256": "c" * 64,
                "managed_iso_sha256": "d" * 64,
                "payload_manifest_sha256": "e" * 64,
                "public_key_id": "sha256:" + "f" * 64,
                "public_key_sha256": "a" * 64,
                "source_iso_sha256": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(RELEASE_CONTRACT),
            "update-index",
            "--index",
            str(tmp_path / "missing-index.json"),
            "--sidecar",
            str(sidecar),
            "--release-id",
            "20260729T090000Z-deadbee",
            "--commit",
            "b" * 40,
            "--created-at",
            "2026-07-29T09:00:00Z",
            "--output",
            str(tmp_path / "new-index.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert "build ID" in completed.stderr


def test_production_release_runbook_preserves_pr5b_boundary() -> None:
    text = RELEASE_RUNBOOK.read_text(encoding="utf-8")
    assert "192.168.100.17:18090" in text
    assert "pve2" in text
    assert "must never be copied" in text
    assert "VM 114 must not be changed" in text
