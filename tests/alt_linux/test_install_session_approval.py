from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.config import Settings
from alt_deploy.install_fingerprint import disk_fingerprint
from alt_deploy.install_inventory import parse_inventory
from alt_deploy.install_session_approval import InstallSessionApprovalService
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService


def test_root_approval_publishes_signed_first_revision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "install-plan-ed25519.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PRIVATE_KEY", str(key_path))
    settings = Settings.from_env()
    repository = InstallSessionRepository(settings)
    payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    created = InstallSessionService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-27T12:00:00+00:00",
        credential_factory=lambda: "credential-for-test",
        session_id_factory=lambda: "install-20260727T120000Z-a1b2c3d4",
    ).create(payload, source_ip="192.168.100.10")
    inventory = parse_inventory(payload)

    approved = InstallSessionApprovalService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-27T12:01:00+00:00",
        euid=lambda: 0,
    ).approve(
        created.session_id,
        inventory_sha256=repository.load_status(created.session_id)["inventory_sha256"],
        disk_fingerprint_value=disk_fingerprint(inventory.disks[0]),
        reason="Approved disposable ALT installation target",
    )

    assert approved["state"] == "plan_published"
    assert approved["plan_revision"] == 1
    approval = json.loads(
        (settings.install_sessions_dir / created.session_id / "approval.json").read_text(
            encoding="utf-8"
        )
    )
    assert approval["operator_uid"] == 0
    assert approval["inventory_sha256"] == approved["inventory_sha256"]
    revision = settings.install_sessions_dir / created.session_id / "revision-0001"
    assert sorted(path.name for path in revision.iterdir()) == [
        "plan-signature.json",
        "plan.json",
        "plan.sha256",
    ]
    repeated = InstallSessionApprovalService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-27T12:02:00+00:00",
        euid=lambda: 0,
    ).approve(
        created.session_id,
        inventory_sha256=approved["inventory_sha256"],
        disk_fingerprint_value=disk_fingerprint(inventory.disks[0]),
        reason="Approved disposable ALT installation target",
    )
    assert repeated == approved
