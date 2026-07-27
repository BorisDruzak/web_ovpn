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
from alt_deploy.errors import ControlError
from alt_deploy.install_fingerprint import disk_fingerprint
from alt_deploy.install_inventory import parse_inventory
from alt_deploy.install_session_approval import InstallSessionApprovalService
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService
from alt_deploy.install_session_signing import public_key_metadata


def test_root_approval_publishes_signed_first_revision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "install-plan-ed25519.pem"
    private_key = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    public_key_path = tmp_path / "install-plan-ed25519.pub"
    public_key_path.write_text(
        json.dumps(public_key_metadata(private_key.public_key())),
        encoding="utf-8",
    )
    public_key_path.chmod(0o644)
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PRIVATE_KEY", str(key_path))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PUBLIC_KEY", str(public_key_path))
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


@pytest.mark.parametrize(
    "failed_method",
    ("publish_revision", "write_approval", "replace_status"),
)
def test_failed_approval_removes_partial_artifacts_and_can_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failed_method: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "install-plan-ed25519.pem"
    key_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    key_path.chmod(0o600)
    public_key_path = tmp_path / "install-plan-ed25519.pub"
    public_key_path.write_text(json.dumps(public_key_metadata(private_key.public_key())), encoding="utf-8")
    public_key_path.chmod(0o644)
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PRIVATE_KEY", str(key_path))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PUBLIC_KEY", str(public_key_path))
    settings = Settings.from_env()
    repository = InstallSessionRepository(settings)
    payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    session_id = "install-20260727T120000Z-a1b2c3d4"
    created = InstallSessionService(
        settings, repository=repository,
        clock=lambda: "2026-07-27T12:00:00+00:00",
        session_id_factory=lambda: session_id,
    ).create(payload, source_ip="192.168.100.10")
    fingerprint = disk_fingerprint(parse_inventory(payload).disks[0])
    service = InstallSessionApprovalService(
        settings, repository=repository,
        clock=lambda: "2026-07-27T12:01:00+00:00", euid=lambda: 0,
    )
    original = getattr(repository, failed_method)

    def fail_write(*args: object, **kwargs: object) -> None:
        raise ControlError("install_session_storage_failed", "injected", 6)

    monkeypatch.setattr(repository, failed_method, fail_write)
    with pytest.raises(ControlError, match="injected"):
        service.approve(
            created.session_id,
            inventory_sha256=repository.load_status(created.session_id)["inventory_sha256"],
            disk_fingerprint_value=fingerprint,
            reason="Approve after injected publication failure",
        )
    session_dir = settings.install_sessions_dir / created.session_id
    assert not (session_dir / "approval.json").exists()
    assert not (session_dir / "revision-0001").exists()
    assert repository.load_status(created.session_id)["state"] == "awaiting_approval"
    monkeypatch.setattr(repository, failed_method, original)
    retried = service.approve(
        created.session_id,
        inventory_sha256=repository.load_status(created.session_id)["inventory_sha256"],
        disk_fingerprint_value=fingerprint,
        reason="Approve after injected publication failure",
    )
    assert retried["state"] == "plan_published"


def test_status_fsync_failure_preserves_an_already_published_plan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "install-plan-ed25519.pem"
    key_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    key_path.chmod(0o600)
    public_key_path = tmp_path / "install-plan-ed25519.pub"
    public_key_path.write_text(json.dumps(public_key_metadata(private_key.public_key())), encoding="utf-8")
    public_key_path.chmod(0o644)
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PRIVATE_KEY", str(key_path))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PUBLIC_KEY", str(public_key_path))
    settings = Settings.from_env()
    repository = InstallSessionRepository(settings)
    payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    created = InstallSessionService(
        settings, repository=repository,
        clock=lambda: "2026-07-27T12:00:00+00:00",
        session_id_factory=lambda: "install-20260727T120000Z-a1b2c3d4",
    ).create(payload, source_ip="192.168.100.10")
    service = InstallSessionApprovalService(
        settings, repository=repository,
        clock=lambda: "2026-07-27T12:01:00+00:00", euid=lambda: 0,
    )
    original_fsync = repository._fsync_directory
    calls = 0

    def fail_final_status_fsync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise ControlError("install_session_storage_failed", "injected fsync", 6)
        original_fsync(path)

    monkeypatch.setattr(repository, "_fsync_directory", fail_final_status_fsync)
    fingerprint = disk_fingerprint(parse_inventory(payload).disks[0])
    with pytest.raises(ControlError) as error:
        service.approve(
            created.session_id,
            inventory_sha256=repository.load_status(created.session_id)["inventory_sha256"],
            disk_fingerprint_value=fingerprint,
            reason="Preserve committed plan after fsync failure",
        )
    assert error.value.code == "install_session_status_commit_uncertain"
    session_dir = settings.install_sessions_dir / created.session_id
    assert repository.load_status(created.session_id)["state"] == "plan_published"
    assert (session_dir / "approval.json").is_file()
    assert (session_dir / "revision-0001" / "plan.json").is_file()
