from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = REPO_ROOT / "tests" / "alt_linux" / "fixtures" / "install"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_execution import ExecutionAuthorizationService
from alt_deploy.install_fingerprint import disk_fingerprint
from alt_deploy.install_inventory import parse_inventory
from alt_deploy.install_session_approval import InstallSessionApprovalService
from alt_deploy.install_session_keys import ensure_install_session_keypair
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService


def _approved_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, preflight: bool
) -> tuple[Settings, InstallSessionRepository, str, dict[str, object], str]:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PRIVATE_KEY", str(tmp_path / "secrets" / "plan.pem"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SIGNING_PUBLIC_KEY", str(tmp_path / "etc" / "plan.pub"))
    settings = Settings.from_env()
    ensure_install_session_keypair(settings, euid=lambda: 0)
    repository = InstallSessionRepository(settings)
    inventory_payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    created = InstallSessionService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-29T12:00:00+00:00",
        session_id_factory=lambda: "install-20260729T120000Z-a1b2c3d4",
    ).create(inventory_payload, source_ip="192.168.100.10", create_nonce="A" * 43)
    inventory = parse_inventory(inventory_payload)
    approved = InstallSessionApprovalService(
        settings, repository=repository,
        clock=lambda: "2026-07-29T12:01:00+00:00", euid=lambda: 0,
    ).approve(
        created.session_id,
        inventory_sha256=repository.load_status(created.session_id)["inventory_sha256"],
        disk_fingerprint_value=disk_fingerprint(inventory.disks[0]),
        reason="Approve disposable execution fixture",
    )
    if preflight:
        status = repository.load_status(created.session_id)
        status["agent_status"] = {
            "agent_version": "2.0.0",
            "boot_id": "fixture-boot",
            "reported_stage": "preflight_ready",
            "schema_version": 1,
            "sent_at": "2026-07-29T12:01:30+00:00",
            "sequence": 5,
        }
        repository.replace_status(created.session_id, status)
    plan_bytes = repository.read_revision_file(created.session_id, "plan.json")
    return settings, repository, created.session_id, approved, hashlib.sha256(plan_bytes).hexdigest()


def test_root_execution_authorization_is_bound_to_preflight_plan_and_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch, preflight=True
    )
    execution = ExecutionAuthorizationService(
        settings, repository=repository,
        clock=lambda: "2026-07-29T12:02:00+00:00", euid=lambda: 0,
    ).authorize(
        session_id,
        plan_sha256=plan_sha256,
        inventory_sha256=approved["inventory_sha256"],
        disk_fingerprint_value=json.loads(
            repository.read_revision_file(session_id, "plan.json")
        )["target_disk"]["fingerprint"],
        confirm_target="/dev/vda",
        reason="Authorize exactly this disposable target",
    )

    assert execution["execution"]["state"] == "authorized"
    assert execution["execution"]["plan_sha256"] == plan_sha256
    assert execution["execution"]["target_disk"] == "/dev/vda"
    assert execution["execution"]["expires_at"] == "2026-07-29T12:07:00+00:00"
    with pytest.raises(ControlError, match="already authorized"):
        ExecutionAuthorizationService(
            settings, repository=repository,
            clock=lambda: "2026-07-29T12:02:01+00:00", euid=lambda: 0,
        ).authorize(
            session_id, plan_sha256=plan_sha256,
            inventory_sha256=approved["inventory_sha256"],
            disk_fingerprint_value=execution["execution"]["disk_fingerprint"],
            confirm_target="/dev/vda", reason="Second execution authorization",
        )


def test_execution_authorization_refuses_a_plan_without_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, repository, session_id, approved, plan_sha256 = _approved_session(
        tmp_path, monkeypatch, preflight=False
    )

    with pytest.raises(ControlError, match="preflight"):
        ExecutionAuthorizationService(
            settings, repository=repository,
            clock=lambda: "2026-07-29T12:02:00+00:00", euid=lambda: 0,
        ).authorize(
            session_id, plan_sha256=plan_sha256,
            inventory_sha256=approved["inventory_sha256"],
            disk_fingerprint_value=json.loads(
                repository.read_revision_file(session_id, "plan.json")
            )["target_disk"]["fingerprint"],
            confirm_target="/dev/vda", reason="Must not bypass preflight",
        )
