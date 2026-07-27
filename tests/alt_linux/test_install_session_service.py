from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService


def test_service_creates_session_for_valid_allowed_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions")
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_PROFILE_ROOT",
        str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"),
    )
    settings = Settings.from_env()
    service = InstallSessionService(
        settings,
        repository=InstallSessionRepository(settings),
        clock=lambda: "2026-07-27T12:00:00+00:00",
        credential_factory=lambda: "credential-for-test",
        session_id_factory=lambda: "install-20260727T120000Z-a1b2c3d4",
    )
    payload = json.loads(
        (FIXTURE_ROOT / "inventory-disk-100g.json").read_text(
            encoding="utf-8"
        )
    )

    created = service.create(payload, source_ip="192.168.100.10")

    assert created.session_id == "install-20260727T120000Z-a1b2c3d4"
    assert created.credential == "credential-for-test"
    assert created.state == "awaiting_approval"
    assert created.poll_after_seconds == 3


def test_service_enforces_per_machine_active_session_quota(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_PROFILE_ROOT",
        str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"),
    )
    settings = Settings.from_env()
    session_ids = iter(
        f"install-20260727T12000{index}Z-a1b2c3d{index}"
        for index in range(6)
    )
    service = InstallSessionService(
        settings,
        repository=InstallSessionRepository(settings),
        clock=lambda: "2026-07-27T12:00:00+00:00",
        session_id_factory=lambda: next(session_ids),
    )
    payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    for _ in range(5):
        service.create(payload, source_ip="192.168.100.10")
    with pytest.raises(ControlError) as error:
        service.create(payload, source_ip="192.168.100.10")
    assert error.value.code == "install_session_machine_quota_exceeded"


def test_service_enforces_global_active_session_quota(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_PROFILE_ROOT",
        str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"),
    )
    settings = Settings.from_env()
    repository = InstallSessionRepository(settings)
    monkeypatch.setattr(
        repository,
        "list_statuses",
        lambda: [{"state": "awaiting_approval"}] * 100,
    )
    service = InstallSessionService(settings, repository=repository)
    payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    with pytest.raises(ControlError) as error:
        service.create(payload, source_ip="192.168.100.10")
    assert error.value.code == "install_session_quota_exceeded"
