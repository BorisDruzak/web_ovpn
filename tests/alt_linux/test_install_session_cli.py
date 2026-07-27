from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest


pytest.importorskip("fcntl", reason="CLI imports POSIX controller locking")


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.cli import main
from alt_deploy.config import Settings
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_service import InstallSessionService


def test_cli_show_redacts_private_session_fields(
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
    payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
    created = InstallSessionService(
        settings,
        repository=repository,
        clock=lambda: "2026-07-27T12:00:00+00:00",
        session_id_factory=lambda: "install-20260727T120000Z-a1b2c3d4",
    ).create(payload, source_ip="192.168.100.10")

    output = io.StringIO()
    assert main(
        ["--json", "install-sessions", "show", created.session_id],
        settings=settings,
        stdout=output,
    ) == 0
    document = json.loads(output.getvalue())
    assert document["session"]["session_id"] == created.session_id
    assert "source_ip" not in document["session"]
    assert "agent_boot_id" not in document["session"]
