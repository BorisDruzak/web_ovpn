from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.config import Settings
from alt_deploy.install_session_repository import (
    InstallSessionRepository,
)


def _settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Settings:
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS",
        str(tmp_path / "install-sessions"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS_LOCK",
        str(tmp_path / "install-sessions.lock"),
    )
    return Settings.from_env()


def test_repository_creates_private_durable_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(monkeypatch, tmp_path)
    repository = InstallSessionRepository(settings)
    session_id = "install-20260727T120000Z-a1b2c3d4"
    status = {
        "schema_version": 1,
        "session_id": session_id,
        "state": "awaiting_approval",
        "stage": "awaiting_approval",
        "stage_history": [],
        "inventory_sha256": "a" * 64,
        "machine_uuid": "machine-1",
        "agent_boot_id": "boot-1",
        "source_ip": "192.168.100.10",
        "created_at": "2026-07-27T12:00:00+00:00",
        "updated_at": "2026-07-27T12:00:00+00:00",
        "last_seen_at": "2026-07-27T12:00:00+00:00",
        "plan_revision": None,
        "cancelled_at": None,
        "cancel_reason": None,
    }

    repository.create(
        session_id=session_id,
        inventory_bytes=b'{"schema_version":1}\n',
        credential_sha256="b" * 64,
        status=status,
    )

    directory = settings.install_sessions_dir / session_id
    assert sorted(path.name for path in directory.iterdir()) == [
        "auth.json",
        "inventory.json",
        "status.json",
    ]
    if os.name != "nt":
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(
            (directory / "inventory.json").stat().st_mode
        ) == 0o600
    assert json.loads((directory / "auth.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "credential_sha256": "b" * 64,
    }
    assert repository.load_status(session_id) == status


@pytest.mark.skipif(os.name == "nt", reason="fchown is POSIX-only")
def test_root_status_replacement_hands_file_to_service_account(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(monkeypatch, tmp_path)
    repository = InstallSessionRepository(settings)
    session_id = "install-20260727T120000Z-a1b2c3d4"
    status = {
        "schema_version": 1, "session_id": session_id,
        "state": "awaiting_approval", "stage": "awaiting_approval",
        "stage_history": [], "inventory_sha256": "a" * 64,
        "machine_uuid": "machine-1", "agent_boot_id": "boot-1",
        "source_ip": "192.168.100.10", "created_at": "2026-07-27T12:00:00+00:00",
        "updated_at": "2026-07-27T12:00:00+00:00", "last_seen_at": "2026-07-27T12:00:00+00:00",
        "plan_revision": None, "cancelled_at": None, "cancel_reason": None,
    }
    repository.create(
        session_id=session_id, inventory_bytes=b'{"schema_version":1}\n',
        credential_sha256="b" * 64, status=status,
    )
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(repository, "_service_owner", lambda: (501, 502))
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append((uid, gid)))
    repository.replace_status(session_id, status)
    assert calls == [(501, 502)]
