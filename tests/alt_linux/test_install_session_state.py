from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
if str(CONTROL_ROOT) not in sys.path:
    sys.path.insert(0, str(CONTROL_ROOT))

from alt_deploy.config import Settings
from alt_deploy.errors import ControlError
from alt_deploy.install_session_repository import InstallSessionRepository
from alt_deploy.install_session_state import InstallSessionStageManager


def _repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[InstallSessionRepository, str]:
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS",
        str(tmp_path / "install-sessions"),
    )
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_SESSIONS_LOCK",
        str(tmp_path / "install-sessions.lock"),
    )
    settings = Settings.from_env()
    repository = InstallSessionRepository(settings)
    session_id = "install-20260727T120000Z-a1b2c3d4"
    status = {
        "schema_version": 1,
        "session_id": session_id,
        "state": "awaiting_approval",
        "stage": "awaiting_approval",
        "stage_history": [
            {"stage": "session_created", "entered_at": "2026-07-27T12:00:00+00:00"},
            {"stage": "inventory_validated", "entered_at": "2026-07-27T12:00:01+00:00"},
            {"stage": "awaiting_approval", "entered_at": "2026-07-27T12:00:02+00:00"},
        ],
        "inventory_sha256": "a" * 64,
        "machine_uuid": "machine-1",
        "agent_boot_id": "boot-1",
        "source_ip": "192.168.100.10",
        "created_at": "2026-07-27T12:00:00+00:00",
        "updated_at": "2026-07-27T12:00:02+00:00",
        "last_seen_at": "2026-07-27T12:00:02+00:00",
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
    return repository, session_id


def test_stage_manager_advances_only_the_next_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, session_id = _repository(monkeypatch, tmp_path)
    manager = InstallSessionStageManager(
        repository,
        clock=lambda: "2026-07-27T12:00:03+00:00",
    )

    updated = manager.advance(session_id, "plan_built")

    assert updated["stage"] == "plan_built"
    assert updated["stage_history"][-1] == {
        "stage": "plan_built",
        "entered_at": "2026-07-27T12:00:03+00:00",
    }
    with pytest.raises(ControlError) as error:
        manager.advance(session_id, "published")
    assert error.value.code == "invalid_install_session_stage_transition"
