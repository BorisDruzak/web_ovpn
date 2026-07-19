import json
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import get_settings, reset_settings_cache
from app.models import ServerDraft
from app import server_drafts
from app.server_drafts import (
    create_draft_request,
    make_draft_request,
    observer_public_key,
    read_public_result,
)


def test_server_draft_persists_only_public_metadata():
    columns = ServerDraft.__table__.columns

    assert set(columns.keys()) == {
        "id",
        "name",
        "host",
        "ssh_user",
        "port",
        "created_at",
        "updated_at",
    }
    assert columns["id"].type.length == 36
    assert columns["host"].type.length == 253
    assert columns["ssh_user"].type.length == 64
    assert columns["port"].default.arg == 22


def test_settings_define_isolated_draft_paths(monkeypatch):
    monkeypatch.setenv("SERVER_DRAFT_QUEUE_DIR", "/tmp/queue")
    monkeypatch.setenv("SERVER_DRAFT_RESULTS_DIR", "/tmp/results")
    monkeypatch.setenv("SERVER_DRAFT_PRIVATE_DIR", "/tmp/private")
    monkeypatch.setenv("OBSERVER_PUBLIC_KEY_PATH", "/tmp/observer.pub")
    reset_settings_cache()

    try:
        settings = get_settings()

        assert settings.server_draft_queue_dir == Path("/tmp/queue")
        assert settings.server_draft_results_dir == Path("/tmp/results")
        assert settings.server_draft_private_dir == Path("/tmp/private")
        assert settings.observer_public_key_path == Path("/tmp/observer.pub")
    finally:
        reset_settings_cache()


def test_request_rejects_unsafe_components_and_bad_port():
    with pytest.raises(ValueError):
        make_draft_request("not-a-uuid", "host;id", "user", 22, "scan")
    with pytest.raises(ValueError):
        make_draft_request(str(uuid4()), "host", "user", 0, "scan")
    with pytest.raises(ValueError):
        make_draft_request(str(uuid4()), "host", "user", 22, "id;whoami")


def test_queue_is_atomic_and_has_no_private_material(tmp_path, monkeypatch):
    request = make_draft_request(str(uuid4()), "server.example", "observer", 22, "scan")
    chmod_calls = []
    original_chmod = server_drafts.os.chmod

    def record_chmod(path, mode):
        chmod_calls.append(mode)
        original_chmod(path, mode)

    monkeypatch.setattr(server_drafts.os, "chmod", record_chmod)

    path = create_draft_request(tmp_path, request)

    assert path == tmp_path / f"{request.id}.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "action": "scan",
        "host": "server.example",
        "id": request.id,
        "port": 22,
        "ssh_user": "observer",
    }
    assert chmod_calls == [0o640]
    assert "PRIVATE KEY" not in path.read_text(encoding="utf-8")
    assert not list(tmp_path.glob(".*.tmp"))


def test_public_result_removes_host_key_and_stderr(tmp_path):
    draft_id = str(uuid4())
    (tmp_path / f"{draft_id}.json").write_text(
        json.dumps(
            {
                "status": "transport",
                "stderr": "raw",
                "host_key": "ssh-ed25519 AAA",
                "algorithm": "ssh-ed25519",
                "fingerprint": "SHA256:public",
                "checked_at": "2026-07-19T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    assert read_public_result(tmp_path, draft_id) == {
        "status": "transport",
        "algorithm": "ssh-ed25519",
        "fingerprint": "SHA256:public",
        "checked_at": "2026-07-19T00:00:00Z",
    }


def test_public_helpers_reject_private_or_unsafe_inputs(tmp_path):
    with pytest.raises(ValueError):
        read_public_result(tmp_path, "not-a-uuid")

    public_key = tmp_path / "observer.pub"
    public_key.write_text("ssh-ed25519 AAA observer\n", encoding="utf-8")
    assert observer_public_key(public_key) == "ssh-ed25519 AAA observer\n"

    public_key.write_text("-----BEGIN PRIVATE KEY-----\nraw\n", encoding="utf-8")
    with pytest.raises(ValueError):
        observer_public_key(public_key)
