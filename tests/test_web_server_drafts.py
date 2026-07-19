import hashlib
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import ServerDraft, WebAuditLog


def make_client(tmp_path, monkeypatch, public_key="ssh-ed25519 AAA observer"):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(b"api-token").hexdigest())
    monkeypatch.setenv("SERVER_DRAFT_QUEUE_DIR", str(tmp_path / "queue"))
    monkeypatch.setenv("SERVER_DRAFT_RESULTS_DIR", str(tmp_path / "results"))
    public_key_path = tmp_path / "observer.pub"
    public_key_path.write_text(f"{public_key}\n", encoding="utf-8")
    monkeypatch.setenv("OBSERVER_PUBLIC_KEY_PATH", str(public_key_path))

    import app.config
    import app.db
    import app.main

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    return TestClient(app.main.app)


def make_logged_in_client(tmp_path, monkeypatch, **kwargs):
    client = make_client(tmp_path, monkeypatch, **kwargs)
    login = client.get("/login")
    csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return client


def post_with_csrf(client, path, data):
    page = client.get("/network/server-drafts")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    return client.post(path, data={**data, "csrf_token": csrf}, follow_redirects=False)


def queued_action(tmp_path):
    entries = list((tmp_path / "queue").glob("*.json"))
    assert len(entries) == 1
    return json.loads(entries[0].read_text(encoding="utf-8"))


def db_session():
    from app.db import get_sessionmaker

    return get_sessionmaker()()


def create_draft(client, tmp_path):
    response = post_with_csrf(
        client,
        "/network/server-drafts/new",
        {"name": "new", "host": "server.example", "ssh_user": "observer", "port": "22"},
    )
    assert response.status_code == 303
    with db_session() as db:
        return db.query(ServerDraft).one().id


def test_pages_and_key_download_require_session(tmp_path, monkeypatch):
    client = make_client(tmp_path, monkeypatch)

    assert client.get("/network/server-drafts", follow_redirects=False).status_code == 303
    assert client.get("/network/server-drafts/public-key", follow_redirects=False).status_code == 303


def test_create_requires_csrf_and_queues_scan(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)

    assert client.post("/network/server-drafts/new", data={"name": "new"}).status_code == 400
    draft_id = create_draft(client, tmp_path)
    with db_session() as db:
        draft = db.get(ServerDraft, draft_id)
        assert draft.host == "server.example"
    assert queued_action(tmp_path)["action"] == "scan"


def test_create_does_not_queue_scan_when_database_persistence_fails(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    original_commit = Session.commit

    def fail_draft_commit(session):
        if any(isinstance(item, ServerDraft) for item in session.new):
            raise SQLAlchemyError("forced persistence failure")
        return original_commit(session)

    monkeypatch.setattr(Session, "commit", fail_draft_commit)

    response = post_with_csrf(
        client,
        "/network/server-drafts/new",
        {"name": "new", "host": "server.example", "ssh_user": "observer", "port": "22"},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/network/server-drafts/new"
    assert not list((tmp_path / "queue").glob("*.json"))
    with db_session() as db:
        assert db.query(ServerDraft).count() == 0


def test_public_key_download_excludes_private_material(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch, public_key="ssh-ed25519 AAA observer")

    response = client.get("/network/server-drafts/public-key")

    assert response.status_code == 200
    assert response.headers["content-disposition"].endswith('filename="openvpm-observer.pub"')
    assert response.text == "ssh-ed25519 AAA observer\n"
    assert "PRIVATE" not in response.text


def test_confirm_uses_stored_fingerprint_and_audits_uuid(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    (results / f"{draft_id}.json").write_text(
        json.dumps({"status": "pending", "fingerprint": "SHA256:expected"}), encoding="utf-8"
    )

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/confirm", {})

    assert response.status_code == 303
    assert queued_action(tmp_path) == {
        "id": draft_id,
        "action": "confirm",
        "host": "server.example",
        "ssh_user": "observer",
        "port": 22,
        "expected_fingerprint": "SHA256:expected",
    }
    with db_session() as db:
        audit = db.query(WebAuditLog).filter_by(action="server-draft-confirm").one()
        assert audit.target_client == draft_id
        assert "server.example" not in audit.message


def test_check_cannot_overwrite_queued_confirm_before_pin_completion(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    (results / f"{draft_id}.json").write_text(
        json.dumps({"status": "pending", "fingerprint": "SHA256:expected"}), encoding="utf-8"
    )
    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {}).status_code == 303
    assert not list((tmp_path / "queue").glob("*.json"))

    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/confirm", {}).status_code == 303
    queued_confirm = queued_action(tmp_path)

    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {}).status_code == 303
    assert queued_action(tmp_path) == queued_confirm
    assert queued_confirm["action"] == "confirm"
    assert f'/network/server-drafts/{draft_id}/check' not in client.get("/network/server-drafts").text


def test_completed_pin_allows_one_check_that_confirm_cannot_overwrite(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    result_path = results / f"{draft_id}.json"
    result_path.write_text(
        json.dumps({"status": "pending", "fingerprint": "SHA256:expected"}), encoding="utf-8"
    )
    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/confirm", {}).status_code == 303

    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    result_path.write_text(
        json.dumps(
            {
                "status": "ok",
                "fingerprint": "SHA256:expected",
                "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        ),
        encoding="utf-8",
    )
    assert f'/network/server-drafts/{draft_id}/check' in client.get("/network/server-drafts").text

    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {}).status_code == 303
    queued_check = queued_action(tmp_path)
    assert queued_check["action"] == "check"

    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {}).status_code == 303
    assert queued_action(tmp_path) == queued_check
    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/confirm", {}).status_code == 303
    assert queued_action(tmp_path) == queued_check
    assert f'/network/server-drafts/{draft_id}/check' not in client.get("/network/server-drafts").text


def test_delete_queues_cleanup_and_removes_public_record(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    result_path = results / f"{draft_id}.json"
    result_path.write_text(json.dumps({"status": "ok"}), encoding="utf-8")

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/delete", {})

    assert response.status_code == 303
    assert queued_action(tmp_path)["action"] == "cleanup"
    assert not result_path.exists()
    with db_session() as db:
        assert db.get(ServerDraft, draft_id) is None
