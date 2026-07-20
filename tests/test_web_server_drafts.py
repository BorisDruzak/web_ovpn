import hashlib
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import models
from app.models import ServerDraft, ServerDraftCleanupOutbox, WebAuditLog
from app.server_draft_worker import process_queue


ServerDraftCheckOutbox = getattr(models, "ServerDraftCheckOutbox", None)


VALID_FINGERPRINT = "SHA256:" + "Q" * 43


def scanned_result():
    return {"status": "pending", "algorithm": "ssh-ed25519", "fingerprint": VALID_FINGERPRINT}


def pinned_result(generation):
    return {
        "status": "ok",
        "fingerprint": VALID_FINGERPRINT,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "pin_generation": generation,
    }


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


def test_draft_key_copy_uses_safe_dom_only():
    template = Path("app/templates/server_drafts.html").read_text()
    script = Path("app/static/app.js").read_text()
    assert "data-copy-observer-key" in template
    assert "navigator.clipboard.writeText" in script
    assert "innerHTML" not in script
    assert "server-observer.key" not in template


def test_confirm_uses_stored_fingerprint_and_audits_uuid(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    (results / f"{draft_id}.json").write_text(
        json.dumps(scanned_result()), encoding="utf-8"
    )

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/confirm", {})

    assert response.status_code == 303
    assert queued_action(tmp_path) == {
        "id": draft_id,
        "action": "confirm",
        "host": "server.example",
        "ssh_user": "observer",
        "port": 22,
        "expected_fingerprint": VALID_FINGERPRINT,
        "pin_generation": queued_action(tmp_path)["pin_generation"],
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
        json.dumps(scanned_result()), encoding="utf-8"
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
        json.dumps(scanned_result()), encoding="utf-8"
    )
    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/confirm", {}).status_code == 303
    generation = queued_action(tmp_path)["pin_generation"]

    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    result_path.write_text(
        json.dumps(pinned_result(generation)),
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


def test_check_is_authorized_and_consumed_by_current_pin_generation(tmp_path, monkeypatch):
    assert ServerDraftCheckOutbox is not None
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    generation = str(uuid4())
    (results / f"{draft_id}.json").write_text(
        json.dumps(pinned_result(generation)), encoding="utf-8"
    )
    with db_session() as db:
        db.add(
            WebAuditLog(
                actor="admin",
                action="server-draft-confirm",
                target_client=draft_id,
                result="ok",
                message=f"pin-generation:{uuid4()}",
            )
        )
        db.commit()

    assert f'/network/server-drafts/{draft_id}/check' not in client.get("/network/server-drafts").text
    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {}).status_code == 303
    assert not list((tmp_path / "queue").glob("*.json"))

    with db_session() as db:
        db.add(
            WebAuditLog(
                actor="admin",
                action="server-draft-confirm",
                target_client=draft_id,
                result="ok",
                message=f"pin-generation:{generation}",
            )
        )
        db.commit()

    assert f'/network/server-drafts/{draft_id}/check' in client.get("/network/server-drafts").text
    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {}).status_code == 303
    first_check = queued_action(tmp_path)
    assert first_check["action"] == "check"
    assert first_check["pin_generation"] == generation

    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {}).status_code == 303
    assert queued_action(tmp_path) == first_check
    with db_session() as db:
        consumed = db.query(WebAuditLog).filter_by(
            action="server-draft-check", result="ok", target_client=draft_id,
            message=f"pin-generation:{generation}",
        ).count()
        assert consumed == 1
        outbox = db.query(ServerDraftCheckOutbox).one()
        assert outbox.draft_id == draft_id
        assert outbox.pin_generation == generation
        assert outbox.status == "published"


def test_check_audit_and_consumption_commit_before_queue_publication(tmp_path, monkeypatch):
    assert ServerDraftCheckOutbox is not None
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    generation = str(uuid4())
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    (results / f"{draft_id}.json").write_text(
        json.dumps(pinned_result(generation)), encoding="utf-8"
    )
    with db_session() as db:
        db.add(
            WebAuditLog(
                actor="admin",
                action="server-draft-confirm",
                target_client=draft_id,
                result="ok",
                message=f"pin-generation:{generation}",
            )
        )
        db.commit()
    original_commit = Session.commit

    def fail_consumption_commit(session):
        if any(isinstance(item, ServerDraftCheckOutbox) for item in session.new):
            raise SQLAlchemyError("forced check consumption failure")
        return original_commit(session)

    monkeypatch.setattr(Session, "commit", fail_consumption_commit)

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {})

    assert response.status_code == 303
    assert not list((tmp_path / "queue").glob("*.json"))
    with db_session() as db:
        assert db.query(ServerDraftCheckOutbox).count() == 0
        assert db.query(WebAuditLog).filter_by(action="server-draft-check").count() == 0


def test_check_queue_failure_leaves_durable_retryable_consumption(tmp_path, monkeypatch):
    assert ServerDraftCheckOutbox is not None
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    generation = str(uuid4())
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    (results / f"{draft_id}.json").write_text(
        json.dumps(pinned_result(generation)), encoding="utf-8"
    )
    with db_session() as db:
        db.add(
            WebAuditLog(
                actor="admin",
                action="server-draft-confirm",
                target_client=draft_id,
                result="ok",
                message=f"pin-generation:{generation}",
            )
        )
        db.commit()

    import app.main

    original_publish = app.main.create_draft_request

    def fail_check_publish(queue_dir, request):
        if request.action == "check":
            raise OSError("forced queue failure")
        return original_publish(queue_dir, request)

    monkeypatch.setattr(app.main, "create_draft_request", fail_check_publish)

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/check", {})

    assert response.status_code == 303
    assert not list((tmp_path / "queue").glob("*.json"))
    page = client.get("/network/server-drafts")
    assert "SSH check publication pending" in page.text
    with db_session() as db:
        outbox = db.query(ServerDraftCheckOutbox).one()
        assert outbox.status == "pending"
        assert outbox.attempts == 1
        assert outbox.last_error == "queue unavailable"
        assert db.query(WebAuditLog).filter_by(
            action="server-draft-check", result="ok", target_client=draft_id
        ).count() == 1

    monkeypatch.setattr(app.main, "create_draft_request", original_publish)
    response = post_with_csrf(client, "/network/server-drafts/check-retry", {})

    assert response.status_code == 303
    assert queued_action(tmp_path)["action"] == "check"
    with db_session() as db:
        outbox = db.query(ServerDraftCheckOutbox).one()
        assert outbox.status == "published"
        assert outbox.attempts == 2


def test_direct_scan_post_cannot_replace_a_confirmable_fingerprint(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    (results / f"{draft_id}.json").write_text(json.dumps(scanned_result()), encoding="utf-8")

    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/scan", {}).status_code == 303

    assert not list((tmp_path / "queue").glob("*.json"))
    assert json.loads((results / f"{draft_id}.json").read_text(encoding="utf-8")) == scanned_result()


def test_delete_queues_cleanup_before_worker_removes_public_record(tmp_path, monkeypatch):
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
    assert result_path.exists()
    with db_session() as db:
        assert db.get(ServerDraft, draft_id) is None


def test_delete_rolls_back_before_cleanup_when_database_flush_fails(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    original_flush = Session.flush

    def fail_draft_delete(session, *args, **kwargs):
        if any(isinstance(item, ServerDraft) and item.id == draft_id for item in session.deleted):
            raise SQLAlchemyError("forced delete failure")
        return original_flush(session, *args, **kwargs)

    monkeypatch.setattr(Session, "flush", fail_draft_delete)

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/delete", {})

    assert response.status_code == 303
    assert not list((tmp_path / "queue").glob("*.cleanup.json"))
    with db_session() as db:
        assert db.get(ServerDraft, draft_id) is not None


def test_delete_commit_failure_never_exposes_cleanup_or_discards_draft_material(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    result_path = tmp_path / "results" / f"{draft_id}.json"
    result_path.parent.mkdir(exist_ok=True)
    result_path.write_text(json.dumps({"status": "ok"}), encoding="utf-8")
    private_path = tmp_path / "private" / f"{draft_id}.known_hosts"
    private_path.parent.mkdir(exist_ok=True)
    private_path.write_text("private", encoding="utf-8")
    original_commit = Session.commit

    def fail_delete_commit(session):
        if any(isinstance(item, ServerDraft) and item.id == draft_id for item in session.deleted):
            raise SQLAlchemyError("forced delete commit failure")
        return original_commit(session)

    monkeypatch.setattr(Session, "commit", fail_delete_commit)

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/delete", {})

    assert response.status_code == 303
    assert not list((tmp_path / "queue").glob("*.cleanup.json"))
    assert result_path.exists()
    assert private_path.exists()
    with db_session() as db:
        assert db.get(ServerDraft, draft_id) is not None
        assert db.query(ServerDraftCleanupOutbox).count() == 0


def test_cleanup_publication_failure_is_durable_visible_and_retryable(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()

    import app.main

    original_publish = app.main.create_draft_request

    def fail_cleanup_publish(queue_dir, request):
        if request.action == "cleanup":
            raise OSError("forced queue failure")
        return original_publish(queue_dir, request)

    monkeypatch.setattr(app.main, "create_draft_request", fail_cleanup_publish)

    response = post_with_csrf(client, f"/network/server-drafts/{draft_id}/delete", {})

    assert response.status_code == 303
    assert not list((tmp_path / "queue").glob("*.cleanup.json"))
    page = client.get("/network/server-drafts")
    assert draft_id in page.text
    assert "retry required" in page.text
    with db_session() as db:
        outbox = db.query(ServerDraftCleanupOutbox).one()
        assert db.get(ServerDraft, draft_id) is None
        assert outbox.draft_id == draft_id
        assert outbox.status == "pending"
        assert outbox.attempts == 1
        assert outbox.last_error == "queue unavailable"

    monkeypatch.setattr(app.main, "create_draft_request", original_publish)
    response = post_with_csrf(client, "/network/server-drafts/cleanup-retry", {})

    assert response.status_code == 303
    assert queued_action(tmp_path) == {"id": draft_id, "action": "cleanup"}
    with db_session() as db:
        outbox = db.query(ServerDraftCleanupOutbox).one()
        assert outbox.status == "published"
        assert outbox.attempts == 2
        assert outbox.last_error == ""


def test_committed_cleanup_intent_drives_normal_worker_cleanup(tmp_path, monkeypatch):
    client = make_logged_in_client(tmp_path, monkeypatch)
    draft_id = create_draft(client, tmp_path)
    (tmp_path / "queue" / f"{draft_id}.json").unlink()
    result_path = tmp_path / "results" / f"{draft_id}.json"
    result_path.parent.mkdir(exist_ok=True)
    result_path.write_text(json.dumps({"status": "ok"}), encoding="utf-8")
    private_path = tmp_path / "private" / f"{draft_id}.candidate"
    private_path.parent.mkdir(exist_ok=True)
    private_path.write_text("private", encoding="utf-8")

    assert post_with_csrf(client, f"/network/server-drafts/{draft_id}/delete", {}).status_code == 303
    assert queued_action(tmp_path) == {"id": draft_id, "action": "cleanup"}
    assert process_queue(tmp_path / "queue", tmp_path / "results", tmp_path / "private") == 1

    assert (tmp_path / "queue" / f"{draft_id}.deleted").is_file()
    assert not result_path.exists()
    assert not private_path.exists()
