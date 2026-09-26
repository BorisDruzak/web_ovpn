"""Permission gates must reject direct requests before domain/CLI work."""
import json

import pytest
from tests.test_inventory_web import _client


def login_operator(client, *, permissions=(), network_admin=False):
    from app.auth import hash_password
    from app.db import get_sessionmaker
    from app.models import WebUser
    with get_sessionmaker()() as db:
        user = WebUser(username="operator", password_hash=hash_password("synthetic-operator"),
            is_admin=False, is_active=True, is_network_admin=network_admin,
            permissions_json=json.dumps(list(permissions)))
        db.add(user)
        db.commit()
    client.post("/logout", data={"csrf_token": client.get("/inventory").text.split('name="csrf_token" value="')[1].split('"')[0]})
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    client.post("/login", data={"username":"operator", "password":"synthetic-operator", "csrf_token":csrf})
    return csrf


@pytest.mark.parametrize("permissions,path", [
    ([], "/inventory/locations"),
    (["inventory:write"], "/clients/synthetic/disable"),
    (["inventory:write"], "/clients/synthetic/download-link"),
    (["vpn:manage"], "/inventory/locations"),
])
def test_capability_denied_before_cli_or_inventory_write(tmp_path, monkeypatch, permissions, path):
    client, _ = _client(tmp_path, monkeypatch)
    csrf = login_operator(client, permissions=permissions)
    def forbidden(*args, **kwargs):
        pytest.fail("permission denied must precede CLI/domain changes")
    monkeypatch.setattr("app.main.run_vpnctl", forbidden)
    monkeypatch.setattr("app.inventory.web.service.create_location", forbidden)
    response = client.post(path, data={"csrf_token":csrf,"name":"Synthetic","confirm_client":"synthetic"}, follow_redirects=False)
    assert response.status_code == 403


def test_inventory_editor_can_save_and_observer_can_view(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    csrf = login_operator(client, permissions=["inventory:write"])
    assert client.get("/inventory").status_code == 200
    assert client.post("/inventory/locations", data={"csrf_token":csrf,"name":"Synthetic"}, follow_redirects=False).status_code == 303


def test_legacy_token_does_not_grant_delete(tmp_path, monkeypatch):
    from tests.test_inventory_api import _client as api_client
    client, headers = api_client(tmp_path, monkeypatch)
    response = client.delete("/api/v1/inventory/assets/missing", headers=headers)
    assert response.status_code == 403


def test_bootstrap_does_not_reset_existing_password_or_roles(tmp_path, monkeypatch):
    _client(tmp_path, monkeypatch)
    from app.auth import ensure_admin_user, hash_password, verify_password
    from app.db import get_sessionmaker
    from app.models import WebUser
    from sqlalchemy import select
    with get_sessionmaker()() as db:
        user = db.scalar(select(WebUser).where(WebUser.username == "admin"))
        user.password_hash = hash_password("changed-password")
        user.is_network_admin = False
        db.commit()
        ensure_admin_user(db)
        db.commit()
        assert verify_password("changed-password", user.password_hash)
        assert user.is_network_admin is False


def test_production_rejects_development_secret(monkeypatch):
    from app.config import get_settings, reset_settings_cache
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("APP_SECRET_KEY", "dev-only-change-me")
    reset_settings_cache()
    with pytest.raises(ValueError, match="session"):
        get_settings()
    reset_settings_cache()


def test_production_cookie_is_secure_even_without_forwarded_header(tmp_path, monkeypatch):
    from app.config import reset_settings_cache
    import importlib
    import app.main
    from fastapi.testclient import TestClient
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'production.sqlite').as_posix()}")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("APP_SECRET_KEY", "synthetic-production-secret-key-32chars")
    from app.db import reset_engine_cache, init_db
    reset_engine_cache()
    importlib.reload(app.main)
    init_db()
    client = TestClient(app.main.app, base_url="https://testserver")
    response = client.get("/login")
    cookie = response.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    reset_settings_cache()


def test_permissions_migration_preserves_old_account_and_is_repeatable(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / "old-users.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE web_users (id INTEGER PRIMARY KEY, username VARCHAR(120) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, is_active BOOLEAN NOT NULL, is_admin BOOLEAN NOT NULL, is_network_admin BOOLEAN NOT NULL, created_at DATETIME NOT NULL, last_login_at DATETIME)")
        connection.execute("INSERT INTO web_users VALUES (1,'observer','original-hash',1,0,0,'2026-01-01',NULL)")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{path.as_posix()}")
    monkeypatch.setenv("ADMIN_PASSWORD", "")
    from app.db import init_db, reset_engine_cache
    reset_engine_cache()
    init_db()
    init_db()
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT password_hash,is_admin,is_network_admin,permissions_json FROM web_users WHERE id=1").fetchone()
        assert row == ("original-hash", 0, 0, "[]")


def test_administrator_can_assign_only_known_permissions(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    from app.auth import hash_password
    from app.db import get_sessionmaker
    from app.models import WebUser
    with get_sessionmaker()() as db:
        operator = WebUser(username="editor", password_hash=hash_password("synthetic"), is_active=True, is_admin=False)
        db.add(operator)
        db.commit()
        operator_id = operator.id
    page = client.get("/admin/users")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    path = f"/admin/users/{operator_id}/permissions"
    assert client.post(path, data={"csrf_token":csrf, "permission":"inventory:write"}, follow_redirects=False).status_code == 303
    assert client.post(path, data={"csrf_token":csrf, "permission":"invented:privilege"}, follow_redirects=False).status_code == 400
    with get_sessionmaker()() as db:
        assert json.loads(db.get(WebUser, operator_id).permissions_json) == ["inventory:write"]
    csrf = login_operator(client, permissions=["inventory:write"])
    assert client.get("/admin/users").status_code == 403
    assert client.post(path, data={"csrf_token":csrf, "permission":"inventory:delete"}).status_code == 403


def test_download_requires_capability_and_owner_without_consuming_denied_token(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    monkeypatch.setenv("OUT_DIR", str(tmp_path))
    client, _ = _client(tmp_path, monkeypatch)
    from app.download_tokens import create_download_token, consume_download_token
    file = tmp_path / "synthetic.ovpn"
    file.write_text("synthetic configuration", encoding="utf-8")
    token, _ = create_download_token(client_name="synthetic", file_path=file, file_type="ovpn",
        created_by="admin", expires_at=datetime.now(timezone.utc) + timedelta(minutes=1))
    login_operator(client)
    assert client.get(f"/download/{token}").status_code == 403
    from app.db import get_sessionmaker
    from app.models import WebUser
    from sqlalchemy import select
    with get_sessionmaker()() as db:
        db.scalar(select(WebUser).where(WebUser.username == "operator")).permissions_json = '["vpn:download"]'
        db.commit()
    assert client.get(f"/download/{token}").status_code == 404
    assert consume_download_token(token, owner="admin") is not None
