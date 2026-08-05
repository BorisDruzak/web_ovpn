from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def make_client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    import app.config
    import app.db
    import app.main

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    return TestClient(app.main.app)


def login(client: TestClient) -> None:
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_endpoint_agent_status_is_session_protected_and_redacted(tmp_path, monkeypatch) -> None:
    client = make_client(tmp_path, monkeypatch)

    denied = client.get("/network/endpoint-agent-status", follow_redirects=False)
    login(client)
    allowed = client.get("/network/endpoint-agent-status")

    assert denied.status_code == 303
    assert allowed.status_code == 200
    assert allowed.json() == {"state": "updating", "last_success_at": None}
    assert "error" not in allowed.text
    assert "mac" not in allowed.text.lower()
