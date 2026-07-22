from __future__ import annotations

import hashlib
import json

import pytest
from fastapi import HTTPException
from starlette.requests import Request


def _request() -> Request:
    request = Request({
        "type": "http", "method": "POST", "scheme": "http", "path": "/api/v1/network/plans",
        "headers": [(b"x-forwarded-proto", b"https")], "client": ("127.0.0.1", 50000),
    })
    request.state.request_id = "test-request"
    return request


def _configure(monkeypatch, tmp_path, tokens: list[dict[str, object]], *, trusted_https: bool = True) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("NETWORK_CHANGE_TRUSTED_HTTPS", "1" if trusted_https else "0")
    monkeypatch.setenv("NETWORK_CHANGE_TRUST_PROXY", "1")
    monkeypatch.setenv("NETWORK_CHANGE_TOKENS_JSON", json.dumps(tokens))
    import app.config
    import app.db

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    app.db.init_db()


def _token_record(token: str, scopes: list[str]) -> dict[str, object]:
    return {"token_hash": hashlib.sha256(token.encode()).hexdigest(), "actor": "api:netops", "scopes": scopes}


def test_network_change_bearer_scopes_are_separate_and_denials_are_audited(tmp_path, monkeypatch) -> None:
    from app.auth import authorize_network_change
    from app.db import get_sessionmaker
    from app.models import WebAuditLog

    _configure(monkeypatch, tmp_path, [
        _token_record("read", ["network:read"]),
        _token_record("plan", ["network:plan"]),
        _token_record("apply", ["network:apply"]),
    ])
    db = get_sessionmaker()()
    try:
        with pytest.raises(HTTPException, match="scope"):
            authorize_network_change(_request(), "Bearer read", db, "network:plan")
        assert authorize_network_change(_request(), "Bearer plan", db, "network:plan") == "api:netops"
        with pytest.raises(HTTPException, match="scope"):
            authorize_network_change(_request(), "Bearer plan", db, "network:apply")
        with pytest.raises(HTTPException, match="scope"):
            authorize_network_change(_request(), "Bearer apply", db, "network:rollback")
        assert db.query(WebAuditLog).filter_by(result="denied").count() == 3
    finally:
        db.close()


def test_network_change_requires_trusted_https_and_network_admin_session_role(tmp_path, monkeypatch) -> None:
    from app.auth import authorize_network_change, authorize_network_change_session
    from app.db import get_sessionmaker
    from app.models import WebAuditLog, WebUser

    _configure(monkeypatch, tmp_path, [_token_record("plan", ["network:plan"])], trusted_https=False)
    db = get_sessionmaker()()
    try:
        with pytest.raises(HTTPException, match="trusted HTTPS"):
            authorize_network_change(_request(), "Bearer plan", db, "network:plan")
        user = WebUser(username="operator", password_hash="hash", is_active=True, is_admin=False, is_network_admin=False)
        db.add(user)
        db.commit()
        with pytest.raises(HTTPException, match="network admin"):
            authorize_network_change_session(_request(), user, db, "network:plan")
        assert db.query(WebAuditLog).filter_by(result="denied").count() == 2
    finally:
        db.close()
