from __future__ import annotations

import hashlib
import importlib
import json
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    token = "network-control-token"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("NETWORK_CHANGE_TRUSTED_HTTPS", "1")
    monkeypatch.setenv("NETWORK_CHANGE_TRUST_PROXY", "1")
    monkeypatch.setenv(
        "NETWORK_CHANGE_TOKENS_JSON",
        json.dumps([
            {
                "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                "actor": "api:netops",
                "scopes": ["network:read", "network:plan", "network:apply", "network:rollback"],
            }
        ]),
    )
    import app.api
    import app.config
    import app.db
    import app.main

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    importlib.reload(app.api)
    importlib.reload(app.main)
    app.db.init_db()
    return TestClient(app.main.app), {
        "Authorization": f"Bearer {token}", "X-Forwarded-Proto": "https", "Idempotency-Key": "test-request-1",
    }


def test_network_change_create_authorizes_scope_and_relays_to_broker(tmp_path, monkeypatch) -> None:
    client, headers = _client(tmp_path, monkeypatch)
    import app.api

    calls: list[dict[str, object]] = []

    def fake_control(action, payload, *, actor, session_id, authorization_id):
        calls.append({
            "action": action, "payload": payload, "actor": actor,
            "session_id": session_id, "authorization_id": authorization_id,
        })
        return {"plan_key": "plan-1", "plan_digest": "sha256:" + "a" * 64, "status": "draft"}

    monkeypatch.setattr(app.api, "call_network_control", fake_control, raising=False)
    response = client.post(
        "/api/v1/network-changes/plans",
        headers=headers,
        json={"subject_type": "asset", "subject_key": "mac:aa:bb:cc:dd:ee:ff", "desired_state": "deny", "reason": "test"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["plan_key"] == "plan-1"
    assert calls == [{
        "action": "plan.create",
        "payload": {"plan": {"subject_type": "asset", "subject_key": "mac:aa:bb:cc:dd:ee:ff", "desired_state": "deny", "reason": "test"}},
        "actor": "api:netops", "session_id": calls[0]["session_id"], "authorization_id": calls[0]["authorization_id"],
    }]


def test_network_change_apply_requires_apply_scope(tmp_path, monkeypatch) -> None:
    client, headers = _client(tmp_path, monkeypatch)
    import app.api

    monkeypatch.setattr(app.api, "call_network_control", lambda *args, **kwargs: {"status": "applied"}, raising=False)
    response = client.post("/api/v1/network-changes/plans/plan-1/apply", headers=headers)

    assert response.status_code == 200


def test_network_change_rejects_mutations_without_an_idempotency_key(tmp_path, monkeypatch) -> None:
    client, headers = _client(tmp_path, monkeypatch)
    headers.pop("Idempotency-Key")
    import app.api

    monkeypatch.setattr(app.api, "call_network_control", lambda *args, **kwargs: {"plan_key": "plan-1"}, raising=False)
    response = client.post(
        "/api/v1/network-changes/plans", headers=headers,
        json={"subject_type": "asset", "subject_key": "mac:aa", "desired_state": "deny", "reason": "test"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Idempotency-Key is required"


def test_network_control_client_inspects_a_plan_before_signing_apply(monkeypatch) -> None:
    import app.netopsctl_client as client_module

    calls: list[dict[str, object]] = []

    def fake_request(socket_path, *, action, payload, authorization, signature):
        calls.append({"socket_path": socket_path, "action": action, "payload": payload, "authorization": authorization})
        if action == "plan.inspect":
            return {"status": "ok", "data": {"plan_key": "plan-1", "plan_digest": "sha256:" + "b" * 64}}
        return {"status": "ok", "data": {"status": "applied"}}

    monkeypatch.setattr(client_module, "broker_request", fake_request)
    monkeypatch.setattr(client_module, "_private_key", lambda: Ed25519PrivateKey.generate())
    monkeypatch.setattr(client_module, "get_settings", lambda: SimpleNamespace(network_control_socket_path="/run/test.sock"))

    result = client_module.run_network_control(
        "plan.apply", {"plan_key": "plan-1"}, actor="api:netops", session_id="request-1", authorization_id="authorization-1",
    )

    assert result == {"status": "applied"}
    assert [call["action"] for call in calls] == ["plan.inspect", "plan.apply"]
    assert calls[0]["authorization"]["scopes"] == ["network.plan.read"]
    assert calls[1]["authorization"]["plan_digest"] == "sha256:" + "b" * 64
