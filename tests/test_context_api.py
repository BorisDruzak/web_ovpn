import hashlib
import importlib
import json
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def make_fake_netctl(path: Path) -> Path:
    script = path.with_suffix(".py") if os.name == "nt" else path
    script.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_NETCTL_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\\n")
if args[1:3] == ["context-view", "search"]:
    print(json.dumps({"status": "ok", "results": [{"asset_key": "mac:aa:bb:cc:dd:ee:ff"}]}))
elif args[1:3] == ["context-view", "asset"]:
    print(json.dumps({"status": "ok", "context": {"asset": {"asset_key": args[-1]}}}))
elif args[1:3] == ["context-view", "topology"]:
    print(json.dumps({"status": "ok", "links": [{"link_key": "access|core", "state": "confirmed"}]}))
elif args[1:3] == ["context-view", "findings"]:
    print(json.dumps({"status": "ok", "findings": [{"finding_key": "runtime:one", "status": "open"}]}))
elif args[1:3] == ["path", "explain"]:
    print(json.dumps({"status": "ok", "explanation": {"verdict": "allowed"}}))
elif args[1:3] == ["users", "add"]:
    print(json.dumps({"status": "ok", "user": {"user_key": args[args.index("--user-key") + 1]}}))
elif args[1:3] == ["users", "bind-asset"]:
    print(json.dumps({"status": "ok", "binding": {"id": 42, "status": "confirmed"}}))
elif args[1:3] == ["users", "inspect"]:
    print(json.dumps({"status": "ok", "context": {"user": {"user_key": args[-1]}}}))
elif args[1:3] == ["users", "retire-binding"]:
    print(json.dumps({"status": "ok", "binding": {"id": int(args[args.index("--binding-id") + 1]), "status": "retired"}}))
elif args[1:3] == ["network-sessions", "open"]:
    print(json.dumps({"status": "ok", "session": {"session_key": args[args.index("--session-key") + 1]}}))
elif args[1:3] == ["network-sessions", "close"]:
    print(json.dumps({"status": "ok", "session": {"session_key": args[args.index("--session-key") + 1], "ended_at": args[args.index("--ended-at") + 1]}}))
else:
    print(json.dumps({"status": "ok"}))
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    if os.name != "nt":
        return script
    wrapper = path.with_suffix(".cmd")
    wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    return wrapper


def make_client(tmp_path: Path, monkeypatch) -> tuple[TestClient, dict[str, str], Path]:
    token = "api-token"
    log_path = tmp_path / "netctl.jsonl"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(token.encode("utf-8")).hexdigest())
    monkeypatch.setenv("NETCTL_PATH", str(make_fake_netctl(tmp_path / "netctl")))
    monkeypatch.setenv("NETCTL_USE_SUDO", "0")
    monkeypatch.setenv("FAKE_NETCTL_LOG", str(log_path))

    import app.config
    import app.db
    import app.main

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    return TestClient(app.main.app), {"Authorization": f"Bearer {token}"}, log_path


def test_context_search_api_delegates_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/context/search", params={"q": "workstation", "limit": 7}, headers=headers)

    assert response.status_code == 200
    assert response.json()["data"]["results"] == [{"asset_key": "mac:aa:bb:cc:dd:ee:ff"}]
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json",
        "context-view",
        "search",
        "--query",
        "workstation",
        "--limit",
        "7",
    ]


def test_context_asset_api_delegates_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/context/assets/mac:aa:bb:cc:dd:ee:ff", headers=headers)

    assert response.status_code == 200
    assert response.json()["data"]["context"]["asset"]["asset_key"] == "mac:aa:bb:cc:dd:ee:ff"
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json",
        "context-view",
        "asset",
        "--asset-key",
        "mac:aa:bb:cc:dd:ee:ff",
    ]


def test_context_topology_api_delegates_bounded_filters_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    response = client.get(
        "/api/v1/context/topology",
        params={"site": "central", "state": "confirmed", "depth": 4},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["data"]["links"] == [{"link_key": "access|core", "state": "confirmed"}]
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json",
        "context-view",
        "topology",
        "--site",
        "central",
        "--state",
        "confirmed",
        "--depth",
        "4",
    ]


def test_context_findings_api_delegates_status_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/context/findings", params={"status": "open"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["data"]["findings"] == [{"finding_key": "runtime:one", "status": "open"}]
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json",
        "context-view",
        "findings",
        "--status",
        "open",
    ]


def test_context_path_api_delegates_a_read_only_explanation_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    response = client.get(
        "/api/v1/context/path",
        params={"asset_key": "mac:aa:bb:cc:dd:ee:ff", "destination": "198.51.100.25", "protocol": "tcp", "port": 443},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["data"]["explanation"]["verdict"] == "allowed"
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json", "path", "explain", "--asset-key", "mac:aa:bb:cc:dd:ee:ff",
        "--destination", "198.51.100.25", "--protocol", "tcp", "--port", "443",
    ]


def test_context_user_creation_api_is_authenticated_and_delegates_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    denied = client.post("/api/v1/context/users", json={"user_key": "employee:api", "display_name": "API User"})
    response = client.post(
        "/api/v1/context/users",
        json={"user_key": "employee:api", "display_name": "API User", "department": "IT"},
        headers=headers,
    )

    assert denied.status_code == 401
    assert response.status_code == 200
    assert response.json()["data"]["user"] == {"user_key": "employee:api"}
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json", "users", "add", "--user-key", "employee:api", "--display-name", "API User", "--department", "IT"
    ]


def test_context_user_binding_inspection_and_retirement_api_delegate_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    binding = client.post(
        "/api/v1/context/users/employee:api/asset-bindings",
        json={"asset_key": "mac:AA:BB:CC:DD:EE:FF", "relation": "primary_user", "confidence": 100, "reason": "approved"},
        headers=headers,
    )
    inspect = client.get("/api/v1/context/users/employee:api", headers=headers)
    retired = client.request("DELETE", "/api/v1/context/user-asset-bindings/42", json={"reason": "reassigned"}, headers=headers)

    assert binding.json()["data"]["binding"]["id"] == 42
    assert inspect.json()["data"]["context"]["user"]["user_key"] == "employee:api"
    assert retired.json()["data"]["binding"]["status"] == "retired"
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json", "users", "retire-binding", "--binding-id", "42", "--reason", "reassigned"
    ]


def test_context_network_session_endpoints_are_authenticated_and_delegate_to_netctl(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/context/network-sessions",
        json={"user_key": "employee:api", "session_key": "radius:one", "source_type": "radius", "started_at": "2026-07-22T12:00:00Z", "evidence": {"ip": "192.0.2.10"}},
        headers=headers,
    )
    closed = client.post("/api/v1/context/network-sessions/radius:one/close", json={"ended_at": "2026-07-22T12:10:00Z"}, headers=headers)
    assert created.json()["data"]["session"]["session_key"] == "radius:one"
    assert closed.json()["data"]["session"]["ended_at"] == "2026-07-22T12:10:00Z"
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json", "network-sessions", "close", "--session-key", "radius:one", "--ended-at", "2026-07-22T12:10:00Z"
    ]


def test_context_user_sessions_api_returns_only_session_evidence(tmp_path, monkeypatch):
    client, headers, log_path = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/context/users/employee:api/sessions", headers=headers)

    assert response.status_code == 200
    assert response.json()["data"]["sessions"] == []
    assert json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1]) == [
        "--json", "users", "inspect", "--user-key", "employee:api",
    ]
