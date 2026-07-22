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
