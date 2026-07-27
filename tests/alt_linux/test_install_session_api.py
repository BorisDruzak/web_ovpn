from __future__ import annotations

import http.client
import json
import sys
import threading
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
API_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "api"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
for path in (CONTROL_ROOT, API_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from alt_deploy.config import Settings
from install_session_api import create_install_session_server


def _request(
    server: object,
    method: str,
    path: str,
    *,
    payload: object | None = None,
    authorization: str | None = None,
) -> tuple[int, dict[str, object]]:
    host, port = server.server_address
    connection = http.client.HTTPConnection(host, port, timeout=3)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    if authorization:
        headers["Authorization"] = authorization
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = json.loads(response.read().decode("utf-8"))
    connection.close()
    return response.status, result


def test_api_creates_session_and_requires_its_bearer_credential(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    settings = Settings.from_env()
    server = create_install_session_server(settings, listen_address="127.0.0.1", listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
        status, created = _request(server, "POST", "/v1/install-sessions", payload=payload)
        assert status == 201
        assert created["state"] == "awaiting_approval"
        session_id = str(created["session_id"])
        credential = str(created["credential"])
        forbidden_status, _ = _request(server, "GET", f"/v1/install-sessions/{session_id}/status")
        assert forbidden_status == 401
        ok_status, current = _request(server, "GET", f"/v1/install-sessions/{session_id}/status", authorization=f"Bearer {credential}")
        assert ok_status == 200
        assert current["state"] == "awaiting_approval"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
