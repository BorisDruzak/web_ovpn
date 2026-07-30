from __future__ import annotations

import http.client
import hashlib
import json
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "control"
API_ROOT = REPO_ROOT / "deploy" / "alt-linux" / "api"
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "install"
for path in (CONTROL_ROOT, API_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from alt_deploy.config import Settings
from alt_deploy.install_session_repository import InstallSessionRepository
from install_session_api import create_install_session_server
import install_session_server as server_module


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


def _create_payload(
    inventory: dict[str, object],
    *,
    nonce: str = "A" * 43,
) -> dict[str, object]:
    return {"create_nonce": nonce, "inventory": inventory}


def _settings_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv(
        "ALT_DEPLOY_INSTALL_PROFILE_ROOT",
        str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"),
    )
    return Settings.from_env()


@contextmanager
def running(server: object):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_health_is_constant_and_does_not_create_session_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings_in(tmp_path, monkeypatch)
    server = create_install_session_server(
        settings, listen_address="127.0.0.1", listen_port=0
    )

    with running(server):
        status, body = _request(server, "GET", "/health")

    assert (status, body) == (
        200,
        {"schema_version": 1, "service": "alt-install-session", "status": "ok"},
    )
    assert not settings.install_sessions_dir.exists()


def test_v1_listener_never_routes_or_redirects_v2_execution_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings_in(tmp_path, monkeypatch)
    server = create_install_session_server(
        settings, listen_address="127.0.0.1", listen_port=0
    )
    path = (
        "/v2/install-sessions/"
        "install-20260729T120000Z-a1b2c3d4/execution/manifest"
    )

    with running(server):
        status, body = _request(server, "GET", path)

    assert status == 404
    assert body == {"status": "error", "error": {"code": "not_found"}}
    assert not settings.install_sessions_dir.exists()


def test_production_entry_point_uses_explicit_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: dict[str, object] = {}

    class FakeServer:
        def serve_forever(self) -> None:
            return

        def server_close(self) -> None:
            return

    monkeypatch.setattr(
        server_module,
        "create_install_session_server",
        lambda settings, **kwargs: called.update(kwargs) or FakeServer(),
    )

    assert server_module.main(
        ["--listen-address", "192.168.100.17", "--listen-port", "18090"]
    ) == 0
    assert called == {"listen_address": "192.168.100.17", "listen_port": 18090}


def test_api_creates_session_and_requires_its_bearer_credential(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    settings = Settings.from_env()
    server = create_install_session_server(settings, listen_address="127.0.0.1", listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
        status, created = _request(
            server,
            "POST",
            "/v1/install-sessions",
            payload=_create_payload(payload),
        )
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


def test_api_rejects_conflicting_heartbeat_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    server = create_install_session_server(Settings.from_env(), listen_address="127.0.0.1", listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        inventory = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
        _, created = _request(
            server,
            "POST",
            "/v1/install-sessions",
            payload=_create_payload(inventory),
        )
        session_id, credential = str(created["session_id"]), str(created["credential"])
        heartbeat = {"schema_version": 1, "boot_id": "boot-100", "agent_version": "1.0.0", "sequence": 1, "reported_stage": "waiting_for_approval", "sent_at": "2026-07-27T12:00:00+00:00"}
        status, _ = _request(server, "POST", f"/v1/install-sessions/{session_id}/heartbeat", payload=heartbeat, authorization=f"Bearer {credential}")
        assert status == 200
        replay_status, _ = _request(server, "POST", f"/v1/install-sessions/{session_id}/heartbeat", payload=heartbeat, authorization=f"Bearer {credential}")
        assert replay_status == 200
        conflict_status, conflict = _request(server, "POST", f"/v1/install-sessions/{session_id}/heartbeat", payload=heartbeat | {"reported_stage": "agent_started"}, authorization=f"Bearer {credential}")
        assert conflict_status == 409
        assert conflict["error"]["code"] == "heartbeat_conflict"
        invalid_status, invalid = _request(server, "POST", f"/v1/install-sessions/{session_id}/heartbeat", payload=heartbeat | {"reported_stage": "plan_available"}, authorization=f"Bearer {credential}")
        assert invalid_status == 400
        assert invalid["error"]["code"] == "heartbeat_invalid"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_api_replays_create_nonce_only_for_the_same_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    server = create_install_session_server(Settings.from_env(), listen_address="127.0.0.1", listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        inventory = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
        payload = _create_payload(inventory, nonce=("B" * 42) + "A")
        first_status, first = _request(server, "POST", "/v1/install-sessions", payload=payload)
        replay_status, replay = _request(server, "POST", "/v1/install-sessions", payload=payload)

        assert first_status == replay_status == 201
        assert replay == first

        different_inventory = dict(inventory)
        different_inventory["agent"] = dict(inventory["agent"]) | {"boot_id": "another-boot"}
        mismatch_status, mismatch = _request(
            server,
            "POST",
            "/v1/install-sessions",
            payload=_create_payload(different_inventory, nonce=("B" * 42) + "A"),
        )
        assert mismatch_status == 409
        assert mismatch["error"]["code"] == "install_session_create_nonce_mismatch"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_api_marks_expired_awaiting_approval_session_inactive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    settings = Settings.from_env()
    server = create_install_session_server(settings, listen_address="127.0.0.1", listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        inventory = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
        _, created = _request(server, "POST", "/v1/install-sessions", payload=_create_payload(inventory, nonce=("C" * 42) + "A"))
        session_id, credential = str(created["session_id"]), str(created["credential"])
        status_path = settings.install_sessions_dir / session_id / "status.json"
        stored = json.loads(status_path.read_text(encoding="utf-8"))
        stored["expires_at"] = "2020-01-01T00:00:00+00:00"
        status_path.write_text(json.dumps(stored), encoding="utf-8")

        status, current = _request(server, "GET", f"/v1/install-sessions/{session_id}/status", authorization=f"Bearer {credential}")
        assert status == 200
        assert current["state"] == "expired"
        heartbeat_status, heartbeat = _request(
            server,
            "POST",
            f"/v1/install-sessions/{session_id}/heartbeat",
            payload={"schema_version": 1, "boot_id": "boot-100", "agent_version": "1.0.0", "sequence": 1, "reported_stage": "waiting_for_approval", "sent_at": "2026-07-27T12:00:00+00:00"},
            authorization=f"Bearer {credential}",
        )
        assert heartbeat_status == 409
        assert heartbeat["error"]["code"] == "session_expired"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_api_accepts_preflight_ready_and_rejects_stages_outside_v1_vocabulary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_PROFILE_ROOT", str(REPO_ROOT / "deploy" / "alt-linux" / "autoinstall" / "profiles"))
    server = create_install_session_server(Settings.from_env(), listen_address="127.0.0.1", listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        inventory = json.loads((FIXTURE_ROOT / "inventory-disk-100g.json").read_text(encoding="utf-8"))
        _, created = _request(server, "POST", "/v1/install-sessions", payload=_create_payload(inventory, nonce=("D" * 42) + "A"))
        session_id, credential = str(created["session_id"]), str(created["credential"])
        heartbeat = {"schema_version": 1, "boot_id": "boot-100", "agent_version": "1.0.0", "sequence": 1, "reported_stage": "preflight_ready", "sent_at": "2026-07-27T12:00:00+00:00"}
        accepted_status, _ = _request(server, "POST", f"/v1/install-sessions/{session_id}/heartbeat", payload=heartbeat, authorization=f"Bearer {credential}")
        rejected_status, rejected = _request(server, "POST", f"/v1/install-sessions/{session_id}/heartbeat", payload=heartbeat | {"sequence": 2, "reported_stage": "plan_available"}, authorization=f"Bearer {credential}")

        assert accepted_status == 200
        assert rejected_status == 400
        assert rejected["error"]["code"] == "heartbeat_invalid"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_api_marks_expired_published_plan_inactive_under_posix_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS", str(tmp_path / "sessions"))
    monkeypatch.setenv("ALT_DEPLOY_INSTALL_SESSIONS_LOCK", str(tmp_path / "sessions.lock"))
    settings = Settings.from_env()
    session_id = "install-20260727T120000Z-a1b2c3d4"
    credential = "E" * 43
    repository = InstallSessionRepository(settings)
    status = {
        "schema_version": 1, "session_id": session_id,
        "state": "plan_published", "stage": "published",
        "stage_history": [
            {"stage": "session_created", "entered_at": "2026-07-27T12:00:00+00:00"},
            {"stage": "inventory_validated", "entered_at": "2026-07-27T12:00:00+00:00"},
            {"stage": "awaiting_approval", "entered_at": "2026-07-27T12:00:00+00:00"},
            {"stage": "plan_built", "entered_at": "2026-07-27T12:00:00+00:00"},
            {"stage": "plan_signed", "entered_at": "2026-07-27T12:00:00+00:00"},
            {"stage": "published", "entered_at": "2026-07-27T12:00:00+00:00"},
        ],
        "inventory_sha256": "a" * 64, "machine_uuid": "machine-1",
        "agent_boot_id": "boot-1", "source_ip": "192.168.100.10",
        "created_at": "2026-07-27T12:00:00+00:00",
        "updated_at": "2026-07-27T12:00:00+00:00",
        "last_seen_at": "2026-07-27T12:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00", "expired_at": None,
        "plan_revision": 1, "cancelled_at": None, "cancel_reason": None,
    }
    repository.create(
        session_id=session_id,
        inventory_bytes=b'{"schema_version":1}\n',
        credential_sha256=hashlib.sha256(credential.encode("ascii")).hexdigest(),
        create_nonce_sha256="b" * 64,
        status=status,
    )
    plan_bytes = b'{"expires_at":"2020-01-01T00:00:00+00:00"}'
    repository.publish_revision(
        session_id,
        plan_bytes=plan_bytes,
        plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        signature={"schema_version": 1},
    )
    server = create_install_session_server(settings, listen_address="127.0.0.1", listen_port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    @contextmanager
    def exclusive_lock(_path: Path):
        yield

    locks = ModuleType("alt_deploy.locks")
    locks.exclusive_lock = exclusive_lock
    monkeypatch.setitem(sys.modules, "alt_deploy.locks", locks)
    monkeypatch.setattr("install_session_api.os", SimpleNamespace(name="posix"))
    try:
        response_status, _ = _request(
            server,
            "GET",
            f"/v1/install-sessions/{session_id}/plan",
            authorization=f"Bearer {credential}",
        )

        assert response_status == 410
        assert repository.load_status(session_id)["state"] == "expired"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
