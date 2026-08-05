from __future__ import annotations

import hashlib
import importlib
from uuid import UUID

from fastapi.testclient import TestClient


DEVICE_ID = UUID("11111111-1111-1111-1111-111111111111")
COLLECTION_ID = UUID("22222222-2222-2222-2222-222222222222")


class FakeAdapter:
    def list_devices(self):
        return [{"id": str(DEVICE_ID), "display_name": "workstation-1", "device_identifier": "agent-1", "retired_at": None}]

    def get_device(self, device_id):
        assert device_id == DEVICE_ID
        return {
            "device": {"id": str(DEVICE_ID), "display_name": "workstation-1", "device_identifier": "agent-1", "retired_at": None},
            "profiles": [],
            "snapshots": [],
        }

    def request_collection(self, device_id, profile, idempotency_key):
        assert device_id == DEVICE_ID
        assert profile == "baseline_v1"
        assert idempotency_key == "request-1"
        return {
            "id": str(COLLECTION_ID), "device_id": str(DEVICE_ID), "profile": profile,
            "status": "queued", "requested_at": "2026-07-29T00:00:00Z",
            "result_received_at": None, "completed_at": None, "failure_code": None,
        }

    def get_collection(self, collection_id):
        assert collection_id == COLLECTION_ID
        return {"collection": self.request_collection(DEVICE_ID, "baseline_v1", "request-1"), "snapshot": None}

    def compare_context(self, device_id, from_snapshot_id, to_snapshot_id):
        assert device_id == DEVICE_ID
        return {"comparison": {"schema_version": "device_context_diff_v1", "profile": "baseline_v1", "before_snapshot_id": str(from_snapshot_id), "after_snapshot_id": str(to_snapshot_id), "changes": []}}


def make_endpoint_client(tmp_path, monkeypatch):
    token = "api-token"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(token.encode("utf-8")).hexdigest())
    import app.config
    import app.db
    import app.main

    app.config.reset_settings_cache()
    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    return TestClient(app.main.app), {"Authorization": f"Bearer {token}"}


def csrf_header(client: TestClient) -> dict[str, str]:
    page = client.get("/login")
    token = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    return {"X-CSRF-Token": token}


def test_endpoint_routes_require_api_authentication(tmp_path, monkeypatch):
    client, _ = make_endpoint_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/endpoints")

    assert response.status_code == 401


def test_request_collection_requires_csrf_and_forwards_idempotency(tmp_path, monkeypatch):
    client, auth_headers = make_endpoint_client(tmp_path, monkeypatch)
    import app.api

    monkeypatch.setattr(app.api, "get_endpoint_context_adapter", lambda: FakeAdapter())

    missing_csrf = client.post(
        f"/api/v1/endpoints/{DEVICE_ID}/collections",
        json={"profile": "baseline_v1"},
        headers=auth_headers | {"Idempotency-Key": "request-1"},
    )
    response = client.post(
        f"/api/v1/endpoints/{DEVICE_ID}/collections",
        json={"profile": "baseline_v1"},
        headers=auth_headers | csrf_header(client) | {"Idempotency-Key": "request-1"},
    )

    assert missing_csrf.status_code == 400
    assert response.status_code == 202
    assert response.json()["data"]["id"] == str(COLLECTION_ID)


def test_endpoint_platform_outage_returns_safe_degraded_response(tmp_path, monkeypatch):
    client, auth_headers = make_endpoint_client(tmp_path, monkeypatch)
    import app.api
    from app.endpoint_platform_client import EndpointPlatformServiceUnavailable

    def unavailable():
        raise EndpointPlatformServiceUnavailable()

    monkeypatch.setattr(app.api, "get_endpoint_context_adapter", unavailable)

    response = client.get("/api/v1/endpoints", headers=auth_headers)

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "code": "endpoint_platform_unavailable"}


def test_endpoint_routes_reject_diagnostic_collection_without_calling_adapter(tmp_path, monkeypatch):
    client, auth_headers = make_endpoint_client(tmp_path, monkeypatch)
    import app.api

    monkeypatch.setattr(app.api, "get_endpoint_context_adapter", lambda: (_ for _ in ()).throw(AssertionError("not called")))
    response = client.post(
        f"/api/v1/endpoints/{DEVICE_ID}/collections",
        json={"profile": "diagnostic_v1"},
        headers=auth_headers | csrf_header(client) | {"Idempotency-Key": "request-1"},
    )

    assert response.status_code == 422
