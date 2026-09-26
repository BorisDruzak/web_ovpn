from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy import select

from app.inventory.models import (
    InventoryAssetType,
    InventoryEndpointState,
    InventoryExternalBinding,
    InventoryExternalBindingStatus as Status,
    InventoryObservation,
)
from app.inventory.service import InventoryService
from tests.test_endpoint_context_api import make_endpoint_client, csrf_header


DEVICE = "11111111-1111-1111-1111-111111111111"
SECOND_DEVICE = "22222222-2222-2222-2222-222222222222"
MAC = "00:11:22:33:44:55"
ROOT = "/api/v1/inventory"


@pytest.fixture
def api(tmp_path, monkeypatch):
    client, auth = make_endpoint_client(tmp_path, monkeypatch)
    return client, auth | csrf_header(client)


def seed(*, candidate=False, stale=False, asset_type=InventoryAssetType.PC):
    from app.db import get_sessionmaker

    now = datetime.now(timezone.utc)
    observed = now - timedelta(days=2) if stale else now
    with get_sessionmaker()() as db:
        service = InventoryService()
        asset = service.create_asset(db, asset_type, assigned_person_name="Assigned Person")
        if asset_type != InventoryAssetType.PC:
            db.commit()
            return asset.id, None
        service.update_details(db, asset, {"ram_gb": 8})
        service.sync_identifiers(db, asset, [{"identifier_type": "mac", "value": MAC}])
        binding = InventoryExternalBinding(
            asset_id=asset.id, source="endpoint_platform", external_id=DEVICE,
            status=Status.CANDIDATE if candidate else Status.CONFIRMED,
            binding_method="mac_exact", confidence=50 if candidate else 100, created_by="test",
            last_verified_at=observed,
            evidence_json={"current": True, "observed_at": observed.isoformat(),
                           "material": {"matches": {"mac_exact": [MAC]}}},
        )
        db.add(binding)
        db.flush()
        if not candidate:
            db.add(InventoryEndpointState(
                binding_id=binding.id, asset_id=asset.id, endpoint_device_id=DEVICE,
                safe_context_json={"ram_gb": 16, "current_user": "os-user"},
                refreshed_at=observed, last_success_at=observed, last_checked_at=now,
            ))
        db.commit()
        return asset.id, binding.id


def no_upstream(monkeypatch):
    def forbidden():
        raise AssertionError("local API must not open the Endpoint adapter")
    monkeypatch.setattr("app.inventory.api.get_endpoint_context_adapter", forbidden, raising=False)


def revision_header(asset):
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    with get_sessionmaker()() as db:
        return {'X-Inventory-Revision':str(db.get(InventoryAsset, asset).manual_revision)}


def test_context_keeps_stale_endpoint_values_without_upstream(api, monkeypatch):
    client, headers = api
    asset, _ = seed(stale=True)
    no_upstream(monkeypatch)
    response = client.get(f"{ROOT}/assets/{asset}/context", headers=headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["effective"]["ram_gb"]["value"] == 16
    assert data["effective"]["ram_gb"]["source"] == "endpoint"
    assert data["manual"]["details"]["ram_gb"] == 8
    assert data["freshness"]["endpoint"]["status"] == "stale"
    assert data["asset"]["assigned_person_name"] == "Assigned Person"
    assert data["sources"]["endpoint"]["current_user"] == "os-user"


def test_lookup_only_returns_active_confirmed_asset(api, monkeypatch):
    client, headers = api
    asset, binding = seed()
    no_upstream(monkeypatch)
    response = client.get(f"{ROOT}/by-endpoint/{DEVICE}", headers=headers)
    assert response.status_code == 200
    assert response.json()["data"]["asset"]["id"] == asset
    from app.db import get_sessionmaker
    with get_sessionmaker()() as db:
        row = db.get(InventoryExternalBinding, binding)
        row.status = Status.ENDED
        row.ended_at = datetime.now(timezone.utc)
        db.commit()
    assert client.get(f"{ROOT}/by-endpoint/{DEVICE}", headers=headers).status_code == 404
    assert client.get(f"{ROOT}/by-endpoint/not-a-uuid", headers=headers).status_code == 422


def test_candidates_are_local_and_confirmation_then_detach_are_audited(api, monkeypatch):
    client, headers = api
    asset, binding = seed(candidate=True)
    no_upstream(monkeypatch)
    candidates = client.get(f"{ROOT}/assets/{asset}/endpoint-candidates", headers=headers)
    assert candidates.status_code == 200
    assert [r["id"] for r in candidates.json()["data"]] == [binding]
    assert client.get(f"{ROOT}/by-endpoint/{DEVICE}", headers=headers).status_code == 404
    confirmed = client.post(f"{ROOT}/assets/{asset}/endpoint-bindings/{binding}/confirm", headers=headers | revision_header(asset))
    assert confirmed.status_code == 200
    assert confirmed.json()["data"]["status"] == "confirmed"
    detached = client.post(f"{ROOT}/assets/{asset}/endpoint-bindings/{binding}/detach", headers=headers | revision_header(asset))
    assert detached.status_code == 200
    assert detached.json()["data"]["status"] == "ended"
    from app.db import get_sessionmaker
    from app.models import WebAuditLog
    with get_sessionmaker()() as db:
        actions = set(db.scalars(select(WebAuditLog.action)))
    assert {"inventory.endpoint.confirm", "inventory.endpoint.detach"} <= actions


def test_rejected_candidate_is_retained_but_not_listed(api):
    client, headers = api
    asset, binding = seed(candidate=True)
    response = client.post(f"{ROOT}/assets/{asset}/endpoint-bindings/{binding}/reject", headers=headers | revision_header(asset))
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "rejected"
    assert client.get(f"{ROOT}/assets/{asset}/endpoint-candidates", headers=headers).json()["data"] == []
    from app.db import get_sessionmaker
    from app.models import WebAuditLog
    with get_sessionmaker()() as db:
        assert db.get(InventoryExternalBinding, binding).ended_at is not None
        assert db.scalar(select(WebAuditLog).where(WebAuditLog.action == "inventory.endpoint.reject"))


def test_binding_decision_requires_original_manual_revision_and_audit_is_atomic(api, monkeypatch):
    client, headers = api
    asset, binding = seed(candidate=True)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    def revision():
        with get_sessionmaker()() as db:
            return db.get(InventoryAsset, asset).manual_revision
    original = revision()
    route = f"{ROOT}/assets/{asset}/endpoint-bindings/{binding}/confirm"
    assert client.post(route, headers=headers).status_code == 428
    assert revision() == original
    with get_sessionmaker()() as db:
        db.get(InventoryAsset, asset).custom_name = 'Concurrent manual edit'
        db.commit()
    current = revision()
    assert client.post(route, headers=headers | {'X-Inventory-Revision':str(original)}).status_code == 409
    assert revision() == current
    def failing_audit(*args, **kwargs):
        raise RuntimeError('synthetic audit failure')
    with monkeypatch.context() as patch:
        patch.setattr('app.inventory.api.write_audit', failing_audit)
        with pytest.raises(RuntimeError, match='synthetic audit failure'):
            client.post(route, headers=headers | {'X-Inventory-Revision':str(current)})
    with get_sessionmaker()() as db:
        assert db.get(InventoryExternalBinding, binding).status == Status.CANDIDATE
    assert revision() == current
    response = client.post(route, headers=headers | {'X-Inventory-Revision':str(current)})
    assert response.status_code == 200
    assert response.json()['manual_revision'] == revision() > current


def test_stale_and_wrong_asset_candidates_cannot_be_confirmed(api):
    client, headers = api
    asset, binding = seed(candidate=True, stale=True)
    other, _ = seed(asset_type=InventoryAssetType.MONITOR)
    assert client.post(f"{ROOT}/assets/{asset}/endpoint-bindings/{binding}/confirm", headers=headers | revision_header(asset)).status_code == 400
    assert client.post(f"{ROOT}/assets/{other}/endpoint-bindings/{binding}/confirm", headers=headers).status_code == 400


@pytest.mark.parametrize('action', ['confirm', 'reject', 'detach', 'reconnect'])
def test_every_binding_decision_rejects_missing_or_stale_revision(api, action):
    client, headers = api
    asset, binding = seed(candidate=action in {'confirm', 'reject'})
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    if action == 'reconnect':
        with get_sessionmaker()() as db:
            row = db.get(InventoryExternalBinding, binding)
            row.status, row.ended_at = Status.ENDED, datetime.now(timezone.utc)
            db.commit()
    original = revision_header(asset)
    route = f'{ROOT}/assets/{asset}/endpoint-bindings/{binding}/{action}'
    assert client.post(route, headers=headers).status_code == 428
    with get_sessionmaker()() as db:
        db.get(InventoryAsset, asset).custom_name = 'Another operator changed the card'
        db.commit()
    current = revision_header(asset)
    assert client.post(route, headers=headers | original).status_code == 409
    assert revision_header(asset) == current
    response = client.post(route, headers=headers | current)
    assert response.status_code == 200, response.text
    assert revision_header(asset) != current


@pytest.mark.parametrize("path,method", [
    ("/assets/pc/context", "get"), (f"/by-endpoint/{DEVICE}", "get"),
    ("/assets/pc/endpoint-candidates", "get"),
    ("/assets/pc/endpoint-bindings/binding/confirm", "post"),
    ("/assets/pc/endpoint-bindings/binding/reject", "post"),
    ("/assets/pc/endpoint-bindings/binding/detach", "post"),
    ("/assets/pc/endpoint-bindings/binding/reconnect", "post"),
    ("/assets/pc/endpoint-refresh", "post"),
    ("/assets/pc/discrepancies/ram_gb/resolve", "post"),
])
def test_all_endpoint_routes_require_authentication(api, path, method):
    client, _ = api
    assert getattr(client, method)(ROOT + path).status_code == 401


@pytest.mark.parametrize("suffix,payload", [
    ("endpoint-bindings/binding/confirm", None),
    ("endpoint-bindings/binding/reject", None),
    ("endpoint-bindings/binding/detach", None),
    ("endpoint-bindings/binding/reconnect", None),
    ("endpoint-refresh", {"profile": "baseline_v1"}),
    ("discrepancies/ram_gb/resolve", {"action": "keep_manual", "expected_revision": "0" * 64}),
])
def test_mutations_require_csrf_before_any_action(api, suffix, payload, monkeypatch):
    client, headers = api
    no_upstream(monkeypatch)
    response = client.post(f"{ROOT}/assets/pc/{suffix}",
                           headers={"Authorization": headers["Authorization"]}, json=payload)
    assert response.status_code == 400
    assert "CSRF" in response.text


@pytest.mark.parametrize("action,expected", [("keep_manual", 8), ("accept_endpoint", 16), ("mark_verified", 16)])
def test_discrepancy_actions_change_local_projection_and_leave_audit(api, action, expected):
    client, headers = api
    asset, _ = seed()
    revision = client.get(f"{ROOT}/assets/{asset}/context", headers=headers).json()["data"]["discrepancies"][0]["revision"]
    response = client.post(f"{ROOT}/assets/{asset}/discrepancies/ram_gb/resolve", headers=headers, json={"action": action, "expected_revision": revision})
    assert response.status_code == 200
    assert response.json()["data"]["manual_value"] == (16 if action == "accept_endpoint" else 8)
    context = client.get(f"{ROOT}/assets/{asset}/context", headers=headers).json()["data"]
    assert context["effective"]["ram_gb"]["value"] == expected
    assert context["manual"]["details"]["ram_gb"] == (16 if action == "accept_endpoint" else 8)
    if action == "mark_verified":
        assert context["asset"]["last_verified_at"] is not None
    from app.db import get_sessionmaker
    from app.models import WebAuditLog
    with get_sessionmaker()() as db:
        audit = db.scalar(select(WebAuditLog).where(WebAuditLog.action == "inventory.endpoint.discrepancy.resolve"))
        assert audit is not None and audit.target_client == asset


class CollectionAdapter:
    def __init__(self, error=None):
        self.error = error
        self.keys = []
        self.closed = 0

    def request_collection(self, device_id, profile, idempotency_key):
        assert device_id == UUID(DEVICE)
        assert profile == "baseline_v1"
        self.keys.append(idempotency_key)
        if self.error:
            raise self.error
        return {"id": SECOND_DEVICE, "device_id": DEVICE, "profile": profile,
                "status": "queued", "requested_at": "2026-09-18T00:00:00Z",
                "result_received_at": None, "completed_at": None, "failure_code": None}

    def close(self):
        self.closed += 1


def test_refresh_generates_keys_closes_adapter_and_does_not_write_state(api, monkeypatch):
    client, headers = api
    asset, binding = seed()
    adapter = CollectionAdapter()
    monkeypatch.setattr("app.inventory.api.get_endpoint_context_adapter", lambda: adapter, raising=False)
    for _ in range(2):
        response = client.post(f"{ROOT}/assets/{asset}/endpoint-refresh", headers=headers | {"Idempotency-Key": "untrusted-key"}, json={"profile": "baseline_v1"})
        assert response.status_code == 202
        assert response.json()["data"]["status"] == "queued"
    assert len(set(adapter.keys)) == 2 and "untrusted-key" not in adapter.keys
    assert adapter.closed == 2
    from app.db import get_sessionmaker
    from app.models import WebAuditLog
    with get_sessionmaker()() as db:
        assert db.get(InventoryEndpointState, binding).safe_context_json["ram_gb"] == 16
        assert list(db.scalars(select(InventoryObservation))) == []
        assert len(list(db.scalars(select(WebAuditLog).where(WebAuditLog.action == "inventory.endpoint.refresh")))) == 2


@pytest.mark.parametrize("failure,code", [
    ("disabled", "endpoint_platform_disabled"),
    ("scope", "endpoint_platform_scope_denied"),
    ("outage", "endpoint_platform_unavailable"),
    ("unexpected", "endpoint_platform_unavailable"),
])
def test_refresh_fails_closed_without_leaking_or_losing_cached_state(api, monkeypatch, failure, code):
    from app.endpoint_platform_client import EndpointPlatformServiceDisabled, EndpointPlatformServiceScopeDenied, EndpointPlatformServiceUnavailable
    errors = {"disabled": EndpointPlatformServiceDisabled(), "scope": EndpointPlatformServiceScopeDenied(),
              "outage": EndpointPlatformServiceUnavailable(), "unexpected": RuntimeError("secret upstream payload")}
    client, headers = api
    asset, _ = seed()
    adapter = CollectionAdapter(errors[failure])
    monkeypatch.setattr("app.inventory.api.get_endpoint_context_adapter", lambda: adapter, raising=False)
    response = client.post(f"{ROOT}/assets/{asset}/endpoint-refresh", headers=headers, json={"profile": "baseline_v1"})
    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "code": code}
    assert adapter.closed == 1
    context = client.get(f"{ROOT}/assets/{asset}/context", headers=headers).json()["data"]
    assert context["effective"]["ram_gb"]["value"] == 16
    from app.db import get_sessionmaker
    from app.models import WebAuditLog
    with get_sessionmaker()() as db:
        audit = db.scalar(select(WebAuditLog).where(WebAuditLog.action == "inventory.endpoint.refresh"))
        assert audit.message == code and audit.result == "degraded"


def test_refresh_rejects_non_pc_unbound_and_unsafe_profile_before_remote_call(api, monkeypatch):
    client, headers = api
    no_upstream(monkeypatch)
    monitor, _ = seed(asset_type=InventoryAssetType.MONITOR)
    candidate, _ = seed(candidate=True)
    for asset in (monitor, candidate):
        assert client.post(f"{ROOT}/assets/{asset}/endpoint-refresh", headers=headers, json={"profile": "baseline_v1"}).status_code == 400
    assert client.get(f"{ROOT}/assets/{monitor}/endpoint-candidates", headers=headers).status_code == 400
    assert client.post(f"{ROOT}/assets/{candidate}/endpoint-refresh", headers=headers, json={"profile": "diagnostic_v1"}).status_code == 422
    assert client.post(f"{ROOT}/assets/{candidate}/discrepancies/location_id/resolve", headers=headers, json={"action": "accept_endpoint", "expected_revision": "0" * 64}).status_code == 400


def test_missing_asset_context_returns_not_found(api):
    client, headers = api
    assert client.get(f"{ROOT}/assets/missing/context", headers=headers).status_code == 404
