"""PC cards expose local provenance and session-authenticated Endpoint actions."""

from datetime import datetime, timezone

import pytest

from app.inventory.models import InventoryAssetType, InventoryEndpointState
from tests.test_inventory_endpoint_api import CollectionAdapter, seed
from tests.test_inventory_web import _client, _csrf


@pytest.fixture
def web(tmp_path, monkeypatch):
    return _client(tmp_path, monkeypatch)[0]


def state_for(binding_id, **values):
    from app.db import get_sessionmaker
    with get_sessionmaker()() as db:
        row = db.get(InventoryEndpointState, binding_id)
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()


def test_pc_card_renders_local_provenance_people_and_discrepancies(web, monkeypatch):
    asset, binding = seed()
    state_for(binding, online=True, agent_version="1.2.3")
    def forbidden(*args, **kwargs):
        raise AssertionError("render must not contact Endpoint")
    monkeypatch.setattr("app.endpoint_context_adapter.get_endpoint_context_adapter", forbidden)
    monkeypatch.setattr("app.inventory.api.get_endpoint_context_adapter", forbidden)
    page = web.get(f"/inventory/assets/{asset}")
    assert page.status_code == 200
    for label in ("АГЕНТ", "Текущий пользователь ОС", "os-user", "Закреплённый человек",
                  "Assigned Person", "РАСХОЖДЕНИЯ", "Endpoint", "Ручные данные", "В сети", "1.2.3"):
        assert label in page.text
    assert f'/api/v1/inventory/assets/{asset}/endpoint-refresh' in page.text
    assert f'/endpoint-bindings/{binding}/detach' in page.text
    assert "Последнее успешное обновление" in page.text


@pytest.mark.parametrize("online,stale,outage,label", [
    (False, False, False, "Не в сети"),
    (True, True, False, "Данные устарели"),
    (True, False, True, "Endpoint временно недоступен"),
])
def test_card_distinguishes_offline_stale_and_outage(web, online, stale, outage, label):
    asset, binding = seed(stale=stale)
    state_for(binding, online=online,
              unavailable_since=datetime.now(timezone.utc) if outage else None)
    page = web.get(f"/inventory/assets/{asset}")
    assert label in page.text
    assert "os-user" in page.text
    assert 'name="ram_gb" value="8"' in page.text


def test_unbound_pc_has_local_candidate_lookup_and_non_pc_has_no_agent(web):
    from app.db import get_sessionmaker
    from app.inventory.service import InventoryService
    with get_sessionmaker()() as db:
        pc = InventoryService().create_asset(db, InventoryAssetType.PC)
        db.commit()
        pc_id = pc.id
    page = web.get(f"/inventory/assets/{pc_id}")
    assert "Агент не привязан" in page.text
    assert "Найти агент" in page.text
    assert "endpoint-refresh" not in page.text
    monitor, _ = seed(asset_type=InventoryAssetType.MONITOR)
    other = web.get(f"/inventory/assets/{monitor}")
    assert "Найти агент" not in other.text
    assert "data-endpoint-card" not in other.text


def test_candidate_controls_use_local_api_and_session_csrf(web):
    asset, binding = seed(candidate=True)
    page = web.get(f"/inventory/assets/{asset}")
    assert "Кандидат" in page.text
    route = f"/api/v1/inventory/assets/{asset}/endpoint-bindings/{binding}/confirm"
    assert route in page.text
    assert web.post(route).status_code == 400
    response = web.post(route, headers={"X-CSRF-Token": _csrf(page.text)})
    assert response.status_code == 200
    assert "Привязка подтверждена" in web.get(f"/inventory/assets/{asset}").text


def test_refresh_uses_session_and_preserves_cached_card(web, monkeypatch):
    asset, binding = seed()
    adapter = CollectionAdapter()
    monkeypatch.setattr("app.inventory.api.get_endpoint_context_adapter", lambda: adapter)
    page = web.get(f"/inventory/assets/{asset}")
    response = web.post(f"/api/v1/inventory/assets/{asset}/endpoint-refresh",
                        headers={"X-CSRF-Token": _csrf(page.text)}, json={"profile": "baseline_v1"})
    assert response.status_code == 202
    assert "os-user" in web.get(f"/inventory/assets/{asset}").text


def test_endpoint_display_values_are_escaped(web):
    asset, binding = seed()
    state_for(binding, safe_context_json={"ram_gb": 16, "current_user": "<script>alert(1)</script>"})
    page = web.get(f"/inventory/assets/{asset}")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "<script>alert(1)</script>" not in page.text


def test_session_context_and_disposition_apply_without_bearer(web):
    asset, _ = seed()
    page = web.get(f"/inventory/assets/{asset}")
    response = web.post(f"/api/v1/inventory/assets/{asset}/discrepancies/ram_gb/resolve",
                        headers={"X-CSRF-Token": _csrf(page.text)}, json={"action": "keep_manual"})
    assert response.status_code == 200
    context = web.get(f"/api/v1/inventory/assets/{asset}/context")
    assert context.status_code == 200
    assert context.json()["data"]["effective"]["ram_gb"]["value"] == 8


@pytest.mark.parametrize("action,candidate,expected", [("reject", True, "rejected"), ("detach", False, "ended")])
def test_session_reject_and_detach_require_csrf(web, action, candidate, expected):
    asset, binding = seed(candidate=candidate)
    page = web.get(f"/inventory/assets/{asset}")
    route = f"/api/v1/inventory/assets/{asset}/endpoint-bindings/{binding}/{action}"
    assert web.post(route).status_code == 400
    response = web.post(route, headers={"X-CSRF-Token": _csrf(page.text)})
    assert response.status_code == 200
    assert response.json()["data"]["status"] == expected


def test_endpoint_session_auth_is_narrow_and_rejects_invalid_bearer(web, monkeypatch):
    import hashlib
    from app.config import reset_settings_cache
    from app.main import app
    from fastapi.testclient import TestClient
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(b"fixture-api-token").hexdigest())
    reset_settings_cache()
    asset, _ = seed()
    route = f"/api/v1/inventory/assets/{asset}/context"
    assert TestClient(app).get(route).status_code == 401
    assert web.get(route, headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert web.get("/api/v1/inventory/assets").status_code == 401
