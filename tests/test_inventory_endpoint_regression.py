"""Cross-domain acceptance: Endpoint failures cannot take local Inventory down."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy import select

from app.endpoint_platform_client import (
    EndpointPlatformServiceDisabled,
    EndpointPlatformServiceScopeDenied,
    EndpointPlatformServiceUnavailable,
)
from app.inventory.models import (
    InventoryAssetType,
    InventoryEndpointState,
    InventoryExternalBinding,
    InventoryObservation,
)
from app.inventory.service import InventoryService
from tests.test_endpoint_context_api import csrf_header, make_endpoint_client
from tests.test_inventory_netctl_sync import _snapshot_page


DEVICE = "11111111-1111-1111-1111-111111111111"
MAC = "00:11:22:33:44:55"


class PublishedContext:
    def __init__(self, collected_at):
        self.collected_at = collected_at.isoformat()

    def list_agent_network_identities(self):
        return [{
            "id": DEVICE, "baseline_mac_keys": ["mac-001122334455"],
            "baseline_collected_at": self.collected_at,
            "last_seen_at": self.collected_at,
            "profiles": [{"profile": "baseline_v1", "collected_at": self.collected_at}],
        }]

    def read_profiles(self, device_id):
        assert device_id == UUID(DEVICE)
        return {
            "baseline_v1": {
                "id": "baseline-1", "profile": "baseline_v1",
                "semantic_hash": "a" * 64, "collected_at": self.collected_at,
                "sections": {
                    "system": {"platform": "windows", "distribution": "Windows 11"},
                    "hardware": {"cpu_model": "CPU", "memory_bytes": 17179869184},
                },
            },
            "health_v1": None, "network_v1": None,
        }

    def close(self):
        pass


@pytest.mark.parametrize("failure", [
    EndpointPlatformServiceUnavailable,
    EndpointPlatformServiceScopeDenied,
    EndpointPlatformServiceDisabled,
])
def test_endpoint_failure_keeps_manual_netctl_and_last_context_usable(
    tmp_path, monkeypatch, failure,
):
    """Catches clearing cached state or coupling local edits/reads to upstream."""
    client, auth = make_endpoint_client(tmp_path, monkeypatch)
    headers = auth | csrf_header(client)
    assert client.post("/login", data={
        "username": "admin", "password": "admin-pass",
        "csrf_token": headers["X-CSRF-Token"],
    }, follow_redirects=False).status_code == 303
    from app.db import get_sessionmaker
    from app.endpoint_agent_network import attach_endpoint_agent_statuses
    from app.inventory import endpoint_sync as worker
    from app.inventory.netctl_sync import synchronize_current_snapshot

    now = datetime.now(timezone.utc)
    previous = now - timedelta(minutes=20)
    with get_sessionmaker()() as db:
        service = InventoryService()
        asset = service.create_asset(db, InventoryAssetType.PC)
        service.update_details(db, asset, {"ram_gb": 8})
        service.sync_identifiers(db, asset, [{"identifier_type": "mac", "value": MAC}])
        db.commit()
        asset_id = asset.id
    monkeypatch.setattr(worker, "get_endpoint_context_adapter", lambda: PublishedContext(previous))
    monkeypatch.setattr(worker, "run_netctl", lambda *args, **kwargs: {})
    assert worker.run_inventory_endpoint_sync(previous) == 0

    def unavailable():
        raise failure()

    monkeypatch.setattr(worker, "get_endpoint_context_adapter", unavailable)
    assert worker.run_inventory_endpoint_sync(now) == 1
    # The independent Netctl worker still consumes its own fresh snapshot.
    snapshot = _snapshot_page(generated_at=now.isoformat(), hosts=[{
        "mac": MAC, "ip": "192.0.2.20", "hostname": "inventory-pc",
    }])
    synced = synchronize_current_snapshot(netctl_call=lambda args, timeout: snapshot)
    assert (synced.status, synced.updated_assets) == ("success", 1)

    def forbidden(*args, **kwargs):
        pytest.fail("local read/edit attempted an Endpoint connection")

    monkeypatch.setattr("app.inventory.api.get_endpoint_context_adapter", forbidden)
    monkeypatch.setattr("app.endpoint_context_adapter.get_endpoint_context_adapter", forbidden)
    root = f"/api/v1/inventory/assets/{asset_id}"
    edited = client.patch(root, headers=headers, json={"assigned_person_name": "Manual Person"})
    assert edited.status_code == 200
    response = client.get(root + "/context", headers=headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["asset"]["assigned_person_name"] == "Manual Person"
    assert data["manual"]["details"]["ram_gb"] == 8
    assert data["effective"]["ram_gb"]["value"] == 16
    assert data["effective"]["ram_gb"]["source"] == "endpoint"
    assert data["effective"]["ram_gb"]["freshness"] == "unavailable"
    assert data["freshness"]["endpoint"]["last_success_at"] == previous.isoformat()
    assert data["effective"]["ip"]["value"] == "192.0.2.20"
    assert data["effective"]["ip"]["source"] == "netctl"
    lookup = client.get(f"/api/v1/inventory/by-endpoint/{DEVICE}", headers=headers)
    assert lookup.status_code == 200 and lookup.json()["data"]["asset"]["id"] == asset_id
    assert client.get("/inventory").status_code == 200
    card = client.get(f"/inventory/assets/{asset_id}")
    assert card.status_code == 200
    assert "Endpoint временно недоступен" in card.text
    assert "Manual Person" in card.text
    with get_sessionmaker()() as db:
        binding = db.scalar(select(InventoryExternalBinding))
        assert binding.status.value == "confirmed" and binding.ended_at is None
        assert db.get(InventoryEndpointState, binding.id).safe_context_json["ram_gb"] == 16
        assert len(list(db.scalars(select(InventoryObservation)))) == 1
        rows = [{"device_key": "mac:" + MAC}]
        assert attach_endpoint_agent_statuses(db, rows) == "stale"
        assert rows[0]["endpoint_agent"]["state"] == "stale"
        assert rows[0]["endpoint_agent"]["device_id"] == DEVICE
