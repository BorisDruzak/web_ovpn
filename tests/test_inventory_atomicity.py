"""Operation-level transactions must survive failures after workplace creation."""
import json

import pytest
from sqlalchemy import func, select

from tests.test_inventory_web import _client, _csrf, _prepare_manual_asset_form
from tests.test_inventory_api import _client as api_client


def assert_no_workplace():
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetRelation
    from app.models import WebAuditLog
    # New session/connection: never assert rollback using cached ORM objects.
    with get_sessionmaker()() as db:
        assert db.scalar(select(func.count()).select_from(InventoryAsset)) == 0
        assert db.scalar(select(func.count()).select_from(InventoryAssetRelation)) == 0
        assert db.scalar(select(func.count()).select_from(WebAuditLog).where(
            WebAuditLog.action.in_(["inventory.asset.create", "inventory.relation.create"]),
            WebAuditLog.result == "ok",
        )) == 0


@pytest.mark.parametrize("invalid", [{"ip_address": "not-an-ip"}, {"ram_gb": "bad"}])
def test_html_workplace_late_validation_rolls_back(tmp_path, monkeypatch, invalid):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "Synthetic"})
    form = _prepare_manual_asset_form(client, monkeypatch, "PC")
    response = client.post("/inventory/assets", data={
        "csrf_token": _csrf(form.text), "asset_type": "PC", "custom_name": "Draft PC",
        "related_devices_json": json.dumps([
            {"asset_type": "MONITOR", "custom_name": "Screen one"},
            {"asset_type": "MONITOR", "custom_name": "Screen two"},
        ]), **invalid,
    }, follow_redirects=False)
    assert response.status_code == 303
    assert_no_workplace()
    restored = client.get(response.headers["location"])
    assert 'value="Draft PC"' in restored.text
    assert "Screen two" in restored.text


def test_api_workplace_late_validation_rolls_back(tmp_path, monkeypatch):
    client, headers = api_client(tmp_path, monkeypatch)
    location = client.post("/api/v1/inventory/locations", headers=headers, json={"name": "Synthetic"}).json()["data"]["id"]
    response = client.post("/api/v1/inventory/workplaces", headers=headers, json={
        "location_id": location,
        "pc": {"asset_type": "PC", "identifiers": [{"identifier_type": "ip", "value": "invalid"}]},
        "children": [{"asset_type": "MONITOR"}, {"asset_type": "MONITOR"}],
    })
    assert response.status_code == 400
    assert_no_workplace()


def test_html_update_late_exception_rolls_back_fields_and_identifiers(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetType
    from app.inventory.service import InventoryService, InventoryValidationError
    with get_sessionmaker()() as db:
        asset = InventoryService().create_asset(db, InventoryAssetType.PC, custom_name="Original")
        asset_id = asset.id
        db.commit()
    original = InventoryService.sync_identifiers
    def fail_at_end(self, db, asset, identifiers):
        original(self, db, asset, identifiers)
        raise InventoryValidationError("synthetic late error")
    monkeypatch.setattr(InventoryService, "sync_identifiers", fail_at_end)
    response = client.post(f"/inventory/assets/{asset_id}", data={
        "csrf_token": csrf, "custom_name": "Unsaved", "ip_address": "192.0.2.3",
    }, follow_redirects=False)
    assert response.status_code == 303
    with get_sessionmaker()() as db:
        asset = db.get(InventoryAsset, asset_id)
        assert asset.custom_name == "Original"
        assert InventoryService().identifiers_for(db, asset) == []
    assert 'value="Unsaved"' in client.get(response.headers["location"]).text


def test_workplace_savepoint_remains_inside_outer_transaction(tmp_path, monkeypatch):
    _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.service import InventoryService
    with get_sessionmaker()() as db:
        InventoryService().create_workplace(db, location_id=None, actor="synthetic",
            child_payloads=[{"asset_type": "MONITOR"}])
        db.rollback()
    assert_no_workplace()


def test_successful_html_workplace_commits_once(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "Synthetic"})
    form = _prepare_manual_asset_form(client, monkeypatch, "PC")
    from sqlalchemy.orm import Session
    original = Session.commit
    commits = []
    def counted(db):
        commits.append(1)
        return original(db)
    monkeypatch.setattr(Session, "commit", counted)
    response = client.post("/inventory/assets", data={
        "csrf_token": _csrf(form.text), "asset_type": "PC", "custom_name": "Saved",
        "related_devices_json": '[{"asset_type":"MONITOR"},{"asset_type":"MONITOR"}]',
    }, follow_redirects=False)
    assert response.status_code == 303
    assert len(commits) == 1


@pytest.mark.parametrize("fail_point", ["details", "audit"])
def test_html_workplace_unexpected_late_failure_rolls_back(tmp_path, monkeypatch, fail_point):
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "Synthetic"})
    form = _prepare_manual_asset_form(client, monkeypatch, "PC")
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic failure")
    monkeypatch.setattr("app.inventory.web.service.update_details" if fail_point == "details"
        else "app.inventory.web.write_audit", fail)
    response = client.post("/inventory/assets", data={
        "csrf_token": _csrf(form.text), "asset_type": "PC", "custom_name": "Retained after error",
        "related_devices_json": '[{"asset_type":"MONITOR"},{"asset_type":"MONITOR"}]',
    }, follow_redirects=False)
    assert response.status_code == 303
    assert_no_workplace()
    page = client.get(response.headers["location"])
    assert "Не удалось сохранить" in page.text
    assert 'value="Retained after error"' in page.text


def test_audit_can_participate_in_rollback_and_legacy_default_still_commits(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    from starlette.requests import Request
    from app.audit import write_audit
    from app.db import get_sessionmaker
    from app.models import WebAuditLog
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    with get_sessionmaker()() as db:
        write_audit(db, request, "test", "synthetic.rollback", "ok", commit=False)
        db.flush()
        db.rollback()
        write_audit(db, request, "test", "synthetic.legacy", "denied")
    with get_sessionmaker()() as db:
        assert db.scalar(select(func.count()).select_from(WebAuditLog).where(WebAuditLog.action == "synthetic.rollback")) == 0
        assert db.scalar(select(func.count()).select_from(WebAuditLog).where(WebAuditLog.action == "synthetic.legacy")) == 1
