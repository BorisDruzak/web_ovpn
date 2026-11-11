from __future__ import annotations

import hashlib
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select


@pytest.fixture
def staging(tmp_path, monkeypatch):
    from app.db import init_db, reset_engine_cache
    from app.main import app

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'people.sqlite').as_posix()}")
    monkeypatch.setenv("ADMIN_PASSWORD", "fixture-admin-password")
    monkeypatch.setenv("HELPDESK_INVENTORY_TOKEN_HASH", hashlib.sha256(b"fixture-helpdesk-only").hexdigest())
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(b"fixture-general-api").hexdigest())
    monkeypatch.setenv("ENDPOINT_PLATFORM_ENABLED", "true")
    monkeypatch.setenv("OPENVPN_WEB_API_PERMISSIONS", "inventory:read,inventory:delete")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    reset_engine_cache()
    init_db()
    with TestClient(app) as client:
        login_page = client.get("/login")
        csrf = login_page.text.split('name="csrf_token" value="')[1].split('"')[0]
        response = client.post("/login", data={
            "username": "admin", "password": "fixture-admin-password", "csrf_token": csrf,
        }, follow_redirects=False)
        assert response.status_code == 303
        yield client, {"X-CSRF-Token": csrf}, {"Authorization": "Bearer fixture-helpdesk-only"}


OPERATOR = "/api/v1/inventory/people"
INTERNAL = "/api/internal/helpdesk/v1/inventory/people"


def _create_person(client, headers):
    response = client.post(OPERATOR, headers=headers, json={"full_name": "Тестовый Сотрудник", "department": "Тестовый отдел"})
    assert response.status_code == 201, response.text
    return response.json()["inventory_person_id"]


def _create_asset(kind="PC", **kwargs):
    from app.db import session_scope
    from app.inventory.models import InventoryAsset, InventoryAssetType

    with session_scope() as db:
        asset = InventoryAsset(asset_type=InventoryAssetType(kind), **kwargs)
        db.add(asset)
        db.flush()
        return asset.id


def _assign(client, headers, person, asset, role):
    return client.put(f"{OPERATOR}/{person}/assignments/{asset}", headers=headers, json={"role": role})


def test_directory_requires_dedicated_credential_and_never_matches_names(staging):
    client, csrf, service = staging
    person = _create_person(client, csrf)
    assert _create_person(client, csrf) != person  # Namesakes stay separate.
    _create_asset(assigned_person_name="Тестовый Сотрудник")
    url = f"{INTERNAL}/{person}"
    assert client.get(url).status_code == 401  # Even an operator session does not suffice.
    assert client.get(url, headers={"Authorization": "Bearer fixture-general-api"}).status_code == 401
    assert client.get(INTERNAL, headers=service).status_code == 404
    response = client.get(url, headers=service)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["assignments"] == []
    namesakes = client.get(OPERATOR, params={"q": "Тестовый"}).json()["people"]
    assert len(namesakes) == 2 and namesakes[0]["inventory_person_id"] != namesakes[1]["inventory_person_id"]
    assert TestClient(client.app).get(OPERATOR).status_code == 401
    assert TestClient(client.app).post(OPERATOR, headers=service,
        json={"full_name": "Test", "department": "Test"}).status_code == 401


def test_assignments_are_idempotent_allow_shared_use_and_preserve_history(staging):
    from app.db import session_scope
    from app.models import WebAuditLog

    client, csrf, service = staging
    primary, shared = (_create_person(client, csrf) for _ in range(2))
    asset = _create_asset(custom_name="Test PC")
    assert _assign(client, csrf, primary, _create_asset("PRINTER"), "primary").status_code == 409
    first = _assign(client, csrf, primary, asset, "primary")
    assert first.status_code == 200, first.text
    original = first.json()
    assert _assign(client, csrf, primary, asset, "primary").json() == original
    assert _assign(client, csrf, shared, asset, "primary").status_code == 409
    assert _assign(client, csrf, shared, asset, "shared").status_code == 200
    url = f"{OPERATOR}/{primary}/assignments/{original['assignment_id']}/end"
    assert client.post(url, headers=csrf, json={"reason": "fixture transfer"}).json()["ended_at"]
    assert client.post(url, headers=csrf, json={"reason": "repeat"}).status_code == 200
    assert client.get(f"{INTERNAL}/{primary}", headers=service).json()["assignments"] == []
    assert len(client.get(f"{INTERNAL}/{shared}", headers=service).json()["assignments"]) == 1
    assert _assign(client, csrf, primary, asset, "primary").json()["assignment_id"] != original["assignment_id"]
    with session_scope() as db:
        assert len(list(db.scalars(select(WebAuditLog).where(WebAuditLog.action == "inventory.person.assignment.end")))) == 1


def test_projection_distinguishes_unlinked_offline_and_unavailable(staging):
    from app.db import session_scope
    from app.inventory.models import InventoryEndpointState, InventoryExternalBinding, InventoryExternalBindingStatus
    from app.models import utcnow

    client, csrf, service = staging
    person = _create_person(client, csrf)
    assets = {key: _create_asset(custom_name=key) for key in ("unlinked", "online", "offline", "unknown", "deleted")}
    for asset in assets.values():
        assert _assign(client, csrf, person, asset, "primary").status_code == 200
    device_ids = {}
    with session_scope() as db:
        for key in ("online", "offline", "unknown"):
            device_ids[key] = str(uuid4())
            row = InventoryExternalBinding(asset_id=assets[key], external_id=device_ids[key],
                status=InventoryExternalBindingStatus.CONFIRMED, binding_method="manual", confidence=100, created_by="test")
            db.add(row)
            db.flush()
            db.add(InventoryEndpointState(binding_id=row.id, asset_id=assets[key], endpoint_device_id=row.external_id,
                online=key == "online", last_seen_at=utcnow(), last_success_at=utcnow(),
                safe_context_json={"identity_status": "available", "identity_checked_at": utcnow().isoformat()},
                unavailable_since=utcnow() - timedelta(seconds=1) if key == "unknown" else None))
    asset_path = f"/api/v1/inventory/assets/{assets['deleted']}"
    operator_api = {**csrf, "Authorization": "Bearer fixture-general-api"}
    revision = client.get(asset_path, headers=operator_api).json()["data"]["manual_revision"]
    deleted = client.request("DELETE", asset_path, headers=operator_api,
                          json={"expected_revision": revision, "reason": "fixture retired"})
    assert deleted.status_code == 200, deleted.text
    response = client.get(f"{INTERNAL}/{person}", headers=service)
    assert response.status_code == 200
    states = {row["name"]: row for row in response.json()["assignments"]}
    assert {key: row["endpoint_status"] for key, row in states.items()} == {
        "unlinked": "not_detected", "online": "online", "offline": "offline", "unknown": "unknown",
    }
    assert states["unlinked"]["endpoint_device_id"] is None
    assert states["unknown"]["endpoint_device_id"] == device_ids["unknown"]
    assert states["offline"]["endpoint_device_id"] == device_ids["offline"]
    restore = client.post(f"{asset_path}/restore", headers=operator_api, json={
        "expected_revision": deleted.json()["data"]["manual_revision"],
    })
    assert restore.status_code == 200
    assert assets["deleted"] not in {row["inventory_asset_id"] for row in
        client.get(f"{INTERNAL}/{person}", headers=service).json()["assignments"]}



def test_concurrent_card_deletion_cannot_leave_a_live_assignment(staging):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from sqlalchemy import event

    from app.db import get_engine, session_scope
    from app.inventory.lifecycle import soft_delete
    from app.inventory.models import InventoryAsset, InventoryPersonAssignment

    client, csrf, service = staging
    person = _create_person(client, csrf)
    asset = _create_asset(custom_name="Retiring fixture PC")
    write_attempted = Event()
    engine = get_engine()

    def before_write(_conn, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith(("UPDATE inventory_assets SET manual_revision=inventory_assets.manual_revision",
                                 "INSERT INTO inventory_person_assignments")):
            write_attempted.set()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with session_scope() as db:
            revision = db.get(InventoryAsset, asset).manual_revision
            soft_delete(db, asset, expected_revision=revision, actor="fixture", reason="retired")
            event.listen(engine, "before_cursor_execute", before_write)
            try:
                pending = executor.submit(_assign, client, csrf, person, asset, "primary")
                assert write_attempted.wait(timeout=3)
                db.commit()
            finally:
                event.remove(engine, "before_cursor_execute", before_write)
        assert pending.result(timeout=5).status_code in {404, 409}

    with session_scope() as db:
        assert db.scalar(select(InventoryPersonAssignment.id).where(InventoryPersonAssignment.asset_id == asset)) is None
    assert client.get(f"{INTERNAL}/{person}", headers=service).json()["assignments"] == []
