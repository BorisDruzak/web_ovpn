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


def test_contacts_stay_in_operator_card_and_endpoint_links_require_confirmed_device(staging, monkeypatch):
    from app.config import get_settings
    from app.db import session_scope
    from app.inventory.models import InventoryExternalBinding, InventoryExternalBindingStatus

    client, csrf, service = staging
    monkeypatch.setenv("ENDPOINT_PLATFORM_BASE_URL", "https://endpoint.fixture.invalid")
    get_settings.cache_clear()
    profile = {"full_name": "Тестовый сотрудник", "department": "Тестовый отдел"}
    contacts = {"work_email": "fixture@example.invalid", "work_phone": "+7 000 111-22-33"}
    created = client.post(OPERATOR, headers=csrf, json={**profile, **contacts})
    assert created.status_code == 201
    person = created.json()["inventory_person_id"]
    detail = f"{OPERATOR}/{person}"
    assert client.put(detail, headers=csrf, json=profile).status_code == 200
    assert {key: client.get(detail).json()[key] for key in contacts} == contacts
    response = client.get(f"{INTERNAL}/{person}", headers=service)
    assert response.status_code == 200 and not (contacts.keys() & response.json().keys())
    assert not (contacts.keys() & client.get(OPERATOR).json()["people"][0].keys())

    confirmed, candidate = (_create_asset(custom_name=name) for name in ("Confirmed", "Candidate"))
    confirmed_device, candidate_device = str(uuid4()), str(uuid4())
    for asset in (confirmed, candidate):
        assert _assign(client, csrf, person, asset, "primary").status_code == 200
    with session_scope() as db:
        for asset, device, status in (
            (confirmed, confirmed_device, InventoryExternalBindingStatus.CONFIRMED),
            (candidate, candidate_device, InventoryExternalBindingStatus.CANDIDATE),
        ):
            db.add(InventoryExternalBinding(asset_id=asset, external_id=device, status=status,
                binding_method="manual", confidence=100, created_by="fixture"))
    page = client.get(f"/inventory/people/{person}")
    assert all(value in page.text for value in contacts.values())
    assert f'https://endpoint.fixture.invalid/admin/devices/{confirmed_device}' in page.text
    assert candidate_device not in page.text
    monkeypatch.setenv("ENDPOINT_PLATFORM_BASE_URL", "https://endpoint.fixture.invalid:broken")
    get_settings.cache_clear()
    assert "/admin/devices/" not in client.get(f"/inventory/people/{person}").text
    assert client.put(detail, headers=csrf, json={**profile, "work_email": None}).json()["work_email"] is None


def test_contact_columns_upgrade_existing_inventory_and_are_repeatable(tmp_path):
    from sqlalchemy import create_engine, text
    from app.db import _migrate_inventory_schema

    engine = create_engine(f"sqlite:///{(tmp_path / 'old-inventory.sqlite').as_posix()}")
    with engine.begin() as db:
        db.execute(text("CREATE TABLE inventory_people (id TEXT PRIMARY KEY, full_name TEXT, department TEXT)"))
        db.execute(text("INSERT INTO inventory_people VALUES ('existing', 'Fixture Name', 'Fixture Department')"))
    _migrate_inventory_schema(engine)
    _migrate_inventory_schema(engine)
    with engine.connect() as db:
        row = db.execute(text("SELECT id, full_name, department, work_email, work_phone FROM inventory_people")).one()
        assert tuple(row) == ("existing", "Fixture Name", "Fixture Department", None, None)
    engine.dispose()


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



def test_operator_page_assigns_inventory_pc_and_requires_csrf(staging):
    client, csrf, service = staging
    asset = _create_asset(custom_name="Fixture operator PC", inventory_number="PC-OPS")
    index = client.get("/inventory/people", params={"asset_id": asset})
    assert index.status_code == 200
    assert index.headers["Cache-Control"] == "no-store"
    assert "Fixture operator PC" in index.text
    assert TestClient(client.app).get("/inventory/people").status_code in {401, 403}
    created = client.post("/inventory/people", data={
        "full_name": "Fixture employee", "department": "Service", "asset_id": asset,
        "csrf_token": csrf["X-CSRF-Token"],
    }, follow_redirects=False)
    assert created.status_code == 303
    path = created.headers["Location"]
    person = path.split("?")[0].rsplit("/", 1)[1]
    _create_asset("PRINTER", custom_name="Fixture operator printer", inventory_number="PC-OPS")
    search = client.get(path.split("?")[0], params={"pc_q": "pc-ops"})
    assert "Fixture operator PC" in search.text
    assert "Fixture operator printer" not in search.text
    assignment = f"/inventory/people/{person}/assign"
    assert client.post(assignment, data={"asset_id": asset, "role": "primary"}).status_code == 400
    result = client.post(assignment, data={
        "asset_id": asset, "role": "primary", "csrf_token": csrf["X-CSRF-Token"],
    })
    assert result.status_code == 200
    assert "Fixture operator PC" in result.text
    assert "Агент не обнаружен" in result.text
    row, = client.get(f"{INTERNAL}/{person}", headers=service).json()["assignments"]
    ended = client.post(f"/inventory/people/{person}/assignments/{row['assignment_id']}/end", data={
        "reason": "Fixture reassignment", "csrf_token": csrf["X-CSRF-Token"],
    })
    assert ended.status_code == 200
    assert "Fixture reassignment" in ended.text
    assert client.get(f"{INTERNAL}/{person}", headers=service).json()["assignments"] == []



def test_operator_directory_filters_presence_before_pagination(staging):
    from app.db import session_scope
    from app.inventory.models import InventoryEndpointState, InventoryExternalBinding, InventoryExternalBindingStatus
    from app.models import utcnow

    client, csrf, _ = staging
    labels = {
        "online": "Fixture connected", "offline": "Fixture disconnected", "unknown": "Fixture unavailable",
        "not_detected": "Fixture without agent", "review": "Fixture proposed binding", "no_pcs": "Fixture without PC",
    }
    assets = {}
    for status, label in labels.items():
        response = client.post(OPERATOR, headers=csrf, json={"full_name": label, "department": "Fixtures"})
        person = response.json()["inventory_person_id"]
        if status != "no_pcs":
            assets[status] = _create_asset(custom_name=f"Test asset {status}")
            assert _assign(client, csrf, person, assets[status], "primary").status_code == 200

    with session_scope() as db:
        for status in ("online", "offline", "unknown", "review"):
            row = InventoryExternalBinding(asset_id=assets[status], external_id=str(uuid4()),
                status=(InventoryExternalBindingStatus.CANDIDATE if status == "review"
                        else InventoryExternalBindingStatus.CONFIRMED),
                binding_method="manual", confidence=100, created_by="test")
            db.add(row)
            db.flush()
            if status != "review":
                observed_at = utcnow() - timedelta(hours=1) if status == "unknown" else utcnow()
                db.add(InventoryEndpointState(binding_id=row.id, asset_id=row.asset_id, endpoint_device_id=row.external_id,
                    online=status == "online", last_seen_at=observed_at,
                    safe_context_json={"identity_status": "available", "identity_checked_at": observed_at.isoformat()}))

    for status, label in labels.items():
        response = client.get("/inventory/people", params={"q": "fixtures", "state": status})
        assert response.status_code == 200
        assert label in response.text
        assert all(other not in response.text for other in labels.values() if other != label)
    assert client.get("/inventory/people", params={"state": "invalid"}).status_code == 422

    # The connected employee must remain on the first filtered page even if
    # earlier names fill the first unfiltered page.
    from app.inventory.models import InventoryPerson
    with session_scope() as db:
        for number in range(50):
            name = f"A fixture {number:02d}"
            db.add(InventoryPerson(full_name=name, department="Fixtures", search_key=f"{name.lower()} fixtures"))
    unfiltered = client.get("/inventory/people", params={"q": "fixtures"})
    assert labels["online"] not in unfiltered.text
    filtered = client.get("/inventory/people", params={"q": "fixtures", "state": "online"})
    assert labels["online"] in filtered.text
    assert "A fixture 00" not in filtered.text


def test_directory_shows_helpdesk_status_and_filters_only_confirmed_absence(staging, monkeypatch):
    from app.config import get_settings
    from app.inventory import helpdesk_status

    client, csrf, service = staging
    linked = _create_person(client, csrf)
    unlinked = client.post(OPERATOR, headers=csrf, json={"full_name": "Без Helpdesk", "department": "Отдел"}).json()["inventory_person_id"]
    helpdesk_person = str(uuid4())
    state = {linked: helpdesk_status.AccountLink(helpdesk_person, "fixture-account")}
    monkeypatch.setattr(helpdesk_status, "read_links", lambda ids: {key: state[key] for key in ids if key in state})
    monkeypatch.setenv("HELPDESK_INVENTORY_STATUS_BASE_URL", "https://helpdesk.fixture.invalid")
    get_settings.cache_clear()

    directory = client.get("/inventory/people")
    assert "Helpdesk связан" in directory.text and "Нет аккаунта Helpdesk" in directory.text
    filtered = client.get("/inventory/people", params={"state": "no_helpdesk"})
    assert f"/inventory/people/{unlinked}" in filtered.text
    assert f"/inventory/people/{linked}" not in filtered.text
    detail = client.get(f"/inventory/people/{linked}")
    assert "fixture-account" in detail.text
    assert f"https://helpdesk.fixture.invalid/app/admin/users?person={helpdesk_person}" in detail.text
    assert "fixture-account" not in client.get(f"{INTERNAL}/{linked}", headers=service).text

    monkeypatch.setattr(helpdesk_status, "read_links", lambda ids: None)
    unavailable = client.get("/inventory/people")
    assert "Статус Helpdesk неизвестен" in unavailable.text
    assert f"/inventory/people/{unlinked}" not in client.get("/inventory/people", params={"state": "no_helpdesk"}).text


def test_helpdesk_status_client_bounds_batches_and_rejects_invalid_responses(tmp_path, monkeypatch):
    import json

    import httpx

    from app.config import get_settings
    from app.inventory import helpdesk_status

    key = "inventory-status-fixture-key-with-32-bytes"
    token = tmp_path / "fixture-key"
    token.write_text(key, encoding="ascii")
    monkeypatch.setenv("HELPDESK_INVENTORY_STATUS_BASE_URL", "https://helpdesk.fixture.invalid")
    monkeypatch.setenv("HELPDESK_INVENTORY_STATUS_TOKEN_FILE", str(token))
    get_settings.cache_clear()
    ids = [str(uuid4()) for _ in range(251)]
    helpdesk_person = str(uuid4())
    calls = []
    mode = "available"

    def respond(request):
        assert request.url == "https://helpdesk.fixture.invalid/api/internal/inventory/v1/helpdesk-account-status"
        assert request.headers["Authorization"] == f"Bearer {key}"
        batch = json.loads(request.content)["inventory_person_ids"]
        calls.append(batch)
        if mode == "redirect":
            return httpx.Response(307, headers={"Location": "https://untrusted.invalid"})
        row = {"inventory_person_id": batch[0], "person_id": helpdesk_person, "user_login": "fixture-login"}
        if mode == "bad_second_batch" and len(batch) == 1:
            row["inventory_person_id"] = ids[0]
        return httpx.Response(200, json={"linked": [row]})

    original = httpx.Client

    def client(**kwargs):
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        return original(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(helpdesk_status.httpx, "Client", client)
    assert helpdesk_status.read_links(ids) == {
        key: helpdesk_status.AccountLink(helpdesk_person, "fixture-login") for key in (ids[0], ids[-1])
    }
    assert [len(batch) for batch in calls] == [250, 1]
    mode = "bad_second_batch"
    assert helpdesk_status.read_links(ids) is None
    mode = "redirect"
    calls.clear()
    assert helpdesk_status.read_links(ids) is None
    assert len(calls) == 1
