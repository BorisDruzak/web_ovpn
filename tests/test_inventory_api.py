from __future__ import annotations

import hashlib
import importlib
import base64

from fastapi.testclient import TestClient


PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL3NwAAAABJRU5ErkJggg=="
)


def _client(tmp_path, monkeypatch) -> tuple[TestClient, dict[str, str]]:
    token = "inventory-api-token"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'inventory.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "inventory-test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")
    monkeypatch.setenv("OPENVPN_WEB_API_TOKEN_HASH", hashlib.sha256(token.encode()).hexdigest())

    import app.db
    import app.main

    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    client = TestClient(app.main.app)
    login_page = client.get("/login")
    csrf = login_page.text.split('name="csrf_token" value="')[1].split('"')[0]
    assert client.post(
        "/login",
        data={"username": "admin", "password": "admin-pass", "csrf_token": csrf},
        follow_redirects=False,
    ).status_code == 303
    return client, {"Authorization": f"Bearer {token}", "X-CSRF-Token": csrf}


def test_inventory_mutation_requires_bearer_and_session_csrf(tmp_path, monkeypatch):
    """Removing either API control would allow an untrusted browser to create inventory data."""
    client, headers = _client(tmp_path, monkeypatch)

    assert client.post("/api/v1/inventory/locations", json={"name": "214"}).status_code == 401
    assert client.post(
        "/api/v1/inventory/locations", headers={"Authorization": headers["Authorization"]}, json={"name": "214"}
    ).status_code == 400


def test_inventory_api_creates_empty_asset_projects_workplace_and_audits(tmp_path, monkeypatch):
    """The API must persist a valid empty asset, then expose exactly one workstation projection."""
    client, headers = _client(tmp_path, monkeypatch)

    location = client.post("/api/v1/inventory/locations", headers=headers, json={"name": "Бухгалтерия"})
    assert location.status_code == 201
    location_id = location.json()["data"]["id"]

    asset = client.post(
        "/api/v1/inventory/assets", headers=headers, json={"asset_type": "MONITOR", "location_id": location_id}
    )
    assert asset.status_code == 201
    assert asset.json()["data"]["custom_name"] is None

    workplace = client.post(
        "/api/v1/inventory/workplaces",
        headers=headers,
        json={
            "location_id": location_id,
            "pc": {"custom_name": "BUH-PC-01"},
            "children": [{"asset_type": "MONITOR", "custom_name": "AOC 24B2X"}],
        },
    )
    assert workplace.status_code == 201
    pc_id = workplace.json()["data"]["pc"]["id"]
    child_id = workplace.json()["data"]["children"][0]["id"]

    tree = client.get(f"/api/v1/inventory/locations/{location_id}/tree", headers=headers)
    assert tree.status_code == 200
    assert [asset["id"] for asset in tree.json()["data"]["top_level_assets"]] == [asset.json()["data"]["id"], pc_id]
    assert tree.json()["data"]["related_by_parent"][pc_id][0]["id"] == child_id

    relation_id = workplace.json()["data"]["relations"][0]["id"]
    detached = client.delete(f"/api/v1/inventory/relations/{relation_id}", headers=headers)
    assert detached.status_code == 200
    assert detached.json()["data"]["ended_at"] is not None

    from app.db import get_sessionmaker
    from app.models import WebAuditLog

    with get_sessionmaker()() as db:
        actions = {row.action for row in db.query(WebAuditLog).all()}
    assert {"inventory.location.create", "inventory.asset.create", "inventory.relation.create", "inventory.relation.end"} <= actions


def test_inventory_photo_api_stores_authorized_image_and_deletes_it(tmp_path, monkeypatch):
    """Photo metadata must not outlive a deleted file or become anonymously downloadable."""
    monkeypatch.setenv("INVENTORY_PHOTO_ROOT", str(tmp_path / "photos"))
    client, headers = _client(tmp_path, monkeypatch)
    location = client.post("/api/v1/inventory/locations", headers=headers, json={"name": "214"}).json()["data"]
    asset = client.post(
        "/api/v1/inventory/assets", headers=headers, json={"asset_type": "MONITOR", "location_id": location["id"]}
    ).json()["data"]

    uploaded = client.post(
        f"/api/v1/inventory/assets/{asset['id']}/photos",
        headers=headers,
        data={"photo_type": "general"},
        files={"photo": ("../../label.png", PNG_BYTES, "image/png")},
    )
    assert uploaded.status_code == 201
    photo = uploaded.json()["data"]
    assert photo["original_filename"] == "label.png"
    assert client.get(f"/api/v1/inventory/photos/{photo['id']}").status_code == 401
    assert client.get(f"/api/v1/inventory/photos/{photo['id']}", headers=headers).content == PNG_BYTES
    assert client.delete(f"/api/v1/inventory/photos/{photo['id']}", headers=headers).status_code == 200
    assert not list((tmp_path / "photos").iterdir())


def test_inventory_asset_api_persists_type_specific_details(tmp_path, monkeypatch):
    """PC hardware fields must remain outside the common asset record and survive a read."""
    client, headers = _client(tmp_path, monkeypatch)
    created = client.post(
        "/api/v1/inventory/assets",
        headers=headers,
        json={"asset_type": "PC", "custom_name": "BUH-PC-01", "details": {"os_name": "Windows 11", "ram_gb": 16}},
    )
    assert created.status_code == 201
    assert created.json()["data"]["details"] == {"os_name": "Windows 11", "cpu_model": None, "cpu_generation": None, "ram_type": None, "ram_gb": 16, "storage_type": None, "storage_gb": None}
    fetched = client.get(f"/api/v1/inventory/assets/{created.json()['data']['id']}", headers=headers)
    assert fetched.json()["data"]["details"]["ram_gb"] == 16


def test_inventory_api_keeps_identifiers_workplace_details_and_walk_check(tmp_path, monkeypatch):
    """A mobile walk can save a complete PC workplace and its confirmation without a second system."""
    client, headers = _client(tmp_path, monkeypatch)
    location_id = client.post("/api/v1/inventory/locations", headers=headers, json={"name": "215"}).json()["data"]["id"]

    workplace = client.post(
        "/api/v1/inventory/workplaces",
        headers=headers,
        json={
            "location_id": location_id,
            "pc": {
                "custom_name": "BUH-PC-02",
                "details": {"os_name": "Windows 11", "ram_gb": 16},
                "identifiers": [{"identifier_type": "ip", "value": "192.168.100.25"}],
            },
            "children": [{"asset_type": "MONITOR", "custom_name": "AOC", "details": {"diagonal_inches": "24"}}],
        },
    )
    assert workplace.status_code == 201
    pc = workplace.json()["data"]["pc"]
    assert pc["details"]["ram_gb"] == 16
    assert pc["identifiers"] == [{"identifier_type": "ip", "value": "192.168.100.25", "normalized_value": "192.168.100.25", "source": "manual", "is_current": True}]
    assert workplace.json()["data"]["children"][0]["details"]["diagonal_inches"] == "24"

    walk = client.post("/api/v1/inventory/sessions", headers=headers)
    checked = client.post(
        f"/api/v1/inventory/sessions/{walk.json()['data']['id']}/checks",
        headers=headers,
        json={"asset_id": pc["id"], "result": "confirmed", "notes": "На месте"},
    )
    assert checked.status_code == 201
    assert checked.json()["data"]["location_id"] == location_id
    assert checked.json()["data"]["result"] == "confirmed"


def test_lookup_for_asset_records_audit_observation_not_only_a_transient_hint(tmp_path, monkeypatch):
    """Network data must be traceable after the operator leaves the mobile form."""
    client, headers = _client(tmp_path, monkeypatch)
    asset_id = client.post("/api/v1/inventory/assets", headers=headers, json={"asset_type": "PC"}).json()["data"]["id"]
    monkeypatch.setattr("app.inventory.api.run_netctl", lambda args, timeout=None: {"hosts": [{"ip": "192.168.100.87", "hostname": "C1-BUH-07"}]})

    result = client.post("/api/v1/inventory/lookup", headers=headers, json={"asset_id": asset_id, "identifier": "192.168.100.87"})
    assert result.status_code == 200

    from app.db import get_sessionmaker
    from app.inventory.models import InventoryObservation

    with get_sessionmaker()() as db:
        observation = db.query(InventoryObservation).one()
    assert observation.asset_id == asset_id
    assert observation.data_json["hostname"] == "C1-BUH-07"
