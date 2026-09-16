from __future__ import annotations

import importlib
import base64

from fastapi.testclient import TestClient


PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL3NwAAAABJRU5ErkJggg=="
)


def _client(tmp_path, monkeypatch) -> tuple[TestClient, str]:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'inventory-web.sqlite').as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", "inventory-web-test-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "admin-pass")

    import app.db
    import app.main

    app.db.reset_engine_cache()
    importlib.reload(app.main)
    app.db.init_db()
    client = TestClient(app.main.app)
    login = client.get("/login")
    csrf = login.text.split('name="csrf_token" value="')[1].split('"')[0]
    assert client.post("/login", data={"username": "admin", "password": "admin-pass", "csrf_token": csrf}, follow_redirects=False).status_code == 303
    return client, csrf


def _csrf(page: str) -> str:
    return page.split('name="csrf_token" value="')[1].split('"')[0]


def test_inventory_page_requires_login_and_has_mobile_capture_controls(tmp_path, monkeypatch):
    """A regression must not expose physical inventory or remove touch-oriented capture controls."""
    client, _ = _client(tmp_path, monkeypatch)

    anonymous = TestClient(__import__("app.main", fromlist=["app"]).app)
    assert anonymous.get("/inventory", follow_redirects=False).status_code == 303

    page = client.get("/inventory")
    assert page.status_code == 200
    assert "ИНВЕНТАРИЗАЦИЯ" in page.text
    assert "inventory-mobile" in page.text
    assert "/static/inventory.css" in page.text


def test_mobile_inventory_creates_tree_and_detaches_child_without_duplicate(tmp_path, monkeypatch):
    """A detached monitor must survive and be rendered once at its location top level."""
    client, csrf = _client(tmp_path, monkeypatch)

    created_location = client.post(
        "/inventory/locations",
        data={"csrf_token": csrf, "name": "Бухгалтерия", "comment": "У окна"},
        follow_redirects=False,
    )
    assert created_location.status_code == 303

    page = client.get("/inventory")
    csrf = _csrf(page.text)
    pc = client.post(
        "/inventory/assets",
        data={"csrf_token": csrf, "asset_type": "PC", "custom_name": "BUH-PC-01"},
        follow_redirects=False,
    )
    assert pc.status_code == 303
    pc_id = pc.headers["location"].rsplit("/", 1)[-1]

    for asset_type, custom_name in (("MONITOR", "AOC 24B2X"), ("UPS", "Ippon")):
        page = client.get("/inventory")
        csrf = _csrf(page.text)
        response = client.post(
            "/inventory/assets",
            data={"csrf_token": csrf, "asset_type": asset_type, "custom_name": custom_name, "parent_asset_id": pc_id},
            follow_redirects=False,
        )
        assert response.status_code == 303

    page = client.get("/inventory")
    csrf = _csrf(page.text)
    assert client.post(
        "/inventory/assets",
        data={"csrf_token": csrf, "asset_type": "PRINTER", "custom_name": "Kyocera M2040"},
        follow_redirects=False,
    ).status_code == 303

    tree = client.get("/inventory")
    assert "BUH-PC-01" in tree.text
    assert "AOC 24B2X" in tree.text
    assert "Ippon" in tree.text
    assert "Kyocera M2040" in tree.text

    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAssetRelation

    with get_sessionmaker()() as db:
        relation_id = db.query(InventoryAssetRelation).filter_by(parent_asset_id=pc_id).order_by(InventoryAssetRelation.id).first().id
    csrf = _csrf(tree.text)
    detached = client.post(f"/inventory/relations/{relation_id}/detach", data={"csrf_token": csrf}, follow_redirects=False)
    assert detached.status_code == 303

    after = client.get("/inventory")
    assert after.text.count("AOC 24B2X") == 1
    assert "Kyocera M2040" in after.text


def test_saved_mobile_asset_accepts_camera_photo(tmp_path, monkeypatch):
    """The phone capture control must persist a validated image after an asset exists."""
    monkeypatch.setenv("INVENTORY_PHOTO_ROOT", str(tmp_path / "photos"))
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post("/inventory/locations", data={"csrf_token": csrf, "name": "214"}, follow_redirects=False).status_code == 303
    page = client.get("/inventory")
    created = client.post(
        "/inventory/assets", data={"csrf_token": _csrf(page.text), "asset_type": "MONITOR", "custom_name": "AOC"}, follow_redirects=False
    )
    asset_id = created.headers["location"].rsplit("/", 1)[-1]
    detail = client.get(f"/inventory/assets/{asset_id}")
    uploaded = client.post(
        f"/inventory/assets/{asset_id}/photos",
        data={"csrf_token": _csrf(detail.text), "photo_type": "general"},
        files={"photo": ("label.png", PNG_BYTES, "image/png")},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    assert "label.png" in client.get(f"/inventory/assets/{asset_id}").text
