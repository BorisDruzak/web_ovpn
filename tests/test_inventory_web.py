from __future__ import annotations

import importlib
import base64
from pathlib import Path

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


def _prepare_manual_asset_form(client: TestClient, monkeypatch, asset_type: str, parent_asset_id: str = ""):
    """Complete the required unsuccessful lookup before a test submits an asset card."""
    suffix = f"&parent_asset_id={parent_asset_id}" if parent_asset_id else ""
    discovery = client.get(f"/inventory/assets/new?asset_type={asset_type}{suffix}")
    monkeypatch.setattr("app.inventory.web.run_netctl", lambda args, timeout=None: {"hosts": []})
    lookup = client.post(
        "/inventory/assets/new/lookup",
        data={
            "csrf_token": _csrf(discovery.text),
            "asset_type": asset_type,
            "parent_asset_id": parent_asset_id,
            "identifier": f"manual-{asset_type.lower()}",
        },
        follow_redirects=False,
    )
    result = client.get(lookup.headers["location"])
    manual = client.post(
        "/inventory/assets/new/manual",
        data={
            "csrf_token": _csrf(result.text),
            "asset_type": asset_type,
            "parent_asset_id": parent_asset_id,
            "identifier": f"manual-{asset_type.lower()}",
        },
        follow_redirects=False,
    )
    assert manual.status_code == 303
    return client.get(manual.headers["location"])


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

    page = _prepare_manual_asset_form(client, monkeypatch, "PC")
    csrf = _csrf(page.text)
    pc = client.post(
        "/inventory/assets",
        data={"csrf_token": csrf, "asset_type": "PC", "custom_name": "BUH-PC-01"},
        follow_redirects=False,
    )
    assert pc.status_code == 303
    pc_id = pc.headers["location"].rsplit("/", 1)[-1]

    for asset_type, custom_name in (("MONITOR", "AOC 24B2X"), ("UPS", "Ippon")):
        page = _prepare_manual_asset_form(client, monkeypatch, asset_type, pc_id)
        csrf = _csrf(page.text)
        response = client.post(
            "/inventory/assets",
            data={"csrf_token": csrf, "asset_type": asset_type, "custom_name": custom_name, "parent_asset_id": pc_id},
            follow_redirects=False,
        )
        assert response.status_code == 303

    page = _prepare_manual_asset_form(client, monkeypatch, "PRINTER")
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


def test_mobile_inventory_rejects_blank_location_name(tmp_path, monkeypatch):
    """A blank location must never become an invisible selectable record."""
    client, csrf = _client(tmp_path, monkeypatch)

    response = client.post(
        "/inventory/locations",
        data={"csrf_token": csrf, "name": "   ", "comment": "Не должно сохраниться"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    page = client.get("/inventory")
    assert "Введите название локации" in page.text
    assert "Без названия" not in page.text


def test_mobile_inventory_offers_inline_location_and_unbound_device_types(tmp_path, monkeypatch):
    """Technicians can add a named location and any standalone device from the location screen."""
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post(
        "/inventory/locations",
        data={"csrf_token": csrf, "name": "ИТ отдел"},
        follow_redirects=False,
    ).status_code == 303

    page = client.get("/inventory")

    assert "+ Новая локация…" in page.text
    assert "СМЕНИТЬ / ДОБАВИТЬ ЛОКАЦИЮ" not in page.text
    assert "ВЫБРАТЬ ЛОКАЦИЮ" in page.text
    assert "Отдельное устройство на локации" in page.text
    assert "/inventory/assets/new?asset_type=MONITOR" in page.text
    assert "/inventory/assets/new?asset_type=PRINTER" in page.text


def test_mobile_inventory_keeps_new_location_form_hidden_until_requested(tmp_path, monkeypatch):
    """The inline new-location form must not take space until the selector requests it."""
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post("/inventory/locations", data={"csrf_token": csrf, "name": "219"}, follow_redirects=False).status_code == 303

    page = client.get("/inventory")
    css = Path("app/static/inventory.css").read_text(encoding="utf-8")

    assert 'id="new-location-form" hidden' in page.text
    assert ".inventory-mobile form[hidden] { display: none; }" in css


def test_mobile_asset_form_localizes_status_and_explains_mac_lookup(tmp_path, monkeypatch):
    """A saved device form presents Russian statuses and an explicit MAC lookup control."""
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post("/inventory/locations", data={"csrf_token": csrf, "name": "218"}, follow_redirects=False).status_code == 303
    page = _prepare_manual_asset_form(client, monkeypatch, "MONITOR")
    created = client.post(
        "/inventory/assets",
        data={"csrf_token": _csrf(page.text), "asset_type": "MONITOR", "custom_name": "AOC"},
        follow_redirects=False,
    )

    detail = client.get(created.headers["location"])

    assert "В эксплуатации" in detail.text
    assert "ПОИСК В СЕТИ" in detail.text
    assert "IP-адрес, MAC-адрес или hostname" in detail.text
    assert "AA:BB:CC:DD:EE:FF" in detail.text


def test_saved_mobile_asset_accepts_camera_photo(tmp_path, monkeypatch):
    """The phone capture control must persist a validated image after an asset exists."""
    monkeypatch.setenv("INVENTORY_PHOTO_ROOT", str(tmp_path / "photos"))
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post("/inventory/locations", data={"csrf_token": csrf, "name": "214"}, follow_redirects=False).status_code == 303
    page = _prepare_manual_asset_form(client, monkeypatch, "MONITOR")
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


def test_mobile_pc_form_persists_hardware_details(tmp_path, monkeypatch):
    """A mobile PC form must not discard RAM and OS while saving common asset fields."""
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "214"}, follow_redirects=False)
    page = _prepare_manual_asset_form(client, monkeypatch, "PC")
    created = client.post(
        "/inventory/assets",
        data={"csrf_token": _csrf(page.text), "asset_type": "PC", "custom_name": "PC-01", "os_name": "Windows 11", "ram_gb": "16"},
        follow_redirects=False,
    )
    asset_id = created.headers["location"].rsplit("/", 1)[-1]
    detail = client.get(f"/inventory/assets/{asset_id}")
    assert 'name="ram_gb"' in detail.text
    assert 'value="16"' in detail.text
    assert 'value="None"' not in detail.text


def test_mobile_pc_draft_saves_related_devices_in_one_submit(tmp_path, monkeypatch):
    """The first PC save must keep the technician's draft monitor instead of requiring a second pass."""
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "216"}, follow_redirects=False)
    page = _prepare_manual_asset_form(client, monkeypatch, "PC")
    created = client.post(
        "/inventory/assets",
        data={
            "csrf_token": _csrf(page.text),
            "asset_type": "PC",
            "custom_name": "PC-03",
            "related_devices_json": '[{"asset_type":"MONITOR","custom_name":"AOC 24"},{"asset_type":"PHONE","custom_name":"Yealink"}]',
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    home = client.get("/inventory")
    assert "PC-03" in home.text
    assert "AOC 24" in home.text
    assert "Yealink" in home.text


def test_mobile_asset_lookup_shows_editable_network_suggestions(tmp_path, monkeypatch):
    """The mobile form exposes read-only lookup output and lets the operator apply it deliberately."""
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "217"}, follow_redirects=False)
    page = _prepare_manual_asset_form(client, monkeypatch, "PC")
    created = client.post("/inventory/assets", data={"csrf_token": _csrf(page.text), "asset_type": "PC", "custom_name": "PC-04"}, follow_redirects=False)
    asset_id = created.headers["location"].rsplit("/", 1)[-1]
    monkeypatch.setattr("app.inventory.web.run_netctl", lambda args, timeout=None: {"hosts": [{"ip": "192.168.100.88", "hostname": "BUH-PC-04"}]})

    lookup = client.post(f"/inventory/assets/{asset_id}/lookup", data={"csrf_token": _csrf(client.get(f'/inventory/assets/{asset_id}').text), "identifier": "192.168.100.88"}, follow_redirects=False)
    assert lookup.status_code == 303
    detail = client.get(f"/inventory/assets/{asset_id}").text
    assert "BUH-PC-04" in detail
    assert "ПОДСТАВИТЬ" in detail


def test_new_mobile_asset_requires_discovery_and_prefills_collection_data(tmp_path, monkeypatch):
    """A new asset is saved only after collection, with discovered fields still editable."""
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post("/inventory/locations", data={"csrf_token": csrf, "name": "219"}, follow_redirects=False).status_code == 303

    discovery = client.get("/inventory/assets/new?asset_type=PC")
    assert "НАЙТИ УСТРОЙСТВО" in discovery.text
    assert 'name="custom_name"' not in discovery.text

    blocked = client.post(
        "/inventory/assets",
        data={"csrf_token": _csrf(discovery.text), "asset_type": "PC", "custom_name": "Недопустимо"},
        follow_redirects=False,
    )
    assert blocked.headers["location"] == "/inventory/assets/new?asset_type=PC"

    monkeypatch.setattr(
        "app.inventory.web.run_netctl",
        lambda args, timeout=None: {"hosts": [{"ip": "192.168.100.88", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "BUH-PC-04", "display_name": "Бухгалтерия ПК"}]},
    )
    lookup = client.post(
        "/inventory/assets/new/lookup",
        data={"csrf_token": _csrf(discovery.text), "asset_type": "PC", "identifier": "192.168.100.88"},
        follow_redirects=False,
    )
    assert lookup.status_code == 303

    form = client.get(lookup.headers["location"])
    assert "Данные сбора получены" in form.text
    assert "Результат: Найдено" in form.text
    assert "ПРОДОЛЖИТЬ ВРУЧНУЮ" not in form.text
    assert 'value="192.168.100.88"' in form.text
    assert 'value="AA:BB:CC:DD:EE:FF"' in form.text
    assert 'value="BUH-PC-04"' in form.text
    assert 'value="Бухгалтерия ПК"' in form.text


def test_new_mobile_asset_allows_manual_entry_only_after_unsuccessful_search(tmp_path, monkeypatch):
    """An unsuccessful valid lookup explicitly unlocks a blank editable asset form."""
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post("/inventory/locations", data={"csrf_token": csrf, "name": "220"}, follow_redirects=False).status_code == 303
    discovery = client.get("/inventory/assets/new?asset_type=PHONE")
    monkeypatch.setattr("app.inventory.web.run_netctl", lambda args, timeout=None: {"hosts": []})

    lookup = client.post(
        "/inventory/assets/new/lookup",
        data={"csrf_token": _csrf(discovery.text), "asset_type": "PHONE", "identifier": "missing-phone"},
        follow_redirects=False,
    )
    result = client.get(lookup.headers["location"])
    assert "ПРОДОЛЖИТЬ ВРУЧНУЮ" in result.text

    manual = client.post(
        "/inventory/assets/new/manual",
        data={"csrf_token": _csrf(result.text), "asset_type": "PHONE", "identifier": "missing-phone"},
        follow_redirects=False,
    )
    form = client.get(manual.headers["location"])
    assert "Ручное заполнение" in form.text
    assert 'name="custom_name"' in form.text
    assert 'value="missing-phone"' in form.text


def test_new_mobile_asset_prefills_nmap_operating_system(tmp_path, monkeypatch):
    """An Nmap fallback must expose its collected OS name in the editable PC card."""
    client, csrf = _client(tmp_path, monkeypatch)
    assert client.post("/inventory/locations", data={"csrf_token": csrf, "name": "221"}, follow_redirects=False).status_code == 303
    discovery = client.get("/inventory/assets/new?asset_type=PC")

    def netctl(args, timeout=None):
        if args[:2] == ["hosts", "list"]:
            return {"hosts": []}
        return {"fingerprint": {"nmap_version": "7.95", "ports": [], "os_matches": [{"name": "Windows 11 Pro", "accuracy": 95, "classes": []}]}}

    monkeypatch.setattr("app.inventory.web.run_netctl", netctl)
    lookup = client.post(
        "/inventory/assets/new/lookup",
        data={"csrf_token": _csrf(discovery.text), "asset_type": "PC", "identifier": "192.168.100.89"},
        follow_redirects=False,
    )

    form = client.get(lookup.headers["location"])
    assert "Источник: Nmap" in form.text
    assert 'value="Windows 11 Pro"' in form.text


def test_mobile_form_rejects_bad_identifier_without_server_error(tmp_path, monkeypatch):
    """A typo from a physical label must remain an editable form error, not a 500 response."""
    client, csrf = _client(tmp_path, monkeypatch)
    client.post("/inventory/locations", data={"csrf_token": csrf, "name": "218"}, follow_redirects=False)
    page = _prepare_manual_asset_form(client, monkeypatch, "PC")
    response = client.post(
        "/inventory/assets",
        data={"csrf_token": _csrf(page.text), "asset_type": "PC", "custom_name": "PC-05", "mac_address": "not-a-mac"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "invalid inventory identifier" in client.get("/inventory").text
