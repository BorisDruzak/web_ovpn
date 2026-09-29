from datetime import datetime, timezone
from urllib.parse import quote

import pytest

from tests.test_inventory_web import _client


def _seed():
    from app.db import get_sessionmaker
    from app.inventory.models import (
        InventoryAsset, InventoryAssetType, InventoryLocation,
        InventoryAssetIdentifier, InventoryIdentifierType, InventoryObservationSource,
    )
    with get_sessionmaker()() as db:
        location = InventoryLocation(name="Бухгалтерия", comment="Второй этаж")
        db.add(location)
        db.flush()
        asset = InventoryAsset(asset_type=InventoryAssetType.PC, location_id=location.id,
            custom_name="Рабочий компьютер", assigned_person_name="Алёна Иванова",
            manufacturer="Lenovo", model="ThinkCentre", serial_number="SN-456",
            inventory_number="ИНВ-123", login_name="a.ivanova")
        other = InventoryAsset(asset_type=InventoryAssetType.MONITOR, custom_name="Чужой монитор")
        deleted = InventoryAsset(asset_type=InventoryAssetType.PC, custom_name="Удалённый компьютер",
            deleted_at=datetime.now(timezone.utc))
        db.add_all([asset, other, deleted])
        db.flush()
        for kind, value, current in [
            (InventoryIdentifierType.IP, "192.0.2.24", True),
            (InventoryIdentifierType.MAC, "AA:BB:CC:DD:EE:FF", True),
            (InventoryIdentifierType.HOSTNAME, "BUH-PC-24", True),
            (InventoryIdentifierType.IP, "198.51.100.99", False),
        ]:
            db.add(InventoryAssetIdentifier(asset_id=asset.id, identifier_type=kind,
                value=value, normalized_value=value.lower(),
                source=InventoryObservationSource.MANUAL, is_current=current))
        db.commit()
        return asset.id, location.id


@pytest.mark.parametrize("query", ["РАБОЧИЙ", "алена", "lenovo", "thinkcentre", "sn-456",
    "инв-123", "a.ivanova", "192.0.2.24", "AA-BB-CC-DD-EE-FF", "aabbccddeeff",
    "buh-pc", "БУХГАЛТЕРИЯ", "второй этаж", "Иванова Lenovo"])
def test_global_search_finds_asset_fields_and_current_identifiers(tmp_path, monkeypatch, query):
    client, _ = _client(tmp_path, monkeypatch)
    asset_id, _ = _seed()
    page = client.get("/inventory", params={"q": query})
    assert page.status_code == 200
    assert f'href="/inventory/assets/{asset_id}?' in page.text
    assert "Чужой монитор" not in page.text
    assert "Найдено устройств: 1" in page.text
    assert "Бухгалтерия" in page.text


@pytest.mark.parametrize("query", ["198.51.100.99", "Удалённый компьютер", "%", "_", "несуществующий"])
def test_search_excludes_deleted_and_historical_identifiers_and_literal_wildcards(tmp_path, monkeypatch, query):
    client, _ = _client(tmp_path, monkeypatch)
    _seed()
    page = client.get("/inventory", params={"q": query})
    assert "Найдено устройств: 0" in page.text
    assert "Ничего не найдено" in page.text


def test_search_context_empty_query_and_html_escaping(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    asset_id, _ = _seed()
    empty = client.get("/inventory", params={"q": "  "})
    assert "Бухгалтерия" in empty.text
    assert "Найдено устройств" not in empty.text
    found = client.get("/inventory", params={"q": "Lenovo"})
    assert 'return_url=/inventory%3Fq%3DLenovo' in found.text
    card = client.get(f"/inventory/assets/{asset_id}?return_url={quote('/inventory?q=Lenovo', safe='')}")
    assert 'href="/inventory?q=Lenovo"' in card.text
    escaped = client.get("/inventory", params={"q": '<script>alert("x")</script>'})
    assert '<script>alert("x")</script>' not in escaped.text
    assert "&lt;script&gt;" in escaped.text
    assert client.get("/inventory", params={"q": "x" * 300}).status_code == 200


def test_search_paginates_without_duplicates(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset, InventoryAssetType
    with get_sessionmaker()() as db:
        db.add_all(InventoryAsset(asset_type=InventoryAssetType.PC, custom_name=f"Тест {i:03}") for i in range(55))
        db.commit()
    first = client.get("/inventory", params={"q": "тест"})
    second = client.get("/inventory", params={"q": "тест", "page": 2})
    assert "Найдено устройств: 55" in first.text
    assert "Тест 000" in first.text and "Тест 050" not in first.text
    assert "Тест 050" in second.text and "Тест 000" not in second.text
    assert "Страница 2 из 2" in second.text
    assert "Страница 2 из 2" in client.get("/inventory", params={"q": "тест", "page": 999}).text
