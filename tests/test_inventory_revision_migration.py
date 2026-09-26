"""Upgrade a synthetic pre-revision store twice without changing its facts."""
from sqlalchemy import text
from tests.test_inventory_api import _client


def test_revision_migration_preserves_card_and_is_repeatable(tmp_path, monkeypatch):
    client, headers = _client(tmp_path, monkeypatch)
    asset = client.post("/api/v1/inventory/assets", headers=headers,
        json={"asset_type":"PC", "custom_name":"Synthetic legacy card"}).json()["data"]
    from app.db import get_engine, init_db, get_sessionmaker
    from app.inventory.models import InventoryAsset
    engine = get_engine()
    with engine.begin() as connection:
        names = connection.scalars(text("SELECT name FROM sqlite_master WHERE type='trigger' AND sql LIKE '%manual_revision%'"))
        for name in list(names):
            connection.exec_driver_sql('DROP TRIGGER "' + name.replace('"', '""') + '"')
        connection.exec_driver_sql("ALTER TABLE inventory_assets DROP COLUMN manual_revision")
    init_db()
    init_db()
    with get_sessionmaker()() as db:
        restored = db.get(InventoryAsset, asset["id"])
        assert restored.custom_name == "Synthetic legacy card"
        assert restored.manual_revision == 1
        assert db.query(InventoryAsset).count() == 1
