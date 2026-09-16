from __future__ import annotations

from sqlalchemy import inspect


def test_inventory_schema_allows_empty_location_and_assets(tmp_path, monkeypatch):
    """Changing inventory fields to required must reject this valid minimal capture."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory.sqlite'}")

    from app.db import get_engine, get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryLocation

    init_db()
    with get_sessionmaker()() as db:
        location = InventoryLocation()
        pc = InventoryAsset(asset_type=InventoryAssetType.PC)
        monitor = InventoryAsset(asset_type=InventoryAssetType.MONITOR)
        db.add_all((location, pc, monitor))
        db.commit()

        assert db.get(InventoryLocation, location.id).name is None
        assert db.get(InventoryAsset, pc.id).custom_name is None
        assert db.get(InventoryAsset, monitor.id).location_id is None

    tables = set(inspect(get_engine()).get_table_names())
    assert {
        "inventory_locations",
        "inventory_assets",
        "inventory_asset_identifiers",
        "inventory_asset_relations",
        "inventory_pc_details",
        "inventory_printer_details",
        "inventory_phone_details",
        "inventory_monitor_details",
        "inventory_ups_details",
        "inventory_observations",
        "inventory_sessions",
        "inventory_checks",
        "inventory_asset_photos",
        "inventory_location_photos",
    } <= tables
