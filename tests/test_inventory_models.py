from __future__ import annotations

from sqlalchemy import inspect, text


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
        "inventory_identifier_sync_runs",
    } <= tables


def test_init_db_migrates_legacy_printer_details_with_connection_type(tmp_path, monkeypatch):
    """Production databases created before the connection field must upgrade in place."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory-legacy.sqlite'}")

    from app.db import get_engine, init_db, reset_engine_cache

    reset_engine_cache()
    with get_engine().begin() as connection:
        connection.execute(text("CREATE TABLE inventory_printer_details (asset_id VARCHAR(36) PRIMARY KEY)"))

    init_db()

    columns = {column["name"] for column in inspect(get_engine()).get_columns("inventory_printer_details")}
    assert "connection_type" in columns


def test_init_db_migrates_pc_columns_transfers_notes_and_normalizes_details(tmp_path, monkeypatch):
    """A deployed pre-v2 SQLite database must upgrade without rebuilding its inventory tables."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory-legacy.sqlite'}")

    from app.db import Base, get_engine, init_db, reset_engine_cache
    from app.inventory.models import InventoryAsset

    reset_engine_cache()
    with get_engine().begin() as connection:
        Base.metadata.create_all(bind=connection, tables=[InventoryAsset.__table__])
        connection.execute(text("ALTER TABLE inventory_assets ADD COLUMN notes TEXT"))
        connection.execute(
            text(
                "CREATE TABLE inventory_pc_details ("
                "asset_id VARCHAR(36) PRIMARY KEY, os_name VARCHAR(255), "
                "cpu_model VARCHAR(255), cpu_generation VARCHAR(100), "
                "ram_type VARCHAR(100), ram_gb INTEGER, storage_type VARCHAR(100), storage_gb INTEGER)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO inventory_assets "
                "(id, asset_type, description, notes, created_at, updated_at) "
                "VALUES ('pc-1', 'PC', 'Основное описание', 'Старый комментарий', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO inventory_pc_details "
                "(asset_id, os_name, cpu_model, cpu_generation, ram_type) "
                "VALUES ('pc-1', 'Win10', '11400', 'I5', 'Ddr4')"
            )
        )

    init_db()
    init_db()

    with get_engine().connect() as connection:
        columns = {column["name"] for column in inspect(get_engine()).get_columns("inventory_pc_details")}
        asset = connection.execute(
            text("SELECT description, notes FROM inventory_assets WHERE id = 'pc-1'")
        ).mappings().one()
        details = connection.execute(
            text("SELECT os_name, os_version, cpu_model, cpu_generation, ram_type FROM inventory_pc_details WHERE asset_id = 'pc-1'")
        ).mappings().one()

    assert "os_version" in columns
    assert asset == {
        "description": "Основное описание\n\nКомментарий: Старый комментарий",
        "notes": None,
    }
    assert details == {
        "os_name": "Windows",
        "os_version": "10",
        "cpu_model": "Intel",
        "cpu_generation": "i5 11400",
        "ram_type": "DDR4",
    }


def test_init_db_transfers_note_into_blank_description(tmp_path, monkeypatch):
    """A comment is the description when the physical card did not have one yet."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory-notes.sqlite'}")

    from app.db import Base, get_engine, init_db, reset_engine_cache
    from app.inventory.models import InventoryAsset

    reset_engine_cache()
    with get_engine().begin() as connection:
        Base.metadata.create_all(bind=connection, tables=[InventoryAsset.__table__])
        connection.execute(text("ALTER TABLE inventory_assets ADD COLUMN notes TEXT"))
        connection.execute(
            text(
                "INSERT INTO inventory_assets "
                "(id, asset_type, description, notes, created_at, updated_at) "
                "VALUES ('printer-1', 'PRINTER', '', 'USB принтер', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )

    init_db()

    with get_engine().connect() as connection:
        row = connection.execute(
            text("SELECT description, notes FROM inventory_assets WHERE id = 'printer-1'")
        ).mappings().one()
    assert row == {"description": "USB принтер", "notes": None}
