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


def test_assignment_migration_preserves_legacy_names_and_guards_new_facts(tmp_path, monkeypatch):
    from pytest import raises
    from sqlalchemy.exc import IntegrityError

    from app.db import get_engine, init_db
    from app.inventory.assignment import ASSIGNMENT_FIELDS

    client, headers = _client(tmp_path, monkeypatch)
    api = "/api/v1/inventory/assets"
    cards = [
        client.post(api, headers=headers, json={"asset_type": "PC", "assigned_person_name": name}).json()["data"]
        for name in ("Примеров  Иван", "Образцов И. И.")
    ]
    asset_ids = [card["id"] for card in cards]
    engine = get_engine()
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TRIGGER inventory_manual_asset_revision")
        connection.exec_driver_sql("DROP TRIGGER inventory_deleted_facts_immutable")
        for field in ASSIGNMENT_FIELDS:
            connection.exec_driver_sql(f"ALTER TABLE inventory_assets DROP COLUMN {field}")
        connection.execute(text("UPDATE inventory_assets SET deleted_at=CURRENT_TIMESTAMP WHERE id=:id"), {"id": asset_ids[1]})
    init_db()
    init_db()
    with engine.begin() as connection:
        rows = [connection.execute(text("""
            SELECT assigned_person_name, assigned_last_name, assigned_first_name, assigned_patronymic,
                assigned_department, manual_revision FROM inventory_assets WHERE id=:id
        """), {"id": asset_id}).one() for asset_id in asset_ids]
        assert rows == [
            ("Примеров  Иван", "Примеров", "Иван", None, None, cards[0]["manual_revision"]),
            ("Образцов И. И.", None, None, None, None, cards[1]["manual_revision"]),
        ]
        update_department = text("UPDATE inventory_assets SET assigned_department=:department WHERE id=:id")
        connection.execute(update_department, {"department": "Архивный отдел", "id": asset_ids[0]})
        assert connection.execute(text("SELECT manual_revision FROM inventory_assets WHERE id=:id"),
            {"id": asset_ids[0]}).scalar_one() == cards[0]["manual_revision"] + 1
        with raises(IntegrityError, match="deleted inventory facts are immutable"):
            connection.execute(update_department, {"department": "Архивный отдел", "id": asset_ids[1]})
