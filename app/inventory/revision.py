"""Atomic manual-fact revisions for the application's SQLite inventory store."""
from sqlalchemy import inspect, text, update
from sqlalchemy.orm import Session

from .models import InventoryAsset


class InventoryRevisionConflict(ValueError):
    pass


class InventoryRevisionRequired(InventoryRevisionConflict):
    pass


def claim_revision(db: Session, asset: InventoryAsset, expected: int | None) -> None:
    if expected is None:
        raise InventoryRevisionRequired("Откройте актуальную карточку: требуется её ревизия")
    result = db.execute(update(InventoryAsset).where(
        InventoryAsset.id == asset.id, InventoryAsset.manual_revision == expected,
    ).values(manual_revision=InventoryAsset.manual_revision + 1)
      .execution_options(synchronize_session=False))
    if result.rowcount != 1:
        raise InventoryRevisionConflict("Карточка изменена другим пользователем. Ввод сохранён; сравните значения перед повторным сохранением.")
    db.refresh(asset)


def migrate_revisions(engine) -> None:
    if engine.dialect.name != "sqlite":
        return  # Current supported deployment uses SQLite, like relation guards.
    columns = {column["name"] for column in inspect(engine).get_columns("inventory_assets")}
    with engine.begin() as connection:
        if "manual_revision" not in columns:
            connection.execute(text("ALTER TABLE inventory_assets ADD COLUMN manual_revision INTEGER NOT NULL DEFAULT 1"))
        # DB-level guards cover child facts even when written outside the web
        # service. Observations and telemetry are deliberately absent.
        fields = ("asset_type", "location_id", "custom_name", "manufacturer", "model", "serial_number", "inventory_number", "status", "assigned_person_name", "login_name", "description", "last_verified_at")
        changes = " OR ".join(f"OLD.{field} IS NOT NEW.{field}" for field in fields)
        connection.execute(text(f"""CREATE TRIGGER IF NOT EXISTS inventory_manual_asset_revision
            AFTER UPDATE OF {','.join(fields)} ON inventory_assets WHEN {changes}
            BEGIN UPDATE inventory_assets SET manual_revision=manual_revision+1 WHERE id=NEW.id; END"""))
        tables = ["inventory_pc_details", "inventory_monitor_details", "inventory_printer_details", "inventory_phone_details", "inventory_ups_details", "inventory_asset_relations", "inventory_asset_identifiers"]
        for table in tables:
            for operation in ("INSERT", "UPDATE", "DELETE"):
                row = "OLD" if operation == "DELETE" else "NEW"
                ids = f"{row}.parent_asset_id,{row}.child_asset_id" if table.endswith("relations") else f"{row}.asset_id"
                conditions = []
                if table.endswith("identifiers"):
                    manual = f"{row}.source = 'MANUAL'"
                    if operation == "UPDATE":
                        manual = f"({manual} OR OLD.source = 'MANUAL')"
                    conditions.append(manual)
                if operation == "UPDATE":
                    columns = [column["name"] for column in inspect(engine).get_columns(table)
                        if column["name"] not in {"first_seen_at", "last_seen_at"}]
                    conditions.append("(" + " OR ".join(f"OLD.{column} IS NOT NEW.{column}" for column in columns) + ")")
                    ids += ",OLD.parent_asset_id,OLD.child_asset_id" if table.endswith("relations") else ",OLD.asset_id"
                condition = "WHEN " + " AND ".join(conditions) if conditions else ""
                connection.execute(text(f"""CREATE TRIGGER IF NOT EXISTS {table}_manual_revision_{operation.lower()}
                    AFTER {operation} ON {table} {condition}
                    BEGIN UPDATE inventory_assets SET manual_revision=manual_revision+1 WHERE id IN ({ids}); END"""))
