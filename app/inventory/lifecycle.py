"""Local historical card lifecycle; never issue provider/network commands."""
from sqlalchemy import event, inspect, select, text, update
from sqlalchemy.orm import Session, with_loader_criteria

from ..models import utcnow
from .models import (InventoryAsset, InventoryAssetIdentifier, InventoryAssetRelation, InventoryExternalBinding,
    InventoryExternalBindingStatus, InventoryLocation, InventoryNetctlBinding)
from .revision import InventoryRevisionConflict, InventoryRevisionRequired


@event.listens_for(Session, "do_orm_execute")
def hide_deleted_cards(state):
    if state.is_select and not state.execution_options.get("inventory_history", False):
        state.statement = state.statement.options(with_loader_criteria(
            InventoryAsset, lambda cls: cls.deleted_at.is_(None), include_aliases=True),
            with_loader_criteria(InventoryAssetIdentifier,
                InventoryAssetIdentifier.asset_id.in_(select(InventoryAsset.id).where(InventoryAsset.deleted_at.is_(None))),
                include_aliases=True))


def historical_asset(db, asset_id):
    return db.scalar(select(InventoryAsset).where(InventoryAsset.id == asset_id)
        .execution_options(inventory_history=True, populate_existing=True))


def lock_active_asset(db, asset_id):
    """Serialize local file mutations with lifecycle without telemetry conflicts."""
    result = db.execute(update(InventoryAsset).where(InventoryAsset.id == asset_id,
        InventoryAsset.deleted_at.is_(None)).values(manual_revision=InventoryAsset.manual_revision)
        .execution_options(synchronize_session=False))
    if result.rowcount != 1:
        raise InventoryRevisionConflict("Карточка уже удалена. Историческое фото сохранено.")


def _require_revision(expected_revision):
    if type(expected_revision) is not int or expected_revision < 1:
        raise InventoryRevisionRequired("Откройте актуальную карточку: требуется её ревизия")


def _claim(db, asset, expected_revision, *, deleted):
    _require_revision(expected_revision)
    result = db.execute(update(InventoryAsset).where(InventoryAsset.id == asset.id,
        InventoryAsset.manual_revision == expected_revision,
        InventoryAsset.deleted_at.is_not(None) if deleted else InventoryAsset.deleted_at.is_(None)
    ).values(manual_revision=InventoryAsset.manual_revision + 1)
        .execution_options(synchronize_session=False))
    if result.rowcount != 1:
        raise InventoryRevisionConflict("Карточка изменилась. Проверьте её состояние перед повторным действием.")
    db.refresh(asset)


def soft_delete(db, asset_id, *, expected_revision, actor, reason):
    _require_revision(expected_revision)
    asset = historical_asset(db, asset_id)
    if asset is None:
        raise InventoryRevisionConflict("Карточка не найдена")
    # A repeat cannot mutate facts or end somebody else's newly created binding.
    if asset.deleted_at is not None:
        return asset, False
    reason = str(reason or "").strip()
    if not reason or len(reason) > 2000:
        raise ValueError("Укажите причину удаления (до 2000 символов)")
    _claim(db, asset, expected_revision, deleted=False)
    now = utcnow()
    for relation in db.scalars(select(InventoryAssetRelation).where(
        (InventoryAssetRelation.parent_asset_id == asset_id) | (InventoryAssetRelation.child_asset_id == asset_id),
        InventoryAssetRelation.ended_at.is_(None))):
        relation.ended_at = now
    for binding in db.scalars(select(InventoryExternalBinding).where(
        InventoryExternalBinding.asset_id == asset_id, InventoryExternalBinding.ended_at.is_(None))):
        binding.status = InventoryExternalBindingStatus.ENDED
        binding.ended_at = now
        binding.updated_at = now
        binding.evidence_json = {**binding.evidence_json, "ended_by":str(actor), "end_reason":"inventory_deleted"}
    # End relationships while the parent still exists in the active domain.
    for binding in db.scalars(select(InventoryNetctlBinding).where(
        InventoryNetctlBinding.asset_id == asset_id, InventoryNetctlBinding.ended_at.is_(None))):
        binding.status = InventoryExternalBindingStatus.ENDED
        binding.ended_at, binding.ended_by, binding.end_reason = now, str(actor), "inventory_deleted"
    db.flush()
    asset.deleted_at, asset.deleted_by, asset.deletion_reason = now, str(actor), reason
    db.flush()
    return asset, True


def restore(db, asset_id, *, expected_revision, actor):
    _require_revision(expected_revision)
    asset = historical_asset(db, asset_id)
    if asset is None:
        raise InventoryRevisionConflict("Карточка не найдена")
    if asset.deleted_at is None:
        return asset, False
    if asset.location_id is not None and db.get(InventoryLocation, asset.location_id) is None:
        raise ValueError("Локация недоступна. Карточка сохранена в удалённых; восстановите локацию сначала.")
    _claim(db, asset, expected_revision, deleted=True)
    asset.deleted_at = None
    asset.restored_at, asset.restored_by = utcnow(), str(actor)
    # Retain deletion attribution and ended relationships; audit records every cycle.
    db.flush()
    return asset, True


def migrate_lifecycle(engine):
    if engine.dialect.name != "sqlite":
        return
    columns = {column["name"] for column in inspect(engine).get_columns("inventory_assets")}
    with engine.begin() as connection:
        for name, sql_type in (("deleted_at","DATETIME"), ("deleted_by","VARCHAR(120)"),
            ("deletion_reason","TEXT"), ("restored_at","DATETIME"), ("restored_by","VARCHAR(120)")):
            if name not in columns:
                connection.execute(text(f"ALTER TABLE inventory_assets ADD COLUMN {name} {sql_type}"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_inventory_assets_deleted_at ON inventory_assets(deleted_at)"))
        connection.execute(text("""CREATE TRIGGER IF NOT EXISTS inventory_netctl_identity_immutable
            BEFORE UPDATE ON inventory_netctl_bindings WHEN OLD.asset_id IS NOT NEW.asset_id OR
                OLD.source IS NOT NEW.source OR OLD.network_key IS NOT NEW.network_key
            BEGIN SELECT RAISE(ABORT, 'netctl relation identity is immutable; end and compare again'); END"""))
        connection.execute(text("""CREATE TRIGGER IF NOT EXISTS inventory_netctl_ended_observation_immutable
            BEFORE UPDATE ON inventory_netctl_bindings WHEN OLD.ended_at IS NOT NULL AND (
                OLD.observation_json IS NOT NEW.observation_json OR
                OLD.observed_snapshot_id IS NOT NEW.observed_snapshot_id OR OLD.observed_at IS NOT NEW.observed_at)
            BEGIN SELECT RAISE(ABORT, 'ended netctl observation is historical'); END"""))
        # These guards also protect stale identity-map objects and direct SQL
        # writers. No global BEGIN hook or reader transaction is introduced.
        for table in ("inventory_pc_details", "inventory_monitor_details", "inventory_printer_details",
            "inventory_phone_details", "inventory_ups_details", "inventory_asset_identifiers", "inventory_observations", "inventory_checks",
            "inventory_asset_photos", "inventory_endpoint_state"):
            for operation in ("INSERT", "UPDATE"):
                connection.execute(text(f"""CREATE TRIGGER IF NOT EXISTS {table}_active_asset_{operation.lower()}
                    BEFORE {operation} ON {table} WHEN NEW.asset_id IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM inventory_assets WHERE id=NEW.asset_id AND deleted_at IS NULL)
                    BEGIN SELECT RAISE(ABORT, 'inventory asset is deleted'); END"""))
        for operation in ("INSERT", "UPDATE"):
            connection.execute(text(f"""CREATE TRIGGER IF NOT EXISTS inventory_netctl_active_asset_{operation.lower()}
                BEFORE {operation} ON inventory_netctl_bindings WHEN NEW.ended_at IS NULL AND NOT EXISTS (
                    SELECT 1 FROM inventory_assets WHERE id=NEW.asset_id AND deleted_at IS NULL)
                BEGIN SELECT RAISE(ABORT, 'inventory netctl binding contains deleted asset'); END"""))
            connection.execute(text(f"""CREATE TRIGGER IF NOT EXISTS inventory_relation_active_assets_{operation.lower()}
                BEFORE {operation} ON inventory_asset_relations WHEN NEW.ended_at IS NULL AND (
                    NOT EXISTS (SELECT 1 FROM inventory_assets WHERE id=NEW.parent_asset_id AND deleted_at IS NULL) OR
                    NOT EXISTS (SELECT 1 FROM inventory_assets WHERE id=NEW.child_asset_id AND deleted_at IS NULL))
                BEGIN SELECT RAISE(ABORT, 'inventory relation contains deleted asset'); END"""))
            connection.execute(text(f"""CREATE TRIGGER IF NOT EXISTS inventory_binding_active_asset_{operation.lower()}
                BEFORE {operation} ON inventory_external_bindings WHEN NEW.ended_at IS NULL AND NOT EXISTS (
                    SELECT 1 FROM inventory_assets WHERE id=NEW.asset_id AND deleted_at IS NULL)
                BEGIN SELECT RAISE(ABORT, 'inventory binding contains deleted asset'); END"""))
        fields = ("asset_type", "location_id", "custom_name", "manufacturer", "model", "serial_number",
            "inventory_number", "status", "assigned_person_name", "login_name", "description", "last_verified_at")
        changes = " OR ".join(f"OLD.{field} IS NOT NEW.{field}" for field in fields)
        connection.execute(text(f"""CREATE TRIGGER IF NOT EXISTS inventory_deleted_facts_immutable
            BEFORE UPDATE ON inventory_assets WHEN OLD.deleted_at IS NOT NULL AND ({changes})
            BEGIN SELECT RAISE(ABORT, 'deleted inventory facts are immutable'); END"""))
        connection.execute(text("""CREATE TRIGGER IF NOT EXISTS inventory_deleted_photo_retained
            BEFORE DELETE ON inventory_asset_photos WHEN EXISTS (
                SELECT 1 FROM inventory_assets WHERE id=OLD.asset_id AND deleted_at IS NOT NULL)
            BEGIN SELECT RAISE(ABORT, 'deleted inventory photo is historical'); END"""))
