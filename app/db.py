from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from typing import Iterator

from sqlalchemy import DateTime, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from .config import get_settings, reset_settings_cache


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator[datetime]):
    """Persist datetimes in UTC and always return an aware UTC value."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


@lru_cache(maxsize=1)
def get_engine():
    settings = get_settings()
    kwargs = {}
    if settings.database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(settings.database_url, future=True, pool_pre_ping=True, **kwargs)


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False, future=True)


def reset_engine_cache() -> None:
    get_sessionmaker.cache_clear()
    get_engine.cache_clear()
    reset_settings_cache()


_TRANSFER_ASSET_NOTES = text(
    """
    UPDATE inventory_assets
    SET description = CASE
        WHEN description IS NULL OR trim(description) = '' THEN notes
        ELSE description || char(10) || char(10) || 'Комментарий: ' || notes
    END,
    notes = NULL
    WHERE notes IS NOT NULL AND trim(notes) <> ''
    """
)

_NORMALIZE_DUPLICATE_INVENTORY_SYNC_SUCCESSES = text(
    """
    WITH ranked AS (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY snapshot_id
                   ORDER BY finished_at DESC, started_at DESC, id DESC
               ) AS row_number
        FROM inventory_identifier_sync_runs
        WHERE status = 'success' AND snapshot_id IS NOT NULL
    )
    UPDATE inventory_identifier_sync_runs
    SET status = 'skipped',
        failure_reason = 'superseded duplicate success during migration'
    WHERE id IN (SELECT id FROM ranked WHERE row_number > 1)
    """
)

_CREATE_INVENTORY_SYNC_SUCCESS_INDEX = text(
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_identifier_sync_success_snapshot "
    "ON inventory_identifier_sync_runs (snapshot_id) WHERE status = 'success'"
)


_NORMALIZE_DUPLICATE_ENDPOINT_CONFIRMED_ASSETS = text(
    """
    WITH ranked AS (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY asset_id, source
                   ORDER BY last_verified_at DESC, updated_at DESC, created_at DESC, id DESC
               ) AS row_number
        FROM inventory_external_bindings
        WHERE status = 'confirmed' AND ended_at IS NULL
    )
    UPDATE inventory_external_bindings
    SET status = 'replaced',
        ended_at = COALESCE(last_verified_at, updated_at, created_at, CURRENT_TIMESTAMP)
    WHERE id IN (SELECT id FROM ranked WHERE row_number > 1)
    """
)

_NORMALIZE_DUPLICATE_ENDPOINT_CONFIRMED_DEVICES = text(
    """
    WITH ranked AS (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY source, external_id
                   ORDER BY last_verified_at DESC, updated_at DESC, created_at DESC, id DESC
               ) AS row_number
        FROM inventory_external_bindings
        WHERE status = 'confirmed' AND ended_at IS NULL
    )
    UPDATE inventory_external_bindings
    SET status = 'replaced',
        ended_at = COALESCE(last_verified_at, updated_at, created_at, CURRENT_TIMESTAMP)
    WHERE id IN (SELECT id FROM ranked WHERE row_number > 1)
    """
)

_NORMALIZE_DUPLICATE_ENDPOINT_CANDIDATES = text(
    """
    WITH ranked AS (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY asset_id, source, external_id
                   ORDER BY last_verified_at DESC, updated_at DESC, created_at DESC, id DESC
               ) AS row_number
        FROM inventory_external_bindings
        WHERE status = 'candidate' AND ended_at IS NULL
    )
    UPDATE inventory_external_bindings
    SET status = 'ended',
        ended_at = COALESCE(last_verified_at, updated_at, created_at, CURRENT_TIMESTAMP)
    WHERE id IN (SELECT id FROM ranked WHERE row_number > 1)
    """
)

_CREATE_ENDPOINT_CONFIRMED_ASSET_INDEX = text(
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_endpoint_confirmed_asset "
    "ON inventory_external_bindings (asset_id, source) "
    "WHERE status = 'confirmed' AND ended_at IS NULL"
)

_CREATE_ENDPOINT_CONFIRMED_DEVICE_INDEX = text(
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_endpoint_confirmed_device "
    "ON inventory_external_bindings (source, external_id) "
    "WHERE status = 'confirmed' AND ended_at IS NULL"
)

_CREATE_ENDPOINT_ACTIVE_CANDIDATE_INDEX = text(
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_endpoint_active_candidate "
    "ON inventory_external_bindings (asset_id, source, external_id) "
    "WHERE status = 'candidate' AND ended_at IS NULL"
)

_CREATE_ENDPOINT_BINDING_PC_INSERT_TRIGGER = text(
    """
    CREATE TRIGGER IF NOT EXISTS ck_inventory_endpoint_binding_pc_insert
    BEFORE INSERT ON inventory_external_bindings
    FOR EACH ROW
    WHEN NOT EXISTS (
        SELECT 1 FROM inventory_assets
        WHERE id = NEW.asset_id AND asset_type = 'PC'
    )
    BEGIN
        SELECT RAISE(ABORT, 'inventory external binding requires a PC asset');
    END
    """
)

_CREATE_ENDPOINT_BINDING_PC_UPDATE_TRIGGER = text(
    """
    CREATE TRIGGER IF NOT EXISTS ck_inventory_endpoint_binding_pc_update
    BEFORE UPDATE OF asset_id ON inventory_external_bindings
    FOR EACH ROW
    WHEN NOT EXISTS (
        SELECT 1 FROM inventory_assets
        WHERE id = NEW.asset_id AND asset_type = 'PC'
    )
    BEGIN
        SELECT RAISE(ABORT, 'inventory external binding requires a PC asset');
    END
    """
)

_CREATE_ENDPOINT_BOUND_ASSET_PC_TRIGGER = text(
    """
    CREATE TRIGGER IF NOT EXISTS ck_inventory_endpoint_bound_asset_pc
    BEFORE UPDATE OF asset_type ON inventory_assets
    FOR EACH ROW
    WHEN NEW.asset_type <> 'PC' AND EXISTS (
        SELECT 1 FROM inventory_external_bindings
        WHERE asset_id = OLD.id
    )
    BEGIN
        SELECT RAISE(ABORT, 'an Endpoint-bound inventory asset must remain a PC');
    END
    """
)

_CREATE_ENDPOINT_OBSERVATION_BINDING_INDEX = text(
    "CREATE INDEX IF NOT EXISTS ix_inventory_observations_binding_id "
    "ON inventory_observations (binding_id)"
)

_CREATE_ENDPOINT_OBSERVATION_DEVICE_INDEX = text(
    "CREATE INDEX IF NOT EXISTS ix_inventory_observations_endpoint_device_id "
    "ON inventory_observations (endpoint_device_id)"
)


def _prepare_inventory_sync_claim_index(engine) -> None:
    """Normalize legacy success races before metadata creates the SQLite partial index."""
    if engine.dialect.name != "sqlite":
        return
    if "inventory_identifier_sync_runs" not in inspect(engine).get_table_names():
        return
    with engine.begin() as connection:
        connection.execute(_NORMALIZE_DUPLICATE_INVENTORY_SYNC_SUCCESSES)
        connection.execute(_CREATE_INVENTORY_SYNC_SUCCESS_INDEX)


def init_inventory_identifier_sync_schema() -> None:
    """Prepare only the inventory sync ledger required by the worker process."""
    from .inventory.models import InventoryIdentifierSyncRun

    engine = get_engine()
    _prepare_inventory_sync_claim_index(engine)
    InventoryIdentifierSyncRun.__table__.create(bind=engine, checkfirst=True)


def _prepare_inventory_endpoint_constraints(engine) -> None:
    """Prepare only Endpoint binding constraints and observation lookup indexes."""
    if engine.dialect.name != "sqlite":
        return
    table_names = set(inspect(engine).get_table_names())
    with engine.begin() as connection:
        if "inventory_external_bindings" in table_names:
            connection.execute(_NORMALIZE_DUPLICATE_ENDPOINT_CONFIRMED_ASSETS)
            connection.execute(_NORMALIZE_DUPLICATE_ENDPOINT_CONFIRMED_DEVICES)
            connection.execute(_NORMALIZE_DUPLICATE_ENDPOINT_CANDIDATES)
            connection.execute(_CREATE_ENDPOINT_CONFIRMED_ASSET_INDEX)
            connection.execute(_CREATE_ENDPOINT_CONFIRMED_DEVICE_INDEX)
            connection.execute(_CREATE_ENDPOINT_ACTIVE_CANDIDATE_INDEX)
            if "inventory_assets" in table_names:
                connection.execute(_CREATE_ENDPOINT_BINDING_PC_INSERT_TRIGGER)
                connection.execute(_CREATE_ENDPOINT_BINDING_PC_UPDATE_TRIGGER)
                connection.execute(_CREATE_ENDPOINT_BOUND_ASSET_PC_TRIGGER)
        if "inventory_observations" in table_names:
            observation_columns = {
                column["name"]
                for column in inspect(engine).get_columns("inventory_observations")
            }
            if "binding_id" in observation_columns:
                connection.execute(_CREATE_ENDPOINT_OBSERVATION_BINDING_INDEX)
            if "endpoint_device_id" in observation_columns:
                connection.execute(_CREATE_ENDPOINT_OBSERVATION_DEVICE_INDEX)


def init_inventory_endpoint_schema() -> None:
    """Prepare only the Inventory Endpoint tables required by the sync worker."""
    from .inventory.models import (
        InventoryEndpointState,
        InventoryEndpointSyncControl,
        InventoryExternalBinding,
    )

    engine = get_engine()
    Base.metadata.create_all(
        bind=engine,
        tables=[
            InventoryExternalBinding.__table__,
            InventoryEndpointState.__table__,
            InventoryEndpointSyncControl.__table__,
        ],
    )
    _migrate_inventory_endpoint_schema(engine)


def _migrate_inventory_endpoint_schema(engine) -> None:
    """Apply only additive Inventory Endpoint migration work."""
    inspector = inspect(engine)
    if "inventory_endpoint_state" in inspector.get_table_names():
        columns = {
            column["name"]
            for column in inspector.get_columns("inventory_endpoint_state")
        }
        missing_columns = {
            "inventory_snapshot_id": "VARCHAR(255)",
            "session_snapshot_id": "VARCHAR(255)",
            "inventory_semantic_hash": "VARCHAR(64)",
            "session_semantic_hash": "VARCHAR(64)",
        }
        with engine.begin() as connection:
            for column_name, column_type in missing_columns.items():
                if column_name not in columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE inventory_endpoint_state "
                            f"ADD COLUMN {column_name} {column_type}"
                        )
                    )
    if "inventory_observations" in inspector.get_table_names():
        columns = {
            column["name"]
            for column in inspector.get_columns("inventory_observations")
        }
        missing_columns = {
            "binding_id": "VARCHAR(36)",
            "endpoint_device_id": "VARCHAR(255)",
            "profile": "VARCHAR(32)",
            "snapshot_id": "VARCHAR(255)",
            "semantic_hash": "VARCHAR(64)",
            "collected_at": "DATETIME",
        }
        with engine.begin() as connection:
            for column_name, column_type in missing_columns.items():
                if column_name not in columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE inventory_observations "
                            f"ADD COLUMN {column_name} {column_type}"
                        )
                    )
    _prepare_inventory_endpoint_constraints(engine)


def _migrate_inventory_schema(engine) -> None:
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    with engine.begin() as connection:
        if "web_users" in table_names:
            columns = {column["name"] for column in inspector.get_columns("web_users")}
            if "is_network_admin" not in columns:
                connection.execute(text("ALTER TABLE web_users ADD COLUMN is_network_admin BOOLEAN NOT NULL DEFAULT 0"))
                connection.execute(text("UPDATE web_users SET is_network_admin = 1 WHERE is_admin = 1"))
        if "inventory_printer_details" in table_names:
            columns = {column["name"] for column in inspector.get_columns("inventory_printer_details")}
            if "connection_type" not in columns:
                connection.execute(text("ALTER TABLE inventory_printer_details ADD COLUMN connection_type VARCHAR(7)"))
        if "inventory_pc_details" in table_names:
            columns = {column["name"] for column in inspector.get_columns("inventory_pc_details")}
            if "os_version" not in columns:
                connection.execute(text("ALTER TABLE inventory_pc_details ADD COLUMN os_version VARCHAR(255)"))
        if "inventory_assets" in table_names:
            columns = {column["name"] for column in inspector.get_columns("inventory_assets")}
            if "notes" in columns:
                connection.execute(_TRANSFER_ASSET_NOTES)
    _migrate_inventory_endpoint_schema(engine)


def init_db() -> None:
    from . import models  # noqa: F401
    from .inventory import models as inventory_models  # noqa: F401
    from .auth import ensure_admin_user

    engine = get_engine()
    _prepare_inventory_sync_claim_index(engine)
    Base.metadata.create_all(bind=engine)
    _migrate_inventory_schema(engine)
    with session_scope() as db:
        ensure_admin_user(db)
        from .inventory.service import InventoryService

        inventory = InventoryService()
        inventory.normalize_existing_pc_details(db)
        inventory.repair_detail_integrity(db)


def get_db() -> Iterator[Session]:
    with get_sessionmaker()() as db:
        yield db


@contextmanager
def session_scope() -> Iterator[Session]:
    db = get_sessionmaker()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
