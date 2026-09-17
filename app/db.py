from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings, reset_settings_cache


class Base(DeclarativeBase):
    pass


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


def _prepare_inventory_sync_claim_index(engine) -> None:
    """Normalize legacy success races before metadata creates the SQLite partial index."""
    if engine.dialect.name != "sqlite":
        return
    if "inventory_identifier_sync_runs" not in inspect(engine).get_table_names():
        return
    with engine.begin() as connection:
        connection.execute(_NORMALIZE_DUPLICATE_INVENTORY_SYNC_SUCCESSES)
        connection.execute(_CREATE_INVENTORY_SYNC_SUCCESS_INDEX)


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
