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


def init_db() -> None:
    from . import models  # noqa: F401
    from .auth import ensure_admin_user

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    if "web_users" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("web_users")}
        if "is_network_admin" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE web_users ADD COLUMN is_network_admin BOOLEAN NOT NULL DEFAULT 0"))
                connection.execute(text("UPDATE web_users SET is_network_admin = 1 WHERE is_admin = 1"))
    with session_scope() as db:
        ensure_admin_user(db)


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
