from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator

from sqlalchemy import create_engine
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

    Base.metadata.create_all(bind=get_engine())
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
