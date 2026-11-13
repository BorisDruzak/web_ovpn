from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from math import ceil

from sqlalchemy import select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from .models import NetworkActionThrottle


NETWORK_ACTION_INTERVAL_SECONDS = 300


@dataclass(frozen=True)
class NetworkActionPermit:
    accepted: bool
    message: str
    retry_after_seconds: int | None = None


def acquire_network_action(
    db: Session,
    actor: str,
    action: str,
    now: datetime,
) -> NetworkActionPermit:
    """Atomically accept at most one actor/action pair in five minutes."""
    cutoff = now - timedelta(seconds=NETWORK_ACTION_INTERVAL_SECONDS)
    try:
        inserted = db.execute(
            insert(NetworkActionThrottle)
            .values(actor=actor, action=action, last_accepted_at=now)
            .on_conflict_do_nothing(index_elements=["actor", "action"])
        )
        accepted = inserted.rowcount == 1
        if not accepted:
            updated = db.execute(
                update(NetworkActionThrottle)
                .where(
                    NetworkActionThrottle.actor == actor,
                    NetworkActionThrottle.action == action,
                    NetworkActionThrottle.last_accepted_at <= cutoff,
                )
                .values(last_accepted_at=now)
            )
            accepted = updated.rowcount == 1
        retry_after_seconds = None
        if not accepted:
            last_accepted = db.execute(
                select(NetworkActionThrottle.last_accepted_at).where(
                    NetworkActionThrottle.actor == actor, NetworkActionThrottle.action == action,
                )
            ).scalar_one()
            last_accepted = last_accepted.replace(tzinfo=last_accepted.tzinfo or UTC)
            cutoff_utc = cutoff.replace(tzinfo=cutoff.tzinfo or UTC)
            retry_after_seconds = max(1, ceil((last_accepted - cutoff_utc).total_seconds()))
        db.commit()
    except Exception:
        db.rollback()
        raise
    if accepted:
        return NetworkActionPermit(True, "")
    return NetworkActionPermit(False, "Повторите действие через 5 минут", retry_after_seconds)
