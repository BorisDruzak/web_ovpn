"""Persist route probe evidence and run configured scheduled route profiles."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import get_sessionmaker
from .models import NetworkRouteRun, utcnow
from .network_actions import NETWORK_ACTION_INTERVAL_SECONDS, acquire_network_action
from .network_probe_profiles import load_probe_profiles
from .network_route_matrix import run_route_matrix


ROUTE_RUN_RETENTION = timedelta(days=14)
MAX_ROUTE_RUN_LIST = 100
SCHEDULE_OWNER = "schedule:"
_SCHEDULE_ACTION = "network-check-route-availability"
_PROBE_SELECTORS = (
    "origin", "target", "protocol", "source_address", "interface", "routing_table",
    "expected_path", "expected_first_hop",
)


def _purge_route_runs(db: Session, now: datetime) -> None:
    db.execute(delete(NetworkRouteRun).where(NetworkRouteRun.checked_at < now - ROUTE_RUN_RETENTION))


def _first_hop(probe: dict) -> str | None:
    value = probe.get("observed_path")
    if not isinstance(value, str):
        return None
    try:
        return str(IPv4Address(value))
    except ValueError:
        return None


def _scheduled_first_hop_changes(db: Session, result: dict, checked_at: datetime) -> list[dict]:
    db.flush()
    previous_json = db.scalar(
        select(NetworkRouteRun.result_json).where(
            NetworkRouteRun.owner == SCHEDULE_OWNER,
            NetworkRouteRun.profile == result["target"],
            NetworkRouteRun.checked_at <= checked_at,
        ).order_by(NetworkRouteRun.checked_at.desc(), NetworkRouteRun.id.desc()).limit(1)
    )
    if previous_json is None:
        return []

    previous_probes = {
        probe.get("id"): probe for probe in json.loads(previous_json)["result"].get("probes", [])
    }
    changes = []
    for probe in result["result"].get("probes", []):
        probe_id = probe.get("id")
        previous = previous_probes.get(probe_id)
        if not probe_id or previous is None or any(
            previous.get(key) != probe.get(key) for key in _PROBE_SELECTORS
        ):
            continue
        old_hop, new_hop = _first_hop(previous), _first_hop(probe)
        if old_hop and new_hop and old_hop != new_hop:
            changes.append({
                "probe_id": probe_id,
                "from": old_hop,
                "to": new_hop,
                "checked_at": result["checked_at"],
            })
    return changes


def persist_route_run(db: Session, *, owner: str, result: dict) -> None:
    """Stage a route result in the caller's transaction."""
    stored_at = utcnow()
    checked_at = datetime.fromisoformat(result["checked_at"])
    _purge_route_runs(db, stored_at)
    if owner == SCHEDULE_OWNER:
        changes = _scheduled_first_hop_changes(db, result, checked_at)
        result = {**result, "result": {**result["result"], "path_changes": changes}}
    row = NetworkRouteRun(
        owner=owner,
        profile=result["target"],
        checked_at=checked_at,
        stored_at=stored_at,
        result_json=json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False),
    )
    db.add(row)


def list_route_runs(
    db: Session, *, owner: str, profile: str | None, limit: int,
) -> list[dict]:
    statement = select(NetworkRouteRun).where(
        NetworkRouteRun.owner.in_((owner, SCHEDULE_OWNER)),
        NetworkRouteRun.checked_at >= utcnow() - ROUTE_RUN_RETENTION,
    )
    if profile is not None:
        statement = statement.where(NetworkRouteRun.profile == profile)
    statement = statement.order_by(NetworkRouteRun.checked_at.desc(), NetworkRouteRun.id.desc()).limit(
        max(0, min(limit, MAX_ROUTE_RUN_LIST))
    )
    return [
        {
            **json.loads(row.result_json),
            "id": row.id,
            "trigger": "scheduled" if row.owner == SCHEDULE_OWNER else "manual",
            "stored_at": row.stored_at.isoformat(),
        }
        for row in db.scalars(statement)
    ]


def run_scheduled_route_probes(db: Session, *, now: datetime | None = None) -> int:
    now = now or utcnow()
    _purge_route_runs(db, now)
    db.commit()
    scheduled = [(key, profile) for key, profile in load_probe_profiles().routes.items() if profile.scheduled]
    if not scheduled:
        return 0

    # Calendar slots stay stable even when service startup is delayed.
    slot_seconds = int(now.timestamp()) // NETWORK_ACTION_INTERVAL_SECONDS * NETWORK_ACTION_INTERVAL_SECONDS
    slot = datetime.fromtimestamp(slot_seconds, UTC)
    if not acquire_network_action(db, SCHEDULE_OWNER, _SCHEDULE_ACTION, slot).accepted:
        return 0

    for profile_id, profile in scheduled:
        evidence = run_route_matrix(profile_id, profile)
        persist_route_run(db, owner=SCHEDULE_OWNER, result={
            "check": "route_availability",
            "target": profile_id,
            "checked_at": utcnow().isoformat(),
            **evidence,
        })
        db.commit()
    return len(scheduled)


def main() -> None:
    with get_sessionmaker()() as db:
        completed = run_scheduled_route_probes(db)
    print(f"Scheduled route profiles completed: {completed}")


if __name__ == "__main__":
    main()
