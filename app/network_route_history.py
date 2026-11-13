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
from .network_route_matrix import PROBE_STATUSES, run_route_matrix


ROUTE_RUN_RETENTION = timedelta(days=14)
MAX_ROUTE_RUN_LIST = 100
SCHEDULE_OWNER = "schedule:"
_SCHEDULE_ACTION = "network-check-route-availability"
_PROBE_SELECTORS = (
    "origin", "target", "protocol", "source_address", "interface", "routing_table",
    "expected_path", "expected_first_hop", "openvpn_client", "config_digest",
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


def _scheduled_changes(db: Session, result: dict, checked_at: datetime) -> dict:
    db.flush()
    previous_json = db.scalar(
        select(NetworkRouteRun.result_json).where(
            NetworkRouteRun.owner == SCHEDULE_OWNER,
            NetworkRouteRun.profile == result["target"],
            NetworkRouteRun.checked_at <= checked_at,
        ).order_by(NetworkRouteRun.checked_at.desc(), NetworkRouteRun.id.desc()).limit(1)
    )
    changes = {"path_changes": [], "probe_changes": []}
    if previous_json is None:
        return changes

    previous_probes = {probe.get("id"): probe for probe in json.loads(previous_json)["result"].get("probes", [])}
    for probe in result["result"].get("probes", []):
        probe_id = probe.get("id")
        previous = previous_probes.get(probe_id)
        if not probe_id or previous is None or any(
            previous.get(key) != probe.get(key) for key in _PROBE_SELECTORS
        ):
            continue
        event = {"probe_id": probe_id, "checked_at": result["checked_at"]}
        old_hop, new_hop = _first_hop(previous), _first_hop(probe)
        if old_hop and new_hop and old_hop != new_hop:
            changes["path_changes"].append({**event, "from": old_hop, "to": new_hop})
        old_status, new_status = previous.get("status"), probe.get("status")
        digest = probe.get("config_digest")
        if (digest and old_status != new_status
                and old_status in PROBE_STATUSES and new_status in PROBE_STATUSES):
            changes["probe_changes"].append({**event, "from": old_status, "to": new_status})
    return changes


def persist_route_run(db: Session, *, owner: str, result: dict) -> None:
    """Stage a route result in the caller's transaction."""
    stored_at = utcnow()
    checked_at = datetime.fromisoformat(result["checked_at"])
    _purge_route_runs(db, stored_at)
    if owner == SCHEDULE_OWNER:
        changes = _scheduled_changes(db, result, checked_at)
        result = {**result, "result": {**result["result"], **changes}}
    row = NetworkRouteRun(
        owner=owner,
        profile=result["target"],
        checked_at=checked_at,
        stored_at=stored_at,
        result_json=json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False),
    )
    db.add(row)


def route_history_window(
    since: str | None, until: str | None, *, assume_utc: bool = False,
) -> tuple[datetime | None, datetime | None]:
    def parse(value: str | None) -> datetime | None:
        if value is None:
            return None
        if len(value) > 40 or "T" not in value:
            raise ValueError("Expected an ISO 8601 timestamp")
        moment = datetime.fromisoformat(value)
        if moment.tzinfo is None:
            if not assume_utc:
                raise ValueError("A time zone is required")
            return moment.replace(tzinfo=UTC)
        return moment.astimezone(UTC)

    try:
        start, end = parse(since), parse(until)
    except (ValueError, OverflowError) as exc:
        raise ValueError("Invalid route history timestamp") from exc
    if start is not None and end is not None and start >= end:
        raise ValueError("since must precede until")
    return start, end


def list_route_runs(
    db: Session, *, owner: str, profile: str | None, limit: int,
    since: datetime | None = None, until: datetime | None = None,
) -> list[dict]:
    statement = select(NetworkRouteRun).where(
        NetworkRouteRun.owner.in_((owner, SCHEDULE_OWNER)),
        NetworkRouteRun.checked_at >= utcnow() - ROUTE_RUN_RETENTION,
    )
    if profile is not None:
        statement = statement.where(NetworkRouteRun.profile == profile)
    if since is not None:
        statement = statement.where(NetworkRouteRun.checked_at >= since)
    if until is not None:
        statement = statement.where(NetworkRouteRun.checked_at < until)
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


def _route_run_configuration_status(run: dict, current: dict[str, str] | None) -> str:
    probes = run["result"].get("probes", [])
    if current is None or any(not probe.get("config_digest") for probe in probes):
        return "unconfirmed"
    saved = {probe["id"]: probe["config_digest"] for probe in probes}
    return "current" if saved == current and len(saved) == len(probes) else "changed"


def annotate_route_run_configurations(runs: list[dict], catalog: list[dict]) -> None:
    current_digests = {
        row["id"]: {probe["id"]: probe["config_digest"] for probe in row["probes"]}
        for row in catalog
    }
    for run in runs:
        run["configuration_status"] = _route_run_configuration_status(run, current_digests.get(run["target"]))


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
