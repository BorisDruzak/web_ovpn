from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

WINDOW = timedelta(hours=1)
MAX_REVERSAL_GAP = timedelta(minutes=15)
STP_CORRELATION_MARGIN = timedelta(minutes=10)
MAX_SOURCES = 50
MAX_FDB_EVENTS = 2_000
MAX_STP_EVENTS = 100
MAX_FINDINGS = 20
MAX_STP_EVENTS_PER_FINDING = 5
MIN_FDB_POLLS = 3
STATUS_PRIORITY = ("no_evidence", "insufficient_data", "mac_flapping", "suspected_loop")


def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _in_window(value: datetime | None, since: datetime, until: datetime) -> bool:
    return value is not None and since <= value <= until


def _stp_changes(
    rows: list[sqlite3.Row], since: datetime, until: datetime,
) -> list[tuple[datetime, datetime, sqlite3.Row]]:
    changes = []
    for row in rows:
        observed = _timestamp(row["observed_at"])
        previous = _timestamp(row["previous_observed_at"])
        if (
            row["event_type"] == "changed"
            and not row["counter_decreased"]
            and previous is not None and observed is not None
            and previous < observed and since <= observed <= until
            and (
                (row["changes_delta"] or 0) > 0
                or row["old_root_bridge_mac"] != row["root_bridge_mac"]
                or row["old_root_port_key"] != row["root_port_key"]
            )
        ):
            changes.append((observed, previous, row))
    return changes


def _find_reversals(
    rows: list[sqlite3.Row], changes: list[tuple[datetime, datetime, sqlite3.Row]],
    since: datetime, until: datetime,
) -> list[dict]:
    previous_by_mac_vlan: dict[tuple[str, str], tuple[datetime, sqlite3.Row]] = {}
    findings: dict[tuple[str, str, str, str], tuple[tuple[bool, datetime], dict]] = {}
    timed_rows = []
    for row in rows:
        at = _timestamp(row["observed_at"])
        if at is not None and since <= at <= until:
            timed_rows.append((at, row))
    for at, row in sorted(timed_rows, key=lambda item: (item[0], item[1]["id"])):
        if row["vlan_id"] is None:
            continue
        key = (row["mac"], row["vlan_key"])
        old, new = row["old_port_key"], row["new_port_key"]
        prior = previous_by_mac_vlan.pop(key, None)
        if row["event_type"] != "moved" or not old or not new or old == new:
            continue
        previous_by_mac_vlan[key] = (at, row)
        if prior is None:
            continue
        previous_at, previous = prior
        if (
            not timedelta(0) < at - previous_at <= MAX_REVERSAL_GAP
            or previous["old_port_key"] != new
            or previous["new_port_key"] != old
        ):
            continue
        # STP reports when a change was seen. Require its whole observation
        # interval to be close to the movement before treating it as correlated.
        stp = [
            event for observed, before, event in changes
            if previous_at - STP_CORRELATION_MARGIN <= before
            and observed <= at + STP_CORRELATION_MARGIN
        ]
        ports = sorted((old, new))
        signature = (*key, *ports)
        rank = (bool(stp), at)
        if signature in findings and findings[signature][0] >= rank:
            continue
        findings[signature] = (rank, {
            "mac": row["mac"],
            "vlan_key": row["vlan_key"],
            "vlan_id": row["vlan_id"],
            "ports": ports,
            "first_observed_at": previous["observed_at"],
            "last_observed_at": row["observed_at"],
            "moves": [
                {field: move[field] for field in ("old_port_key", "new_port_key", "observed_at")}
                for move in (previous, row)
            ],
            "stp_events": [dict(event) for event in stp[:MAX_STP_EVENTS_PER_FINDING]],
            "stp_truncated": len(stp) > MAX_STP_EVENTS_PER_FINDING,
        })
    return [finding for _, finding in sorted(findings.values(), key=lambda entry: entry[0], reverse=True)]


def _read_source(conn: sqlite3.Connection, device: sqlite3.Row, since: datetime, until: datetime) -> dict:
    # Collector timestamps are UTC ISO strings. Prefix bounds preserve index
    # lookups for the canonical Z suffix and equivalent +00:00 timestamps.
    lower = since.isoformat(timespec="seconds")[:19]
    upper = (until + timedelta(seconds=1)).isoformat(timespec="seconds")[:19]
    source_id = device["id"]
    events = conn.execute(
        """
        SELECT id, mac, vlan_key, vlan_id, old_port_key, new_port_key, event_type, observed_at
        FROM switch_fdb_events
        WHERE source_id = ? AND observed_at >= ? AND observed_at < ?
        ORDER BY observed_at DESC, id DESC LIMIT ?
        """,
        (source_id, lower, upper, MAX_FDB_EVENTS + 1),
    ).fetchall()
    fdb_truncated = len(events) > MAX_FDB_EVENTS
    events = events[:MAX_FDB_EVENTS]
    stp_events = conn.execute(
        """
        SELECT id, observed_at, previous_observed_at, event_type,
               old_root_bridge_mac, root_bridge_mac, old_root_port_key, root_port_key,
               old_root_path_cost, root_path_cost, old_protocol, protocol,
               changes_delta, counter_decreased
        FROM switch_stp_events
        WHERE source_id = ? AND observed_at >= ? AND observed_at < ?
        ORDER BY observed_at DESC, id DESC LIMIT ?
        """,
        (source_id, lower, upper, MAX_STP_EVENTS + 1),
    ).fetchall()
    stp_truncated = len(stp_events) > MAX_STP_EVENTS
    stp_events = stp_events[:MAX_STP_EVENTS]
    polls = conn.execute(
        """
        SELECT started_at FROM switch_collection_runs
        WHERE source_id = ? AND started_at >= ? AND started_at < ?
          AND status IN ('success', 'partial')
        ORDER BY started_at DESC, id DESC LIMIT ?
        """,
        (source_id, lower, upper, MIN_FDB_POLLS),
    ).fetchall()

    recent_polls = [
        poll["started_at"] for poll in polls if _in_window(_timestamp(poll["started_at"]), since, until)
    ]
    fdb_last_at = device["fdb_last_success_at"]
    fdb_last = _timestamp(fdb_last_at)
    if _in_window(fdb_last, since, until):
        # The current-state timestamp can still be present when history is incomplete.
        fdb_status = "insufficient"
    elif fdb_last is not None and fdb_last < since:
        fdb_status = "stale"
    else:
        fdb_status = "unavailable"
        fdb_last_at = None
    if recent_polls:
        fdb_last_at = recent_polls[0]
        fdb_status = "insufficient"
    if len(recent_polls) >= MIN_FDB_POLLS:
        known_vlan = any(row["vlan_id"] is not None for row in events) or conn.execute(
            """
            SELECT 1 FROM current_switch_fdb
            WHERE source_id = ? AND vlan_key >= 'vid:' AND vlan_key < 'vid;'
              AND last_seen_at >= ? AND last_seen_at < ?
            LIMIT 1
            """,
            (source_id, lower, upper),
        ).fetchone() is not None
        if known_vlan:
            fdb_status = "recent"
    stp_observed = _timestamp(device["stp_observed_at"])
    stp_status = "unavailable"
    if _in_window(stp_observed, since, until):
        stp_status = "recent"
    elif stp_observed is not None and stp_observed < since:
        stp_status = "stale"
    coverage = {
        "fdb": {
            "status": fdb_status,
            "last_observed_at": fdb_last_at,
            "events_read": len(events),
            "truncated": fdb_truncated,
            "unmapped_moves": sum(row["vlan_id"] is None and row["event_type"] == "moved" for row in events),
        },
        "stp": {
            "status": stp_status,
            "last_observed_at": device["stp_observed_at"],
            "events_read": len(stp_events),
            "truncated": stp_truncated,
            "scope": "switch",
        },
        "broadcast": {"status": "unavailable"},
    }
    findings = _find_reversals(events, _stp_changes(stp_events, since, until), since, until)
    truncated = (
        fdb_truncated or stp_truncated or len(findings) > MAX_FINDINGS
        or any(finding["stp_truncated"] for finding in findings)
    )
    if findings:
        status = "suspected_loop" if findings[0]["stp_events"] else "mac_flapping"
    elif fdb_status == stp_status == "recent" and not truncated:
        status = "no_evidence"
    else:
        status = "insufficient_data"
    return {
        "source": device["name"],
        "site": device["site"],
        "last_collect_at": device["last_collect_at"],
        "last_status": device["last_status"],
        "status": status,
        "coverage": coverage,
        "evidence": findings[:MAX_FINDINGS],
        "truncated": truncated,
    }


def read_loop_diagnostics(
    conn: sqlite3.Connection, source: str | None = None, *, now: datetime | None = None,
) -> dict:
    """Read recent persisted switch telemetry and report possible loop evidence."""
    until = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    since = until - WINDOW
    source_filter = " AND sources.name = ?" if source is not None else ""
    params = (source, MAX_SOURCES + 1) if source is not None else (MAX_SOURCES + 1,)
    devices = conn.execute(
        """
        SELECT sources.id, sources.name, sources.site, sources.last_collect_at,
               sources.last_status, stp.observed_at AS stp_observed_at,
               devices.last_success_at AS fdb_last_success_at
        FROM network_sources AS sources
        LEFT JOIN current_switch_stp_state AS stp ON stp.source_id = sources.id
        LEFT JOIN switch_devices AS devices ON devices.source_id = sources.id
        WHERE sources.enabled = 1 AND sources.driver = 'snmp_switch'
        """
        + source_filter
        + " ORDER BY sources.name LIMIT ?",
        params,
    ).fetchall()
    sources = [_read_source(conn, device, since, until) for device in devices[:MAX_SOURCES]]
    sources_truncated = len(devices) > MAX_SOURCES
    statuses = [item["status"] for item in sources]
    if sources_truncated:
        statuses.append("insufficient_data")
    return {
        "source": source,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": max(statuses, key=STATUS_PRIORITY.index, default="no_sources"),
        "sources": sources,
        "truncated": sources_truncated or any(item["truncated"] for item in sources),
    }
