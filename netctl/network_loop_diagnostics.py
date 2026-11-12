from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from .switch_telemetry import broadcast_counters_unreliable, derive_broadcast_rates

WINDOW = timedelta(hours=1)
MAX_REVERSAL_GAP = timedelta(minutes=15)
STP_CORRELATION_MARGIN = timedelta(minutes=10)
MAX_SOURCES = 50
MAX_FDB_EVENTS = 2_000
MAX_STP_EVENTS = 100
MAX_BROADCAST_SAMPLES = 2_000
MAX_FINDINGS = 20
MAX_STP_EVENTS_PER_FINDING = 5
MAX_BROADCAST_INTERVALS_PER_FINDING = 12
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


def _broadcast_rates(
    samples: list[tuple[datetime, sqlite3.Row]],
) -> list[tuple[datetime, datetime, dict]]:
    previous_by_port: dict[str, tuple[datetime, sqlite3.Row]] = {}
    intervals = []
    for at, current in sorted(samples, key=lambda item: (item[0], item[1]["id"])):
        port = current["port_key"]
        prior = previous_by_port.get(port)
        previous_by_port[port] = (at, current)
        if prior is None:
            continue
        prior_at, previous = prior
        seconds = (at - prior_at).total_seconds()
        rates = derive_broadcast_rates(current, previous, seconds)
        if not rates:
            continue
        intervals.append((prior_at, at, {
            "port_key": port,
            "if_index": current["if_index"],
            "since": previous["observed_at"],
            "until": current["observed_at"],
            "interval_seconds": seconds,
            **rates,
        }))
    return intervals


def _broadcast_evidence(
    conn: sqlite3.Connection, source_id: int, since: datetime, until: datetime,
    lower: str, upper: str, findings: list[dict], *, has_history: bool, unreliable: bool,
) -> dict:
    coverage = {
        "status": "unavailable", "scope": "port", "last_observed_at": None,
        "sampled_ports": 0, "valid_intervals": 0, "truncated": False,
    }
    for finding in findings:
        finding.update(broadcast_intervals=[], broadcast_truncated=False)
    if unreliable:
        return {**coverage, "status": "unreliable_counters"}
    if not has_history:
        return coverage

    rows = conn.execute(
        """
        SELECT id, port_key, if_index, observed_at, sys_uptime_ticks,
               in_broadcast_packets, out_broadcast_packets, counter_discontinuity_ticks
        FROM switch_port_counter_samples
        WHERE source_id = ? AND observed_at >= ? AND observed_at < ?
          AND (in_broadcast_packets IS NOT NULL OR out_broadcast_packets IS NOT NULL)
        ORDER BY observed_at DESC, id DESC LIMIT ?
        """,
        (source_id, lower, upper, MAX_BROADCAST_SAMPLES + 1),
    ).fetchall()
    coverage["truncated"] = len(rows) > MAX_BROADCAST_SAMPLES
    samples = []
    for row in rows[:MAX_BROADCAST_SAMPLES]:
        at = _timestamp(row["observed_at"])
        if at is not None and since <= at <= until:
            samples.append((at, row))
    if not samples:
        older = conn.execute(
            """
            SELECT observed_at FROM switch_port_counter_samples
            WHERE source_id = ? AND observed_at < ?
              AND (in_broadcast_packets IS NOT NULL OR out_broadcast_packets IS NOT NULL)
            ORDER BY observed_at DESC, id DESC LIMIT 1
            """,
            (source_id, lower),
        ).fetchone()
        if older is not None:
            coverage.update(status="stale", last_observed_at=older["observed_at"])
        return coverage

    intervals = _broadcast_rates(samples)
    coverage.update(
        status="recent" if intervals else "insufficient",
        last_observed_at=samples[0][1]["observed_at"],
        sampled_ports=len({row["port_key"] for _, row in samples}),
        valid_intervals=len(intervals),
    )
    for finding in findings:
        started = _timestamp(finding["first_observed_at"])
        ended = _timestamp(finding["last_observed_at"])
        evidence = [
            interval for before, after, interval in intervals
            if started is not None and ended is not None and before < ended and started < after
            and interval["port_key"] in finding["ports"]
        ]
        finding.update(
            broadcast_intervals=evidence[:MAX_BROADCAST_INTERVALS_PER_FINDING],
            broadcast_truncated=len(evidence) > MAX_BROADCAST_INTERVALS_PER_FINDING or coverage["truncated"],
        )
    return coverage


def _read_source(
    conn: sqlite3.Connection, device: sqlite3.Row, since: datetime, until: datetime, *, has_broadcast_history: bool,
) -> dict:
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
        SELECT started_at, json_extract(outcomes_json, '$.qbridge_fdb_rejected_rows') AS fdb_rejections
        FROM switch_collection_runs
        WHERE source_id = ? AND started_at >= ? AND started_at < ?
          AND status IN ('success', 'partial')
        ORDER BY started_at DESC, id DESC LIMIT ?
        """,
        (source_id, lower, upper, MIN_FDB_POLLS),
    ).fetchall()

    recent_polls = [
        poll for poll in polls if _in_window(_timestamp(poll["started_at"]), since, until)
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
        fdb_last_at = recent_polls[0]["started_at"]
        fdb_status = "insufficient"
    fdb_reason = None
    if any(poll["fdb_rejections"] == "parse_error" for poll in recent_polls):
        fdb_reason = "partial_fdb_poll"
    elif fdb_status == "insufficient" and len(recent_polls) < MIN_FDB_POLLS:
        fdb_reason = "too_few_polls"
    elif len(recent_polls) >= MIN_FDB_POLLS:
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
        else:
            fdb_reason = "no_vlan_observations"
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
            **({"reason": fdb_reason} if fdb_reason else {}),
        },
        "stp": {
            "status": stp_status,
            "last_observed_at": device["stp_observed_at"],
            "events_read": len(stp_events),
            "truncated": stp_truncated,
            "scope": "switch",
        },
    }
    findings = _find_reversals(events, _stp_changes(stp_events, since, until), since, until)
    truncated = (
        fdb_truncated or stp_truncated or len(findings) > MAX_FINDINGS
        or any(finding["stp_truncated"] for finding in findings)
    )
    findings = findings[:MAX_FINDINGS]
    coverage["broadcast"] = _broadcast_evidence(
        conn, source_id, since, until, lower, upper, findings, has_history=has_broadcast_history,
        unreliable=broadcast_counters_unreliable(device["profile_id"], device["sys_descr"]),
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
        "evidence": findings,
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
               devices.last_success_at AS fdb_last_success_at, devices.profile_id, devices.sys_descr
        FROM network_sources AS sources
        LEFT JOIN current_switch_stp_state AS stp ON stp.source_id = sources.id
        LEFT JOIN switch_devices AS devices ON devices.source_id = sources.id
        WHERE sources.enabled = 1 AND sources.driver = 'snmp_switch'
        """
        + source_filter
        + " ORDER BY sources.name LIMIT ?",
        params,
    ).fetchall()
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(switch_port_counter_samples)")}
    has_broadcast_history = {"in_broadcast_packets", "out_broadcast_packets", "counter_discontinuity_ticks"} <= columns
    sources = [
        _read_source(conn, device, since, until, has_broadcast_history=has_broadcast_history)
        for device in devices[:MAX_SOURCES]
    ]
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
