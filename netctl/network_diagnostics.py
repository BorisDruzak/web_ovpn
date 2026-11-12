from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from .switch_telemetry import (
    broadcast_counters_unreliable, counter_sample_from_row, derive_broadcast_rates, derive_port_telemetry,
)

HISTORY_HOURS = 24
MAX_POINTS = 1440
MAX_INTERVAL_SECONDS = 900
PORT_COUNTERS = ("in_errors", "out_errors", "in_discards", "out_discards")


def _counter(value: object) -> str | None:
    if type(value) is int and 0 <= value < 2**64:
        return str(value)
    return None


def record_router_samples(conn: sqlite3.Connection, source_id: int, observed_at: str, interfaces: list[dict]) -> None:
    conn.executemany(
        """
        INSERT INTO router_interface_counter_samples
            (source_id, interface_name, observed_at, interface_type, mac, running, rx_bytes, tx_bytes,
             in_errors, out_errors, in_discards, out_discards, link_downs)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (source_id, interface_name, observed_at) DO NOTHING
        """,
        (
            (source_id, item["name"], observed_at, item.get("type") or "", item.get("mac") or "",
             int(bool(item.get("running")) and not item.get("disabled")),
             _counter(item.get("rx_bytes")), _counter(item.get("tx_bytes")),
             *(_counter(item.get(key)) for key in PORT_COUNTERS), _counter(item.get("link_downs")))
            for item in interfaces if item.get("name")
        ),
    )


def _router_rates(current: sqlite3.Row, previous: sqlite3.Row, elapsed: float) -> dict:
    if not current["running"] or not previous["running"]:
        return {}
    if any(current[key] != previous[key] for key in ("interface_type", "mac")):
        return {}
    metrics = {}
    byte_counters = ("rx_bytes", "tx_bytes")
    if all(row[key] is not None for row in (current, previous) for key in byte_counters):
        rx, tx = (int(current[key]) - int(previous[key]) for key in byte_counters)
        if min(rx, tx) < 0:
            return {}
        metrics.update(rx_bps=rx * 8 / elapsed, tx_bps=tx * 8 / elapsed)
    if "link_downs" in current.keys() and current["link_downs"] == previous["link_downs"]:
        for key in PORT_COUNTERS:
            after, before = current[key], previous[key]
            if after is not None and before is not None and int(after) >= int(before):
                metrics[f"{key}_delta"] = int(after) - int(before)
    return metrics


def _switch_rates(current: sqlite3.Row, previous: sqlite3.Row, elapsed: float) -> dict:
    if current["if_index"] != previous["if_index"]:
        return {}
    newest, prior = map(counter_sample_from_row, (current, previous))
    speed = current["speed_bps"] if current["speed_bps"] == previous["speed_bps"] else None
    metrics = derive_port_telemetry(newest, prior, elapsed_seconds=elapsed, port_speed_bps=speed)
    if metrics["telemetry_state"] == "counter_reset":
        return {}
    # At longer intervals a 32-bit counter can wrap without visibly decreasing.
    if newest.octet_counter_bits == 32 and (not speed or speed * elapsed >= 2**32 * 8):
        metrics.update(rx_bps=None, tx_bps=None)
    if (newest.sys_uptime_ticks is not None and prior.sys_uptime_ticks is not None
            and newest.sys_uptime_ticks < prior.sys_uptime_ticks):
        return {}
    for key in PORT_COUNTERS:
        after, before = current[key], previous[key]
        if after is not None and before is not None and after >= before:
            metrics[f"{key}_delta"] = after - before
    return metrics


def _traffic_points(rows: list[sqlite3.Row], *, switch: bool, unreliable_broadcast: bool) -> list[dict]:
    points = []
    previous = None
    for row in reversed(rows):
        observed = datetime.fromisoformat(row["observed_at"])
        elapsed = (observed - previous[0]).total_seconds() if previous is not None else None
        metrics = {}
        broadcast = {}
        if elapsed is not None and 0 < elapsed <= MAX_INTERVAL_SECONDS:
            metrics = (_switch_rates(row, previous[1], elapsed) if switch
                       else _router_rates(row, previous[1], elapsed))
            if switch and not unreliable_broadcast:
                broadcast = derive_broadcast_rates(row, previous[1], elapsed)
        point = {
            "observed_at": row["observed_at"],
            "interval_seconds": elapsed,
            "rx_bps": metrics.get("rx_bps"),
            "tx_bps": metrics.get("tx_bps"),
            **{f"{key}_delta": metrics.get(f"{key}_delta") for key in PORT_COUNTERS},
        }
        if switch:
            point.update(in_broadcast_pps=broadcast.get("in_pps"), out_broadcast_pps=broadcast.get("out_pps"))
        points.append(point)
        previous = observed, row
    return points


def _broadcast_coverage(rows: list[sqlite3.Row], points: list[dict]) -> dict:
    valid_intervals = sum(
        point["in_broadcast_pps"] is not None or point["out_broadcast_pps"] is not None
        for point in points
    )
    if valid_intervals:
        return {"status": "measured", "valid_intervals": valid_intervals}
    if not rows:
        return {"status": "no_samples", "valid_intervals": 0}
    counters = [
        row for row in rows
        if "counter_discontinuity_ticks" in row.keys()
        and (row["in_broadcast_packets"] is not None or row["out_broadcast_packets"] is not None)
    ]
    if not counters:
        status = "no_counters"
    elif all(row["counter_discontinuity_ticks"] is None for row in counters):
        status = "missing_discontinuity_marker"
    else:
        status = "no_valid_intervals"
    return {"status": status, "valid_intervals": 0}


def _switch_interface_choices(
    conn: sqlite3.Connection, source_id: int,
) -> tuple[list[dict], dict[str, sqlite3.Row]]:
    rows = conn.execute("""
        SELECT port_key AS key, name, alias AS description, speed_bps, if_index
        FROM switch_ports WHERE source_id = ?
        ORDER BY if_index, name, last_seen_at DESC, collector_run_id DESC, port_key
    """, (source_id,))
    current = {}
    aliases = {}
    for row in rows:
        if_index = row["if_index"]
        identity = (if_index, row["name"]) if if_index is not None and row["name"] else row["key"]
        aliases[row["key"]] = current.setdefault(identity, row)
    interfaces = [
        {key: row[key] for key in ("key", "name", "description", "speed_bps")}
        for row in current.values()
    ]
    return interfaces, aliases


def _merged_switch_samples(
    conn: sqlite3.Connection, source_id: int, port: sqlite3.Row, cutoff: str,
) -> list[sqlite3.Row]:
    return conn.execute("""
        SELECT * FROM (
            SELECT sample.*, ROW_NUMBER() OVER (
                PARTITION BY sample.observed_at
                ORDER BY (sample.port_key = ?) DESC, sample.id DESC
            ) AS sample_rank
            FROM switch_ports AS alias
            JOIN switch_port_counter_samples AS sample
              ON sample.source_id = alias.source_id AND sample.port_key = alias.port_key
            WHERE alias.source_id = ? AND alias.if_index = ? AND alias.name = ?
              AND sample.if_index = alias.if_index AND sample.observed_at >= ?
        )
        WHERE sample_rank = 1 ORDER BY observed_at DESC LIMIT ?
    """, (port["key"], source_id, port["if_index"], port["name"], cutoff, MAX_POINTS)).fetchall()


def read_diagnostics(
    conn: sqlite3.Connection, source: str, interface: str, *, now: datetime | None = None,
) -> dict:
    now = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = (now - timedelta(hours=HISTORY_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {"since": cutoff, "until": now.isoformat(), "interfaces": [],
              "points": [], "stp": None, "stp_events": [], "selected": None}
    device = conn.execute(
        "SELECT id, driver, last_collect_at, last_status FROM network_sources WHERE name = ? AND enabled = 1",
        (source,),
    ).fetchone()
    if device is None:
        return result
    source_id = device["id"]
    switch = device["driver"] == "snmp_switch"
    result["source"] = dict(device)
    aliases = {}
    if switch:
        result["interfaces"], aliases = _switch_interface_choices(conn, source_id)
        stp = conn.execute("SELECT * FROM current_switch_stp_state WHERE source_id = ?", (source_id,)).fetchone()
        result["stp"] = dict(stp) if stp else None
        events = conn.execute("""
            SELECT * FROM switch_stp_events WHERE source_id = ? AND observed_at >= ?
            ORDER BY observed_at DESC, id DESC LIMIT ?
        """, (source_id, cutoff, MAX_POINTS + 1)).fetchall()
        result["stp_events"] = [dict(row) for row in events[:MAX_POINTS]]
        result["stp_truncated"] = len(events) > MAX_POINTS
        samples = """SELECT * FROM switch_port_counter_samples
                     WHERE source_id = ? AND port_key = ? AND observed_at >= ?"""
    else:
        result["interfaces"] = [dict(row) for row in conn.execute("""
            SELECT name AS key, name, comment AS description, NULL AS speed_bps
            FROM network_interfaces WHERE source_id = ? ORDER BY name
        """, (source_id,))]
        samples = """SELECT * FROM router_interface_counter_samples
                     WHERE source_id = ? AND interface_name = ? AND observed_at >= ?"""
    canonical = aliases.get(interface)
    key = canonical["key"] if canonical is not None else interface
    selected = next((port for port in result["interfaces"] if port["key"] == key), None)
    if selected is not None:
        if canonical is not None and sum(row["key"] == key for row in aliases.values()) > 1:
            rows = _merged_switch_samples(conn, source_id, canonical, cutoff)
        else:
            rows = conn.execute(
                samples + " ORDER BY observed_at DESC, id DESC LIMIT ?",
                (source_id, key, cutoff, MAX_POINTS),
            ).fetchall()
        result["selected"] = selected
        model = conn.execute(
            "SELECT profile_id, sys_descr FROM switch_devices WHERE source_id = ?", (source_id,),
        ).fetchone() if switch else None
        unreliable = model is not None and broadcast_counters_unreliable(model["profile_id"], model["sys_descr"])
        result["points"] = _traffic_points(rows, switch=switch, unreliable_broadcast=unreliable)
        if switch:
            result["broadcast_coverage"] = (
                {"status": "unreliable_counters", "valid_intervals": 0}
                if unreliable else _broadcast_coverage(rows, result["points"])
            )
    return result
