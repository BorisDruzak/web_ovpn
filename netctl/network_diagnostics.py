from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from .switch_telemetry import counter_sample_from_row, derive_port_telemetry

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
            (source_id, interface_name, observed_at, interface_type, mac, running, rx_bytes, tx_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (source_id, interface_name, observed_at) DO NOTHING
        """,
        (
            (source_id, item["name"], observed_at, item.get("type") or "", item.get("mac") or "",
             int(bool(item.get("running")) and not item.get("disabled")),
             _counter(item.get("rx_bytes")), _counter(item.get("tx_bytes")))
            for item in interfaces if item.get("name")
        ),
    )


def _router_rates(current: sqlite3.Row, previous: sqlite3.Row, elapsed: float) -> dict:
    if not current["running"] or not previous["running"]:
        return {}
    if any(current[key] != previous[key] for key in ("interface_type", "mac")):
        return {}
    counters = ("rx_bytes", "tx_bytes")
    if any(row[key] is None for row in (current, previous) for key in counters):
        return {}
    rx, tx = (int(current[key]) - int(previous[key]) for key in counters)
    return {"rx_bps": rx * 8 / elapsed, "tx_bps": tx * 8 / elapsed} if min(rx, tx) >= 0 else {}


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


def _traffic_points(rows: list[sqlite3.Row], *, switch: bool) -> list[dict]:
    points = []
    previous = None
    for row in reversed(rows):
        observed = datetime.fromisoformat(row["observed_at"])
        elapsed = (observed - previous[0]).total_seconds() if previous is not None else None
        metrics = {}
        if elapsed is not None and 0 < elapsed <= MAX_INTERVAL_SECONDS:
            metrics = (_switch_rates(row, previous[1], elapsed) if switch
                       else _router_rates(row, previous[1], elapsed))
        points.append({
            "observed_at": row["observed_at"],
            "interval_seconds": elapsed,
            "rx_bps": metrics.get("rx_bps"),
            "tx_bps": metrics.get("tx_bps"),
            **{f"{key}_delta": metrics.get(f"{key}_delta") for key in PORT_COUNTERS},
        })
        previous = observed, row
    return points


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
    if switch:
        result["interfaces"] = [dict(row) for row in conn.execute("""
            SELECT port_key AS key, name, alias AS description, speed_bps
            FROM switch_ports WHERE source_id = ? ORDER BY if_index, port_key
        """, (source_id,))]
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
    selected = next((port for port in result["interfaces"] if port["key"] == interface), None)
    if selected is not None:
        rows = conn.execute(
            samples + " ORDER BY observed_at DESC, id DESC LIMIT ?",
            (source_id, interface, cutoff, MAX_POINTS),
        ).fetchall()
        result["selected"] = selected
        result["points"] = _traffic_points(rows, switch=switch)
    return result
