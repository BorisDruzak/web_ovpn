from __future__ import annotations

from dataclasses import replace
import json
import sqlite3
from typing import TYPE_CHECKING, TypedDict

from .util import utc_now

if TYPE_CHECKING:
    from .context_classifier import SegmentRule


ALLOWED_INTERVAL_MINUTES = (5, 10, 15, 30, 60)


class AvailabilitySegmentSetting(TypedDict):
    segment_id: str
    enabled: bool
    tcp_ports: tuple[int, ...]
    interval_minutes: int
    updated_at: str


def _validated_tcp_ports(tcp_ports: tuple[int, ...]) -> tuple[int, ...]:
    if not isinstance(tcp_ports, tuple):
        raise ValueError("tcp_ports must be a tuple")
    if len(tcp_ports) > 3:
        raise ValueError("tcp_ports must contain at most 3 ports")
    if any(not isinstance(port, int) or isinstance(port, bool) for port in tcp_ports):
        raise ValueError("tcp_ports must contain integers")
    if any(port < 1 or port > 65535 for port in tcp_ports):
        raise ValueError("tcp_ports must contain ports in 1..65535")
    if len(set(tcp_ports)) != len(tcp_ports):
        raise ValueError("tcp_ports must not contain duplicates")
    return tuple(sorted(tcp_ports))


def _validated_interval(interval_minutes: int) -> int:
    if (
        not isinstance(interval_minutes, int)
        or isinstance(interval_minutes, bool)
        or interval_minutes not in ALLOWED_INTERVAL_MINUTES
    ):
        raise ValueError("interval_minutes must be one of 5, 10, 15, 30, 60")
    return interval_minutes


def _setting_from_row(row: sqlite3.Row) -> AvailabilitySegmentSetting:
    try:
        ports_value = json.loads(str(row["tcp_ports_json"]))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("stored availability tcp_ports are invalid") from exc
    if not isinstance(ports_value, list):
        raise ValueError("stored availability tcp_ports are invalid")
    ports = _validated_tcp_ports(tuple(ports_value))
    interval_minutes = _validated_interval(int(row["interval_minutes"]))
    enabled_value = row["enabled"]
    if enabled_value not in (0, 1):
        raise ValueError("stored availability enabled value is invalid")
    return {
        "segment_id": str(row["segment_id"]),
        "enabled": bool(enabled_value),
        "tcp_ports": ports,
        "interval_minutes": interval_minutes,
        "updated_at": str(row["updated_at"]),
    }


def list_availability_settings(conn: sqlite3.Connection) -> list[AvailabilitySegmentSetting]:
    rows = conn.execute(
        """
        SELECT segment_id, enabled, tcp_ports_json, interval_minutes, updated_at
        FROM availability_segment_settings
        ORDER BY segment_id
        """
    ).fetchall()
    return [_setting_from_row(row) for row in rows]


def set_availability_setting(
    conn: sqlite3.Connection,
    segment_id: str,
    *,
    enabled: bool,
    tcp_ports: tuple[int, ...],
    interval_minutes: int,
) -> AvailabilitySegmentSetting:
    """Persist a bounded override only for an active canonical IPv4 segment."""
    ports = _validated_tcp_ports(tcp_ports)
    interval = _validated_interval(interval_minutes)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    if not isinstance(segment_id, str) or not segment_id:
        raise ValueError("segment_id must be a non-empty string")

    from .context_classifier import load_active_segment_rules

    rules_by_id = {rule.segment_id: rule for rule in load_active_segment_rules(conn)}
    rule = rules_by_id.get(segment_id)
    if rule is None or rule.network.version != 4:
        raise ValueError("setting requires an active IPv4 segment")

    updated_at = utc_now()
    conn.execute(
        """
        INSERT INTO availability_segment_settings (
            segment_id, enabled, tcp_ports_json, interval_minutes, updated_at
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(segment_id) DO UPDATE SET
            enabled=excluded.enabled,
            tcp_ports_json=excluded.tcp_ports_json,
            interval_minutes=excluded.interval_minutes,
            updated_at=excluded.updated_at
        """,
        (
            segment_id,
            int(enabled),
            json.dumps(list(ports), separators=(",", ":")),
            interval,
            updated_at,
        ),
    )
    conn.commit()
    return {
        "segment_id": segment_id,
        "enabled": enabled,
        "tcp_ports": ports,
        "interval_minutes": interval,
        "updated_at": updated_at,
    }


def resolve_availability_segment_rules(
    conn: sqlite3.Connection, rules: list[SegmentRule]
) -> list[SegmentRule]:
    """Overlay persisted values without ever replacing canonical segment identity or CIDR."""
    settings_by_segment_id = {
        setting["segment_id"]: setting for setting in list_availability_settings(conn)
    }
    resolved: list[SegmentRule] = []
    for rule in rules:
        setting = settings_by_segment_id.get(rule.segment_id)
        if setting is None or rule.network.version != 4:
            resolved.append(rule)
            continue
        resolved.append(
            replace(
                rule,
                availability_monitoring=setting["enabled"],
                availability_tcp_ports=setting["tcp_ports"],
                availability_interval_minutes=setting["interval_minutes"],
            )
        )
    return resolved


def load_active_availability_segments(conn: sqlite3.Connection) -> tuple[SegmentRule, ...]:
    """Expose effective segments through the settings module without duplicating the resolver."""
    from .context_classifier import load_active_availability_segments as load_effective_segments

    return load_effective_segments(conn)
