from __future__ import annotations

import json
import sqlite3
from typing import Any


def get_runtime_asset_by_key(
    conn: sqlite3.Connection, asset_key: str
) -> dict[str, Any] | None:
    """Return the runtime asset identified by its stable runtime key."""
    row = conn.execute(
        "SELECT * FROM assets WHERE asset_key = ?",
        (asset_key,),
    ).fetchone()
    return dict(row) if row is not None else None


def list_asset_interfaces(
    conn: sqlite3.Connection, asset_id: int
) -> list[dict[str, Any]]:
    """Return an asset's interfaces in stable key order."""
    rows = conn.execute(
        """
        SELECT * FROM asset_interfaces
        WHERE asset_id = ?
        ORDER BY interface_key, mac, interface_type, interface_name, id
        """,
        (asset_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_current_ip_observations(
    conn: sqlite3.Connection, asset_id: int
) -> list[dict[str, Any]]:
    """Return current IP observations, newest evidence first."""
    rows = conn.execute(
        """
        SELECT * FROM ip_observations
        WHERE asset_id = ? AND is_current = 1
        ORDER BY last_seen_at DESC, first_seen_at DESC, ip, source_key,
                 observation_source, id
        """,
        (asset_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_current_hostname_observations(
    conn: sqlite3.Connection, asset_id: int
) -> list[dict[str, Any]]:
    """Return current hostname observations, newest evidence first."""
    rows = conn.execute(
        """
        SELECT * FROM hostname_observations
        WHERE asset_id = ? AND is_current = 1
        ORDER BY last_seen_at DESC, first_seen_at DESC, hostname, source_key,
                 source_type, id
        """,
        (asset_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def runtime_identity_report(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Return the runtime-identity migration report with JSON arrays decoded."""
    row = conn.execute(
        "SELECT * FROM runtime_asset_migration_reports WHERE migration_version = ?",
        (2,),
    ).fetchone()
    if row is None:
        return None

    report = dict(row)
    for field in (
        "unresolved_legacy_host_ids",
        "unresolved_observation_ids",
        "unresolved_tag_records",
        "aggregation_conflicts",
    ):
        report[field] = _decode_json_array(report.pop(f"{field}_json", "[]"))
    return report


def _decode_json_array(value: Any) -> list[Any]:
    try:
        decoded = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        return []
    return decoded if isinstance(decoded, list) else []
