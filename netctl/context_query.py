from __future__ import annotations

import sqlite3
from typing import Any

from .normalizer import normalize_mac
from .findings import findings_for_asset
from .runtime_assets import (
    get_runtime_asset_by_key,
    list_asset_interfaces,
    list_current_hostname_observations,
    list_current_ip_observations,
)


def _asset_public(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        key: asset[key]
        for key in ("asset_key", "kind", "status", "site", "location", "display_name", "identity_method", "identity_confidence", "provisional")
        if key in asset
    }


def _attachment(conn: sqlite3.Connection, asset_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT status, selected_source_id, selected_port_key, selected_vlan_key,
                  selected_vlan_id, confidence, last_seen_at
           FROM asset_attachment_resolutions
           WHERE asset_id = ? ORDER BY confidence DESC, asset_interface_id LIMIT 1""",
        (asset_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def inspect_asset_context(conn: sqlite3.Connection, asset_key: str) -> dict[str, Any] | None:
    asset = get_runtime_asset_by_key(conn, asset_key)
    if asset is None:
        return None
    asset_id = int(asset["id"])
    return {
        "asset": _asset_public(asset),
        "intent": None,
        "owner": None,
        "interfaces": [
            {key: item[key] for key in ("interface_key", "mac", "interface_type", "interface_name", "lifecycle") if key in item}
            for item in list_asset_interfaces(conn, asset_id)[:32]
        ],
        "attachment": _attachment(conn, asset_id),
        "network": {
            "ip_observations": list_current_ip_observations(conn, asset_id)[:64],
            "hostname_observations": list_current_hostname_observations(conn, asset_id)[:64],
        },
        "topology_path": {"nodes": [], "complete": False, "reason": "no_attachment"},
        "source_health": [],
        "findings": findings_for_asset(conn, asset_id),
        "evidence": {},
    }


def search_context(conn: sqlite3.Connection, query: str, limit: int = 25) -> list[dict[str, Any]]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    value = query.strip()
    if not value:
        return []
    normalized_mac = normalize_mac(value)
    params: list[object] = [value.lower(), value.lower(), value.lower()]
    conditions = ["lower(assets.asset_key) = ?", "lower(hostnames.hostname) = ?", "ips.ip = ?"]
    if normalized_mac is not None:
        conditions.append("lower(replace(replace(interfaces.mac, ':', ''), '-', '')) = ?")
        params.append(normalized_mac.replace(":", "").lower())
    rows = conn.execute(
        f"""
        SELECT DISTINCT assets.asset_key, assets.display_name, assets.kind, assets.site
        FROM assets
        LEFT JOIN asset_interfaces AS interfaces ON interfaces.asset_id = assets.id
        LEFT JOIN ip_observations AS ips ON ips.asset_id = assets.id AND ips.is_current = 1
        LEFT JOIN hostname_observations AS hostnames ON hostnames.asset_id = assets.id AND hostnames.is_current = 1
        WHERE {' OR '.join(conditions)}
        ORDER BY assets.asset_key
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()
    return [dict(row) for row in rows]
