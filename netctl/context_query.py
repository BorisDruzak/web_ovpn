from __future__ import annotations

import json
import sqlite3
from collections import deque
from typing import Any

from .normalizer import normalize_mac
from .findings import findings_for_asset
from .runtime_assets import (
    get_runtime_asset_by_key,
    list_asset_interfaces,
    list_current_hostname_observations,
    list_current_ip_observations,
)
from .util import utc_now


def _asset_public(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        key: asset[key]
        for key in ("asset_key", "kind", "status", "site", "location", "display_name", "identity_method", "identity_confidence", "provisional")
        if key in asset
    }


def _attachment(conn: sqlite3.Connection, asset_id: int, asset_interface_id: int | None = None) -> dict[str, Any] | None:
    conditions = ["asset_id = ?"]
    params: list[object] = [asset_id]
    if asset_interface_id is not None:
        conditions.append("asset_interface_id = ?")
        params.append(asset_interface_id)
    row = conn.execute(
        f"""SELECT status, selected_source_id, selected_port_key, selected_vlan_key,
                  selected_vlan_id, confidence, last_seen_at
           FROM asset_attachment_resolutions
           WHERE {' AND '.join(conditions)} ORDER BY confidence DESC, asset_interface_id LIMIT 1""",
        params,
    ).fetchone()
    if row is None:
        return None
    attachment = dict(row)
    alternatives = conn.execute(
        f"""SELECT sources.name AS source, candidates.port_key, candidates.vlan_key,
                  candidates.vlan_id, candidates.candidate_class,
                  candidates.topology_depth, candidates.score, candidates.observed_at
           FROM asset_attachment_candidates AS candidates
           JOIN network_sources AS sources ON sources.id = candidates.switch_source_id
           WHERE candidates.asset_id = ? {"AND candidates.asset_interface_id = ?" if asset_interface_id is not None else ""}
           ORDER BY candidates.score DESC, candidates.observed_at DESC,
                    sources.name, candidates.port_key, candidates.vlan_key
           LIMIT 32""",
        (asset_id, asset_interface_id) if asset_interface_id is not None else (asset_id,),
    ).fetchall()
    attachment["alternatives"] = [dict(item) for item in alternatives]
    return attachment


def _owner(conn: sqlite3.Connection, asset_id: int) -> dict[str, Any]:
    timestamp = utc_now()
    rows = [dict(row) for row in conn.execute(
        """SELECT users.user_key, users.display_name, bindings.relation, bindings.status,
                  bindings.confidence, bindings.valid_from, bindings.valid_until, bindings.binding_source
           FROM user_asset_bindings AS bindings
           JOIN users ON users.id = bindings.user_id
           WHERE bindings.asset_id = ? AND users.status = 'active' AND bindings.status = 'confirmed'
             AND bindings.relation IN ('owner', 'primary_user', 'shared_user')
             AND bindings.valid_from <= ? AND (bindings.valid_until IS NULL OR bindings.valid_until > ?)
           ORDER BY users.user_key, bindings.id LIMIT 32""",
        (asset_id, timestamp, timestamp),
    )]
    shared = [row for row in rows if row["relation"] == "shared_user"]
    exclusive = [row for row in rows if row["relation"] in {"owner", "primary_user"}]
    if shared:
        status = "shared"
    elif len(exclusive) == 1:
        status = "confirmed"
    elif len(exclusive) > 1:
        status = "ambiguous"
    else:
        status = "none"
    return {"status": status, "bindings": rows}


def _intent(conn: sqlite3.Connection, asset_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT context_id, intent_stable_id, binding_source, confidence, status, last_seen_at
           FROM asset_intent_bindings WHERE asset_id = ?
           ORDER BY confidence DESC, last_seen_at DESC, id DESC LIMIT 1""",
        (asset_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def _source_health(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            "SELECT name AS source, last_collect_at, last_status FROM network_sources ORDER BY name, id LIMIT 64"
        )
    ]


def _topology_path(conn: sqlite3.Connection, attachment: dict[str, Any] | None) -> dict[str, Any]:
    if attachment is None or attachment.get("status") != "confirmed" or attachment.get("selected_source_id") is None:
        return {"nodes": [], "complete": False, "reason": "no_attachment"}
    roots: set[int] = set()
    for row in conn.execute("SELECT id, driver_options_json FROM network_sources"):
        try:
            options = json.loads(str(row["driver_options_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            options = {}
        if isinstance(options, dict) and options.get("topology_role") == "core":
            roots.add(int(row["id"]))
    start = int(attachment["selected_source_id"])
    adjacency: dict[int, set[int]] = {}
    for row in conn.execute("SELECT source_a_id, source_b_id FROM current_switch_links WHERE state != 'conflicting'"):
        first, second = int(row["source_a_id"]), int(row["source_b_id"])
        adjacency.setdefault(first, set()).add(second)
        adjacency.setdefault(second, set()).add(first)
    queue: deque[tuple[int, list[int]]] = deque([(start, [start])])
    seen = {start}
    while queue:
        source_id, path = queue.popleft()
        if source_id in roots:
            return {"nodes": path[:32], "complete": True, "reason": ""}
        for peer in sorted(adjacency.get(source_id, set())):
            if peer not in seen:
                seen.add(peer)
                queue.append((peer, path + [peer]))
    return {"nodes": [start], "complete": False, "reason": "no_core_path"}


def inspect_asset_context(conn: sqlite3.Connection, asset_key: str) -> dict[str, Any] | None:
    asset = get_runtime_asset_by_key(conn, asset_key)
    if asset is None:
        return None
    asset_id = int(asset["id"])
    return {
        "asset": _asset_public(asset),
        "intent": _intent(conn, asset_id),
        "owner": _owner(conn, asset_id),
        "interfaces": [
            {
                **{key: item[key] for key in ("interface_key", "mac", "interface_type", "interface_name", "lifecycle") if key in item},
                "attachment": _attachment(conn, asset_id, int(item["id"])),
            }
            for item in list_asset_interfaces(conn, asset_id)[:32]
        ],
        "attachment": _attachment(conn, asset_id),
        "network": {
            "ip_observations": list_current_ip_observations(conn, asset_id)[:64],
            "hostname_observations": list_current_hostname_observations(conn, asset_id)[:64],
        },
        "topology_path": _topology_path(conn, _attachment(conn, asset_id)),
        "source_health": _source_health(conn),
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
    params: list[object] = [value.lower(), value.lower(), value.lower(), value.lower()]
    conditions = ["lower(assets.asset_key) = ?", "lower(hostnames.hostname) = ?", "ips.ip = ?", "lower(intent_bindings.intent_stable_id) = ?"]
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
        LEFT JOIN asset_intent_bindings AS intent_bindings ON intent_bindings.asset_id = assets.id
        WHERE {' OR '.join(conditions)}
        ORDER BY assets.asset_key
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()
    results = [dict(row) for row in rows]
    for item in results:
        item["bindings"] = _confirmed_asset_bindings(conn, str(item["asset_key"]))
    if len(results) >= limit:
        return results
    users = conn.execute(
        """SELECT user_key, display_name, status
           FROM users
           WHERE lower(user_key) = ? OR lower(display_name) = ?
           ORDER BY user_key
           LIMIT ?""",
        (value.lower(), value.lower(), limit - len(results)),
    ).fetchall()
    results.extend(
        {
            "result_type": "user",
            "user_key": row["user_key"],
            "display_name": row["display_name"],
            "status": row["status"],
            "bindings": _confirmed_user_bindings(conn, str(row["user_key"])),
        }
        for row in users
    )
    return results


def _confirmed_asset_bindings(conn: sqlite3.Connection, asset_key: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT users.user_key, users.display_name, bindings.relation, bindings.confidence
           FROM user_asset_bindings AS bindings
           JOIN users ON users.id = bindings.user_id
           JOIN assets ON assets.id = bindings.asset_id
           WHERE assets.asset_key = ? AND bindings.status = 'confirmed'
           ORDER BY users.user_key, bindings.id LIMIT 32""",
        (asset_key,),
    ).fetchall()
    return [dict(row) for row in rows]


def _confirmed_user_bindings(conn: sqlite3.Connection, user_key: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT assets.asset_key, bindings.relation
           FROM user_asset_bindings AS bindings
           JOIN users ON users.id = bindings.user_id
           JOIN assets ON assets.id = bindings.asset_id
           WHERE users.user_key = ? AND bindings.status = 'confirmed'
           ORDER BY assets.asset_key, bindings.id LIMIT 32""",
        (user_key,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_topology_context(
    conn: sqlite3.Connection,
    site: str = "",
    state: str = "",
    depth: int = 4,
) -> list[dict[str, Any]]:
    if not 1 <= depth <= 32:
        raise ValueError("depth must be between 1 and 32")
    if state not in {"", "confirmed", "inferred", "ambiguous", "conflicting"}:
        raise ValueError("invalid topology state")
    conditions: list[str] = []
    params: list[object] = []
    if site:
        conditions.append("(source_a.site = ? OR source_b.site = ?)")
        params.extend([site, site])
    if state:
        conditions.append("links.state = ?")
        params.append(state)
    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = conn.execute(
        f"""
        SELECT links.link_key, links.port_a_key, links.port_b_key, links.state,
               links.confidence, links.first_seen_at, links.last_seen_at,
               source_a.name AS source_a, source_b.name AS source_b
        FROM current_switch_links AS links
        JOIN network_sources AS source_a ON source_a.id = links.source_a_id
        JOIN network_sources AS source_b ON source_b.id = links.source_b_id
        {where}
        ORDER BY links.link_key
        LIMIT 256
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]
