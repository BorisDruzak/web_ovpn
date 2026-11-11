from __future__ import annotations

import json
import sqlite3
from typing import Any


DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
OPTIONAL_STATE_DEFAULT_PAGE_SIZE = 500
OPTIONAL_STATE_MAX_PAGE_SIZE = 5000
_LLDP_FINGERPRINT_TYPES = {
    "bridge": "network",
    "router": "network",
    "telephone": "phone",
    "wlan_access_point": "network",
}
_FDB_PORT_MATCH = """
    p.source_id = f.source_id AND p.collector_run_id = f.collector_run_id
    AND (
        p.port_key = f.port_key
        OR (f.port_key LIKE 'physical:%' AND f.if_index > 0 AND p.port_key = 'ifindex:' || f.if_index
            AND NOT EXISTS (
                SELECT 1 FROM switch_ports AS exact
                WHERE exact.source_id = f.source_id AND exact.port_key = f.port_key
                  AND exact.collector_run_id = f.collector_run_id
            ))
    )
"""


def query_confirmed_attachment_ports(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return confirmed direct FDB attachments with the original observation time."""
    return [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT DISTINCT candidates.switch_source_id AS source_id, p.port_key,
                   candidates.vlan_id, interfaces.mac, candidates.observed_at
            FROM asset_attachment_resolutions AS resolutions
            JOIN asset_attachment_candidates AS candidates
              ON candidates.asset_interface_id = resolutions.asset_interface_id
             AND candidates.switch_source_id = resolutions.selected_source_id
             AND candidates.port_key = resolutions.selected_port_key
             AND candidates.vlan_key = resolutions.selected_vlan_key
             AND candidates.correlation_run_id = resolutions.correlation_run_id
            JOIN asset_interfaces AS interfaces ON interfaces.id = candidates.asset_interface_id
            JOIN network_sources AS sources ON sources.id = candidates.switch_source_id
            JOIN current_switch_fdb AS f
              ON f.source_id = candidates.switch_source_id AND f.port_key = candidates.port_key
             AND f.vlan_key = candidates.vlan_key AND f.mac = interfaces.mac COLLATE NOCASE
            JOIN switch_ports AS p ON {_FDB_PORT_MATCH}
            WHERE resolutions.status = 'confirmed' AND candidates.candidate_class = 'direct'
              AND interfaces.lifecycle = 'active' AND sources.enabled = 1 AND p.oper_status = 'up'
              AND lower(f.status) NOT IN ('self', 'mgmt')
            ORDER BY candidates.switch_source_id, p.port_key, candidates.vlan_id, interfaces.mac
            """
        )
    ]


def query_observed_mac_ports(
    conn: sqlite3.Connection, macs: set[str], *, learned_only: bool = False,
) -> list[dict[str, Any]]:
    if not macs:
        return []
    return [dict(row) for row in conn.execute(
        f"""
        SELECT f.source_id, p.port_key, f.mac, f.vlan_id, f.last_seen_at AS observed_at
        FROM current_switch_fdb AS f
        JOIN network_sources AS s ON s.id = f.source_id
        JOIN switch_ports AS p ON {_FDB_PORT_MATCH}
        WHERE lower(f.mac) IN (SELECT value FROM json_each(?))
          AND s.enabled = 1 AND p.oper_status = 'up' AND lower(f.status) NOT IN ('self', 'mgmt')
          AND (? = 0 OR lower(f.status) = 'learned')
        ORDER BY f.source_id, f.port_key, f.vlan_id, f.mac
        """,
        (json.dumps(sorted(macs)), learned_only),
    )]


def validate_pagination(
    limit: int, offset: int, *, maximum: int = MAX_PAGE_SIZE
) -> None:
    if type(limit) is not int or not 1 <= limit <= maximum:
        raise ValueError(f"limit must be between 1 and {maximum}")
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be zero or greater")


def _page(
    conn: sqlite3.Connection,
    sql: str,
    params: list[Any],
    *,
    limit: int,
    offset: int,
    maximum: int = MAX_PAGE_SIZE,
) -> dict[str, Any]:
    validate_pagination(limit, offset, maximum=maximum)
    rows = [
        dict(row)
        for row in conn.execute(sql, [*params, limit + 1, offset]).fetchall()
    ]
    has_more = len(rows) > limit
    items = rows[:limit]
    return {
        "items": items,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "returned": len(items),
            "has_more": has_more,
            "next_offset": offset + len(items) if has_more else None,
        },
    }


def query_switch_ports(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, Any]:
    where, params = _source_filter(source)
    return _page(
        conn,
        """
        SELECT s.name AS source, p.port_key, p.if_index, p.bridge_port,
               p.physical_port, p.name, p.alias, p.mac, p.admin_status,
               p.oper_status, p.speed_bps, p.last_seen_at, p.collector_run_id
        FROM switch_ports AS p
        JOIN network_sources AS s ON s.id = p.source_id
        """
        + where
        + " ORDER BY s.name, p.port_key LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
    )


def query_switch_fdb(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    vlan: int | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, Any]:
    predicates, params = _predicates(source)
    if vlan is not None:
        predicates.append("f.vlan_id = ?")
        params.append(vlan)
    return _page(
        conn,
        """
        SELECT s.name AS source, f.fdb_id, f.vlan_key, f.vlan_id, f.mac,
               f.port_key, f.bridge_port, f.if_index, f.physical_port,
               f.port_name, f.status, f.first_seen_at, f.last_seen_at,
               f.collector_run_id
        FROM current_switch_fdb AS f
        JOIN network_sources AS s ON s.id = f.source_id
        """
        + _where(predicates)
        + " ORDER BY s.name, f.vlan_key, f.mac LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
    )


def query_switch_events(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    event_type: str = "",
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, Any]:
    predicates, params = _predicates(source)
    if event_type:
        predicates.append("e.event_type = ?")
        params.append(event_type)
    return _page(
        conn,
        """
        SELECT e.id, s.name AS source, e.fdb_id, e.vlan_key, e.vlan_id,
               e.mac, e.event_type, e.old_port_key, e.new_port_key,
               e.observed_at, e.collector_run_id
        FROM switch_fdb_events AS e
        JOIN network_sources AS s ON s.id = e.source_id
        """
        + _where(predicates)
        + " ORDER BY e.observed_at DESC, e.id DESC LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
    )


def query_switch_capabilities(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, Any]:
    where, params = _source_filter(source)
    return _page(
        conn,
        """
        SELECT s.name AS source, c.capability, c.outcome, c.rows_seen,
               c.profile_fingerprint, c.checked_at, c.expires_at
        FROM switch_capabilities AS c
        JOIN network_sources AS s ON s.id = c.source_id
        """
        + where
        + " ORDER BY s.name, c.capability LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
    )


def query_switch_vlans(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    limit: int = OPTIONAL_STATE_DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, object]:
    where, params = _source_filter(source)
    return _page(
        conn,
        """
        SELECT s.name AS source, v.vlan_id, v.port_key, v.if_index,
               v.bridge_port, v.physical_port, v.port_name, v.egress,
               v.untagged, v.pvid, v.observed_at, v.collector_run_id
        FROM current_switch_vlan_memberships AS v
        JOIN network_sources AS s ON s.id = v.source_id
        """
        + where
        + " ORDER BY s.name, v.vlan_id, v.port_key LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
        maximum=OPTIONAL_STATE_MAX_PAGE_SIZE,
    )


def query_switch_lldp_neighbors(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    limit: int = OPTIONAL_STATE_DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, object]:
    where, params = _source_filter(source)
    page = _page(
        conn,
        """
        SELECT s.name AS source, n.local_port_key, n.chassis_id, n.port_id,
               n.system_name, n.observed_at, n.collector_run_id,
               n.chassis_id_subtype, n.port_id_subtype, n.port_description,
               n.system_description, n.system_capabilities_json,
               n.enabled_capabilities_json, n.management_addresses_json
        FROM current_switch_lldp_neighbors AS n
        JOIN network_sources AS s ON s.id = n.source_id
        """
        + where
        + " ORDER BY s.name, n.local_port_key, n.chassis_id, n.port_id "
        "LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
        maximum=OPTIONAL_STATE_MAX_PAGE_SIZE,
    )
    for row in page["items"]:
        system_capabilities = _string_list(
            row.pop("system_capabilities_json", "[]")
        )
        enabled_capabilities = _string_list(
            row.pop("enabled_capabilities_json", "[]")
        )
        row["system_capabilities"] = system_capabilities
        row["enabled_capabilities"] = enabled_capabilities
        row["management_addresses"] = _string_list(
            row.pop("management_addresses_json", "[]")
        )
        row["fingerprint_evidence"] = _lldp_fingerprint_evidence(
            system_capabilities, enabled_capabilities
        )
    return page


def query_switch_stp(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    limit: int = OPTIONAL_STATE_DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, object]:
    where, params = _source_filter(source)
    return _page(
        conn,
        """
        SELECT s.name AS source, stp.protocol, stp.root_bridge_mac,
               stp.root_port_key, stp.root_path_cost, stp.topology_changes,
               stp.observed_at
        FROM current_switch_stp_state AS stp
        JOIN network_sources AS s ON s.id = stp.source_id
        """
        + where
        + " ORDER BY s.name LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
        maximum=OPTIONAL_STATE_MAX_PAGE_SIZE,
    )


def query_switch_telemetry(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, Any]:
    where, params = _source_filter(source)
    return _page(
        conn,
        """
        SELECT s.name AS source, t.port_key, p.if_index, p.speed_bps,
               t.collector_run_id, t.observed_at, t.sample_interval_seconds,
               t.rx_bps, t.tx_bps, t.rx_utilization_pct,
               t.tx_utilization_pct, t.in_errors_delta, t.out_errors_delta,
               t.in_discards_delta, t.out_discards_delta, t.telemetry_state
        FROM current_switch_port_telemetry AS t
        JOIN network_sources AS s ON s.id = t.source_id
        LEFT JOIN switch_ports AS p
          ON p.source_id = t.source_id AND p.port_key = t.port_key
        """
        + where
        + " ORDER BY s.name, t.port_key LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
    )


def query_switch_port_roles(
    conn: sqlite3.Connection,
    *,
    source: str = "",
    limit: int = OPTIONAL_STATE_DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> dict[str, object]:
    where, params = _source_filter(source)
    page = _page(
        conn,
        """
        SELECT s.name AS source, roles.port_key, roles.role, roles.confidence,
               roles.mac_count, roles.known_asset_count,
               roles.unique_vendor_count, child.name AS child_source,
               roles.evidence_json, roles.observed_at, roles.correlation_run_id
        FROM current_switch_port_roles AS roles
        JOIN network_sources AS s ON s.id = roles.source_id
        LEFT JOIN network_sources AS child ON child.id = roles.child_source_id
        """
        + where
        + " ORDER BY s.name, roles.port_key LIMIT ? OFFSET ?",
        params,
        limit=limit,
        offset=offset,
        maximum=OPTIONAL_STATE_MAX_PAGE_SIZE,
    )
    for row in page["items"]:
        row["evidence"] = _port_role_evidence(row.pop("evidence_json", "[]"))
    return page


def query_switch_status(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            """
            SELECT s.name AS source, s.host, s.site, s.role, s.enabled,
                   d.profile_id, d.sys_name, d.last_success_at,
                   (SELECT r.status FROM switch_collection_runs AS r
                    WHERE r.source_id = s.id
                    ORDER BY r.started_at DESC, r.id DESC LIMIT 1) AS last_status,
                   (SELECT COUNT(*) FROM switch_ports AS p
                    WHERE p.source_id = s.id) AS ports,
                   (SELECT COUNT(*) FROM current_switch_fdb AS f
                    WHERE f.source_id = s.id) AS fdb_entries
            FROM network_sources AS s
            LEFT JOIN switch_devices AS d ON d.source_id = s.id
            WHERE s.driver = 'snmp_switch'
            ORDER BY s.name
            """
        ).fetchall()
    ]


def _predicates(source: str) -> tuple[list[str], list[Any]]:
    if not source:
        return [], []
    return ["s.name = ?"], [source]


def _source_filter(source: str) -> tuple[str, list[Any]]:
    predicates, params = _predicates(source)
    return _where(predicates), params


def _where(predicates: list[str]) -> str:
    return " WHERE " + " AND ".join(predicates) if predicates else ""


def _string_list(value: object) -> list[str]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if (
        type(decoded) is not list
        or len(decoded) > 16
        or any(type(item) is not str for item in decoded)
    ):
        return []
    return decoded


def _port_role_evidence(value: object) -> list[dict[str, object]]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if type(decoded) is not list:
        return []
    allowed = {
        "type",
        "peer_source_id",
        "mac_count",
        "known_asset_count",
        "unique_vendor_count",
        "access_port_mac_threshold",
        "switch_management_mac_seen",
        "density_role",
        "child_source",
        "child_leaf_mac_count",
        "matched_mac_count",
        "coverage",
        "child_management_mac_seen",
        "suppressed_by",
    }
    return [
        {key: item[key] for key in allowed if key in item}
        for item in decoded[:16]
        if isinstance(item, dict) and isinstance(item.get("type"), str)
    ]


def _lldp_fingerprint_evidence(
    system_capabilities: list[str], enabled_capabilities: list[str]
) -> list[dict[str, object]]:
    evidence: list[dict[str, object]] = []
    seen: set[str] = set()
    for capability in (*system_capabilities, *enabled_capabilities):
        candidate_type = _LLDP_FINGERPRINT_TYPES.get(capability)
        if candidate_type is None or capability in seen:
            continue
        seen.add(capability)
        evidence.append(
            {
                "provider": "lldp",
                "signal": capability,
                "candidate_type": candidate_type,
                "weight": 90,
                "summary": f"LLDP {capability} capability",
            }
        )
    return evidence
