from __future__ import annotations

import sqlite3
from typing import Any


DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
OPTIONAL_STATE_DEFAULT_PAGE_SIZE = 500
OPTIONAL_STATE_MAX_PAGE_SIZE = 5000


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
    return _page(
        conn,
        """
        SELECT s.name AS source, n.local_port_key, n.chassis_id, n.port_id,
               n.system_name, n.observed_at, n.collector_run_id
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
