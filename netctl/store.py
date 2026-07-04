from __future__ import annotations

import json
import sqlite3
from typing import Any

from .db import get_source, insert_event
from .normalizer import is_stale_noise_ip, normalize_hosts
from .util import utc_now


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _clear_current(conn: sqlite3.Connection, source_id: int) -> None:
    for table in [
        "network_interfaces",
        "network_routes",
        "dhcp_leases",
        "arp_entries",
        "bridge_hosts",
        "network_neighbors",
    ]:
        conn.execute(f"DELETE FROM {table} WHERE source_id = ?", (source_id,))


def _insert_observation(
    conn: sqlite3.Connection,
    source_id: int,
    observed_at: str,
    observation_type: str,
    item: dict[str, Any],
    host_id: int | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO host_observations
            (host_id, source_id, observed_at, observation_type, ip, mac, hostname, interface, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            host_id,
            source_id,
            observed_at,
            observation_type,
            item.get("ip") or item.get("address"),
            item.get("mac"),
            item.get("hostname") or item.get("identity"),
            item.get("interface"),
            _json(item),
        ),
    )


def _upsert_host(conn: sqlite3.Connection, host: dict[str, Any]) -> int:
    existing = conn.execute("SELECT id, first_seen_at FROM network_hosts WHERE ip = ?", (host["ip"],)).fetchone()
    first_seen = existing["first_seen_at"] if existing else host["first_seen_at"]
    conn.execute(
        """
        INSERT INTO network_hosts
            (ip, mac, hostname, display_name, category, status, site, first_seen_at, last_seen_at, last_source, tags_json, comment)
        VALUES
            (:ip, :mac, :hostname, :display_name, :category, :status, :site, :first_seen_at, :last_seen_at, :last_source, :tags_json, :comment)
        ON CONFLICT(ip) DO UPDATE SET
            mac=excluded.mac,
            hostname=excluded.hostname,
            display_name=excluded.display_name,
            category=excluded.category,
            status=excluded.status,
            site=excluded.site,
            last_seen_at=excluded.last_seen_at,
            last_source=excluded.last_source,
            tags_json=excluded.tags_json,
            comment=excluded.comment
        """,
        {
            **host,
            "first_seen_at": first_seen,
            "tags_json": _json({"sources": host.get("sources", []), "tags": host.get("tags", [])}),
        },
    )
    row = conn.execute("SELECT id FROM network_hosts WHERE ip = ?", (host["ip"],)).fetchone()
    return int(row["id"])


def _demote_absent_noise_hosts(conn: sqlite3.Connection, source: dict[str, Any], current_ips: set[str], observed_at: str) -> None:
    rows = conn.execute(
        """
        SELECT id, ip FROM network_hosts
        WHERE last_source = ? AND category IN ('unknown', 'telephony', 'wan')
        """,
        (source["name"],),
    ).fetchall()
    for row in rows:
        ip = str(row["ip"])
        if ip in current_ips or not is_stale_noise_ip(ip):
            continue
        conn.execute(
            """
            UPDATE network_hosts
            SET category = ?, status = ?, last_seen_at = ?, tags_json = ?
            WHERE id = ?
            """,
            ("noise", "seen", observed_at, _json({"sources": [], "tags": ["noise", "stale_arp"]}), row["id"]),
        )


def save_collection(
    conn: sqlite3.Connection,
    source: dict[str, Any],
    snapshot: dict[str, Any],
    started_at: str,
    status: str = "ok",
    message: str = "",
) -> dict[str, Any]:
    source_id = int(source["id"])
    observed_at = utc_now()
    counts = {
        "arp": len(snapshot.get("arp", [])),
        "dhcp_leases": len(snapshot.get("dhcp_leases", [])),
        "interfaces": len(snapshot.get("interfaces", [])),
        "routes": len(snapshot.get("routes", [])),
        "neighbors": len(snapshot.get("neighbors", [])),
        "bridge_hosts": len(snapshot.get("bridge_hosts", [])),
        "firewall_address_lists": len(snapshot.get("firewall_address_lists", [])),
    }
    _clear_current(conn, source_id)

    for item in snapshot.get("interfaces", []):
        conn.execute(
            """
            INSERT INTO network_interfaces
              (source_id, name, type, running, disabled, mac, comment, rx_bytes, tx_bytes, rx_packets, tx_packets, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                item.get("name"),
                item.get("type"),
                int(bool(item.get("running"))),
                int(bool(item.get("disabled"))),
                item.get("mac"),
                item.get("comment"),
                int(item.get("rx_bytes") or 0),
                int(item.get("tx_bytes") or 0),
                int(item.get("rx_packets") or 0),
                int(item.get("tx_packets") or 0),
                observed_at,
            ),
        )
    for item in snapshot.get("routes", []):
        conn.execute(
            """
            INSERT INTO network_routes
              (source_id, dst_address, gateway, distance, active, disabled, dynamic, comment, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                item.get("dst_address"),
                item.get("gateway"),
                item.get("distance"),
                int(bool(item.get("active"))),
                int(bool(item.get("disabled"))),
                int(bool(item.get("dynamic"))),
                item.get("comment"),
                observed_at,
            ),
        )
    for item in snapshot.get("dhcp_leases", []):
        conn.execute(
            """
            INSERT INTO dhcp_leases
              (source_id, ip, mac, hostname, status, server, last_seen, expires_after, comment, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                item.get("ip"),
                item.get("mac"),
                item.get("hostname"),
                item.get("status"),
                item.get("server"),
                item.get("last_seen"),
                item.get("expires_after"),
                item.get("comment"),
                observed_at,
            ),
        )
        _insert_observation(conn, source_id, observed_at, "dhcp", item)
    for item in snapshot.get("arp", []):
        conn.execute(
            """
            INSERT INTO arp_entries
              (source_id, ip, mac, interface, complete, dynamic, comment, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                item.get("ip"),
                item.get("mac"),
                item.get("interface"),
                int(bool(item.get("complete"))),
                int(bool(item.get("dynamic"))),
                item.get("comment"),
                observed_at,
            ),
        )
        _insert_observation(conn, source_id, observed_at, "arp", item)
    for item in snapshot.get("bridge_hosts", []):
        conn.execute(
            """
            INSERT INTO bridge_hosts
              (source_id, mac, bridge, interface, dynamic, local, age, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                item.get("mac"),
                item.get("bridge"),
                item.get("interface"),
                int(bool(item.get("dynamic"))),
                int(bool(item.get("local"))),
                item.get("age"),
                observed_at,
            ),
        )
        _insert_observation(conn, source_id, observed_at, "bridge_host", item)
    for item in snapshot.get("neighbors", []):
        conn.execute(
            """
            INSERT INTO network_neighbors
              (source_id, address, mac, identity, interface, platform, version, uptime, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                item.get("address"),
                item.get("mac"),
                item.get("identity"),
                item.get("interface"),
                item.get("platform"),
                item.get("version"),
                item.get("uptime"),
                observed_at,
            ),
        )
        _insert_observation(conn, source_id, observed_at, "neighbor", item)

    source_for_normalizer = dict(source)
    hosts = normalize_hosts(source_for_normalizer, snapshot, observed_at)
    current_ips = {host["ip"] for host in hosts}
    for host in hosts:
        host_id = _upsert_host(conn, host)
        for item_type in ["arp", "dhcp_leases", "neighbors"]:
            for item in snapshot.get(item_type, []):
                if item.get("ip") == host["ip"] or item.get("address") == host["ip"]:
                    _insert_observation(conn, source_id, observed_at, item_type.rstrip("s"), item, host_id=host_id)
    _demote_absent_noise_hosts(conn, source, current_ips, observed_at)

    conn.execute(
        """
        INSERT INTO collection_runs (source_id, started_at, finished_at, status, message, counts_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (source_id, started_at, observed_at, status, message, _json(counts)),
    )
    conn.execute(
        "UPDATE network_sources SET last_collect_at = ?, last_status = ?, last_error = ? WHERE id = ?",
        (observed_at, status, message if status != "ok" else "", source_id),
    )
    insert_event(conn, "info" if status == "ok" else "error", "collect", message or f"collect {source['name']}", source_id=source_id, data=counts)
    conn.commit()
    return counts


def query_hosts(conn: sqlite3.Connection, q: str = "", category: str = "", status: str = "") -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if category and category != "all":
        clauses.append("category = ?")
        params.append(category)
    if status and status != "all":
        clauses.append("status = ?")
        params.append(status)
    if q:
        like = f"%{q.lower()}%"
        clauses.append("(lower(ip) LIKE ? OR lower(coalesce(mac,'')) LIKE ? OR lower(coalesce(hostname,'')) LIKE ? OR lower(coalesce(display_name,'')) LIKE ?)")
        params.extend([like, like, like, like])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM network_hosts{where} ORDER BY ip",
        params,
    ).fetchall()
    return [decode_host(dict(row)) for row in rows]


def decode_host(row: dict[str, Any]) -> dict[str, Any]:
    tags = {}
    if row.get("tags_json"):
        try:
            tags = json.loads(row["tags_json"])
        except json.JSONDecodeError:
            tags = {}
    row["sources"] = tags.get("sources", [])
    row["tags"] = tags.get("tags", [])
    return row


def inspect_host(conn: sqlite3.Connection, ip_or_id: str) -> dict[str, Any] | None:
    if ip_or_id.isdigit():
        row = conn.execute("SELECT * FROM network_hosts WHERE id = ?", (int(ip_or_id),)).fetchone()
    else:
        row = conn.execute("SELECT * FROM network_hosts WHERE ip = ?", (ip_or_id,)).fetchone()
    return decode_host(dict(row)) if row else None


def related_for_host(conn: sqlite3.Connection, host: dict[str, Any]) -> dict[str, Any]:
    ip = host["ip"]
    mac = host.get("mac")
    params = [ip]
    mac_clause = ""
    if mac:
        mac_clause = " OR mac = ?"
        params.append(mac)
    result = {}
    for name, table in [
        ("observations", "host_observations"),
        ("arp", "arp_entries"),
        ("dhcp_leases", "dhcp_leases"),
        ("bridge_hosts", "bridge_hosts"),
        ("neighbors", "network_neighbors"),
    ]:
        column = "ip" if table not in {"network_neighbors"} else "address"
        query = f"SELECT * FROM {table} WHERE {column} = ?{mac_clause} ORDER BY id DESC LIMIT 200"
        result[name] = [dict(row) for row in conn.execute(query, params).fetchall()]
    return result


def dashboard_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    hosts = [dict(row) for row in conn.execute("SELECT category, status FROM network_hosts").fetchall()]
    summary = {
        "total_hosts": len(hosts),
        "online": sum(1 for host in hosts if host.get("status") == "online"),
        "seen": sum(1 for host in hosts if host.get("status") == "seen"),
        "offline": sum(1 for host in hosts if host.get("status") == "offline"),
        "local_device": sum(1 for host in hosts if host.get("category") == "local_device"),
        "vpn_client": sum(1 for host in hosts if host.get("category") == "vpn_client"),
        "router": sum(1 for host in hosts if host.get("category") == "router"),
        "site_device": sum(1 for host in hosts if host.get("category") == "site_device"),
        "network_infra": sum(1 for host in hosts if host.get("category") == "network_infra"),
        "telephony": sum(1 for host in hosts if host.get("category") == "telephony"),
        "mgmt": sum(1 for host in hosts if host.get("category") == "mgmt"),
        "wan": sum(1 for host in hosts if host.get("category") == "wan"),
        "vipnet_transit": sum(1 for host in hosts if host.get("category") == "vipnet_transit"),
        "noise": sum(1 for host in hosts if host.get("category") == "noise"),
        "unknown": sum(1 for host in hosts if host.get("category") == "unknown"),
    }
    sources = [dict(row) for row in conn.execute("SELECT name, driver, host, site, role, enabled, last_collect_at, last_status, last_error FROM network_sources ORDER BY name").fetchall()]
    return {"summary": summary, "sources": sources}
