from __future__ import annotations

import json
import ipaddress
import sqlite3
from typing import Any

from .db import get_source
from .context_classifier import SegmentRule, legacy_segment_rules, load_active_segment_rules
from .normalizer import is_stale_noise_ip, normalize_hosts, normalize_mac
from .runtime_writer import (
    recompute_runtime_identity_findings,
    sync_runtime_hosts,
)
from .util import utc_now


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def device_key_for_host(host: dict[str, Any]) -> tuple[str, str]:
    mac = normalize_mac(host.get("mac"))
    if mac:
        return f"mac:{mac}", "mac"
    return f"ip:{host['ip']}", "ip"


def _normalize_tag(tag: str) -> str:
    value = tag.strip()
    if not value:
        raise ValueError("tag must not be empty")
    if any(char.isspace() for char in value):
        raise ValueError("tag must not contain whitespace")
    return value


def _decode_tags(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return sorted(str(item) for item in data if str(item).strip())
    return []


def _manual_tags(conn: sqlite3.Connection, device_key: str) -> list[str]:
    row = conn.execute("SELECT tags_json FROM network_device_tags WHERE device_key = ?", (device_key,)).fetchone()
    return _decode_tags(row["tags_json"] if row else None)


def resolve_device_key(conn: sqlite3.Connection, target: str) -> tuple[str, str]:
    raw = target.strip()
    if raw.startswith("mac:"):
        mac = normalize_mac(raw.removeprefix("mac:"))
        if not mac:
            raise ValueError("invalid MAC address")
        return f"mac:{mac}", "mac"
    if raw.startswith("ip:"):
        ip = str(ipaddress.ip_address(raw.removeprefix("ip:")))
        return f"ip:{ip}", "ip"
    mac = normalize_mac(raw)
    if mac:
        return f"mac:{mac}", "mac"
    ip = str(ipaddress.ip_address(raw))
    row = conn.execute("SELECT ip, mac FROM network_hosts WHERE ip = ?", (ip,)).fetchone()
    if row and row["mac"]:
        mac = normalize_mac(row["mac"])
        if mac:
            return f"mac:{mac}", "mac"
    return f"ip:{ip}", "ip"


def set_device_tags(conn: sqlite3.Connection, target: str, tags: list[str]) -> dict[str, Any]:
    device_key, match_type = resolve_device_key(conn, target)
    clean_tags = sorted({_normalize_tag(tag) for tag in tags})
    now = utc_now()
    if clean_tags:
        conn.execute(
            """
            INSERT INTO network_device_tags (device_key, match_type, tags_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_key) DO UPDATE SET
                match_type=excluded.match_type,
                tags_json=excluded.tags_json,
                updated_at=excluded.updated_at
            """,
            (device_key, match_type, _json(clean_tags), now, now),
        )
    else:
        conn.execute("DELETE FROM network_device_tags WHERE device_key = ?", (device_key,))
    _refresh_host_manual_tags(conn, device_key)
    conn.commit()
    return {"device_key": device_key, "match_type": match_type, "tags": clean_tags}


def add_device_tag(conn: sqlite3.Connection, target: str, tag: str) -> dict[str, Any]:
    device_key, _ = resolve_device_key(conn, target)
    tags = _manual_tags(conn, device_key)
    tags.append(tag)
    return set_device_tags(conn, target, tags)


def remove_device_tag(conn: sqlite3.Connection, target: str, tag: str) -> dict[str, Any]:
    device_key, _ = resolve_device_key(conn, target)
    remove = _normalize_tag(tag)
    tags = [item for item in _manual_tags(conn, device_key) if item != remove]
    return set_device_tags(conn, target, tags)


def list_device_tags(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        {
            "device_key": row["device_key"],
            "match_type": row["match_type"],
            "tags": _decode_tags(row["tags_json"]),
            "updated_at": row["updated_at"],
        }
        for row in conn.execute("SELECT * FROM network_device_tags ORDER BY device_key").fetchall()
    ]


def _refresh_host_manual_tags(conn: sqlite3.Connection, device_key: str) -> None:
    rows = conn.execute("SELECT * FROM network_hosts WHERE device_key = ?", (device_key,)).fetchall()
    for row in rows:
        host = decode_host(dict(row))
        auto_tags = host.get("auto_tags") or []
        manual_tags = _manual_tags(conn, device_key)
        merged = sorted(set(auto_tags) | set(manual_tags))
        conn.execute(
            "UPDATE network_hosts SET tags_json = ? WHERE id = ?",
            (_json({"sources": host.get("sources", []), "tags": merged, "auto_tags": auto_tags, "manual_tags": manual_tags}), row["id"]),
        )


def _clear_current(conn: sqlite3.Connection, source_id: int) -> None:
    for table in [
        "network_interfaces",
        "network_routes",
        "dhcp_leases",
        "arp_entries",
        "bridge_hosts",
        "network_neighbors",
        "firewall_address_lists",
        "firewall_rules",
        "update_posture",
        "update_posture_schedulers",
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
    device_key, _ = device_key_for_host(host)
    host["device_key"] = device_key
    auto_tags = sorted(host.get("tags", []))
    manual_tags = _manual_tags(conn, device_key)
    merged_tags = sorted(set(auto_tags) | set(manual_tags))
    conn.execute(
        """
        INSERT INTO network_hosts
            (ip, mac, hostname, display_name, category, device_key, device_type, device_confidence, device_evidence_json, status, site, first_seen_at, last_seen_at, last_source, tags_json, comment)
        VALUES
            (:ip, :mac, :hostname, :display_name, :category, :device_key, :device_type, :device_confidence, :device_evidence_json, :status, :site, :first_seen_at, :last_seen_at, :last_source, :tags_json, :comment)
        ON CONFLICT(ip) DO UPDATE SET
            mac=excluded.mac,
            hostname=excluded.hostname,
            display_name=excluded.display_name,
            category=excluded.category,
            device_key=excluded.device_key,
            device_type=excluded.device_type,
            device_confidence=excluded.device_confidence,
            device_evidence_json=excluded.device_evidence_json,
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
            "device_evidence_json": _json(host.get("device_evidence", [])),
            "tags_json": _json({"sources": host.get("sources", []), "tags": merged_tags, "auto_tags": auto_tags, "manual_tags": manual_tags}),
        },
    )
    row = conn.execute("SELECT id FROM network_hosts WHERE ip = ?", (host["ip"],)).fetchone()
    return int(row["id"])


def _demote_absent_noise_hosts(
    conn: sqlite3.Connection,
    source: dict[str, Any],
    current_ips: set[str],
    observed_at: str,
    *,
    segment_rules: list[SegmentRule],
) -> None:
    rows = conn.execute(
        """
        SELECT id, ip FROM network_hosts
        WHERE last_source = ? AND category IN ('unknown', 'telephony', 'wan', 'noise')
        """,
        (source["name"],),
    ).fetchall()
    for row in rows:
        ip = str(row["ip"])
        if ip in current_ips or not is_stale_noise_ip(ip, segment_rules=segment_rules):
            continue
        conn.execute(
            """
            UPDATE network_hosts
            SET category = ?, device_key = ?, device_type = ?, device_confidence = ?, device_evidence_json = ?, status = ?, last_seen_at = ?, tags_json = ?
            WHERE id = ?
            """,
            (
                "noise",
                f"ip:{ip}",
                "noise",
                50,
                _json(["stale_arp"]),
                "seen",
                observed_at,
                _json({"sources": [], "tags": ["device:noise", "noise", "stale_arp"], "auto_tags": ["device:noise", "noise", "stale_arp"], "manual_tags": []}),
                row["id"],
            ),
        )


def save_collection(
    conn: sqlite3.Connection,
    source: dict[str, Any],
    snapshot: dict[str, Any],
    started_at: str,
    status: str = "ok",
    message: str = "",
) -> dict[str, Any]:
    conn.execute("SAVEPOINT save_collection")
    try:
        counts = _save_collection(
            conn,
            source,
            snapshot,
            started_at,
            status=status,
            message=message,
        )
        conn.execute("RELEASE SAVEPOINT save_collection")
        conn.commit()
        return counts
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT save_collection")
        conn.execute("RELEASE SAVEPOINT save_collection")
        conn.rollback()
        raise


def _save_collection(
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
        "firewall_rules": sum(len(snapshot.get(key, [])) for key in ("firewall_filter_rules", "firewall_nat_rules", "firewall_mangle_rules")),
    }
    segment_rules = load_active_segment_rules(conn)
    classifier_fallback = not segment_rules
    if classifier_fallback:
        segment_rules = legacy_segment_rules()
    counts["context_classifier_fallback"] = classifier_fallback
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
              (source_id, dst_address, gateway, distance, active, disabled, dynamic, comment, routing_table, scope, target_scope, immediate_gateway, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                item.get("routing_table") or "main",
                item.get("scope"),
                item.get("target_scope"),
                item.get("immediate_gateway") or "",
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
    for item in snapshot.get("firewall_address_lists", []):
        conn.execute(
            """
            INSERT INTO firewall_address_lists
              (source_id, list, address, comment, dynamic, disabled, creation_time, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                item.get("list"),
                item.get("address"),
                item.get("comment"),
                int(bool(item.get("dynamic"))),
                int(bool(item.get("disabled"))),
                item.get("creation_time"),
                observed_at,
            ),
        )
    for key, table_name in {
        "firewall_filter_rules": "filter",
        "firewall_nat_rules": "nat",
        "firewall_mangle_rules": "mangle",
    }.items():
        for item in snapshot.get(key, []):
            conn.execute(
                """
                INSERT INTO firewall_rules
                  (source_id, identity, table_name, chain, action, disabled, src_address, dst_address, src_address_list, dst_address_list, protocol, comment, packets, bytes, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id,
                    item.get("id"),
                    table_name,
                    item.get("chain"),
                    item.get("action"),
                    int(bool(item.get("disabled"))),
                    item.get("src_address"),
                    item.get("dst_address"),
                    item.get("src_address_list"),
                    item.get("dst_address_list"),
                    item.get("protocol"),
                    item.get("comment"),
                    int(item.get("packets") or 0),
                    int(item.get("bytes") or 0),
                    observed_at,
                ),
            )
    posture = snapshot.get("update_posture") or {}
    if posture:
        conn.execute(
            """
            INSERT INTO update_posture
              (source_id, channel, installed_version, latest_version, routerboot_current_version, routerboot_upgrade_version, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                posture.get("channel"),
                posture.get("installed_version"),
                posture.get("latest_version"),
                posture.get("routerboot_current_version"),
                posture.get("routerboot_upgrade_version"),
                observed_at,
            ),
        )
        for scheduler in posture.get("schedulers", []):
            conn.execute(
                """
                INSERT INTO update_posture_schedulers
                  (source_id, name, disabled, next_run, interval, start_date, start_time, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id,
                    scheduler.get("name"),
                    int(bool(scheduler.get("disabled"))),
                    scheduler.get("next_run"),
                    scheduler.get("interval"),
                    scheduler.get("start_date"),
                    scheduler.get("start_time"),
                    observed_at,
                ),
            )

    source_for_normalizer = dict(source)
    hosts = normalize_hosts(source_for_normalizer, snapshot, observed_at, segment_rules=segment_rules)
    current_ips = {host["ip"] for host in hosts}
    for host in hosts:
        host_id = _upsert_host(conn, host)
        for item_type in ["arp", "dhcp_leases", "neighbors"]:
            for item in snapshot.get(item_type, []):
                if item.get("ip") == host["ip"] or item.get("address") == host["ip"]:
                    _insert_observation(conn, source_id, observed_at, item_type.rstrip("s"), item, host_id=host_id)
    _demote_absent_noise_hosts(
        conn,
        source,
        current_ips,
        observed_at,
        segment_rules=segment_rules,
    )

    runtime_counts: dict[str, int] = {}
    finding_counts: dict[str, int] = {}
    if status == "ok":
        runtime_counts = sync_runtime_hosts(
            conn,
            source=source,
            hosts=hosts,
            observed_at=observed_at,
        )
        finding_counts = recompute_runtime_identity_findings(
            conn,
            observed_at=observed_at,
        )
    counts.update(
        {
            "runtime_assets_touched": runtime_counts.get("assets_touched", 0),
            "runtime_ips_current": runtime_counts.get("ips_current", 0),
            "runtime_hostnames_current": runtime_counts.get("hostnames_current", 0),
            "runtime_findings_open": finding_counts.get("open", 0),
        }
    )

    if classifier_fallback:
        conn.execute(
            """
            INSERT INTO network_events
                (ts, source_id, host_id, severity, event_type, message, data_json)
            VALUES (?, ?, NULL, 'warning', 'context_classifier_fallback', ?, ?)
            """,
            (
                utc_now(),
                source_id,
                "no active context segment rules; using explicit legacy compatibility rules",
                _json({"context_classifier_fallback": True}),
            ),
        )

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
    conn.execute(
        """
        INSERT INTO network_events
            (ts, source_id, host_id, severity, event_type, message, data_json)
        VALUES (?, ?, NULL, ?, 'collect', ?, ?)
        """,
        (
            utc_now(),
            source_id,
            "info" if status == "ok" else "error",
            message or f"collect {source['name']}",
            _json(counts),
        ),
    )
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
    row["auto_tags"] = tags.get("auto_tags", [])
    row["manual_tags"] = tags.get("manual_tags", [])
    if not row.get("device_key") and row.get("ip"):
        row["device_key"] = device_key_for_host(row)[0]
    row["device_type"] = row.get("device_type") or "unknown"
    row["device_confidence"] = int(row.get("device_confidence") or 0)
    try:
        row["device_evidence"] = json.loads(row.get("device_evidence_json") or "[]")
    except json.JSONDecodeError:
        row["device_evidence"] = []
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
        if table == "bridge_hosts":
            if not mac:
                result[name] = []
                continue
            result[name] = [dict(row) for row in conn.execute("SELECT * FROM bridge_hosts WHERE mac = ? ORDER BY id DESC LIMIT 200", (mac,)).fetchall()]
            continue
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
