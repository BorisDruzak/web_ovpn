"""Build and publish the unprivileged collector's persistent public host view."""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .availability import bulk_project_host_availability
from .store import decode_host


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HostSnapshotStatus:
    snapshot_id: int = 0
    generated_at: str | None = None
    total_hosts: int = 0
    duration_ms: int = 0


@dataclass(frozen=True)
class BuiltHostSnapshot:
    rows: tuple[tuple[Any, ...], ...]
    sources: tuple[tuple[str, str], ...]


def snapshot_status(conn: sqlite3.Connection) -> HostSnapshotStatus:
    # Older read-only databases are valid but have no published snapshot yet.
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'network_host_snapshot_meta'").fetchone() is None:
        return HostSnapshotStatus()
    row = conn.execute(
        "SELECT snapshot_id, generated_at, total_hosts, duration_ms FROM network_host_snapshot_meta WHERE singleton = 1"
    ).fetchone()
    return HostSnapshotStatus(*row) if row else HostSnapshotStatus()


def build_host_snapshot(conn: sqlite3.Connection, *, now: str | datetime) -> BuiltHostSnapshot:
    rows = conn.execute(
        """SELECT network_hosts.*, assets.manual_name AS manual_name
           FROM network_hosts LEFT JOIN assets ON assets.asset_key = network_hosts.device_key"""
    ).fetchall()
    valid_hosts = []
    unprojected_hosts = []
    for row in rows:
        host = decode_host(dict(row))
        try:
            address = ipaddress.ip_address(str(host["ip"]))
        except ValueError:
            # Preserve malformed legacy rows for inspection, without projecting reachability.
            unprojected_hosts.append({**host, "status": "stale", "availability": None})
        else:
            if address.version == 4:
                valid_hosts.append(host)
            else:
                # The availability engine currently supports IPv4 targets only.
                unprojected_hosts.append({**host, "status": "stale", "availability": None})
    hosts = bulk_project_host_availability(conn, valid_hosts, now=now) + unprojected_hosts
    state_rows = []
    source_rows = []
    for host in hosts:
        ip = str(host["ip"])
        try:
            address = ipaddress.ip_address(ip)
            # Fixed-width unsigned numeric bytes avoid SQLite's signed 64-bit IPv6 limit.
            ip_sort = bytes([address.version]) + int(address).to_bytes(16, "big")
            network = str(ipaddress.ip_network(f"{ip}/{24 if address.version == 4 else 64}", strict=False))
        except ValueError:
            ip_sort = b"\xff"
            network = ""
        search_text = " ".join([
            *(str(host.get(key) or "") for key in (
                "ip", "mac", "hostname", "manual_name", "display_name", "device_type", "device_key"
            )),
            *(str(tag) for tag in host.get("tags", [])),
        ]).lower()
        seen_at = host.get("last_seen_at")
        if seen_at:
            try:
                observed = datetime.fromisoformat(str(seen_at).replace("Z", "+00:00"))
                seen_at = observed.astimezone(timezone.utc).isoformat() if observed.tzinfo else "invalid"
            except ValueError:
                seen_at = "invalid"
        state_rows.append((
            ip, ip_sort, str(host.get("category") or ""), str(host.get("status") or ""),
            network, int(bool(host.get("hostname") or host.get("display_name"))), int(bool(host.get("mac"))),
            seen_at, search_text,
            json.dumps(host, ensure_ascii=False, separators=(",", ":"), allow_nan=False),
        ))
        sources = set(host.get("sources") or [])
        if host.get("last_source"):
            sources.add(str(host["last_source"]))
        source_rows.extend((ip, source) for source in sorted(sources))
    return BuiltHostSnapshot(tuple(state_rows), tuple(source_rows))


def _insert_snapshot_rows(conn, snapshot: BuiltHostSnapshot, snapshot_id: int) -> None:
    conn.executemany(
        """INSERT INTO network_host_current_state
           (snapshot_id, ip, ip_sort, category, status, network, has_hostname, has_mac,
            last_seen_at, search_text, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ((snapshot_id, *row) for row in snapshot.rows),
    )
    conn.executemany(
        "INSERT INTO network_host_current_sources (snapshot_id, ip, source) VALUES (?, ?, ?)",
        ((snapshot_id, *row) for row in snapshot.sources),
    )


def _replace_snapshot_metadata(conn, status: HostSnapshotStatus) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO network_host_snapshot_meta
           (singleton, snapshot_id, generated_at, total_hosts, duration_ms) VALUES (1, ?, ?, ?, ?)""",
        (status.snapshot_id, status.generated_at, status.total_hosts, status.duration_ms),
    )


def refresh_host_snapshot(conn: sqlite3.Connection, *, now: str | datetime) -> HostSnapshotStatus:
    started = time.monotonic()
    snapshot_id = 0
    count = 0
    logger.info("host_snapshot.refresh.start id=%d count=%d duration_ms=0", snapshot_id, count)
    try:
        if conn.in_transaction:
            # Releasing a nested savepoint would not release the caller's WAL read view.
            # Never commit or roll back work owned by a refresh caller.
            raise sqlite3.ProgrammingError("host snapshot refresh requires no active transaction")
        # Build from one consistent source view, then release it before taking a
        # writer lock. An unrelated writer may commit while projection runs.
        conn.execute("BEGIN")
        try:
            snapshot = build_host_snapshot(conn, now=now)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        count = len(snapshot.rows)
        generated_at = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if isinstance(now, datetime) else now
        # Acquire write ownership before reading the latest published id. This
        # transaction never upgrades the potentially stale source-read snapshot.
        conn.execute("BEGIN IMMEDIATE")
        try:
            snapshot_id = snapshot_status(conn).snapshot_id + 1
            conn.execute("DELETE FROM network_host_current_sources")
            conn.execute("DELETE FROM network_host_current_state")
            _insert_snapshot_rows(conn, snapshot, snapshot_id)
            status = HostSnapshotStatus(snapshot_id, generated_at, count, int((time.monotonic() - started) * 1000))
            _replace_snapshot_metadata(conn, status)
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    except Exception:
        logger.error("host_snapshot.refresh.error id=%d count=%d duration_ms=%d", snapshot_id, count, int((time.monotonic() - started) * 1000))
        raise
    logger.info("host_snapshot.refresh.finish id=%d count=%d duration_ms=%d", snapshot_id, count, int((time.monotonic() - started) * 1000))
    return status


def list_host_snapshot(conn: sqlite3.Connection, filters: Mapping[str, Any], page: int, limit: int) -> dict[str, Any]:
    started = time.monotonic()
    if not isinstance(page, int) or not isinstance(limit, int):
        raise ValueError("invalid host pagination")
    page, limit = max(1, page), min(250, max(1, limit))
    # The metadata, count and page must come from one SQLite read snapshot.
    conn.execute("SAVEPOINT read_host_snapshot")
    try:
        metadata = snapshot_status(conn)
        clauses = ["h.snapshot_id = ?"]
        params: list[Any] = [metadata.snapshot_id]
        category = filters.get("category") or "all"
        if category == "all":
            clauses.append("h.category != 'noise'")
        else:
            clauses.append("h.category = ?")
            params.append(category)
        network = filters.get("network") or "all"
        if network != "all":
            subnet = ipaddress.ip_network(network, strict=False)
            clauses.append("h.ip_sort BETWEEN ? AND ?")
            params.extend(bytes([subnet.version]) + int(address).to_bytes(16, "big")
                          for address in (subnet.network_address, subnet.broadcast_address))
        status = filters.get("status") or "current"
        if status == "current":
            clauses.append("h.status IN ('online', 'seen', 'connected')")
        elif status != "all":
            clauses.append("h.status = ?")
            params.append(status)
        query = str(filters.get("q") or "").strip().lower()
        if query:
            clauses.append("instr(h.search_text, ?) > 0")
            params.append(query)
        seen_within = filters.get("seen_within") or "all"
        windows = {"1h": 1 / 24, "24h": 1, "7d": 7, "30d": 30}
        if seen_within != "all":
            if seen_within not in windows:
                raise ValueError("invalid seen_within filter")
            cutoff_reference = datetime.now(timezone.utc).isoformat()
            clauses.append(
                "((julianday(h.last_seen_at) BETWEEN julianday(?) - ? AND julianday(?)) "
                "OR (coalesce(h.last_seen_at, '') = '' AND h.status IN ('online', 'seen', 'connected')))"
            )
            params.extend((cutoff_reference, windows[seen_within], cutoff_reference))
        for key in ("has_hostname", "has_mac"):
            value = filters.get(key)
            if value is not None and value != "":
                if value not in (True, False, "yes", "no", "true", "false", "1", "0"):
                    raise ValueError(f"invalid {key} filter")
                clauses.append(f"h.{key} = ?")
                params.append(int(value in (True, "yes", "true", "1")))
        if filters.get("source") and filters["source"] != "all":
            clauses.append("EXISTS (SELECT 1 FROM network_host_current_sources s WHERE s.snapshot_id = h.snapshot_id AND s.ip = h.ip AND s.source = ?)")
            params.append(filters["source"])
        where = " AND ".join(clauses)
        total = conn.execute(f"SELECT count(*) FROM network_host_current_state h WHERE {where}", params).fetchone()[0] if metadata.snapshot_id else 0
        rows = conn.execute(
            f"SELECT h.payload_json FROM network_host_current_state h WHERE {where} ORDER BY h.ip_sort, h.ip LIMIT ? OFFSET ?",
            (*params, limit, (page - 1) * limit),
        ).fetchall() if metadata.snapshot_id and (page - 1) * limit < total else []
        sources = conn.execute(
            "SELECT DISTINCT source FROM network_host_current_sources WHERE snapshot_id = ? ORDER BY source",
            (metadata.snapshot_id,),
        ).fetchall() if metadata.snapshot_id else []
        result = {"hosts": [json.loads(row[0]) for row in rows], "total": total, "page": page,
                "limit": limit, "pages": (total + limit - 1) // limit, "snapshot": asdict(metadata),
                "sources": [{"name": row[0]} for row in sources]}
    finally:
        conn.execute("RELEASE SAVEPOINT read_host_snapshot")
    logger.info(
        "host_snapshot.list.finish id=%d count=%d total=%d page=%d limit=%d duration_ms=%d",
        metadata.snapshot_id, len(result["hosts"]), total, page, limit,
        int((time.monotonic() - started) * 1000),
    )
    return result
