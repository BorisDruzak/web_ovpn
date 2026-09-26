"""Build and publish the unprivileged collector's persistent public host view."""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .availability import bulk_project_host_availability
from .store import decode_host


logger = logging.getLogger(__name__)
# Two expected ten-minute collection cycles. Freshness is derived on reads so
# a stopped collector can become stale without a write or a network operation.
HOST_SNAPSHOT_MAX_AGE = timedelta(minutes=20)


@dataclass(frozen=True)
class HostSnapshotStatus:
    snapshot_id: int = 0
    generated_at: str | None = None
    total_hosts: int = 0
    duration_ms: int = 0
    stale: bool = False


@dataclass(frozen=True)
class BuiltHostSnapshot:
    rows: tuple[tuple[Any, ...], ...]
    sources: tuple[tuple[str, str], ...]


def _reference_time(now: str | datetime | None) -> datetime:
    value = datetime.fromisoformat(now.replace("Z", "+00:00")) if isinstance(now, str) else now
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)


def snapshot_status(conn: sqlite3.Connection, *, now: str | datetime | None = None) -> HostSnapshotStatus:
    # Older read-only databases are valid but have no published snapshot yet.
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'network_host_snapshot_meta'").fetchone() is None:
        return HostSnapshotStatus()
    row = conn.execute(
        "SELECT snapshot_id, generated_at, total_hosts, duration_ms FROM network_host_snapshot_meta WHERE singleton = 1"
    ).fetchone()
    if row is None:
        return HostSnapshotStatus()
    try:
        generated = datetime.fromisoformat(row[1].replace("Z", "+00:00"))
        stale = generated.tzinfo is None or not timedelta(0) <= _reference_time(now) - generated <= HOST_SNAPSHOT_MAX_AGE
    except (TypeError, ValueError):
        stale = True
    return HostSnapshotStatus(*row, stale=stale)


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


def _snapshot_query(metadata, filters, reference_time, states):
    inventory_link = filters.get("inventory_link") or "all"
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
        cutoff_reference = reference_time.isoformat()
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
    prefix, source = '', 'network_host_current_state h'
    if states is not None:
        # Materialize once and let SQLite index the join; never filter a page
        # of decoded hosts or pass thousands of keys as SQL placeholders.
        prefix = 'WITH inventory_projection AS MATERIALIZED (SELECT key,value FROM json_each(?)) '
        source += " LEFT JOIN inventory_projection p ON p.key=json_extract(h.payload_json,'$.device_key')"
        params.insert(0,json.dumps(states,separators=(',',':')))
        selected = {'linked':'linked','unlinked':'unlinked','candidates':'candidate','conflicts':'ambiguous'}[inventory_link]
        clauses.append("coalesce(p.value,'unlinked') = ?")
        params.append(selected)
    where = " AND ".join(clauses)
    return prefix, source, where, params


def list_host_snapshot(conn: sqlite3.Connection, filters: Mapping[str, Any], page: int, limit: int, *, now: str | datetime | None = None) -> dict[str, Any]:
    started = time.monotonic()
    reference_time = _reference_time(now)
    if not isinstance(page, int) or not isinstance(limit, int):
        raise ValueError("invalid host pagination")
    page, limit = max(1, page), min(250, max(1, limit))
    from .inventory_projection import FILTERS, validate_projection
    inventory_link = filters.get('inventory_link') or 'all'
    if inventory_link not in FILTERS:
        raise ValueError('invalid inventory relation filter')
    projection = filters.get('inventory_projection')
    states = validate_projection(projection) if inventory_link != 'all' else None
    # The metadata, count and page must come from one SQLite read snapshot.
    conn.execute("SAVEPOINT read_host_snapshot")
    try:
        metadata = snapshot_status(conn, now=reference_time)
        prefix, source, where, params = _snapshot_query(metadata, filters, reference_time, states)
        total = conn.execute(f"{prefix}SELECT count(*) FROM {source} WHERE {where}", params).fetchone()[0] if metadata.snapshot_id else 0
        pages = (total + limit - 1) // limit
        if metadata.snapshot_id:
            page = min(page, max(1, pages))
        rows = conn.execute(
            f"{prefix}SELECT h.payload_json FROM {source} WHERE {where} ORDER BY h.ip_sort, h.ip LIMIT ? OFFSET ?",
            (*params, limit, (page - 1) * limit),
        ).fetchall() if metadata.snapshot_id and (page - 1) * limit < total else []
        sources = conn.execute(
            "SELECT DISTINCT source FROM network_host_current_sources WHERE snapshot_id = ? ORDER BY source",
            (metadata.snapshot_id,),
        ).fetchall() if metadata.snapshot_id else []
        result = {"hosts": [json.loads(row[0]) for row in rows], "total": total, "page": page,
                "limit": limit, "pages": pages, "snapshot": asdict(metadata),
                "sources": [{"name": row[0]} for row in sources]}
    finally:
        conn.execute("RELEASE SAVEPOINT read_host_snapshot")
    logger.info(
        "host_snapshot.list.finish id=%d count=%d total=%d page=%d limit=%d duration_ms=%d",
        metadata.snapshot_id, len(result["hosts"]), total, page, limit,
        int((time.monotonic() - started) * 1000),
    )
    return result


HOST_EXPORT_MAX_ROWS = 10_000
HOST_EXPORT_MAX_BYTES = 16 * 1024 * 1024


def export_host_snapshot(conn: sqlite3.Connection, filters: Mapping[str, Any], *, now=None) -> dict[str, Any]:
    """Read a full bounded selection from one published snapshot, never a page loop."""
    from .inventory_projection import FILTERS, validate_projection
    inventory_link = filters.get('inventory_link') or 'all'
    if inventory_link not in FILTERS:
        raise ValueError('invalid inventory relation filter')
    projection = filters.get('inventory_projection')
    states = validate_projection(projection) if projection is not None else None
    if inventory_link != 'all' and states is None:
        raise ValueError('inventory relation filter requires projection')
    if inventory_link == 'all':
        states = None
    reference_time = _reference_time(now)
    conn.execute('SAVEPOINT export_host_snapshot')
    try:
        metadata = snapshot_status(conn, now=reference_time)
        if not metadata.snapshot_id:
            raise ValueError('host_snapshot_absent')
        prefix, source, where, params = _snapshot_query(metadata, filters, reference_time, states)
        total = conn.execute(f'{prefix}SELECT count(*) FROM {source} WHERE {where}',params).fetchone()[0]
        if total > HOST_EXPORT_MAX_ROWS:
            raise ValueError('host_export_row_budget')
        # Check aggregate UTF-8 bytes inside SQLite before loading/decoding rows.
        payload_bytes = conn.execute(f'{prefix}SELECT coalesce(sum(length(cast(h.payload_json AS BLOB))),0) FROM {source} WHERE {where}',params).fetchone()[0]
        if payload_bytes > HOST_EXPORT_MAX_BYTES:
            raise ValueError('host_export_byte_budget')
        rows = conn.execute(f'{prefix}SELECT h.payload_json FROM {source} WHERE {where} ORDER BY h.ip_sort,h.ip',params)
        result = {'hosts':[json.loads(row[0]) for row in rows], 'total':total,
                  'snapshot':asdict(metadata),
                  'inventory_projection_revision':projection['revision'] if projection is not None else None}
        # This is the exact CLI envelope/encoding, including status and worst-case CRLF newline.
        if len(json.dumps({'status':'ok',**result},ensure_ascii=True,default=str).encode('ascii'))+2 > HOST_EXPORT_MAX_BYTES:
            raise ValueError('host_export_byte_budget')
        return result
    finally:
        conn.execute('RELEASE SAVEPOINT export_host_snapshot')
