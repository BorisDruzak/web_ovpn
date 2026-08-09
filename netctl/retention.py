from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Iterable

from .config import normalize_snmp_driver_options


_SWITCH_CURRENT_TABLES = (
    "switch_ports",
    "current_switch_fdb",
    "current_switch_vlan_memberships",
    "current_switch_lldp_neighbors",
    "current_switch_port_telemetry",
)
_PATH_CURRENT_TABLES = (
    "router_filter_rules",
    "router_nat_rules",
    "router_mangle_rules",
    "router_routing_rules",
    "router_address_list_entries",
    "router_ipsec_policies",
)
_EVENT_TABLES = (
    ("switch_fdb_events", "observed_at"),
    ("switch_link_events", "observed_at"),
    ("asset_attachment_events", "observed_at"),
    ("host_observations", "observed_at"),
    ("network_events", "ts"),
    ("availability_result_events", "observed_at"),
)


def _validate_cutoff(cutoff: str) -> str:
    try:
        parsed = datetime.fromisoformat(str(cutoff).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid retention cutoff") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("retention cutoff must be UTC")
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("retention cutoff must be UTC")
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ids(rows: Iterable[sqlite3.Row]) -> set[int]:
    return {int(row[0]) for row in rows if row[0] is not None}


def _latest_run_ids(conn: sqlite3.Connection, table: str, group_column: str, statuses: tuple[str, ...]) -> set[int]:
    placeholders = ", ".join("?" for _ in statuses)
    return _ids(
        conn.execute(
            f"""SELECT runs.id FROM {table} AS runs
                WHERE runs.status IN ({placeholders})
                  AND runs.id = (
                    SELECT latest.id FROM {table} AS latest
                    WHERE latest.{group_column} IS runs.{group_column}
                      AND latest.status IN ({placeholders})
                    ORDER BY COALESCE(latest.finished_at, latest.started_at) DESC, latest.id DESC
                    LIMIT 1
                  )""",
            (*statuses, *statuses),
        )
    )


def _current_run_ids(conn: sqlite3.Connection, tables: tuple[str, ...], column: str) -> set[int]:
    protected: set[int] = set()
    for table in tables:
        protected.update(_ids(conn.execute(f"SELECT DISTINCT {column} FROM {table}")))
    return protected


def protected_switch_run_ids(
    conn: sqlite3.Connection,
    *,
    excluded_counter_sample_ids: set[int] | None = None,
) -> set[int]:
    """Return switch collection runs still needed by current state or recovery."""
    excluded = excluded_counter_sample_ids or set()
    counter_sample_run_ids = {
        int(row[1])
        for row in conn.execute(
            "SELECT id, collector_run_id FROM switch_port_counter_samples"
        )
        if row[1] is not None and int(row[0]) not in excluded
    }
    return (
        _current_run_ids(conn, _SWITCH_CURRENT_TABLES, "collector_run_id")
        | counter_sample_run_ids
        | _latest_run_ids(
            conn, "switch_collection_runs", "source_id", ("success", "partial")
        )
    )


def protected_correlation_run_ids(conn: sqlite3.Connection) -> set[int]:
    """Return correlation runs still referenced by current topology/attachments."""
    return _current_run_ids(
        conn,
        ("current_switch_links", "asset_attachment_candidates", "asset_attachment_resolutions"),
        "correlation_run_id",
    ) | _latest_run_ids(conn, "network_correlation_runs", "run_type", ("success", "partial"))


def protected_path_fact_run_ids(conn: sqlite3.Connection) -> set[int]:
    """Return router fact runs used by current router state or source recovery."""
    return _current_run_ids(conn, _PATH_CURRENT_TABLES, "collector_run_id") | _latest_run_ids(
        conn, "router_path_fact_runs", "source_id", ("success",))


def protected_availability_run_ids(conn: sqlite3.Connection) -> set[int]:
    """Return CIDR runs still needed by current availability state or recovery."""
    return _current_run_ids(conn, ("availability_results",), "run_id") | _latest_run_ids(
        conn, "availability_runs", "cidr", ("success",)
    )


def _latest_current_nmap_run_ids(
    conn: sqlite3.Connection, *, status: str | None = None
) -> set[int]:
    status_clause = " AND runs.status = ?" if status is not None else ""
    latest_status_clause = " AND latest.status = ?" if status is not None else ""
    order = (
        "COALESCE(latest.finished_at, latest.started_at)"
        if status == "success"
        else "latest.started_at"
    )
    params: tuple[object, ...] = (status, status) if status is not None else ()
    return _ids(
        conn.execute(
            f"""SELECT runs.id FROM nmap_fingerprint_runs AS runs
                WHERE EXISTS (
                    SELECT 1 FROM ip_observations AS ips
                    WHERE ips.asset_id = runs.asset_id AND ips.is_current = 1
                      AND ips.ip = runs.target_ip
                )
                {status_clause}
                  AND runs.id = (
                    SELECT latest.id FROM nmap_fingerprint_runs AS latest
                    WHERE latest.asset_id = runs.asset_id
                      AND latest.target_ip = runs.target_ip
                      AND latest.profile = runs.profile
                      {latest_status_clause}
                    ORDER BY {order} DESC, latest.id DESC
                    LIMIT 1
                  )""",
            params,
        )
    )


def protected_nmap_run_ids(conn: sqlite3.Connection) -> set[int]:
    """Keep current-target status/recovery rows and every active single flight."""
    running = _ids(
        conn.execute(
            "SELECT id FROM nmap_fingerprint_runs WHERE status = 'running'"
        )
    )
    return (
        running
        | _latest_current_nmap_run_ids(conn)
        | _latest_current_nmap_run_ids(conn, status="success")
    )


def _old_ids(conn: sqlite3.Connection, table: str, timestamp_column: str, cutoff: str, protected: set[int] | None = None) -> list[int]:
    query = f"SELECT id FROM {table} WHERE {timestamp_column} < ?"
    params: list[object] = [cutoff]
    if protected:
        placeholders = ", ".join("?" for _ in protected)
        query += f" AND id NOT IN ({placeholders})"
        params.extend(sorted(protected))
    return [int(row[0]) for row in conn.execute(query, params)]


def _child_ids_for_runs(
    conn: sqlite3.Connection, table: str, run_ids: list[int]
) -> list[int]:
    if not run_ids:
        return []
    placeholders = ", ".join("?" for _ in run_ids)
    return [
        int(row[0])
        for row in conn.execute(
            f"SELECT id FROM {table} WHERE run_id IN ({placeholders}) ORDER BY id",
            run_ids,
        )
    ]


def _count_current_references(conn: sqlite3.Connection, tables: tuple[str, ...], column: str) -> int:
    return len(_current_run_ids(conn, tables, column))


def _counter_sample_ids(
    conn: sqlite3.Connection, reference_time: str
) -> list[int]:
    reference = datetime.fromisoformat(reference_time.replace("Z", "+00:00"))
    expired: list[int] = []
    for row in conn.execute(
        """SELECT id, driver_options_json FROM network_sources
           WHERE driver = 'snmp_switch' ORDER BY id"""
    ):
        try:
            raw_options = json.loads(str(row["driver_options_json"] or "{}"))
            if not isinstance(raw_options, dict):
                raise ValueError("stored SNMP options are not a mapping")
            options = normalize_snmp_driver_options(raw_options)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("invalid stored SNMP retention settings") from None
        source_cutoff = (
            reference - timedelta(days=int(options["counter_retention_days"]))
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expired.extend(
            int(item[0])
            for item in conn.execute(
                """SELECT id FROM switch_port_counter_samples
                   WHERE source_id = ? AND observed_at < ?""",
                (int(row["id"]), source_cutoff),
            )
        )
    return sorted(expired)


def _retention_reference(value: str | None) -> str:
    if value is None:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
    return _validate_cutoff(value)


def retention_report(
    conn: sqlite3.Connection,
    cutoff: str,
    reference_time: str | None = None,
) -> dict[str, dict[str, int]]:
    """Return deterministic candidate and protection counts without changing the database."""
    cutoff = _validate_cutoff(cutoff)
    reference_time = _retention_reference(reference_time)
    counter_sample_ids = _counter_sample_ids(conn, reference_time)
    switch_protected = protected_switch_run_ids(
        conn, excluded_counter_sample_ids=set(counter_sample_ids)
    )
    correlation_protected = protected_correlation_run_ids(conn)
    path_protected = protected_path_fact_run_ids(conn)
    availability_protected = protected_availability_run_ids(conn)
    nmap_protected = protected_nmap_run_ids(conn)
    nmap_run_ids = _old_ids(
        conn,
        "nmap_fingerprint_runs",
        "COALESCE(finished_at, started_at)",
        cutoff,
        nmap_protected,
    )
    delete = {table: len(_old_ids(conn, table, column, cutoff)) for table, column in _EVENT_TABLES}
    delete["switch_port_counter_samples"] = len(counter_sample_ids)
    delete["nmap_fingerprint_ports"] = len(
        _child_ids_for_runs(conn, "nmap_fingerprint_ports", nmap_run_ids)
    )
    delete["nmap_fingerprint_os_matches"] = len(
        _child_ids_for_runs(conn, "nmap_fingerprint_os_matches", nmap_run_ids)
    )
    delete["nmap_fingerprint_runs"] = len(nmap_run_ids)
    delete.update(
        {
            "ip_observations": int(conn.execute(
                "SELECT COUNT(*) FROM ip_observations WHERE is_current = 0 AND last_seen_at < ?", (cutoff,)
            ).fetchone()[0]),
            "hostname_observations": int(conn.execute(
                "SELECT COUNT(*) FROM hostname_observations WHERE is_current = 0 AND last_seen_at < ?", (cutoff,)
            ).fetchone()[0]),
            "collection_runs": len(_old_ids(conn, "collection_runs", "COALESCE(finished_at, started_at)", cutoff,
                                               _latest_run_ids(conn, "collection_runs", "source_id", ("ok",)))),
            "switch_collection_runs": len(_old_ids(conn, "switch_collection_runs", "COALESCE(finished_at, started_at)", cutoff, switch_protected)),
            "network_correlation_runs": len(_old_ids(conn, "network_correlation_runs", "COALESCE(finished_at, started_at)", cutoff, correlation_protected)),
            "router_path_fact_runs": len(_old_ids(conn, "router_path_fact_runs", "COALESCE(finished_at, started_at)", cutoff, path_protected)),
            "availability_runs": len(_old_ids(conn, "availability_runs", "COALESCE(finished_at, started_at)", cutoff, availability_protected)),
        }
    )
    return {
        "delete": {key: delete[key] for key in sorted(delete)},
        "keep": {
            "switch_collection_runs_current_reference": _count_current_references(conn, _SWITCH_CURRENT_TABLES, "collector_run_id"),
            "switch_collection_runs_last_success": len(_latest_run_ids(conn, "switch_collection_runs", "source_id", ("success", "partial"))),
            "network_correlation_runs_current_reference": _count_current_references(conn, ("current_switch_links", "asset_attachment_candidates", "asset_attachment_resolutions"), "correlation_run_id"),
            "network_correlation_runs_last_success": len(_latest_run_ids(conn, "network_correlation_runs", "run_type", ("success", "partial"))),
            "router_path_fact_runs_current_reference": _count_current_references(conn, _PATH_CURRENT_TABLES, "collector_run_id"),
            "router_path_fact_runs_last_success": len(_latest_run_ids(conn, "router_path_fact_runs", "source_id", ("success",))),
            "availability_runs_current_reference": _count_current_references(conn, ("availability_results",), "run_id"),
            "availability_runs_last_success": len(_latest_run_ids(conn, "availability_runs", "cidr", ("success",))),
            "nmap_fingerprint_runs_current": len(_latest_current_nmap_run_ids(conn)),
            "nmap_fingerprint_runs_last_success": len(_latest_current_nmap_run_ids(conn, status="success")),
            "nmap_fingerprint_runs_running": len(_ids(conn.execute("SELECT id FROM nmap_fingerprint_runs WHERE status = 'running'"))),
        },
    }


def _delete_ids(conn: sqlite3.Connection, table: str, ids: list[int]) -> int:
    if not ids:
        return 0
    placeholders = ", ".join("?" for _ in ids)
    return int(conn.execute(f"DELETE FROM {table} WHERE id IN ({placeholders})", ids).rowcount)


def _verify_database(conn: sqlite3.Connection) -> None:
    if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise RuntimeError("retention_failed")
    integrity = conn.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or str(integrity[0]).lower() != "ok":
        raise RuntimeError("retention_failed")


def apply_retention(
    conn: sqlite3.Connection,
    cutoff: str,
    reference_time: str | None = None,
) -> dict[str, object]:
    """Prune expired history atomically, preserving state and last successful recovery runs."""
    cutoff = _validate_cutoff(cutoff)
    reference_time = _retention_reference(reference_time)
    conn.execute("BEGIN IMMEDIATE")
    try:
        report = retention_report(
            conn, cutoff, reference_time=reference_time
        )
        deleted: dict[str, int] = {}
        deleted["switch_port_counter_samples"] = _delete_ids(
            conn,
            "switch_port_counter_samples",
            _counter_sample_ids(conn, reference_time),
        )
        nmap_run_ids = _old_ids(
            conn,
            "nmap_fingerprint_runs",
            "COALESCE(finished_at, started_at)",
            cutoff,
            protected_nmap_run_ids(conn),
        )
        deleted["nmap_fingerprint_ports"] = _delete_ids(
            conn,
            "nmap_fingerprint_ports",
            _child_ids_for_runs(conn, "nmap_fingerprint_ports", nmap_run_ids),
        )
        deleted["nmap_fingerprint_os_matches"] = _delete_ids(
            conn,
            "nmap_fingerprint_os_matches",
            _child_ids_for_runs(conn, "nmap_fingerprint_os_matches", nmap_run_ids),
        )
        deleted["nmap_fingerprint_runs"] = _delete_ids(
            conn, "nmap_fingerprint_runs", nmap_run_ids
        )
        for table, timestamp_column in _EVENT_TABLES:
            deleted[table] = _delete_ids(conn, table, _old_ids(conn, table, timestamp_column, cutoff))
        deleted["ip_observations"] = int(conn.execute(
            "DELETE FROM ip_observations WHERE is_current = 0 AND last_seen_at < ?", (cutoff,)
        ).rowcount)
        deleted["hostname_observations"] = int(conn.execute(
            "DELETE FROM hostname_observations WHERE is_current = 0 AND last_seen_at < ?", (cutoff,)
        ).rowcount)
        deleted["collection_runs"] = _delete_ids(conn, "collection_runs", _old_ids(
            conn, "collection_runs", "COALESCE(finished_at, started_at)", cutoff,
            _latest_run_ids(conn, "collection_runs", "source_id", ("ok",)),
        ))
        deleted["switch_collection_runs"] = _delete_ids(conn, "switch_collection_runs", _old_ids(
            conn, "switch_collection_runs", "COALESCE(finished_at, started_at)", cutoff, protected_switch_run_ids(conn)
        ))
        deleted["network_correlation_runs"] = _delete_ids(conn, "network_correlation_runs", _old_ids(
            conn, "network_correlation_runs", "COALESCE(finished_at, started_at)", cutoff, protected_correlation_run_ids(conn)
        ))
        deleted["router_path_fact_runs"] = _delete_ids(conn, "router_path_fact_runs", _old_ids(
            conn, "router_path_fact_runs", "COALESCE(finished_at, started_at)", cutoff, protected_path_fact_run_ids(conn)
        ))
        deleted["availability_runs"] = _delete_ids(conn, "availability_runs", _old_ids(
            conn, "availability_runs", "COALESCE(finished_at, started_at)", cutoff, protected_availability_run_ids(conn)
        ))
        _verify_database(conn)
        metrics = {
            "page_count": int(conn.execute("PRAGMA page_count").fetchone()[0]),
            "freelist_count": int(conn.execute("PRAGMA freelist_count").fetchone()[0]),
        }
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"deleted": {key: deleted[key] for key in sorted(deleted)}, "kept": report["keep"], "total_deleted": sum(deleted.values()), "page_metrics": metrics}
