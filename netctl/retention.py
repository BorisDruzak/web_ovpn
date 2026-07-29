from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Iterable


_SWITCH_CURRENT_TABLES = (
    "switch_ports",
    "current_switch_fdb",
    "current_switch_vlan_memberships",
    "current_switch_lldp_neighbors",
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


def protected_switch_run_ids(conn: sqlite3.Connection) -> set[int]:
    """Return switch collection runs still needed by current state or recovery."""
    return _current_run_ids(conn, _SWITCH_CURRENT_TABLES, "collector_run_id") | _latest_run_ids(
        conn, "switch_collection_runs", "source_id", ("success", "partial")
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


def _old_ids(conn: sqlite3.Connection, table: str, timestamp_column: str, cutoff: str, protected: set[int] | None = None) -> list[int]:
    query = f"SELECT id FROM {table} WHERE {timestamp_column} < ?"
    params: list[object] = [cutoff]
    if protected:
        placeholders = ", ".join("?" for _ in protected)
        query += f" AND id NOT IN ({placeholders})"
        params.extend(sorted(protected))
    return [int(row[0]) for row in conn.execute(query, params)]


def _count_current_references(conn: sqlite3.Connection, tables: tuple[str, ...], column: str) -> int:
    return len(_current_run_ids(conn, tables, column))


def retention_report(conn: sqlite3.Connection, cutoff: str) -> dict[str, dict[str, int]]:
    """Return deterministic candidate and protection counts without changing the database."""
    cutoff = _validate_cutoff(cutoff)
    switch_protected = protected_switch_run_ids(conn)
    correlation_protected = protected_correlation_run_ids(conn)
    path_protected = protected_path_fact_run_ids(conn)
    availability_protected = protected_availability_run_ids(conn)
    delete = {table: len(_old_ids(conn, table, column, cutoff)) for table, column in _EVENT_TABLES}
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


def apply_retention(conn: sqlite3.Connection, cutoff: str) -> dict[str, object]:
    """Prune expired history atomically, preserving state and last successful recovery runs."""
    cutoff = _validate_cutoff(cutoff)
    conn.execute("BEGIN IMMEDIATE")
    try:
        report = retention_report(conn, cutoff)
        deleted: dict[str, int] = {}
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
