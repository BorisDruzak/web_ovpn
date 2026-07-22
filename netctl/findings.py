from __future__ import annotations

import json
import sqlite3
from typing import Any


def _finding_rows(
    conn: sqlite3.Connection,
    where: str,
    params: tuple[object, ...],
    limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for table, source in (("runtime_identity_findings", "runtime_identity"), ("topology_findings", "topology")):
        for row in conn.execute(
            f"SELECT finding_key, finding_type, severity, status, first_seen_at, last_seen_at, details_json FROM {table}{where} ORDER BY last_seen_at DESC, finding_key LIMIT ?",
            (*params, limit),
        ):
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json"))
            except (TypeError, ValueError, json.JSONDecodeError):
                item["details"] = {}
            item["source"] = source
            rows.append(item)
    return sorted(rows, key=lambda item: (str(item["last_seen_at"]), str(item["finding_key"])), reverse=True)[:limit]


def findings_for_asset(conn: sqlite3.Connection, asset_id: int, limit: int = 100) -> list[dict[str, Any]]:
    rows = _finding_rows(conn, " WHERE asset_id = ?", (asset_id,), limit)
    source_rows = conn.execute(
        """SELECT DISTINCT selected_source_id
           FROM asset_attachment_resolutions
           WHERE asset_id = ? AND selected_source_id IS NOT NULL""",
        (asset_id,),
    ).fetchall()
    source_ids = [int(row["selected_source_id"]) for row in source_rows]
    rows.extend(_switch_collection_failures(conn, source_ids, limit))
    return _sort_and_limit(rows, limit)


def list_context_findings(
    conn: sqlite3.Connection,
    status: str = "open",
    limit: int = 100,
) -> list[dict[str, Any]]:
    if status not in {"open", "acknowledged", "resolved"}:
        raise ValueError("invalid finding status")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    rows = _finding_rows(conn, " WHERE status = ?", (status,), limit)
    if status == "open":
        rows.extend(_switch_collection_failures(conn, None, limit))
    return _sort_and_limit(rows, limit)


def _switch_collection_failures(
    conn: sqlite3.Connection,
    source_ids: list[int] | None,
    limit: int,
) -> list[dict[str, Any]]:
    conditions = ["runs.status IN ('failed', 'partial')"]
    params: list[object] = []
    if source_ids is not None:
        if not source_ids:
            return []
        conditions.append(f"runs.source_id IN ({','.join('?' for _ in source_ids)})")
        params.extend(source_ids)
    rows = conn.execute(
        f"""
        SELECT runs.id, runs.status AS run_status, runs.started_at, runs.finished_at,
               runs.error_class, sources.name AS source_name
        FROM switch_collection_runs AS runs
        JOIN network_sources AS sources ON sources.id = runs.source_id
        WHERE {' AND '.join(conditions)}
        ORDER BY runs.finished_at DESC, runs.id DESC
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()
    return [
        {
            "finding_key": f"switch_collection_run:{row['id']}",
            "finding_type": "switch_collection_failed" if row["run_status"] == "failed" else "switch_collection_partial",
            "severity": "error" if row["run_status"] == "failed" else "warning",
            "status": "open",
            "first_seen_at": row["started_at"],
            "last_seen_at": row["finished_at"] or row["started_at"],
            "details": {"source": row["source_name"], "error_class": row["error_class"]},
            "source": "switch_collection",
        }
        for row in rows
    ]


def _sort_and_limit(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda item: (str(item["last_seen_at"]), str(item["finding_key"])), reverse=True)[:limit]
