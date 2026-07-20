from __future__ import annotations

import json
import sqlite3
from typing import Any


def get_runtime_asset_by_key(
    conn: sqlite3.Connection, asset_key: str
) -> dict[str, Any] | None:
    """Return the runtime asset identified by its stable runtime key."""
    row = conn.execute(
        "SELECT * FROM assets WHERE asset_key = ?",
        (asset_key,),
    ).fetchone()
    return dict(row) if row is not None else None


def list_asset_interfaces(
    conn: sqlite3.Connection, asset_id: int
) -> list[dict[str, Any]]:
    """Return an asset's interfaces in stable key order."""
    rows = conn.execute(
        """
        SELECT * FROM asset_interfaces
        WHERE asset_id = ?
        ORDER BY interface_key, mac, interface_type, interface_name, id
        """,
        (asset_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_current_ip_observations(
    conn: sqlite3.Connection, asset_id: int
) -> list[dict[str, Any]]:
    """Return current IP observations, newest evidence first."""
    rows = conn.execute(
        """
        SELECT * FROM ip_observations
        WHERE asset_id = ? AND is_current = 1
        ORDER BY last_seen_at DESC, first_seen_at DESC, ip, source_key,
                 observation_source, id
        """,
        (asset_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_current_hostname_observations(
    conn: sqlite3.Connection, asset_id: int
) -> list[dict[str, Any]]:
    """Return current hostname observations, newest evidence first."""
    rows = conn.execute(
        """
        SELECT * FROM hostname_observations
        WHERE asset_id = ? AND is_current = 1
        ORDER BY last_seen_at DESC, first_seen_at DESC, hostname, source_key,
                 source_type, id
        """,
        (asset_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def runtime_identity_report(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Return the runtime-identity migration report with JSON arrays decoded."""
    row = conn.execute(
        "SELECT * FROM runtime_asset_migration_reports WHERE migration_version = ?",
        (2,),
    ).fetchone()
    if row is None:
        return None

    report = dict(row)
    for field in (
        "unresolved_legacy_host_ids",
        "unresolved_observation_ids",
        "unresolved_tag_records",
        "aggregation_conflicts",
    ):
        json_field = f"{field}_json"
        report[field] = _decode_json_array(report.pop(json_field), json_field)
    return report


def runtime_identity_status(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return a compact, read-only runtime-identity operational summary."""
    counts = {
        "assets": _count_rows(conn, "assets"),
        "interfaces": _count_rows(conn, "asset_interfaces"),
        "current_ip_observations": _count_where(
            conn, "ip_observations", "is_current = ?", (1,)
        ),
        "current_hostname_observations": _count_where(
            conn, "hostname_observations", "is_current = ?", (1,)
        ),
    }
    migration_only_ips = _count_where(
        conn,
        "ip_observations",
        "observation_source = ? AND is_current = ?",
        ("legacy_network_host", 1),
    )
    migration_only_hostnames = _count_where(
        conn,
        "hostname_observations",
        "source_type = ? AND is_current = ?",
        ("legacy_network_host", 1),
    )
    return {
        "schema_migration_versions": [
            int(row[0])
            for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ],
        "counts": counts,
        "last_successful_collections": _last_successful_collections(conn),
        "open_findings": _open_finding_aggregates(conn),
        "migration_2_report_summary": _migration_2_report_summary(conn),
        "migration_only_current": {
            "ip_observations": migration_only_ips,
            "hostname_observations": migration_only_hostnames,
            "total": migration_only_ips + migration_only_hostnames,
        },
    }


def inspect_runtime_asset(
    conn: sqlite3.Connection, asset_key: str
) -> dict[str, Any] | None:
    """Return a runtime asset with its current evidence and related findings."""
    asset = get_runtime_asset_by_key(conn, asset_key)
    if asset is None:
        return None

    asset_id = int(asset["id"])
    findings = _findings_for_asset(conn, asset_id)
    return {
        "asset": asset,
        "interfaces": list_asset_interfaces(conn, asset_id),
        "current_ip_observations": list_current_ip_observations(conn, asset_id),
        "current_hostname_observations": list_current_hostname_observations(
            conn, asset_id
        ),
        "findings": findings,
    }


def list_runtime_identity_findings(
    conn: sqlite3.Connection, status: str = "open"
) -> list[dict[str, Any]]:
    """Return runtime identity findings for one allowed lifecycle status."""
    if status not in {"open", "acknowledged", "resolved"}:
        raise ValueError("invalid finding status")
    rows = conn.execute(
        """
        SELECT findings.*, assets.asset_key, sources.name AS source
        FROM runtime_identity_findings AS findings
        LEFT JOIN assets ON assets.id = findings.asset_id
        LEFT JOIN network_sources AS sources ON sources.id = findings.source_id
        WHERE findings.status = ?
        ORDER BY
            CASE findings.severity
                WHEN 'critical' THEN 1
                WHEN 'error' THEN 2
                WHEN 'warning' THEN 3
                ELSE 4
            END,
            findings.finding_type,
            findings.finding_key
        """,
        (status,),
    ).fetchall()
    return [_finding_public(row) for row in rows]


def _count_rows(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _count_where(
    conn: sqlite3.Connection,
    table: str,
    predicate: str,
    params: tuple[Any, ...],
) -> int:
    return int(
        conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {predicate}", params).fetchone()[0]
    )


def _last_successful_collections(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT sources.id AS source_id, sources.name AS source,
               runs.started_at, runs.finished_at
        FROM network_sources AS sources
        JOIN collection_runs AS runs ON runs.id = (
            SELECT candidate.id
            FROM collection_runs AS candidate
            WHERE candidate.source_id = sources.id AND candidate.status = ?
            ORDER BY candidate.finished_at DESC, candidate.id DESC
            LIMIT 1
        )
        ORDER BY sources.name, sources.id
        """,
        ("ok",),
    ).fetchall()
    return [dict(row) for row in rows]


def _open_finding_aggregates(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    by_type = conn.execute(
        """
        SELECT finding_type, COUNT(*) AS count
        FROM runtime_identity_findings
        WHERE status = ?
        GROUP BY finding_type
        ORDER BY finding_type
        """,
        ("open",),
    ).fetchall()
    by_severity = conn.execute(
        """
        SELECT severity, COUNT(*) AS count
        FROM runtime_identity_findings
        WHERE status = ?
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'critical' THEN 1
            WHEN 'error' THEN 2
            WHEN 'warning' THEN 3
            ELSE 4
        END
        """,
        ("open",),
    ).fetchall()
    return {
        "by_type": [dict(row) for row in by_type],
        "by_severity": [dict(row) for row in by_severity],
    }


def _migration_2_report_summary(conn: sqlite3.Connection) -> dict[str, Any] | None:
    report = runtime_identity_report(conn)
    if report is None:
        return None
    summary = {
        field: report[field]
        for field in (
            "migration_version",
            "completed_at",
            "legacy_host_count",
            "mapped_legacy_host_count",
            "mac_asset_count",
            "provisional_asset_count",
            "interface_count",
            "ip_observation_count",
            "hostname_observation_count",
            "tag_binding_count",
        )
    }
    for field in (
        "unresolved_legacy_host_ids",
        "unresolved_observation_ids",
        "unresolved_tag_records",
        "aggregation_conflicts",
    ):
        summary[f"{field}_count"] = len(report[field])
    return summary


def _findings_for_asset(
    conn: sqlite3.Connection, asset_id: int
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT findings.*, assets.asset_key, sources.name AS source
        FROM runtime_identity_findings AS findings
        JOIN assets ON assets.id = findings.asset_id
        LEFT JOIN network_sources AS sources ON sources.id = findings.source_id
        WHERE findings.asset_id = ?
        ORDER BY findings.last_seen_at DESC, findings.finding_key
        """,
        (asset_id,),
    ).fetchall()
    return [_finding_public(row) for row in rows]


def _finding_public(row: sqlite3.Row) -> dict[str, Any]:
    finding = dict(row)
    raw_details = finding.pop("details_json")
    try:
        details = json.loads(raw_details)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime identity finding contains invalid details JSON") from exc
    if not isinstance(details, dict):
        raise ValueError("runtime identity finding details must be a JSON object")
    finding["details"] = details
    return finding


def _decode_json_array(value: Any, field: str) -> list[Any]:
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{field} contains invalid JSON") from exc
    if not isinstance(decoded, list):
        raise ValueError(f"{field} must contain a JSON array")
    return decoded
