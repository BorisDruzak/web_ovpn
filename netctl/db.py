from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .config import load_config_sources
from .util import utc_now


def db_path_from_url(db_url: str) -> Path:
    if not db_url.startswith("sqlite:///"):
        raise ValueError("only sqlite:/// DB URLs are supported")
    return Path(db_url.removeprefix("sqlite:///")).expanduser()


def connect(db_url: str) -> sqlite3.Connection:
    path = db_path_from_url(db_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS network_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            driver TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT NOT NULL,
            secret_ref TEXT NOT NULL,
            tls INTEGER NOT NULL DEFAULT 1,
            verify_tls INTEGER NOT NULL DEFAULT 0,
            site TEXT,
            role TEXT,
            ssh_identity_file TEXT,
            ssh_proxy_jump TEXT,
            ssh_connect_timeout INTEGER NOT NULL DEFAULT 8,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_collect_at TEXT,
            last_status TEXT,
            last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS collection_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            message TEXT,
            counts_json TEXT
        );
        CREATE TABLE IF NOT EXISTS network_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            hostname TEXT,
            display_name TEXT,
            category TEXT,
            device_key TEXT,
            device_type TEXT,
            device_confidence INTEGER,
            device_evidence_json TEXT,
            status TEXT,
            site TEXT,
            first_seen_at TEXT,
            last_seen_at TEXT,
            last_source TEXT,
            tags_json TEXT,
            comment TEXT
        );
        CREATE TABLE IF NOT EXISTS network_device_tags (
            device_key TEXT PRIMARY KEY,
            match_type TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS host_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            source_id INTEGER,
            observed_at TEXT NOT NULL,
            observation_type TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            hostname TEXT,
            interface TEXT,
            data_json TEXT
        );
        CREATE TABLE IF NOT EXISTS network_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            name TEXT,
            type TEXT,
            running INTEGER,
            disabled INTEGER,
            mac TEXT,
            comment TEXT,
            rx_bytes INTEGER,
            tx_bytes INTEGER,
            rx_packets INTEGER,
            tx_packets INTEGER,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS network_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            dst_address TEXT,
            gateway TEXT,
            distance TEXT,
            active INTEGER,
            disabled INTEGER,
            dynamic INTEGER,
            comment TEXT,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS dhcp_leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            ip TEXT,
            mac TEXT,
            hostname TEXT,
            status TEXT,
            server TEXT,
            last_seen TEXT,
            expires_after TEXT,
            comment TEXT,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS arp_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            ip TEXT,
            mac TEXT,
            interface TEXT,
            complete INTEGER,
            dynamic INTEGER,
            comment TEXT,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS bridge_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            mac TEXT,
            bridge TEXT,
            interface TEXT,
            dynamic INTEGER,
            local INTEGER,
            age TEXT,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS network_neighbors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER,
            address TEXT,
            mac TEXT,
            identity TEXT,
            interface TEXT,
            platform TEXT,
            version TEXT,
            uptime TEXT,
            last_seen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            source_id INTEGER,
            host_id INTEGER,
            severity TEXT NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            data_json TEXT
        );
        CREATE TABLE IF NOT EXISTS context_revisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            source_path TEXT NOT NULL,
            validated_at TEXT NOT NULL,
            git_sha TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            error_json TEXT NOT NULL DEFAULT '[]',
            counts_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(context_id, sha256)
        );
        """
    )
    _ensure_column(conn, "network_hosts", "device_key", "TEXT")
    _ensure_column(conn, "network_hosts", "device_type", "TEXT")
    _ensure_column(conn, "network_hosts", "device_confidence", "INTEGER")
    _ensure_column(conn, "network_hosts", "device_evidence_json", "TEXT")
    _ensure_column(conn, "network_sources", "ssh_identity_file", "TEXT")
    _ensure_column(conn, "network_sources", "ssh_proxy_jump", "TEXT")
    _ensure_column(conn, "network_sources", "ssh_connect_timeout", "INTEGER NOT NULL DEFAULT 8")
    _ensure_column(conn, "context_revisions", "counts_json", "TEXT NOT NULL DEFAULT '{}'")
    conn.commit()


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {str(row["name"] if isinstance(row, sqlite3.Row) else row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def context_revision_public(row: sqlite3.Row | None) -> dict[str, Any] | None:
    revision = row_to_dict(row)
    if revision is None:
        return None
    try:
        counts = json.loads(revision.pop("counts_json", "{}") or "{}")
    except (TypeError, json.JSONDecodeError):
        counts = {}
    revision["counts"] = counts if isinstance(counts, dict) else {}
    return revision


def record_context_revision(
    conn: sqlite3.Connection,
    context: dict[str, Any],
    source_path: str | Path,
    git_sha: str,
) -> dict[str, Any]:
    conn.execute(
        """
        INSERT INTO context_revisions
            (context_id, schema_version, sha256, source_path, validated_at, git_sha, status, error_json, counts_json)
        VALUES (?, ?, ?, ?, ?, ?, 'ok', '[]', ?)
        ON CONFLICT(context_id, sha256) DO UPDATE SET counts_json = excluded.counts_json
        """,
        (
            context["context_id"],
            context["schema_version"],
            context["sha256"],
            str(source_path),
            utc_now(),
            git_sha,
            json.dumps(context.get("counts") if isinstance(context.get("counts"), dict) else {}, ensure_ascii=False, sort_keys=True),
        ),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM context_revisions WHERE context_id = ? AND sha256 = ?",
        (context["context_id"], context["sha256"]),
    ).fetchone()
    return context_revision_public(row) or {}


def latest_context_revision(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT * FROM context_revisions
        WHERE status = 'ok'
        ORDER BY validated_at DESC, id DESC
        LIMIT 1
        """
    ).fetchone()
    return context_revision_public(row)


def upsert_source(conn: sqlite3.Connection, source: dict[str, Any]) -> int:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO network_sources
            (name, driver, host, port, username, secret_ref, tls, verify_tls, site, role, enabled, created_at, updated_at)
        VALUES
            (:name, :driver, :host, :port, :username, :secret_ref, :tls, :verify_tls, :site, :role, :enabled, :created_at, :updated_at)
        ON CONFLICT(name) DO UPDATE SET
            driver=excluded.driver,
            host=excluded.host,
            port=excluded.port,
            username=excluded.username,
            secret_ref=excluded.secret_ref,
            tls=excluded.tls,
            verify_tls=excluded.verify_tls,
            site=excluded.site,
            role=excluded.role,
            enabled=excluded.enabled,
            updated_at=excluded.updated_at
        """,
        {
            **source,
            "tls": int(bool(source.get("tls"))),
            "verify_tls": int(bool(source.get("verify_tls"))),
            "enabled": int(bool(source.get("enabled", True))),
            "created_at": now,
            "updated_at": now,
        },
    )
    conn.commit()
    _ensure_column(conn, "network_sources", "ssh_identity_file", "TEXT")
    _ensure_column(conn, "network_sources", "ssh_proxy_jump", "TEXT")
    _ensure_column(conn, "network_sources", "ssh_connect_timeout", "INTEGER NOT NULL DEFAULT 8")
    conn.execute(
        """
        UPDATE network_sources
        SET ssh_identity_file = ?, ssh_proxy_jump = ?, ssh_connect_timeout = ?
        WHERE name = ?
        """,
        (
            source.get("ssh_identity_file") or "",
            source.get("ssh_proxy_jump") or "",
            int(source.get("ssh_connect_timeout") or 8),
            source["name"],
        ),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM network_sources WHERE name = ?", (source["name"],)).fetchone()
    return int(row["id"])


def sync_config_sources(conn: sqlite3.Connection, config_path: str | Path) -> None:
    for source in load_config_sources(config_path):
        upsert_source(conn, source)


def source_public(source: dict[str, Any]) -> dict[str, Any]:
    result = dict(source)
    for key in ["id", "tls", "verify_tls", "enabled"]:
        if key in result and key != "id":
            result[key] = bool(result[key])
    result.pop("password", None)
    return result


def get_source(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM network_sources WHERE name = ?", (name,)).fetchone()
    return row_to_dict(row)


def list_sources(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return rows_to_dicts(conn.execute("SELECT * FROM network_sources ORDER BY name").fetchall())


def insert_event(
    conn: sqlite3.Connection,
    severity: str,
    event_type: str,
    message: str,
    source_id: int | None = None,
    host_id: int | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO network_events (ts, source_id, host_id, severity, event_type, message, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (utc_now(), source_id, host_id, severity, event_type, message, json.dumps(data or {}, ensure_ascii=False)),
    )
    conn.commit()
