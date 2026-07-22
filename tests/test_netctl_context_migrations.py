import sqlite3
from pathlib import Path


INTENT_TABLES = {
    "intent_sites",
    "intent_locations",
    "intent_segments",
    "intent_assets",
    "intent_services",
    "intent_links",
}


def create_pre_pr_1b_database(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE context_revisions (
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
                validation_order INTEGER NOT NULL DEFAULT 0,
                UNIQUE(context_id, sha256)
            );
            CREATE TABLE network_hosts (
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
            CREATE TABLE host_observations (
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
            CREATE TABLE dhcp_leases (
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
            """
        )
        conn.execute(
            """
            INSERT INTO context_revisions
                (id, context_id, schema_version, sha256, source_path, validated_at, git_sha, status, error_json, counts_json, validation_order)
            VALUES (17, 'legacy-network', '2.2.0', 'aabbcc', 'legacy.yaml', '2026-07-15T00:00:00Z', 'abc123', 'ok', '[]', '{"sites":1}', 4)
            """
        )
        conn.execute("INSERT INTO network_hosts (id, ip, hostname) VALUES (31, '10.0.0.31', 'legacy-host')")
        conn.execute(
            """
            INSERT INTO host_observations (id, host_id, observed_at, observation_type, ip)
            VALUES (41, 31, '2026-07-15T00:01:00Z', 'dhcp', '10.0.0.31')
            """
        )
        conn.execute("INSERT INTO dhcp_leases (id, ip, hostname) VALUES (51, '10.0.0.31', 'legacy-host')")
        conn.commit()
    finally:
        conn.close()


def test_connect_migrates_pre_pr_1b_database_without_changing_runtime_rows(tmp_path: Path) -> None:
    from netctl.db import connect

    db_path = tmp_path / "legacy.sqlite"
    create_pre_pr_1b_database(db_path)

    conn = connect(f"sqlite:///{db_path.as_posix()}")
    try:
        table_names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }

        assert {"schema_migrations", "context_import_runs", "context_heads", *INTENT_TABLES} <= table_names
        assert [tuple(row) for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()] == [
            (version,) for version in range(1, 13)
        ]
        assert conn.execute("SELECT * FROM context_heads").fetchall() == []
        assert [tuple(row) for row in conn.execute("SELECT id, context_id, sha256 FROM context_revisions").fetchall()] == [
            (17, "legacy-network", "aabbcc")
        ]
        assert [tuple(row) for row in conn.execute("SELECT id, ip, hostname FROM network_hosts").fetchall()] == [(31, "10.0.0.31", "legacy-host")]
        assert [tuple(row) for row in conn.execute("SELECT id, host_id, ip FROM host_observations").fetchall()] == [(41, 31, "10.0.0.31")]
        assert [tuple(row) for row in conn.execute("SELECT id, ip, hostname FROM dhcp_leases").fetchall()] == [(51, "10.0.0.31", "legacy-host")]
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()
