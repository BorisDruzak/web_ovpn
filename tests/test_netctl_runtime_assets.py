import sqlite3
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def pr_1b_database(tmp_path: Path) -> str:
    """Create the schema a PR 1B deployment has before runtime-asset migration 2."""
    from netctl.migrations import _migration_1

    db_path = tmp_path / "netctl.sqlite"
    db_url = f"sqlite:///{db_path.as_posix()}"
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
            CREATE TABLE network_sources (
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
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """
        )
        _migration_1(conn)
        conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (1, '2026-07-17T00:00:00Z')")
        conn.commit()
        assert [row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")] == [1]
    finally:
        conn.close()
    return db_url


def _seed_legacy_hosts(db_url: str, hosts: list[dict[str, Any]]) -> None:
    db_path = Path(db_url.removeprefix("sqlite:///"))
    conn = sqlite3.connect(db_path)
    try:
        for host in hosts:
            values = {
                "id": None,
                "ip": "",
                "mac": None,
                "hostname": None,
                "display_name": None,
                "category": None,
                "device_key": None,
                "device_type": None,
                "device_confidence": None,
                "device_evidence_json": None,
                "status": None,
                "site": None,
                "first_seen_at": None,
                "last_seen_at": None,
                "last_source": None,
                "tags_json": None,
                "comment": None,
                **host,
            }
            conn.execute(
                """
                INSERT INTO network_hosts (
                    id, ip, mac, hostname, display_name, category, device_key,
                    device_type, device_confidence, device_evidence_json, status,
                    site, first_seen_at, last_seen_at, last_source, tags_json, comment
                ) VALUES (
                    :id, :ip, :mac, :hostname, :display_name, :category, :device_key,
                    :device_type, :device_confidence, :device_evidence_json, :status,
                    :site, :first_seen_at, :last_seen_at, :last_source, :tags_json, :comment
                )
                """,
                values,
            )
        conn.commit()
    finally:
        conn.close()


def test_connect_enables_runtime_identity_pragmas(pr_1b_database: str) -> None:
    from netctl.db import connect

    conn = connect(pr_1b_database)
    try:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert [row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")] == [1, 2]
    finally:
        conn.close()


def test_same_mac_with_changed_ips_maps_to_one_asset(pr_1b_database: str) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [
            {
                "id": 11,
                "ip": "10.0.0.11",
                "mac": "aa-bb-cc-dd-ee-ff",
                "hostname": "printer-old",
                "first_seen_at": "2026-07-15T10:00:00Z",
                "last_seen_at": "2026-07-15T11:00:00Z",
            },
            {
                "id": 12,
                "ip": "10.0.0.12",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "printer-new",
                "first_seen_at": "2026-07-16T10:00:00Z",
                "last_seen_at": "2026-07-16T11:00:00Z",
            },
        ],
    )

    conn = connect(pr_1b_database)
    try:
        asset = conn.execute("SELECT id, asset_key FROM assets").fetchone()
        assert tuple(asset) == (asset["id"], "mac:AA:BB:CC:DD:EE:FF")
        assert [
            tuple(row)
            for row in conn.execute(
                "SELECT interface_key, mac FROM asset_interfaces ORDER BY id"
            ).fetchall()
        ] == [("mac:AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF")]
        assert [
            tuple(row)
            for row in conn.execute(
                "SELECT ip, is_current FROM ip_observations ORDER BY ip"
            ).fetchall()
        ] == [("10.0.0.11", 1), ("10.0.0.12", 1)]
        assert conn.execute("SELECT COUNT(*) FROM legacy_host_asset_mappings").fetchone()[0] == 2
    finally:
        conn.close()


def test_different_macs_do_not_merge_on_matching_names(pr_1b_database: str) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [
            {
                "id": 21,
                "ip": "10.0.0.21",
                "mac": "00:11:22:33:44:55",
                "hostname": "shared-name",
                "display_name": "Shared display",
            },
            {
                "id": 22,
                "ip": "10.0.0.22",
                "mac": "66:77:88:99:AA:BB",
                "hostname": "shared-name",
                "display_name": "Shared display",
            },
        ],
    )

    conn = connect(pr_1b_database)
    try:
        assert [row[0] for row in conn.execute("SELECT asset_key FROM assets ORDER BY asset_key")] == [
            "mac:00:11:22:33:44:55",
            "mac:66:77:88:99:AA:BB",
        ]
        assert conn.execute(
            "SELECT COUNT(DISTINCT asset_id) FROM legacy_host_asset_mappings"
        ).fetchone()[0] == 2
    finally:
        conn.close()


def test_ip_only_host_gets_provisional_key_and_confidence(pr_1b_database: str) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [{"id": 31, "ip": "10.0.0.31", "mac": "invalid", "device_key": "ip:10.0.0.31"}],
    )

    conn = connect(pr_1b_database)
    try:
        asset = conn.execute(
            """
            SELECT asset_key, identity_method, identity_confidence, provisional
            FROM assets
            """
        ).fetchone()
        assert tuple(asset) == ("legacy-host:31", "provisional_legacy", 20, 1)
        interface = conn.execute(
            "SELECT interface_key, mac FROM asset_interfaces"
        ).fetchone()
        assert tuple(interface) == ("legacy-host:31:unknown", None)
        assert conn.execute(
            "SELECT mapping_kind FROM legacy_host_asset_mappings WHERE legacy_network_host_id = 31"
        ).fetchone()[0] == "provisional"
    finally:
        conn.close()


def test_runtime_ip_is_not_globally_unique(pr_1b_database: str) -> None:
    from netctl.db import connect

    conn = connect(pr_1b_database)
    try:
        now = "2026-07-17T12:00:00Z"
        conn.executemany(
            """
            INSERT INTO assets (
                asset_key, identity_method, identity_confidence, provisional,
                first_seen_at, last_seen_at, created_at, updated_at
            ) VALUES (?, 'manual', 100, 0, ?, ?, ?, ?)
            """,
            [("manual:first", now, now, now, now), ("manual:second", now, now, now, now)],
        )
        asset_ids = [row[0] for row in conn.execute("SELECT id FROM assets ORDER BY id")]
        conn.executemany(
            """
            INSERT INTO ip_observations (
                asset_id, source_key, ip, first_seen_at, last_seen_at,
                is_current, observation_source
            ) VALUES (?, 'manual:test', '10.0.0.99', ?, ?, 1, 'test')
            """,
            [(asset_id, now, now) for asset_id in asset_ids],
        )
        assert conn.execute(
            "SELECT COUNT(*) FROM ip_observations WHERE ip = '10.0.0.99'"
        ).fetchone()[0] == 2
    finally:
        conn.close()


def test_migration_report_maps_every_legacy_host(pr_1b_database: str) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [
            {"id": 41, "ip": "10.0.0.41", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "one"},
            {"id": 42, "ip": "10.0.0.42", "mac": "aa-bb-cc-dd-ee-ff", "hostname": "two"},
            {"id": 43, "ip": "10.0.0.43", "hostname": "three"},
        ],
    )

    conn = connect(pr_1b_database)
    try:
        report = conn.execute(
            """
            SELECT legacy_host_count, mapped_legacy_host_count, mac_asset_count,
                   provisional_asset_count, interface_count, ip_observation_count,
                   hostname_observation_count, tag_binding_count,
                   unresolved_legacy_host_ids_json
            FROM runtime_asset_migration_reports
            WHERE migration_version = 2
            """
        ).fetchone()
        assert tuple(report) == (3, 3, 1, 1, 2, 3, 3, 0, "[]")
    finally:
        conn.close()
