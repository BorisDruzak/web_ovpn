import json
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


def _seed_legacy_observations(db_url: str, observations: list[dict[str, Any]]) -> None:
    db_path = Path(db_url.removeprefix("sqlite:///"))
    conn = sqlite3.connect(db_path)
    try:
        for observation in observations:
            values = {
                "id": None,
                "host_id": None,
                "source_id": None,
                "observed_at": "2026-07-16T00:00:00Z",
                "observation_type": "test",
                "ip": None,
                "mac": None,
                "hostname": None,
                "interface": None,
                "data_json": "{}",
                **observation,
            }
            conn.execute(
                """
                INSERT INTO host_observations (
                    id, host_id, source_id, observed_at, observation_type,
                    ip, mac, hostname, interface, data_json
                ) VALUES (
                    :id, :host_id, :source_id, :observed_at, :observation_type,
                    :ip, :mac, :hostname, :interface, :data_json
                )
                """,
                values,
            )
        conn.commit()
    finally:
        conn.close()


def _seed_network_source(db_url: str, source_id: int) -> None:
    db_path = Path(db_url.removeprefix("sqlite:///"))
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO network_sources (
                id, name, driver, host, port, username, secret_ref,
                created_at, updated_at
            ) VALUES (?, ?, 'test', '127.0.0.1', 1, 'test', 'TEST_SECRET', ?, ?)
            """,
            (
                source_id,
                f"source-{source_id}",
                "2026-07-16T00:00:00Z",
                "2026-07-16T00:00:00Z",
            ),
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


def test_historical_source_key_deduplicates_when_source_id_is_null(
    pr_1b_database: str,
) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [{"id": 51, "ip": "10.0.0.51", "mac": "00:11:22:33:44:51"}],
    )
    _seed_legacy_observations(
        pr_1b_database,
        [
            {
                "id": 151,
                "host_id": 51,
                "source_id": None,
                "observation_type": "dhcp",
                "ip": "10.0.0.50",
                "hostname": "history-51",
            }
        ],
    )

    conn = connect(pr_1b_database)
    try:
        ip_observation = conn.execute(
            """
            SELECT asset_id, source_id, source_key, ip, first_seen_at,
                   last_seen_at, is_current, observation_source
            FROM ip_observations
            WHERE source_key = 'legacy-host-observation:151'
            """
        ).fetchone()
        assert tuple(ip_observation) == (
            ip_observation["asset_id"],
            None,
            "legacy-host-observation:151",
            "10.0.0.50",
            "2026-07-16T00:00:00Z",
            "2026-07-16T00:00:00Z",
            0,
            "dhcp",
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO ip_observations (
                    asset_id, source_id, source_key, ip, first_seen_at,
                    last_seen_at, is_current, observation_source
                ) VALUES (?, NULL, ?, ?, ?, ?, 0, ?)
                """,
                (
                    ip_observation["asset_id"],
                    ip_observation["source_key"],
                    ip_observation["ip"],
                    ip_observation["first_seen_at"],
                    ip_observation["last_seen_at"],
                    ip_observation["observation_source"],
                ),
            )

        hostname_observation = conn.execute(
            """
            SELECT asset_id, source_id, source_key, hostname, source_type,
                   first_seen_at, last_seen_at, is_current
            FROM hostname_observations
            WHERE source_key = 'legacy-host-observation:151'
            """
        ).fetchone()
        assert hostname_observation["source_id"] is None
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO hostname_observations (
                    asset_id, hostname, source_id, source_key, source_type,
                    first_seen_at, last_seen_at, is_current
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, 0)
                """,
                (
                    hostname_observation["asset_id"],
                    hostname_observation["hostname"],
                    hostname_observation["source_key"],
                    hostname_observation["source_type"],
                    hostname_observation["first_seen_at"],
                    hostname_observation["last_seen_at"],
                ),
            )
    finally:
        conn.close()


def test_orphan_source_historical_observation_uses_null_source_id(
    pr_1b_database: str,
) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [{"id": 52, "ip": "10.0.0.52", "mac": "00:11:22:33:44:52"}],
    )
    _seed_legacy_observations(
        pr_1b_database,
        [
            {
                "id": 152,
                "host_id": 52,
                "source_id": 9999,
                "observation_type": "arp",
                "ip": "10.0.0.52",
            }
        ],
    )

    conn = connect(pr_1b_database)
    try:
        row = conn.execute(
            """
            SELECT source_id, source_key, observation_source, is_current
            FROM ip_observations
            WHERE source_key = 'legacy-host-observation:152'
            """
        ).fetchone()
        assert tuple(row) == (None, "legacy-host-observation:152", "arp", 0)
    finally:
        conn.close()


def test_historical_observation_history_uses_host_mac_ip_precedence(
    pr_1b_database: str,
) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [
            {"id": 61, "ip": "10.0.0.61", "mac": "00:11:22:33:44:61"},
            {"id": 62, "ip": "10.0.0.62", "mac": "00:11:22:33:44:62"},
            {"id": 63, "ip": "10.0.0.63", "mac": "00:11:22:33:44:63"},
        ],
    )
    _seed_network_source(pr_1b_database, 7)
    _seed_legacy_observations(
        pr_1b_database,
        [
            {
                "id": 161,
                "host_id": 61,
                "observation_type": "host-priority",
                "ip": "10.0.0.62",
                "mac": "00:11:22:33:44:62",
                "hostname": "by-host",
            },
            {
                "id": 162,
                "observation_type": "mac-priority",
                "ip": "10.0.0.61",
                "mac": "00-11-22-33-44-62",
                "hostname": "by-mac",
            },
            {
                "id": 163,
                "source_id": 7,
                "observation_type": "ip-fallback",
                "ip": "10.0.0.63",
                "hostname": "by-ip",
            },
        ],
    )

    conn = connect(pr_1b_database)
    try:
        assert [
            tuple(row)
            for row in conn.execute(
                """
                SELECT observations.source_key, assets.asset_key,
                       observations.observation_source, observations.is_current,
                       observations.source_id
                FROM ip_observations AS observations
                JOIN assets ON assets.id = observations.asset_id
                WHERE observations.source_key LIKE 'legacy-host-observation:%'
                ORDER BY observations.source_key
                """
            ).fetchall()
        ] == [
            ("legacy-host-observation:161", "mac:00:11:22:33:44:61", "host-priority", 0, None),
            ("legacy-host-observation:162", "mac:00:11:22:33:44:62", "mac-priority", 0, None),
            ("legacy-host-observation:163", "mac:00:11:22:33:44:63", "ip-fallback", 0, 7),
        ]
        assert [
            tuple(row)
            for row in conn.execute(
                """
                SELECT observations.source_key, assets.asset_key,
                       observations.source_type, observations.is_current,
                       observations.source_id
                FROM hostname_observations AS observations
                JOIN assets ON assets.id = observations.asset_id
                WHERE observations.source_key LIKE 'legacy-host-observation:%'
                ORDER BY observations.source_key
                """
            ).fetchall()
        ] == [
            ("legacy-host-observation:161", "mac:00:11:22:33:44:61", "host-priority", 0, None),
            ("legacy-host-observation:162", "mac:00:11:22:33:44:62", "mac-priority", 0, None),
            ("legacy-host-observation:163", "mac:00:11:22:33:44:63", "ip-fallback", 0, 7),
        ]
    finally:
        conn.close()


def test_unresolved_historical_observation_history_is_reported(
    pr_1b_database: str,
) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(pr_1b_database, [{"id": 71, "ip": "10.0.0.71"}])
    _seed_legacy_observations(
        pr_1b_database,
        [
            {
                "id": 171,
                "host_id": 9999,
                "observation_type": "neighbor",
                "ip": "192.0.2.171",
                "mac": "not-a-mac",
                "hostname": "unresolved",
            }
        ],
    )

    conn = connect(pr_1b_database)
    try:
        report_json = conn.execute(
            """
            SELECT unresolved_observation_ids_json
            FROM runtime_asset_migration_reports
            WHERE migration_version = 2
            """
        ).fetchone()[0]
        report = json.loads(report_json)
        assert [record["observation_id"] for record in report] == [171]
        assert all(record["reason"] for record in report)
        assert conn.execute(
            """
            SELECT COUNT(*) FROM ip_observations
            WHERE source_key = 'legacy-host-observation:171'
            """
        ).fetchone()[0] == 0
        assert conn.execute(
            """
            SELECT COUNT(*) FROM hostname_observations
            WHERE source_key = 'legacy-host-observation:171'
            """
        ).fetchone()[0] == 0
    finally:
        conn.close()


def test_resolved_mac_only_observation_history_is_reported(
    pr_1b_database: str,
) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [{"id": 72, "ip": "10.0.0.72", "mac": "00:11:22:33:44:72"}],
    )
    _seed_legacy_observations(
        pr_1b_database,
        [
            {
                "id": 172,
                "observation_type": "bridge",
                "mac": "00-11-22-33-44-72",
            }
        ],
    )

    conn = connect(pr_1b_database)
    try:
        report_json = conn.execute(
            """
            SELECT unresolved_observation_ids_json
            FROM runtime_asset_migration_reports
            WHERE migration_version = 2
            """
        ).fetchone()[0]
        assert json.loads(report_json) == [
            {
                "observation_id": 172,
                "reason": "unsupported_mac_only_observation",
            }
        ]
    finally:
        conn.close()


def test_invalid_mac_only_observation_history_reports_invalid_mac(
    pr_1b_database: str,
) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(pr_1b_database, [{"id": 73, "ip": "10.0.0.73"}])
    _seed_legacy_observations(
        pr_1b_database,
        [
            {
                "id": 173,
                "observation_type": "bridge",
                "mac": "not-a-valid-mac",
            }
        ],
    )

    conn = connect(pr_1b_database)
    try:
        report_json = conn.execute(
            """
            SELECT unresolved_observation_ids_json
            FROM runtime_asset_migration_reports
            WHERE migration_version = 2
            """
        ).fetchone()[0]
        assert json.loads(report_json) == [
            {
                "observation_id": 173,
                "reason": "invalid_mac",
            }
        ]
    finally:
        conn.close()


def test_reused_ip_history_can_belong_to_different_assets_at_different_times(
    pr_1b_database: str,
) -> None:
    from netctl.db import connect

    _seed_legacy_hosts(
        pr_1b_database,
        [
            {"id": 81, "ip": "10.0.0.81", "mac": "00:11:22:33:44:81"},
            {"id": 82, "ip": "10.0.0.82", "mac": "00:11:22:33:44:82"},
        ],
    )
    _seed_legacy_observations(
        pr_1b_database,
        [
            {
                "id": 181,
                "host_id": 81,
                "observed_at": "2026-07-14T00:00:00Z",
                "observation_type": "dhcp",
                "ip": "10.0.0.99",
            },
            {
                "id": 182,
                "host_id": 82,
                "observed_at": "2026-07-15T00:00:00Z",
                "observation_type": "dhcp",
                "ip": "10.0.0.99",
            },
        ],
    )

    conn = connect(pr_1b_database)
    try:
        assert [
            tuple(row)
            for row in conn.execute(
                """
                SELECT observations.ip, assets.asset_key,
                       observations.first_seen_at, observations.last_seen_at,
                       observations.is_current
                FROM ip_observations AS observations
                JOIN assets ON assets.id = observations.asset_id
                WHERE observations.ip = '10.0.0.99'
                ORDER BY observations.first_seen_at
                """
            ).fetchall()
        ] == [
            ("10.0.0.99", "mac:00:11:22:33:44:81", "2026-07-14T00:00:00Z", "2026-07-14T00:00:00Z", 0),
            ("10.0.0.99", "mac:00:11:22:33:44:82", "2026-07-15T00:00:00Z", "2026-07-15T00:00:00Z", 0),
        ]
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
