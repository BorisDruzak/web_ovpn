from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


CORRELATION_TABLES = {
    "network_correlation_runs",
    "current_switch_links",
    "switch_link_events",
    "asset_attachment_resolutions",
    "asset_attachment_candidates",
    "asset_attachment_events",
    "topology_findings",
}


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _database_at_migration_8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> sqlite3.Connection:
    from netctl import migrations
    from netctl.db import connect

    migration_8_and_before = tuple(
        entry for entry in migrations.MIGRATIONS if entry[0] <= 8
    )
    with monkeypatch.context() as migration_patch:
        migration_patch.setattr(migrations, "MIGRATIONS", migration_8_and_before)
        return connect(_db_url(tmp_path / "netctl.sqlite"))


def _migration_versions(conn: sqlite3.Connection) -> list[int]:
    return [
        int(row[0])
        for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
    ]


def test_migration_9_creates_correlation_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netctl import migrations

    conn = _database_at_migration_8(tmp_path, monkeypatch)
    try:
        migrations.apply_migrations(conn)

        assert _migration_versions(conn) == list(range(1, 10))
        assert CORRELATION_TABLES <= _table_names(conn)
        assert {
            row[1]
            for row in conn.execute("PRAGMA index_list(asset_interfaces)")
        } >= {"asset_interfaces_id_asset_idx"}
    finally:
        conn.close()


def test_migration_9_failure_rolls_back_schema_and_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netctl import migrations

    assert hasattr(migrations, "_migration_9")
    original_migration_9 = migrations._migration_9
    conn = _database_at_migration_8(tmp_path, monkeypatch)

    def fail_after_migration_9(connection: sqlite3.Connection) -> None:
        original_migration_9(connection)
        raise RuntimeError("injected migration 9 failure")

    migration_8_and_before = tuple(
        entry for entry in migrations.MIGRATIONS if entry[0] <= 8
    )
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (*migration_8_and_before, (9, fail_after_migration_9)),
    )
    try:
        with pytest.raises(RuntimeError, match="injected migration 9 failure"):
            migrations.apply_migrations(conn)

        assert CORRELATION_TABLES.isdisjoint(_table_names(conn))
        assert _migration_versions(conn) == list(range(1, 9))
        assert {
            row[1]
            for row in conn.execute("PRAGMA index_list(asset_interfaces)")
        }.isdisjoint({"asset_interfaces_id_asset_idx"})
    finally:
        conn.close()


def _evidence_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE context_heads (context_id TEXT PRIMARY KEY, context_revision_id INTEGER NOT NULL);
        CREATE TABLE intent_links (
            context_revision_id INTEGER NOT NULL, stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL, relation TEXT NOT NULL,
            endpoint_a_json TEXT NOT NULL, endpoint_b_json TEXT NOT NULL
        );
        CREATE TABLE switch_ports (
            source_id INTEGER NOT NULL, port_key TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
            alias TEXT NOT NULL DEFAULT '', PRIMARY KEY(source_id, port_key)
        );
        CREATE TABLE current_switch_fdb (
            source_id INTEGER NOT NULL, vlan_key TEXT NOT NULL, mac TEXT NOT NULL,
            port_key TEXT NOT NULL, last_seen_at TEXT NOT NULL
        );
        CREATE TABLE current_switch_lldp_neighbors (
            source_id INTEGER NOT NULL, local_port_key TEXT NOT NULL, chassis_id TEXT NOT NULL,
            port_id TEXT NOT NULL, system_name TEXT NOT NULL DEFAULT '', observed_at TEXT NOT NULL
        );
        """
    )
    return conn


def _identities():
    from netctl.source_identity import SourceIdentity

    return (
        SourceIdentity(1, "router", "mikrotik_api", "core", 10, "mac:AA", "ctx", "router", ("AA:AA:AA:AA:AA:01",)),
        SourceIdentity(2, "switch", "snmp_switch", "access", 20, "mac:BB", "ctx", "switch", ("BB:BB:BB:BB:BB:02",)),
        SourceIdentity(3, "switch-duplicate-name", "snmp_switch", "access", 30, "mac:CC", "ctx", "other", ("CC:CC:CC:CC:CC:03",)),
    )


def test_collect_link_evidence_keeps_intent_fdb_and_lldp_rows_separate() -> None:
    from netctl.topology_evidence import collect_link_evidence

    conn = _evidence_db()
    try:
        conn.execute("INSERT INTO context_heads VALUES ('ctx', 7)")
        conn.execute(
            "INSERT INTO intent_links VALUES (7, 'router-switch', 'active', 'CONNECTED_TO', ?, ?)",
            ('{"device":"router","interface":"ether1"}', '{"device":"switch","interface":"ge24"}'),
        )
        conn.executemany(
            "INSERT INTO switch_ports VALUES (?, ?, ?, '')",
            [(1, "ifindex:1", "ether1"), (2, "physical:24", "ge24")],
        )
        conn.execute(
            "INSERT INTO current_switch_fdb VALUES (1, '1', 'BB:BB:BB:BB:BB:02', 'ifindex:1', '2026-07-22T08:00:00Z')"
        )
        conn.execute(
            "INSERT INTO current_switch_lldp_neighbors VALUES (1, 'ifindex:1', 'BB:BB:BB:BB:BB:02', 'ge24', '', '2026-07-22T08:01:00Z')"
        )

        evidence = collect_link_evidence(conn, _identities())

        assert [(item.evidence_type, item.confidence) for item in evidence] == [
            ("fdb_management_mac", 70),
            ("intent", 90),
            ("lldp_chassis_mac", 90),
        ]
        assert all(item.endpoint_a.source_id == 1 and item.endpoint_b.source_id == 2 for item in evidence)
        assert {item.endpoint_a.port_key for item in evidence} == {"ifindex:1"}
        assert [item.endpoint_b.port_key for item in evidence] == ["", "physical:24", "physical:24"]
    finally:
        conn.close()


def test_collect_link_evidence_keeps_partial_intent_and_rejects_self_or_unknown_mac() -> None:
    from netctl.topology_evidence import collect_link_evidence

    conn = _evidence_db()
    try:
        conn.execute("INSERT INTO context_heads VALUES ('ctx', 7)")
        conn.execute(
            "INSERT INTO intent_links VALUES (7, 'partial', 'active', 'CONNECTED_TO', ?, ?)",
            ('{"device":"router","interface":"ether1"}', '{"device":"switch","interface":"missing"}'),
        )
        conn.execute("INSERT INTO switch_ports VALUES (1, 'ifindex:1', 'ether1', '')")
        conn.executemany(
            "INSERT INTO current_switch_fdb VALUES (1, '1', ?, 'ifindex:1', '2026-07-22T08:00:00Z')",
            [("AA:AA:AA:AA:AA:01",), ("DD:DD:DD:DD:DD:04",)],
        )

        evidence = collect_link_evidence(conn, _identities())

        assert [(item.evidence_type, item.confidence, item.endpoint_b.port_key) for item in evidence] == [
            ("intent", 65, "")
        ]
    finally:
        conn.close()
