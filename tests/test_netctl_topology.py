from __future__ import annotations

import json
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


def _topology_db(tmp_path: Path) -> sqlite3.Connection:
    from netctl.db import connect

    conn = connect(_db_url(tmp_path / "topology.sqlite"))
    now = "2026-07-22T08:00:00Z"
    conn.executemany(
        """
        INSERT INTO network_sources (
            id, name, driver, host, port, username, secret_ref, tls,
            verify_tls, enabled, created_at, updated_at
        ) VALUES (?, ?, 'snmp_switch', '127.0.0.1', 161, '', 'env:TEST', 0, 0, 1, ?, ?)
        """,
        [(1, "core", now, now), (2, "access-a", now, now), (3, "access-b", now, now)],
    )
    conn.commit()
    return conn


def _link_evidence(
    first_source: int,
    first_port: str,
    second_source: int,
    second_port: str,
    evidence_type: str,
    confidence: int,
) -> object:
    from netctl.topology_models import LinkEndpoint, LinkEvidence

    return LinkEvidence(
        LinkEndpoint(first_source, first_port),
        LinkEndpoint(second_source, second_port),
        evidence_type,
        confidence,
        "2026-07-22T08:00:00Z",
        "intent-link" if evidence_type == "intent" else "",
        {},
    )


def _topology_identities() -> tuple[object, ...]:
    from netctl.source_identity import SourceIdentity

    return (
        SourceIdentity(1, "core", "snmp_switch", "core", None, "", "", "", ()),
        SourceIdentity(2, "access-a", "snmp_switch", "access", None, "", "", "", ()),
        SourceIdentity(3, "access-b", "snmp_switch", "access", None, "", "", "", ()),
    )


def test_reconcile_topology_classifies_links_is_idempotent_and_records_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netctl import topology_reconcile

    conn = _topology_db(tmp_path)
    initial = (
        _link_evidence(1, "ifindex:1", 2, "physical:24", "intent", 90),
        _link_evidence(1, "ifindex:1", 2, "physical:24", "fdb_management_mac", 70),
        _link_evidence(2, "physical:1", 3, "", "fdb_management_mac", 70),
    )
    try:
        monkeypatch.setattr(topology_reconcile, "list_source_identities", lambda _conn: _topology_identities())
        monkeypatch.setattr(topology_reconcile, "collect_link_evidence", lambda _conn, _identities: initial)

        first = topology_reconcile.reconcile_topology(conn, "2026-07-22T08:00:00Z")
        rows = conn.execute(
            "SELECT source_a_id, port_a_key, source_b_id, port_b_key, state, confidence FROM current_switch_links ORDER BY link_key"
        ).fetchall()
        assert first["counts"]["confirmed"] == 1
        assert [(row["state"], row["confidence"]) for row in rows] == [("confirmed", 100), ("inferred", 70)]
        assert conn.execute("SELECT count(*) FROM switch_link_events").fetchone()[0] == 2

        second = topology_reconcile.reconcile_topology(conn, "2026-07-22T08:01:00Z")
        assert second["counts"]["events"] == 0
        assert conn.execute("SELECT count(*) FROM switch_link_events").fetchone()[0] == 2

        changed = (
            _link_evidence(1, "ifindex:2", 2, "physical:24", "intent", 90),
            _link_evidence(1, "ifindex:2", 2, "physical:24", "fdb_management_mac", 70),
            _link_evidence(2, "physical:1", 3, "", "fdb_management_mac", 70),
        )
        monkeypatch.setattr(topology_reconcile, "collect_link_evidence", lambda _conn, _identities: changed)
        third = topology_reconcile.reconcile_topology(conn, "2026-07-22T08:02:00Z")
        assert third["counts"]["events"] == 1
        assert conn.execute(
            "SELECT event_type FROM switch_link_events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0] == "changed"

        monkeypatch.setattr(topology_reconcile, "collect_link_evidence", lambda _conn, _identities: changed[:2])
        fourth = topology_reconcile.reconcile_topology(conn, "2026-07-22T08:03:00Z")
        assert fourth["counts"]["events"] == 1
        assert conn.execute(
            "SELECT event_type FROM switch_link_events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0] == "disappeared"
    finally:
        conn.close()


def test_reconcile_topology_records_conflict_and_preserves_current_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from netctl import topology_reconcile

    conn = _topology_db(tmp_path)
    stable = (_link_evidence(1, "ifindex:1", 2, "physical:24", "lldp_chassis_mac", 90),)
    try:
        monkeypatch.setattr(topology_reconcile, "list_source_identities", lambda _conn: _topology_identities())
        monkeypatch.setattr(topology_reconcile, "collect_link_evidence", lambda _conn, _identities: stable)
        topology_reconcile.reconcile_topology(conn, "2026-07-22T08:00:00Z")

        conflicting = (
            _link_evidence(1, "ifindex:1", 2, "physical:24", "lldp_chassis_mac", 90),
            _link_evidence(1, "ifindex:2", 2, "physical:24", "lldp_chassis_mac", 90),
        )
        monkeypatch.setattr(topology_reconcile, "collect_link_evidence", lambda _conn, _identities: conflicting)
        result = topology_reconcile.reconcile_topology(conn, "2026-07-22T08:01:00Z")
        assert result["counts"]["conflicting"] == 1
        assert conn.execute("SELECT count(*) FROM topology_findings WHERE status = 'open'").fetchone()[0] == 1
        current_before_failure = [
            tuple(row)
            for row in conn.execute("SELECT * FROM current_switch_links ORDER BY link_key")
        ]

        conn.execute(
            """
            CREATE TRIGGER fail_link_replace BEFORE INSERT ON current_switch_links
            BEGIN SELECT RAISE(ABORT, 'injected link replacement failure'); END
            """
        )
        conn.commit()
        with pytest.raises(sqlite3.DatabaseError, match="injected link replacement failure"):
            topology_reconcile.reconcile_topology(conn, "2026-07-22T08:02:00Z")
        assert [tuple(row) for row in conn.execute("SELECT * FROM current_switch_links ORDER BY link_key")] == current_before_failure
        assert conn.execute(
            "SELECT status FROM network_correlation_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()[0] == "failed"
    finally:
        conn.close()


def test_aggregate_link_evidence_uses_each_declared_confidence_rule() -> None:
    from netctl.topology_reconcile import aggregate_link_evidence

    links = aggregate_link_evidence(
        (
            _link_evidence(1, "ifindex:1", 2, "physical:1", "lldp_chassis_mac", 90),
            _link_evidence(1, "ifindex:2", 3, "physical:2", "intent", 90),
            _link_evidence(2, "physical:3", 3, "", "intent", 65),
        ),
        "2026-07-22T08:00:00Z",
    )

    assert [(link.state, link.confidence) for link in links] == [
        ("inferred", 85),
        ("inferred", 60),
        ("inferred", 45),
    ]


def test_topology_depths_handle_missing_core_and_cycles() -> None:
    from netctl.topology_models import CurrentSwitchLink
    from netctl.topology_reconcile import topology_depths

    links = (
        CurrentSwitchLink("1::2:", 1, "", 2, "", "inferred", 70, "", "", ()),
        CurrentSwitchLink("2::3:", 2, "", 3, "", "inferred", 70, "", "", ()),
        CurrentSwitchLink("1::3:", 1, "", 3, "", "inferred", 70, "", "", ()),
    )
    assert topology_depths(links, {1}) == {1: 0, 2: 1, 3: 1}
    assert topology_depths(links, set()) == {}


def test_topology_cli_reads_status_links_and_findings_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import netctl.cli as cli

    conn = _topology_db(tmp_path)
    db_url = _db_url(tmp_path / "topology.sqlite")
    try:
        run_id = conn.execute(
            """
            INSERT INTO network_correlation_runs (run_type, started_at, finished_at, status)
            VALUES ('topology', '2026-07-22T08:00:00Z', '2026-07-22T08:00:00Z', 'success')
            """
        ).lastrowid
        conn.execute(
            """
            INSERT INTO current_switch_links (
                link_key, source_a_id, port_a_key, source_b_id, port_b_key, state,
                confidence, first_seen_at, last_seen_at, correlation_run_id
            ) VALUES ('1:ifindex:1|2:physical:24', 1, 'ifindex:1', 2, 'physical:24',
                'confirmed', 100, '2026-07-22T08:00:00Z', '2026-07-22T08:00:00Z', ?)
            """,
            (run_id,),
        )
        conn.execute(
            """
            INSERT INTO topology_findings (
                finding_key, finding_type, severity, status, source_id,
                first_seen_at, last_seen_at
            ) VALUES ('finding', 'incompatible_link_evidence', 'error', 'open', 1,
                '2026-07-22T08:00:00Z', '2026-07-22T08:00:00Z')
            """
        )
        conn.commit()
    finally:
        conn.close()

    calls: list[str] = []
    original_read_only = cli.connect_read_only

    def tracked_read_only(url: str) -> sqlite3.Connection:
        calls.append(url)
        return original_read_only(url)

    monkeypatch.setattr(cli, "connect_read_only", tracked_read_only)
    assert cli.main(["--json", "--db", db_url, "topology", "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["links"]["confirmed"] == 1
    assert cli.main(["--json", "--db", db_url, "topology", "links", "--state", "confirmed"]) == 0
    links = json.loads(capsys.readouterr().out)
    assert [item["link_key"] for item in links["links"]] == ["1:ifindex:1|2:physical:24"]
    assert cli.main(["--json", "--db", db_url, "topology", "findings", "--status", "open"]) == 0
    findings = json.loads(capsys.readouterr().out)
    assert [item["finding_key"] for item in findings["findings"]] == ["finding"]
    assert calls == [db_url, db_url, db_url]
