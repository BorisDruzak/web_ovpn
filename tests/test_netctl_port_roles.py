from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest


NOW = "2026-08-09T10:00:00Z"


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _port_role_db(tmp_path: Path) -> sqlite3.Connection:
    from netctl.db import connect

    conn = connect(_db_url(tmp_path / "port-roles.sqlite"))
    conn.executemany(
        """
        INSERT INTO assets (
            id, asset_key, identity_method, identity_confidence, provisional,
            first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (?, ?, 'manual', 100, 0, ?, ?, ?, ?)
        """,
        [
            (100, "mac:AA:AA:AA:AA:AA:01", NOW, NOW, NOW, NOW),
            (200, "mac:BB:BB:BB:BB:BB:02", NOW, NOW, NOW, NOW),
            (301, "mac:10:00:00:00:00:01", NOW, NOW, NOW, NOW),
            (302, "mac:20:00:00:00:00:01", NOW, NOW, NOW, NOW),
        ],
    )
    conn.executemany(
        """
        INSERT INTO asset_interfaces (
            asset_id, interface_key, mac, first_seen_at, last_seen_at
        ) VALUES (?, 'eth0', ?, ?, ?)
        """,
        [
            (100, "AA:AA:AA:AA:AA:01", NOW, NOW),
            (200, "BB:BB:BB:BB:BB:02", NOW, NOW),
            (301, "10:00:00:00:00:01", NOW, NOW),
            (302, "20:00:00:00:00:01", NOW, NOW),
        ],
    )
    conn.executemany(
        """
        INSERT INTO network_sources (
            id, name, driver, host, port, username, secret_ref, tls,
            verify_tls, enabled, driver_options_json, created_at, updated_at
        ) VALUES (?, ?, 'snmp_switch', '127.0.0.1', 161, '', 'env:TEST',
                  0, 0, 1, ?, ?, ?)
        """,
        [
            (1, "core", '{"access_port_mac_threshold":4,"topology_role":"core"}', NOW, NOW),
            (2, "access", '{"access_port_mac_threshold":10,"topology_role":"access"}', NOW, NOW),
        ],
    )
    conn.executemany(
        "INSERT INTO switch_devices (source_id, runtime_asset_id, updated_at) VALUES (?, ?, ?)",
        [(1, 100, NOW), (2, 200, NOW)],
    )
    conn.executemany(
        """
        INSERT INTO switch_collection_runs (
            id, source_id, started_at, finished_at, status, outcomes_json
        ) VALUES (?, ?, ?, ?, 'success', '{"fdb":"success_with_rows"}')
        """,
        [(11, 1, NOW, NOW), (22, 2, NOW, NOW)],
    )
    conn.executemany(
        """
        INSERT INTO switch_ports (
            source_id, port_key, name, oper_status, last_seen_at, collector_run_id
        ) VALUES (?, ?, ?, 'up', ?, ?)
        """,
        [
            (1, "physical:1", "endpoint", NOW, 11),
            (1, "physical:2", "pass-through", NOW, 11),
            (1, "physical:3", "dense", NOW, 11),
            (1, "physical:4", "confirmed-downlink", NOW, 11),
            (1, "physical:5", "lldp-downlink", NOW, 11),
            (1, "physical:6", "management-only", NOW, 11),
            (2, "physical:23", "confirmed-uplink", NOW, 22),
            (2, "physical:24", "lldp-uplink", NOW, 22),
        ],
    )
    fdb_rows = [
        (1, "10", "10:00:00:00:00:01", "physical:1"),
        (1, "20", "10:00:00:00:00:02", "physical:2"),
        (1, "21", "20:00:00:00:00:01", "physical:2"),
        (1, "30", "30:00:00:00:00:01", "physical:3"),
        (1, "31", "30:00:00:00:00:02", "physical:3"),
        (1, "32", "40:00:00:00:00:01", "physical:3"),
        (1, "33", "50:00:00:00:00:01", "physical:3"),
        (1, "40", "AA:AA:AA:AA:AA:01", "physical:6"),
    ]
    conn.executemany(
        """
        INSERT INTO current_switch_fdb (
            source_id, vlan_key, mac, port_key, status,
            first_seen_at, last_seen_at, collector_run_id
        ) VALUES (?, ?, ?, ?, 'learned', ?, ?, 11)
        """,
        [(*row, NOW, NOW) for row in fdb_rows],
    )
    conn.commit()
    return conn


def _link(
    first_source: int,
    first_port: str,
    second_source: int,
    second_port: str,
    state: str,
    evidence_type: str,
):
    from netctl.topology_models import CurrentSwitchLink, LinkEndpoint, LinkEvidence

    evidence = LinkEvidence(
        LinkEndpoint(first_source, first_port),
        LinkEndpoint(second_source, second_port),
        evidence_type,
        90,
        NOW,
        "",
        {},
    )
    return CurrentSwitchLink(
        f"{first_source}:{first_port}|{second_source}:{second_port}",
        first_source,
        first_port,
        second_source,
        second_port,
        state,
        100 if state == "confirmed" else 85,
        "",
        NOW,
        (evidence,),
    )


def test_migration_creates_constrained_current_port_role_table(tmp_path: Path) -> None:
    conn = _port_role_db(tmp_path)
    try:
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(current_switch_port_roles)")
        }
        assert {
            "source_id", "port_key", "role", "confidence", "mac_count",
            "known_asset_count", "unique_vendor_count", "child_source_id",
            "evidence_json", "observed_at", "correlation_run_id",
        } <= columns
        run_id = conn.execute(
            "INSERT INTO network_correlation_runs (run_type, started_at, status) VALUES ('topology', ?, 'running')",
            (NOW,),
        ).lastrowid
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """INSERT INTO current_switch_port_roles (
                       source_id, port_key, role, confidence, mac_count,
                       known_asset_count, unique_vendor_count, observed_at,
                       correlation_run_id
                   ) VALUES (1, 'physical:1', 'uplink', 100, 1, 1, 1, ?, ?)""",
                (NOW, run_id),
            )
    finally:
        conn.close()


def test_port_role_engine_is_deterministic_and_strong_topology_wins_density(
    tmp_path: Path,
) -> None:
    from netctl.port_roles import infer_port_roles
    from netctl.source_identity import list_source_identities

    conn = _port_role_db(tmp_path)
    links = (
        _link(1, "physical:4", 2, "physical:23", "confirmed", "intent"),
        _link(1, "physical:5", 2, "physical:24", "inferred", "lldp_chassis_mac"),
    )
    try:
        roles = infer_port_roles(
            conn,
            links=links,
            identities=list_source_identities(conn),
            depths={1: 0, 2: 1},
            observed_at=NOW,
        )
        by_port = {(item.source_id, item.port_key): item for item in roles}

        assert (by_port[(1, "physical:1")].role, by_port[(1, "physical:1")].confidence) == (
            "endpoint", 80,
        )
        assert (by_port[(1, "physical:2")].role, by_port[(1, "physical:2")].confidence) == (
            "shared_edge", 55,
        )
        dense = by_port[(1, "physical:3")]
        assert (dense.role, dense.confidence, dense.mac_count) == ("shared_edge", 70, 4)
        assert dense.known_asset_count == 0
        assert dense.unique_vendor_count == 3
        assert (by_port[(1, "physical:4")].role, by_port[(1, "physical:4")].confidence) == (
            "backbone", 100,
        )
        assert (
            by_port[(1, "physical:5")].role,
            by_port[(1, "physical:5")].confidence,
            by_port[(1, "physical:5")].child_source_id,
        ) == ("downstream_bridge", 95, 2)
        assert (by_port[(2, "physical:24")].role, by_port[(2, "physical:24")].confidence) == (
            "backbone", 95,
        )
        assert by_port[(1, "physical:6")].role == "unknown"
        assert by_port[(1, "physical:6")].mac_count == 1
        assert by_port[(1, "physical:1")].known_asset_count == 1
    finally:
        conn.close()


def test_topology_reconcile_persists_roles_and_port_roles_cli_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import netctl.cli as cli
    from netctl import topology_reconcile
    from netctl.source_identity import list_source_identities

    conn = _port_role_db(tmp_path)
    db_url = _db_url(tmp_path / "port-roles.sqlite")
    identities = list_source_identities(conn)
    evidence = (_link(1, "physical:5", 2, "physical:24", "inferred", "lldp_chassis_mac").evidence[0],)
    try:
        monkeypatch.setattr(topology_reconcile, "list_source_identities", lambda _conn: identities)
        monkeypatch.setattr(topology_reconcile, "collect_link_evidence", lambda _conn, _identities: evidence)

        result = topology_reconcile.reconcile_topology(conn, NOW, {})

        assert result["counts"]["port_roles"] == 8
        persisted = conn.execute(
            "SELECT role, confidence, child_source_id, correlation_run_id FROM current_switch_port_roles WHERE source_id = 1 AND port_key = 'physical:5'"
        ).fetchone()
        assert tuple(persisted) == ("downstream_bridge", 95, 2, result["run_id"])
    finally:
        conn.close()

    assert cli.main([
        "--json", "--db", db_url, "switches", "port-roles",
        "--source", "core", "--limit", "5000",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["pagination"]["returned"] == 6
    assert {item["source"] for item in payload["port_roles"]} == {"core"}
    downstream = next(item for item in payload["port_roles"] if item["port_key"] == "physical:5")
    assert downstream["child_source"] == "access"
    assert downstream["evidence"][0]["type"] == "lldp_child_switch"
