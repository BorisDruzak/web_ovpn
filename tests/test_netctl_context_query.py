from __future__ import annotations

import sqlite3
import json
from pathlib import Path


def _context_db(tmp_path: Path) -> sqlite3.Connection:
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'context.sqlite').as_posix()}")
    now = "2026-07-22T12:00:00Z"
    conn.executemany(
        """INSERT INTO assets (id, asset_key, identity_method, identity_confidence, provisional,
            first_seen_at, last_seen_at, created_at, updated_at)
           VALUES (?, ?, 'manual', 100, 0, ?, ?, ?, ?)""",
        [(1, "mac:AA:BB:CC:DD:EE:01", now, now, now, now), (2, "mac:AA:BB:CC:DD:EE:02", now, now, now, now)],
    )
    conn.executemany(
        "INSERT INTO asset_interfaces (asset_id, interface_key, mac, first_seen_at, last_seen_at) VALUES (?, 'eth0', ?, ?, ?)",
        [(1, "aa-bb-cc-dd-ee-01", now, now), (2, "AA:BB:CC:DD:EE:02", now, now)],
    )
    conn.executemany(
        """INSERT INTO ip_observations (asset_id, site, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
           VALUES (?, 'central', ?, '192.0.2.10', ?, ?, 1, 'collector_host')""",
        [(1, "one", now, now), (2, "two", now, now)],
    )
    conn.execute(
        "INSERT INTO hostname_observations (asset_id, hostname, source_key, source_type, first_seen_at, last_seen_at, is_current) VALUES (1, 'Workstation', 'one', 'collector_host', ?, ?, 1)",
        (now, now),
    )
    conn.executemany(
        """INSERT INTO network_sources (id, name, driver, host, port, username, secret_ref, tls, verify_tls, enabled, created_at, updated_at)
           VALUES (?, ?, 'snmp_switch', '127.0.0.1', 161, '', 'env:TEST', 0, 0, 1, ?, ?)""",
        [(10, 'access', now, now), (11, 'core', now, now)],
    )
    conn.execute("UPDATE network_sources SET site = 'central' WHERE id IN (10, 11)")
    conn.execute(
        """INSERT INTO switch_collection_runs
           (source_id, started_at, finished_at, status, error_class, error_message, outcomes_json)
           VALUES (10, ?, ?, 'failed', 'TimeoutError', 'private transport detail', '{}')""",
        (now, now),
    )
    conn.execute("UPDATE network_sources SET driver_options_json = '{\"topology_role\": \"core\"}' WHERE id = 11")
    run_id = conn.execute("INSERT INTO network_correlation_runs (run_type, started_at, finished_at, status) VALUES ('attachments', ?, ?, 'success')", (now, now)).lastrowid
    conn.execute(
        """INSERT INTO asset_attachment_resolutions (asset_interface_id, asset_id, status, selected_source_id, selected_port_key, selected_vlan_key, confidence, first_seen_at, last_seen_at, correlation_run_id)
           VALUES (1, 1, 'confirmed', 10, 'physical:48', '20', 85, ?, ?, ?)""",
        (now, now, run_id),
    )
    conn.execute(
        """INSERT INTO asset_attachment_candidates
           (asset_interface_id, asset_id, switch_source_id, port_key, vlan_key, candidate_class, score, observed_at, correlation_run_id, evidence_json)
           VALUES (1, 1, 10, 'physical:47', '20', 'direct', 80, ?, ?, '[{"collector_run_id": 4}]')""",
        (now, run_id),
    )
    topology_run = conn.execute("INSERT INTO network_correlation_runs (run_type, started_at, finished_at, status) VALUES ('topology', ?, ?, 'success')", (now, now)).lastrowid
    conn.execute(
        """INSERT INTO current_switch_links (link_key, source_a_id, port_a_key, source_b_id, port_b_key, state, confidence, first_seen_at, last_seen_at, correlation_run_id)
           VALUES ('10:uplink|11:core', 10, 'uplink', 11, 'core', 'confirmed', 100, ?, ?, ?)""",
        (now, now, topology_run),
    )
    conn.execute(
        """INSERT INTO asset_intent_bindings (asset_id, context_id, intent_stable_id, binding_source, confidence, status, first_seen_at, last_seen_at)
           VALUES (1, 'central', 'device:workstation-01', 'manual', 100, 'confirmed', ?, ?)""",
        (now, now),
    )
    conn.execute(
        """INSERT INTO topology_findings
           (finding_key, finding_type, severity, status, asset_id, source_id, first_seen_at, last_seen_at, details_json)
           VALUES ('topology:asset-one', 'attachment_ambiguous', 'warning', 'open', 1, 10, ?, ?, '{}')""",
        (now, now),
    )
    conn.commit()
    return conn


def test_inspect_asset_context_has_exact_safe_top_level_contract(tmp_path: Path) -> None:
    from netctl.context_query import inspect_asset_context

    conn = _context_db(tmp_path)
    try:
        result = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")
        assert result is not None
        assert set(result) == {"asset", "intent", "owner", "interfaces", "attachment", "network", "topology_path", "source_health", "findings", "evidence"}
        assert result["owner"] == {"status": "none", "bindings": []}
        assert result["asset"]["asset_key"] == "mac:AA:BB:CC:DD:EE:01"
        assert result["network"]["ip_observations"][0]["ip"] == "192.0.2.10"
        assert result["attachment"]["selected_port_key"] == "physical:48"
        assert result["attachment"]["alternatives"] == [
            {"source": "access", "port_key": "physical:47", "vlan_key": "20", "vlan_id": None, "candidate_class": "direct", "topology_depth": None, "score": 80, "observed_at": "2026-07-22T12:00:00Z"}
        ]
        assert result["topology_path"] == {"nodes": [10, 11], "complete": True, "reason": ""}
        assert result["intent"]["intent_stable_id"] == "device:workstation-01"
        assert [item["source"] for item in result["source_health"]] == ["access", "core"]
    finally:
        conn.close()


def test_search_context_returns_all_explicit_matches_for_safe_identity_keys(tmp_path: Path) -> None:
    from netctl.context_query import search_context

    conn = _context_db(tmp_path)
    try:
        assert [item["asset_key"] for item in search_context(conn, "aa:bb:cc:dd:ee:01")] == ["mac:AA:BB:CC:DD:EE:01"]
        assert [item["asset_key"] for item in search_context(conn, "WORKSTATION")] == ["mac:AA:BB:CC:DD:EE:01"]
        assert [item["asset_key"] for item in search_context(conn, "192.0.2.10")] == ["mac:AA:BB:CC:DD:EE:01", "mac:AA:BB:CC:DD:EE:02"]
        assert [item["asset_key"] for item in search_context(conn, "device:workstation-01")] == ["mac:AA:BB:CC:DD:EE:01"]
    finally:
        conn.close()


def test_asset_context_keeps_attachments_per_interface_and_resolves_owner(tmp_path: Path) -> None:
    from netctl.context_query import inspect_asset_context
    from netctl.user_context import bind_user_asset, create_user

    conn = _context_db(tmp_path)
    try:
        create_user(conn, "employee:owner", "Owner", now="2026-07-22T12:00:00Z")
        bind_user_asset(
            conn, "employee:owner", "mac:AA:BB:CC:DD:EE:01", relation="owner",
            confidence=100, reason="assigned", now="2026-07-22T12:00:00Z",
        )
        result = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")
        assert result is not None
        assert result["owner"] == {
            "status": "confirmed",
            "bindings": [{
                "user_key": "employee:owner", "display_name": "Owner", "relation": "owner",
                "status": "confirmed", "confidence": 100, "valid_from": "2026-07-22T12:00:00Z",
                "valid_until": None, "binding_source": "manual",
            }],
        }
        assert result["interfaces"] == [{
            "interface_key": "eth0", "mac": "aa-bb-cc-dd-ee-01", "interface_type": "",
            "interface_name": "", "lifecycle": "active",
            "attachment": {
                "status": "confirmed", "selected_source_id": 10, "selected_port_key": "physical:48",
                "selected_vlan_key": "20", "selected_vlan_id": None, "confidence": 85,
                "last_seen_at": "2026-07-22T12:00:00Z", "alternatives": [{
                    "source": "access", "port_key": "physical:47", "vlan_key": "20", "vlan_id": None,
                    "candidate_class": "direct", "topology_depth": None, "score": 80,
                    "observed_at": "2026-07-22T12:00:00Z",
                }],
            },
        }]
    finally:
        conn.close()


def test_context_view_cli_reads_asset_context(tmp_path: Path, capsys) -> None:
    import netctl.cli as cli

    conn = _context_db(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'context.sqlite').as_posix()}"
    conn.close()
    assert cli.main(["--json", "--db", db_url, "context-view", "asset", "--asset-key", "mac:AA:BB:CC:DD:EE:01"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["context"]["asset"]["asset_key"] == "mac:AA:BB:CC:DD:EE:01"


def test_context_view_cli_lists_topology_with_bounded_filters(tmp_path: Path, capsys) -> None:
    import netctl.cli as cli

    conn = _context_db(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'context.sqlite').as_posix()}"
    conn.close()

    assert cli.main([
        "--json", "--db", db_url, "context-view", "topology",
        "--site", "central", "--state", "confirmed", "--depth", "4",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["links"][0]["link_key"] == "10:uplink|11:core"
    assert result["depth"] == 4


def test_context_view_cli_lists_aggregated_findings(tmp_path: Path, capsys) -> None:
    import netctl.cli as cli

    conn = _context_db(tmp_path)
    db_url = f"sqlite:///{(tmp_path / 'context.sqlite').as_posix()}"
    conn.close()

    assert cli.main(["--json", "--db", db_url, "context-view", "findings", "--status", "open"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["findings"][0] == {
        "finding_key": "topology:asset-one",
        "finding_type": "attachment_ambiguous",
        "severity": "warning",
        "status": "open",
        "first_seen_at": "2026-07-22T12:00:00Z",
        "last_seen_at": "2026-07-22T12:00:00Z",
        "details": {},
        "source": "topology",
    }


def test_asset_findings_include_selected_switch_collection_failure_without_error_text(tmp_path: Path) -> None:
    from netctl.findings import findings_for_asset

    conn = _context_db(tmp_path)
    try:
        failure = next(item for item in findings_for_asset(conn, 1) if item["source"] == "switch_collection")
        assert failure["finding_key"] == "switch_collection_run:1"
        assert failure["finding_type"] == "switch_collection_failed"
        assert failure["details"] == {"source": "access", "error_class": "TimeoutError"}
    finally:
        conn.close()
