from __future__ import annotations

import sqlite3
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
    conn.execute("UPDATE network_sources SET driver_options_json = '{\"topology_role\": \"core\"}' WHERE id = 11")
    run_id = conn.execute("INSERT INTO network_correlation_runs (run_type, started_at, finished_at, status) VALUES ('attachments', ?, ?, 'success')", (now, now)).lastrowid
    conn.execute(
        """INSERT INTO asset_attachment_resolutions (asset_interface_id, asset_id, status, selected_source_id, selected_port_key, selected_vlan_key, confidence, first_seen_at, last_seen_at, correlation_run_id)
           VALUES (1, 1, 'confirmed', 10, 'physical:48', '20', 85, ?, ?, ?)""",
        (now, now, run_id),
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
    conn.commit()
    return conn


def test_inspect_asset_context_has_exact_safe_top_level_contract(tmp_path: Path) -> None:
    from netctl.context_query import inspect_asset_context

    conn = _context_db(tmp_path)
    try:
        result = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")
        assert result is not None
        assert set(result) == {"asset", "intent", "owner", "interfaces", "attachment", "network", "topology_path", "source_health", "findings", "evidence"}
        assert result["owner"] is None
        assert result["asset"]["asset_key"] == "mac:AA:BB:CC:DD:EE:01"
        assert result["network"]["ip_observations"][0]["ip"] == "192.0.2.10"
        assert result["attachment"]["selected_port_key"] == "physical:48"
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
