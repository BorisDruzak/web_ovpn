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
        [(10, 'access-a', now, now), (20, 'distribution-a', now, now), (30, 'core-a', now, now)],
    )
    conn.execute("UPDATE network_sources SET site = 'central' WHERE id IN (10, 20, 30)")
    conn.execute("UPDATE network_sources SET host = '192.0.2.10' WHERE id = 10")
    collection_run_id = conn.execute(
        """INSERT INTO switch_collection_runs
           (source_id, started_at, finished_at, status, error_class, error_message, outcomes_json)
           VALUES (10, ?, ?, 'failed', 'TimeoutError', 'private transport detail', '{}')""",
        (now, now),
    ).lastrowid
    conn.execute("UPDATE network_sources SET driver_options_json = '{\"topology_role\": \"core\"}' WHERE id = 30")
    run_id = conn.execute(
        """INSERT INTO network_correlation_runs
           (run_type, started_at, finished_at, status, source_watermark_json)
           VALUES ('attachments', ?, ?, 'success', '{\"access-a\":\"2026-07-26T10:00:00Z\"}')""",
        ("2026-07-26T10:05:00Z", "2026-07-26T10:05:00Z"),
    ).lastrowid
    conn.execute(
        """INSERT INTO asset_attachment_resolutions (asset_interface_id, asset_id, status, selected_source_id, selected_port_key, selected_vlan_key, selected_vlan_id, confidence, first_seen_at, last_seen_at, correlation_run_id)
           VALUES (1, 1, 'confirmed', 10, 'physical:7', '20', 20, 85, ?, ?, ?)""",
        (now, now, run_id),
    )
    conn.executemany(
        """INSERT INTO switch_ports (source_id, port_key, name, alias, oper_status, last_seen_at, collector_run_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [
            (10, "physical:7", "ether7", "Office 12", "up", now, collection_run_id),
            (10, "physical:49", "ether49", "", "up", now, collection_run_id),
        ],
    )
    conn.execute(
        """INSERT INTO current_switch_vlan_memberships
           (source_id, vlan_id, port_key, port_name, egress, untagged, pvid, observed_at, collector_run_id)
           VALUES (10, 20, 'physical:7', 'ether7', 1, 1, 1, ?, ?)""",
        (now, collection_run_id),
    )
    conn.executemany(
        """INSERT INTO current_switch_fdb
           (source_id, vlan_key, vlan_id, mac, port_key, status, first_seen_at, last_seen_at, collector_run_id)
           VALUES (10, '20', 20, ?, 'physical:7', 'learned', ?, ?, ?)""",
        [
            ("aa:bb:cc:dd:ee:01", now, now, collection_run_id),
            ("AA-BB-CC-DD-EE-02", now, now, collection_run_id),
            ("AA:BB:CC:DD:EE:03", now, now, collection_run_id),
        ],
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
           VALUES ('10:uplink|20:downlink', 10, 'physical:49', 20, 'physical:1', 'confirmed', 100, ?, ?, ?)""",
        (now, now, topology_run),
    )
    conn.execute(
        """INSERT INTO current_switch_links (link_key, source_a_id, port_a_key, source_b_id, port_b_key, state, confidence, first_seen_at, last_seen_at, correlation_run_id)
           VALUES ('20:uplink|30:core', 20, 'physical:2', 30, 'physical:1', 'confirmed', 95, ?, ?, ?)""",
        (now, now, topology_run),
    )
    conn.execute(
        """INSERT INTO asset_attachment_events
           (asset_interface_id, asset_id, event_type, before_json, after_json, observed_at, correlation_run_id)
           VALUES (1, 1, 'attached', '{\"status\":\"unresolved\",\"evidence\":\"private\"}',
                   '{\"status\":\"confirmed\",\"selected_source_id\":10,\"selected_port_key\":\"physical:7\",\"selected_vlan_key\":\"20\",\"selected_vlan_id\":20,\"confidence\":85,\"evidence\":\"private\"}',
                   '2026-07-26T10:05:00Z', ?)""",
        (run_id,),
    )
    conn.execute(
        """INSERT INTO asset_attachment_events
           (asset_interface_id, asset_id, event_type, before_json, after_json, observed_at, correlation_run_id)
           VALUES (1, 1, 'moved', '{}', '{}', '2026-06-25T10:05:00Z', ?)""",
        (run_id,),
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
        assert set(result) == {"asset", "intent", "owner", "interfaces", "attachment", "network", "topology_path", "attachment_events", "freshness", "source_health", "findings", "evidence"}
        assert result["owner"] == {"status": "none", "bindings": []}
        assert result["asset"]["asset_key"] == "mac:AA:BB:CC:DD:EE:01"
        assert result["network"]["ip_observations"][0]["ip"] == "192.0.2.10"
        assert result["attachment"]["selected_port_key"] == "physical:7"
        assert result["attachment"]["alternatives"] == [
            {"source": "access-a", "port_key": "physical:47", "vlan_key": "20", "vlan_id": None, "candidate_class": "direct", "topology_depth": None, "score": 80, "observed_at": "2026-07-22T12:00:00Z"}
        ]
        assert result["topology_path"]["nodes"] == [10, 20, 30]
        assert result["topology_path"]["complete"] is True
        assert result["topology_path"]["reason"] == ""
        assert result["intent"]["intent_stable_id"] == "device:workstation-01"
        assert [item["source"] for item in result["source_health"]] == ["access-a", "core-a", "distribution-a"]
    finally:
        conn.close()


def test_inspect_asset_context_enriches_confirmed_attachment(tmp_path: Path) -> None:
    """Fails if a confirmed resolution omits joined safe network metadata."""
    from netctl.context_query import inspect_asset_context

    conn = _context_db(tmp_path)
    try:
        context = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")

        assert context is not None
        assert context["attachment"]["status"] == "confirmed"
        assert context["attachment"]["switch"] == {
            "id": 10, "name": "access-a", "site": "central", "host": "192.0.2.10",
        }
        assert context["attachment"]["port"]["alias"] == "Office 12"
        assert context["attachment"]["port"]["oper_status"] == "up"
        assert context["attachment"]["vlan_membership"] == {
            "vlan_id": 20, "egress": True, "untagged": True, "pvid": True,
        }
        assert context["attachment"]["port_peers"]["known_asset_count"] == 1
        assert context["attachment"]["port_peers"]["unknown_mac_count"] == 1
        assert context["attachment"]["port_peers"]["items"][0]["asset"]["asset_key"] == "mac:AA:BB:CC:DD:EE:02"
    finally:
        conn.close()


def test_inspect_asset_context_preserves_uncertain_attachment_states(tmp_path: Path) -> None:
    from netctl.context_query import inspect_asset_context

    conn = _context_db(tmp_path)
    try:
        conn.execute("UPDATE asset_attachment_resolutions SET status = 'ambiguous'")
        ambiguous = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")
        assert ambiguous is not None
        assert ambiguous["attachment"]["port"] is None
        assert ambiguous["attachment"]["port_peers"] is None

        conn.execute("UPDATE asset_attachment_resolutions SET status = 'uplink_only'")
        uplink_only = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")
        assert uplink_only is not None
        assert uplink_only["attachment"]["switch"] is None

        conn.execute("UPDATE asset_attachment_resolutions SET status = 'unresolved'")
        conn.execute("DELETE FROM asset_attachment_candidates")
        unresolved = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")
        assert unresolved is not None
        assert unresolved["attachment"]["alternatives"] == []
    finally:
        conn.close()


def test_inspect_asset_context_bounds_confirmed_port_peers(tmp_path: Path) -> None:
    from netctl.context_query import inspect_asset_context

    conn = _context_db(tmp_path)
    now = "2026-07-26T10:05:00Z"
    try:
        collection_run_id = conn.execute(
            "SELECT id FROM switch_collection_runs WHERE source_id = 10"
        ).fetchone()[0]
        for asset_id in range(3, 36):
            mac = f"AA:BB:CC:00:00:{asset_id:02X}"
            conn.execute(
                """INSERT INTO assets (id, asset_key, identity_method, identity_confidence, provisional,
                    first_seen_at, last_seen_at, created_at, updated_at)
                   VALUES (?, ?, 'manual', 100, 0, ?, ?, ?, ?)""",
                (asset_id, f"mac:{mac}", now, now, now, now),
            )
            conn.execute(
                """INSERT INTO asset_interfaces (asset_id, interface_key, mac, first_seen_at, last_seen_at)
                   VALUES (?, 'eth0', ?, ?, ?)""",
                (asset_id, mac.replace(":", "-"), now, now),
            )
            conn.execute(
                """INSERT INTO current_switch_fdb
                   (source_id, vlan_key, vlan_id, mac, port_key, status, first_seen_at, last_seen_at, collector_run_id)
                   VALUES (10, '20', 20, ?, 'physical:7', 'learned', ?, ?, ?)""",
                (mac, now, now, collection_run_id),
            )
        confirmed = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")
        assert confirmed is not None
        assert len(confirmed["attachment"]["port_peers"]["items"]) == 32
        assert confirmed["attachment"]["port_peers"]["truncated"] is True
    finally:
        conn.close()


def test_inspect_asset_context_returns_named_path_history_and_freshness(tmp_path: Path) -> None:
    """Fails if path edges, recent attachment history, or run freshness are omitted."""
    from netctl.context_query import inspect_asset_context

    conn = _context_db(tmp_path)
    try:
        context = inspect_asset_context(conn, "mac:AA:BB:CC:DD:EE:01")

        assert context is not None
        assert context["topology_path"]["nodes"] == [10, 20, 30]
        assert context["topology_path"]["hops"][0]["from"]["name"] == "access-a"
        assert context["topology_path"]["hops"][0]["to"]["name"] == "distribution-a"
        assert len(context["attachment_events"]) == 1
        assert context["attachment_events"][0]["after"] == {
            "status": "confirmed", "selected_source_id": 10, "selected_port_key": "physical:7",
            "selected_vlan_key": "20", "selected_vlan_id": 20, "confidence": 85,
        }
        assert context["freshness"]["attachment_reconciled_at"] == "2026-07-26T10:05:00Z"
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
        assert len(result["interfaces"]) == 1
        interface = result["interfaces"][0]
        assert {key: interface[key] for key in ("interface_key", "mac", "interface_type", "interface_name", "lifecycle")} == {
            "interface_key": "eth0", "mac": "aa-bb-cc-dd-ee-01", "interface_type": "",
            "interface_name": "", "lifecycle": "active",
        }
        assert interface["attachment"]["selected_port_key"] == "physical:7"
        assert interface["attachment"]["selected_vlan_id"] == 20
        assert interface["attachment"]["alternatives"] == [{
            "source": "access-a", "port_key": "physical:47", "vlan_key": "20", "vlan_id": None,
            "candidate_class": "direct", "topology_depth": None, "score": 80,
            "observed_at": "2026-07-22T12:00:00Z",
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
    assert result["links"][0]["link_key"] == "10:uplink|20:downlink"
    assert result["depth"] == 4
    assert result["max_nodes"] == 250
    assert result["truncated"] is False


def test_context_topology_declares_node_bound_truncation(tmp_path: Path) -> None:
    from netctl.context_query import topology_context

    conn = _context_db(tmp_path)
    try:
        result = topology_context(conn, max_nodes=1)
        assert result == {
            "links": [], "max_nodes": 1, "node_count": 0,
            "truncated": True, "truncation_reason": "max_nodes",
        }
    finally:
        conn.close()


def test_context_topology_depth_limits_the_graph_to_hops_from_a_core_source(tmp_path: Path) -> None:
    from netctl.context_query import topology_context

    conn = _context_db(tmp_path)
    now = "2026-07-22T12:00:00Z"
    try:
        conn.executemany(
            """INSERT INTO network_sources (id, name, driver, host, port, username, secret_ref, tls, verify_tls, enabled, created_at, updated_at, site)
               VALUES (?, ?, 'snmp_switch', '127.0.0.1', 161, '', 'env:TEST', 0, 0, 1, ?, ?, 'central')""",
            [(12, "distribution", now, now), (13, "edge", now, now)],
        )
        topology_run = conn.execute(
            "INSERT INTO network_correlation_runs (run_type, started_at, finished_at, status) VALUES ('topology', ?, ?, 'success')",
            (now, now),
        ).lastrowid
        conn.executemany(
            """INSERT INTO current_switch_links (link_key, source_a_id, port_a_key, source_b_id, port_b_key, state, confidence, first_seen_at, last_seen_at, correlation_run_id)
               VALUES (?, ?, '', ?, '', 'confirmed', 100, ?, ?, ?)""",
            [
                    ("12:distribution|30:core", 12, 30, now, now, topology_run),
                ("12:distribution|13:edge", 12, 13, now, now, topology_run),
            ],
        )
        conn.commit()

        result = topology_context(conn, depth=1)

        assert [link["link_key"] for link in result["links"]] == ["12:distribution|30:core", "20:uplink|30:core"]
        assert result["truncated"] is True
        assert result["truncation_reason"] == "depth"
    finally:
        conn.close()


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
        assert failure["details"] == {"source": "access-a", "error_class": "TimeoutError"}
    finally:
        conn.close()


def test_context_snapshot_declares_active_revision_and_successful_correlation_runs(tmp_path: Path) -> None:
    from netctl.context_query import context_snapshot

    conn = _context_db(tmp_path)
    try:
        assert context_snapshot(conn) == {
            "context_revision_id": None,
            "topology_correlation_run_id": 2,
            "attachment_correlation_run_id": 1,
            "observation_cutoff": "2026-07-22T12:00:00Z",
        }
    finally:
        conn.close()
