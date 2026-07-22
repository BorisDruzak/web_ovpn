from __future__ import annotations

from pathlib import Path


PATH_FACT_TABLES = {
    "router_routing_rules",
    "router_address_list_entries",
    "router_filter_rules",
    "router_nat_rules",
    "router_mangle_rules",
    "router_ipsec_policies",
    "router_path_fact_runs",
}


def test_migration_12_creates_read_only_path_fact_schema(tmp_path: Path) -> None:
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'path-facts.sqlite').as_posix()}")
    try:
        tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert PATH_FACT_TABLES <= tables
        assert [int(row[0]) for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")] == list(range(1, 13))
        columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(router_filter_rules)")}
        assert {"source_id", "rule_key", "chain", "position", "disabled", "action", "src_cidr", "dst_cidr", "comment", "observed_at", "collector_run_id", "unsupported_matchers_json"} <= columns
    finally:
        conn.close()


def test_router_rule_model_keeps_only_normalized_match_fields() -> None:
    from netctl.path_models import RouterRule

    rule = RouterRule(
        rule_key="*1", family="filter", chain="forward", position=3, disabled=False, action="accept",
        src_cidr="192.0.2.0/24", dst_cidr="198.51.100.0/24", protocol="tcp", dst_port="443",
        in_interface="bridge", out_interface="wan", src_address_list="", dst_address_list="blocked",
        routing_mark="vpn", connection_state="new", comment="allow app", unsupported_matchers=("layer7",),
    )
    assert rule.unsupported_matchers == ("layer7",)
    assert not hasattr(rule, "raw")


def test_path_fact_collection_replaces_only_successful_fact_families(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.path_facts import save_path_facts

    conn = connect(f"sqlite:///{(tmp_path / 'path-facts.sqlite').as_posix()}")
    now = "2026-07-22T12:00:00Z"
    try:
        source_id = conn.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, enabled, created_at, updated_at)
               VALUES ('router', 'mikrotik_api', '127.0.0.1', 8729, '', 'env:TEST', 0, 0, 1, ?, ?)""",
            (now, now),
        ).lastrowid
        first = save_path_facts(conn, source_id, {
            "firewall_filter_rules": [{"id": "*1", "chain": "forward", "action": "accept", "disabled": False, "src_address": "", "dst_address": "", "protocol": "tcp", "comment": "allow"}],
        }, {"firewall_filter_rules": "success"}, now)
        assert first["status"] == "success"
        assert conn.execute("SELECT action FROM router_filter_rules").fetchone()[0] == "accept"
        second = save_path_facts(conn, source_id, {
            "firewall_filter_rules": [{"id": "*1", "chain": "forward", "action": "drop"}],
        }, {"firewall_filter_rules": "failed"}, "2026-07-22T12:05:00Z")
        assert second["status"] == "failed"
        assert conn.execute("SELECT action FROM router_filter_rules").fetchone()[0] == "accept"
    finally:
        conn.close()


def test_firewall_rule_normalization_keeps_path_match_fields() -> None:
    from netctl.drivers.mikrotik_api import MikroTikApiDriver

    rule = MikroTikApiDriver.normalize_firewall_rule_rows([{
        ".id": "*1", "chain": "forward", "action": "accept", "dst-port": "443",
        "in-interface": "bridge", "out-interface": "wan", "connection-state": "new", "routing-mark": "vpn",
    }], "filter")[0]
    assert {key: rule[key] for key in ("dst_port", "in_interface", "out_interface", "connection_state", "routing_mark")} == {
        "dst_port": "443", "in_interface": "bridge", "out_interface": "wan", "connection_state": "new", "routing_mark": "vpn",
    }


def test_collection_persists_path_facts_only_when_outcomes_are_supplied(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.store import save_collection

    conn = connect(f"sqlite:///{(tmp_path / 'path-facts.sqlite').as_posix()}")
    now = "2026-07-22T12:00:00Z"
    try:
        source_id = conn.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, enabled, created_at, updated_at)
               VALUES ('router', 'mikrotik_api', '127.0.0.1', 8729, '', 'env:TEST', 0, 0, 1, ?, ?)""",
            (now, now),
        ).lastrowid
        save_collection(conn, {"id": source_id, "name": "router"}, {
            "firewall_filter_rules": [{"id": "*1", "chain": "forward", "action": "drop"}],
            "path_fact_outcomes": {"firewall_filter_rules": "success"},
        }, now)
        assert conn.execute("SELECT action FROM router_filter_rules").fetchone()[0] == "drop"
    finally:
        conn.close()


def test_driver_marks_only_collected_path_fact_families_as_successful() -> None:
    from netctl.drivers.mikrotik_api import MikroTikApiDriver

    assert MikroTikApiDriver.path_fact_outcomes({"firewall_filter_rules": []}) == {
        "firewall_filter_rules": "success"
    }


def test_path_facts_store_routing_address_list_and_ipsec_without_raw_fields(tmp_path: Path) -> None:
    from netctl.db import connect
    from netctl.path_facts import save_path_facts

    conn = connect(f"sqlite:///{(tmp_path / 'path-facts.sqlite').as_posix()}")
    now = "2026-07-22T12:00:00Z"
    try:
        source_id = conn.execute(
            """INSERT INTO network_sources (name, driver, host, port, username, secret_ref, tls, verify_tls, enabled, created_at, updated_at)
               VALUES ('router', 'mikrotik_api', '127.0.0.1', 8729, '', 'env:TEST', 0, 0, 1, ?, ?)""",
            (now, now),
        ).lastrowid
        save_path_facts(conn, source_id, {
            "router_routing_rules": [{"id": "*r", "action": "lookup", "table_name": "vpn"}],
            "firewall_address_lists": [{"id": "*a", "list": "blocked", "address": "203.0.113.0/24"}],
            "ipsec_policies": [{"id": "*p", "src_address": "192.0.2.0/24", "dst_address": "198.51.100.0/24", "action": "encrypt"}],
        }, {
            "router_routing_rules": "success", "firewall_address_lists": "success", "ipsec_policies": "success",
        }, now)
        assert conn.execute("SELECT table_name FROM router_routing_rules").fetchone()[0] == "vpn"
        assert tuple(conn.execute("SELECT list_name, address FROM router_address_list_entries").fetchone()) == ("blocked", "203.0.113.0/24")
        assert tuple(conn.execute("SELECT src_cidr, dst_cidr FROM router_ipsec_policies").fetchone()) == ("192.0.2.0/24", "198.51.100.0/24")
    finally:
        conn.close()


def test_driver_normalizes_routing_and_ipsec_policy_facts_without_raw_properties() -> None:
    from netctl.drivers.mikrotik_api import MikroTikApiDriver

    routing = MikroTikApiDriver.normalize_routing_rule_rows([{".id": "*r", "action": "lookup", "table": "vpn", "priority": "5"}])[0]
    ipsec = MikroTikApiDriver.normalize_path_ipsec_policy_rows([{".id": "*p", "src-address": "192.0.2.0/24", "dst-address": "198.51.100.0/24", "action": "encrypt", "proposal": "private"}])[0]
    assert routing == {"id": "*r", "position": 5, "disabled": False, "action": "lookup", "src_address": "", "dst_address": "", "routing_mark": "", "table_name": "vpn", "comment": ""}
    assert ipsec == {"id": "*p", "position": 0, "disabled": False, "action": "encrypt", "src_address": "192.0.2.0/24", "dst_address": "198.51.100.0/24", "protocol": "", "comment": ""}
