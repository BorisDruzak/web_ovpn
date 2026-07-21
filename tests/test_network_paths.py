import json

import pytest

from app.server_observer import parse_utc


def definition(role, **overrides):
    from app.network_paths import PathDefinition

    values = {
        "role": role,
        "router_source": "router-a",
        "openvpn_pool": "198.51.100.0/24",
        "target_cidr": "203.0.113.0/24",
        "return_route": {"dst_address": "198.51.100.0/24", "gateway": "198.51.100.1"},
        "address_lists": (),
        "policy_matchers": (),
    }
    values.update(overrides)
    return PathDefinition(**values)


def router_rows(**overrides):
    values = {
        "sources": [{"source": "router-a", "status": "ok", "collected_at": "2026-07-21T17:55:00Z"}],
        "routes": [
            {
                "source": "router-a",
                "dst_address": "198.51.100.0/24",
                "gateway": "198.51.100.1",
                "active": True,
                "disabled": False,
                "last_seen_at": "2026-07-21T17:55:00Z",
            }
        ],
        "address_lists": [],
        "firewall_rules": [],
    }
    values.update(overrides)
    return values


def inputs(role="directum", **overrides):
    values = {
        "definitions": {role: definition(role)},
        "runtime": {"overall": "ok", "sections": {"openvpn": {"service_active": True}}},
        "collector": {"enabled": True, "active": True},
        "router_rows": router_rows(),
        "server_health": {
            "collected_at": "2026-07-21T17:55:00Z",
            "targets": [{"role": role, "status": "ok"}],
        },
        "now": parse_utc("2026-07-21T18:00:00Z"),
    }
    values.update(overrides)
    return values


def policy_matcher():
    return {
        "table": "filter",
        "chain": "forward",
        "action": "accept",
        "src_address": "198.51.100.0/24",
        "dst_address": "203.0.113.0/24",
        "comment_contains": "vpn",
    }


def policy_rule(**overrides):
    values = {
        **policy_matcher(),
        "source": "router-a",
        "disabled": False,
        "packets": 8,
        "bytes": 800,
        "last_seen_at": "2026-07-21T17:55:00Z",
        "comment": "VPN target policy",
    }
    values.update(overrides)
    return values


def address_list(**overrides):
    values = {
        "source": "router-a",
        "list": "vpn-targets",
        "address": "203.0.113.0/24",
        "disabled": False,
        "last_seen_at": "2026-07-21T17:55:00Z",
    }
    values.update(overrides)
    return values


def expected_address_list():
    return {"list": "vpn-targets", "address": "203.0.113.0/24"}


def full_definition(role="directum", **overrides):
    values = {
        "address_lists": (expected_address_list(),),
        "policy_matchers": (policy_matcher(),),
    }
    values.update(overrides)
    return definition(role, **values)


def all_evidence_rows(**overrides):
    values = router_rows(address_lists=[address_list()], firewall_rules=[policy_rule()])
    values.update(overrides)
    return values


def config(role="directum"):
    return {
        "paths": [
            {
                "role": role,
                "router_source": "router-a",
                "openvpn_pool": "198.51.100.0/24",
                "target_cidr": "203.0.113.0/24",
                "return_route": {"dst_address": "198.51.100.0/24", "gateway": "198.51.100.1"},
                "address_lists": [expected_address_list()],
                "policy_matchers": [policy_matcher()],
            }
        ]
    }


def check(row, name):
    return next(item for item in row["checks"] if item["name"] == name)


def test_path_is_critical_when_expected_return_route_is_absent():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(
        definitions={"directum": definition("directum")},
        runtime={"overall": "ok", "sections": {"openvpn": {"service_active": True}}},
        collector={"enabled": True, "active": True},
        router_rows={"routes": []},
        server_health={"targets": [{"role": "directum", "status": "ok"}]},
        now=parse_utc("2026-07-21T18:00:00Z"),
    )

    assert result[0]["status"] == "critical"
    assert check(result[0], "return_route")["status"] == "critical"


def test_path_is_critical_when_a_matching_policy_rule_is_disabled():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=all_evidence_rows(firewall_rules=[policy_rule(disabled=True)]),
    ))

    assert result[0]["status"] == "critical"
    assert check(result[0], "policy:1")["status"] == "critical"


def test_path_is_critical_when_required_address_list_membership_is_missing():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=all_evidence_rows(address_lists=[]),
    ))

    assert result[0]["status"] == "critical"
    assert check(result[0], "address_list:1")["status"] == "critical"


def test_path_warns_when_matching_policy_counter_is_zero():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=all_evidence_rows(firewall_rules=[policy_rule(packets=0, bytes=0)]),
    ))

    assert result[0]["status"] == "warn"
    assert check(result[0], "policy:1")["status"] == "warn"


def test_path_is_unknown_without_a_configured_policy_matcher():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(definitions={"directum": definition("directum")}))

    assert result[0]["status"] == "unknown"
    assert check(result[0], "policy")["status"] == "unknown"


def test_stale_router_evidence_overrides_positive_route_evidence():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": definition("directum")},
        router_rows=router_rows(sources=[{"source": "router-a", "status": "stale", "collected_at": "2026-07-21T17:00:00Z"}]),
    ))

    assert result[0]["status"] == "stale"
    assert check(result[0], "return_route")["status"] == "stale"


def test_stale_server_health_evidence_overrides_target_ok_status():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(server_health={
        "collected_at": "2026-07-21T17:00:00Z",
        "targets": [{"role": "directum", "status": "ok"}],
    }))

    assert result[0]["status"] == "stale"
    assert check(result[0], "server_health")["status"] == "stale"


def test_inactive_collector_timer_overrides_positive_router_evidence():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(collector={"enabled": True, "active": False}))

    assert result[0]["status"] == "error"
    assert check(result[0], "collector")["status"] == "error"


def test_load_path_config_rejects_unregistered_role(tmp_path):
    from app.network_paths import load_path_config

    path = tmp_path / "network-paths.json"
    path.write_text(json.dumps(config("unregistered")), encoding="utf-8")

    with pytest.raises(ValueError, match="registered"):
        load_path_config(path, {"directum"})
