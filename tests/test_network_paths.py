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
        "runtime": {
            "overall": "ok",
            "sections": {"openvpn": {"service_active": True, "server_network": "198.51.100.0/24"}},
        },
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


def test_path_is_not_ok_when_openvpn_pool_evidence_is_absent():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=all_evidence_rows(),
        runtime={"overall": "ok", "sections": {"openvpn": {"service_active": True}}},
    ))

    assert result[0]["status"] == "critical"
    assert check(result[0], "openvpn")["status"] == "critical"


def test_source_less_route_does_not_match_configured_router():
    from app.network_paths import evaluate_paths

    row = router_rows()
    row["routes"][0].pop("source")
    result = evaluate_paths(**inputs(router_rows=row))

    assert check(result[0], "return_route")["status"] == "critical"


def test_source_less_address_list_does_not_match_configured_router():
    from app.network_paths import evaluate_paths

    row = all_evidence_rows()
    row["address_lists"][0].pop("source")
    result = evaluate_paths(**inputs(definitions={"directum": full_definition()}, router_rows=row))

    assert check(result[0], "address_list:1")["status"] == "critical"


def test_source_less_policy_does_not_match_configured_router():
    from app.network_paths import evaluate_paths

    row = all_evidence_rows()
    row["firewall_rules"][0].pop("source")
    result = evaluate_paths(**inputs(definitions={"directum": full_definition()}, router_rows=row))

    assert check(result[0], "policy:1")["status"] == "critical"


def test_malformed_router_row_collections_are_safe_and_not_ok():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=router_rows(routes=1, address_lists="invalid", firewall_rules={"invalid": True}),
    ))

    assert result[0]["status"] != "ok"


def test_missing_router_source_timestamp_is_not_ok_with_fresh_row_evidence():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=all_evidence_rows(sources=[{"source": "router-a", "status": "ok"}]),
    ))

    assert result[0]["status"] != "ok"
    assert check(result[0], "router_source")["status"] in {"stale", "unknown"}


def test_malformed_router_matcher_attribute_is_non_matching_and_safe():
    from app.network_paths import evaluate_paths

    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=all_evidence_rows(firewall_rules=[policy_rule(dst_address=1)]),
    ))

    assert check(result[0], "policy:1")["status"] == "critical"


def test_path_policy_and_address_list_must_bind_openvpn_pool_to_target_cidr():
    from app.network_paths import evaluate_paths

    unrelated_matcher = {
        "table": "filter",
        "chain": "forward",
        "action": "accept",
        "src_address": "192.0.2.0/24",
        "dst_address": "192.0.3.0/24",
    }
    unrelated_address_list = {"list": "unrelated", "address": "192.0.3.0/24"}
    result = evaluate_paths(**inputs(
        definitions={
            "directum": full_definition(
                address_lists=(unrelated_address_list,),
                policy_matchers=(unrelated_matcher,),
            )
        },
        router_rows=router_rows(
            address_lists=[address_list(list="unrelated", address="192.0.3.0/24")],
            firewall_rules=[
                policy_rule(
                    src_address="192.0.2.0/24",
                    dst_address="192.0.3.0/24",
                    comment="unrelated policy",
                )
            ],
        ),
    ))

    assert result[0]["status"] == "critical"
    assert check(result[0], "address_list:1")["status"] == "critical"
    assert check(result[0], "policy:1")["status"] == "critical"


@pytest.mark.parametrize("evidence", ["router", "server_health"])
def test_materially_future_path_evidence_is_stale(evidence):
    from app.network_paths import evaluate_paths

    future = "2026-07-21T18:10:00Z"
    values = inputs(definitions={"directum": full_definition()}, router_rows=all_evidence_rows())
    if evidence == "router":
        values["router_rows"]["sources"][0]["collected_at"] = future
        for collection in ("routes", "address_lists", "firewall_rules"):
            values["router_rows"][collection][0]["last_seen_at"] = future
    else:
        values["server_health"]["collected_at"] = future

    result = evaluate_paths(**values)

    assert result[0]["status"] == "stale"
    assert check(result[0], "router_source" if evidence == "router" else "server_health")["status"] == "stale"


def test_matching_server_target_status_is_not_overridden_by_unrelated_aggregate_error():
    from app.network_paths import evaluate_paths

    server_health = {
        "collected_at": "2026-07-21T17:55:00Z",
        "overall": "error",
        "targets": [
            {"role": "directum", "status": "ok"},
            {"role": "file_server", "status": "error"},
        ],
    }
    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=all_evidence_rows(),
        server_health=server_health,
    ))

    assert check(result[0], "server_health")["status"] == "ok"
    assert result[0]["status"] == "ok"


def test_path_evidence_time_is_oldest_contributing_timestamp():
    from app.network_paths import evaluate_paths

    rows = all_evidence_rows()
    rows["sources"][0]["collected_at"] = "2026-07-21T17:58:00Z"
    rows["routes"][0]["last_seen_at"] = "2026-07-21T17:57:00Z"
    rows["address_lists"][0]["last_seen_at"] = "2026-07-21T17:56:00Z"
    rows["firewall_rules"][0]["last_seen_at"] = "2026-07-21T17:55:00Z"
    result = evaluate_paths(**inputs(
        definitions={"directum": full_definition()},
        router_rows=rows,
        server_health={
            "collected_at": "2026-07-21T17:59:00Z",
            "targets": [{"role": "directum", "status": "ok"}],
        },
    ))

    assert result[0]["collected_at"] == "2026-07-21T17:55:00Z"


def test_role_registry_accepts_only_unique_allowlisted_role_names(tmp_path):
    from app.network_paths import load_role_registry

    registry = tmp_path / "server-roles.json"
    registry.write_text(json.dumps({"roles": ["directum"]}), encoding="utf-8")
    assert load_role_registry(registry) == {"directum"}

    registry.write_text(json.dumps({"roles": ["directum", "directum"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="unique"):
        load_role_registry(registry)

    registry.write_text(json.dumps({"roles": ["unregistered"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="allowed"):
        load_role_registry(registry)


@pytest.mark.parametrize("timestamp", ["2026-07-21T18:10:00Z", "corrupt"])
def test_update_posture_summary_never_marks_future_or_corrupt_cli_evidence_fresh(timestamp):
    from app.network_paths import update_posture_summary

    summary = update_posture_summary(
        "router-a",
        {
            "status": "ok",
            "sources": [{"source": "router-a", "status": "ok", "collected_at": timestamp}],
            "update_posture": [
                {
                    "source": "router-a",
                    "channel": "stable",
                    "installed_version": "7.19.4",
                    "routerboot_current_version": "7.19.4",
                    "routerboot_upgrade_version": "7.20.1",
                    "last_seen_at": timestamp,
                    "schedulers": [],
                    "raw_output": "must-not-escape",
                }
            ],
        },
        parse_utc("2026-07-21T18:00:00Z"),
    )

    assert summary["status"] == "stale"
    assert summary["freshness"] == "stale"
    assert summary["collected_at"] == ""
    assert "must-not-escape" not in json.dumps(summary)


def test_missing_update_posture_summary_is_unknown():
    from app.network_paths import update_posture_summary

    summary = update_posture_summary(
        "router-a", {}, parse_utc("2026-07-21T18:00:00Z")
    )

    assert summary["status"] == "unknown"
    assert summary["freshness"] == "unknown"


def test_update_posture_summary_rejects_future_source_timestamp_with_fresh_row():
    from app.network_paths import update_posture_summary

    summary = update_posture_summary(
        "router-a",
        {
            "status": "ok",
            "sources": [
                {"source": "router-a", "status": "ok", "collected_at": "2026-07-21T18:10:00Z"}
            ],
            "update_posture": [
                {
                    "source": "router-a",
                    "channel": "stable",
                    "installed_version": "7.19.4",
                    "routerboot_current_version": "7.19.4",
                    "routerboot_upgrade_version": "7.20.1",
                    "last_seen_at": "2026-07-21T17:55:00Z",
                    "schedulers": [],
                }
            ],
        },
        parse_utc("2026-07-21T18:00:00Z"),
    )

    assert summary["status"] == "stale"
    assert summary["freshness"] == "stale"
    assert summary["collected_at"] == ""
