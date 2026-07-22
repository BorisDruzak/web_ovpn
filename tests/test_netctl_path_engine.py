from __future__ import annotations


def test_path_engine_selects_longest_prefix_route_in_requested_table() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routing_table="vpn",
        routes=(
            {"routing_table": "vpn", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "active": True},
            {"routing_table": "vpn", "dst_address": "198.51.100.0/24", "gateway": "10.0.0.2", "active": True},
        ),
        filter_rules=(),
    )

    assert result.verdict is PathVerdict.ALLOWED
    assert result.selected_routing_table == "vpn"
    assert result.selected_route == {"routing_table": "vpn", "dst_address": "198.51.100.0/24", "gateway": "10.0.0.2", "active": True}
    assert result.unknown_reasons == ()


def test_path_engine_marks_unsupported_rule_before_decision_as_unknown() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routes=({"routing_table": "main", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "active": True},),
        filter_rules=(
            {"action": "accept", "unsupported_matchers": ["layer7"]},
            {"action": "drop", "protocol": "tcp", "dst_port": "443"},
        ),
    )

    assert result.verdict is PathVerdict.UNKNOWN
    assert result.unknown_reasons == ("unsupported_filter_matcher",)


def test_path_engine_blocks_only_explicit_unreachable_route_when_no_gateway_exists() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "203.0.113.5", "tcp", 443),
        source_ips=("192.0.2.10",),
        routes=({"routing_table": "main", "dst_address": "203.0.113.0/24", "active": True, "type": "blackhole"},),
        filter_rules=(),
    )

    assert result.verdict is PathVerdict.BLOCKED
    assert result.unknown_reasons == ()


def test_path_engine_selects_first_matching_routing_rule_table() -> None:
    from netctl.path_engine import select_routing_table

    assert select_routing_table(
        ({"position": 1, "action": "lookup", "src_cidr": "192.0.2.0/24", "table_name": "vpn"},),
        "192.0.2.10",
    ) == "vpn"


def test_path_engine_uses_routing_rule_before_route_lookup() -> None:
    from netctl.path_engine import PathRequest, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routing_rules=({"position": 1, "action": "lookup", "src_cidr": "192.0.2.0/24", "table_name": "vpn"},),
        routes=({"routing_table": "vpn", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "active": True},),
        filter_rules=(),
    )

    assert result.selected_routing_table == "vpn"


def test_path_engine_records_matching_ipsec_policy_as_tunnel_stage() -> None:
    from netctl.path_engine import PathRequest, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routes=({"routing_table": "main", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "active": True},),
        filter_rules=(),
        ipsec_policies=({"src_cidr": "192.0.2.0/24", "dst_cidr": "198.51.100.0/24", "action": "encrypt"},),
    )

    assert result.stages[-1]["stage"] == "ipsec"
