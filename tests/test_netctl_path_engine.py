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


def test_path_engine_rejects_ambiguous_source_ip_context() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10", "192.0.3.10"),
        routes=(),
        filter_rules=(),
    )

    assert result.verdict is PathVerdict.UNKNOWN
    assert result.unknown_reasons == ("ambiguous_source_ips",)


def test_path_engine_rejects_stale_facts() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routes=(),
        filter_rules=(),
        facts_fresh=False,
    )

    assert result.verdict is PathVerdict.UNKNOWN
    assert result.unknown_reasons == ("stale_path_facts",)


def test_path_engine_blocks_ordered_matching_filter_drop() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routes=({"routing_table": "main", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "active": True},),
        filter_rules=({"action": "drop", "protocol": "tcp", "dst_port": "443"},),
    )

    assert result.verdict is PathVerdict.BLOCKED


def test_path_engine_ignores_unsupported_rule_when_known_matchers_do_not_match() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routes=({"routing_table": "main", "dst_address": "0.0.0.0/0", "active": True},),
        filter_rules=(
            {"action": "drop", "protocol": "udp", "unsupported_matchers": ["layer7"]},
            {"action": "drop", "protocol": "tcp", "dst_port": "443"},
        ),
    )

    assert result.verdict is PathVerdict.BLOCKED


def test_path_engine_matches_destination_address_list_without_blocking_internal_destination() -> None:
    from netctl.path_engine import PathRequest, PathVerdict, explain_path

    shared = {
        "source_ips": ("192.0.2.10",),
        "routes": ({"routing_table": "main", "dst_address": "0.0.0.0/0", "active": True},),
        "filter_rules": ({"action": "drop", "dst_address_list": "wan-deny"},),
        "address_lists": ({"list": "wan-deny", "address": "198.51.100.0/24"},),
    }

    internet = explain_path(PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443), **shared)
    internal = explain_path(PathRequest("mac:AA:BB:CC:DD:EE:FF", "10.0.0.25", "tcp", 443), **shared)

    assert internet.verdict is PathVerdict.BLOCKED
    assert internal.verdict is PathVerdict.ALLOWED


def test_path_engine_records_nat_as_a_forward_only_stage() -> None:
    from netctl.path_engine import PathRequest, explain_path

    result = explain_path(
        PathRequest("mac:AA:BB:CC:DD:EE:FF", "198.51.100.25", "tcp", 443),
        source_ips=("192.0.2.10",),
        routes=({"routing_table": "main", "dst_address": "0.0.0.0/0", "active": True},),
        filter_rules=(),
        nat_rules=({"action": "dst-nat", "dst_address": "198.51.100.0/24", "protocol": "tcp", "dst_port": "443"},),
    )

    assert result.stages[-1]["stage"] == "nat"
    assert result.evidence == ({"scope": "forward_only", "reverse_path_analyzed": False},)


def test_select_source_context_requires_exactly_one_current_address() -> None:
    from netctl.path_engine import select_source_context

    assert select_source_context(("192.0.2.10",)) == ("192.0.2.10", None)
    assert select_source_context(()) == (None, "ambiguous_source_ips")
    assert select_source_context(("192.0.2.10", "192.0.3.10")) == (None, "ambiguous_source_ips")
