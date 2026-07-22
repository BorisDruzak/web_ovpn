from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable


class PathVerdict(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PathRequest:
    asset_key: str
    destination_ip: str
    protocol: str
    destination_port: int | None


@dataclass(frozen=True)
class PathExplanation:
    verdict: PathVerdict
    source_asset_key: str
    source_ips: tuple[str, ...]
    enforcement_source: str
    selected_routing_table: str
    selected_route: dict[str, Any] | None
    stages: tuple[dict[str, Any], ...]
    unknown_reasons: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]


def select_source_context(source_ips: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Return the sole current source address, or a conservative ambiguity reason."""
    if len(source_ips) != 1:
        return None, "ambiguous_source_ips"
    try:
        ipaddress.ip_address(source_ips[0])
    except ValueError:
        return None, "invalid_source_ip"
    return source_ips[0], None


def _matches_cidr(value: str, cidr: object) -> bool | None:
    if not cidr:
        return True
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return None


def _rule_value(rule: dict[str, Any], canonical: str, normalized: str) -> object:
    return rule.get(canonical) or rule.get(normalized) or ""


def _matches_address_list(entries: Iterable[dict[str, Any]], list_name: object, address: str) -> bool | None:
    if not list_name:
        return True
    found = False
    for entry in entries:
        if entry.get("disabled") or str(entry.get("list") or "") != str(list_name):
            continue
        found = True
        matched = _matches_cidr(address, entry.get("address"))
        if matched is None:
            return None
        if matched:
            return True
    return False if found else None


def select_route(routes: Iterable[dict[str, Any]], destination_ip: str, routing_table: str) -> dict[str, Any] | None:
    destination = ipaddress.ip_address(destination_ip)
    matches: list[tuple[int, dict[str, Any]]] = []
    for route in routes:
        if not route.get("active") or str(route.get("routing_table") or "main") != routing_table:
            continue
        try:
            network = ipaddress.ip_network(str(route.get("dst_address") or ""), strict=False)
        except ValueError:
            continue
        if destination in network:
            matches.append((network.prefixlen, route))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def select_routing_table(rules: Iterable[dict[str, Any]], source_ip: str) -> str:
    source = ipaddress.ip_address(source_ip)
    for rule in sorted(rules, key=lambda item: int(item.get("position") or 0)):
        if rule.get("disabled") or str(rule.get("action") or "") not in {"lookup", "lookup-only-in-table"}:
            continue
        cidr = str(rule.get("src_cidr") or "")
        if cidr:
            try:
                if source not in ipaddress.ip_network(cidr, strict=False):
                    continue
            except ValueError:
                continue
        if rule.get("table_name"):
            return str(rule["table_name"])
    return "main"


def evaluate_filter(
    rules: Iterable[dict[str, Any]],
    request: PathRequest,
    *,
    source_ip: str,
    address_lists: Iterable[dict[str, Any]] = (),
) -> tuple[PathVerdict | None, str | None]:
    for rule in rules:
        if rule.get("disabled"):
            continue
        chain = str(rule.get("chain") or "forward").lower()
        if chain != "forward":
            continue
        source_match = _matches_cidr(source_ip, _rule_value(rule, "src_cidr", "src_address"))
        destination_match = _matches_cidr(request.destination_ip, _rule_value(rule, "dst_cidr", "dst_address"))
        destination_list_match = _matches_address_list(address_lists, rule.get("dst_address_list"), request.destination_ip)
        source_list_match = _matches_address_list(address_lists, rule.get("src_address_list"), source_ip)
        if False in (source_match, destination_match, destination_list_match, source_list_match):
            continue
        if None in (source_match, destination_match, destination_list_match, source_list_match):
            return PathVerdict.UNKNOWN, "unresolved_filter_address_matcher"
        if rule.get("protocol") and str(rule["protocol"]).lower() != request.protocol.lower():
            continue
        if rule.get("dst_port") and request.destination_port is None:
            return PathVerdict.UNKNOWN, "missing_destination_port"
        if rule.get("dst_port") and str(rule["dst_port"]) != str(request.destination_port):
            continue
        if any(rule.get(field) for field in ("in_interface", "out_interface", "routing_mark", "connection_state")):
            return PathVerdict.UNKNOWN, "unresolved_filter_matcher"
        if rule.get("unsupported_matchers"):
            return PathVerdict.UNKNOWN, "unsupported_filter_matcher"
        action = str(rule.get("action") or "").lower()
        if action in {"drop", "reject"}:
            return PathVerdict.BLOCKED, None
        if action == "accept":
            return PathVerdict.ALLOWED, None
        if action:
            return PathVerdict.UNKNOWN, "unsupported_filter_action"
    return None, None


def explain_nat(
    rules: Iterable[dict[str, Any]],
    request: PathRequest,
    *,
    source_ip: str,
) -> dict[str, Any] | None:
    """Return the first deterministically matching NAT rule without rewriting the flow."""
    for rule in rules:
        if rule.get("disabled"):
            continue
        source_match = _matches_cidr(source_ip, _rule_value(rule, "src_cidr", "src_address"))
        destination_match = _matches_cidr(request.destination_ip, _rule_value(rule, "dst_cidr", "dst_address"))
        if source_match is not True or destination_match is not True:
            continue
        if rule.get("protocol") and str(rule["protocol"]).lower() != request.protocol.lower():
            continue
        if rule.get("dst_port") and str(rule["dst_port"]) != str(request.destination_port):
            continue
        action = str(rule.get("action") or "").lower()
        if action in {"src-nat", "masquerade", "dst-nat", "netmap", "redirect"}:
            return {"stage": "nat", "rule": rule, "translation_verified": False}
    return None


def match_ipsec_policy(policies: Iterable[dict[str, Any]], source_ip: str, destination_ip: str) -> dict[str, Any] | None:
    source = ipaddress.ip_address(source_ip)
    destination = ipaddress.ip_address(destination_ip)
    for policy in policies:
        if policy.get("disabled") or str(policy.get("action") or "").lower() not in {"encrypt", "require"}:
            continue
        try:
            if source in ipaddress.ip_network(str(policy.get("src_cidr") or ""), strict=False) and destination in ipaddress.ip_network(str(policy.get("dst_cidr") or ""), strict=False):
                return policy
        except ValueError:
            continue
    return None


def explain_path(
    request: PathRequest,
    *,
    source_ips: tuple[str, ...],
    routes: Iterable[dict[str, Any]],
    filter_rules: Iterable[dict[str, Any]],
    routing_table: str = "main",
    routing_rules: Iterable[dict[str, Any]] = (),
    ipsec_policies: Iterable[dict[str, Any]] = (),
    nat_rules: Iterable[dict[str, Any]] = (),
    address_lists: Iterable[dict[str, Any]] = (),
    facts_fresh: bool = True,
) -> PathExplanation:
    evidence = ({"scope": "forward_only", "reverse_path_analyzed": False},)
    if not facts_fresh:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "routeros_path_facts", routing_table, None, (), ("stale_path_facts",), evidence)
    source_ip, source_reason = select_source_context(source_ips)
    if source_reason:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "routeros_path_facts", routing_table, None, (), (source_reason,), evidence)
    routing_rule_records = tuple(routing_rules)
    route_records = tuple(routes)
    filter_records = tuple(filter_rules)
    address_list_records = tuple(address_lists)
    routing_table = select_routing_table(routing_rule_records, source_ip) if routing_rule_records else routing_table
    route = select_route(route_records, request.destination_ip, routing_table)
    stages: list[dict[str, Any]] = []
    if route is None:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "routeros_path_facts", routing_table, None, (), ("no_matching_route",), evidence)
    stages.append({"stage": "route", "route": route})
    if str(route.get("route_type") or route.get("type") or "").lower() in {"blackhole", "unreachable", "prohibit"}:
        return PathExplanation(PathVerdict.BLOCKED, request.asset_key, source_ips, "routeros_path_facts", routing_table, route, tuple(stages), (), evidence)
    if (policy := match_ipsec_policy(ipsec_policies, source_ip, request.destination_ip)) is not None:
        stages.append({"stage": "ipsec", "policy": policy})
    verdict, reason = evaluate_filter(filter_records, request, source_ip=source_ip, address_lists=address_list_records)
    if reason:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "routeros_path_facts", routing_table, route, tuple(stages), (reason,), evidence)
    if (nat_stage := explain_nat(nat_rules, request, source_ip=source_ip)) is not None:
        stages.append(nat_stage)
    if verdict is None:
        verdict = PathVerdict.ALLOWED
    return PathExplanation(verdict, request.asset_key, source_ips, "routeros_path_facts", routing_table, route, tuple(stages), (), evidence)
