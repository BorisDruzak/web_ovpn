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


def evaluate_filter(rules: Iterable[dict[str, Any]], request: PathRequest) -> tuple[PathVerdict | None, str | None]:
    for rule in rules:
        if rule.get("disabled"):
            continue
        if rule.get("unsupported_matchers"):
            return PathVerdict.UNKNOWN, "unsupported_filter_matcher"
        if rule.get("protocol") and str(rule["protocol"]).lower() != request.protocol.lower():
            continue
        if rule.get("dst_port") and request.destination_port is not None and str(rule["dst_port"]) != str(request.destination_port):
            continue
        action = str(rule.get("action") or "").lower()
        if action in {"drop", "reject"}:
            return PathVerdict.BLOCKED, None
        if action == "accept":
            return PathVerdict.ALLOWED, None
    return None, None


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
    facts_fresh: bool = True,
) -> PathExplanation:
    if not facts_fresh:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "", routing_table, None, (), ("stale_path_facts",), ())
    if len(source_ips) != 1:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "", routing_table, None, (), ("ambiguous_source_ips",), ())
    if source_ips:
        routing_table = select_routing_table(routing_rules, source_ips[0]) if tuple(routing_rules) else routing_table
    route = select_route(routes, request.destination_ip, routing_table)
    stages: list[dict[str, Any]] = []
    if route is None:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "", routing_table, None, (), ("no_matching_route",), ())
    stages.append({"stage": "route", "route": route})
    if str(route.get("type") or "").lower() in {"blackhole", "unreachable", "prohibit"}:
        return PathExplanation(PathVerdict.BLOCKED, request.asset_key, source_ips, "", routing_table, route, tuple(stages), (), ())
    if source_ips and (policy := match_ipsec_policy(ipsec_policies, source_ips[0], request.destination_ip)) is not None:
        stages.append({"stage": "ipsec", "policy": policy})
    verdict, reason = evaluate_filter(filter_rules, request)
    if reason:
        return PathExplanation(PathVerdict.UNKNOWN, request.asset_key, source_ips, "", routing_table, route, tuple(stages), (reason,), ())
    if verdict is None:
        verdict = PathVerdict.ALLOWED
    return PathExplanation(verdict, request.asset_key, source_ips, "", routing_table, route, tuple(stages), (), ())
