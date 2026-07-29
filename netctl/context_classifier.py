from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import sqlite3
from typing import Any


Network = ipaddress.IPv4Network | ipaddress.IPv6Network
MIN_AVAILABILITY_PREFIXLEN = 24
MAX_AVAILABILITY_TARGETS = 4096
OBSERVER_CATEGORIES: frozenset[str] = frozenset(
    {
        "local_device",
        "site_device",
        "vpn_client",
        "telephony",
        "mgmt",
        "vipnet_transit",
        "wan",
        "noise",
        "unknown",
    }
)


@dataclass(frozen=True)
class SegmentRule:
    segment_id: str
    network: Network
    observer_category: str
    site: str
    availability_monitoring: bool = False
    availability_tcp_ports: tuple[int, ...] = ()


def load_active_segment_rules(conn: sqlite3.Connection) -> list[SegmentRule]:
    eligible_heads = conn.execute(
        """
        SELECT heads.context_id, heads.context_revision_id
        FROM context_heads AS heads
        WHERE EXISTS (
            SELECT 1
            FROM intent_segments AS candidate_segments
            WHERE candidate_segments.context_revision_id = heads.context_revision_id
              AND candidate_segments.lifecycle = 'active'
        )
        ORDER BY heads.context_id
        """
    ).fetchall()
    if not eligible_heads:
        return []
    if len(eligible_heads) != 1:
        context_ids = ", ".join(str(row["context_id"]) for row in eligible_heads)
        raise ValueError(f"multiple active network contexts: {context_ids}")
    revision_id = int(eligible_heads[0]["context_revision_id"])
    rows = conn.execute(
        """
        SELECT segments.stable_id, segments.canonical_json
        FROM intent_segments AS segments
        WHERE segments.context_revision_id = ?
          AND segments.lifecycle = 'active'
        """,
        (revision_id,),
    ).fetchall()
    rules: list[SegmentRule] = []
    for row in rows:
        segment_id = str(row["stable_id"])
        try:
            value = json.loads(row["canonical_json"])
            if not isinstance(value, dict):
                raise ValueError("canonical_json must contain an object")
            cidr = value.get("cidr")
            if not isinstance(cidr, str) or not cidr.strip():
                raise ValueError("cidr must be a non-empty string")
            availability_monitoring = value.get("availability_monitoring", False)
            if not isinstance(availability_monitoring, bool):
                raise ValueError("availability_monitoring must be a boolean")
            if availability_monitoring and cidr != cidr.strip():
                raise ValueError("availability cidr must be canonical")
            network = ipaddress.ip_network(cidr, strict=False)
            category = value.get("observer_category", "unknown")
            if category not in OBSERVER_CATEGORIES:
                raise ValueError(f"invalid observer_category {category!r}")
            site = value.get("site", "")
            if not isinstance(site, str):
                raise ValueError("site must be a string when present")
            has_availability_tcp_ports = "availability_tcp_ports" in value
            availability_tcp_ports_value = value.get("availability_tcp_ports", [])
            if not isinstance(availability_tcp_ports_value, list):
                raise ValueError("availability_tcp_ports must be a list")
            if not availability_monitoring and has_availability_tcp_ports:
                raise ValueError("availability_tcp_ports requires availability_monitoring to be true")
            if len(availability_tcp_ports_value) > 3:
                raise ValueError("availability_tcp_ports must contain at most 3 ports")
            if any(
                not isinstance(port, int) or isinstance(port, bool)
                for port in availability_tcp_ports_value
            ):
                raise ValueError("availability_tcp_ports must contain integers")
            if any(port < 1 or port > 65535 for port in availability_tcp_ports_value):
                raise ValueError("availability_tcp_ports must contain ports in 1..65535")
            if len(set(availability_tcp_ports_value)) != len(availability_tcp_ports_value):
                raise ValueError("availability_tcp_ports must not contain duplicates")
            if availability_monitoring and network.version != 4:
                raise ValueError("availability monitoring requires an IPv4 cidr")
            if availability_monitoring:
                if cidr != network.with_prefixlen:
                    raise ValueError("availability cidr must be canonical")
                if network.prefixlen < MIN_AVAILABILITY_PREFIXLEN:
                    raise ValueError(
                        f"availability cidr must be at least /{MIN_AVAILABILITY_PREFIXLEN}"
                    )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed active segment {segment_id}: {exc}") from exc
        rules.append(
            SegmentRule(
                segment_id=segment_id,
                network=network,
                observer_category=category,
                site=site,
                availability_monitoring=availability_monitoring,
                availability_tcp_ports=tuple(sorted(availability_tcp_ports_value)),
            )
        )
    return sorted(rules, key=lambda rule: (-rule.network.prefixlen, rule.segment_id))


def load_active_availability_segments(conn: sqlite3.Connection) -> tuple[SegmentRule, ...]:
    rules = load_active_segment_rules(conn)
    monitored = tuple(rule for rule in rules if rule.availability_monitoring)
    target_count = 0
    for index, rule in enumerate(monitored):
        for previous in monitored[:index]:
            if rule.network.overlaps(previous.network):
                raise ValueError("availability cidrs must not overlap")
        target_count += (
            rule.network.num_addresses
            if rule.network.prefixlen >= 31
            else rule.network.num_addresses - 2
        )
        if target_count > MAX_AVAILABILITY_TARGETS:
            raise ValueError(
                f"availability target limit {MAX_AVAILABILITY_TARGETS} exceeded"
            )
    return monitored


def match_segment_rule(ip: str, *, rules: list[SegmentRule]) -> SegmentRule | None:
    address = ipaddress.ip_address(ip)
    matches = [
        rule
        for rule in rules
        if rule.network.version == address.version and address in rule.network
    ]
    if not matches:
        return None
    return min(matches, key=lambda item: (-item.network.prefixlen, item.segment_id))


def classify_address(
    ip: str,
    *,
    rules: list[SegmentRule],
    source: dict[str, Any],
    has_name: bool,
    network_infra: bool,
) -> str:
    address = ipaddress.ip_address(ip)
    source_host = source.get("host")
    if source_host:
        try:
            if address == ipaddress.ip_address(str(source_host)):
                return "router"
        except ValueError:
            pass
    if network_infra:
        return "network_infra"
    rule = match_segment_rule(ip, rules=rules)
    if rule is None:
        return "unknown"
    if rule.observer_category == "local_device" and not has_name:
        return "unknown"
    return rule.observer_category


def legacy_segment_rules() -> list[SegmentRule]:
    """Return the pre-context rules for an explicitly acknowledged compatibility fallback."""
    definitions = (
        ("legacy-central-lan", "192.168.100.0/23", "local_device", "main"),
        ("legacy-vpn-pool", "192.168.50.0/24", "vpn_client", ""),
        ("legacy-remote-site-51", "192.168.51.0/24", "site_device", ""),
        ("legacy-remote-site-52", "192.168.52.0/24", "site_device", ""),
        ("legacy-telephony", "192.168.0.0/24", "telephony", ""),
        ("legacy-mgmt-10", "10.83.1.0/24", "mgmt", ""),
        ("legacy-mgmt-90", "90.99.99.0/30", "mgmt", ""),
        ("legacy-vipnet-transit", "10.254.254.0/30", "vipnet_transit", ""),
        ("legacy-wan-private", "192.168.1.0/24", "wan", ""),
        ("legacy-wan-public", "78.29.0.0/18", "wan", ""),
        ("legacy-link-local-noise", "169.254.0.0/16", "noise", ""),
    )
    return [
        SegmentRule(segment_id, ipaddress.ip_network(cidr), category, site)
        for segment_id, cidr, category, site in definitions
    ]
