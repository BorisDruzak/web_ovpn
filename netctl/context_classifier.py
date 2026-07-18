from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import sqlite3
from typing import Any


Network = ipaddress.IPv4Network | ipaddress.IPv6Network
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


def load_active_segment_rules(conn: sqlite3.Connection) -> list[SegmentRule]:
    rows = conn.execute(
        """
        SELECT segments.stable_id, segments.canonical_json
        FROM context_heads AS heads
        JOIN intent_segments AS segments
          ON segments.context_revision_id = heads.context_revision_id
        WHERE segments.lifecycle = 'active'
        """
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
            network = ipaddress.ip_network(cidr, strict=False)
            category = value.get("observer_category", "unknown")
            if category not in OBSERVER_CATEGORIES:
                raise ValueError(f"invalid observer_category {category!r}")
            site = value.get("site", "")
            if not isinstance(site, str):
                raise ValueError("site must be a string when present")
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed active segment {segment_id}: {exc}") from exc
        rules.append(
            SegmentRule(
                segment_id=segment_id,
                network=network,
                observer_category=category,
                site=site,
            )
        )
    return sorted(rules, key=lambda rule: (-rule.network.prefixlen, rule.segment_id))


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
    matches = [
        rule
        for rule in rules
        if rule.network.version == address.version and address in rule.network
    ]
    if not matches:
        return "unknown"
    rule = min(matches, key=lambda item: (-item.network.prefixlen, item.segment_id))
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
