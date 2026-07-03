from __future__ import annotations

import ipaddress
from typing import Any

CENTRAL_LAN = ipaddress.ip_network("192.168.100.0/23")
VPN_POOL = ipaddress.ip_network("192.168.50.0/24")
REMOTE_SITE_LANS = [ipaddress.ip_network("192.168.51.0/24"), ipaddress.ip_network("192.168.52.0/24")]


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _category(ip: str, source: dict[str, Any], has_name: bool) -> str:
    address = ipaddress.ip_address(ip)
    if ip == str(source.get("host") or ""):
        return "router"
    if address in VPN_POOL:
        return "vpn_client"
    if address in CENTRAL_LAN:
        return "local_device" if has_name else "unknown"
    if any(address in network for network in REMOTE_SITE_LANS):
        return "site_device"
    return "unknown"


def _ensure_host(hosts: dict[str, dict[str, Any]], ip: str, now: str, source: dict[str, Any]) -> dict[str, Any]:
    if ip not in hosts:
        hosts[ip] = {
            "ip": ip,
            "mac": None,
            "hostname": None,
            "display_name": None,
            "category": "unknown",
            "status": "seen",
            "site": source.get("site"),
            "first_seen_at": now,
            "last_seen_at": now,
            "last_source": source.get("name"),
            "sources": [],
            "tags": [],
            "comment": None,
        }
    return hosts[ip]


def _add_source(host: dict[str, Any], name: str) -> None:
    if name not in host["sources"]:
        host["sources"].append(name)


def normalize_hosts(source: dict[str, Any], snapshot: dict[str, Any], observed_at: str) -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    source_ip = _ip(source.get("host"))
    if source_ip:
        router = _ensure_host(hosts, source_ip, observed_at, source)
        identity = next((item.get("name") for item in snapshot.get("identity", []) if item.get("name")), None)
        router["hostname"] = identity or source.get("name")
        router["display_name"] = router["hostname"]
        router["status"] = "online"
        _add_source(router, "mikrotik_identity")

    for lease in snapshot.get("dhcp_leases", []):
        ip = _ip(lease.get("ip") or lease.get("active_address"))
        if not ip:
            continue
        host = _ensure_host(hosts, ip, observed_at, source)
        host["mac"] = lease.get("mac") or host["mac"]
        host["hostname"] = lease.get("hostname") or host["hostname"]
        host["display_name"] = host["hostname"] or host["display_name"]
        host["status"] = "online" if str(lease.get("status") or "").lower() in {"bound", "online"} else "seen"
        _add_source(host, "mikrotik_dhcp")

    for arp in snapshot.get("arp", []):
        ip = _ip(arp.get("ip"))
        if not ip:
            continue
        host = _ensure_host(hosts, ip, observed_at, source)
        host["mac"] = host["mac"] or arp.get("mac")
        host["comment"] = host["comment"] or arp.get("comment")
        if arp.get("complete"):
            host["status"] = "online"
        _add_source(host, "mikrotik_arp")

    for neighbor in snapshot.get("neighbors", []):
        ip = _ip(neighbor.get("address"))
        if not ip:
            continue
        host = _ensure_host(hosts, ip, observed_at, source)
        host["mac"] = host["mac"] or neighbor.get("mac")
        identity = neighbor.get("identity")
        if identity:
            host["hostname"] = host["hostname"] or identity
            host["display_name"] = host["display_name"] or identity
        _add_source(host, "mikrotik_neighbor")

    for host in hosts.values():
        has_name = bool(host.get("hostname") or host.get("display_name"))
        host["category"] = _category(host["ip"], source, has_name)
        if host["category"] == "router":
            host["display_name"] = host["display_name"] or source.get("name")
            host["hostname"] = host["hostname"] or source.get("name")
        host["sources"] = sorted(host["sources"])
    return sorted(hosts.values(), key=lambda item: ipaddress.ip_address(item["ip"]))
