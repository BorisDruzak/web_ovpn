from __future__ import annotations

import ipaddress
import re
from typing import Any

CENTRAL_LAN = ipaddress.ip_network("192.168.100.0/23")
VPN_POOL = ipaddress.ip_network("192.168.50.0/24")
REMOTE_SITE_LANS = [ipaddress.ip_network("192.168.51.0/24"), ipaddress.ip_network("192.168.52.0/24")]
TELEPHONY_NETWORKS = [ipaddress.ip_network("192.168.0.0/24")]
MGMT_NETWORKS = [ipaddress.ip_network("10.83.1.0/24"), ipaddress.ip_network("90.99.99.0/30")]
VIPNET_TRANSIT_NETWORKS = [ipaddress.ip_network("10.254.254.0/30")]
WAN_NETWORKS = [ipaddress.ip_network("192.168.1.0/24"), ipaddress.ip_network("78.29.0.0/18")]
NOISE_NETWORKS = [ipaddress.ip_network("169.254.0.0/16")]
MAC_RE = re.compile(r"^[0-9A-F]{12}$")


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def normalize_mac(value: Any) -> str | None:
    if value is None:
        return None
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if not MAC_RE.match(raw.upper()):
        return None
    raw = raw.upper()
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2))


def ip_in_any_network(ip: str, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in network for network in networks)


def is_stale_noise_ip(ip: str) -> bool:
    return ip_in_any_network(ip, [*TELEPHONY_NETWORKS, *WAN_NETWORKS, *NOISE_NETWORKS])


def _category(host: dict[str, Any], source: dict[str, Any], has_name: bool) -> str:
    ip = str(host["ip"])
    address = ipaddress.ip_address(ip)
    if ip == str(source.get("host") or ""):
        return "router"
    if host.get("network_infra"):
        return "network_infra"
    if address in VPN_POOL:
        return "vpn_client"
    if ip_in_any_network(ip, VIPNET_TRANSIT_NETWORKS):
        return "vipnet_transit"
    if ip_in_any_network(ip, MGMT_NETWORKS):
        return "mgmt"
    if ip_in_any_network(ip, TELEPHONY_NETWORKS):
        return "telephony"
    if ip_in_any_network(ip, WAN_NETWORKS):
        return "wan"
    if ip_in_any_network(ip, NOISE_NETWORKS):
        return "noise"
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


def _add_tag(host: dict[str, Any], name: str) -> None:
    if name not in host["tags"]:
        host["tags"].append(name)


def _apply_hint_tags(host: dict[str, Any], *values: Any) -> None:
    text = " ".join(str(value or "") for value in values).lower()
    if any(token in text for token in ["pve", "pbs", "ipmi", "mgmt", "mellanox"]):
        _add_tag(host, "mgmt")
    if any(token in text for token in ["phone", "grandstream", "atc"]):
        _add_tag(host, "telephony")


def _token_text(host: dict[str, Any]) -> str:
    values = [
        host.get("ip"),
        host.get("hostname"),
        host.get("display_name"),
        host.get("comment"),
        host.get("category"),
        " ".join(host.get("tags") or []),
    ]
    return " ".join(str(value or "") for value in values).lower()


def _has_token(text: str, tokens: tuple[str, ...]) -> bool:
    words = set(re.split(r"[^a-z0-9]+", text))
    return any(token in words or (len(token) >= 4 and token in text) for token in tokens)


def _device_guess(host: dict[str, Any]) -> tuple[str, int, list[str]]:
    category = str(host.get("category") or "")
    text = _token_text(host)
    if category in {"router", "network_infra"}:
        return "network", 95, [f"category:{category}"]
    if category in {"wan", "vipnet_transit"}:
        return "network", 80, [f"category:{category}"]
    if category == "noise":
        return "noise", 50, ["category:noise"]
    if category == "telephony" or _has_token(text, ("phone", "grandstream", "yealink", "atc", "sip", "voip")):
        return "phone", 85, ["category:telephony" if category == "telephony" else "text:phone"]
    if _has_token(text, ("camera", "cam", "hikvision", "dahua", "hiwatch", "onvif", "rtsp")):
        return "camera", 80, ["text:camera"]
    if _has_token(text, ("printer", "print", "hp", "canon", "xerox", "brother", "kyocera")):
        return "printer", 80, ["text:printer"]
    if category == "mgmt" or _has_token(text, ("pve", "pbs", "ipmi", "proxmox", "server", "srv", "nas", "nextcloud", "onlyoffice")):
        return "server", 80, ["category:mgmt" if category == "mgmt" else "text:server"]
    if _has_token(text, ("pc", "desktop", "laptop", "notebook", "win", "workstation", "ws")):
        return "pc", 70, ["text:pc"]
    if category == "vpn_client":
        return "pc", 55, ["category:vpn_client"]
    return "unknown", 0, []


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
        host["mac"] = normalize_mac(lease.get("mac")) or host["mac"]
        host["hostname"] = lease.get("hostname") or host["hostname"]
        host["display_name"] = host["hostname"] or host["display_name"]
        if not host["display_name"] and lease.get("comment"):
            host["display_name"] = lease.get("comment")
        host["status"] = "online" if str(lease.get("status") or "").lower() in {"bound", "online"} else "seen"
        host["comment"] = host["comment"] or lease.get("comment")
        _apply_hint_tags(host, lease.get("hostname"), lease.get("comment"))
        _add_source(host, "mikrotik_dhcp")

    for arp in snapshot.get("arp", []):
        ip = _ip(arp.get("ip"))
        if not ip:
            continue
        if not arp.get("complete") and ip not in hosts:
            continue
        host = _ensure_host(hosts, ip, observed_at, source)
        host["mac"] = host["mac"] or normalize_mac(arp.get("mac"))
        host["comment"] = host["comment"] or arp.get("comment")
        if arp.get("complete"):
            host["status"] = "online"
        _add_source(host, "mikrotik_arp")

    for neighbor in snapshot.get("neighbors", []):
        ip = _ip(neighbor.get("address"))
        if not ip:
            continue
        host = _ensure_host(hosts, ip, observed_at, source)
        host["mac"] = host["mac"] or normalize_mac(neighbor.get("mac"))
        identity = neighbor.get("identity")
        if identity:
            host["hostname"] = host["hostname"] or identity
            host["display_name"] = host["display_name"] or identity
        platform = str(neighbor.get("platform") or "").lower()
        if platform == "mikrotik" or str(identity or "").lower().startswith(("mt-", "mikrotik", "cap-")):
            host["network_infra"] = True
            _add_tag(host, "network_infra")
        _add_source(host, "mikrotik_neighbor")

    for host in hosts.values():
        has_name = bool(host.get("hostname") or host.get("display_name"))
        host["category"] = _category(host, source, has_name)
        if host["category"] == "router":
            host["display_name"] = host["display_name"] or source.get("name")
            host["hostname"] = host["hostname"] or source.get("name")
        if host["category"] not in {"unknown", "local_device"}:
            _add_tag(host, host["category"])
        device_type, confidence, evidence = _device_guess(host)
        host["device_type"] = device_type
        host["device_confidence"] = confidence
        host["device_evidence"] = evidence
        if device_type != "unknown":
            _add_tag(host, f"device:{device_type}")
        host["sources"] = sorted(host["sources"])
        host["tags"] = sorted(host["tags"])
        host.pop("network_infra", None)
    return sorted(hosts.values(), key=lambda item: ipaddress.ip_address(item["ip"]))
