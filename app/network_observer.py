from __future__ import annotations

import ipaddress
from typing import Any

NETWORK_FILTERS = [
    "192.168.100.0/23",
    "192.168.100.0/24",
    "192.168.101.0/24",
    "192.168.0.0/24",
    "10.83.1.0/24",
    "10.254.254.0/30",
    "192.168.1.0/24",
    "78.29.0.0/18",
    "192.168.50.0/24",
    "192.168.51.0/24",
    "192.168.52.0/24",
]

CATEGORY_LABELS = {
    "local_device": "Обычная сеть",
    "vpn_client": "VPN",
    "router": "Роутер",
    "site_device": "Site-to-site",
    "network_infra": "Сетевая инфраструктура",
    "telephony": "Телефония",
    "mgmt": "Управление",
    "wan": "WAN/провайдер",
    "vipnet_transit": "ViPNet transit",
    "noise": "Шум",
    "unknown": "Неизвестно",
}

SOURCE_LABELS = {
    "openvpn": "VPN",
    "mikrotik_arp": "MikroTik ARP",
    "mikrotik_dhcp": "DHCP",
    "mikrotik_neighbor": "Neighbor",
    "mikrotik_identity": "Identity",
}


def list_from(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key, [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _vpn_ip(row: dict[str, Any]) -> str:
    return str(row.get("virtual_address") or row.get("vpn_ip") or row.get("ip") or "")


def _display_name(row: dict[str, Any]) -> str:
    return str(row.get("display_name") or row.get("hostname") or row.get("common_name") or row.get("name") or row.get("ip") or "")


def normalize_netctl_host(row: dict[str, Any]) -> dict[str, Any]:
    sources = row.get("sources")
    if not isinstance(sources, list):
        sources = []
    return {
        "ip": str(row.get("ip") or ""),
        "mac": row.get("mac"),
        "hostname": row.get("hostname"),
        "display_name": _display_name(row),
        "category": row.get("category") or "unknown",
        "status": row.get("status") or "seen",
        "sources": list(sources),
        "site": row.get("site") or "",
        "last_seen_at": row.get("last_seen_at") or "",
        "last_source": row.get("last_source") or "",
        "vpn_client": None,
    }


def vpn_rows(connected: list[dict[str, Any]], clients: list[dict[str, Any]]) -> list[dict[str, Any]]:
    profiles = {str(item.get("name") or ""): item for item in clients}
    rows: list[dict[str, Any]] = []
    for item in connected:
        ip = _vpn_ip(item)
        if not ip:
            continue
        common_name = str(item.get("common_name") or item.get("name") or "")
        profile = item.get("profile") or (profiles.get(common_name) or {}).get("profile")
        rows.append(
            {
                "ip": ip,
                "mac": None,
                "hostname": None,
                "display_name": common_name or ip,
                "category": "vpn_client",
                "status": "connected",
                "sources": ["openvpn"],
                "site": "vpn",
                "last_seen_at": item.get("connected_since") or "",
                "last_source": "openvpn",
                "vpn_client": {
                    "common_name": common_name,
                    "profile": profile,
                    "real_address": item.get("real_address"),
                },
            }
        )
    return rows


def merge_unified_hosts(
    netctl_hosts: list[dict[str, Any]],
    connected: list[dict[str, Any]],
    vpn_clients: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = {row["ip"]: row for row in [normalize_netctl_host(item) for item in netctl_hosts] if row.get("ip")}
    for vpn in vpn_rows(connected, vpn_clients):
        existing = rows.get(vpn["ip"])
        if not existing:
            rows[vpn["ip"]] = vpn
            continue
        existing["sources"] = sorted(set(existing.get("sources", [])) | {"openvpn"})
        existing["vpn_client"] = vpn["vpn_client"]
        existing["status"] = "connected"
        if existing.get("category") in {"", "unknown"}:
            existing["category"] = "vpn_client"
        if not existing.get("display_name"):
            existing["display_name"] = vpn["display_name"]
    return sorted(rows.values(), key=lambda item: ipaddress.ip_address(item["ip"]))


def filter_unified_hosts(rows: list[dict[str, Any]], params: dict[str, str]) -> list[dict[str, Any]]:
    q = (params.get("q") or "").strip().lower()
    category = params.get("category") or "all"
    status = params.get("status") or "all"
    source = params.get("source") or "all"
    network = params.get("network") or "all"
    has_hostname = params.get("has_hostname") or ""
    has_mac = params.get("has_mac") or ""
    result = rows
    if category == "all":
        result = [row for row in result if row.get("category") != "noise"]
    if q:
        result = [
            row
            for row in result
            if q in " ".join(str(row.get(key) or "") for key in ["ip", "mac", "hostname", "display_name"]).lower()
        ]
    if category != "all":
        result = [row for row in result if row.get("category") == category]
    if status != "all":
        result = [row for row in result if row.get("status") == status]
    if source != "all":
        if source == "openvpn":
            result = [row for row in result if "openvpn" in row.get("sources", [])]
        else:
            result = [row for row in result if row.get("last_source") == source or any(str(s).startswith("mikrotik") for s in row.get("sources", []))]
    if network != "all":
        net = ipaddress.ip_network(network, strict=False)
        result = [row for row in result if ipaddress.ip_address(row["ip"]) in net]
    if has_hostname == "yes":
        result = [row for row in result if row.get("hostname") or row.get("display_name")]
    if has_hostname == "no":
        result = [row for row in result if not (row.get("hostname") or row.get("display_name"))]
    if has_mac == "yes":
        result = [row for row in result if row.get("mac")]
    if has_mac == "no":
        result = [row for row in result if not row.get("mac")]
    return result
