"""Build the infrastructure snapshot outside the web request lifecycle."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from netctl.config import DEFAULT_DB_URL, load_secrets
from netctl.context import load_context_bytes, load_schema, validate_context
from netctl.db import connect_read_only, list_sources
from netctl.drivers import legacy_driver_for
from netctl.snmp.lacp import read_lacp_members
from netctl.snmp.transport import SnmpTransport
from netctl.source_identity import list_source_identities
from netctl.switch_queries import query_confirmed_attachment_ports, query_observed_mac_ports

from .infrastructure_map import (
    CLUSTER_HEALTH_METHODS, CLUSTER_KIND, INTERFACE_NAME, MAX_SNAPSHOT_BYTES, NETWORK_KINDS, RECIPROCAL_MAC_SOURCE,
    index_port_states, observation_is_fresh, port_label_key,
)
from .infrastructure_service_probes import apply_service_probes, probe_icmp
from .netctl_client import NetctlError, run_netctl
from .server_health_view import build_server_health_view

KINDS = {
    "switch": NETWORK_KINDS[0], "router": NETWORK_KINDS[1],
    "wireless_access_point": NETWORK_KINDS[2], "hypervisor": "Гипервизор",
    "endpoint": "Рабочая станция", "firewall_dns_host": "Межсетевой экран и DNS",
    "security_gateway": "Шлюз", "ip_pbx": "АТС", "fxs_gateway": "Телефонный шлюз",
}
HEALTH = {"success": "ok", "ok": "ok", "partial": "warn", "warn": "warn", "critical": "critical"}
MAC = re.compile(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
FUNCTIONAL_CHECKS = {
    "nextcloud": ("nextcloud_status", "Nextcloud status"),
    "onlyoffice": ("https_healthcheck", "HTTPS"),
    "acti": ("https_ready", "HTTPS readiness"),
    "acti_backup": ("backup_snapshot_fresh", "Свежесть резервной копии"),
}


def _observation(state: str, source: str, method: str, checked_at: str) -> dict:
    return {"state": state, "source": source, "method": method, "checkedAt": checked_at}


def _proxmox_cluster_health(hub: dict, cluster: dict, rows: list[dict], checked_at: str) -> None:
    quorum = cluster.get("quorate")
    quorum_state = {0: "unreachable", 1: "reachable"}.get(quorum, "unknown") if type(quorum) is int else "unknown"
    if quorum_state != "unknown":
        hub["properties"]["Кворум"] = "Есть" if quorum else "Отсутствует"

    count = cluster.get("nodes")
    members = [row for row in rows if row.get("type") == "node"]
    names = {row["name"] for row in members if isinstance(row.get("name"), str) and row["name"]}
    flags = [row.get("online") for row in members]
    members_state = "unknown"
    if type(count) is int and 0 < count == len(members) == len(names) and all(
        type(flag) is int and flag in (0, 1) for flag in flags
    ):
        online = sum(flags)
        hub["properties"]["Узлы"] = f"{online} из {count} в сети"
        members_state = "reachable" if online == count else "unreachable"
    hub["serviceChecks"] = [
        _observation(state, "Proxmox", method, checked_at)
        for method, state in zip(CLUSTER_HEALTH_METHODS, (quorum_state, members_state))
    ]


def _host_observation(host: dict, now: datetime) -> dict | None:
    value = host.get("availability") or {}
    checked_at = value.get("checked_at")
    if value.get("run_status") != "success" or not observation_is_fresh(checked_at, now):
        return None
    if value.get("state") == "online" and value.get("reason") == "active_probe":
        method = {"icmp": "ICMP", "tcp": "TCP", "arp": "ARP"}.get(value.get("active_method"), "Активная проверка")
        return _observation("reachable", "netctl", method, checked_at)
    if value.get("state") == "offline" and value.get("reason") == "active_negative_no_passive_evidence":
        return _observation("unreachable", "netctl", "Активная проверка", checked_at)
    return None


def _guest_macs(config: dict) -> set[str]:
    return {match.lower() for key, value in config.items()
            if re.fullmatch(r"net[0-9]+", key) and isinstance(value, str)
            for match in MAC.findall(value)}


def _guest_interfaces(config: dict) -> dict:
    interfaces = {}
    for name, raw in config.items():
        if not re.fullmatch(r"net[0-9]+", name) or not isinstance(raw, str):
            continue
        options = dict(part.split("=", 1) for part in raw.split(",") if "=" in part)
        bridge = options.get("bridge", "")
        if INTERFACE_NAME.fullmatch(bridge):
            tag = options.get("tag", "")
            first_value = raw.partition(",")[0].partition("=")[2]
            mac = options.get("hwaddr", first_value)
            interfaces[name] = (bridge, int(tag) if re.fullmatch(r"[0-9]{1,4}", tag) else None,
                                options.get("link_down") == "1", mac.lower() if MAC.fullmatch(mac) else "")
    return interfaces


def _guest_observation(macs: set[str], host_macs: dict, counts: Counter, now: datetime) -> dict | None:
    observations = [
        _host_observation(host, now)
        for mac in macs if counts[mac] == 1 for host in host_macs.get(mac, [])
    ]
    reachable = [item for item in observations if item and item["state"] == "reachable"]
    if reachable:
        return max(reachable, key=lambda item: item["checkedAt"])
    covered = all(counts[mac] == 1 and host_macs.get(mac) for mac in macs)
    if covered and observations and all(observations):
        return max(observations, key=lambda item: item["checkedAt"])
    return None


def _arp_mappings(rows: list[dict], now: datetime) -> dict:
    mappings = {}
    for row in rows:
        ip = row.get("ip")
        mac = str(row.get("mac") or "").lower()
        observed = row.get("last_seen_at")
        if isinstance(ip, str) and MAC.fullmatch(mac) and observation_is_fresh(observed, now):
            stamp = datetime.fromisoformat(observed)
            known = mappings.setdefault(ip, {})
            known[mac] = max(known.get(mac, stamp), stamp)
    return {ip: next(iter(macs.items())) for ip, macs in mappings.items() if len(macs) == 1}


def _verified_arp_checks(mappings: dict, hosts: dict, now: datetime) -> dict:
    checks = {}
    for ip, (mac, arp_at) in mappings.items():
        probe = _host_observation(hosts.get(ip, {}), now)
        if probe and probe["state"] == "reachable" and datetime.fromisoformat(probe["checkedAt"]) >= arp_at:
            checks.setdefault(mac, []).append((ip, {**probe, "method": probe["method"] + " · ARP"}))
    return checks


def _reciprocal_lldp(network: dict, rows: list[dict], peers_by_port: dict, arp: dict, now: datetime):
    sources = {row["name"]: row for row in network.get("sources", [])
               if row.get("enabled") and row.get("driver") == "snmp_switch"}
    chassis_owners = {}
    ports = {}

    def remember(mac, source, observed):
        owners = chassis_owners.setdefault(mac, {})
        owners[source] = max(owners.get(source, observed), observed)

    for source, row in sources.items():
        if row.get("host") in arp:
            mac, observed = arp[row["host"]]
            remember(mac, source, observed)
    for port in network.get("ports", []):
        source, stamp = port["source"], port.get("last_seen_at")
        if (source not in sources or port.get("oper_status") != "up"
                or not observation_is_fresh(stamp, now) or type(port.get("if_index")) is not int):
            continue
        ports.setdefault(source, {})[port["port_key"]] = port
        mac = str(port.get("mac") or "").lower()
        if MAC.fullmatch(mac):
            remember(mac, source, datetime.fromisoformat(stamp))

    def peer(row):
        mac = str(row.get("chassis_id") or "").lower()
        if row.get("chassis_id_subtype") not in {"4", "mac_address"}:
            return None, None
        owners = chassis_owners.get(mac, {})
        if len(owners) == 1:
            return next(iter(owners.items()))
        return None, None

    def matches_port(advertisement, source, port):
        identifier = str(advertisement.get("port_id") or "").strip().casefold()
        subtype = str(advertisement.get("port_id_subtype"))
        field = {"1": "alias", "5": "name", "interface_alias": "alias", "interface_name": "name"}.get(subtype)
        if not identifier or not field:
            return False
        indexes = {p["if_index"] for p in ports[source].values()
                   if str(p.get(field) or "").strip().casefold() == identifier
                   or (field == "alias" and str(p["if_index"]) == identifier)}
        return indexes == {port["if_index"]}

    observations = {}
    for row in rows:
        source, key = row.get("source"), row.get("local_port_key")
        port = ports.get(source, {}).get(key)
        if port and len(peers_by_port[(source, key)]) == 1:
            observations.setdefault(source, []).append((row, port))
    for source, local in observations.items():
        for row, port in local:
            remote, peer_at = peer(row)
            if not remote or source >= remote:
                continue
            for reverse, other_port in observations.get(remote, []):
                local_peer, reverse_at = peer(reverse)
                if (local_peer == source and matches_port(row, remote, other_port)
                        and matches_port(reverse, source, port)):
                    at = min(peer_at, reverse_at, *(datetime.fromisoformat(value) for value in (
                        row["observed_at"], reverse["observed_at"], port["last_seen_at"], other_port["last_seen_at"],
                    )))
                    yield source, remote, port["name"], other_port["name"], at.isoformat()


async def _collect_lacp(network: dict, configured: list[dict], now: datetime) -> list[dict]:
    sources = {row["name"]: row for row in network["sources"] if row["enabled"] and row["driver"] == "snmp_switch"}
    indexes = {}
    for port in network["ports"]:
        index = port.get("if_index")
        if (port.get("oper_status") == "up" and observation_is_fresh(port.get("last_seen_at"), now)
                and type(index) is int and index > 0):
            indexes.setdefault((port["source"], port["name"].casefold()), set()).add(index)

    def port_index(source, port):
        matches = indexes.get((source, port.casefold()), set())
        return next(iter(matches)) if len(matches) == 1 else None

    observations = []
    for spec in configured:
        source, aggregate = spec["source"], spec["aggregate"]
        names = {port.casefold(): port for port in spec["members"]}
        if source not in sources or not (aggregate_index := port_index(source, aggregate)):
            continue
        members = {port: index for port in names.values() if (index := port_index(source, port)) and index != aggregate_index}
        if not members or len(set(members.values())) != len(members):
            continue
        try:
            async with asyncio.timeout(5), SnmpTransport.from_source(sources[source]) as transport:
                live = await read_lacp_members(transport, aggregate_index, members)
        except (TimeoutError, OSError, ValueError):
            continue
        if live:
            observations.append({"source": source, "asset": spec["asset"], "aggregate": aggregate,
                                 "expected": len(names), "at": datetime.now(timezone.utc).isoformat(), "members": live})
    return observations


def _probe_on_link_guest(address: str, mac: str) -> bool:
    def ip_query(*args):
        return json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", *args], timeout=2))

    try:
        routes = ip_query("route", "get", address)
        if len(routes) != 1 or routes[0].get("gateway") or routes[0].get("via") or not routes[0].get("dev"):
            return False
        if not probe_icmp(address):
            return False
        neighbors = ip_query("neigh", "show", "to", address, "dev", routes[0]["dev"])
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    # Linux moves a cached neighbor to DELAY/PROBE when sending traffic before revalidation.
    return any(row.get("dst") == address and str(row.get("lladdr", "")).lower() == mac
               and {"REACHABLE", "DELAY", "PROBE"}.intersection(row.get("state", [])) for row in neighbors)


def _router_layer2_observation(sources: list[dict], name: str, interface: str, mac: str,
                               *, address: str | None = None) -> dict | None:
    source = next((row for row in sources if row["name"] == name and row.get("enabled")
                   and row.get("driver") == "mikrotik_api"), None)
    if source is None:
        return None
    try:
        if legacy_driver_for(source, load_secrets()).probe_layer2(interface, mac, address=address):
            method = "MAC ping · L2" if address is None else "ARP · L2"
            return _observation("reachable", name, method, datetime.now(timezone.utc).isoformat())
    except (OSError, RuntimeError, ValueError):
        pass
    return None


def _collect_asset_mac_probes(context: dict, sources: list[dict], configured: dict) -> dict:
    ownership = {}
    for device in context.get("devices", []):
        for mac in device.get("mac_addresses", []):
            ownership.setdefault(mac.lower(), set()).add(device["id"])
    checks = {}
    for asset, spec in configured.items():
        mac = spec["mac"].lower()
        if ownership.get(mac) != {asset}:
            continue
        observation = _router_layer2_observation(sources, spec["source"], spec["interface"], mac)
        if observation:
            checks[asset] = observation
    return checks


def _collect_guest_arp_probes(pve: dict, network: dict, configured: dict, now: datetime,
                              router_sources: dict | None = None) -> dict:
    configs = pve.get("configs", {})
    counts = Counter(mac for config in configs.values() for mac in _guest_macs(config))
    arp_rows = network.get("arp", [])
    arp = _arp_mappings(arp_rows, now)
    candidates = []
    for guest in pve.get("guests", []):
        vmid = str(guest["vmid"])
        if guest.get("status") != "running" or guest.get("template") or vmid not in configured:
            continue
        try:
            address = str(ipaddress.IPv4Address(configured[vmid]))
        except (TypeError, ValueError):
            continue
        if address not in arp:
            continue
        mac, _ = arp[address]
        interfaces = _guest_interfaces(configs.get(vmid, {}))
        if counts[mac] == 1 and any(nic_mac == mac and not disabled for _, _, disabled, nic_mac in interfaces.values()):
            candidates.append((vmid, address, mac))

    def check(candidate):
        vmid, address, mac = candidate
        if _probe_on_link_guest(address, mac):
            return mac, address, _observation("reachable", "UI_VPN", "ICMP · ARP", datetime.now(timezone.utc).isoformat())
        name = (router_sources or {}).get(vmid)
        if not name:
            return None
        interfaces = {row["interface"] for row in arp_rows if row.get("ip") == address and row.get("source") == name
                      and str(row.get("mac", "")).lower() == mac and row.get("interface")
                      and observation_is_fresh(row.get("last_seen_at"), now)}
        if len(interfaces) == 1:
            observation = _router_layer2_observation(network.get("sources", []), name, interfaces.pop(), mac, address=address)
            if observation:
                return mac, address, observation
        return None

    checks = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        for result in pool.map(check, candidates):
            if result:
                mac, address, observation = result
                checks.setdefault(mac, []).append((address, observation))
    return checks


def _route_checks(intent: dict, source: str, routes: list[dict], now: datetime) -> list[dict]:
    gateway = intent.get("next_hop")
    table = intent.get("routing_table", "main")
    checks = []
    for destination in intent.get("destinations", [])[:12]:
        matches = [
            row["last_seen_at"] for row in routes
            if row.get("source") == source and row.get("routing_table") == table
            and row.get("dst_address") == destination and row.get("gateway") == gateway
            and row.get("active") == 1 and row.get("disabled") == 0
            and observation_is_fresh(row.get("last_seen_at"), now)
        ]
        checks.append({
            "state": "reachable" if matches else "unknown", "source": "Network Observer",
            "method": "Маршрут", "target": destination, "via": gateway,
            "checkedAt": max(matches) if matches else now.isoformat(),
        })
    return checks


def _transit_port(segment: dict, spec: dict, network: dict, arp_mappings: dict, now: datetime) -> tuple[str, str] | None:
    try:
        subnet = ipaddress.IPv4Network(segment["cidr"])
        local, remote = ipaddress.IPv4Address(segment["local_address"]), ipaddress.IPv4Address(spec["peer"])
    except (KeyError, ValueError):
        return None
    if subnet.prefixlen not in {30, 31} or set(subnet.hosts()) != {local, remote}:
        return None
    peer = str(remote)
    if peer not in arp_mappings:
        return None
    mac, _ = arp_mappings[peer]
    source = spec["source"]
    routes = {
        row["gateway"]: row["last_seen_at"] for row in network.get("routes", [])
        if row.get("source") == source and row.get("dst_address") == str(subnet)
        and row.get("routing_table") == "main" and row.get("route_type") == "unicast"
        and row.get("active") == 1 and row.get("disabled") == 0 and row.get("dynamic") == 1
        and row.get("gateway") == row.get("immediate_gateway")
        and observation_is_fresh(row.get("last_seen_at"), now)
    }
    if len(routes) != 1:
        return None
    (port, route_at), = routes.items()
    if not isinstance(port, str) or not INTERFACE_NAME.fullmatch(port):
        return None
    interfaces = [row["last_seen_at"] for row in network.get("router_interfaces", [])
                  if row.get("source") == source and row.get("name") == port and row.get("type") == "ether"
                  and row.get("running") == 1 and row.get("disabled") == 0 and observation_is_fresh(row.get("last_seen_at"), now)]
    neighbors = [row["last_seen_at"] for row in network.get("arp", [])
                 if row.get("source") == source and row.get("ip") == peer and row.get("interface") == port
                 and str(row.get("mac") or "").lower() == mac and observation_is_fresh(row.get("last_seen_at"), now)]
    if interfaces and neighbors:
        return port, min(datetime.fromisoformat(stamp) for stamp in (route_at, max(interfaces), max(neighbors))).isoformat()
    return None


def _bridge_attachment_port(address: str | None, source: str, bridge: str, network: dict,
                            arp_mappings: dict, now: datetime) -> tuple[str, str] | None:
    if address not in arp_mappings or not INTERFACE_NAME.fullmatch(bridge):
        return None
    mac, _ = arp_mappings[address]
    arp = [row["last_seen_at"] for row in network.get("arp", [])
           if row.get("source") == source and row.get("ip") == address and row.get("interface") == bridge
           and str(row.get("mac") or "").lower() == mac and observation_is_fresh(row.get("last_seen_at"), now)]
    learned = [row for row in network.get("router_bridge_hosts", [])
               if row.get("source") == source and row.get("bridge") == bridge
               and str(row.get("mac") or "").lower() == mac and observation_is_fresh(row.get("last_seen_at"), now)]
    ports = {row.get("interface") for row in learned}
    if not arp or len(ports) != 1:
        return None
    port, = ports
    if not isinstance(port, str) or not INTERFACE_NAME.fullmatch(port):
        return None
    active = [row["last_seen_at"] for row in network.get("router_interfaces", [])
              if row.get("source") == source and row.get("name") == port and row.get("type") == "ether"
              and row.get("running") == 1 and row.get("disabled") == 0 and observation_is_fresh(row.get("last_seen_at"), now)]
    if active:
        observed = min(datetime.fromisoformat(stamp) for stamp in (
            max(arp), max(active), max(row["last_seen_at"] for row in learned),
        ))
        return port, observed.isoformat()
    return None


def _collect_ipsec_policies(sources: list[dict], configured: dict) -> dict:
    names = {spec[side] for spec in configured.values() for side in ("local_source", "remote_source")}
    targets = [source for source in sources if source["name"] in names and source.get("enabled")
               and source["driver"] in {"mikrotik_api", "mikrotik_ssh"}]
    if not targets:
        return {}
    secrets = load_secrets()

    def collect(source):
        try:
            snapshot = legacy_driver_for(source, secrets).ipsec_status()
        except Exception:
            return source["name"], {}
        if any(error.get("section") == "policies" for error in snapshot.get("errors", [])):
            return source["name"], {}
        return source["name"], {"at": datetime.now(timezone.utc).isoformat(), "policies": snapshot["policies"]}

    with ThreadPoolExecutor(max_workers=4) as pool:
        return dict(pool.map(collect, targets))


def _ipsec_policy_checks(feature: dict, remote: str, spec: dict, snapshots: dict, now: datetime) -> list[dict]:
    def direction(source, peer, src, dst):
        snapshot = snapshots.get(source, {})
        at = snapshot.get("at")
        if not observation_is_fresh(at, now):
            return "unknown", None
        established = any(policy.get("peer") == peer and policy.get("src_address") == src
                          and policy.get("dst_address") == dst and policy.get("action") == "encrypt"
                          and policy.get("tunnel") is True and policy.get("established") is True
                          for policy in snapshot["policies"])
        return ("reachable" if established else "unreachable"), datetime.fromisoformat(at)

    checks = []
    for local in feature["policy_destinations"]:
        forward, left = direction(spec["local_source"], feature["central_peer"]["name"], local, remote)
        reverse, right = direction(spec["remote_source"], feature["remote_peer"]["name"], remote, local)
        states = (forward, reverse)
        state = "unreachable" if "unreachable" in states else "unknown" if "unknown" in states else "reachable"
        stamps = [stamp for status, stamp in ((forward, left), (reverse, right)) if status == state or state == "reachable"]
        checked_at = min((stamp for stamp in stamps if stamp), default=now).isoformat()
        checks.append({**_observation(state, "MikroTik IPsec", "IPsec фаза 2", checked_at), "target": local})
    return checks


def _collect_ipsec_connectivity(context: dict, sources: list[dict], configured: dict) -> dict:
    features = {item["id"]: item for item in context.get("features", []) if item.get("kind") == "policy_based_ipsec"}
    segments = {item["id"]: item["cidr"] for item in context.get("segments", []) if item.get("cidr")}
    devices = {item["id"]: item.get("management_ip") for item in context.get("devices", [])}
    routers = {source["name"]: source for source in sources if source.get("enabled") and source["driver"] == "mikrotik_ssh"}
    observations = {}
    for feature_id, spec in configured.items():
        feature, probe = features.get(feature_id), spec.get("connectivity")
        router = routers.get(spec.get("remote_source"))
        if not feature or not probe or not router:
            continue
        try:
            local = ipaddress.IPv4Address(devices.get(probe["asset"]))
            remote = ipaddress.IPv4Address(devices.get(feature["remote_device"]))
            if (router.get("host") != str(remote)
                    or remote not in ipaddress.IPv4Network(segments.get(spec["remote_segment"]))
                    or not any(local in ipaddress.IPv4Network(cidr) for cidr in feature["policy_destinations"])):
                continue
        except (KeyError, ValueError):
            continue

        checks = []
        for source, address, probe_once in (
            ("UI_VPN", remote, lambda: probe_icmp(str(remote), source_ip=str(local))),
            (router["name"], local, lambda: legacy_driver_for(router, load_secrets()).ping_ipv4(str(local), str(remote))),
        ):
            try:
                replied = probe_once()
            except (OSError, ValueError, subprocess.SubprocessError):
                replied = False
            stamp = datetime.now(timezone.utc).isoformat()
            checks.append({**_observation("reachable" if replied else "unknown", source, "ICMP", stamp),
                           "target": str(address)})
        observations[feature_id] = checks
    return observations


def _reconcile_fdb_ports(links) -> None:
    direct = {}
    reciprocal = {}
    physical = [link for link in links if link["kind"] == "Сетевое соединение"]

    def endpoints(link, report):
        for side, peer in (("a", "b"), ("b", "a")):
            if report[side]:
                yield (link[side], report[side].casefold()), link[peer]

    for link in physical:
        for report in link.get("portEvidence", []):
            if report["confirmed"] and report["source"] in {"LLDP UI_VPN", "LLDP · двустороннее"}:
                neighbors = reciprocal if report["source"] == "LLDP · двустороннее" else direct
                for endpoint, peer in endpoints(link, report):
                    neighbors.setdefault(endpoint, set()).add(peer)
    owners = {**direct, **reciprocal}

    for link in physical:
        evidence = link.get("portEvidence", [])
        changed = False
        for report in evidence:
            if report["confirmed"] and report["source"] == "netctl FDB" and any(
                len(owners.get(endpoint, ())) == 1 and peer not in owners[endpoint]
                for endpoint, peer in endpoints(link, report)
            ):
                report["confirmed"] = False
                changed = True
        if not changed:
            continue
        surviving = [report for report in evidence if report["confirmed"]]
        if not surviving:
            link["confirmed"] = False
            link["details"] = "MAC виден через порт другого соседа LLDP"
        elif not any(report["source"] == link["source"] and report["at"] == link["observedAt"] for report in surviving):
            best = max(surviving, key=lambda report: datetime.fromisoformat(report["at"]).timestamp()
                       if report["at"] else 0)
            link.update(source=best["source"], observedAt=best["at"])


def _corroborate_fdb_ports(links, nodes: dict, now: datetime) -> None:
    active = {
        key: {port["name"].casefold(): datetime.fromisoformat(port["checkedAt"]) for port in node.get("ports", [])
              if port.get("name") and port["state"] == "up" and observation_is_fresh(port["checkedAt"], now)}
        for key, node in nodes.items() if node["kind"] == NETWORK_KINDS[0]
    }
    for link in links:
        if (link["kind"] != "Сетевое соединение" or not link["confirmed"]
                or link["a"] not in active or link["b"] not in active):
            continue
        reports = link.get("portEvidence", [])
        declared = [row for row in reports if row["source"] == "GitHub" and row["confirmed"]]
        if len(declared) != 1 or link["source"] in {"LLDP UI_VPN", "LLDP · двустороннее"}:
            continue
        pair = declared[0]
        stamps = []
        for local, remote in (("a", "b"), ("b", "a")):
            port = pair[local].casefold()
            up_at = active[link[local]].get(port)
            sightings = [row for row in reports if row["source"] == "netctl FDB" and row[local]
                         and observation_is_fresh(row["at"], now)]
            if up_at is None or {row[local].casefold() for row in sightings} != {port}:
                break
            one_sided = [datetime.fromisoformat(row["at"]) for row in sightings if row["confirmed"] and not row[remote]]
            if not one_sided:
                break
            stamps.extend((up_at, max(one_sided)))
        else:
            reports.append({"a": pair["a"], "b": pair["b"], "source": "SNMP · двусторонний FDB",
                            "at": min(stamps).isoformat(), "confirmed": True})


def _reciprocal_management_paths(links, nodes: dict, sightings: dict, now: datetime):
    if not sightings:
        return
    ports = {key: index_port_states(item.get("ports", []), now) for key, item in nodes.items()
             if item["kind"] == NETWORK_KINDS[0]}
    for link in links:
        a, b = link["a"], link["b"]
        if link["kind"] != "Сетевое соединение" or link["confirmed"] or a not in ports or b not in ports:
            continue
        declared = [report for report in link.get("portEvidence", []) if report["source"] == "GitHub"]
        if len(declared) != 1:
            continue
        pair, = declared
        names = []
        stamps = []
        for side, local, remote in (("a", a, b), ("b", b, a)):
            expected = ports[local].get(port_label_key(pair[side]))
            observations = sightings.get((local, remote), [])
            if not expected or expected["state"] != "up" or not observations:
                break
            actual_names = {port_label_key(name) for name, _ in observations}
            if actual_names != {port_label_key(expected["name"])}:
                break
            names.append(expected["name"])
            stamps.extend((datetime.fromisoformat(expected["checkedAt"]), max(at for _, at in observations)))
        else:
            yield a, b, tuple(names), min(stamps).isoformat()


def _add_guest_switch_uplinks(links, nodes: dict, pve: dict, now: datetime) -> None:
    owners = {}
    candidates = {}
    for link in links:
        if not link["confirmed"] or link["kind"] != "Сетевое соединение":
            continue
        for local, remote in (("a", "b"), ("b", "a")):
            switch, peer = link[local], link[remote]
            if nodes[switch]["kind"] != NETWORK_KINDS[0]:
                continue
            for report in link.get("portEvidence", []):
                source = report["source"]
                if (not report["confirmed"] or not report[local] or not observation_is_fresh(report["at"], now)
                        or source not in {"netctl FDB + Proxmox", "LLDP UI_VPN", "LLDP · двустороннее"}):
                    continue
                switch_port = (switch, report[local].casefold())
                endpoint = (peer, report[remote].casefold())
                owners.setdefault(switch_port, set()).add(endpoint)
                if source == "netctl FDB + Proxmox" and endpoint[1] and nodes[peer]["kind"] == "Гипервизор":
                    candidates.setdefault(endpoint, {})[switch_port] = {
                        "id": switch, "port": report[local], "at": report["at"],
                    }

    running = {(row["node"], row["vmid"]) for row in pve.get("guests", [])
               if row.get("status") == "running" and not row.get("template")}
    for link in links:
        host, guest = link["a"], link["b"]
        if (not link["confirmed"] or link["kind"] != "Размещение ВМ"
                or (host, nodes[guest].get("vmid")) not in running):
            continue
        for report in link.get("portEvidence", []):
            virtual = report.get("virtual")
            if (not virtual or not report["confirmed"] or not observation_is_fresh(report["at"], now)
                    or virtual["linkDisabled"] or not virtual["bridgeActive"] or virtual["switchPorts"]):
                continue
            bridge = pve.get("bridges", {}).get(host, {}).get(report["a"], {})
            uplink = bridge.get("bridge_ports")
            if not isinstance(uplink, str) or virtual["uplinks"] != [uplink] or uplink not in pve.get("activePorts", {}).get(host, []):
                continue
            endpoint = (host, uplink.casefold())
            paths = candidates.get(endpoint, {})
            if len(paths) == 1:
                (switch_port, evidence), = paths.items()
                if owners[switch_port] == {endpoint}:
                    checked_at = min(datetime.fromisoformat(stamp) for stamp in (evidence["at"], report["at"]))
                    virtual["switchUplink"] = {**evidence, "at": checked_at.isoformat()}


def build_graph(context: dict, network: dict, server: dict, pve: dict, bindings: dict, now: datetime) -> dict:
    nodes = {}
    edges = {}

    def node(key, name, kind, site="", origin="GitHub"):
        return nodes.setdefault(key, {
            "id": key, "name": name, "kind": kind, "site": site, "origin": origin,
            "properties": {}, "sources": [], "checks": [],
        })

    def edge(a, b, kind, source, confirmed=True, details="", ports=None, at=None, vlan=None, virtual=None,
             evidence_only=False):
        if a not in nodes or b not in nodes or a == b:
            return
        key = (tuple(sorted((a, b))), kind)
        current = edges.get(key)
        evidence = current.get("portEvidence", []) if current else []
        if not current or confirmed and not evidence_only and (not current["confirmed"] or source != "GitHub"):
            edges[key] = {"a": a, "b": b, "kind": kind, "source": source,
                          "confirmed": confirmed, "details": details, "observedAt": at}
        if current and edges[key]["a"] != current["a"]:
            evidence = [{**item, "a": item["b"], "b": item["a"]} for item in evidence]
        if ports and any(ports):
            if edges[key]["a"] != a:
                ports = ports[::-1]
            report = {"a": ports[0], "b": ports[1], "source": source, "at": at,
                      "confirmed": confirmed}
            if virtual is not None:
                report.update({"source": "Proxmox · конфигурация ВМ", "virtual": virtual})
            if vlan is not None:
                report["vlan"] = vlan
            if report not in evidence:
                evidence.append(report)
        if evidence:
            edges[key]["portEvidence"] = evidence

    def source(item, name, raw, at, label=""):
        item["sources"].append({"name": name, "raw": raw, "status": HEALTH.get(raw, "unknown"),
                                "at": at, "label": label})

    host_ips = {}
    host_macs = {}
    fresh_macs_by_ip = {}
    for host in network.get("hosts", []):
        if host.get("ip"):
            host_ips[host["ip"]] = host
        mac = str(host.get("mac") or "").lower()
        if MAC.fullmatch(mac):
            host_macs.setdefault(mac, []).append(host)
            if host.get("ip") and observation_is_fresh(host.get("last_seen_at"), now):
                fresh_macs_by_ip.setdefault(host["ip"], set()).add(mac)
    addresses = {}
    address_by_asset = {}
    observed_addresses = {}
    names = {}
    declared_macs = {}
    declared_devices_by_mac = {}
    for device in context.get("devices", []):
        key = device["id"]
        item = node(key, device["name"], KINDS.get(device["kind"], "Сервер"), device.get("site", ""))
        addresses.setdefault(str(device.get("management_ip") or ""), []).append(key)
        address_by_asset[key] = device.get("management_ip")
        observed_addresses[key] = device.get("observed_ipv4_addresses", [])
        observation = _host_observation(host_ips.get(device.get("management_ip"), {}), now)
        if observation:
            item["reachability"] = observation
        names.setdefault(device["name"].casefold(), []).append(key)
        declared_macs[key] = {mac.lower() for mac in device.get("mac_addresses", []) if MAC.fullmatch(mac)}
        for mac in declared_macs[key]:
            declared_devices_by_mac.setdefault(mac, set()).add(key)
        if device.get("model"):
            item["properties"]["Модель"] = device["model"]
    for device in context.get("devices", []):
        key = device["id"]
        if device["kind"] == "endpoint" and len(declared_macs[key]) == 1:
            mac, = declared_macs[key]
            if declared_devices_by_mac[mac] == {key}:
                nodes[key]["endpointKey"] = "mac:" + mac.upper()
    intents = {item["id"]: item for item in context.get("routing_intent", []) if "id" in item}
    for service in context.get("services", []):
        host = service.get("device")
        item = node(service["id"], service["name"], "Сервис", nodes.get(host, {}).get("site", ""))
        route = bindings.get("route_evidence", {}).get(service["id"], {})
        intent = intents.get(route.get("intent"))
        if intent and route.get("source"):
            item["serviceChecks"] = _route_checks(intent, route["source"], network.get("routes", []), now)
        edge(host, service["id"], "Размещение", "GitHub")
    for service_id, spec in bindings.get("asset_services", {}).items():
        asset = spec["asset"]
        if asset in address_by_asset and service_id not in nodes:
            item = node(service_id, spec["label"], "Сервис", nodes[asset]["site"], "UI_VPN")
            item["probeTargetIP"] = address_by_asset[asset]
            edge(asset, service_id, "Размещение", "Настройки карты")
    verified_host_ports = set()
    for link in context.get("links", []):
        if link.get("state", {}).get("intent") == "absent":
            continue
        a, b = link["endpoint_a"], link["endpoint_b"]
        kind = "Размещение ВМ" if link.get("relation") == "virtualized_on" else "Сетевое соединение"
        ports = (a.get("interface") or "", b.get("interface") or "")
        verified = link.get("state", {}).get("verified") is True
        edge(a["device"], b["device"], kind, "GitHub", verified, ports=ports)
        if verified and link.get("relation") == "connected_to":
            for switch, host in ((a, b), (b, a)):
                if (nodes.get(switch["device"], {}).get("kind") == NETWORK_KINDS[0]
                        and nodes.get(host["device"], {}).get("kind") == "Гипервизор"):
                    verified_host_ports.add((host["device"], switch["device"], (switch.get("interface") or "").casefold()))

    switch_status = {row["source"]: row for row in network.get("switches", [])}
    port_groups = {}
    port_names = {}
    for port in network.get("ports", []):
        port_groups.setdefault(port["source"], []).append(port)
        port_names[(port["source"], port.get("port_key"))] = port.get("name") or port.get("port_key")

    def port_label(source_name, key):
        return port_names.get((source_name, key), key)

    source_nodes = {}
    source_ids = {}
    source_names = {}
    for row in network.get("sources", []):
        name = row["name"]
        candidates = addresses.get(str(row.get("host") or ""), []) if row.get("host") else []
        configured = (row.get("driver_options") or {}).get("intent_stable_id")
        key = configured if configured in nodes else candidates[0] if len(candidates) == 1 else "observer:" + name
        kind = NETWORK_KINDS[0] if row.get("driver") == "snmp_switch" else NETWORK_KINDS[1]
        item = node(key, name, kind, row.get("site", ""), "UI_VPN")
        source_nodes[name] = key
        if row.get("id") is not None:
            source_ids[row["id"]] = key
            source_names[row["id"]] = name
        status = switch_status.get(name, {})
        raw = status.get("last_status") or row.get("last_status")
        collected_at = row.get("last_collect_at") or status.get("last_success_at")
        source(item, "Network Observer", raw, collected_at)
        direct = _host_observation(host_ips.get(row.get("host"), {}), now)
        if raw in {"ok", "success"} and row.get("enabled") and observation_is_fresh(collected_at, now):
            method = "SNMP" if row.get("driver") == "snmp_switch" else "Опрос устройства"
            item["reachability"] = _observation("reachable", "Network Observer", method, collected_at)
        elif direct:
            item["reachability"] = direct
        item["properties"]["Источник сбора"] = name
        if name in port_groups:
            ports = port_groups[name]
            latest_run = max((port["collector_run_id"] for port in ports
                              if type(port.get("collector_run_id")) is int), default=None)
            item["ports"] = [
                {"name": port.get("name") or port.get("port_key"),
                 "key": port.get("port_key"),
                 "state": "disabled" if port.get("admin_status") == "down" else port.get("oper_status"),
                 "speedBps": port.get("speed_bps"), "checkedAt": port.get("last_seen_at")}
                for port in ports if port.get("collector_run_id") == latest_run
            ]
        if "fdb_entries" in status:
            item["properties"]["Записи MAC-таблицы"] = str(status["fdb_entries"])
    features = {item["id"]: item for item in context.get("features", []) if item.get("kind") == "policy_based_ipsec"}
    segments = {item["id"]: item["cidr"] for item in context.get("segments", []) if item.get("cidr")}
    for feature_id, spec in bindings.get("ipsec_links", {}).items():
        feature = features.get(feature_id)
        remote = segments.get(spec.get("remote_segment"))
        if not feature or not remote or not feature.get("policy_destinations"):
            continue
        local_device, remote_device = feature["local_device"], feature["remote_device"]
        if (source_nodes.get(spec["local_source"]), source_nodes.get(spec["remote_source"])) != (local_device, remote_device):
            continue
        item = node(f"ipsec:{feature_id}", spec["label"], "Сервис", origin="UI_VPN")
        checks = _ipsec_policy_checks(feature, remote, spec, network.get("ipsec", {}), now)
        item["serviceChecks"] = checks
        states = {check["state"] for check in checks}
        state = "unreachable" if "unreachable" in states else "unknown" if "unknown" in states else "reachable"
        checked_at = min(check["checkedAt"] for check in checks if check["state"] == state)
        item["reachability"] = _observation(state, "MikroTik IPsec", "IPsec фаза 2", checked_at)
        for device in (local_device, remote_device):
            edge(device, item["id"], "Цель проверки", "Настройки карты")
        if probe := spec.get("connectivity"):
            path = node(f"ipsec:{feature_id}:connectivity", probe["label"], "Сервис", origin="UI_VPN")
            readings = network.get("ipsec_connectivity", {}).get(feature_id, [])
            path["serviceChecks"] = readings
            if len(readings) == 2 and all(r["state"] == "reachable" and observation_is_fresh(r["checkedAt"], now)
                                         for r in readings):
                path["reachability"] = _observation("reachable", "UI_VPN · MikroTik", "ICMP",
                                                    min(r["checkedAt"] for r in readings))
            for device in (local_device, remote_device):
                edge(device, path["id"], "Цель проверки", "Настройки карты")
    arp_mappings = _arp_mappings(network.get("arp", []), now)
    transit_segments = {segment["id"]: segment for segment in context.get("segments", [])}
    for segment_id, spec in bindings.get("transit_links", {}).items():
        segment = transit_segments.get(segment_id, {})
        router, asset = segment.get("gateway_device"), spec.get("asset")
        if not router or source_nodes.get(spec["source"]) != router or asset not in address_by_asset or asset == router:
            continue
        item = node(f"transit:{segment_id}", spec["label"], "Сервис", nodes[asset]["site"], "UI_VPN")
        item["probeTargetIP"] = None
        evidence = _transit_port(segment, spec, network, arp_mappings, now)
        if evidence:
            port, observed = evidence
            item["probeTargetIP"] = spec["peer"]
            edge(router, asset, "Транзитный сегмент", "MikroTik · ARP",
                 details=f"{segment['local_address']} ↔ {spec['peer']}", ports=(port, ""), at=observed)
        bridge = spec.get("lan_bridge")
        address = address_by_asset[asset]
        if isinstance(bridge, str) and addresses.get(address) == [asset]:
            attachment = _bridge_attachment_port(address, spec["source"], bridge, network, arp_mappings, now)
            if attachment:
                port, observed = attachment
                edge(router, asset, "Путь по MAC-таблице", "MikroTik · ARP + FDB",
                     details=f"{address} · {bridge}", ports=(port, ""), at=observed)
        for endpoint in (router, asset):
            edge(endpoint, item["id"], "Цель проверки", "Настройки карты")
    fdb_reports = []
    for row in network.get("links", []):
        a_id, b_id = row.get("source_a_id"), row.get("source_b_id")
        a, b = source_ids.get(a_id), source_ids.get(b_id)
        if not a or not b or a == b:
            continue
        for report in row.get("evidence", []):
            evidence_type = report.get("evidence_type")
            if evidence_type not in {"lldp_chassis_mac", "fdb_management_mac", "fdb_subtree"}:
                continue
            end_a, end_b = report.get("endpoint_a", {}), report.get("endpoint_b", {})
            if (end_a.get("source_id"), end_b.get("source_id")) != (a_id, b_id):
                continue
            observed = report.get("observed_at")
            confirmed = row.get("state") == "confirmed" and observation_is_fresh(observed, now)
            ports = (port_label(source_names.get(a_id), end_a.get("port_key") or ""),
                     port_label(source_names.get(b_id), end_b.get("port_key") or ""))
            if evidence_type == "lldp_chassis_mac":
                edge(a, b, "Сетевое соединение", "netctl", confirmed, ports=ports, at=observed)
            elif any(ports):
                fdb_reports.append((a, b, confirmed, ports, observed))
    fresh_lldp = [row for row in network.get("lldp", []) if observation_is_fresh(row.get("observed_at"), now)]
    peers_by_port = {}
    lldp_address_owners = {}
    for row in fresh_lldp:
        local = (row.get("source"), row.get("local_port_key"))
        chassis = str(row.get("chassis_id") or row.get("system_name") or "").casefold()
        identity = (chassis, str(row.get("port_id") or "").casefold())
        peers_by_port.setdefault(local, set()).add(identity)
        for address in row.get("management_addresses", []):
            lldp_address_owners.setdefault(address, set()).add(chassis)
    router_neighbor_macs = {}
    for row in network.get("router_neighbors", []):
        mac = str(row.get("mac") or "").lower()
        if MAC.fullmatch(mac) and observation_is_fresh(row.get("last_seen_at"), now):
            name = str(row.get("identity") or "").casefold()
            router_neighbor_macs.setdefault((name, row.get("address")), set()).add(mac)
    for row in fresh_lldp:
        a = source_nodes.get(row.get("source"))
        name = str(row.get("system_name") or "").casefold()
        candidates = [key for key in names.get(name, []) if nodes[key]["kind"] in NETWORK_KINDS]
        if a and len(candidates) == 1 and a != candidates[0]:
            neighbor, = candidates
            item = nodes[neighbor]
            raw_port = row.get("local_port_key", "")
            port = port_label(row.get("source"), raw_port)
            is_interface_name = str(row.get("port_id_subtype")) in {"1", "5", "interface_alias", "interface_name"}
            remote = row.get("port_id") if is_interface_name else ""
            chassis_mac = str(row.get("chassis_id") or "").lower()
            conflict = bool(declared_macs[neighbor] and MAC.fullmatch(chassis_mac)
                            and chassis_mac not in declared_macs[neighbor])
            direct = bool(raw_port) and len(peers_by_port[(row.get("source"), raw_port)]) == 1
            note = "" if direct else " · несколько соседей на порту"
            item["properties"]["Соседство LLDP"] = f"{nodes[a]['name']} · {port}{note}"
            if conflict:
                item["properties"]["Сопоставление LLDP"] = "MAC шасси отличается от инвентаря"
            edge(a, neighbor, "Сетевое соединение", "LLDP UI_VPN", direct and not conflict,
                 details=note.removeprefix(" · "), ports=(port, remote or ""), at=row.get("observed_at"))
            advertised = row.get("management_addresses", [])
            if len(advertised) == 1 and "Адрес управления по LLDP" not in item["properties"]:
                item["properties"]["IP заявлен в LLDP"] = advertised[0]
            if declared_devices_by_mac.get(chassis_mac) != {neighbor} or "reachability" in item:
                continue
            verified = []
            for address in advertised:
                host_mac = str(host_ips.get(address, {}).get("mac") or "").lower()
                same_identity = host_mac == chassis_mac or router_neighbor_macs.get((name, address)) == {host_mac}
                if (same_identity and fresh_macs_by_ip.get(address) == {host_mac}
                        and lldp_address_owners.get(address) == {chassis_mac}
                        and set(addresses.get(address, [])) <= {neighbor}):
                    verified.append(address)
            if len(verified) == 1:
                address, = verified
                item["properties"].pop("IP заявлен в LLDP", None)
                item["properties"]["Адрес управления по LLDP"] = address
                observation = _host_observation(host_ips[address], now)
                if observation:
                    item["reachability"] = observation

    for a, b, port_a, port_b, at in _reciprocal_lldp(network, fresh_lldp, peers_by_port, arp_mappings, now):
        edge(source_nodes.get(a), source_nodes.get(b), "Сетевое соединение", "LLDP · двустороннее",
             ports=(port_a, port_b), at=at)

    for a, b, confirmed, ports, observed in fdb_reports:
        physical = edges.get((tuple(sorted((a, b))), "Сетевое соединение"))
        if physical:
            edge(a, b, "Сетевое соединение", "netctl FDB", confirmed and physical["confirmed"],
                 ports=ports, at=observed, evidence_only=True)
        else:
            edge(a, b, "Путь по MAC-таблице", "netctl FDB", False, ports=ports, at=observed)

    for device in context.get("devices", []):
        key = device["id"]
        item = nodes[key]
        if device.get("management_ip") or "reachability" in item or item["kind"] not in NETWORK_KINDS:
            continue
        matches = {}
        for mac in declared_macs[key]:
            if declared_devices_by_mac.get(mac) != {key}:
                continue
            for host in host_macs.get(mac, []):
                address = host.get("ip")
                if (not addresses.get(address) and fresh_macs_by_ip.get(address) == {mac}
                        and observation_is_fresh(host.get("last_seen_at"), now)):
                    matches[address] = host
        if len(matches) == 1:
            address, = matches
            if address != item["properties"].get("Адрес управления по LLDP"):
                item["properties"]["IP по MAC"] = address
            observation = _host_observation(matches[address], now)
            if observation and observation["state"] == "reachable":
                item["reachability"] = observation

    guest_switch_ports = {}
    for report in network.get("guest_fdb", []):
        switch = source_ids.get(report["source_id"])
        at = report["observed_at"]
        if switch and observation_is_fresh(at, now):
            port = port_label(source_names[report["source_id"]], report["port_key"])
            guest_switch_ports.setdefault(report["mac"].lower(), []).append(
                {"id": switch, "port": port, "at": at, "vlan": report["vlan_id"]},
            )

    guest_services = {}
    roles = bindings.get("roles", {})
    for target in server.get("targets", []):
        role = target["role"]
        configured = roles.get(role, {})
        host = configured.get("asset")
        item = node("role:" + role, configured.get("label") or role, "Сервис",
                    nodes.get(host, {}).get("site", ""), "UI_VPN")
        source(item, "Server Observer", target["status"], target.get("observed_at"))
        item["sources"][-1]["stale"] = server.get("freshness") != "current"
        target_checks = target.get("checks", [])
        valid_report = role != "acti_backup" or [check["status"] for check in target_checks
                                                  if check["name"] == "watchdog_fresh"] == ["ok"]
        item["checks"] = [{"name": check["name"], "status": HEALTH.get(check["status"], "unknown")
                           if valid_report or check["name"] == "watchdog_fresh" else "unknown",
                           "observed": check.get("observed"), "latency": check.get("latency_ms")}
                          for check in target_checks]
        checked_at = target.get("observed_at")
        functional = FUNCTIONAL_CHECKS.get(role)
        if functional and valid_report and server.get("freshness") == "current" and observation_is_fresh(checked_at, now):
            check_name, method = functional
            result = next((check["status"] for check in target_checks if check["name"] == check_name), None)
            if result in {"ok", "critical", "warn"}:
                state = "reachable" if result == "ok" else "unreachable"
                item["reachability"] = _observation(state, "Server Observer", method, checked_at)
        if host:
            edge(host, item["id"], "Цель проверки", "Настройки карты")
        elif type(configured.get("vmid")) is int:
            item["probeTargetIP"] = None
            guest_services.setdefault(str(configured["vmid"]), []).append((item, configured))

    for service_id, spec in bindings.get("guest_services", {}).items():
        if service_id not in nodes:
            item = node(service_id, spec["label"], "Сервис", origin="UI_VPN")
            item["probeTargetIP"] = None
            guest_services.setdefault(str(spec["vmid"]), []).append((item, spec))

    cluster_id = ""
    hypervisors = []
    online_hypervisors = set()
    overview_guests = []
    pve_at = pve.get("at", now.isoformat())
    if pve:
        arp_checks = _verified_arp_checks(arp_mappings, host_ips, now)
        for mac, checks in network.get("guest_arp_probes", {}).items():
            arp_checks.setdefault(mac, []).extend(checks)
        cluster = next((row for row in pve["cluster"] if row.get("type") == "cluster"), {})
        cluster_id = "proxmox:cluster"
        hub = node(cluster_id, cluster.get("name", "Proxmox"), CLUSTER_KIND, origin="Proxmox")
        _proxmox_cluster_health(hub, cluster, pve["cluster"], pve_at)
        states = {check["state"] for check in hub["serviceChecks"]}
        source(hub, "Proxmox", "critical" if "unreachable" in states else "unknown" if "unknown" in states else "ok", pve_at)
        hub["reachability"] = _observation("reachable", "Proxmox", "API кластера", pve_at)
        for host in sorted(pve["nodes"], key=lambda row: row["node"]):
            key = host["node"]
            item = node(key, key, "Гипервизор", origin="Proxmox")
            hypervisors.append(key)
            online = host.get("status") == "online"
            if online:
                online_hypervisors.add(key)
                item["resources"] = {
                    "checkedAt": pve_at, "cpuRatio": host.get("cpu"), "logicalCpus": host.get("maxcpu"),
                    "memoryUsedBytes": host.get("mem"), "memoryTotalBytes": host.get("maxmem"),
                    "rootUsedBytes": host.get("disk"), "rootTotalBytes": host.get("maxdisk"),
                    "uptimeSeconds": host.get("uptime"),
                }
            label = {"online": "В сети", "offline": "Не в сети"}.get(host.get("status"), "Неизвестно")
            item["properties"]["Состояние узла"] = label
            source(item, "Proxmox", "ok" if online else "critical" if label == "Не в сети" else "unknown", pve_at, label)
            if host.get("status") in {"online", "offline"} and observation_is_fresh(pve_at, now):
                state = "reachable" if online else "unreachable"
                item.setdefault("reachability", _observation(state, "Proxmox", "Состояние узла в кластере", pve_at))
            edge(cluster_id, key, "Узел кластера", "Proxmox")
        guest_macs = {key: _guest_macs(config) for key, config in pve.get("configs", {}).items()}
        mac_counts = Counter(mac for macs in guest_macs.values() for mac in macs)
        guest_interfaces = {key: _guest_interfaces(config) for key, config in pve.get("configs", {}).items()}
        interface_mac_counts = Counter(mac for interfaces in guest_interfaces.values() for _, _, _, mac in interfaces.values())
        uplink_evidence = {}
        for guest in sorted(pve["guests"], key=lambda row: row["vmid"]):
            vmid, host = guest["vmid"], guest["node"]
            binding = bindings.get("guests", {}).get(str(vmid), {})
            asset = binding.get("asset")
            matched = asset in nodes and asset not in overview_guests and _matches_mac(
                binding.get("mac"), pve.get("configs", {}).get(str(vmid), {}),
            )
            key = asset if matched else f"pve-guest:{vmid}"
            kind = "Контейнер" if guest.get("type") == "lxc" else "Виртуальная машина"
            item = node(key, guest.get("name") or f"ВМ {vmid}", kind, origin="Proxmox")
            if matched:
                overview_guests.append(key)
                item["aliases"] = [item["name"]]
                item["name"] = guest.get("name") or item["name"]
            item.update(kind=kind, guest=True, vmid=vmid, pveHost=host)
            status, label = {
                "running": ("ok", "Запущена"), "stopped": ("warn", "Выключена"),
                "paused": ("warn", "Приостановлена"),
            }.get(guest.get("status"), ("unknown", "Неизвестно"))
            if guest.get("template"):
                status, label = "unknown", "Шаблон"
            source(item, "Proxmox", status, pve_at, label)
            item.pop("reachability", None)
            config = pve.get("configs", {}).get(str(vmid), {})
            interfaces = guest_interfaces.get(str(vmid), {})
            if observation_is_fresh(pve_at, now):
                for service, spec in guest_services.get(str(vmid), []):
                    mac = str(spec.get("mac") or "").lower()
                    if mac_counts[mac] != 1 or mac not in guest_macs.get(str(vmid), set()):
                        continue
                    edge(key, service["id"], "Размещение", "Proxmox", at=pve_at)
                    for consumer in spec.get("used_by", []):
                        if nodes.get(consumer, {}).get("kind") == "Сервис":
                            edge(consumer, service["id"], "Зависимость сервиса", "Настройки карты")
                    address = bindings.get("guest_probe_ips", {}).get(str(vmid))
                    if (status == "ok" and arp_mappings.get(address, (None,))[0] == mac
                            and any(nic_mac == mac and not disabled for _, _, disabled, nic_mac in interfaces.values())):
                        service["probeTargetIP"] = address
            if not guest.get("template") and guest.get("status") == "stopped":
                item["reachability"] = _observation("stopped", "Proxmox", "Состояние ВМ", pve_at)
            elif guest.get("status") == "running" and not guest.get("template") and observation_is_fresh(pve_at, now):
                disabled_macs = {mac for _, _, disabled, mac in interfaces.values() if disabled}
                usable_macs = guest_macs.get(str(vmid), set()) - disabled_macs
                observation = _guest_observation(usable_macs, host_macs, mac_counts, now)
                if not observation or observation["state"] != "reachable":
                    verified = [check for _, _, disabled, mac in interfaces.values()
                                if not disabled and mac in usable_macs and mac_counts[mac] == 1
                                for check in arp_checks.get(mac, [])]
                    if verified:
                        address, observation = max(verified, key=lambda pair: datetime.fromisoformat(pair[1]["checkedAt"]))
                        item["properties"]["IP проверки по ARP"] = address
                configured_nics = {name for name in config if re.fullmatch(r"net[0-9]+", name)}
                if (guest.get("type") == "qemu" and config.get("directNetworkOnly") is True
                        and interfaces and configured_nics == interfaces.keys()
                        and all(disabled for _, _, disabled, _ in interfaces.values())):
                    observation = _observation("unreachable", "Proxmox", "Все адаптеры ВМ отключены", pve_at)
                if observation:
                    item["reachability"] = observation
            item["properties"].update({"VMID": str(vmid), "Узел Proxmox": host, "Состояние ВМ": label})
            if guest.get("maxmem"):
                item["properties"]["Память (выделено)"] = _gib(guest["maxmem"])
            if status == "ok" and guest.get("mem"):
                item["properties"]["Память по Proxmox"] = _gib(guest["mem"])
            if status == "ok" and guest.get("cpu") is not None:
                item["properties"]["CPU по Proxmox"] = f"{100 * guest['cpu']:.1f}%"
            edge(host, key, "Размещение ВМ", "Proxmox", details=f"VM {vmid}", at=pve_at)
            for name, (bridge, vlan, disabled, mac) in interfaces.items():
                observed_bridge = pve.get("bridges", {}).get(host, {}).get(bridge, {})
                uplinks = [value for value in re.split(r"[\s,]+", observed_bridge.get("bridge_ports") or "")
                           if INTERFACE_NAME.fullmatch(value) and value != "none"]
                active = observed_bridge.get("active")
                switch_ports = []
                if status == "ok" and not disabled and interface_mac_counts[mac] == 1 and mac_counts[mac] == 1:
                    switch_ports = [
                        report for report in guest_switch_ports.get(mac, [])
                        if (host, report["id"], report["port"].casefold()) in verified_host_ports
                    ]
                uplink = observed_bridge.get("bridge_ports")
                if (host in online_hypervisors and active == 1 and observation_is_fresh(pve_at, now)
                        and uplink in pve.get("activePorts", {}).get(host, [])):
                    for report in switch_ports:
                        checked = min(datetime.fromisoformat(pve_at), datetime.fromisoformat(report["at"]))
                        ports = uplink_evidence.setdefault((host, report["id"], report["port"]), {})
                        ports[uplink] = max(ports.get(uplink, checked), checked)
                virtual = {"linkDisabled": disabled, "bridgeActive": bool(active) if active in (0, 1) else None,
                           "uplinks": uplinks, "switchPorts": switch_ports}
                edge(host, key, "Размещение ВМ", "Proxmox", details=f"VM {vmid}", at=pve_at,
                     ports=(bridge, name), vlan=vlan, virtual=virtual)
        locations = Counter((host, uplink) for (host, _, _), ports in uplink_evidence.items() for uplink in ports)
        for (host, switch, port), uplinks in uplink_evidence.items():
            if len(uplinks) == 1:
                (uplink, checked_at), = uplinks.items()
                if locations[(host, uplink)] == 1:
                    edge(switch, host, "Сетевое соединение", "netctl FDB + Proxmox",
                         ports=(port, uplink), at=checked_at.isoformat())
        for key, value in list(edges.items()):
            if value["kind"] == "Размещение ВМ" and value["source"] == "GitHub":
                value["confirmed"] = False

    virtual_assets = {link["endpoint_a"]["device"] for link in context.get("links", [])
                      if link.get("relation") == "virtualized_on" and link.get("state", {}).get("intent") != "absent"}
    devices_by_mac = {}
    management_ports = {}
    for device in context.get("devices", []):
        key = device["id"]
        address = device.get("management_ip")
        declared = {mac.lower() for mac in device.get("mac_addresses", []) if MAC.fullmatch(mac)}
        observed = fresh_macs_by_ip.get(address, set())
        macs = declared or (observed if len(observed) == 1 and len(addresses.get(address, [])) == 1 else set())
        for mac in macs:
            devices_by_mac.setdefault(mac, set()).add(key)
        management = pve.get("management", {}).get(key, {})
        port = management.get("port")
        arp = arp_mappings.get(address)
        if (key in online_hypervisors and observation_is_fresh(pve_at, now) and management.get("address") == address
                and len(addresses.get(address, [])) == 1 and arp and arp[0] in macs
                and isinstance(port, str) and INTERFACE_NAME.fullmatch(port)):
            management_ports[key] = (port, *arp)
    attachments = [report for report in network.get("attachments", [])
                   if observation_is_fresh(report.get("observed_at"), now)]
    locations = {}
    asset_ip_checks = bindings.get("asset_ip_checks", {})
    for report in attachments:
        locations.setdefault(report["mac"].lower(), set()).add((report["source_id"], report["port_key"]))
    for report in attachments:
        observed = report["observed_at"]
        switch = source_ids.get(report["source_id"])
        mac = report["mac"].lower()
        candidates = devices_by_mac.get(mac, set())
        if not switch or len(candidates) != 1:
            continue
        device, = candidates
        if device in virtual_assets or nodes[device].get("guest"):
            continue
        port_key = report["port_key"]
        port = port_label(source_names[report["source_id"]], port_key)
        management = management_ports.get(device)
        if management and management[1] == mac and len(locations[mac]) == 1:
            checked_at = min(datetime.fromisoformat(observed), datetime.fromisoformat(pve_at), management[2])
            edge(switch, device, "Сетевое соединение", "netctl FDB + Proxmox",
                 ports=(port, management[0]), at=checked_at.isoformat(), vlan=report["vlan_id"])
        else:
            physical = edges.get((tuple(sorted((switch, device))), "Сетевое соединение"), {})
            switch_side = "a" if physical.get("a") == switch else "b"
            matches = len(locations[mac]) == 1 and any(
                p["confirmed"] and p["source"] == "GitHub" and p[switch_side].casefold() == port.casefold()
                for p in physical.get("portEvidence", [])
            )
            kind = "Сетевое соединение" if matches else "Путь по MAC-таблице"
            edge(switch, device, kind, "netctl FDB", ports=(port, ""), at=observed,
                 vlan=report["vlan_id"], evidence_only=matches)
            target = asset_ip_checks.get(device)
            if matches and mac in declared_macs[device] and target in observed_addresses[device]:
                nodes[device]["probeTargetIP"] = target
    switch_sources = {row["name"]: row["id"] for row in network.get("sources", [])
                      if row.get("enabled") and row.get("driver") == "snmp_switch" and row.get("id") is not None}
    for asset, switch_source in bindings.get("asset_fdb_paths", {}).items():
        address = address_by_asset.get(asset)
        switch = source_nodes.get(switch_source)
        source_id = switch_sources.get(switch_source)
        if (source_id is None or not switch or addresses.get(address) != [asset] or address not in arp_mappings
                or asset in virtual_assets or nodes[asset].get("guest")):
            continue
        mac, arp_at = arp_mappings[address]
        if (declared_macs[asset] and mac not in declared_macs[asset]) or devices_by_mac.get(mac, set()) - {asset}:
            continue
        observations = [row for row in network.get("asset_fdb", [])
                        if row["source_id"] == source_id and row["mac"].lower() == mac
                        and observation_is_fresh(row["observed_at"], now)]
        ports = {row["port_key"] for row in observations}
        if len(ports) != 1:
            continue
        port, = ports
        live = [row["last_seen_at"] for row in port_groups.get(switch_source, [])
                if row["port_key"] == port and row.get("oper_status") == "up" and row.get("admin_status") != "down"
                and observation_is_fresh(row.get("last_seen_at"), now)]
        if live:
            for row in observations:
                checked = min(arp_at, datetime.fromisoformat(max(live)), datetime.fromisoformat(row["observed_at"]))
                edge(switch, asset, "Путь по MAC-таблице", "netctl FDB", details=address,
                     ports=(port_label(switch_source, port), ""), at=checked.isoformat(), vlan=row["vlan_id"])
    for report in network.get("lacp", []):
        asset = report["asset"]
        address = address_by_asset.get(asset)
        switch = source_nodes.get(report["source"])
        if (not switch or nodes[switch]["kind"] != NETWORK_KINDS[0] or not address
                or addresses[address] != [asset] or address not in arp_mappings
                or not observation_is_fresh(report["at"], now)):
            continue
        mac, arp_at = arp_mappings[address]
        if declared_macs[asset] and mac not in declared_macs[asset]:
            continue
        matching = [member for member in report["members"] if member["mac"] == mac]
        peer_counts = Counter(member["partner_port"] for member in matching)
        confirmed = [member for member in matching if peer_counts[member["partner_port"]] == 1]
        checked_at = min(arp_at, datetime.fromisoformat(report["at"])).isoformat()
        for member in confirmed:
            edge(switch, asset, "Сетевое соединение", "SNMP LACP + ARP", at=checked_at,
                 details=f"LACP: подтверждено {len(confirmed)} из {report['expected']} портов",
                 ports=(f"{report['aggregate']} / {member['port']}", f"LACP {member['partner_port']}"))
    for key, observation in network.get("asset_mac_checks", {}).items():
        if key in nodes and observation_is_fresh(observation["checkedAt"], now):
            nodes[key].setdefault("reachability", observation)
            nodes[key].setdefault("serviceChecks", []).append(observation)
    _reconcile_fdb_ports(edges.values())
    _corroborate_fdb_ports(edges.values(), nodes, now)
    _add_guest_switch_uplinks(edges.values(), nodes, pve, now)
    management_sightings = {}
    for row in network.get("switch_management_fdb", []):
        source_id = row["source_id"]
        local, remote = source_ids.get(source_id), source_ids.get(row["peer_source_id"])
        if local and remote and local != remote and observation_is_fresh(row["observed_at"], now):
            port = port_label(source_names[source_id], row["port_key"])
            management_sightings.setdefault((local, remote), []).append((port, datetime.fromisoformat(row["observed_at"])))
    for a, b, ports, at in list(_reciprocal_management_paths(edges.values(), nodes, management_sightings, now)):
        edge(a, b, "Путь по MAC-таблице", RECIPROCAL_MAC_SOURCE, ports=ports, at=at,
             details="Оба коммутатора видят MAC управления друг друга")
    return {"schema": 1, "snapshotAt": now.isoformat(), "nodes": list(nodes.values()),
            "links": list(edges.values()), "clusterId": cluster_id, "nodeOrder": hypervisors,
            "overviewGuests": overview_guests}


def _matches_mac(expected: str | None, config: dict) -> bool:
    return isinstance(expected, str) and expected.lower() in _guest_macs(config)


def _gib(value: int) -> str:
    return f"{value / 1024**3:.2f} ГиБ"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_proxmox(url: str, token_file: Path, ca_file: Path | None, guests: set[str],
                 management_bridges: dict[str, str] | None = None) -> dict:
    origin = urlsplit(url)
    if origin.scheme != "https" or not origin.hostname or origin.username or origin.path not in ("", "/") or origin.query or origin.fragment:
        raise ValueError("Proxmox requires an HTTPS origin")
    token = token_file.read_text(encoding="utf-8").strip()
    if not token.startswith("PVEAPIToken=") or any(char.isspace() for char in token):
        raise ValueError("invalid Proxmox token format")
    opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def get(path):
        request = Request(url.rstrip("/") + "/api2/json/" + path, headers={"Authorization": token})
        with opener.open(request, timeout=8) as response:
            payload = response.read(MAX_SNAPSHOT_BYTES + 1)
        if len(payload) > MAX_SNAPSHOT_BYTES:
            raise ValueError("Proxmox response exceeds limit")
        return json.loads(payload)["data"]

    result = {"cluster": get("cluster/status"), "nodes": get("cluster/resources?type=node"),
              "guests": get("cluster/resources?type=vm"), "configs": {}, "bridges": {}}
    def read_guest(guest):
        key = str(guest["vmid"])
        node = quote(guest["node"], safe="")
        try:
            config = get(f"nodes/{node}/{guest['type']}/{int(key)}/config?current=1")
        except (URLError, TimeoutError):
            return key, {}
        network = {name: value for name, value in config.items() if re.fullmatch(r"net[0-9]+", name)}
        if guest["type"] == "qemu":
            network["directNetworkOnly"] = not any(
                re.fullmatch(r"args|hookscript|(?:hostpci|usb)[0-9]+", name) for name in config
            )
        return key, network

    def read_interface(node, interface):
        try:
            data = get(f"nodes/{quote(node, safe='')}/network/{quote(interface, safe='')}")
        except (URLError, TimeoutError):
            return {}
        return data if isinstance(data, dict) else {}

    def read_bridge(pair):
        node, bridge = pair
        data = read_interface(node, bridge)
        if data.get("type") not in ("bridge", "OVSBridge"):
            return node, bridge, {}
        return node, bridge, {key: data.get(key) for key in ("active", "bridge_ports", "address")}

    def read_physical_port(pair):
        node, port = pair
        interface = read_interface(node, port)
        return node, port, interface.get("type") == "eth" and interface.get("active") == 1

    candidates = [guest for guest in result["guests"] if guest["type"] in {"qemu", "lxc"}
                  and (str(guest["vmid"]) in guests or guest.get("status") == "running")]
    with ThreadPoolExecutor(max_workers=6) as pool:
        result["configs"] = dict(pool.map(read_guest, candidates))
        used_bridges = {(guest["node"], bridge) for guest in candidates
                        for bridge, _, _, _ in _guest_interfaces(result["configs"][str(guest["vmid"])]).values()}
        management = {(row["node"], bridge) for row in result["nodes"] if row.get("status") == "online"
                      for bridge in [(management_bridges or {}).get(row["node"])]
                      if isinstance(bridge, str) and INTERFACE_NAME.fullmatch(bridge)}
        used_bridges.update(management)
        for node, bridge, data in pool.map(read_bridge, sorted(used_bridges)):
            if data:
                result["bridges"].setdefault(node, {})[bridge] = data
        physical_candidates = {(node, port) for node, bridges in result["bridges"].items() for data in bridges.values()
                               for port in [data.get("bridge_ports")] if data.get("active") == 1
                               and isinstance(port, str) and INTERFACE_NAME.fullmatch(port)}
        active_ports = {}
        for node, port, active in pool.map(read_physical_port, sorted(physical_candidates)):
            if active:
                active_ports.setdefault(node, []).append(port)
        result["activePorts"] = active_ports
        result["management"] = {}
        for node, bridge in management:
            data = result["bridges"].get(node, {}).get(bridge, {})
            if data.get("active") == 1 and data.get("bridge_ports") in active_ports.get(node, []):
                result["management"][node] = {"address": data.get("address"), "port": data["bridge_ports"]}
    result["at"] = datetime.now(timezone.utc).isoformat()
    return result


def _switch_management_fdb(connection, sources: list[dict]) -> list[dict]:
    enabled = {row["id"] for row in sources if row.get("enabled") and row.get("driver") == "snmp_switch"}
    if not enabled:
        return []
    owners = {}
    for identity in list_source_identities(connection):
        for mac in identity.management_macs:
            owners.setdefault(mac.lower(), set()).add(identity.source_id)
    unique = {mac: next(iter(ids)) for mac, ids in owners.items() if len(ids) == 1 and ids <= enabled}
    return [{**row, "peer_source_id": unique[row["mac"].lower()]}
            for row in query_observed_mac_ports(connection, set(unique), learned_only=True)
            if row["source_id"] in enabled and row["source_id"] != unique[row["mac"].lower()]]


def read_network(guest_macs: set[str] | None = None, route_sources: set[str] | None = None,
                 transit_sources: set[str] | None = None, *, asset_fdb_ips: set[str] | None = None) -> dict:
    commands = {
        "switches": (["switches", "status"], "switches"),
        "links": (["topology", "links"], "links"),
    }
    with closing(connect_read_only(DEFAULT_DB_URL)) as connection:
        data = {"sources": list_sources(connection), "attachments": query_confirmed_attachment_ports(connection)}
        data["switch_management_fdb"] = _switch_management_fdb(connection, data["sources"])
        data["router_neighbors"] = [dict(row) for row in connection.execute(
            """
            SELECT n.identity, n.address, n.mac, n.last_seen_at
            FROM network_neighbors AS n
            JOIN network_sources AS s ON s.id = n.source_id
            WHERE s.enabled = 1 AND s.driver IN ('mikrotik_api', 'mikrotik_ssh')
            """
        )]
        if guest_macs:
            data["guest_fdb"] = query_observed_mac_ports(connection, guest_macs)
        data["arp"] = [dict(row) for row in connection.execute(
            """
            SELECT a.ip, a.mac, a.interface, a.last_seen_at, s.name AS source
            FROM arp_entries AS a
            JOIN network_sources AS s ON s.id = a.source_id
            WHERE s.enabled = 1 AND s.driver IN ('mikrotik_api', 'mikrotik_ssh')
              AND a.complete = 1 AND a.dynamic = 1
            """
        )]
        if asset_fdb_ips:
            macs = {row["mac"].lower() for row in data["arp"] if row["ip"] in asset_fdb_ips and row["mac"]}
            data["asset_fdb"] = query_observed_mac_ports(connection, macs)
        if route_sources:
            data["routes"] = [dict(row) for row in connection.execute(
                """
                SELECT s.name AS source, r.dst_address, r.gateway, r.routing_table,
                       r.immediate_gateway, r.active, r.disabled, r.dynamic, r.route_type, r.last_seen_at
                FROM network_routes AS r
                JOIN network_sources AS s ON s.id = r.source_id
                WHERE s.enabled = 1 AND s.name IN (SELECT value FROM json_each(?))
                """,
                (json.dumps(sorted(route_sources)),),
            )]
        if transit_sources:
            data["router_interfaces"] = [dict(row) for row in connection.execute(
                """
                SELECT s.name AS source, i.name, i.type, i.running, i.disabled, i.last_seen_at
                FROM network_interfaces AS i
                JOIN network_sources AS s ON s.id = i.source_id
                WHERE s.enabled = 1 AND s.name IN (SELECT value FROM json_each(?))
                """,
                (json.dumps(sorted(transit_sources)),),
            )]
            data["router_bridge_hosts"] = [dict(row) for row in connection.execute(
                """
                SELECT s.name AS source, b.mac, b.bridge, b.interface, b.last_seen_at
                FROM bridge_hosts AS b
                JOIN network_sources AS s ON s.id = b.source_id
                WHERE s.enabled = 1 AND b.dynamic = 1 AND b.local = 0
                  AND s.name IN (SELECT value FROM json_each(?))
                """,
                (json.dumps(sorted(transit_sources)),),
            )]
    data.update({name: run_netctl(args, timeout=15)[key] for name, (args, key) in commands.items()})
    try:
        data["hosts"] = run_netctl(["hosts", "export", "--status", "all"], timeout=25)["hosts"]
    except NetctlError:
        data["hosts"] = []
    for query, key in (("ports", "ports"), ("lldp", "lldp_neighbors")):
        items = data[query] = []
        offset = 0
        for _ in range(20):
            result = run_netctl(["switches", query, "--limit", "500", "--offset", str(offset)], timeout=15)
            items.extend(result[key])
            next_offset = result["pagination"]["next_offset"]
            if next_offset is None:
                break
            if type(next_offset) is not int or next_offset <= offset:
                raise ValueError("invalid switch inventory pagination")
            offset = next_offset
        else:
            raise ValueError("switch inventory exceeds collection limit")
    return data


def publish_snapshot(path: Path, graph: dict) -> None:
    body = json.dumps(graph, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(body) > MAX_SNAPSHOT_BYTES:
        raise ValueError("infrastructure snapshot exceeds limit")
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            temporary.chmod(0o640)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--server-health", type=Path, required=True)
    parser.add_argument("--bindings", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--git-revision", default="")
    pve_input = parser.add_mutually_exclusive_group()
    pve_input.add_argument("--proxmox-url")
    pve_input.add_argument("--proxmox-export", type=Path)
    parser.add_argument("--proxmox-token-file", type=Path)
    parser.add_argument("--proxmox-ca", type=Path)
    args = parser.parse_args()
    if args.proxmox_url and not args.proxmox_token_file:
        parser.error("--proxmox-url requires --proxmox-token-file")
    try:
        context_raw = args.context.read_bytes()
        context = load_context_bytes(context_raw)
        if validate_context(context, load_schema(args.schema)):
            raise ValueError("network context did not validate")
        bindings = json.loads(args.bindings.read_text(encoding="utf-8")) if args.bindings else {}
        pve = {}
        if args.proxmox_url:
            guest_ids = set(bindings.get("guests", {}))
            guest_ids.update(str(service["vmid"]) for service in bindings.get("guest_services", {}).values())
            guest_ids.update(str(role["vmid"]) for role in bindings.get("roles", {}).values()
                             if type(role.get("vmid")) is int and not role.get("asset"))
            pve = read_proxmox(args.proxmox_url, args.proxmox_token_file, args.proxmox_ca, guest_ids,
                               bindings.get("hypervisor_management_bridges"))
        elif args.proxmox_export:
            pve = json.loads(args.proxmox_export.read_text(encoding="utf-8"))
            if not pve.get("at"):
                raise ValueError("Proxmox export requires observation time")
        guest_macs = {mac for config in pve.get("configs", {}).values() for mac in _guest_macs(config)}
        route_sources = {item["source"] for item in bindings.get("route_evidence", {}).values() if item.get("source")}
        lacp_links = bindings.get("lacp_links", [])
        transit_links = bindings.get("transit_links", {})
        transit_sources = {spec["source"] for spec in transit_links.values()}
        asset_fdb_paths = bindings.get("asset_fdb_paths", {})
        asset_fdb_ips = {device["management_ip"] for device in context.get("devices", [])
                         if device["id"] in asset_fdb_paths and device.get("management_ip")}
        network = read_network(guest_macs, route_sources | transit_sources, transit_sources, asset_fdb_ips=asset_fdb_ips)
        if lacp_links:
            network["lacp"] = asyncio.run(_collect_lacp(network, lacp_links, datetime.now(timezone.utc)))
        if bindings.get("ipsec_links"):
            network["ipsec"] = _collect_ipsec_policies(network["sources"], bindings["ipsec_links"])
            network["ipsec_connectivity"] = _collect_ipsec_connectivity(context, network["sources"], bindings["ipsec_links"])
        network["guest_arp_probes"] = _collect_guest_arp_probes(
            pve, network, bindings.get("guest_probe_ips", {}), datetime.now(timezone.utc),
            bindings.get("guest_router_arp_sources"),
        )
        network["asset_mac_checks"] = _collect_asset_mac_probes(
            context, network["sources"], bindings.get("asset_mac_probes", {}),
        )
        now = datetime.now(timezone.utc)
        graph = build_graph(context, network, build_server_health_view(args.server_health, now), pve, bindings, now)
        probes = {**bindings.get("service_probes", {}),
                  **{asset: [{"type": "icmp", "ip": address}]
                     for asset, address in bindings.get("asset_ip_checks", {}).items()},
                  **{f"transit:{segment}": [{"type": "icmp", "ip": spec["peer"]}]
                     for segment, spec in transit_links.items()}}
        apply_service_probes(graph["nodes"], probes)
        graph["snapshotAt"] = datetime.now(timezone.utc).isoformat()
        graph["git"] = args.git_revision
        graph["contextSha256"] = hashlib.sha256(context_raw).hexdigest()
        publish_snapshot(args.output, graph)
    except Exception as exc:
        parser.exit(1, f"Снимок инфраструктуры не обновлён ({type(exc).__name__}).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
