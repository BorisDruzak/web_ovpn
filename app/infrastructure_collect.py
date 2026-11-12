"""Build the infrastructure snapshot outside the web request lifecycle."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from time import sleep
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from netctl.config import DEFAULT_DB_URL, load_secrets
from netctl.context import load_context_bytes, load_schema, validate_context
from netctl.db import list_sources, read_context_snapshot
from netctl.drivers import legacy_driver_for
from netctl.snmp.interfaces import read_interface_link
from netctl.snmp.lacp import read_lacp_members
from netctl.snmp.stp import read_stp_designated_ports, read_stp_root_path
from netctl.snmp.transport import SnmpTransport
from netctl.source_identity import list_source_identities
from netctl.switch_queries import (
    FDB_PORT_MATCH, query_confirmed_attachment_ports, query_observed_mac_ports,
    query_switch_lldp_neighbors, query_switch_ports,
)

from .infrastructure_backup import backup_policy, backup_service_checks, read_proxmox_backup
from .infrastructure_map import (
    BACKUP_PROBE_METHOD, BACKUP_SERVICE_ID, GUEST_IO_MAX_AGE,
    CLUSTER_HEALTH_METHODS, CLUSTER_KIND, INTERFACE_NAME, MAX_DOWNSTREAM_SWITCHES, MAX_ROUTER_NEIGHBORS,
    MAX_SNAPSHOT_BYTES, NETWORK_KINDS,
    PVE_DISK_DEVICE, PVE_STORAGE_ID, RECIPROCAL_MAC_SOURCE,
    SHARED_LLDP_KIND, SHARED_LLDP_SOURCE, STP_ROOT_PATH_MAX_AGE,
    index_port_states, observation_is_fresh, port_label_key,
    project_hypervisor_disks, project_hypervisor_lvm_thin, project_hypervisor_zfs,
)
from .infrastructure_port_ssh import collect_proxmox_port_states
from .infrastructure_service_probes import apply_service_probes, probe_icmp
from .netctl_client import NetctlError, run_netctl
from .server_health_view import build_server_health_view

KINDS = {
    "switch": NETWORK_KINDS[0], "router": NETWORK_KINDS[1],
    "wireless_access_point": NETWORK_KINDS[2], "hypervisor": "Гипервизор",
    "endpoint": "Рабочая станция", "firewall_dns_host": "Межсетевой экран и DNS",
    "security_gateway": "Шлюз", "ip_pbx": "АТС", "fxs_gateway": "Телефонный шлюз",
    "management_controller": "Контроллер управления",
    "video_recorder": "Видеорегистратор",
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


def _guest_disks(config: dict, guest_type: str) -> list[dict]:
    disks = []
    volume_key = "volume" if guest_type == "lxc" else "file"
    for device, raw in config.items():
        if not PVE_DISK_DEVICE.fullmatch(device) or not isinstance(raw, str):
            continue
        is_mount = device == "rootfs" or device.startswith("mp")
        if is_mount != (guest_type == "lxc"):
            continue
        parts = raw.split(",")
        options = dict(part.split("=", 1) for part in parts if "=" in part)
        reference = options.get(volume_key, parts[0] if "=" not in parts[0] else "")
        storage, _, volume = reference.partition(":")
        if (not PVE_STORAGE_ID.fullmatch(storage) or not volume or volume.isdecimal()
                or volume.startswith(("/", "iso/")) or options.get("media") == "cdrom"
                or re.fullmatch(r"(?:vm-[0-9]+-)?cloudinit(?:\.[a-z0-9]+)?", volume.rsplit("/", 1)[-1])):
            continue
        disk = {"device": device, "storage": storage}
        size = re.fullmatch(r"([0-9]{1,16}(?:\.[0-9]{1,6})?)([KMGTPE]?)", options.get("size", ""))
        if size:
            power = ("", "K", "M", "G", "T", "P", "E").index(size[2])
            size_bytes = Decimal(size[1]) * 1024**power
            if 0 < size_bytes < 2**53 and size_bytes == int(size_bytes):
                disk["sizeBytes"] = int(size_bytes)
        disks.append(disk)
    return sorted(disks, key=lambda disk: (disk["device"] != "rootfs", disk["device"]))


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


async def _collect_stp_observations(sources: list[dict], switches: list[dict], now: datetime) -> tuple[dict, dict]:
    profiles = {"css326": read_stp_root_path, "snr": read_stp_designated_ports}
    observed_profiles = {row["source"]: row.get("profile_id") for row in switches
                         if observation_is_fresh(row.get("last_success_at"), now)}
    eligible = [(source, (source.get("driver_options") or {}).get("profile_hint") or observed_profiles.get(source["name"]))
                for source in sources
                if source.get("enabled") and source.get("driver") == "snmp_switch"]
    eligible = [(source, profile) for source, profile in eligible if profile in profiles]

    async def read(source, profile):
        try:
            async with asyncio.timeout(5), SnmpTransport.from_source(source) as transport:
                observation = await profiles[profile](transport)
        except (TimeoutError, OSError, ValueError):
            return {}
        if not observation:
            return {}
        sample = observation if profile == "css326" else {"ports": observation}
        return {**sample, "checkedAt": datetime.now(timezone.utc).isoformat()}

    observations = await asyncio.gather(*(read(source, profile) for source, profile in eligible))
    roots, designated = {}, {}
    for (source, profile), observation in zip(eligible, observations):
        if observation:
            target = roots if profile == "css326" else designated
            target[source["name"]] = observation
    return roots, designated


async def _check_declared_switch_ports(context: dict, network: dict, pve: dict, now: datetime) -> None:
    host_ports = {(host, port["name"]) for host, ports in pve.get("physicalPorts", {}).items()
                  for port in ports if port.get("source") == "Proxmox · sysfs"}
    switches = {row["id"]: row.get("management_ip") for row in context.get("devices", []) if row["kind"] == "switch"}
    sources = [row for row in network.get("sources", []) if row.get("enabled") and row.get("driver") == "snmp_switch"]
    address_counts = Counter(row.get("host") for row in sources)
    sources = {row["host"]: row for row in sources if row.get("host") and address_counts[row["host"]] == 1}
    rows_by_source = {}
    for row in network.get("ports", []):
        rows_by_source.setdefault(row["source"], []).append(row)
    candidates = {}
    for address, source in sources.items():
        ports = rows_by_source.get(source["name"], [])
        latest = max((row["collector_run_id"] for row in ports if type(row.get("collector_run_id")) is int), default=None)
        if latest is None:
            continue
        current = [row for row in ports if row.get("collector_run_id") == latest]
        indexes = Counter(row.get("if_index") for row in current)
        labels = index_port_states([
            {"name": row.get("name"), "key": row.get("port_key"), "checkedAt": row.get("last_seen_at")}
            for row in current
        ], now)
        by_name = {
            port_label_key(row["name"]): row for row in current
            if row.get("name") and type(row.get("if_index")) is int and 1 <= row["if_index"] <= 2_147_483_647
            and indexes[row["if_index"]] == 1
        }
        candidates[address] = {label: by_name[port_label_key(port["name"])] for label, port in labels.items()
                               if port_label_key(port["name"]) in by_name}
    checks = {}
    pending = {}
    for link in context.get("links", []):
        vlan = link.get("vlan")
        state = link.get("state", {})
        if (link.get("relation") != "connected_to" or state.get("intent") == "absent"
                or (isinstance(vlan, dict) and vlan.get("mode") == "tagged_transit")):
            continue
        ends = [(switches.get(end["device"]), port_label_key(end.get("interface") or ""), end)
                for end in (link["endpoint_a"], link["endpoint_b"])]
        available = [candidates.get(address, {}).get(label) for address, label, _ in ends]
        if state.get("verified") is True:
            if not all(row is not None or (end["device"], end.get("interface")) in host_ports
                       for row, (_, _, end) in zip(available, ends)):
                continue
            target = checks
        else:
            target = pending
        for row, (address, _, _) in zip(available, ends):
            if row is not None:
                target.setdefault(address, {})[row["if_index"]] = row

    for address, rows in pending.items():
        wanted = checks.setdefault(address, {})
        new_ports = [(index, row) for index, row in rows.items() if index not in wanted]
        wanted.update(new_ports[:8])

    async def check(source, wanted):
        try:
            async with asyncio.timeout(6), SnmpTransport.from_source(source) as transport:
                for index, row in wanted.items():
                    try:
                        observation = await read_interface_link(transport, index, row["name"])
                    except ValueError:
                        continue
                    if observation:
                        row["linkCheck"] = {**observation, "checkedAt": datetime.now(timezone.utc).isoformat()}
        except (TimeoutError, OSError, ValueError):
            pass

    await asyncio.gather(*(check(sources[address], wanted) for address, wanted in checks.items()))


def _probe_on_link_mac(address: str, mac: str, *, fresh_only: bool = False) -> bool:
    def ip_query(*args):
        return json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", *args], timeout=2))

    try:
        routes = ip_query("route", "get", address)
        if len(routes) != 1 or routes[0].get("gateway") or routes[0].get("via") or not routes[0].get("dev"):
            return False
        if not probe_icmp(address):
            return False
        query = ("neigh", "show", "to", address, "dev", routes[0]["dev"])

        def states() -> set[str]:
            return {state for row in ip_query(*query) if row.get("dst") == address
                    and str(row.get("lladdr", "")).lower() == mac for state in row.get("state", [])}

        observed = states()
        pending = {"DELAY", "PROBE"}
        if fresh_only and "REACHABLE" not in observed and observed & pending:
            # Allow Linux to complete neighbor revalidation after sending to a cached MAC.
            sleep(6)
            observed = states()
        accepted = {"REACHABLE"} if fresh_only else {"REACHABLE"} | pending
        return bool(observed & accepted)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


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
                              router_sources: dict | None = None, *, auto_on_link: bool = False) -> dict:
    configs = pve.get("configs", {})
    counts = Counter(mac for config in configs.values() for mac in _guest_macs(config))
    arp_rows = network.get("arp", [])
    arp = _arp_mappings(arp_rows, now)
    candidates = []
    automatic = []
    addresses_by_mac = {}
    if auto_on_link and observation_is_fresh(pve.get("at"), now):
        for address, (mac, _) in arp.items():
            try:
                address = str(ipaddress.IPv4Address(address))
            except ValueError:
                continue
            addresses_by_mac.setdefault(mac, set()).add(address)
    for guest in pve.get("guests", []):
        vmid = str(guest["vmid"])
        if guest.get("status") != "running" or guest.get("template"):
            continue
        interfaces = _guest_interfaces(configs.get(vmid, {}))
        usable = {mac for _, _, disabled, mac in interfaces.values() if not disabled and counts[mac] == 1}
        if vmid not in configured:
            matches = {(address, mac) for mac in usable for address in addresses_by_mac.get(mac, ())}
            if len(matches) == 1:
                address, mac = matches.pop()
                automatic.append((vmid, address, mac))
            continue
        try:
            address = str(ipaddress.IPv4Address(configured[vmid]))
        except (TypeError, ValueError):
            continue
        if address not in arp:
            continue
        mac, _ = arp[address]
        if mac in usable:
            candidates.append((vmid, address, mac))

    def check(candidate):
        vmid, address, mac = candidate
        if _probe_on_link_mac(address, mac):
            return mac, address, _observation("reachable", "UI_VPN", "ICMP · ARP", datetime.now(timezone.utc).isoformat())
        name = (router_sources or {}).get(vmid) if vmid in configured else None
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
        for result in pool.map(check, candidates + automatic[:48]):
            if result:
                mac, address, observation = result
                checks.setdefault(mac, []).append((address, observation))
    return checks


def _route_checks(intent: dict, source: str, routes: list[dict], now: datetime, *, host_routes: object = None) -> list[dict]:
    gateway = intent.get("next_hop")
    table = intent.get("routing_table", "main")
    rejecting_types = {"blackhole", "unreachable", "prohibit"}
    destinations = list(dict.fromkeys(intent.get("destinations", [])[:12]))
    if isinstance(host_routes, list):
        scopes = [ipaddress.ip_network(destination) for destination in destinations]
        for raw in host_routes[:4]:
            if not isinstance(raw, str):
                continue
            try:
                host = ipaddress.ip_network(raw)
            except ValueError:
                continue
            if (host.prefixlen == host.max_prefixlen and str(host) not in destinations
                    and any(host.version == scope.version and host.subnet_of(scope) for scope in scopes)):
                destinations.append(str(host))
    checks = []
    for destination in destinations[:12]:
        scoped = [
            row for row in routes
            if row.get("source") == source and row.get("routing_table") == table
            and row.get("dst_address") == destination and isinstance(row.get("last_seen_at"), str)
        ]
        checked_at = max((row["last_seen_at"] for row in scoped), default=None)
        check = {
            "state": "unknown", "source": "Network Observer",
            "method": "Маршрут", "target": destination, "via": gateway,
            "checkedAt": checked_at, "required": True, "component": True,
        }
        checks.append(check)
        if not observation_is_fresh(checked_at, now):
            continue
        latest = [row for row in scoped if row["last_seen_at"] == checked_at]
        active = [row for row in latest if row.get("active") == 1 and row.get("disabled") == 0]
        active_types = {row.get("route_type", "unicast") for row in active}
        if active_types == {"unicast"}:
            active_gateways = {row.get("gateway") for row in active}
            if len(active_gateways) > 1:
                check["reason"] = "route_multiple_gateways"
            elif active_gateways == {gateway}:
                check["state"] = "reachable"
            elif len(active_gateways) == 1:
                observed, = active_gateways
                try:
                    observed = str(ipaddress.ip_address(observed))
                except ValueError:
                    continue
                check.update(state="unreachable", reason="route_other_gateway", observedVia=observed)
        elif active_types and active_types <= rejecting_types:
            check.update(state="unreachable", reason="route_rejecting")
        elif not active and any(row.get("gateway") == gateway and
                                (row.get("active") == 0 or row.get("disabled") == 1) for row in latest):
            check.update(state="unreachable", reason="route_inactive")
    return checks


def _inventory_ipv4_interface(device: dict, address: str, now: datetime) -> tuple[str, str] | None:
    state = device.get("observed_state")
    rows = state.get("ipv4_interfaces") if isinstance(state, dict) else None
    matches = []
    for row in rows[:32] if isinstance(rows, list) else ():
        if not isinstance(row, dict):
            continue
        name, observed, interface_address = row.get("name"), row.get("observed_at"), row.get("address")
        if (not isinstance(name, str) or not INTERFACE_NAME.fullmatch(name)
                or not isinstance(observed, str) or not isinstance(interface_address, str)):
            continue
        try:
            stamp = datetime.fromisoformat(observed)
            if stamp.tzinfo is None or stamp > now or str(ipaddress.IPv4Interface(interface_address).ip) != address:
                continue
            matches.append((name, stamp.astimezone(timezone.utc).isoformat()))
        except (OverflowError, ValueError):
            continue
    return matches[0] if len(matches) == 1 else None


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
        key: index_port_states(node.get("ports", []), now)
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
        names = []
        stamps = []
        for local, remote in (("a", "b"), ("b", "a")):
            index = active[link[local]]
            port = index.get(port_label_key(pair[local]))
            sightings = [row for row in reports if row["source"] == "netctl FDB" and row[local]
                         and observation_is_fresh(row["at"], now)]
            observed_names = {index.get(port_label_key(row[local]), {}).get("name") for row in sightings}
            if not port or port["state"] != "up" or observed_names != {port["name"]}:
                break
            one_sided = [datetime.fromisoformat(row["at"]) for row in sightings if row["confirmed"] and not row[remote]]
            if not one_sided:
                break
            names.append(port["name"])
            stamps.extend((datetime.fromisoformat(port["checkedAt"]), max(one_sided)))
        else:
            reports.append({"a": names[0], "b": names[1], "source": "SNMP · двусторонний FDB",
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
    mac_paths = {}
    mac_path_owners = {}
    for link in links:
        if not link["confirmed"] or link["kind"] not in {"Сетевое соединение", "Путь по MAC-таблице"}:
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
                hypervisor_port = (
                    source == "netctl FDB + Proxmox" and endpoint[1] and nodes[peer]["kind"] == "Гипервизор"
                )
                evidence = {"id": switch, "port": report[local], "at": report["at"]}
                if link["kind"] == "Путь по MAC-таблице":
                    if hypervisor_port:
                        mac_path_owners.setdefault(switch_port, set()).add(endpoint)
                        mac_paths.setdefault(endpoint, {})[switch_port] = {**evidence, "viaMacTable": True}
                    continue
                owners.setdefault(switch_port, set()).add(endpoint)
                if hypervisor_port:
                    candidates.setdefault(endpoint, {})[switch_port] = evidence

    guest_states = {(row["node"], row["vmid"]): row.get("status") for row in pve.get("guests", [])
                    if not row.get("template")}
    for link in links:
        host, guest = link["a"], link["b"]
        guest_state = guest_states.get((host, nodes[guest].get("vmid")))
        if (not link["confirmed"] or link["kind"] != "Размещение ВМ"
                or guest_state not in {"running", "stopped", "paused", "prelaunch"}):
            continue
        for report in link.get("portEvidence", []):
            virtual = report.get("virtual")
            if (not virtual or not report["confirmed"] or not observation_is_fresh(report["at"], now)
                    or not virtual["bridgeActive"] or virtual["switchPorts"]):
                continue
            bridge = pve.get("bridges", {}).get(host, {}).get(report["a"], {})
            uplink = bridge.get("bridge_ports")
            if not isinstance(uplink, str) or virtual["uplinks"] != [uplink] or uplink not in pve.get("activePorts", {}).get(host, []):
                continue
            endpoint = (host, uplink.casefold())
            paths = candidates.get(endpoint) or mac_paths.get(endpoint, {})
            if len(paths) != 1:
                continue
            (switch_port, evidence), = paths.items()
            if owners.get(switch_port, {endpoint}) != {endpoint}:
                continue
            if evidence.get("viaMacTable") and mac_path_owners[switch_port] != {endpoint}:
                continue
            checked_at = min(datetime.fromisoformat(stamp) for stamp in (evidence["at"], report["at"]))
            virtual["switchUplink"] = {**evidence, "at": checked_at.isoformat()}
            if guest_state != "running" or virtual["linkDisabled"]:
                virtual["switchUplink"]["configuredOnly"] = True


def _local_vlan_probe_specs(context: dict, configured: object) -> dict:
    specs = {}
    if not isinstance(configured, dict):
        return specs
    for link in context.get("links", []):
        link_id = link.get("id")
        if not isinstance(link_id, str):
            continue
        local = configured.get(link_id)
        vlan = link.get("vlan", {})
        state = link.get("state", {})
        if (not local or link.get("relation") != "connected_to" or not isinstance(vlan, dict) or vlan.get("mode") != "tagged_transit"
                or state.get("verified") is not True or state.get("intent") == "absent"):
            continue
        left, right = link["endpoint_a"], link["endpoint_b"]
        here, peer = (right, left) if right["device"] == local else (left, right)
        name, vlan_id = here.get("interface"), vlan.get("id")
        if (here["device"] != local or here["device"] == peer["device"]
                or not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)
                or type(vlan_id) is not int or not 1 <= vlan_id <= 4094):
            continue
        try:
            source = ipaddress.IPv4Interface(here.get("address"))
            destination = ipaddress.IPv4Interface(peer.get("address"))
        except ValueError:
            continue
        if source.ip != destination.ip and source.network == destination.network:
            specs[f"transit:{link_id}"] = {"type": "vlan_transit", "interface": name, "vlan": vlan_id,
                                          "address": str(source), "ip": str(destination.ip),
                                          "localAsset": local, "peerAsset": peer["device"]}
    return specs


def _wireguard_probe_specs(context: dict, configured: object, vlans: dict) -> dict:
    if not isinstance(configured, list):
        return {}
    specs = {}
    for intent in context.get("routing_intent", []):
        key = intent.get("id")
        if not isinstance(key, str) or key not in configured or intent.get("status") != "active_verified":
            continue
        ingress, interface = intent.get("ingress_interface"), intent.get("default_interface")
        mark, table = intent.get("mark"), intent.get("routing_table")
        if (not all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) for name in (ingress, interface))
                or not isinstance(mark, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", mark)
                or type(table) is not int or not 1 <= table <= 0xffffffff):
            continue
        matches = [(service, vlan) for service, vlan in vlans.items()
                   if vlan["localAsset"] == intent.get("source_device") and vlan["interface"] == ingress]
        if len(matches) == 1:
            service, vlan = matches[0]
            specs[f"policy:{key}"] = {"type": "wireguard_policy", "interface": interface, "ingress": ingress,
                                     "mark": int(mark, 16), "table": table, "peer": vlan["ip"],
                                     "report": "/run/openvpn-policy-observer/latest.json",
                                     "localAsset": vlan["localAsset"], "transitService": service}
    return specs


def _downstream_links(context: dict, configured: object) -> dict:
    if not isinstance(configured, list):
        return {}
    devices = {device["id"]: device for device in context.get("devices", []) if device.get("kind") == "switch"}
    links = {}
    for link in context.get("links", []):
        if (link.get("id") not in configured[:MAX_DOWNSTREAM_SWITCHES] or link.get("relation") != "connected_to"
                or link.get("state", {}).get("intent") == "absent"):
            continue
        a, b = link["endpoint_a"], link["endpoint_b"]
        address = devices.get(a["device"], {}).get("management_ip")
        if address and b["device"] in devices and a.get("interface") and b.get("interface"):
            links[link["id"]] = (address, a, {**b, "address": devices[b["device"]].get("management_ip")})
    return links


def _check_downstream_addresses(nodes: list[dict], network: dict, now: datetime) -> None:
    groups = [node["downstream"]["devices"] for node in nodes if node.get("downstream")]
    missing = [entry for devices in sorted(groups, key=len) for entry in devices if "ip" not in entry]
    if not missing:
        return
    observed_macs = {}
    candidate_ips = {}
    for source in ("hosts", "arp"):
        for row in network.get(source, []):
            mac = str(row.get("mac") or "").lower()
            if not MAC.fullmatch(mac) or not observation_is_fresh(row.get("last_seen_at"), now):
                continue
            try:
                address = str(ipaddress.IPv4Address(row.get("ip")))
            except ValueError:
                continue
            observed_macs.setdefault(address, set()).add(mac)
            if source == "hosts":
                candidate_ips.setdefault(mac, set()).add(address)
    checks = {}
    for entry in missing:
        mac = entry["mac"]
        addresses = candidate_ips.get(mac, set())
        if len(addresses) == 1:
            address, = addresses
            if observed_macs[address] == {mac}:
                checks.setdefault((address, mac), []).append(entry)

    def check(pair):
        address, mac = pair
        if _probe_on_link_mac(address, mac, fresh_only=True):
            return _observation("reachable", "UI_VPN", "ICMP · ARP", datetime.now(timezone.utc).isoformat())
        return None

    targets = sorted(checks)[:16]
    if targets:
        with ThreadPoolExecutor(max_workers=6) as pool:
            for pair, observation in zip(targets, pool.map(check, targets)):
                if observation:
                    for entry in checks[pair]:
                        entry.update(ip=pair[0], identityCheckedAt=observation["checkedAt"], reachability=observation)


def build_graph(context: dict, network: dict, server: dict, pve: dict, bindings: dict, now: datetime,
                *, local_vlan_probes: dict | None = None, wireguard_probes: dict | None = None) -> dict:
    nodes = {}
    edges = {}

    def node(key, name, kind, site="", origin="GitHub"):
        return nodes.setdefault(key, {
            "id": key, "name": name, "kind": kind, "site": site, "origin": origin,
            "properties": {}, "sources": [], "checks": [],
        })

    def edge(a, b, kind, source, confirmed=True, details="", ports=None, at=None, vlan=None, virtual=None,
             evidence_only=False, lacp_polled_at=None):
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
            if lacp_polled_at is not None:
                report["lacpPolledAt"] = lacp_polled_at
            if report not in evidence:
                evidence.append(report)
        if evidence:
            edges[key]["portEvidence"] = evidence

    def source(item, name, raw, at, label=""):
        item["sources"].append({"name": name, "raw": raw, "status": HEALTH.get(raw, "unknown"),
                                "at": at, "label": label})

    def service_dependencies(service_id, configured):
        consumers = configured.get("used_by", [])
        if not isinstance(consumers, list):
            return
        for consumer in consumers:
            if isinstance(consumer, str) and nodes.get(consumer, {}).get("kind") == "Сервис":
                edge(consumer, service_id, "Зависимость сервиса", "Настройки карты")

    host_ips = {}
    host_macs = {}
    fresh_macs_by_ip = {}
    asset_ip_checks = bindings.get("asset_ip_checks", {})
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
        declared_macs[key] = {mac.lower() for mac in device.get("mac_addresses", []) if MAC.fullmatch(mac)}
        host = host_ips.get(device.get("management_ip"), {})
        bound_switch = device["kind"] == "switch" and key in asset_ip_checks and declared_macs[key]
        if not bound_switch or str(host.get("mac") or "").lower() in declared_macs[key]:
            if observation := _host_observation(host, now):
                item["reachability"] = observation
        names.setdefault(device["name"].casefold(), []).append(key)
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
    bridge_owners = {mac: owners.copy() for mac, owners in declared_devices_by_mac.items()}
    for device in context.get("devices", []):
        rstp = device.get("observed_state", {}).get("rstp")
        bridge = rstp.get("bridge_id") if isinstance(rstp, dict) else None
        if device["kind"] in {"switch", "router"} and isinstance(bridge, str):
            mac = bridge.rsplit(".", 1)[-1].lower()
            if MAC.fullmatch(mac):
                bridge_owners.setdefault(mac, set()).add(device["id"])
    intents = {item["id"]: item for item in context.get("routing_intent", []) if "id" in item}
    for service in context.get("services", []):
        host = service.get("device")
        item = node(service["id"], service["name"], "Сервис", nodes.get(host, {}).get("site", ""))
        route = bindings.get("route_evidence", {}).get(service["id"], {})
        intent = intents.get(route.get("intent"))
        if intent and route.get("source"):
            item["serviceChecks"] = _route_checks(intent, route["source"], network.get("routes", []), now,
                                                 host_routes=route.get("host_routes"))
        edge(host, service["id"], "Размещение", "GitHub")
    identity_services = {}
    for service_id, spec in bindings.get("asset_services", {}).items():
        asset = spec["asset"]
        if asset in address_by_asset and service_id not in nodes:
            item = node(service_id, spec["label"], "Сервис", nodes[asset]["site"], "UI_VPN")
            if spec.get("require_network_identity") is True:
                item["probeTargetIP"] = None
                identity_services.setdefault(asset, []).append(item)
            else:
                item["probeTargetIP"] = address_by_asset[asset]
            edge(asset, service_id, "Размещение", "Настройки карты")
    backup = bindings.get("proxmox_backup_monitor")
    backup_observation = pve.get("backup", {})
    guest_backup_checks = {}
    if (policy := backup_policy(backup)) and (asset := backup.get("asset")) in nodes:
        item = node(BACKUP_SERVICE_ID, "Резервное копирование Proxmox", "Сервис", nodes[asset]["site"], "UI_VPN")
        checks = backup_service_checks(backup_observation, policy, now)
        guest_backup_checks = {check["backupVmid"]: check for check in checks if "backupVmid" in check}
        item["serviceChecks"] = checks
        states = {check["state"] for check in checks}
        state = "reachable" if "reachable" in states else "unreachable" if states == {"unreachable"} else "unknown"
        item["reachability"] = _observation(state, "Проверка сервиса", BACKUP_PROBE_METHOD, checks[0]["checkedAt"])
        edge(asset, item["id"], "Размещение", "Настройки карты")
    verified_host_ports = set()
    shared_ports = set()
    for link in context.get("links", []):
        if link.get("state", {}).get("intent") == "absent":
            continue
        a, b = link["endpoint_a"], link["endpoint_b"]
        kind = {"virtualized_on": "Размещение ВМ", "management_for": "Управление оборудованием"}.get(
            link.get("relation"), "Сетевое соединение")
        vlan = link.get("vlan")
        tagged_transit = isinstance(vlan, dict) and vlan.get("mode") == "tagged_transit" and link.get("relation") == "connected_to"
        if tagged_transit:
            kind = "Транзитный сегмент"
        ports = (a.get("interface") or "", b.get("interface") or "")
        verified = link.get("state", {}).get("verified") is True
        if (link.get("relation") == "connected_to" and ports[0]
                and link.get("state", {}).get("observed") == "lldp_neighbor_on_shared_or_intermediate_l2_path"):
            shared_ports.add((a["device"], port_label_key(ports[0])))
            edge(a["device"], b["device"], SHARED_LLDP_KIND, "GitHub", False, ports=ports)
            continue
        edge(a["device"], b["device"], kind, "GitHub", verified, ports=ports,
             vlan=vlan.get("id") if tagged_transit else None)
        if verified and kind == "Сетевое соединение" and link.get("relation") == "connected_to":
            for switch, host in ((a, b), (b, a)):
                if (nodes.get(switch["device"], {}).get("kind") == NETWORK_KINDS[0]
                        and nodes.get(host["device"], {}).get("kind") == "Гипервизор"):
                    verified_host_ports.add((host["device"], switch["device"], (switch.get("interface") or "").casefold()))
    for service_id, spec in (local_vlan_probes or {}).items():
        if spec["localAsset"] in nodes and spec["peerAsset"] in nodes:
            node(service_id, f"Транзит VLAN {spec['vlan']}", "Сервис", nodes[spec["localAsset"]]["site"], "UI_VPN")
            for endpoint in (spec["localAsset"], spec["peerAsset"]):
                edge(endpoint, service_id, "Цель проверки", "Настройки карты")
    for service_id, spec in (wireguard_probes or {}).items():
        if spec["localAsset"] in nodes and spec["transitService"] in nodes:
            node(service_id, f"Выход WireGuard · {spec['interface']}", "Сервис", nodes[spec["localAsset"]]["site"], "UI_VPN")
            edge(spec["localAsset"], service_id, "Цель проверки", "Настройки карты")
            edge(service_id, spec["transitService"], "Зависимость сервиса", "Настройки карты")

    fresh_lldp = [row for row in network.get("lldp", []) if observation_is_fresh(row.get("observed_at"), now)]
    peers_by_port = {}
    peers_by_sample = {}
    for row in fresh_lldp:
        local = (row.get("source"), row.get("local_port_key"))
        chassis = str(row.get("chassis_id") or row.get("system_name") or "").casefold()
        identity = (chassis, str(row.get("port_id") or "").casefold())
        peers_by_port.setdefault(local, set()).add(identity)
        run = row.get("collector_run_id")
        if chassis and type(run) is int:
            peers_by_sample.setdefault((*local, run, row["observed_at"]), {}).setdefault(identity, row)

    switch_status = {row["source"]: row for row in network.get("switches", [])}
    router_ports = {}
    for interface in network.get("router_interfaces", []):
        name = interface.get("name")
        if interface.get("type") != "ether" or not isinstance(name, str) or not INTERFACE_NAME.fullmatch(name):
            continue
        state = ("disabled" if interface.get("disabled") == 1 else
                 {1: "up", 0: "down"}.get(interface.get("running"), "unknown"))
        router_ports.setdefault(interface["source"], []).append({
            "name": name, "source": "RouterOS", "state": state, "checkedAt": interface.get("last_seen_at"),
        })
    for reading in network.get("router_neighbors", []):
        interfaces = reading.get("interface")
        mac = str(reading.get("mac") or "").lower()
        if not isinstance(interfaces, str) or not MAC.fullmatch(mac):
            continue
        local_names = {name.strip() for name in interfaces.split(",")}
        ports = [port for port in router_ports.get(reading.get("source"), [])
                 if port["name"] in local_names and port["checkedAt"] == reading.get("last_seen_at")]
        if len(ports) == 1 and ports[0]["state"] == "up":
            ports[0].setdefault("routerNeighbors", {})[mac] = {
                "name": reading.get("identity"), "address": reading.get("address"), "platform": reading.get("platform"),
            }
    for ports in router_ports.values():
        for port in ports:
            if readings := port.get("routerNeighbors"):
                port["routerNeighbors"] = {"total": len(readings),
                                           "devices": {mac: readings[mac] for mac in sorted(readings)[:MAX_ROUTER_NEIGHBORS]}}
    port_groups = {}
    port_names = {}
    for port in network.get("ports", []):
        port_groups.setdefault(port["source"], []).append(port)
        port_names[(port["source"], port.get("port_key"))] = port.get("name") or port.get("port_key")
    port_telemetry = {(row["source"], row["port_key"], row["collector_run_id"], row["observed_at"]): row
                      for row in network.get("port_telemetry", [])}
    fdb_vlans = {}
    for row in network.get("port_fdb_vlans", []):
        key = (row["source"], row["collector_run_id"], row["observed_at"], row["port_key"])
        fdb_vlans.setdefault(key, []).append({"id": row["vlan_id"], "learnedMacCount": row["learned_mac_count"]})
    fdb_learned = {(row["source"], row["collector_run_id"], row["observed_at"], row["port_key"]): row
                   for row in network.get("port_fdb_learned", [])}
    vlans_by_key, vlans_by_index = {}, {}
    for row in network.get("port_vlans", []):
        scope = (row["source"], row["collector_run_id"], row["observed_at"])
        vlans_by_key.setdefault((*scope, row["port_key"]), []).append(row)
        index = row.get("if_index")
        if type(index) is int and index > 0:
            vlans_by_index.setdefault((*scope, index), []).append(row)

    def port_label(source_name, key):
        return port_names.get((source_name, key), key)

    source_nodes = {}
    source_ids = {}
    source_names = {}
    designated_ports = {}
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
        if row.get("enabled") and row.get("driver") in {"mikrotik_api", "mikrotik_ssh"} and name in router_ports:
            item["ports"] = router_ports[name]
        if name in port_groups:
            ports = port_groups[name]
            latest_run = max((port["collector_run_id"] for port in ports
                              if type(port.get("collector_run_id")) is int), default=None)
            current = [port for port in ports if port.get("collector_run_id") == latest_run]
            stp = network.get("stp_root_paths", {}).get(name)
            if stp and row.get("enabled"):
                matches = [port for port in current if port.get("bridge_port") == stp["rootPortNumber"]]
                if len(matches) == 1:
                    root_port = matches[0]
                    if (root_port.get("oper_status") == "up" and root_port.get("admin_status") != "down"
                            and observation_is_fresh(root_port.get("last_seen_at"), now)):
                        item["stpRootPath"] = {**stp, "localPort": root_port["name"]}
                        owners = bridge_owners.get(stp["designatedBridgeMac"], set())
                        if len(owners) == 1 and item["id"] not in owners:
                            item["stpRootPath"]["bridgeDeviceId"], = owners
            index_counts = Counter(port.get("if_index") for port in current)
            sample = network.get("stp_designated_ports", {}).get(name, {})
            if row.get("enabled") and observation_is_fresh(sample.get("checkedAt"), now, max_age=STP_ROOT_PATH_MAX_AGE):
                by_index = {port["if_index"]: port["name"] for port in current
                            if type(port.get("if_index")) is int and index_counts[port["if_index"]] == 1
                            and port.get("name") and port.get("oper_status") == "up" and port.get("admin_status") != "down"
                            and observation_is_fresh(port.get("last_seen_at"), now)}
                for pair, index in sample["ports"].items():
                    if index in by_index:
                        designated_ports.setdefault((key, *pair), []).append((by_index[index], sample["checkedAt"]))
            item["ports"] = [
                {"name": port.get("name") or port.get("port_key"),
                 "key": port.get("port_key"),
                 "state": "disabled" if port.get("admin_status") == "down" else port.get("oper_status"),
                 "speedBps": port.get("speed_bps"), "checkedAt": port.get("last_seen_at")}
                for port in current
            ]
            for port, raw_port in zip(item["ports"], current):
                if raw_port.get("linkCheck"):
                    port["linkCheck"] = raw_port["linkCheck"]
                scope = (name, latest_run, port["checkedAt"])
                neighbors = peers_by_sample.get((name, port["key"], latest_run, port["checkedAt"]))
                if neighbors and port["state"] == "up":
                    port["lldpNeighborCount"] = len(neighbors)
                    port["lldpChassisCount"] = len({chassis for chassis, _ in neighbors})
                    port["lldpNeighbors"] = []
                    for identity in sorted(neighbors)[:16]:
                        neighbor = neighbors[identity]
                        mac = str(neighbor.get("chassis_id") or "").lower()
                        names_seen = {host["hostname"] for host in host_macs.get(mac, [])
                                      if isinstance(host.get("hostname"), str) and host["hostname"]
                                      and observation_is_fresh(host.get("last_seen_at"), now)
                                      and fresh_macs_by_ip.get(host.get("ip")) == {mac}}
                        port["lldpNeighbors"].append({
                            "chassisId": mac, "portId": neighbor.get("port_id"),
                            "systemName": neighbor.get("system_name"),
                            "hostName": next(iter(names_seen)) if len(names_seen) == 1 else None,
                        })
                learned_vlans = fdb_vlans.get((*scope, port["key"]))
                if learned_vlans and port["state"] == "up":
                    port["fdbVlans"] = {"checkedAt": port["checkedAt"], "vlans": learned_vlans}
                learned = fdb_learned.get((*scope, port["key"]))
                if learned is not None and port["state"] == "up":
                    port["fdbLearned"] = {"checkedAt": port["checkedAt"],
                                          "learnedMacCount": learned["learned_mac_count"],
                                          "partial": learned["partial"] == 1}
                index = raw_port.get("if_index")
                memberships = [row for row in vlans_by_key.get((*scope, port["key"]), [])
                               if index is None or row.get("if_index") in (None, index)]
                if not memberships and type(index) is int and index > 0 and index_counts[index] == 1:
                    memberships = vlans_by_index.get((*scope, index), [])
                if memberships:
                    port["vlanMemberships"] = {
                        "checkedAt": port["checkedAt"],
                        "vlans": [{"id": row["vlan_id"], "pvid": row["pvid"] == 1,
                                   "egress": ("untagged" if row["untagged"] == 1 else "tagged")
                                   if row["egress"] == 1 else ""} for row in memberships[:4094]],
                    }
                sample = port_telemetry.get((name, port["key"], latest_run, port["checkedAt"]))
                if not sample or port["state"] != "up":
                    continue
                port["telemetry"] = {
                    "checkedAt": sample["observed_at"], "intervalSeconds": sample["sample_interval_seconds"],
                    "rxBps": sample.get("rx_bps"), "txBps": sample.get("tx_bps"),
                    "rxErrors": sample.get("in_errors_delta"), "txErrors": sample.get("out_errors_delta"),
                    "rxDiscards": sample.get("in_discards_delta"), "txDiscards": sample.get("out_discards_delta"),
                }
        if "fdb_entries" in status:
            item["properties"]["Записи MAC-таблицы"] = str(status["fdb_entries"])
    for item in nodes.values():
        if stp := item.get("stpRootPath"):
            matches = designated_ports.get((stp.get("bridgeDeviceId"), stp.get("designatedBridgeId"),
                                            stp["designatedPortId"]), [])
            if len(matches) == 1:
                stp["designatedPortName"], stp["designatedPortCheckedAt"] = matches[0]
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
    devices = {device["id"]: device for device in context.get("devices", [])}
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
            if archived := _inventory_ipv4_interface(devices[asset], spec["peer"], now):
                edge(router, asset, "Транзитный сегмент", "GitHub", False, ports=("", archived[0]), at=archived[1])
        bridge = spec.get("lan_bridge")
        address = address_by_asset[asset]
        if isinstance(bridge, str) and addresses.get(address) == [asset]:
            attachment = _bridge_attachment_port(address, spec["source"], bridge, network, arp_mappings, now)
            if attachment:
                port, observed = attachment
                edge(router, asset, "Путь по MAC-таблице", "MikroTik · ARP + FDB",
                     details=f"{address} · {bridge}", ports=(port, ""), at=observed)
                if archived := _inventory_ipv4_interface(devices[asset], address, now):
                    edge(router, asset, "Путь по MAC-таблице", "GitHub", False, ports=("", archived[0]), at=archived[1])
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
                if any((key, port_label_key(port)) in shared_ports for key, port in zip((a, b), ports)):
                    continue
                edge(a, b, "Сетевое соединение", "netctl", confirmed, ports=ports, at=observed)
            elif any(ports):
                fdb_reports.append((a, b, confirmed, ports, observed))
    lldp_chassis_ports = {}
    lldp_address_owners = {}
    for row in fresh_lldp:
        local = (row.get("source"), row.get("local_port_key"))
        chassis = str(row.get("chassis_id") or row.get("system_name") or "").casefold()
        if MAC.fullmatch(chassis):
            lldp_chassis_ports.setdefault((local[0], chassis), set()).add(local[1])
        for address in row.get("management_addresses", []):
            lldp_address_owners.setdefault(address, set()).add(chassis)
    router_neighbor_macs = {}
    for row in network.get("router_neighbors", []):
        mac = str(row.get("mac") or "").lower()
        if MAC.fullmatch(mac) and observation_is_fresh(row.get("last_seen_at"), now):
            name = str(row.get("identity") or "").casefold()
            stamp = datetime.fromisoformat(row["last_seen_at"])
            by_mac = router_neighbor_macs.setdefault((name, row.get("address")), {})
            by_mac[mac] = max(by_mac.get(mac, stamp), stamp)
    lldp_port_states = {key: index_port_states(item.get("ports", []), now) for key, item in nodes.items()
                        if item["kind"] == NETWORK_KINDS[0]}
    for row in fresh_lldp:
        a = source_nodes.get(row.get("source"))
        name = str(row.get("system_name") or "").casefold()
        candidates = [key for key in names.get(name, []) if nodes[key]["kind"] in NETWORK_KINDS]
        if a and len(candidates) == 1 and a != candidates[0]:
            neighbor, = candidates
            item = nodes[neighbor]
            raw_port = row.get("local_port_key") or ""
            port = port_label(row.get("source"), raw_port)
            is_interface_name = str(row.get("port_id_subtype")) in {"1", "5", "interface_alias", "interface_name"}
            remote = row.get("port_id") if is_interface_name else ""
            chassis_mac = str(row.get("chassis_id") or "").lower()
            conflict = bool(declared_macs[neighbor] and MAC.fullmatch(chassis_mac)
                            and chassis_mac not in declared_macs[neighbor])
            peers = peers_by_port[(row.get("source"), raw_port)]
            chassis_ports = lldp_chassis_ports.get((row.get("source"), chassis_mac), set())
            shared = (a, port_label_key(port)) in shared_ports or len({chassis for chassis, _ in peers if chassis}) > 1
            direct = bool(raw_port) and len(peers) == 1 and len(chassis_ports) <= 1 and not shared
            note = " · общий порт" if shared else "" if direct else " · соседство неоднозначно"
            item["properties"]["Соседство LLDP"] = f"{nodes[a]['name']} · {port}{note}"
            advertised = row.get("management_addresses", [])
            alternate = None
            if conflict:
                item["properties"]["Сопоставление LLDP"] = "MAC шасси отличается от инвентаря"
                if (shared and item["kind"] == NETWORK_KINDS[1] and len(advertised) == 1
                        and not declared_devices_by_mac.get(chassis_mac)):
                    address, = advertised
                    arp = arp_mappings.get(address)
                    router_macs = router_neighbor_macs.get((name, address), {})
                    if (arp and arp[0] == chassis_mac and set(router_macs) == {chassis_mac}
                            and fresh_macs_by_ip.get(address) == lldp_address_owners.get(address) == {chassis_mac}
                            and set(addresses.get(address, [])) <= {neighbor}):
                        alternate = (address, min(arp[1], router_macs[chassis_mac]))
                        item["properties"]["Сопоставление LLDP"] += " · текущий MAC подтверждён по ARP и MikroTik"
            observed_at = row["observed_at"]
            if shared and raw_port:
                live_port = lldp_port_states.get(a, {}).get(port_label_key(port))
                confirmed = (bool(live_port and live_port["state"] == "up")
                             and (declared_devices_by_mac.get(chassis_mac) == {neighbor} or alternate is not None)
                             and chassis_ports == {raw_port})
                if confirmed:
                    stamp = min(datetime.fromisoformat(observed_at), datetime.fromisoformat(live_port["checkedAt"]))
                    observed_at = min(stamp, alternate[1]).isoformat() if alternate else stamp.isoformat()
                edge(a, neighbor, SHARED_LLDP_KIND, SHARED_LLDP_SOURCE, confirmed,
                     details=item["properties"].get("Сопоставление LLDP", "") if conflict else "",
                     ports=(port, ""), at=observed_at)
            else:
                edge(a, neighbor, "Сетевое соединение", "LLDP UI_VPN", direct and not conflict,
                     details=note.removeprefix(" · "), ports=(port, remote or ""), at=observed_at)
            if alternate:
                address = alternate[0]
                item["properties"].pop("IP заявлен в LLDP", None)
                item["properties"]["Адрес управления по LLDP"] = address
                host = host_ips.get(address, {})
                observation = _host_observation(host, now) if str(host.get("mac") or "").lower() == chassis_mac else None
                if observation:
                    observation["checkedAt"] = min(datetime.fromisoformat(observation["checkedAt"]),
                                                   datetime.fromisoformat(row["observed_at"]), alternate[1]).isoformat()
                    item.setdefault("reachability", observation)
                continue
            if len(advertised) == 1 and "Адрес управления по LLDP" not in item["properties"]:
                item["properties"]["IP заявлен в LLDP"] = advertised[0]
            active_switch_check = item["kind"] == NETWORK_KINDS[0] and neighbor in asset_ip_checks
            if declared_devices_by_mac.get(chassis_mac) != {neighbor} or ("reachability" in item and not active_switch_check):
                continue
            verified = []
            for address in advertised:
                host_mac = str(host_ips.get(address, {}).get("mac") or "").lower()
                same_identity = host_mac == chassis_mac or set(router_neighbor_macs.get((name, address), {})) == {host_mac}
                if (same_identity and fresh_macs_by_ip.get(address) == {host_mac}
                        and lldp_address_owners.get(address) == {chassis_mac}
                        and set(addresses.get(address, [])) <= {neighbor}):
                    verified.append(address)
            if len(verified) == 1:
                address, = verified
                item["properties"].pop("IP заявлен в LLDP", None)
                item["properties"]["Адрес управления по LLDP"] = address
                arp = arp_mappings.get(address)
                if (active_switch_check and direct and address == asset_ip_checks[neighbor]
                        and arp and arp[0] == chassis_mac == str(host_ips[address].get("mac") or "").lower()):
                    item["probeTargetIP"] = address
                    item["probeTargetIdentityAt"] = min(arp[1], datetime.fromisoformat(row["observed_at"])).isoformat()
                observation = _host_observation(host_ips[address], now)
                if observation:
                    item.setdefault("reachability", observation)

    for a, b, port_a, port_b, at in _reciprocal_lldp(network, fresh_lldp, peers_by_port, arp_mappings, now):
        local, remote = source_nodes.get(a), source_nodes.get(b)
        if (local, port_label_key(port_a)) not in shared_ports and (remote, port_label_key(port_b)) not in shared_ports:
            edge(local, remote, "Сетевое соединение", "LLDP · двустороннее", ports=(port_a, port_b), at=at)

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
    targets = {target["role"]: target for target in server.get("targets", [])}
    observer_current = server.get("freshness") == "current" and server.get("collector", {}).get("status") != "error"
    for role in dict.fromkeys([*targets, *roles]):
        target = targets.get(role, {})
        configured = roles.get(role, {})
        host = configured.get("asset")
        item = node("role:" + role, configured.get("label") or role, "Сервис",
                    nodes.get(host, {}).get("site", ""), "UI_VPN")
        source(item, "Server Observer", target.get("status", "unknown"), target.get("observed_at"))
        item["sources"][-1]["stale"] = not observer_current
        target_checks = target.get("checks", [])
        valid_report = role != "acti_backup" or [check["status"] for check in target_checks
                                                  if check["name"] == "watchdog_fresh"] == ["ok"]
        item["checks"] = [{"name": check["name"], "status": HEALTH.get(check["status"], "unknown")
                           if valid_report or check["name"] == "watchdog_fresh" else "unknown",
                           "observed": check.get("observed") if valid_report or check["name"] == "watchdog_fresh" else None,
                           "expected": check.get("expected"),
                           "error": check.get("message") or check.get("error"),
                           "latency": check.get("latency_ms")}
                          for check in target_checks]
        configured_checks = configured.get("required_observer_checks", [])
        required_checks = list(configured_checks) if isinstance(configured_checks, list) else []
        functional = FUNCTIONAL_CHECKS.get(role)
        if functional:
            required_checks.insert(0, functional[0])
        if role == "acti_backup":
            required_checks.insert(0, "repository_capacity")
        item["requiredObserverChecks"] = required_checks
        checked_at = target.get("observed_at")
        if functional and valid_report and observer_current and observation_is_fresh(checked_at, now):
            check_name, method = functional
            results = [check["status"] for check in target_checks if check["name"] == check_name]
            if results in (["ok"], ["critical"], ["warn"]):
                state = "reachable" if results == ["ok"] else "unreachable"
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

    for role, spec in roles.items():
        if spec.get("asset") in nodes:
            service_dependencies("role:" + role, spec)

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
                item["ports"] = pve.get("physicalPorts", {}).get(key, [])
                item["resources"] = {
                    "checkedAt": pve_at, "cpuRatio": host.get("cpu"), "logicalCpus": host.get("maxcpu"),
                    "memoryUsedBytes": host.get("mem"), "memoryTotalBytes": host.get("maxmem"),
                    "rootUsedBytes": host.get("disk"), "rootTotalBytes": host.get("maxdisk"),
                    "uptimeSeconds": host.get("uptime"),
                }
                if isinstance(node_status := pve.get("nodeStatus"), dict):
                    item["resourceCapacity"] = node_status.get(key, {})
                disks = project_hypervisor_disks(pve.get("disks", {}).get(key), now)
                if disks:
                    item["hardwareDisks"] = disks
                zfs = project_hypervisor_zfs(pve.get("zfs", {}).get(key), now)
                if zfs:
                    item["zfsPools"] = zfs
                lvm_thin = project_hypervisor_lvm_thin(pve.get("lvmThin", {}).get(key), now)
                if lvm_thin:
                    item["lvmThinPools"] = lvm_thin
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
        guest_ids = Counter(row["vmid"] for row in pve["guests"])
        for guest in sorted(pve["guests"], key=lambda row: row["vmid"]):
            vmid, host = guest["vmid"], guest["node"]
            binding = bindings.get("guests", {}).get(str(vmid), {})
            asset = binding.get("asset")
            bound_mac = binding.get("mac")
            matched = asset in nodes and asset not in overview_guests and _matches_mac(
                bound_mac, pve.get("configs", {}).get(str(vmid), {}),
            )
            key = asset if matched else f"pve-guest:{vmid}"
            kind = "Контейнер" if guest.get("type") == "lxc" else "Виртуальная машина"
            item = node(key, guest.get("name") or f"ВМ {vmid}", kind, origin="Proxmox")
            if matched:
                overview_guests.append(key)
                item["aliases"] = [item["name"]]
                item["name"] = guest.get("name") or item["name"]
            item.update(kind=kind, guest=True, vmid=vmid, pveHost=host)
            if guest_backup_checks and guest_ids[vmid] == 1 and not guest.get("template"):
                coverage = "unknown"
                if vmid in backup_observation.get("guests", set()):
                    coverage = "scheduled"
                elif backup_observation and not backup_observation.get("incomplete"):
                    coverage = "not_scheduled"
                item["backupCoverage"] = {"state": coverage, "storage": backup["storage"],
                                          "checkedAt": backup_observation.get("checkedAt", now.isoformat())}
                if vmid in guest_backup_checks:
                    item.setdefault("serviceChecks", []).append(guest_backup_checks[vmid])
            prelaunch = guest.get("type") == "qemu" and guest.get("status") == "prelaunch"
            status, label = {
                "running": ("ok", "Запущена"), "stopped": ("warn", "Выключена"),
                "paused": ("warn", "Приостановлена"),
            }.get(guest.get("status"), ("unknown", "Неизвестно"))
            if guest.get("template"):
                status, label = "unknown", "Шаблон"
            elif prelaunch:
                status, label = "critical", "Гостевая ОС ещё не запущена"
            source(item, "Proxmox", status, pve_at, label)
            if status == "ok" and guest_ids[vmid] == 1:
                item["resources"] = {
                    "checkedAt": pve.get("guestResourcesAt", pve_at),
                    "cpuRatio": guest.get("cpu"), "logicalCpus": guest.get("maxcpu"),
                    "memoryUsedBytes": guest.get("mem"), "memoryTotalBytes": guest.get("maxmem"),
                    "uptimeSeconds": guest.get("uptime"),
                }
                counters = {name: guest[name] for name in ("netin", "netout", "diskread", "diskwrite")
                            if type(guest.get(name)) is int and 0 <= guest[name] < 2**64}
                if counters:
                    item["guestIoCounters"] = counters
            item.pop("reachability", None)
            config = pve.get("configs", {}).get(str(vmid), {})
            interfaces = guest_interfaces.get(str(vmid), {})
            configured_nics = {name for name in config if re.fullmatch(r"net[0-9]+", name)}
            if observation_is_fresh(pve_at, now):
                if status == "ok":
                    enabled_macs = {mac for _, _, disabled, mac in interfaces.values() if mac and not disabled}
                    conflicting = {mac for mac in enabled_macs if mac_counts[mac] > 1 or interface_mac_counts[mac] > 1}
                    if conflicting:
                        item["agentMatchConflict"] = True
                    keys = sorted({
                        "mac-" + mac.replace(":", "") for mac in enabled_macs - conflicting
                        if declared_devices_by_mac.get(mac, set()) <= {key}
                    })
                    if keys:
                        item["agentMatchKeys"] = keys
                lock = guest.get("lock")
                if isinstance(lock, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,31}", lock):
                    item["properties"]["Блокировка Proxmox"] = {"backup": "Резервное копирование"}.get(lock, lock)
                disks = _guest_disks(config, guest.get("type")) if not guest.get("template") else []
                if disks:
                    item["guestStorage"] = {"checkedAt": pve_at, "disks": disks}
                if not guest.get("template") and config.get("networkConfigRead") is True:
                    disabled_count = sum(disabled for _, _, disabled, _ in interfaces.values())
                    item["guestNetwork"] = {"checkedAt": pve_at, "configured": len(configured_nics),
                                            "enabled": len(interfaces) - disabled_count, "disabled": disabled_count}
                stopped = guest.get("status") == "stopped" and not guest.get("template")
                if stopped and matched and guest_ids[vmid] == 1 and mac_counts[bound_mac.lower()] == 1:
                    for role, spec in roles.items():
                        if spec.get("asset") == key:
                            nodes["role:" + role]["reachability"] = _observation(
                                "stopped", "Proxmox", "Состояние ВМ", pve_at,
                            )
                for service, spec in guest_services.get(str(vmid), []):
                    mac = str(spec.get("mac") or "").lower()
                    if mac_counts[mac] != 1 or mac not in guest_macs.get(str(vmid), set()):
                        continue
                    edge(key, service["id"], "Размещение", "Proxmox", at=pve_at)
                    service_dependencies(service["id"], spec)
                    if stopped and guest_ids[vmid] == 1:
                        service["reachability"] = _observation("stopped", "Proxmox", "Состояние ВМ", pve_at)
                    address = bindings.get("guest_probe_ips", {}).get(str(vmid))
                    if (status == "ok" and arp_mappings.get(address, (None,))[0] == mac
                            and any(nic_mac == mac and not disabled for _, _, disabled, nic_mac in interfaces.values())):
                        service["probeTargetIP"] = address
            if not guest.get("template") and guest.get("status") == "stopped":
                item["reachability"] = _observation("stopped", "Proxmox", "Состояние ВМ", pve_at)
            elif prelaunch and not guest.get("template") and observation_is_fresh(pve_at, now):
                item["reachability"] = _observation("unreachable", "Proxmox", "QEMU prelaunch", pve_at)
            elif guest.get("status") == "running" and not guest.get("template") and observation_is_fresh(pve_at, now):
                disabled_macs = {mac for _, _, disabled, mac in interfaces.values() if disabled}
                usable_macs = guest_macs.get(str(vmid), set()) - disabled_macs
                observation = _guest_observation(usable_macs, host_macs, mac_counts, now)
                verified = [check for _, _, disabled, mac in interfaces.values()
                            if not disabled and mac in usable_macs and mac_counts[mac] == 1
                            for check in arp_checks.get(mac, [])]
                if verified:
                    address, checked = max(verified, key=lambda pair: datetime.fromisoformat(pair[1]["checkedAt"]))
                    if (not observation or observation["state"] != "reachable"
                            or datetime.fromisoformat(checked["checkedAt"]) >= datetime.fromisoformat(observation["checkedAt"])):
                        observation = checked
                        item["properties"]["IP проверки по ARP"] = address
                if (guest.get("type") == "qemu" and config.get("directNetworkOnly") is True
                        and interfaces and configured_nics == interfaces.keys()
                        and all(disabled for _, _, disabled, _ in interfaces.values())):
                    observation = _observation("unreachable", "Proxmox", "Все адаптеры ВМ отключены", pve_at)
                if not observation and config.get("networkConfigRead") is True and not configured_nics:
                    observation = _observation("unknown", "Proxmox", "Адаптеры Proxmox не заданы", pve_at)
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
            management = management_ports.get(asset)
            remote_port = management[0] if management and management[1] == mac else ""
            provenance = "netctl FDB + Proxmox" if remote_port else "netctl FDB"
            for row in observations:
                checked = min(arp_at, datetime.fromisoformat(max(live)), datetime.fromisoformat(row["observed_at"]))
                if remote_port:
                    checked = min(checked, datetime.fromisoformat(pve_at))
                edge(switch, asset, "Путь по MAC-таблице", provenance, details=address,
                     ports=(port_label(switch_source, port), remote_port), at=checked.isoformat(), vlan=row["vlan_id"])
            if declared_devices_by_mac.get(mac) == {asset}:
                checked = min(arp_at, datetime.fromisoformat(max(live)),
                              max(datetime.fromisoformat(row["observed_at"]) for row in observations)).isoformat()
                for item in identity_services.get(asset, []):
                    item.update(probeTargetIP=address, probeTargetIdentityAt=checked)
                if asset_ip_checks.get(asset) == address and "probeTargetIdentityAt" not in nodes[asset]:
                    nodes[asset].update(probeTargetIP=address, probeTargetIdentityAt=checked,
                                        probeTargetIdentityMethod="ICMP · ARP + FDB")
    for spec in bindings.get("lacp_links", []):
        asset, aggregate = spec["asset"], spec["aggregate"]
        if asset not in nodes:
            continue
        declared = {
            local["device"] for row in context.get("links", []) if row.get("relation") == "connected_to"
            and row.get("state", {}).get("intent") != "absent"
            for local, peer in ((row["endpoint_a"], row["endpoint_b"]), (row["endpoint_b"], row["endpoint_a"]))
            if peer["device"] == asset and local.get("interface") == aggregate
            and nodes.get(local["device"], {}).get("kind") == NETWORK_KINDS[0]
        }
        switch = next(iter(declared)) if len(declared) == 1 else source_nodes.get(spec["source"])
        if switch and switch != asset and nodes[switch]["kind"] == NETWORK_KINDS[0]:
            nodes[asset].setdefault("lacpExpectations", []).append({
                "switchId": switch, "aggregate": aggregate, "members": spec["members"],
            })
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
                 ports=(f"{report['aggregate']} / {member['port']}", f"LACP {member['partner_port']}"),
                 lacp_polled_at=report["at"])
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
    reciprocal_ports = {}
    for a, b, ports, at in list(_reciprocal_management_paths(edges.values(), nodes, management_sightings, now)):
        pair = tuple(sorted((a, b)))
        reciprocal_ports[pair] = {"a": ports[0], "b": ports[1], "at": at, "confirmed": True,
                                  "source": RECIPROCAL_MAC_SOURCE}
        edge(a, b, "Путь по MAC-таблице", RECIPROCAL_MAC_SOURCE, ports=ports, at=at,
             details="Оба коммутатора видят MAC управления друг друга")
    downstream_links = _downstream_links(context, bindings.get("downstream_mac_links"))
    if downstream_links:
        addresses_by_mac = {}
        for address, (mac, stamp) in arp_mappings.items():
            addresses_by_mac.setdefault(mac, []).append((address, stamp))
        for link_id, (_, local, remote) in downstream_links.items():
            sample = network.get("downstream_fdb", {}).get(link_id, {})
            upstream, asset = local["device"], remote["device"]
            if (source_nodes.get(sample.get("source")) != upstream
                    or not observation_is_fresh(sample.get("at"), now)):
                continue
            own_macs = {mac for mac in declared_macs[asset] if declared_devices_by_mac[mac] == {asset}}
            learned = {mac.lower() for mac in sample["macs"] if MAC.fullmatch(mac)}
            pair = tuple(sorted((upstream, asset)))
            physical = edges.get((pair, "Сетевое соединение"), {})
            side, peer = ("a", "b") if physical.get("a") == upstream else ("b", "a")
            local_ports = index_port_states(nodes[upstream].get("ports", []), now)
            remote_ports = index_port_states(nodes[asset].get("ports", []), now)
            local_label = port_label_key(local["interface"])
            remote_label = port_label_key(remote["interface"])
            local_port = local_ports.get(local_label, {})
            remote_port = remote_ports.get(remote_label, {})
            upstream_port = local_port.get("name", local["interface"])
            local_name = port_label_key(upstream_port)
            remote_name = port_label_key(remote_port.get("name", remote_label))
            reports = [*physical.get("portEvidence", [])]
            if pair in reciprocal_ports:
                reports.append(reciprocal_ports[pair])
            proof = {}
            inventory = False
            for row in reports:
                if (not row["confirmed"] or port_label_key(row[side]) not in {local_label, local_name}
                        or port_label_key(row[peer]) not in {remote_label, remote_name}):
                    continue
                if row["source"] == "GitHub" and physical.get("confirmed"):
                    inventory = True
                if not observation_is_fresh(row["at"], now):
                    continue
                stamp = datetime.fromisoformat(row["at"])
                if row["source"] in {"LLDP UI_VPN", "LLDP · двустороннее"}:
                    proof.setdefault("lldp", []).append(stamp)
                elif row["source"] in {RECIPROCAL_MAC_SOURCE, "SNMP · двусторонний FDB"}:
                    proof.setdefault("reciprocal_mac", []).append(stamp)
            stp = nodes[asset].get("stpRootPath", {})
            if (inventory and local_port.get("state") == remote_port.get("state") == "up"
                    and stp.get("bridgeDeviceId") == upstream
                    and port_label_key(stp.get("localPort", "")) == remote_name
                    and observation_is_fresh(stp.get("checkedAt"), now, max_age=STP_ROOT_PATH_MAX_AGE)):
                proof["inventory_stp"] = [min(datetime.fromisoformat(reading["checkedAt"])
                                              for reading in (local_port, remote_port, stp))]
            basis = next((key for key in ("lldp", "reciprocal_mac", "inventory_stp") if key in proof), "")
            if not basis:
                continue
            remote_sample = sample.get("remote", {})
            sightings = {}
            if source_nodes.get(remote_sample.get("source")) == asset:
                for row in remote_sample["readings"]:
                    if row["mac"] in learned and observation_is_fresh(row["at"], now):
                        sightings.setdefault(row["mac"], set()).add((row["name"], row["at"]))
            observed_ports = {}
            for mac, readings in sightings.items():
                if len(readings) != 1:
                    continue
                (name, at), = readings
                key = port_label_key(name)
                port = remote_ports.get(key, {})
                if (key not in {remote_label, remote_name} and port.get("state") == "up"
                        and datetime.fromisoformat(port["checkedAt"]) == datetime.fromisoformat(at)):
                    observed_ports[mac] = {"name": name, "checkedAt": at}
            if basis != "lldp" or not own_macs.intersection(learned):
                learned = set(observed_ports)
            if not learned - own_macs:
                continue
            devices = []
            for mac in sorted(learned - own_macs):
                device = {"mac": mac}
                if mac in observed_ports:
                    device["switchPort"] = observed_ports[mac]
                identities = addresses_by_mac.get(mac, [])
                if len(identities) == 1:
                    address, stamp = identities[0]
                    device.update(ip=address, identityCheckedAt=stamp.isoformat())
                    host = host_ips.get(address, {})
                    if str(host.get("mac") or "").lower() == mac:
                        device["reachability"] = _host_observation(host, now)
                devices.append(device)
            checked_at = min(datetime.fromisoformat(sample["at"]), max(proof[basis]))
            nodes[asset]["downstream"] = {"upstreamId": upstream, "port": upstream_port,
                                          "checkedAt": checked_at.isoformat(), "basis": basis, "devices": devices}

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
                 management_bridges: dict[str, str] | None = None, *, backup_storage: str | None = None) -> dict:
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
        response_data = json.loads(payload)
        if not isinstance(response_data, dict) or "data" not in response_data:
            raise ValueError("invalid Proxmox response")
        return response_data["data"]

    result = {"cluster": get("cluster/status"), "nodes": get("cluster/resources?type=node"),
              "guests": get("cluster/resources?type=vm"), "configs": {}, "bridges": {}}
    result["guestResourcesAt"] = datetime.now(timezone.utc).isoformat()
    if any(not isinstance(result[key], list) or not all(isinstance(row, dict) for row in result[key])
           for key in ("cluster", "nodes", "guests")):
        raise ValueError("invalid Proxmox inventory")
    def read_guest(guest):
        key = str(guest["vmid"])
        node = quote(guest["node"], safe="")
        try:
            config = get(f"nodes/{node}/{guest['type']}/{int(key)}/config?current=1")
        except (URLError, TimeoutError):
            return key, {}
        selected = {name: value for name, value in config.items() if PVE_DISK_DEVICE.fullmatch(name)}
        if key in guests or not guest.get("template"):
            selected.update({name: value for name, value in config.items() if re.fullmatch(r"net[0-9]+", name)})
            selected["networkConfigRead"] = True
            if guest["type"] == "qemu":
                selected["directNetworkOnly"] = not any(
                    re.fullmatch(r"args|hookscript|(?:hostpci|usb)[0-9]+", name) for name in config
                )
        return key, selected

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

    def read_list(path):
        try:
            rows = get(path)
        except (URLError, TimeoutError, ValueError, KeyError):
            return []
        return [row for row in rows[:128] if isinstance(row, dict)] if isinstance(rows, list) else []

    def read_node_status(node):
        try:
            row = get(f"nodes/{quote(node, safe='')}/status")
        except (URLError, TimeoutError, ValueError, KeyError):
            return node, {}
        if not isinstance(row, dict):
            return node, {}
        status = {"checkedAt": datetime.now(timezone.utc).isoformat()}
        for key, fields in (("rootfs", ("avail", "total")), ("swap", ("used", "total")),
                            ("memory", ("free", "available", "total"))):
            if isinstance(values := row.get(key), dict):
                status[key] = {field: values.get(field) for field in fields}
        return node, status

    def read_physical_ports(node):
        rows = read_list(f"nodes/{quote(node, safe='')}/network?type=eth")
        checked_at = datetime.now(timezone.utc).isoformat()
        ports = [
            {"name": row["iface"], "source": "Proxmox", "state": "unknown", "checkedAt": checked_at,
             "proxmoxActive": row.get("active") == 1}
            for row in rows if row.get("type") == "eth" and row.get("exists") == 1
            and isinstance(row.get("iface"), str) and INTERFACE_NAME.fullmatch(row["iface"])
        ]
        return node, sorted(ports, key=lambda port: port["name"])

    def read_disks(node):
        rows = read_list(f"nodes/{quote(node, safe='')}/disks/list")
        states = {"OK": "ok", "PASSED": "ok", "FAILED": "critical", "FAILED!": "critical"}
        disks = [{"device": row.get("devpath"), "kind": row.get("type"),
                  "smartState": states.get(str(row.get("health")).strip().upper(), "unknown"),
                  "sizeBytes": row.get("size"), "endurancePercent": row.get("wearout")}
                 for row in rows]
        return node, {"checkedAt": datetime.now(timezone.utc).isoformat(), "disks": disks}

    def read_zfs(node):
        rows = read_list(f"nodes/{quote(node, safe='')}/disks/zfs")
        pools = [{"name": row.get("name"), "health": row.get("health"),
                  "sizeBytes": row.get("size"), "freeBytes": row.get("free")} for row in rows]
        return node, {"checkedAt": datetime.now(timezone.utc).isoformat(), "pools": pools}

    def read_lvm_thin(node):
        rows = read_list(f"nodes/{quote(node, safe='')}/disks/lvmthin")
        pools = [{"name": row.get("lv"), "volumeGroup": row.get("vg"),
                  "sizeBytes": row.get("lv_size"), "usedBytes": row.get("used"),
                  "metadataSizeBytes": row.get("metadata_size"), "metadataUsedBytes": row.get("metadata_used")}
                 for row in rows]
        return node, {"checkedAt": datetime.now(timezone.utc).isoformat(), "pools": pools}

    online_nodes = {node["node"] for node in result["nodes"] if node.get("status") == "online"}
    candidates = [guest for guest in result["guests"] if guest["type"] in {"qemu", "lxc"}
                  and (str(guest["vmid"]) in guests or guest.get("status") == "running"
                       or (not guest.get("template") and guest["node"] in online_nodes))]
    with ThreadPoolExecutor(max_workers=6) as pool:
        result["nodeStatus"] = dict(pool.map(read_node_status, sorted(online_nodes)))
        result["physicalPorts"] = dict(pool.map(read_physical_ports, sorted(online_nodes)))
        result["disks"] = dict(pool.map(read_disks, sorted(online_nodes)))
        result["zfs"] = dict(pool.map(read_zfs, sorted(online_nodes)))
        result["lvmThin"] = dict(pool.map(read_lvm_thin, sorted(online_nodes)))
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
    if backup_storage:
        result["backup"] = read_proxmox_backup(get, [row["node"] for row in result["nodes"]],
                                               backup_storage, datetime.now(timezone.utc))
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


def _read_downstream_fdb(connection, sources: list[dict], configured: dict) -> dict:
    samples = {}
    sources_by_host = {}
    for source in sources:
        if source.get("enabled") and source.get("driver") == "snmp_switch":
            sources_by_host.setdefault(source.get("host"), []).append(source)
    for link_id, (address, local, remote) in configured.items():
        eligible = sources_by_host.get(address, [])
        if len(eligible) != 1:
            continue
        source, = eligible
        port_rows = connection.execute("""
            SELECT port_key, name, collector_run_id FROM switch_ports
            WHERE source_id = ? AND collector_run_id = (
                SELECT max(collector_run_id) FROM switch_ports WHERE source_id = ?
            )
        """, (source["id"], source["id"]))
        port_label = port_label_key(local["interface"])
        candidates = [row for row in port_rows if row["name"] and port_label_key(row["name"]) == port_label]
        if len(candidates) != 1:
            continue
        port, = candidates
        rows = list(connection.execute(f"""
            SELECT DISTINCT lower(f.mac) AS mac, p.port_key, p.last_seen_at
            FROM current_switch_fdb AS f
            JOIN switch_ports AS p ON {FDB_PORT_MATCH}
            WHERE f.source_id = ? AND p.port_key = ? AND p.collector_run_id = ?
              AND p.oper_status = 'up' AND p.admin_status IS NOT 'down'
              AND f.last_seen_at = p.last_seen_at AND lower(f.status) = 'learned'
            LIMIT 257
        """, (source["id"], port["port_key"], port["collector_run_id"])))
        readings = {(row["port_key"], row["last_seen_at"]) for row in rows}
        if 1 <= len(rows) <= 256 and len(readings) == 1:
            samples[link_id] = {"source": source["name"], "at": rows[0]["last_seen_at"],
                                "macs": [row["mac"] for row in rows]}
            peers = sources_by_host.get(remote.get("address"), []) if remote.get("address") else []
            if len(peers) == 1:
                peer, = peers
                rows = list(connection.execute(f"""
                    SELECT DISTINCT lower(f.mac) AS mac, p.name, p.last_seen_at AS at
                    FROM current_switch_fdb AS f
                    JOIN switch_ports AS p ON {FDB_PORT_MATCH}
                    WHERE f.source_id = ? AND lower(f.mac) IN (SELECT value FROM json_each(?))
                      AND p.oper_status = 'up' AND p.admin_status IS NOT 'down'
                      AND f.last_seen_at = p.last_seen_at AND lower(f.status) = 'learned'
                    LIMIT 1025
                """, (peer["id"], json.dumps(samples[link_id]["macs"]))))
                if len(rows) <= 1024:
                    samples[link_id]["remote"] = {"source": peer["name"], "readings": [dict(row) for row in rows]}
    return samples


def read_network(guest_macs: set[str] | None = None, route_sources: set[str] | None = None,
                 transit_sources: set[str] | None = None, *, asset_fdb_ips: set[str] | None = None,
                 downstream_links: dict | None = None) -> dict:
    commands = {
        "switches": (["switches", "status"], "switches"),
        "links": (["topology", "links"], "links"),
    }
    with read_context_snapshot(DEFAULT_DB_URL) as connection:
        data = {"sources": list_sources(connection), "attachments": query_confirmed_attachment_ports(connection)}
        if downstream_links:
            data["downstream_fdb"] = _read_downstream_fdb(connection, data["sources"], downstream_links)
        data["port_telemetry"] = [dict(row) for row in connection.execute(
            """
            SELECT s.name AS source, t.port_key, t.collector_run_id, t.observed_at,
                   t.sample_interval_seconds, t.rx_bps, t.tx_bps, t.in_errors_delta,
                   t.out_errors_delta, t.in_discards_delta, t.out_discards_delta
            FROM current_switch_port_telemetry AS t
            JOIN network_sources AS s ON s.id = t.source_id
            WHERE s.enabled = 1 AND s.driver = 'snmp_switch' AND t.telemetry_state = 'ok'
            """
        )]
        data["port_vlans"] = [dict(row) for row in connection.execute(
            """
            SELECT s.name AS source, v.port_key, v.if_index, v.collector_run_id, v.observed_at,
                   v.vlan_id, v.egress, v.untagged, v.pvid
            FROM current_switch_vlan_memberships AS v
            JOIN network_sources AS s ON s.id = v.source_id
            WHERE s.enabled = 1 AND s.driver = 'snmp_switch'
            """
        )]
        data["port_fdb_vlans"] = [dict(row) for row in connection.execute(
            f"""
            SELECT s.name AS source, p.port_key, f.collector_run_id, f.last_seen_at AS observed_at,
                   f.vlan_id, COUNT(DISTINCT lower(f.mac)) AS learned_mac_count
            FROM current_switch_fdb AS f
            JOIN network_sources AS s ON s.id = f.source_id
            JOIN switch_ports AS p ON {FDB_PORT_MATCH}
            WHERE s.enabled = 1 AND s.driver = 'snmp_switch'
              AND lower(f.status) = 'learned' AND f.vlan_id BETWEEN 1 AND 4094
              AND p.last_seen_at = f.last_seen_at AND p.oper_status = 'up'
            GROUP BY s.name, p.port_key, f.collector_run_id, f.last_seen_at, f.vlan_id
            """
        )]
        data["port_fdb_learned"] = [dict(row) for row in connection.execute(
            f"""
            SELECT s.name AS source, p.port_key, p.collector_run_id, p.last_seen_at AS observed_at,
                   COUNT(DISTINCT lower(f.mac)) AS learned_mac_count,
                   CASE WHEN json_extract(r.outcomes_json, '$.qbridge_fdb_rejected_rows') = 'parse_error'
                        THEN 1 ELSE 0 END AS partial
            FROM switch_ports AS p
            JOIN network_sources AS s ON s.id = p.source_id
            JOIN switch_collection_runs AS r ON r.id = p.collector_run_id AND r.source_id = p.source_id
            LEFT JOIN current_switch_fdb AS f ON {FDB_PORT_MATCH}
                AND f.last_seen_at = p.last_seen_at AND lower(f.status) = 'learned'
            WHERE s.enabled = 1 AND s.driver = 'snmp_switch' AND p.oper_status = 'up'
              AND r.started_at = p.last_seen_at AND r.status IN ('success', 'partial')
              AND json_extract(r.outcomes_json, '$.fdb') IN ('success_with_rows', 'success_empty')
            GROUP BY p.source_id, p.port_key
            """
        )]
        data["switch_management_fdb"] = _switch_management_fdb(connection, data["sources"])
        data["router_neighbors"] = [dict(row) for row in connection.execute(
            """
            SELECT s.name AS source, n.identity, n.address, n.mac, n.interface, n.platform, n.last_seen_at
            FROM network_neighbors AS n
            JOIN network_sources AS s ON s.id = n.source_id
            WHERE s.enabled = 1 AND s.driver IN ('mikrotik_api', 'mikrotik_ssh')
            ORDER BY s.name, n.interface, n.mac
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
            data["asset_fdb"] = query_observed_mac_ports(connection, macs, learned_only=True)
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
        data["router_interfaces"] = [dict(row) for row in connection.execute(
            """
            SELECT s.name AS source, i.name, i.type, i.running, i.disabled, i.last_seen_at
            FROM network_interfaces AS i
            JOIN network_sources AS s ON s.id = i.source_id
            WHERE s.enabled = 1 AND s.driver IN ('mikrotik_api', 'mikrotik_ssh') AND i.type = 'ether'
            ORDER BY s.name, i.name
            """
        )]
        if transit_sources:
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
        for name, query in (("ports", query_switch_ports), ("lldp", query_switch_lldp_neighbors)):
            items = data[name] = []
            offset = 0
            for _ in range(20):
                result = query(connection, limit=500, offset=offset)
                items.extend(result["items"])
                next_offset = result["pagination"]["next_offset"]
                if next_offset is None:
                    break
                if type(next_offset) is not int or next_offset <= offset:
                    raise ValueError("invalid switch inventory pagination")
                offset = next_offset
            else:
                raise ValueError("switch inventory exceeds collection limit")
    data.update({name: run_netctl(args, timeout=15)[key] for name, (args, key) in commands.items()})
    try:
        data["hosts"] = run_netctl(["hosts", "export", "--status", "all"], timeout=25)["hosts"]
    except NetctlError:
        data["hosts"] = []
    return data


def _previous_snapshot(path: Path, context_sha: str) -> dict:
    try:
        with path.open("rb") as handle:
            body = handle.read(MAX_SNAPSHOT_BYTES + 1)
        if len(body) > MAX_SNAPSHOT_BYTES:
            return {}
        previous = json.loads(body)
    except (OSError, ValueError, RecursionError):
        return {}
    if (not isinstance(previous, dict) or previous.get("schema") != 1
            or previous.get("contextSha256") != context_sha
            or not isinstance(previous.get("nodes"), list)):
        return {}
    return previous


def _add_guest_io_rates(graph: dict, previous: dict) -> None:
    prior = {node["id"]: node for node in previous.get("nodes", [])[:600]
             if isinstance(node, dict) and isinstance(node.get("id"), str) and node.get("guest") is True}
    for node in graph["nodes"]:
        old = prior.get(node["id"])
        counters = node.get("guestIoCounters")
        if not old or not counters or any(old.get(key) != node[key] for key in ("vmid", "pveHost", "kind", "name")):
            continue
        old_counters, old_resources = old.get("guestIoCounters"), old.get("resources")
        if not isinstance(old_counters, dict) or not isinstance(old_resources, dict):
            continue
        current = node["resources"]
        stamp = datetime.fromisoformat(current["checkedAt"])
        old_stamp = old_resources.get("checkedAt")
        if not observation_is_fresh(old_stamp, stamp, max_age=GUEST_IO_MAX_AGE):
            continue
        interval = (stamp - datetime.fromisoformat(old_stamp)).total_seconds()
        uptime, prior_uptime = current.get("uptimeSeconds"), old_resources.get("uptimeSeconds")
        if (interval < 30 or type(uptime) is not int or type(prior_uptime) is not int
                or not 0 <= prior_uptime < uptime or abs(uptime - prior_uptime - interval) > 30):
            continue
        rates = {}
        for keys, output in (
            (("netin", "netout"), ("networkInBytesPerSecond", "networkOutBytesPerSecond")),
            (("diskread", "diskwrite"), ("diskReadBytesPerSecond", "diskWriteBytesPerSecond")),
        ):
            if all(type(old_counters.get(key)) is int and 0 <= old_counters[key] <= counters.get(key, -1) for key in keys):
                rates.update({field: round((counters[key] - old_counters[key]) / interval, 2)
                              for key, field in zip(keys, output)})
        if rates:
            node["guestIo"] = {**rates, "checkedAt": current["checkedAt"], "intervalSeconds": round(interval, 2)}


def _retain_proxmox_inventory(graph: dict, previous: dict) -> None:
    if not previous:
        return
    current = {node["id"]: node for node in graph["nodes"]}
    retained = set()
    for old in previous["nodes"][:600]:
        keys = ("id", "kind", "name")
        if not isinstance(old, dict) or not all(isinstance(old.get(key), str) and old[key] for key in keys):
            continue
        kind, node_id = old["kind"], old["id"]
        guest = kind in ("Виртуальная машина", "Контейнер") and old.get("guest") is True and type(old.get("vmid")) is int
        if not guest and kind not in ("Гипервизор", CLUSTER_KIND):
            continue
        identity = {key: old[key] for key in keys}
        item = current.setdefault(node_id, {**identity, "origin": "Последний снимок Proxmox"})
        if guest:
            item.update(kind=kind, guest=True, vmid=old["vmid"])
        retained.add(node_id)
    graph["nodes"] = list(current.values())
    cluster_id = previous.get("clusterId")
    if isinstance(cluster_id, str) and cluster_id in retained:
        graph["clusterId"] = cluster_id
    graph["nodeOrder"] = sorted(node_id for node_id in retained if current[node_id]["kind"] == "Гипервизор")

    previous_links = previous.get("links")
    if not isinstance(previous_links, list):
        return
    existing = {(edge["a"], edge["b"], edge["kind"]) for edge in graph["links"]}
    for edge in previous_links[:2400]:
        if not isinstance(edge, dict):
            continue
        a, b, kind = (edge.get(key) for key in ("a", "b", "kind"))
        if not isinstance(a, str) or not isinstance(b, str) or a not in retained or b not in retained:
            continue
        if kind in ("Размещение ВМ", "Узел кластера") and (a, b, kind) not in existing:
            graph["links"].append({"a": a, "b": b, "kind": kind, "source": "Последний снимок Proxmox", "confirmed": False})
            existing.add((a, b, kind))


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
        collection_issues = []
        if args.proxmox_url:
            guest_ids = set(bindings.get("guests", {}))
            guest_ids.update(str(service["vmid"]) for service in bindings.get("guest_services", {}).values())
            guest_ids.update(str(role["vmid"]) for role in bindings.get("roles", {}).values()
                             if type(role.get("vmid")) is int and not role.get("asset"))
            backup = bindings.get("proxmox_backup_monitor")
            backup_options = {"backup_storage": backup["storage"]} if backup_policy(backup) else {}
            try:
                pve = read_proxmox(args.proxmox_url, args.proxmox_token_file, args.proxmox_ca, guest_ids,
                                   bindings.get("hypervisor_management_bridges"),
                                   **backup_options)
            except (OSError, KeyError, ValueError) as exc:
                collection_issues.append("proxmox")
                print(f"Proxmox inventory unavailable ({type(exc).__name__})", file=sys.stderr)
        elif args.proxmox_export:
            pve = json.loads(args.proxmox_export.read_text(encoding="utf-8"))
            if not pve.get("at"):
                raise ValueError("Proxmox export requires observation time")
        credentials = os.environ.get("CREDENTIALS_DIRECTORY")
        if args.proxmox_url and pve and bindings.get("proxmox_port_observer") is True and credentials:
            collect_proxmox_port_states(context, pve, Path(credentials))
        guest_macs = {mac for config in pve.get("configs", {}).values() for mac in _guest_macs(config)}
        route_sources = {item["source"] for item in bindings.get("route_evidence", {}).values() if item.get("source")}
        lacp_links = bindings.get("lacp_links", [])
        transit_links = bindings.get("transit_links", {})
        transit_sources = {spec["source"] for spec in transit_links.values()}
        asset_fdb_paths = bindings.get("asset_fdb_paths", {})
        asset_fdb_ips = {device["management_ip"] for device in context.get("devices", [])
                         if device["id"] in asset_fdb_paths and device.get("management_ip")}
        try:
            network = read_network(guest_macs, route_sources | transit_sources, transit_sources, asset_fdb_ips=asset_fdb_ips,
                                   downstream_links=_downstream_links(context, bindings.get("downstream_mac_links")))
        except (NetctlError, sqlite3.Error, OSError, ValueError) as exc:
            collection_issues.append("network_observer")
            print(f"Network Observer inventory unavailable ({type(exc).__name__})", file=sys.stderr)
            network = {}
        else:
            asyncio.run(_check_declared_switch_ports(context, network, pve, datetime.now(timezone.utc)))
            if lacp_links:
                network["lacp"] = asyncio.run(_collect_lacp(network, lacp_links, datetime.now(timezone.utc)))
            network["stp_root_paths"], network["stp_designated_ports"] = asyncio.run(
                _collect_stp_observations(network["sources"], network.get("switches", []), datetime.now(timezone.utc))
            )
            if bindings.get("ipsec_links"):
                network["ipsec"] = _collect_ipsec_policies(network["sources"], bindings["ipsec_links"])
                network["ipsec_connectivity"] = _collect_ipsec_connectivity(context, network["sources"], bindings["ipsec_links"])
            network["guest_arp_probes"] = _collect_guest_arp_probes(
                pve, network, bindings.get("guest_probe_ips", {}), datetime.now(timezone.utc),
                bindings.get("guest_router_arp_sources"),
                auto_on_link=bindings.get("guest_auto_arp_probes") is True,
            )
            network["asset_mac_checks"] = _collect_asset_mac_probes(
                context, network["sources"], bindings.get("asset_mac_probes", {}),
            )
        now = datetime.now(timezone.utc)
        server = build_server_health_view(args.server_health, now)
        if server.get("freshness") in ("missing", "invalid") or server.get("collector", {}).get("status") == "error":
            collection_issues.append("server_observer_unavailable")
        elif server.get("freshness") == "stale":
            collection_issues.append("server_observer_stale")
        local_vlan_probes = _local_vlan_probe_specs(context, bindings.get("local_vlan_transits"))
        wireguard_probes = _wireguard_probe_specs(context, bindings.get("wireguard_policy_checks"), local_vlan_probes)
        graph = build_graph(context, network, server, pve, bindings, now,
                            local_vlan_probes=local_vlan_probes, wireguard_probes=wireguard_probes)
        _check_downstream_addresses(graph["nodes"], network, now)
        if server.get("collected_at"):
            graph["serverObserverAt"] = server["collected_at"]
        probes = {**bindings.get("service_probes", {}),
                  **{asset: [{"type": "icmp", "ip": address}]
                     for asset, address in bindings.get("asset_ip_checks", {}).items()},
                  **{f"transit:{segment}": [{"type": "icmp", "ip": spec["peer"]}]
                     for segment, spec in transit_links.items()},
                  **{service_id: [spec] for service_id, spec in (local_vlan_probes | wireguard_probes).items()}}
        apply_service_probes(graph["nodes"], probes)
        graph["snapshotAt"] = datetime.now(timezone.utc).isoformat()
        graph["git"] = args.git_revision
        graph["contextSha256"] = hashlib.sha256(context_raw).hexdigest()
        if collection_issues:
            graph["collectionIssues"] = collection_issues
        previous = _previous_snapshot(args.output, graph["contextSha256"])
        if "proxmox" in collection_issues:
            _retain_proxmox_inventory(graph, previous)
        else:
            _add_guest_io_rates(graph, previous)
        publish_snapshot(args.output, graph)
    except Exception as exc:
        parser.exit(1, f"Снимок инфраструктуры не обновлён ({type(exc).__name__}).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
