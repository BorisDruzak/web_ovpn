"""Build the infrastructure snapshot outside the web request lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from netctl.config import DEFAULT_DB_URL
from netctl.context import load_context_bytes, load_schema, validate_context
from netctl.db import connect_read_only, list_sources
from netctl.switch_queries import query_confirmed_attachment_ports, query_observed_mac_ports

from .infrastructure_map import INTERFACE_NAME, MAX_SNAPSHOT_BYTES, NETWORK_KINDS, observation_is_fresh
from .infrastructure_service_probes import apply_service_probes
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


def build_graph(context: dict, network: dict, server: dict, pve: dict, bindings: dict, now: datetime) -> dict:
    nodes = {}
    edges = {}

    def node(key, name, kind, site="", origin="GitHub"):
        return nodes.setdefault(key, {
            "id": key, "name": name, "kind": kind, "site": site, "origin": origin,
            "properties": {}, "sources": [], "checks": [],
        })

    def edge(a, b, kind, source, confirmed=True, details="", ports=None, at=None, vlan=None, virtual=None):
        if a not in nodes or b not in nodes or a == b:
            return
        key = (tuple(sorted((a, b))), kind)
        current = edges.get(key)
        evidence = current.get("portEvidence", []) if current else []
        if not current or confirmed and (not current["confirmed"] or source != "GitHub"):
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
    names = {}
    declared_devices_by_mac = {}
    for device in context.get("devices", []):
        key = device["id"]
        item = node(key, device["name"], KINDS.get(device["kind"], "Сервер"), device.get("site", ""))
        addresses.setdefault(str(device.get("management_ip") or ""), []).append(key)
        observation = _host_observation(host_ips.get(device.get("management_ip"), {}), now)
        if observation:
            item["reachability"] = observation
        names.setdefault(device["name"].casefold(), []).append(key)
        for mac in device.get("mac_addresses", []):
            if MAC.fullmatch(mac):
                declared_devices_by_mac.setdefault(mac.lower(), set()).add(key)
        if device.get("model"):
            item["properties"]["Модель"] = device["model"]
    intents = {item["id"]: item for item in context.get("routing_intent", []) if "id" in item}
    for service in context.get("services", []):
        host = service.get("device")
        item = node(service["id"], service["name"], "Сервис", nodes.get(host, {}).get("site", ""))
        route = bindings.get("route_evidence", {}).get(service["id"], {})
        intent = intents.get(route.get("intent"))
        if intent and route.get("source"):
            item["serviceChecks"] = _route_checks(intent, route["source"], network.get("routes", []), now)
        edge(host, service["id"], "Размещение", "GitHub")
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
                 "state": "disabled" if port.get("admin_status") == "down" else port.get("oper_status"),
                 "speedBps": port.get("speed_bps"), "checkedAt": port.get("last_seen_at")}
                for port in ports if port.get("collector_run_id") == latest_run
            ]
        if "fdb_entries" in status:
            item["properties"]["Записи MAC-таблицы"] = str(status["fdb_entries"])
    for row in network.get("links", []):
        a_id, b_id = row.get("source_a_id"), row.get("source_b_id")
        a, b = source_ids.get(a_id), source_ids.get(b_id)
        edge(a, b, "Сетевое соединение", "netctl", False)
        for report in row.get("evidence", []):
            if report.get("evidence_type") not in {"lldp_chassis_mac", "fdb_management_mac", "fdb_subtree"}:
                continue
            end_a, end_b = report.get("endpoint_a", {}), report.get("endpoint_b", {})
            if (end_a.get("source_id"), end_b.get("source_id")) != (a_id, b_id):
                continue
            observed = report.get("observed_at")
            confirmed = row.get("state") == "confirmed" and observation_is_fresh(observed, now)
            ports = (port_label(source_names.get(a_id), end_a.get("port_key") or ""),
                     port_label(source_names.get(b_id), end_b.get("port_key") or ""))
            edge(a, b, "Сетевое соединение", "netctl", confirmed, ports=ports, at=observed)
    for row in network.get("lldp", []):
        if not observation_is_fresh(row.get("observed_at"), now):
            continue
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
            item["properties"]["Соседство LLDP"] = f"{nodes[a]['name']} · {port}"
            edge(a, neighbor, "Сетевое соединение", "LLDP UI_VPN", True,
                 ports=(port, remote or ""), at=row.get("observed_at"))
            chassis_mac = str(row.get("chassis_id") or "").lower()
            if declared_devices_by_mac.get(chassis_mac) == {neighbor} and "reachability" not in item:
                verified = {ip for ip in row.get("management_addresses", [])
                            if fresh_macs_by_ip.get(ip) == {chassis_mac}
                            and str(host_ips[ip].get("mac") or "").lower() == chassis_mac}
                if len(verified) == 1:
                    address, = verified
                    item["properties"]["Адрес управления по LLDP"] = address
                    observation = _host_observation(host_ips[address], now)
                    if observation:
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

    roles = bindings.get("roles", {})
    for target in server.get("targets", []):
        role = target["role"]
        configured = roles.get(role, {})
        host = configured.get("asset")
        item = node("role:" + role, configured.get("label") or role, "Сервис",
                    nodes.get(host, {}).get("site", ""), "UI_VPN")
        source(item, "Server Observer", target["status"], target.get("observed_at"))
        item["sources"][-1]["stale"] = server.get("freshness") != "current"
        item["checks"] = [{"name": check["name"], "status": HEALTH.get(check["status"], "unknown"),
                           "observed": check.get("observed"), "latency": check.get("latency_ms")}
                          for check in target.get("checks", [])]
        checked_at = target.get("observed_at")
        functional = FUNCTIONAL_CHECKS.get(role)
        if functional and server.get("freshness") == "current" and observation_is_fresh(checked_at, now):
            check_name, method = functional
            result = next((check["status"] for check in target.get("checks", []) if check["name"] == check_name), None)
            if result in {"ok", "critical", "warn"}:
                state = "reachable" if result == "ok" else "unreachable"
                item["reachability"] = _observation(state, "Server Observer", method, checked_at)
        edge(host, item["id"], "Цель проверки", "Настройки карты")

    cluster_id = ""
    hypervisors = []
    overview_guests = []
    pve_at = pve.get("at", now.isoformat())
    if pve:
        cluster = next((row for row in pve["cluster"] if row.get("type") == "cluster"), {})
        cluster_id = "proxmox:cluster"
        hub = node(cluster_id, cluster.get("name", "Proxmox"), "Кластер Proxmox", origin="Proxmox")
        quorum = cluster.get("quorate")
        source(hub, "Proxmox", {1: "ok", 0: "critical"}.get(quorum, "unknown"), pve_at)
        hub["reachability"] = _observation("reachable", "Proxmox", "API кластера", pve_at)
        for host in sorted(pve["nodes"], key=lambda row: row["node"]):
            key = host["node"]
            item = node(key, key, "Гипервизор", origin="Proxmox")
            hypervisors.append(key)
            online = host.get("status") == "online"
            label = {"online": "В сети", "offline": "Не в сети"}.get(host.get("status"), "Неизвестно")
            source(item, "Proxmox", "ok" if online else "critical" if label == "Не в сети" else "unknown", pve_at, label)
            if host.get("status") in {"online", "offline"} and observation_is_fresh(pve_at, now):
                state = "reachable" if online else "unreachable"
                item.setdefault("reachability", _observation(state, "Proxmox", "Состояние узла в кластере", pve_at))
            edge(cluster_id, key, "Узел кластера", "Proxmox")
        guest_macs = {key: _guest_macs(config) for key, config in pve.get("configs", {}).items()}
        mac_counts = Counter(mac for macs in guest_macs.values() for mac in macs)
        guest_interfaces = {key: _guest_interfaces(config) for key, config in pve.get("configs", {}).items()}
        interface_mac_counts = Counter(mac for interfaces in guest_interfaces.values() for _, _, _, mac in interfaces.values())
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
            if not guest.get("template") and guest.get("status") == "stopped":
                item["reachability"] = _observation("stopped", "Proxmox", "Состояние ВМ", pve_at)
            elif guest.get("status") == "running" and not guest.get("template") and observation_is_fresh(pve_at, now):
                observation = _guest_observation(guest_macs.get(str(vmid), set()), host_macs, mac_counts, now)
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
            for name, (bridge, vlan, disabled, mac) in guest_interfaces.get(str(vmid), {}).items():
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
                virtual = {"linkDisabled": disabled, "bridgeActive": bool(active) if active in (0, 1) else None,
                           "uplinks": uplinks, "switchPorts": switch_ports}
                edge(host, key, "Размещение ВМ", "Proxmox", details=f"VM {vmid}", at=pve_at,
                     ports=(bridge, name), vlan=vlan, virtual=virtual)
        for key, value in list(edges.items()):
            if value["kind"] == "Размещение ВМ" and value["source"] == "GitHub":
                value["confirmed"] = False

    virtual_assets = {link["endpoint_a"]["device"] for link in context.get("links", [])
                      if link.get("relation") == "virtualized_on" and link.get("state", {}).get("intent") != "absent"}
    devices_by_mac = {}
    for device in context.get("devices", []):
        key = device["id"]
        address = device.get("management_ip")
        declared = {mac.lower() for mac in device.get("mac_addresses", []) if MAC.fullmatch(mac)}
        observed = fresh_macs_by_ip.get(address, set())
        macs = declared or (observed if len(observed) == 1 and len(addresses.get(address, [])) == 1 else set())
        for mac in macs:
            devices_by_mac.setdefault(mac, set()).add(key)
    for report in network.get("attachments", []):
        observed = report["observed_at"]
        switch = source_ids.get(report["source_id"])
        candidates = devices_by_mac.get(str(report["mac"]).lower(), set())
        if not switch or len(candidates) != 1 or not observation_is_fresh(observed, now):
            continue
        device, = candidates
        if device in virtual_assets or nodes[device].get("guest"):
            continue
        port_key = report["port_key"]
        port = port_label(source_names[report["source_id"]], port_key)
        edge(switch, device, "Путь по MAC-таблице", "netctl FDB",
             ports=(port, ""), at=observed, vlan=report["vlan_id"])
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


def read_proxmox(url: str, token_file: Path, ca_file: Path | None, guests: dict) -> dict:
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
        return key, {name: value for name, value in config.items() if re.fullmatch(r"net[0-9]+", name)}

    def read_bridge(pair):
        node, bridge = pair
        try:
            data = get(f"nodes/{quote(node, safe='')}/network/{quote(bridge, safe='')}")
        except (URLError, TimeoutError):
            return node, bridge, {}
        if not isinstance(data, dict) or data.get("type") not in ("bridge", "OVSBridge"):
            return node, bridge, {}
        return node, bridge, {key: data.get(key) for key in ("active", "bridge_ports")}

    candidates = [guest for guest in result["guests"] if guest["type"] in {"qemu", "lxc"}
                  and (str(guest["vmid"]) in guests or guest.get("status") == "running")]
    with ThreadPoolExecutor(max_workers=6) as pool:
        result["configs"] = dict(pool.map(read_guest, candidates))
        used_bridges = {(guest["node"], bridge) for guest in candidates
                        for bridge, _, _, _ in _guest_interfaces(result["configs"][str(guest["vmid"])]).values()}
        for node, bridge, data in pool.map(read_bridge, sorted(used_bridges)):
            if data:
                result["bridges"].setdefault(node, {})[bridge] = data
    result["at"] = datetime.now(timezone.utc).isoformat()
    return result


def read_network(guest_macs: set[str] | None = None, route_sources: set[str] | None = None) -> dict:
    commands = {
        "switches": (["switches", "status"], "switches"),
        "links": (["topology", "links"], "links"),
    }
    with closing(connect_read_only(DEFAULT_DB_URL)) as connection:
        data = {"sources": list_sources(connection), "attachments": query_confirmed_attachment_ports(connection)}
        if guest_macs:
            data["guest_fdb"] = query_observed_mac_ports(connection, guest_macs)
        if route_sources:
            data["routes"] = [dict(row) for row in connection.execute(
                """
                SELECT s.name AS source, r.dst_address, r.gateway, r.routing_table,
                       r.active, r.disabled, r.last_seen_at
                FROM network_routes AS r
                JOIN network_sources AS s ON s.id = r.source_id
                WHERE s.enabled = 1 AND s.name IN (SELECT value FROM json_each(?))
                """,
                (json.dumps(sorted(route_sources)),),
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
            pve = read_proxmox(args.proxmox_url, args.proxmox_token_file, args.proxmox_ca, bindings.get("guests", {}))
        elif args.proxmox_export:
            pve = json.loads(args.proxmox_export.read_text(encoding="utf-8"))
            if not pve.get("at"):
                raise ValueError("Proxmox export requires observation time")
        guest_macs = {mac for config in pve.get("configs", {}).values() for mac in _guest_macs(config)}
        route_sources = {item["source"] for item in bindings.get("route_evidence", {}).values() if item.get("source")}
        network = read_network(guest_macs, route_sources)
        now = datetime.now(timezone.utc)
        graph = build_graph(context, network, build_server_health_view(args.server_health, now), pve, bindings, now)
        apply_service_probes(graph["nodes"], bindings.get("service_probes", {}))
        graph["snapshotAt"] = datetime.now(timezone.utc).isoformat()
        graph["git"] = args.git_revision
        graph["contextSha256"] = hashlib.sha256(context_raw).hexdigest()
        publish_snapshot(args.output, graph)
    except Exception as exc:
        parser.exit(1, f"Снимок инфраструктуры не обновлён ({type(exc).__name__}).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
