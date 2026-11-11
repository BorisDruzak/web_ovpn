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

from .infrastructure_map import MAX_SNAPSHOT_BYTES, NETWORK_KINDS, observation_is_fresh
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
HTTP_CHECKS = {"https_live", "https_healthcheck"}


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


def build_graph(context: dict, network: dict, server: dict, pve: dict, bindings: dict, now: datetime) -> dict:
    nodes = {}
    edges = {}

    def node(key, name, kind, site="", origin="GitHub"):
        return nodes.setdefault(key, {
            "id": key, "name": name, "kind": kind, "site": site, "origin": origin,
            "properties": {}, "sources": [], "checks": [],
        })

    def edge(a, b, kind, source, confirmed=True, details=""):
        if a not in nodes or b not in nodes or a == b:
            return
        key = (tuple(sorted((a, b))), kind)
        current = edges.get(key)
        if not current or confirmed and (not current["confirmed"] or source != "GitHub"):
            edges[key] = {"a": a, "b": b, "kind": kind, "source": source,
                          "confirmed": confirmed, "details": details}

    def source(item, name, raw, at, label=""):
        item["sources"].append({"name": name, "raw": raw, "status": HEALTH.get(raw, "unknown"),
                                "at": at, "label": label})

    host_ips = {}
    host_macs = {}
    for host in network.get("hosts", []):
        if host.get("ip"):
            host_ips[host["ip"]] = host
        mac = str(host.get("mac") or "").lower()
        if MAC.fullmatch(mac):
            host_macs.setdefault(mac, []).append(host)
    addresses = {}
    names = {}
    for device in context.get("devices", []):
        key = device["id"]
        item = node(key, device["name"], KINDS.get(device["kind"], "Сервер"), device.get("site", ""))
        addresses.setdefault(str(device.get("management_ip") or ""), []).append(key)
        observation = _host_observation(host_ips.get(device.get("management_ip"), {}), now)
        if observation:
            item["reachability"] = observation
        names.setdefault(device["name"].casefold(), []).append(key)
        if device.get("model"):
            item["properties"]["Модель"] = device["model"]
    for service in context.get("services", []):
        host = service.get("device")
        node(service["id"], service["name"], "Сервис", nodes.get(host, {}).get("site", ""))
        edge(host, service["id"], "Размещение", "GitHub")
    for link in context.get("links", []):
        if link.get("state", {}).get("intent") == "absent":
            continue
        a, b = link["endpoint_a"], link["endpoint_b"]
        kind = "Размещение ВМ" if link.get("relation") == "virtualized_on" else "Сетевое соединение"
        ports = " ↔ ".join(endpoint["interface"] for endpoint in (a, b) if endpoint.get("interface"))
        edge(a["device"], b["device"], kind, "GitHub", link.get("state", {}).get("verified") is True, ports)

    switch_status = {row["source"]: row for row in network.get("switches", [])}
    port_groups = {}
    for port in network.get("ports", []):
        port_groups.setdefault(port["source"], []).append(port)
    source_nodes = {}
    source_ids = {}
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
            active = sum(port.get("oper_status") == "up" for port in ports)
            item["properties"]["Порты (линк поднят / всего)"] = f"{active} / {len(ports)}"
        if "fdb_entries" in status:
            item["properties"]["Записи MAC-таблицы"] = str(status["fdb_entries"])
    for row in network.get("links", []):
        a = source_ids.get(row.get("source_a_id"))
        b = source_ids.get(row.get("source_b_id"))
        ports = " ↔ ".join(row[field] for field in ("port_a_key", "port_b_key") if row.get(field))
        observed = row.get("last_seen_at")
        fresh = observation_is_fresh(observed, now)
        edge(a, b, "Сетевое соединение", "netctl", row.get("state") == "confirmed" and fresh, ports)
    for row in network.get("lldp", []):
        if not observation_is_fresh(row.get("observed_at"), now):
            continue
        a = source_nodes.get(row.get("source"))
        name = str(row.get("system_name") or "").casefold()
        candidates = [key for key in names.get(name, []) if nodes[key]["kind"] in NETWORK_KINDS]
        if a and len(candidates) == 1 and a != candidates[0]:
            port = row.get("local_port_key", "")
            nodes[candidates[0]]["properties"]["Соседство LLDP"] = f"{nodes[a]['name']} · {port}"
            edge(a, candidates[0], "Сетевое соединение", "LLDP UI_VPN", True, port)

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
        http = [check["status"] for check in target.get("checks", []) if check["name"] in HTTP_CHECKS]
        if server.get("freshness") == "current" and observation_is_fresh(checked_at, now) and http:
            if "ok" in http or all(status == "critical" for status in http):
                item["reachability"] = _observation(
                    "reachable" if "ok" in http else "unreachable", "Server Observer", "HTTPS", checked_at,
                )
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
            edge(host, key, "Размещение ВМ", "Proxmox", True, f"VM {vmid}")
        for key, value in list(edges.items()):
            if value["kind"] == "Размещение ВМ" and value["source"] == "GitHub":
                value["confirmed"] = False
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
              "guests": get("cluster/resources?type=vm"), "configs": {}}
    def read_guest(guest):
        key = str(guest["vmid"])
        node = quote(guest["node"], safe="")
        try:
            config = get(f"nodes/{node}/{guest['type']}/{int(key)}/config")
        except (URLError, TimeoutError):
            return key, {}
        return key, {name: value for name, value in config.items() if re.fullmatch(r"net[0-9]+", name)}

    candidates = [guest for guest in result["guests"] if guest["type"] in {"qemu", "lxc"}
                  and (str(guest["vmid"]) in guests or guest.get("status") == "running")]
    with ThreadPoolExecutor(max_workers=6) as pool:
        result["configs"] = dict(pool.map(read_guest, candidates))
    result["at"] = datetime.now(timezone.utc).isoformat()
    return result


def read_network() -> dict:
    commands = {
        "switches": (["switches", "status"], "switches"),
        "links": (["topology", "links"], "links"),
    }
    with closing(connect_read_only(DEFAULT_DB_URL)) as connection:
        data = {"sources": list_sources(connection)}
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
        network = read_network()
        now = datetime.now(timezone.utc)
        graph = build_graph(context, network, build_server_health_view(args.server_health, now), pve, bindings, now)
        graph["git"] = args.git_revision
        graph["contextSha256"] = hashlib.sha256(context_raw).hexdigest()
        publish_snapshot(args.output, graph)
    except Exception as exc:
        parser.exit(1, f"Снимок инфраструктуры не обновлён ({type(exc).__name__}).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
