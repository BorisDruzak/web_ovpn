from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

LOGGER = logging.getLogger(__name__)

MAX_SNAPSHOT_BYTES = 1_000_000
MAX_AGE = timedelta(minutes=25)
STATES = ("critical", "warn", "ok", "unknown")
NETWORK_KINDS = ("Коммутатор", "Маршрутизатор", "Точка доступа", "Сетевое устройство")
INTERFACE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")
PVE_DISK_DEVICE = re.compile(r"(?:scsi|sata|virtio|ide|mp)[0-9]{1,3}|rootfs")
PVE_STORAGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
REACHABILITY_STATES = ("reachable", "unreachable", "stopped", "unknown")
SERVICE_LINKS = {"Размещение", "Цель проверки", "Зависимость сервиса"}
CLUSTER_KIND = "Кластер Proxmox"
CLUSTER_HEALTH_METHODS = ("Кворум", "Участники кластера")
RECIPROCAL_MAC_SOURCE = "SNMP · взаимные MAC"
SHARED_LLDP_KIND = "Путь через общий порт"
SHARED_LLDP_SOURCE = "LLDP · общий порт"
OBSERVER_CHECK_LABELS = {
    "watchdog_fresh": "Свежесть отчёта watchdog",
    "backup_snapshot_fresh": "Свежесть резервной копии",
    "repository_capacity": "Ёмкость хранилища копий",
    "c_disk_free": "Свободно на диске C:",
    "root_disk_free": "Свободно на корневом разделе",
    "data_disk_free": "Свободно на разделе данных",
    "rxdata_log_bytes": "Размер журналов Directum",
}
OBSERVER_METRIC_UNITS = {
    "c_disk_free": "percent",
    "root_disk_free": "percent",
    "data_disk_free": "percent",
    "rxdata_log_bytes": "bytes",
}
PUBLIC_PROPERTIES = {
    "Модель", "VMID", "Размещение по GitHub", "Источник сбора",
    "Порты (линк поднят / всего)", "Записи MAC-таблицы", "Соседство LLDP", "Адрес управления по LLDP", "IP по MAC",
    "IP заявлен в LLDP", "Сопоставление LLDP", "IP проверки по ARP",
    "Подключение", "Привязка", "Кворум", "Узлы", "Состояние узла",
    "Привязка Directum", "Состояние ВМ", "Узел Proxmox", "Память (выделено)",
    "Память по Proxmox", "CPU по Proxmox", "Блокировка Proxmox",
}
RUNTIME_PROPERTIES = {
    "Состояние ВМ", "Состояние узла", "Кворум", "Память по Proxmox", "CPU по Proxmox", "Блокировка Proxmox",
}


def _time(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 48:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return stamp.astimezone(timezone.utc) if stamp.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _text(value: object, limit: int = 160) -> str:
    return value[:limit] if isinstance(value, str) else ""


def observation_is_fresh(value: object, now: datetime) -> bool:
    stamp = _time(value)
    return stamp is not None and timedelta(0) <= now - stamp <= MAX_AGE


def _rows(value: object, limit: int) -> list[dict]:
    return [row for row in value[:limit] if isinstance(row, dict)] if isinstance(value, list) else []


def _state(value: object) -> str:
    return value if value in STATES else "unknown"


def _number(value: object) -> int | float | None:
    if type(value) is int and abs(value) <= 10**20:
        return value
    return value if type(value) is float and math.isfinite(value) else None


def _observer_measurement(check: dict, name: str) -> dict:
    unit = OBSERVER_METRIC_UNITS.get(name)
    observed = _number(check.get("observed"))
    if unit is None:
        return {"observed": observed}

    def valid(value):
        if unit == "percent":
            return value is not None and 0 <= value <= 100
        return type(value) is int and 0 <= value < 2**53

    result = {"unit": unit, "observed": observed if valid(observed) else None}
    expected = _number(check.get("expected"))
    if valid(expected):
        result["warningThreshold"] = expected
    return result


def _network_address(value: object) -> str:
    if not isinstance(value, str) or len(value) > 64:
        return ""
    try:
        return str(ipaddress.ip_network(value)) if "/" in value else str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _public_reachability(value: object, now: datetime) -> dict:
    empty = {"state": "unknown", "source": "", "method": "", "checkedAt": None, "stale": False}
    if not isinstance(value, dict) or value.get("state") not in REACHABILITY_STATES:
        return empty
    stamp = _time(value.get("checkedAt"))
    if stamp is None or stamp > now:
        return empty
    stale = not observation_is_fresh(value.get("checkedAt"), now)
    return {
        "state": "unknown" if stale else value["state"],
        "source": _text(value.get("source"), 48), "method": _text(value.get("method"), 32),
        "checkedAt": stamp.isoformat(), "stale": stale,
    }


def _public_port(row: dict, now: datetime) -> dict:
    stamp = _time(row.get("checkedAt"))
    fresh = observation_is_fresh(row.get("checkedAt"), now)
    state = row.get("state")
    speed = row.get("speedBps")
    return {
        "name": _text(row.get("name"), 64),
        "state": state if fresh and state in ("up", "down", "disabled") else "unknown",
        "speedBps": speed if fresh and state == "up" and type(speed) is int and 0 < speed <= 10**15 else None,
        "checkedAt": stamp.isoformat() if stamp is not None and stamp <= now else None,
        "stale": not fresh,
    }


def port_label_key(label: str) -> str:
    label = label.strip().casefold()
    gigabit = re.fullmatch(r"(?:gi|gigabitethernet)\s*(\d+/\d+/\d+)", label)
    return f"gi{gigabit[1]}" if gigabit else label


def index_port_states(rows: list[dict], now: datetime) -> dict:
    by_label = {}
    for row in rows:
        port = _public_port(row, now)
        label = port_label_key(port["name"])
        if not label:
            continue
        aliases = {label}
        physical = re.fullmatch(r"physical:([1-9]\d{0,3})", _text(row.get("key")))
        if physical:
            aliases.add(f"port{physical[1]}")
        for alias in aliases:
            by_label.setdefault(alias, []).append(port)
    return {alias: candidates[0] for alias, candidates in by_label.items()
            if len(candidates) == 1 and not candidates[0]["stale"]}


def _public_service_check(check: dict, now: datetime) -> dict:
    path = _text(check.get("path"))
    port = check.get("port")
    result = {
        **_public_reachability(check, now),
        "port": port if type(port) is int and 1 <= port <= 65535 else None,
        "target": _network_address(check.get("target")), "via": _network_address(check.get("via")),
        "path": path if re.fullmatch(r"/[A-Za-z0-9._/-]{0,159}", path) and not path.startswith("//") else "",
    }
    reason = check.get("reason")
    if check.get("method") == "Маршрут":
        if result["checkedAt"] is None and check.get("state") == "unknown":
            result.update(method="Маршрут", source=_text(check.get("source"), 48))
        if result["state"] == "unreachable" and reason in (
            "route_other_gateway", "route_inactive", "route_rejecting",
        ):
            result["reason"] = reason
            observed_via = _network_address(check.get("observedVia"))
            if reason == "route_other_gateway" and observed_via and "/" not in observed_via:
                result["observedVia"] = observed_via
    if reason in ("connection_refused", "timeout", "transport_error", "unexpected_response", "sip_response",
                  "icmp_port_unreachable", "icmp_rejected"):
        result["reason"] = reason
    error_source = _network_address(check.get("errorSource"))
    if reason in ("icmp_port_unreachable", "icmp_rejected") and error_source and "/" not in error_source:
        result["errorSource"] = error_source
    code = check.get("responseCode")
    if reason == "sip_response" and type(code) is int and 100 <= code <= 699:
        result["responseCode"] = code
    return result


def _public_hypervisor_resources(row: object, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now):
        return {}
    values = {}
    cpu = row.get("cpuRatio")
    if type(cpu) in (int, float) and 0 <= cpu <= 1:
        values["cpuRatio"] = cpu
    max_safe_int = 2**53 - 1
    for key, minimum in (("logicalCpus", 1), ("uptimeSeconds", 0)):
        value = row.get(key)
        if type(value) is int and minimum <= value <= max_safe_int:
            values[key] = value
    for used_key, total_key in (("memoryUsedBytes", "memoryTotalBytes"), ("rootUsedBytes", "rootTotalBytes")):
        used, total = row.get(used_key), row.get(total_key)
        if type(used) is int and type(total) is int and 0 <= used <= total <= max_safe_int and total > 0:
            values.update({used_key: used, total_key: total})
    if values:
        values["checkedAt"] = _time(row["checkedAt"]).isoformat()
    return values


def _public_guest_storage(row: object, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now):
        return {}
    disks = []
    for disk in _rows(row.get("disks"), 257):
        device, storage = disk.get("device"), disk.get("storage")
        if not (isinstance(device, str) and PVE_DISK_DEVICE.fullmatch(device)
                and isinstance(storage, str) and PVE_STORAGE_ID.fullmatch(storage)):
            continue
        public = {"device": device, "storage": storage}
        size = disk.get("sizeBytes")
        if type(size) is int and 0 < size < 2**53:
            public["sizeBytes"] = size
        disks.append(public)
    return {"checkedAt": _time(row["checkedAt"]).isoformat(), "disks": disks} if disks else {}


def _public_node(row: dict, now: datetime) -> dict:
    sources = []
    for item in _rows(row.get("sources"), 12):
        stamp = _time(item.get("at"))
        sources.append({
            "name": _text(item.get("name"), 48),
            "status": _state(item.get("status")),
            "label": _text(item.get("label"), 64),
            "raw": _text(item.get("raw"), 32),
            "at": stamp.isoformat() if stamp else None,
            "stale": item.get("stale") is True or not observation_is_fresh(item.get("at"), now),
        })
    fresh = [source for source in sources if not source["stale"]]
    supplied = row.get("properties")
    properties = {
        key: _text(value) for key, value in supplied.items()
        if key in PUBLIC_PROPERTIES and isinstance(value, str)
    } if isinstance(supplied, dict) else {}
    if not any(source["name"] == "Proxmox" for source in fresh):
        for key in RUNTIME_PROPERTIES:
            properties.pop(key, None)
    if not any(source["name"] == "Network Observer" for source in fresh):
        properties.pop("Записи MAC-таблицы", None)
        properties.pop("Порты (линк поднят / всего)", None)
    ports = [_public_port(port, now) for port in _rows(row.get("ports"), 500)]
    observer = next((source for source in sources if source["name"] == "Server Observer"), None)
    aliases = row.get("aliases")
    resources = {}
    if row.get("kind") == "Гипервизор" and any(s["name"] == "Proxmox" and s["status"] == "ok" for s in fresh):
        resources = _public_hypervisor_resources(row.get("resources"), now)
    guest_storage = _public_guest_storage(row.get("guestStorage"), now) if row.get("guest") is True else {}
    required = row.get("requiredObserverChecks")
    required_names = dict.fromkeys(
        name for name in required[:80] if isinstance(name, str) and re.fullmatch(r"[a-z0-9_]{1,64}", name)
    ) if row.get("kind") == "Сервис" and isinstance(required, list) else {}
    checks = _rows(row.get("checks"), 80)
    check_counts = Counter(_text(check.get("name"), 64) for check in checks)
    checks.extend({"name": name} for name in required_names if not check_counts[name])
    return {
        **{key: _text(row.get(key)) for key in ("id", "name", "kind", "site", "origin", "pveHost")},
        "guest": row.get("guest") is True,
        "vmid": row.get("vmid") if type(row.get("vmid")) is int else None,
        "aliases": [_text(value) for value in aliases[:12] if isinstance(value, str)] if isinstance(aliases, list) else [],
        "status": next((state for state in STATES if any(source["status"] == state for source in fresh)), "unknown"),
        "reachability": _public_reachability(row.get("reachability"), now),
        "sources": sources,
        "properties": properties,
        **({"resources": resources} if resources else {}),
        **({"guestStorage": guest_storage} if guest_storage else {}),
        "ports": [port for port in ports if port["name"]],
        "serviceChecks": [_public_service_check(check, now) for check in _rows(row.get("serviceChecks"), 16)],
        "checks": [
            {"name": name,
             **({"label": OBSERVER_CHECK_LABELS[name]} if name in OBSERVER_CHECK_LABELS else {}),
             **({"required": True} if name in required_names else {}),
             "status": _state(check.get("status")) if observer and not observer["stale"]
             and (name not in required_names or check_counts[name] == 1) else "unknown",
             "checkedAt": observer["at"] if observer else None, "stale": not observer or observer["stale"],
             **_observer_measurement(check, name), "latency": _number(check.get("latency"))}
            for check in checks
            for name in [_text(check.get("name"), 64)]
        ],
    }


def _map_statuses(nodes: dict, links: list[dict]) -> None:
    services = {key: set() for key in nodes}
    consumers = {key: set() for key in nodes}
    for edge in links:
        if edge["confirmed"] and edge["kind"] in SERVICE_LINKS and nodes[edge["b"]]["kind"] == "Сервис":
            services[edge["a"]].add(edge["b"])
            consumers[edge["b"]].add(edge["a"])

    local_issues = {}
    for key, node in nodes.items():
        checks = [check["status"] for check in node["checks"] if check.get("required")]
        if node["kind"] == CLUSTER_KIND:
            cluster = {check["method"]: check["state"] for check in node["serviceChecks"]}
            check_state = {"reachable": "ok", "unreachable": "critical"}
            checks.extend(check_state.get(cluster.get(method), "unknown") for method in CLUSTER_HEALTH_METHODS)
        local_issues[key] = (
            bool({"critical", "warn"}.intersection(checks)), "unknown" in checks,
        )

    failed = {key for key, node in nodes.items()
              if local_issues[key][0] or node["reachability"]["state"] in {"unreachable", "stopped"}}
    unconfirmed = {key for key, node in nodes.items()
                   if local_issues[key][1] or node["reachability"]["state"] == "unknown"}
    # A dependency can affect every consumer, including services in a cycle.
    for affected in (failed, unconfirmed):
        pending = deque(affected)
        while pending:
            for consumer in consumers[pending.popleft()] - affected:
                affected.add(consumer)
                pending.append(consumer)

    for key, node in nodes.items():
        unavailable = sorted(services[key] & failed)
        unknown = sorted((services[key] & unconfirmed) - failed)
        local_failed, local_unknown = local_issues[key]
        state = node["reachability"]["state"]
        node["serviceAvailability"] = {"unavailable": unavailable, "unknown": unknown}
        if state in {"unreachable", "stopped"}:
            node["mapStatus"] = "critical"
        elif state == "reachable" and (unavailable or local_failed):
            node["mapStatus"] = "warn"
        elif state == "reachable" and not unknown and not local_unknown:
            node["mapStatus"] = "ok"
        else:
            node["mapStatus"] = "unknown"


def _attach_endpoint_presence(db: Session, keys: dict[str, str], nodes: dict, now: datetime) -> None:
    from sqlalchemy.exc import SQLAlchemyError
    from .inventory.network_projection import attach_network_projection

    counts = Counter(keys.values())
    hosts = [{"device_key": key, "node_id": node_id} for node_id, key in keys.items() if counts[key] == 1]
    if not hosts:
        return
    try:
        with db.begin_nested():
            attach_network_projection(db, hosts, now=now, include_presence=True)
    except SQLAlchemyError:
        LOGGER.warning("Inventory presence unavailable for the infrastructure map")
        return
    for host in hosts:
        at = host["endpoint_agent"].get("presence_at")
        if at is None:
            continue
        node = nodes[host["node_id"]]
        observed = _public_reachability({"state": "reachable", "source": "Endpoint Platform",
                                         "method": "Агент на связи", "checkedAt": at}, now)
        node["serviceChecks"].append({**observed, "port": None, "target": "", "via": "", "path": ""})
        if node["reachability"]["state"] == "unknown":
            node["reachability"] = observed


def load_infrastructure_map(path: Path, now: datetime | None = None, *, db: Session | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    empty = {
        "availability": "missing", "snapshotAt": None, "nodes": [], "links": [],
        "clusterId": "", "nodeOrder": [], "overviewGuests": [], "switchKinds": list(NETWORK_KINDS), "git": "",
    }
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_SNAPSHOT_BYTES + 1)
        if len(payload) > MAX_SNAPSHOT_BYTES:
            return {**empty, "availability": "invalid"}
        raw = json.loads(payload)
    except FileNotFoundError:
        return empty
    except (OSError, ValueError, RecursionError):
        return {**empty, "availability": "invalid"}
    if not isinstance(raw, dict) or raw.get("schema") != 1:
        return {**empty, "availability": "invalid"}
    stamp = _time(raw.get("snapshotAt"))
    if stamp is None or stamp > now:
        return {**empty, "availability": "invalid"}

    nodes = {}
    port_states = {}
    endpoint_keys = {}
    for row in _rows(raw.get("nodes"), 600):
        node = _public_node(row, now)
        if node["id"] and node["name"] and node["id"] not in nodes:
            nodes[node["id"]] = node
            if node["kind"] == NETWORK_KINDS[0]:
                port_states[node["id"]] = index_port_states(_rows(row.get("ports"), 500), now)
            key = _text(row.get("endpointKey"))
            if node["kind"] == "Рабочая станция" and re.fullmatch(r"mac:(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", key):
                endpoint_keys[node["id"]] = key
    links = []
    for row in _rows(raw.get("links"), 2400):
        edge = {key: _text(row.get(key)) for key in ("a", "b", "kind", "source", "details")}
        if edge["a"] in nodes and edge["b"] in nodes and edge["a"] != edge["b"]:
            evidence = []
            for report in _rows(row.get("portEvidence"), 24):
                observed = _time(report.get("at"))
                source = _text(report.get("source"), 48)
                evidence.append({
                    "a": _text(report.get("a"), 64), "b": _text(report.get("b"), 64), "source": source,
                    "at": observed.isoformat() if observed else None,
                    "confirmed": report.get("confirmed") is True and (
                        source == "GitHub" or observation_is_fresh(report.get("at"), now)),
                })
                paired = edge["kind"] == "Сетевое соединение" or source in {RECIPROCAL_MAC_SOURCE, "netctl FDB + Proxmox"}
                if (paired and evidence[-1]["a"] and evidence[-1]["b"]) or source == SHARED_LLDP_SOURCE:
                    states = {}
                    for side in ("a", "b"):
                        port = port_states.get(edge[side], {}).get(port_label_key(evidence[-1][side]))
                        if port and port["state"] != "unknown":
                            states[side] = port
                    if states:
                        evidence[-1]["portStates"] = states
                vlan = report.get("vlan")
                if type(vlan) is int and 1 <= vlan <= 4094:
                    evidence[-1]["vlan"] = vlan
                virtual = report.get("virtual")
                if source == "Proxmox · конфигурация ВМ" and isinstance(virtual, dict):
                    uplinks = virtual.get("uplinks")
                    evidence[-1]["virtual"] = {
                        "linkDisabled": virtual.get("linkDisabled") is True,
                        "bridgeActive": virtual["bridgeActive"] if type(virtual.get("bridgeActive")) is bool else None,
                        "uplinks": [value for value in uplinks[:32] if isinstance(value, str) and INTERFACE_NAME.fullmatch(value)]
                        if isinstance(uplinks, list) else [],
                        "switchPorts": [
                            {"id": switch_id, "port": _text(match.get("port"), 64), "at": _time(match["at"]).isoformat(),
                             "vlan": match["vlan"] if type(match.get("vlan")) is int and 1 <= match["vlan"] <= 4094 else None}
                            for match in _rows(virtual.get("switchPorts"), 12)
                            for switch_id in [_text(match.get("id"))]
                            if switch_id in nodes and nodes[switch_id]["kind"] == NETWORK_KINDS[0]
                            and observation_is_fresh(match.get("at"), now)
                        ],
                    }
                    switch_uplink = virtual.get("switchUplink")
                    if isinstance(switch_uplink, dict) and evidence[-1]["confirmed"]:
                        switch_id, port = _text(switch_uplink.get("id")), _text(switch_uplink.get("port"), 64)
                        if (port and switch_id in nodes and nodes[switch_id]["kind"] == NETWORK_KINDS[0]
                                and observation_is_fresh(switch_uplink.get("at"), now)):
                            evidence[-1]["virtual"]["switchUplink"] = {
                                "id": switch_id, "port": port, "at": _time(switch_uplink["at"]).isoformat(),
                                **({"viaMacTable": True} if switch_uplink.get("viaMacTable") is True else {}),
                            }
            confirmed = row.get("confirmed") is True
            if edge["source"] in {"netctl", "LLDP UI_VPN", "LLDP · двустороннее", "netctl FDB",
                                  "netctl FDB + Proxmox", "Proxmox", "SNMP LACP + ARP", "MikroTik · ARP",
                                  "MikroTik · ARP + FDB", RECIPROCAL_MAC_SOURCE, SHARED_LLDP_SOURCE} and row.get("observedAt"):
                confirmed = confirmed and observation_is_fresh(row["observedAt"], now)
            links.append({**edge, "confirmed": confirmed, "portEvidence": evidence})
    if db is not None and endpoint_keys and now - stamp <= MAX_AGE:
        _attach_endpoint_presence(db, endpoint_keys, nodes, now)
    _map_statuses(nodes, links)
    revision = _text(raw.get("git"), 41)

    def node_ids(key: str) -> list[str]:
        values = raw.get(key)
        if not isinstance(values, list):
            return []
        return list(dict.fromkeys(value for value in values[:600] if isinstance(value, str) and value in nodes))

    return {
        **empty, "availability": "stale" if now - stamp > MAX_AGE else "ready",
        "snapshotAt": stamp.isoformat(), "nodes": list(nodes.values()), "links": links,
        "clusterId": _text(raw.get("clusterId")), "nodeOrder": node_ids("nodeOrder"),
        "overviewGuests": node_ids("overviewGuests"),
        "git": revision if re.fullmatch(r"[0-9a-f]{40}", revision) else "",
    }
