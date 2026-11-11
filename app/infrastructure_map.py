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
ZFS_PROBLEM_STATES = {"DEGRADED", "FAULTED", "OFFLINE", "REMOVED", "UNAVAIL", "SUSPENDED"}
LVM_THIN_WARNING_PERCENT = 90
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
    "backup_snapshot_count": "Снимков в хранилище",
    "repository_capacity": "Ёмкость хранилища копий",
    "c_disk_free": "Свободно на диске C:",
    "root_disk_free": "Свободно на корневом разделе",
    "data_disk_free": "Свободно на разделе данных",
    "rxdata_log_bytes": "Размер журналов Directum",
}
OBSERVER_METRIC_UNITS = {
    "backup_snapshot_fresh": "hours",
    "backup_snapshot_count": "count",
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
        if unit == "hours":
            return value is not None and 0 <= value < 2**53
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
    result = {
        "name": _text(row.get("name"), 64),
        "state": state if fresh and state in ("up", "down", "disabled") else "unknown",
        "speedBps": speed if fresh and state == "up" and type(speed) is int and 0 < speed <= 10**15 else None,
        "checkedAt": stamp.isoformat() if stamp is not None and stamp <= now else None,
        "stale": not fresh,
    }
    neighbor_count = row.get("lldpNeighborCount")
    if result["state"] == "up" and type(neighbor_count) is int and 1 <= neighbor_count <= 65535:
        result["lldpNeighborCount"] = neighbor_count
    if row.get("source") == "RouterOS":
        result["source"] = "RouterOS"
    return result


def _physical_port_alias(row: dict) -> str:
    key = _text(row.get("key"))
    physical = re.fullmatch(r"physical:([1-9]\d{0,3})", key)
    if physical:
        return f"Port{physical[1]}"
    slot = re.fullmatch(r"Slot0/([1-9]\d{0,3})", _text(row.get("name")), re.IGNORECASE)
    return f"Port{slot[1]}" if slot and key == f"ifindex:{slot[1]}" else ""


def _public_port_telemetry(sample: object, port: dict, now: datetime) -> dict:
    if port["state"] != "up" or not isinstance(sample, dict):
        return {}
    stamp = _time(sample.get("checkedAt"))
    interval = _number(sample.get("intervalSeconds"))
    if (stamp is None or stamp.isoformat() != port["checkedAt"] or interval is None
            or not 0 < interval <= MAX_AGE.total_seconds() or now - stamp + timedelta(seconds=interval) > MAX_AGE):
        return {}
    metrics = {}
    for key in ("rxBps", "txBps"):
        value = _number(sample.get(key))
        if value is not None and 0 <= value <= 10**15:
            metrics[key] = value
    for key in ("rxErrors", "txErrors", "rxDiscards", "txDiscards"):
        value = sample.get(key)
        if type(value) is int and 0 <= value < 2**53:
            metrics[key] = value
    return {"checkedAt": port["checkedAt"], "intervalSeconds": interval, **metrics} if metrics else {}


def _current_port_vlan_rows(sample: object, port: dict) -> list[dict]:
    if port["stale"] or not isinstance(sample, dict):
        return []
    stamp = _time(sample.get("checkedAt"))
    if stamp is None or stamp.isoformat() != port["checkedAt"]:
        return []
    return _rows(sample.get("vlans"), 4094)


def _public_port_vlans(sample: object, port: dict) -> dict:
    vlans = {}
    for row in _current_port_vlan_rows(sample, port):
        vlan_id, egress, pvid = row.get("id"), row.get("egress"), row.get("pvid")
        if (type(vlan_id) is int and 1 <= vlan_id <= 4094 and egress in ("", "tagged", "untagged")
                and type(pvid) is bool and (egress or pvid)):
            vlans.setdefault(vlan_id, []).append({"id": vlan_id, "egress": egress, "pvid": pvid})
    unique = [rows[0] for _, rows in sorted(vlans.items()) if len(rows) == 1]
    return {"checkedAt": port["checkedAt"], "vlans": unique} if unique else {}


def _public_port_fdb_vlans(sample: object, port: dict) -> dict:
    if port["state"] != "up":
        return {}
    vlans = []
    for row in _current_port_vlan_rows(sample, port):
        vlan_id, count = row.get("id"), row.get("learnedMacCount")
        if type(vlan_id) is int and 1 <= vlan_id <= 4094 and type(count) is int and 0 < count < 2**53:
            vlans.append({"id": vlan_id, "learnedMacCount": count})
    return {"checkedAt": port["checkedAt"], "vlans": sorted(vlans, key=lambda row: row["id"])} if vlans else {}


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
        physical = _physical_port_alias(row)
        if physical:
            aliases.add(port_label_key(physical))
        for alias in aliases:
            by_label.setdefault(alias, []).append(port)
    return {alias: candidates[0] for alias, candidates in by_label.items()
            if len(candidates) == 1 and not candidates[0]["stale"]}


def _public_dns_check(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    name, record = _text(value.get("name"), 255), value.get("record")
    if record not in ("A", "AAAA", "SOA") or not re.fullmatch(r"\.|(?:[A-Za-z0-9_-]{1,63}\.){1,127}", name):
        return {}
    result = {"name": name, "record": record}
    rcode, transport = value.get("rcode"), value.get("transport")
    if isinstance(rcode, str) and re.fullmatch(r"[A-Z0-9]{1,16}", rcode) and transport in ("UDP", "TCP"):
        result.update(rcode=rcode, transport=transport)
        addresses = value.get("addresses")
        if record in ("A", "AAAA") and isinstance(addresses, list):
            result["addresses"] = [address for item in addresses[:16] if (address := _network_address(item))
                                   and "/" not in address and (":" in address) == (record == "AAAA")]
    return result


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
    if result["method"] == "DNS":
        diagnostic = _public_dns_check(check.get("dns"))
        if diagnostic:
            result["dns"] = diagnostic
            if reason in ("dns_no_answer", "dns_address_mismatch"):
                result["reason"] = reason
    if check.get("method") == "OpenVPN Management":
        configured_port = check.get("configuredPort")
        sessions = check.get("sessionCount")
        if type(configured_port) is int and 1 <= configured_port <= 65535:
            result["configuredPort"] = configured_port
        if (result["checkedAt"] and type(sessions) is int and 0 <= sessions <= 4096
                and type(check.get("daemonReady")) is bool):
            result.update(sessionCount=sessions, daemonReady=check["daemonReady"])
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
        if result["state"] == "unknown" and not result["stale"] and reason == "route_multiple_gateways":
            result["reason"] = reason
    if reason in ("connection_refused", "timeout", "transport_error", "unexpected_response", "sip_response",
                  "icmp_port_unreachable", "icmp_rejected"):
        result["reason"] = reason
    if (reason == "icmp_identity_unconfirmed" and result["method"] == "ICMP адреса из инвентаря"
            and result["state"] == "reachable"):
        result["reason"] = reason
    error_source = _network_address(check.get("errorSource"))
    if reason in ("icmp_port_unreachable", "icmp_rejected") and error_source and "/" not in error_source:
        result["errorSource"] = error_source
    code = check.get("responseCode")
    if reason == "sip_response" and type(code) is int and 100 <= code <= 699:
        result["responseCode"] = code
    attempts = check.get("attempts")
    if result["method"] == "SIP OPTIONS (UDP)" and type(attempts) is int and 1 <= attempts <= 3:
        result["attempts"] = attempts
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


def project_hypervisor_disks(row: object, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now):
        return {}
    disks = []
    for entry in _rows(row.get("disks"), 128):
        device = entry.get("device")
        if not isinstance(device, str) or not re.fullmatch(r"/dev/[A-Za-z0-9][A-Za-z0-9_-]{0,31}", device):
            continue
        kind, state = entry.get("kind"), entry.get("smartState")
        disk = {"device": device, "kind": kind if kind in ("ssd", "hdd", "nvme", "usb") else "",
                "smartState": state if state in ("ok", "critical") else "unknown"}
        size, endurance = entry.get("sizeBytes"), entry.get("endurancePercent")
        if type(size) is int and 0 < size < 2**53:
            disk["sizeBytes"] = size
        if type(endurance) in (int, float) and 0 <= endurance <= 100:
            disk["endurancePercent"] = endurance
        disks.append(disk)
    return {"checkedAt": _time(row["checkedAt"]).isoformat(), "disks": disks} if disks else {}


def project_hypervisor_zfs(row: object, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now):
        return {}
    pools = []
    for entry in _rows(row.get("pools"), 128):
        name, health = entry.get("name"), entry.get("health")
        if not isinstance(name, str) or not PVE_STORAGE_ID.fullmatch(name):
            continue
        known = isinstance(health, str) and (health == "ONLINE" or health in ZFS_PROBLEM_STATES)
        pool = {"name": name, "health": health if known else "UNKNOWN"}
        size, free = entry.get("sizeBytes"), entry.get("freeBytes")
        if type(size) is int and 0 < size < 2**53:
            pool["sizeBytes"] = size
            if type(free) is int and 0 <= free <= size:
                pool["freeBytes"] = free
        pools.append(pool)
    return {"checkedAt": _time(row["checkedAt"]).isoformat(), "pools": pools} if pools else {}


def project_hypervisor_lvm_thin(row: object, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now):
        return {}
    pools = []
    for entry in _rows(row.get("pools"), 128):
        name, group = entry.get("name"), entry.get("volumeGroup")
        if not all(isinstance(value, str) and PVE_STORAGE_ID.fullmatch(value) for value in (name, group)):
            continue
        pool = {"name": name, "volumeGroup": group}
        capacity_checks = []
        for size_key, used_key in (("sizeBytes", "usedBytes"), ("metadataSizeBytes", "metadataUsedBytes")):
            size, used = entry.get(size_key), entry.get(used_key)
            if type(size) is int and type(used) is int and 0 <= used <= size < 2**53 and size > 0:
                pool.update({size_key: size, used_key: used})
                capacity_checks.append(100 * used >= LVM_THIN_WARNING_PERCENT * size)
        pool["capacityStatus"] = "warn" if any(capacity_checks) else "ok" if len(capacity_checks) == 2 else "unknown"
        pools.append(pool)
    return {"checkedAt": _time(row["checkedAt"]).isoformat(),
            "warningThresholdPercent": LVM_THIN_WARNING_PERCENT, "pools": pools} if pools else {}


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
    port_rows = _rows(row.get("ports"), 500)
    ports = [_public_port(port, now) for port in port_rows]
    physical_aliases = [_physical_port_alias(port) for port in port_rows]
    label_counts = Counter(key for port, alias in zip(ports, physical_aliases)
                           for key in {port_label_key(port["name"]), port_label_key(alias)} if key)
    for port, alias in zip(ports, physical_aliases):
        if alias and port_label_key(alias) != port_label_key(port["name"]) and label_counts[port_label_key(alias)] == 1:
            port["aliases"] = [alias]
    for port, raw_port in zip(ports, port_rows):
        telemetry = _public_port_telemetry(raw_port.get("telemetry"), port, now)
        if telemetry:
            port["telemetry"] = telemetry
        memberships = _public_port_vlans(raw_port.get("vlanMemberships"), port)
        if memberships:
            port["vlanMemberships"] = memberships
        fdb_vlans = _public_port_fdb_vlans(raw_port.get("fdbVlans"), port)
        if fdb_vlans:
            port["fdbVlans"] = fdb_vlans
    observer = next((source for source in sources if source["name"] == "Server Observer"), None)
    aliases = row.get("aliases")
    resources = {}
    hardware_disks = {}
    zfs_pools = {}
    lvm_thin_pools = {}
    if row.get("kind") == "Гипервизор" and any(s["name"] == "Proxmox" and s["status"] == "ok" for s in fresh):
        resources = _public_hypervisor_resources(row.get("resources"), now)
        hardware_disks = project_hypervisor_disks(row.get("hardwareDisks"), now)
        zfs_pools = project_hypervisor_zfs(row.get("zfsPools"), now)
        lvm_thin_pools = project_hypervisor_lvm_thin(row.get("lvmThinPools"), now)
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
        **({"hardwareDisks": hardware_disks} if hardware_disks else {}),
        **({"zfsPools": zfs_pools} if zfs_pools else {}),
        **({"lvmThinPools": lvm_thin_pools} if lvm_thin_pools else {}),
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
        if any(disk["smartState"] == "critical" for disk in node.get("hardwareDisks", {}).get("disks", [])):
            checks.append("critical")
        if any(pool["health"] in ZFS_PROBLEM_STATES for pool in node.get("zfsPools", {}).get("pools", [])):
            checks.append("warn")
        if any(pool["capacityStatus"] == "warn" for pool in node.get("lvmThinPools", {}).get("pools", [])):
            checks.append("warn")
        if node["kind"] == CLUSTER_KIND:
            cluster = {check["method"]: check["state"] for check in node["serviceChecks"]}
            check_state = {"reachable": "ok", "unreachable": "critical"}
            checks.extend(check_state.get(cluster.get(method), "unknown") for method in CLUSTER_HEALTH_METHODS)
        local_issues[key] = (
            bool({"critical", "warn"}.intersection(checks)), "unknown" in checks,
        )

    down = {key for key, node in nodes.items() if node["reachability"]["state"] in {"unreachable", "stopped"}}
    failed = down | {key for key, (has_failure, _) in local_issues.items() if has_failure}
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
        unavailable = sorted(services[key] & down)
        degraded = sorted((services[key] & failed) - down)
        unknown = sorted((services[key] & unconfirmed) - failed)
        local_failed, local_unknown = local_issues[key]
        state = node["reachability"]["state"]
        node["serviceAvailability"] = {"unavailable": unavailable, "degraded": degraded, "unknown": unknown}
        if state in {"unreachable", "stopped"}:
            node["mapStatus"] = "critical"
        elif state == "reachable" and (unavailable or degraded or local_failed):
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


def _attach_storage_assignments(nodes: dict, links: list[dict], cluster_id: str) -> None:
    cluster = nodes.get(cluster_id)
    if not cluster or cluster["kind"] != CLUSTER_KIND:
        return
    by_host = {}
    checked_at = []
    seen = set()
    for link in links:
        if not link["confirmed"] or link["kind"] != "Размещение ВМ" or link["source"] != "Proxmox":
            continue
        host, guest = nodes[link["a"]], nodes[link["b"]]
        storage = guest.get("guestStorage")
        if (not storage or guest["id"] in seen or host["id"] != guest["pveHost"]
                or host["kind"] != "Гипервизор"):
            continue
        seen.add(guest["id"])
        checked_at.append(storage["checkedAt"])
        counts = Counter(disk["storage"] for disk in storage["disks"])
        stores = by_host.setdefault(host["id"], {})
        for name, count in counts.items():
            entry = stores.setdefault(name, {"id": name, "guestCount": 0, "diskCount": 0})
            entry["guestCount"] += 1
            entry["diskCount"] += count
    if by_host:
        cluster["storageAssignments"] = {
            "checkedAt": min(checked_at, key=_time),
            "hosts": [{"id": host, "storages": [stores[name] for name in sorted(stores)]}
                      for host, stores in sorted(by_host.items())],
        }


def _compare_link_ports(ports: dict) -> dict:
    if set(ports) != {"a", "b"}:
        return {}
    a, b = ports["a"], ports["b"]
    first, last = sorted((_time(a["checkedAt"]), _time(b["checkedAt"])))
    if last - first > timedelta(minutes=2):
        return {}
    up_count = sum(port["state"] == "up" for port in (a, b))
    if up_count == 2:
        state = "speed_mismatch" if a["speedBps"] and b["speedBps"] and a["speedBps"] != b["speedBps"] else "both_up"
    else:
        state = "one_down" if up_count else "both_down"
    return {"state": state, "checkedAt": first.isoformat()}


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
            if node["kind"] in NETWORK_KINDS[:2]:
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
                observed_attachment = (source in {"netctl FDB", "MikroTik · ARP", "MikroTik · ARP + FDB"}
                                       and evidence[-1]["confirmed"])
                both_ports = paired and evidence[-1]["a"] and evidence[-1]["b"]
                if both_ports or source == SHARED_LLDP_SOURCE or observed_attachment:
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
                                **({"configuredOnly": True} if switch_uplink.get("configuredOnly") is True else {}),
                            }
            confirmed = row.get("confirmed") is True
            if edge["source"] in {"netctl", "LLDP UI_VPN", "LLDP · двустороннее", "netctl FDB",
                                  "netctl FDB + Proxmox", "Proxmox", "SNMP LACP + ARP", "MikroTik · ARP",
                                  "MikroTik · ARP + FDB", RECIPROCAL_MAC_SOURCE, SHARED_LLDP_SOURCE} and row.get("observedAt"):
                confirmed = confirmed and observation_is_fresh(row["observedAt"], now)
            if confirmed and edge["kind"] == "Сетевое соединение":
                for report in evidence:
                    if report["confirmed"]:
                        comparison = _compare_link_ports(report.get("portStates", {}))
                        if comparison:
                            report["portComparison"] = comparison
            links.append({**edge, "confirmed": confirmed, "portEvidence": evidence})
    if db is not None and endpoint_keys and now - stamp <= MAX_AGE:
        _attach_endpoint_presence(db, endpoint_keys, nodes, now)
    _map_statuses(nodes, links)
    cluster_id = _text(raw.get("clusterId"))
    _attach_storage_assignments(nodes, links, cluster_id)
    revision = _text(raw.get("git"), 41)

    def node_ids(key: str) -> list[str]:
        values = raw.get(key)
        if not isinstance(values, list):
            return []
        return list(dict.fromkeys(value for value in values[:600] if isinstance(value, str) and value in nodes))

    return {
        **empty, "availability": "stale" if now - stamp > MAX_AGE else "ready",
        "snapshotAt": stamp.isoformat(), "nodes": list(nodes.values()), "links": links,
        "clusterId": cluster_id, "nodeOrder": node_ids("nodeOrder"),
        "overviewGuests": node_ids("overviewGuests"),
        "git": revision if re.fullmatch(r"[0-9a-f]{40}", revision) else "",
    }
