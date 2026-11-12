from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .server_observer import STALE_AFTER as SERVER_OBSERVER_MAX_AGE

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

LOGGER = logging.getLogger(__name__)

MAX_SNAPSHOT_BYTES = 1_000_000
MAX_AGE = timedelta(minutes=25)
MAX_DOWNSTREAM_SWITCHES = 12
SERVICE_PROBE_MAX_AGE = timedelta(minutes=5)
STP_ROOT_PATH_MAX_AGE = timedelta(minutes=5)
PORT_LINK_CHECK_MAX_AGE = timedelta(minutes=5)
RESOURCE_CAPACITY_MAX_AGE = timedelta(minutes=5)
GUEST_IO_MAX_AGE = timedelta(minutes=5)
LACP_HEALTH_MAX_AGE = timedelta(minutes=5)
LACP_PARTNER_MAX_AGE = timedelta(minutes=8)
ROOT_FREE_WARNING_PERCENT = 10
SWAP_USED_WARNING_PERCENT = 90
BACKUP_PROBE_METHOD = "Копия Proxmox"
BACKUP_SERVICE_ID = "proxmox-pbs-backups"
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
CURRENT_PORT_PAIR_SOURCES = {
    "netctl", "LLDP UI_VPN", "LLDP · двустороннее", "netctl FDB + Proxmox",
    "SNMP LACP + ARP", "SNMP · двусторонний FDB",
}
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
    "windows_memory_available_bytes": "Доступно памяти в Windows",
    "windows_memory_available_percent": "Доля доступной памяти Windows",
    "linux_memory_available_bytes": "Доступно памяти в Linux",
    "linux_memory_available_percent": "Доля доступной памяти Linux",
    "directumrx_active": "Служба Directum RX",
    "iis_active": "Служба IIS",
    "mongo_active": "Служба MongoDB",
    "rabbitmq_active": "Служба RabbitMQ",
    "redis_active": "Служба Redis",
    "mongo_tcp_27017": "MongoDB TCP/27017",
    "rabbitmq_tcp_5672": "RabbitMQ TCP/5672",
    "redis_tcp_6379": "Redis TCP/6379",
}
OBSERVER_CHECK_ERRORS = ("timeout", "transport", "parse", "unexpected_response")
OBSERVER_METRIC_UNITS = {
    "backup_snapshot_fresh": "hours",
    "backup_snapshot_count": "count",
    "c_disk_free": "percent",
    "root_disk_free": "percent",
    "data_disk_free": "percent",
    "rxdata_log_bytes": "bytes",
    "windows_memory_available_bytes": "bytes",
    "windows_memory_available_percent": "percent",
    "linux_memory_available_bytes": "bytes",
    "linux_memory_available_percent": "percent",
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


def observation_is_fresh(value: object, now: datetime, *, max_age: timedelta = MAX_AGE) -> bool:
    stamp = _time(value)
    return stamp is not None and timedelta(0) <= now - stamp <= max_age


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


def _public_reachability(value: object, now: datetime, *, max_age: timedelta = MAX_AGE) -> dict:
    empty = {"state": "unknown", "source": "", "method": "", "checkedAt": None, "stale": False}
    if not isinstance(value, dict) or value.get("state") not in REACHABILITY_STATES:
        return empty
    stamp = _time(value.get("checkedAt"))
    if stamp is None or stamp > now:
        return empty
    source = _text(value.get("source"), 48)
    if source == "Server Observer":
        max_age = SERVER_OBSERVER_MAX_AGE
    stale = now - stamp > max_age
    return {
        "state": "unknown" if stale else value["state"],
        "source": source, "method": _text(value.get("method"), 32),
        "checkedAt": stamp.isoformat(), "stale": stale,
    }


def _service_reachability(observation: object, checks: list[dict], now: datetime) -> dict:
    if not isinstance(observation, dict) or observation.get("source") != "Проверка сервиса":
        return _public_reachability(observation, now)
    reachability = _public_reachability(observation, now, max_age=SERVICE_PROBE_MAX_AGE)
    primary = [check for check in checks if check.get("required") and not check.get("component")]
    answered = [check["checkedAt"] for check in primary if check["state"] == "reachable"]
    if answered:
        return {**reachability, "state": "reachable", "checkedAt": max(answered), "stale": False}
    if primary and all(check["state"] == "unreachable" for check in primary):
        return {**reachability, "state": "unreachable",
                "checkedAt": min(check["checkedAt"] for check in primary), "stale": False}
    return {**reachability, "state": "unknown"}


def _public_port(row: dict, now: datetime) -> dict:
    stamp = _time(row.get("checkedAt"))
    fresh = observation_is_fresh(row.get("checkedAt"), now)
    source = row.get("source")
    state = "unknown" if source == "Proxmox" else row.get("state")
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
        chassis_count = row.get("lldpChassisCount")
        if type(chassis_count) is int and 1 <= chassis_count <= neighbor_count:
            result["lldpChassisCount"] = chassis_count
        neighbors = []
        for neighbor in _rows(row.get("lldpNeighbors"), min(neighbor_count, 16)):
            reading = {key: value for key in ("systemName", "chassisId", "portId", "hostName")
                       if (value := _text(neighbor.get(key), 64)) and re.fullmatch(r"[\w .:/-]+", value)}
            if reading.get("chassisId") or reading.get("systemName"):
                neighbors.append(reading)
        if neighbors:
            result["lldpNeighbors"] = neighbors
            result["lldpCheckedAt"] = result["checkedAt"]
    learned = row.get("fdbLearned")
    if result["state"] == "up" and isinstance(learned, dict) and _time(learned.get("checkedAt")) == stamp:
        count, partial = learned.get("learnedMacCount"), learned.get("partial")
        if type(count) is int and 0 <= count < 2**53 and type(partial) is bool:
            result["fdbLearned"] = {"checkedAt": result["checkedAt"], "learnedMacCount": count, "partial": partial}
    if source in ("RouterOS", "Proxmox", "Proxmox · sysfs"):
        result["source"] = source
    if fresh and source in ("Proxmox", "Proxmox · sysfs") and type(row.get("proxmoxActive")) is bool:
        result["proxmoxActive"] = row["proxmoxActive"]
    if telemetry := _public_port_telemetry(row.get("telemetry"), result, now):
        result["telemetry"] = telemetry
    return result


def _physical_port_alias(row: dict) -> str:
    key = _text(row.get("key"))
    physical = re.fullmatch(r"physical:([1-9]\d{0,3})", key)
    if physical:
        return f"Port{physical[1]}"
    slot = re.fullmatch(r"Slot0/([1-9]\d{0,3})", _text(row.get("name")), re.IGNORECASE)
    return f"Port{slot[1]}" if slot and key == f"ifindex:{slot[1]}" else ""


def _apply_port_link_check(port: dict, row: dict, now: datetime) -> None:
    sample = row.get("linkCheck")
    if not isinstance(sample, dict) or not observation_is_fresh(sample.get("checkedAt"), now, max_age=PORT_LINK_CHECK_MAX_AGE):
        return
    stamp = _time(sample["checkedAt"])
    previous = _time(port["checkedAt"])
    state = sample.get("state")
    if (previous and stamp <= previous) or state not in ("up", "down", "disabled"):
        return
    speed = sample.get("speedBps")
    port.update(state=state, source="SNMP", checkedAt=stamp.isoformat(), stale=False,
                speedBps=speed if state == "up" and type(speed) is int and 0 < speed <= 10**15 else None)
    if state != "up":
        for key in ("lldpChassisCount", "lldpNeighborCount", "lldpNeighbors", "lldpCheckedAt",
                    "fdbLearned", "fdbVlans", "telemetry"):
            port.pop(key, None)


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
        _apply_port_link_check(port, row, now)
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
    backup = check.get("method") == BACKUP_PROBE_METHOD and check.get("source") == "Proxmox"
    max_age = SERVICE_PROBE_MAX_AGE if backup or (check.get("source") == "UI_VPN" and check.get("required") is True) else MAX_AGE
    result = {
        **_public_reachability(check, now, max_age=max_age),
        "port": port if type(port) is int and 1 <= port <= 65535 else None,
        "target": _network_address(check.get("target")), "via": _network_address(check.get("via")),
        "path": path if re.fullmatch(r"/[A-Za-z0-9._/-]{0,159}", path) and not path.startswith("//") else "",
    }
    reason = check.get("reason")
    if reason == "probe_configuration" and result["source"] == "UI_VPN" and result["method"] == "Настройки проверки":
        result["reason"] = reason
    if backup:
        vmid, hours = check.get("backupVmid"), check.get("backupMaxAgeHours")
        if type(vmid) is int and 1 <= vmid <= 999_999_999:
            result["backupVmid"] = vmid
        if type(hours) is int and 1 <= hours <= 744:
            result["backupMaxAgeHours"] = hours
        completed = _time(check.get("backupCompletedAt"))
        if completed is not None and completed <= now:
            result["backupCompletedAt"] = completed.isoformat()
            if result["state"] == "reachable" and "backupMaxAgeHours" in result and now - completed > timedelta(hours=hours):
                result["state"], reason = "unreachable", "backup_overdue"
        if reason in {"backup_no_result", "backup_task_failed", "backup_overdue",
                      "backup_schedule_missing", "backup_untracked_schedule"}:
            result["reason"] = reason
    if reason == "timeout" and result["method"] in ("HTTP", "HTTPS", "DNS", "SMB2", "PostgreSQL SSLRequest"):
        result["reason"] = reason
    if check.get("supplemental") is True:
        result["supplemental"] = True
    elif check.get("required") is True:
        result["required"] = True
        if check.get("component") is True:
            result["component"] = True
    if (check.get("skipped") is True and result["checkedAt"] and result["state"] == "unknown"
            and reason in ("probe_target_unconfirmed", "probe_target_mismatch", "probe_host_stopped")):
        return {**result, "target": "", "skipped": True, "reason": reason}
    identified_icmp = result["method"] in ("ICMP · LLDP + ARP", "ICMP · ARP + FDB")
    if identified_icmp or (result["source"] == "UI_VPN" and "identityCheckedAt" in check):
        identity_at = check.get("identityCheckedAt")
        if observation_is_fresh(identity_at, now):
            result["identityCheckedAt"] = _time(identity_at).isoformat()
        else:
            result.update(state="unknown", stale=True)
    icmp = identified_icmp or result["method"] in ("ICMP", "ICMP адреса из инвентаря", "ICMP · VLAN")
    if icmp:
        round_trip = check.get("roundTripMs")
        if type(round_trip) in (int, float) and 0 <= round_trip <= 3000:
            result["roundTripMs"] = round_trip
        if reason in ("icmp_no_echo_reply", "icmp_unreachable", "icmp_probe_error",
                      "icmp_route_unconfirmed", "icmp_route_mismatch"):
            result["reason"] = reason
        route = check.get("localRoute")
        if isinstance(route, dict) and not result["stale"] and route.get("state") in ("reachable", "unreachable", "unknown"):
            details = {"state": route["state"]}
            for key in ("expectedGateway", "gateway", "sourceIP"):
                address = _network_address(route.get(key))
                if address and "/" not in address and ":" not in address:
                    details[key] = address
            interface = route.get("interface")
            if isinstance(interface, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
                details["interface"] = interface
            result["localRoute"] = details
    if result["method"] == "ICMP · VLAN":
        vlan = check.get("vlanTransit")
        if isinstance(vlan, dict):
            name, vlan_id = vlan.get("interface"), vlan.get("id")
            try:
                address = str(ipaddress.IPv4Interface(vlan.get("localAddress")))
            except ValueError:
                address = ""
            if (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)
                    and type(vlan_id) is int and 1 <= vlan_id <= 4094 and address):
                result["vlanTransit"] = {"interface": name, "id": vlan_id, "localAddress": address}
        if reason in ("vlan_probe_error", "vlan_interface_missing", "vlan_id_mismatch",
                      "vlan_link_down", "vlan_address_mismatch", "vlan_route_mismatch"):
            result["reason"] = reason
    if result["method"] == "Маршрут · WireGuard":
        policy = check.get("wireguardPolicy")
        if isinstance(policy, dict):
            details = {key: policy[key] for key in ("ingress", "interface") if isinstance(policy.get(key), str)
                       and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", policy[key])}
            details.update({key: policy[key] for key in ("mark", "table", "peerCount")
                            if type(policy.get(key)) is int and 0 <= policy[key] <= 0xffffffff})
            details.update({key: policy[key] for key in ("markerConfirmed", "routeConfirmed") if type(policy.get(key)) is bool})
            handshake = _time(policy.get("latestHandshake"))
            if handshake is not None and handshake <= now:
                details["latestHandshake"] = handshake.isoformat()
                if result["state"] == "reachable" and now - handshake > SERVICE_PROBE_MAX_AGE:
                    result["state"], reason = "unknown", "wireguard_handshake_unconfirmed"
            result["wireguardPolicy"] = details
        if reason in ("wireguard_route_unconfirmed", "wireguard_route_mismatch", "wireguard_evidence_unavailable",
                      "wireguard_mark_unconfirmed", "wireguard_mark_mismatch", "wireguard_handshake_unconfirmed"):
            result["reason"] = reason
    if result["method"] in ("HTTP", "HTTPS"):
        host = check.get("httpHost")
        if result["method"] == "HTTP" and isinstance(host, str) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            result["httpHost"] = host
        status = check.get("httpStatus")
        if type(status) is int and 100 <= status <= 599:
            result["httpStatus"] = status
        if reason in (
            "http_status", "http_content_type", "http_body_limit", "http_invalid_json",
            "http_reported_unavailable", "http_payload_mismatch", "http_certificate_pin",
            "http_tls_certificate", "http_tls_error", "http_bad_response", "http_connection_refused",
            "http_connection_reset", "http_configuration",
        ):
            result["reason"] = reason
    if result["method"] == "PostgreSQL SSLRequest":
        tls_state = check.get("postgresqlTls")
        if tls_state in ("negotiated", "declined", "failed"):
            result["postgresqlTls"] = tls_state
        version = check.get("tlsVersion")
        if tls_state == "negotiated" and isinstance(version, str) and re.fullmatch(r"TLSv1(?:\.[0-9])?", version):
            result["tlsVersion"] = version
        if tls_state == "failed" and reason == "postgresql_tls_handshake":
            result["reason"] = reason
    if result["method"] == "SMB2":
        dialect = check.get("smbDialect")
        if dialect in ("2.0.2", "2.1", "3.0", "3.0.2") and type(check.get("smbSigningRequired")) is bool:
            result.update(smbDialect=dialect, smbSigningRequired=check["smbSigningRequired"])
    if result["method"] == "SMB Mount":
        share = check.get("smbShare")
        if isinstance(share, str) and re.fullmatch(r"//[0-9.]{7,15}/[A-Za-z0-9_.$-]{1,64}", share):
            result["smbShare"] = share
        if reason in ("smb_mount_probe", "smb_mount_idle", "smb_mount_missing", "smb_mount_source",
                      "smb_mount_read", "smb_mount_changed"):
            result["reason"] = reason
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
    if result["method"] == "OpenVPN TUN":
        name, address = check.get("tunnelInterface"), check.get("tunnelAddress")
        if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
            result["tunnelInterface"] = name
        if isinstance(address, str) and len(address) <= 18:
            try:
                result["tunnelAddress"] = str(ipaddress.IPv4Interface(address))
            except ValueError:
                pass
        if reason in ("openvpn_tunnel_probe", "openvpn_tunnel_missing", "openvpn_tunnel_kind",
                      "openvpn_tunnel_down", "openvpn_tunnel_address"):
            result["reason"] = reason
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
    has_error_source = reason in ("icmp_port_unreachable", "icmp_rejected") or (icmp and reason == "icmp_unreachable")
    if has_error_source and error_source and "/" not in error_source:
        result["errorSource"] = error_source
    code = check.get("responseCode")
    if reason == "sip_response" and type(code) is int and 100 <= code <= 699:
        result["responseCode"] = code
    attempts = check.get("attempts")
    if result["method"] == "SIP OPTIONS (UDP)" and type(attempts) is int and 1 <= attempts <= 3:
        result["attempts"] = attempts
    return result


def _public_proxmox_resources(row: object, now: datetime) -> dict:
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


def _public_guest_io(row: object, resources: dict, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now, max_age=GUEST_IO_MAX_AGE):
        return {}
    stamp = _time(row["checkedAt"]).isoformat()
    interval = _number(row.get("intervalSeconds"))
    if stamp != resources.get("checkedAt") or interval is None or not 30 <= interval <= GUEST_IO_MAX_AGE.total_seconds():
        return {}
    rates = {}
    for keys in (("networkInBytesPerSecond", "networkOutBytesPerSecond"),
                 ("diskReadBytesPerSecond", "diskWriteBytesPerSecond")):
        pair = {key: _number(row.get(key)) for key in keys}
        if all(rate is not None and 0 <= rate < 2**53 for rate in pair.values()):
            rates.update(pair)
    return {**rates, "checkedAt": stamp, "intervalSeconds": interval} if rates else {}


def _public_resource_capacity(row: dict, now: datetime) -> dict:
    stamp = _time(row.get("checkedAt"))
    result = {"root": {"status": "unknown"}, "swap": {"status": "unknown"},
              "thresholds": {"rootFreePercent": ROOT_FREE_WARNING_PERCENT, "swapUsedPercent": SWAP_USED_WARNING_PERCENT}}
    if stamp is None or stamp > now:
        return result
    result["checkedAt"] = stamp.isoformat()
    result["stale"] = now - stamp > RESOURCE_CAPACITY_MAX_AGE
    if result["stale"]:
        return result

    for group, input_key, output_key, fields in (
        ("rootfs", "avail", "root", {"avail": "availableBytes"}),
        ("swap", "used", "swap", {"used": "usedBytes"}),
        ("memory", "free", "memory", {"free": "freeBytes", "available": "availableBytes"}),
    ):
        sample = row.get(group)
        if not isinstance(sample, dict):
            continue
        amount, total = sample.get(input_key), sample.get("total")
        if type(amount) is not int or type(total) is not int or not 0 <= amount <= total < 2**53:
            continue
        if total == 0:
            if group == "swap":
                result["swap"] = {"status": "not_configured", "usedBytes": 0, "totalBytes": 0}
            continue
        values = {target: value for source, target in fields.items()
                  if type(value := sample.get(source)) is int and 0 <= value <= total}
        result[output_key] = {**values, "totalBytes": total}
        if group == "rootfs":
            result["root"]["status"] = "warn" if 100 * amount <= ROOT_FREE_WARNING_PERCENT * total else "ok"
        elif group == "swap":
            result["swap"]["status"] = "warn" if 100 * amount >= SWAP_USED_WARNING_PERCENT * total else "ok"
    return result


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


def _public_guest_network(row: object, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now):
        return {}
    counts = {key: row.get(key) for key in ("configured", "enabled", "disabled")}
    if any(type(value) is not int or not 0 <= value <= 256 for value in counts.values()):
        return {}
    if counts["enabled"] + counts["disabled"] > counts["configured"]:
        return {}
    return {"checkedAt": _time(row["checkedAt"]).isoformat(), **counts}


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


def _public_downstream(row: object, ports: list[dict], stp_path: dict, now: datetime) -> dict:
    if not isinstance(row, dict) or not observation_is_fresh(row.get("checkedAt"), now):
        return {}
    upstream, port = _text(row.get("upstreamId")), _text(row.get("port"), 64)
    basis = row.get("basis", "lldp")
    if not upstream or not port or basis not in ("lldp", "reciprocal_mac", "inventory_stp"):
        return {}
    stp_evidence = {}
    if basis == "inventory_stp":
        if stp_path.get("bridgeDeviceId") != upstream:
            return {}
        stp_evidence = {"stpCheckedAt": stp_path["checkedAt"]}
    devices = {}
    active_ports = {(port["name"], port["checkedAt"]) for port in ports if port["state"] == "up"}
    for entry in _rows(row.get("devices"), 256):
        mac = _text(entry.get("mac"), 17)
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or int(mac[:2], 16) & 1:
            continue
        ip = _network_address(entry.get("ip"))
        identity_at = entry.get("identityCheckedAt")
        if ip and "/" not in ip and observation_is_fresh(identity_at, now):
            device = {"mac": mac, "ip": ip, "identityCheckedAt": _time(identity_at).isoformat(),
                      "reachability": _public_reachability(entry.get("reachability"), now)}
        else:
            device = {"mac": mac, "reachability": _public_reachability(None, now)}
        if isinstance(switch_port := entry.get("switchPort"), dict):
            name = _text(switch_port.get("name"), 64)
            at = switch_port.get("checkedAt")
            if observation_is_fresh(at, now) and (name, _time(at).isoformat()) in active_ports:
                device["switchPort"] = {"name": name, "checkedAt": _time(at).isoformat()}
        if basis == "lldp" or "switchPort" in device:
            devices[mac] = device
    if not devices:
        return {}
    ordered = sorted(devices.values(), key=lambda item: (item.get("ip", "~"), item["mac"]))
    return {"upstreamId": upstream, "port": port, "basis": basis, "checkedAt": _time(row["checkedAt"]).isoformat(),
            "deviceCount": len(ordered), "devices": ordered, **stp_evidence}


def _public_node(row: dict, now: datetime) -> dict:
    sources = []
    for item in _rows(row.get("sources"), 12):
        stamp = _time(item.get("at"))
        name = _text(item.get("name"), 48)
        max_age = SERVER_OBSERVER_MAX_AGE if name == "Server Observer" else MAX_AGE
        sources.append({
            "name": name,
            "status": _state(item.get("status")),
            "label": _text(item.get("label"), 64),
            "raw": _text(item.get("raw"), 32),
            "at": stamp.isoformat() if stamp else None,
            "stale": item.get("stale") is True or not observation_is_fresh(item.get("at"), now, max_age=max_age),
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
        memberships = _public_port_vlans(raw_port.get("vlanMemberships"), port)
        if memberships:
            port["vlanMemberships"] = memberships
        fdb_vlans = _public_port_fdb_vlans(raw_port.get("fdbVlans"), port)
        if fdb_vlans:
            port["fdbVlans"] = fdb_vlans
        _apply_port_link_check(port, raw_port, now)
    observer = next((source for source in sources if source["name"] == "Server Observer"), None)
    aliases = row.get("aliases")
    resources = {}
    capacity = {}
    hardware_disks = {}
    zfs_pools = {}
    lvm_thin_pools = {}
    if any(s["name"] == "Proxmox" and s["status"] == "ok" for s in fresh):
        if row.get("guest") is True or row.get("kind") == "Гипервизор":
            resources = _public_proxmox_resources(row.get("resources"), now)
        if row.get("kind") == "Гипервизор":
            if isinstance(resource_capacity := row.get("resourceCapacity"), dict):
                capacity = _public_resource_capacity(resource_capacity, now)
            hardware_disks = project_hypervisor_disks(row.get("hardwareDisks"), now)
            zfs_pools = project_hypervisor_zfs(row.get("zfsPools"), now)
            lvm_thin_pools = project_hypervisor_lvm_thin(row.get("lvmThinPools"), now)
    guest_storage = _public_guest_storage(row.get("guestStorage"), now) if row.get("guest") is True else {}
    guest_network = _public_guest_network(row.get("guestNetwork"), now) if row.get("guest") is True else {}
    guest_io = _public_guest_io(row.get("guestIo"), resources, now) if row.get("guest") is True else {}
    backup_coverage = {}
    backup = row.get("backupCoverage")
    if row.get("guest") is True and isinstance(backup, dict):
        storage = backup.get("storage")
        stamp = _time(backup.get("checkedAt"))
        state = backup.get("state")
        if (isinstance(storage, str) and PVE_STORAGE_ID.fullmatch(storage)
                and stamp is not None and stamp <= now and state in ("scheduled", "not_scheduled", "unknown")):
            stale = now - stamp > SERVICE_PROBE_MAX_AGE
            backup_coverage = {"storage": storage, "serviceId": BACKUP_SERVICE_ID, "checkedAt": stamp.isoformat(),
                               "state": "unknown" if stale else state, "stale": stale}
    required = row.get("requiredObserverChecks")
    required_names = dict.fromkeys(
        name for name in required[:80] if isinstance(name, str) and re.fullmatch(r"[a-z0-9_]{1,64}", name)
    ) if row.get("kind") == "Сервис" and isinstance(required, list) else {}
    checks = _rows(row.get("checks"), 80)
    check_counts = Counter(_text(check.get("name"), 64) for check in checks)
    checks.extend({"name": name} for name in required_names if not check_counts[name])
    service_checks = [_public_service_check(check, now) for check in _rows(row.get("serviceChecks"), 16)]
    stp = row.get("stpRootPath")
    stp_path = {}
    if row.get("kind") == NETWORK_KINDS[0] and isinstance(stp, dict):
        local_port = _text(stp.get("localPort"), 64)
        bridge = _text(stp.get("designatedBridgeMac"), 17)
        port_id = _text(stp.get("designatedPortId"), 5)
        if (observation_is_fresh(stp.get("checkedAt"), now, max_age=STP_ROOT_PATH_MAX_AGE)
                and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", bridge)
                and re.fullmatch(r"[0-9a-f]{2}:[0-9a-f]{2}", port_id)
                and sum(port["name"] == local_port and port["state"] == "up" for port in ports) == 1):
            stp_path = {"localPort": local_port, "designatedBridgeMac": bridge, "designatedPortId": port_id,
                        "checkedAt": _time(stp["checkedAt"]).isoformat()}
            bridge_device = _text(stp.get("bridgeDeviceId"))
            if bridge_device:
                stp_path["bridgeDeviceId"] = bridge_device
    downstream = (_public_downstream(row.get("downstream"), ports, stp_path, now)
                  if row.get("kind") == NETWORK_KINDS[0] else {})
    return {
        **{key: _text(row.get(key)) for key in ("id", "name", "kind", "site", "origin", "pveHost")},
        "guest": row.get("guest") is True,
        "vmid": row.get("vmid") if type(row.get("vmid")) is int else None,
        "aliases": [_text(value) for value in aliases[:12] if isinstance(value, str)] if isinstance(aliases, list) else [],
        "sourceStatus": next((state for state in STATES if any(source["status"] == state for source in fresh)), "unknown"),
        "reachability": _service_reachability(row.get("reachability"), service_checks, now),
        "sources": sources,
        "properties": properties,
        **({"resources": resources} if resources else {}),
        **({"resourceCapacity": capacity} if capacity else {}),
        **({"hardwareDisks": hardware_disks} if hardware_disks else {}),
        **({"zfsPools": zfs_pools} if zfs_pools else {}),
        **({"lvmThinPools": lvm_thin_pools} if lvm_thin_pools else {}),
        **({"guestStorage": guest_storage} if guest_storage else {}),
        **({"guestNetwork": guest_network} if guest_network else {}),
        **({"guestIo": guest_io} if guest_io else {}),
        **({"backupCoverage": backup_coverage} if backup_coverage else {}),
        **({"stpRootPath": stp_path} if stp_path else {}),
        **({"downstream": downstream} if downstream else {}),
        "ports": [port for port in ports if port["name"]],
        "serviceChecks": service_checks,
        "checks": [
            {"name": name,
             **({"label": OBSERVER_CHECK_LABELS[name]} if name in OBSERVER_CHECK_LABELS else {}),
             **({"required": True} if name in required_names else {}),
             "status": _state(check.get("status")) if observer and not observer["stale"]
             and (name not in required_names or check_counts[name] == 1) else "unknown",
             **({"error": check["error"]} if observer and not observer["stale"]
                and check_counts[name] == 1 and check.get("status") == "unknown"
                and check.get("error") in OBSERVER_CHECK_ERRORS else {}),
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
    check_state = {"reachable": "ok", "unreachable": "critical"}
    for key, node in nodes.items():
        checks = [check["status"] for check in node["checks"] if check.get("required")]
        checks.extend(check_state.get(check["state"], "unknown")
                      for check in node["serviceChecks"] if check.get("required"))
        if any(disk["smartState"] == "critical" for disk in node.get("hardwareDisks", {}).get("disks", [])):
            checks.append("critical")
        if any(pool["health"] in ZFS_PROBLEM_STATES for pool in node.get("zfsPools", {}).get("pools", [])):
            checks.append("warn")
        if any(pool["capacityStatus"] == "warn" for pool in node.get("lvmThinPools", {}).get("pools", [])):
            checks.append("warn")
        if capacity := node.get("resourceCapacity"):
            checks.extend(capacity[key]["status"] for key in ("root", "swap"))
        checks.extend(report["status"] for report in node.get("lacpHealth", []))
        if node["kind"] == CLUSTER_KIND:
            cluster = {check["method"]: check["state"] for check in node["serviceChecks"]}
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
        node["status"] = node["mapStatus"]


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


def _attach_lacp_port_states(report: dict, edge: dict, nodes: dict, port_states: dict) -> None:
    for side, peer in (("a", "b"), ("b", "a")):
        if nodes[edge[side]]["kind"] != NETWORK_KINDS[0]:
            continue
        aggregate, separator, member = report[side].partition(" / ")
        partner = re.fullmatch(r"LACP ([1-9][0-9]{0,4})", report[peer])
        if (not separator or not INTERFACE_NAME.fullmatch(aggregate) or not INTERFACE_NAME.fullmatch(member)
                or partner is None or int(partner[1]) > 65535):
            continue
        lacp = {"side": side, "aggregate": aggregate, "member": member, "partnerPort": int(partner[1])}
        ports = port_states.get(edge[side], {})
        aggregate_state = ports.get(port_label_key(aggregate))
        if aggregate_state and aggregate_state["state"] != "unknown":
            lacp["aggregateState"] = aggregate_state
        member_state = ports.get(port_label_key(member))
        if member_state and member_state["state"] != "unknown":
            report["portStates"] = {side: member_state}
        report["lacp"] = lacp
        return


def _attach_lacp_health(nodes: dict, expectations: dict, links: list[dict], port_states: dict, now: datetime) -> None:
    forwarding = {}
    for edge in links:
        if edge["kind"] != "Сетевое соединение" or not edge["confirmed"]:
            continue
        for report in edge["portEvidence"]:
            lacp = report.get("lacp")
            if not lacp:
                continue
            polled_at = lacp.get("polledAt", report["at"])
            if (not observation_is_fresh(polled_at, now, max_age=LACP_HEALTH_MAX_AGE)
                    or not observation_is_fresh(report["at"], now, max_age=LACP_PARTNER_MAX_AGE)):
                continue
            side = lacp["side"]
            peer = edge["b" if side == "a" else "a"]
            key = (peer, edge[side], lacp["aggregate"].casefold(), lacp["member"].casefold())
            forwarding[key] = (polled_at, lacp["partnerPort"])

    for node_id, configured in expectations.items():
        for spec in configured:
            switch_id, aggregate = _text(spec.get("switchId")), _text(spec.get("aggregate"), 32)
            names = spec.get("members")
            if (switch_id == node_id or nodes.get(switch_id, {}).get("kind") != NETWORK_KINDS[0]
                    or not INTERFACE_NAME.fullmatch(aggregate) or not isinstance(names, list)
                    or not 1 <= len(names) <= 16 or not all(isinstance(name, str) and INTERFACE_NAME.fullmatch(name) for name in names)
                    or len({name.casefold() for name in names}) != len(names)):
                continue
            members = []
            for name in names:
                port = port_states.get(switch_id, {}).get(port_label_key(name), {})
                sample = forwarding.get((node_id, switch_id, aggregate.casefold(), name.casefold()))
                at = port.get("checkedAt")
                if (port.get("state") in {"down", "disabled"} and observation_is_fresh(at, now, max_age=LACP_HEALTH_MAX_AGE)
                        and (not sample or _time(at) >= _time(sample[0]))):
                    members.append({"name": name, "status": port["state"], "checkedAt": at})
                elif sample:
                    members.append({"name": name, "status": "forwarding", "checkedAt": sample[0], "partnerPort": sample[1]})
                else:
                    members.append({"name": name, "status": "unknown"})
            states = {member["status"] for member in members}
            status = "warn" if states & {"down", "disabled"} else "unknown" if "unknown" in states else "ok"
            nodes[node_id].setdefault("lacpHealth", []).append({
                "switchId": switch_id, "aggregate": aggregate, "members": members, "status": status,
            })


def _compare_link_ports(ports: dict) -> dict:
    if set(ports) != {"a", "b"} or any(port["state"] == "unknown" for port in ports.values()):
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


def _link_port_alerts(evidence: list[dict]) -> list[dict]:
    alerts = {}
    for report in evidence:
        if not report.get("pairEvidence"):
            continue
        ports = report.get("portStates", {})
        comparison = report.get("portComparison")
        if comparison:
            if comparison["state"] == "both_up":
                continue
            alert = comparison
        else:
            down = [side for side, port in ports.items() if port["state"] in {"down", "disabled"}]
            if not down:
                continue
            alert = {"state": "port_down", "downSides": sorted(down),
                     "checkedAt": min(ports[side]["checkedAt"] for side in down)}
        a, b = (ports.get(side, {}).get("name", report[side]) for side in ("a", "b"))
        alerts[(port_label_key(a), port_label_key(b))] = {"portA": a, "portB": b, **alert}
    return list(alerts.values())


def summarize_topology(graph: dict) -> dict:
    nodes = {node["id"]: node for node in graph["nodes"]}
    port_aliases = {
        (node["id"], port_label_key(alias)): port_label_key(port["name"])
        for node in nodes.values()
        for port in node["ports"]
        for alias in port.get("aliases", [])
    }
    port_names = {node_id: {port_label_key(port["name"]) for port in node["ports"]} for node_id, node in nodes.items()}
    unnamed = {"", "-", "unknown", "неизвестно"}

    def port_key(node_id, label):
        key = port_label_key(label)
        return port_aliases.get((node_id, key), key)

    paths = {}
    for link in graph["links"]:
        if link["confirmed"] and link["kind"] in ("Путь по MAC-таблице", SHARED_LLDP_KIND):
            paths.setdefault(frozenset((link["a"], link["b"])), []).extend(
                (link["a"], report) for report in link["portEvidence"] if report["confirmed"]
            )

    counts = {"current": 0, "verifiedInventory": 0, "unconfirmed": 0}
    pending = {}
    alerts = []
    for link in graph["links"]:
        if link["kind"] != "Сетевое соединение":
            continue
        a, b = link["a"], link["b"]
        alerts.extend({"a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"], **alert}
                      for alert in link.get("portAlerts", []))
        reports = link["portEvidence"]
        current = [r for r in reports if link["confirmed"] and r.get("pairEvidence") == "current"]
        inventory = any(r.get("pairEvidence") == "verified_inventory" for r in reports)
        counts["current" if current else "verifiedInventory" if inventory else "unconfirmed"] += 1

        def covers(declared, report):
            sides = [side for side in ("a", "b") if port_label_key(declared[side]) not in unnamed]
            lacp = report.get("lacp")
            if lacp:
                side = lacp["side"]
                if port_key(link[side], declared[side]) == port_key(link[side], lacp["aggregate"]):
                    return True
            if report["source"] == "netctl FDB + Proxmox":
                sides = [side for side in sides if nodes[link[side]]["kind"] != "Гипервизор"
                         or port_key(link[side], declared[side]) in port_names[link[side]]]
            return bool(sides) and all(
                port_key(link[side], declared[side]) == port_key(link[side], report[side]) for side in sides
            )

        for declared in reports:
            if (declared["source"] != "GitHub" or declared["confirmed"]
                    or all(port_label_key(declared[side]) in unnamed for side in ("a", "b"))
                    or any(covers(declared, r) for r in current)):
                continue
            related = []
            for origin, report in paths.get(frozenset((a, b)), []):
                pa, pb = (report["a"], report["b"]) if origin == a else (report["b"], report["a"])
                if ((pa and port_key(a, pa) == port_key(a, declared["a"]))
                        or (pb and port_key(b, pb) == port_key(b, declared["b"]))):
                    related.append({"portA": pa, "portB": pb, "source": report["source"], "checkedAt": report["at"],
                                    **({"stpPaths": report["stpPaths"]} if "stpPaths" in report else {})})
            lldp = {side: {"checkedAt": port["lldpCheckedAt"], "neighbors": port["lldpNeighbors"]}
                    for side, port in declared.get("portStates", {}).items() if port.get("lldpNeighbors")}
            pending[(a, b, declared["a"], declared["b"])] = {
                "a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"],
                "portA": declared["a"], "portB": declared["b"], "observedPaths": related[:8],
                **({"lldpObservations": lldp} if lldp else {}),
            }
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    stp = [{"id": node["id"], "name": node["name"], **node["stpRootPath"]}
           for node in nodes.values() if "stpRootPath" in node]
    lacp = [{"id": node["id"], "name": node["name"], **report}
            for node in nodes.values() for report in node.get("lacpHealth", [])]
    downstream = [{"id": node["id"], "name": node["name"], **node["downstream"]}
                  for node in nodes.values() if "downstream" in node]
    return {**metadata, "topologyAudit": {"directLinks": counts, "pendingTotal": len(pending),
                                        "portAlertTotal": len(alerts), "portAlerts": alerts[:64],
                                        "stpRootPaths": stp,
                                        "lacpHealth": lacp[:64],
                                        "downstreamSwitches": downstream[:MAX_DOWNSTREAM_SWITCHES],
                                        "pending": [pending[key] for key in sorted(pending)[:64]]}}


def _attachment_node(node: dict) -> dict:
    return {key: node[key] for key in ("id", "name", "kind", "vmid", "mapStatus") if node.get(key) is not None}


def _guest_attachments(nodes: dict, links: list[dict], guest_ids: list[str]) -> dict:
    placements = defaultdict(list)
    physical = defaultdict(list)
    selected_guests = set(guest_ids)
    for edge in links:
        if not edge["confirmed"]:
            continue
        a, b = edge["a"], edge["b"]
        if edge["kind"] == "Размещение ВМ" and b in selected_guests and nodes[a]["kind"] == "Гипервизор":
            placements[b].append(edge)
        elif edge["kind"] == "Сетевое соединение":
            if nodes[a]["kind"] == "Гипервизор" and nodes[b]["kind"] == NETWORK_KINDS[0]:
                host_side, switch_side = "a", "b"
            elif nodes[b]["kind"] == "Гипервизор" and nodes[a]["kind"] == NETWORK_KINDS[0]:
                host_side, switch_side = "b", "a"
            else:
                continue
            for report in edge["portEvidence"]:
                if report.get("pairEvidence") == "current" and report["confirmed"]:
                    host_port, switch_port = report[host_side], report[switch_side]
                    physical[edge[host_side], edge[switch_side], port_label_key(switch_port)].append({
                        "hostPort": host_port, "switchPort": switch_port,
                        "source": report["source"], "checkedAt": report["at"],
                    })

    guests = {}
    for guest_id in guest_ids:
        candidates = placements[guest_id]
        guest = {"guest": _attachment_node(nodes[guest_id]), "hypervisor": None, "interfaces": [],
                 "placement": "ambiguous" if len(candidates) > 1 else "unconfirmed"}
        guests[guest_id] = guest
        if len(candidates) != 1:
            continue
        edge, = candidates
        host_id = edge["a"]
        guest.update(hypervisor=_attachment_node(nodes[host_id]), placement="confirmed")
        for report in edge["portEvidence"]:
            virtual = report.get("virtual")
            if not report["confirmed"] or not virtual or not report["b"]:
                continue
            interface = {"guestPort": report["b"], "bridge": report["a"], "checkedAt": report["at"],
                         "bridgeActive": virtual["bridgeActive"], "linkDisabled": virtual["linkDisabled"],
                         "uplinks": virtual["uplinks"], "switchObservations": []}
            if "vlan" in report:
                interface["vlan"] = report["vlan"]
            guest["interfaces"].append(interface)
            matches = [("guest_mac", row) for row in virtual["switchPorts"]] if not virtual["linkDisabled"] else []
            uplink = virtual.get("switchUplink")
            if not matches and uplink:
                configured = virtual["linkDisabled"] or virtual["bridgeActive"] is False or uplink.get("configuredOnly")
                matches = [("configured_bridge" if configured else "bridge_uplink", uplink)]
            for basis, match in matches:
                if not match["port"]:
                    continue
                switch_id = match["id"]
                observation = {"basis": basis, "switch": _attachment_node(nodes[switch_id]), "switchPort": match["port"],
                               "checkedAt": match["at"]}
                if match.get("vlan") is not None:
                    observation["vlan"] = match["vlan"]
                if match.get("viaMacTable"):
                    observation["viaMacTable"] = True
                if basis != "configured_bridge" and virtual["bridgeActive"] is True:
                    pairs = physical[host_id, switch_id, port_label_key(match["port"])]
                    uplinks = {port_label_key(name) for name in virtual["uplinks"]}
                    pairs = [pair for pair in pairs if port_label_key(pair["hostPort"]) in uplinks]
                    if len({port_label_key(pair["hostPort"]) for pair in pairs}) == 1:
                        observation["physicalPair"] = max(pairs, key=lambda pair: pair["checkedAt"])
                interface["switchObservations"].append(observation)
    return guests


def summarize_guest_attachment(graph: dict, node_id: str) -> dict:
    nodes = {node["id"]: node for node in graph["nodes"]}
    anchor = nodes.get(node_id)
    guest_ids = set()
    if anchor and anchor["guest"]:
        guest_ids.add(node_id)
    elif anchor and anchor["kind"] == "Сервис":
        guest_ids.update(edge["a"] for edge in graph["links"] if edge["b"] == node_id
                         and edge["confirmed"] and edge["kind"] in {"Размещение", "Цель проверки"}
                         and nodes[edge["a"]]["guest"])

    guests = _guest_attachments(nodes, graph["links"], sorted(guest_ids)[:12])
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    return {**metadata, "attachment": {"node": _attachment_node(anchor) if anchor else None,
                                       "guestTotal": len(guest_ids), "guests": list(guests.values())}}


def summarize_guest_attachment_audit(graph: dict) -> dict:
    nodes = {node["id"]: node for node in graph["nodes"]}
    guest_ids = [node_id for node_id, node in nodes.items() if node["guest"]]
    guests = _guest_attachments(nodes, graph["links"], guest_ids)
    evidence_order = {
        ("guest_mac", True): "guest_mac_with_physical_pair",
        ("guest_mac", False): "guest_mac",
        ("bridge_uplink", True): "bridge_with_physical_pair",
        ("bridge_uplink", False): "bridge_uplink",
        ("configured_bridge", False): "configured_bridge",
    }
    guest_counts = dict.fromkeys(("running", "stopped", "unknown"), 0)
    interface_counts = dict.fromkeys((*evidence_order.values(), "unconfirmed", "inactive"), 0)
    gaps = []
    for guest_id, attachment in guests.items():
        node = nodes[guest_id]
        power = "unknown"
        if node["reachability"]["state"] == "stopped":
            power = "stopped"
        elif any(source["name"] == "Proxmox" and source["label"] == "Запущена" and not source["stale"]
                 for source in node["sources"]):
            power = "running"
        guest_counts[power] += 1

        incomplete = []
        for interface in attachment["interfaces"]:
            if power == "stopped" or interface["linkDisabled"]:
                state = "inactive"
            else:
                evidence = {(row["basis"], "physicalPair" in row) for row in interface["switchObservations"]}
                state = next((label for key, label in evidence_order.items() if key in evidence), "unconfirmed")
            interface_counts[state] += 1
            if state not in {"guest_mac_with_physical_pair", "inactive"}:
                incomplete.append({"guestPort": interface["guestPort"], "bridge": interface["bridge"], "state": state})
        if power != "stopped" and (incomplete or not attachment["interfaces"]):
            gaps.append({"guest": attachment["guest"], "hypervisor": attachment["hypervisor"],
                         "power": power, "placement": attachment["placement"], "interfaces": incomplete})

    gaps.sort(key=lambda gap: (gap["power"] != "running", gap["guest"]["id"]))
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    return {**metadata, "attachmentAudit": {"guestCounts": guest_counts, "interfaceCounts": interface_counts,
                                            "gapTotal": len(gaps), "gaps": gaps[:64]}}


def summarize_services(graph: dict) -> dict:
    nodes = {node["id"]: node for node in graph["nodes"]}
    hosts = {}
    for link in graph["links"]:
        if (link["confirmed"] and link["kind"] in {"Размещение", "Цель проверки"}
                and nodes[link["a"]]["kind"] != "Сервис" and nodes[link["b"]]["kind"] == "Сервис"):
            hosts.setdefault(link["b"], set()).add(link["a"])

    priority = {"critical": 0, "warn": 1, "unknown": 2, "ok": 3}
    check_status = {"reachable": "ok", "unreachable": "critical"}
    counts = dict.fromkeys(priority, 0)
    services = []
    for node in nodes.values():
        if node["kind"] != "Сервис":
            continue
        state = node["mapStatus"]
        counts[state] += 1
        checks = [
            {"check": check["name"], "label": check.get("label", check["name"]),
             "required": check.get("required") is True,
             "status": check["status"], "source": "Server Observer",
             **{key: check[key] for key in ("checkedAt", "stale", "error", "unit", "observed", "warningThreshold")
                if key in check}}
            for check in node["checks"] if check.get("required") or check["status"] in ("critical", "warn")
        ]
        checks.extend(
            {"check": check["method"], "status": check_status.get(check["state"], "unknown"),
             "required": check.get("required") is True,
             **{key: check[key] for key in ("source", "checkedAt", "stale", "reason", "path", "port", "target")
                if key in check and check[key] is not None and check[key] != ""}}
            for check in node["serviceChecks"] if check.get("required") or (
                state == "unknown" and check.get("supplemental") and check["state"] != "reachable"
            )
        )
        totals = Counter(check["status"] for check in checks if check["required"])
        issues = sorted((check for check in checks if check["status"] != "ok"),
                        key=lambda check: (not check["required"], priority[check["status"]]))
        services.append({
            "id": node["id"], "name": node["name"], "status": state, "reachability": node["reachability"],
            "hosts": sorted(hosts.get(node["id"], ())), "dependencies": node["serviceAvailability"],
            "requiredChecks": {"passed": totals["ok"], "failed": totals["critical"] + totals["warn"],
                               "unconfirmed": totals["unknown"]},
            "issueTotal": len(issues), "issues": issues[:6],
        })
    services.sort(key=lambda node: (priority[node["status"]], node["name"].casefold(), node["id"]))
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    return {**metadata, "serviceAudit": {"total": len(services), "counts": counts, "services": services[:128]}}


def _summarize_guest_agents(nodes: dict, keys: dict, identities: list[dict], now: datetime) -> dict:
    from .inventory.endpoint import CANDIDATE_MAX_AGE, STATE_MAX_AGE

    by_id = {row["id"]: row for row in identities if isinstance(row, dict)
             and isinstance(row.get("id"), str) and 0 < len(row["id"]) <= 255}
    if len(by_id) != len(identities) or len(by_id) > 1000:
        return {"sourceState": "unavailable"}
    by_mac = defaultdict(set)
    for identity_id, row in by_id.items():
        mac_keys = row.get("baseline_mac_keys")
        for key in mac_keys if isinstance(mac_keys, list) else []:
            if isinstance(key, str) and re.fullmatch(r"mac-[0-9a-f]{12}", key):
                by_mac[key].add(identity_id)
    owners = Counter(key for values in keys.values() for key in values)
    matches = {node_id: set().union(*(by_mac[key] for key in values if owners[key] == 1))
               for node_id, values in keys.items()}
    guests_by_identity = Counter(identity_id for values in matches.values() for identity_id in values)
    guests = []
    for node_id, candidates in matches.items():
        if not candidates:
            continue
        node = nodes[node_id]
        entry = {key: node[key] for key in ("id", "name", "vmid")}
        entry.update(state="ambiguous", registrations=len(candidates))
        if len(candidates) == 1:
            identity_id, = candidates
            if guests_by_identity[identity_id] == 1:
                entry["state"] = "matched"
                identity = by_id[identity_id]
                baseline, last_seen = _time(identity.get("baseline_collected_at")), _time(identity.get("last_seen_at"))
                fresh = (baseline and timedelta(0) <= now - baseline <= CANDIDATE_MAX_AGE
                         and last_seen and timedelta(0) <= now - last_seen <= STATE_MAX_AGE)
                entry["presence"] = "online" if fresh and identity.get("online") is True else "unconfirmed"
                if entry["presence"] == "online":
                    entry["lastSeenAt"] = last_seen.isoformat()
        guests.append(entry)
    return {"sourceState": "ready", "eligible": len(keys),
            "matched": sum(row["state"] == "matched" for row in guests),
            "ambiguous": sum(row["state"] == "ambiguous" for row in guests),
            "guests": sorted(guests, key=lambda row: row["vmid"])[:64]}


def load_infrastructure_map(
    path: Path, now: datetime | None = None, *, db: Session | None = None,
    agent_identities: list[dict] | None = None, include_guest_attachments: bool = False,
) -> dict:
    now = now or datetime.now(timezone.utc)
    empty = {
        "availability": "missing", "snapshotAt": None, "nodes": [], "links": [],
        "clusterId": "", "nodeOrder": [], "overviewGuests": [], "switchKinds": list(NETWORK_KINDS), "git": "",
        **({"guestAttachments": {}} if include_guest_attachments else {}),
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
    agent_keys = {}
    lacp_expectations = {}
    for row in _rows(raw.get("nodes"), 600):
        node = _public_node(row, now)
        if node["id"] and node["name"] and node["id"] not in nodes:
            nodes[node["id"]] = node
            if expected := _rows(row.get("lacpExpectations"), 8):
                lacp_expectations[node["id"]] = expected
            if node["kind"] in (*NETWORK_KINDS[:2], "Гипервизор"):
                port_states[node["id"]] = index_port_states(_rows(row.get("ports"), 500), now)
            key = _text(row.get("endpointKey"))
            if node["kind"] == "Рабочая станция" and re.fullmatch(r"mac:(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", key):
                endpoint_keys[node["id"]] = key
            keys = row.get("agentMatchKeys")
            if (agent_identities is not None and node["guest"] and node["vmid"] is not None
                    and now - stamp <= MAX_AGE and isinstance(keys, list)
                    and any(s["name"] == "Proxmox" and s["label"] == "Запущена" and not s["stale"] for s in node["sources"])):
                valid = {key for key in keys[:32] if isinstance(key, str) and re.fullmatch(r"mac-[0-9a-f]{12}", key)}
                if valid:
                    agent_keys[node["id"]] = valid
    for node_id, node in nodes.items():
        stp = node.get("stpRootPath", {})
        bridge_id = stp.get("bridgeDeviceId")
        if bridge_id == node_id or nodes.get(bridge_id, {}).get("kind") not in NETWORK_KINDS[:2]:
            stp.pop("bridgeDeviceId", None)
        if downstream := node.get("downstream"):
            upstream_id = downstream["upstreamId"]
            if upstream_id == node_id or nodes.get(upstream_id, {}).get("kind") != NETWORK_KINDS[0]:
                node.pop("downstream")
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
                if (edge["kind"] == "Сетевое соединение" and both_ports and evidence[-1]["confirmed"]
                        and all(evidence[-1][side].strip().casefold() not in {"", "unknown", "неизвестно", "-"}
                                for side in ("a", "b"))):
                    if source == "GitHub":
                        evidence[-1]["pairEvidence"] = "verified_inventory"
                    elif source in CURRENT_PORT_PAIR_SOURCES:
                        evidence[-1]["pairEvidence"] = "current"
                if source == "SNMP LACP + ARP":
                    if evidence[-1].get("pairEvidence") == "current":
                        _attach_lacp_port_states(evidence[-1], edge, nodes, port_states)
                        polled = _time(report.get("lacpPolledAt"))
                        if "lacp" in evidence[-1] and observed and polled and observed <= polled <= now:
                            evidence[-1]["lacp"]["polledAt"] = polled.isoformat()
                elif both_ports or source == SHARED_LLDP_SOURCE or observed_attachment:
                    states = {}
                    for side in ("a", "b"):
                        port = port_states.get(edge[side], {}).get(port_label_key(evidence[-1][side]))
                        if port and (port["state"] != "unknown" or "proxmoxActive" in port):
                            states[side] = port
                    if states:
                        evidence[-1]["portStates"] = states
                if source == RECIPROCAL_MAC_SOURCE and evidence[-1]["confirmed"]:
                    stp_paths = []
                    for side, port in evidence[-1].get("portStates", {}).items():
                        node_id = edge[side]
                        stp = nodes[node_id].get("stpRootPath", {})
                        if port["state"] == "up" and stp.get("localPort") == port["name"]:
                            stp_paths.append({**stp, "deviceId": node_id})
                    if stp_paths:
                        evidence[-1]["stpPaths"] = stp_paths
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
            alerts = []
            if confirmed and edge["kind"] == "Сетевое соединение":
                for report in evidence:
                    if report["confirmed"]:
                        comparison = _compare_link_ports(report.get("portStates", {}))
                        if comparison:
                            report["portComparison"] = comparison
                alerts = _link_port_alerts(evidence)
            links.append({**edge, "confirmed": confirmed, "portEvidence": evidence,
                          **({"portAlerts": alerts} if alerts else {})})
    if db is not None and endpoint_keys and now - stamp <= MAX_AGE:
        _attach_endpoint_presence(db, endpoint_keys, nodes, now)
    if lacp_expectations:
        _attach_lacp_health(nodes, lacp_expectations, links, port_states, now)
    _map_statuses(nodes, links)
    cluster_id = _text(raw.get("clusterId"))
    _attach_storage_assignments(nodes, links, cluster_id)
    revision = _text(raw.get("git"), 41)

    def node_ids(key: str) -> list[str]:
        values = raw.get(key)
        if not isinstance(values, list):
            return []
        return list(dict.fromkeys(value for value in values[:600] if isinstance(value, str) and value in nodes))

    raw_issues = raw.get("collectionIssues")
    known_issues = ("proxmox", "network_observer", "server_observer_unavailable", "server_observer_stale")
    issues = [name for name in known_issues if isinstance(raw_issues, list) and name in raw_issues]
    observer_at = _time(raw.get("serverObserverAt"))
    if (observer_at and now - observer_at > SERVER_OBSERVER_MAX_AGE
            and not {"server_observer_stale", "server_observer_unavailable"}.intersection(issues)):
        issues.append("server_observer_stale")
    return {
        **empty, "availability": "stale" if now - stamp > MAX_AGE else "ready",
        "snapshotAt": stamp.isoformat(), "nodes": list(nodes.values()), "links": links,
        "clusterId": cluster_id, "nodeOrder": node_ids("nodeOrder"),
        "overviewGuests": node_ids("overviewGuests"),
        "git": revision if re.fullmatch(r"[0-9a-f]{40}", revision) else "",
        **({"collectionIssues": issues} if issues else {}),
        **({"agentAudit": _summarize_guest_agents(nodes, agent_keys, agent_identities, now)}
           if agent_identities is not None else {}),
        **({"guestAttachments": _guest_attachments(nodes, links, [key for key, node in nodes.items() if node["guest"]])}
           if include_guest_attachments else {}),
    }
