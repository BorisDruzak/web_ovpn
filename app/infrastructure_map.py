from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from collections import Counter, defaultdict, deque
from collections.abc import Callable
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from netctl.snmp.interfaces import (
    BRIDGE_STP_PORT_STATES, LLDP_ADMIN_STATES, PAUSE_FRAME_COLUMNS, PAUSE_MODES, RX_ERROR_COLUMNS,
)
from netctl.snmp.lldp import LLDP_PORT_ID_SUBTYPES
from netctl.snmp.outcomes import SnmpOutcome
from netctl.switch_store import OPTIONAL_SWITCH_CAPABILITIES

from .endpoint_context_adapter import get_endpoint_context_adapter
from .endpoint_platform_client import EndpointPlatformServiceError
from .network_route_receipt_timing import MAX_AGE as ROUTE_RECEIPT_MAX_AGE
from .server_observer import STALE_AFTER as SERVER_OBSERVER_MAX_AGE
from .server_observer import (
    ACTI_BACKUP_MAX_REPOSITORY_BYTES, ACTI_BACKUP_MIN_FREE_GIB, ACTI_BACKUP_WATCHDOG_MAX_AGE,
    valid_acti_backup_job, valid_acti_backup_repository, valid_backup_snapshot_at, valid_observer_disk_capacity,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

LOGGER = logging.getLogger(__name__)
WINDOWS_PROBE_SOURCE = "Windows · сетевая проба"
WINDOWS_ADAPTER_SOURCE = "Windows · физический адаптер"

MAX_SNAPSHOT_BYTES = 1_000_000
MAX_AGE = timedelta(minutes=25)
MAX_DOWNSTREAM_SWITCHES = 12
SERVICE_PROBE_MAX_AGE = timedelta(minutes=5)
PROBE_TRANSITION_MAX_AGE = timedelta(hours=24)
STP_ROOT_PATH_MAX_AGE = timedelta(minutes=5)
TRANSCEIVER_MAX_AGE = timedelta(minutes=5)
PORT_LINK_CHECK_MAX_AGE = timedelta(minutes=5)
RX_SILENCE_MAX_WINDOW = timedelta(hours=1)
RX_SILENCE_MAX_INTERVALS = 6
PORT_COUNTER_KEYS = ("rxErrors", "txErrors", "rxDiscards", "txDiscards")
GUEST_AGENT_PROFILES = ("health_v1", "network_v1", "inventory_v1")
GUEST_AGENT_SERVICE_NAMES = ("sshd", "NetworkManager")
GUEST_AGENT_HEALTH_MAX_AGE = timedelta(minutes=6)
GUEST_AGENT_NETWORK_MAX_AGE = timedelta(minutes=20)
GUEST_ENROLLMENT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
VLAN_AUDIT_MAX_AGE = timedelta(minutes=10)
BRIDGE_VLAN_CONFIG_MODES = ("enabled", "disabled", "not_reported")
ROUTER_NEIGHBOR_MAX_AGE = timedelta(minutes=10)
MAX_ROUTER_NEIGHBORS = 16
PPPOE_METHOD = "Сессия PPPoE"
SNMP_COLLECTION_METHOD = "Сбор данных SNMP"
PPPOE_INTERNET_METHOD = "ICMP через PPPoE"
PPPOE_SOURCE = "RouterOS · PPPoE"
PPPOE_PARENT_LINK_MAX_AGE = timedelta(minutes=10)
RESOURCE_CAPACITY_MAX_AGE = timedelta(minutes=5)
GUEST_IO_MAX_AGE = timedelta(minutes=5)
GUEST_NETWORK_RATE_FIELDS = ("networkInBytesPerSecond", "networkOutBytesPerSecond")
LACP_HEALTH_MAX_AGE = timedelta(minutes=5)
LACP_PARTNER_MAX_AGE = timedelta(minutes=8)
ROOT_FREE_WARNING_PERCENT = 10
SWAP_USED_WARNING_PERCENT = 90
MEMORY_AVAILABLE_WARNING_PERCENT = 10
BACKUP_PROBE_METHOD = "Копия Proxmox"
PBS_STORAGE_METHOD = "Хранилище PBS"
LOCAL_STORAGE_METHOD = "Локальное хранилище Proxmox"
LOCAL_STORAGE_TYPES = ("lvmthin", "zfspool")
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
REDFISH_PAIR_SOURCE = "netctl FDB + Redfish"
REDFISH_PAIR_MAX_AGE = timedelta(minutes=10)
ENDPOINT_PAIR_SOURCE = "SNMP + Windows"
ENDPOINT_PAIR_MAX_AGE = timedelta(minutes=3)
CURRENT_PORT_PAIR_SOURCES = {
    "netctl", "LLDP UI_VPN", "LLDP · двустороннее", "netctl FDB + Proxmox",
    "SNMP · двусторонний FDB", "SNMP · порты STP", REDFISH_PAIR_SOURCE, ENDPOINT_PAIR_SOURCE,
}
PORT_EVIDENCE_MAX_AGE = {
    PPPOE_SOURCE: SERVICE_PROBE_MAX_AGE,
    "SNMP · порты STP": STP_ROOT_PATH_MAX_AGE,
    REDFISH_PAIR_SOURCE: REDFISH_PAIR_MAX_AGE,
    ENDPOINT_PAIR_SOURCE: ENDPOINT_PAIR_MAX_AGE,
}
SHARED_LLDP_KIND = "Путь через общий порт"
SHARED_LLDP_SOURCE = "LLDP · общий порт"
LLDP_FIRMWARE_MAX_AGE = timedelta(minutes=10)
FIRMWARE_VERSION = r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}(?:[a-z][a-z0-9]{0,7})?"
FIRMWARE_BUILD = r"[0-9]{1,12}"
OBSERVER_CHECK_LABELS = {
    "watchdog_fresh": "Свежесть отчёта watchdog",
    "backup_snapshot_fresh": "Свежесть резервной копии",
    "backup_fresh": "Свежесть копии по отчёту ACTI",
    "backup_check_fresh": "Свежесть проверки восстановления",
    "backup_job": "Последний запуск резервирования ACTI",
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
    "postgresql_from_directum": "PostgreSQL из ВМ Directum · SSLRequest",
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


def inventory_link_sources(value: object) -> list[dict]:
    sources = {}
    for row in _rows(value, 8):
        path, observed = row.get("path"), row.get("observedOn")
        if (not isinstance(path, str) or len(path) > 240 or not re.fullmatch(
                r"(?:docs|evidence)/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:md|ya?ml|json|txt)", path)
                or not isinstance(observed, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", observed)):
            continue
        try:
            date.fromisoformat(observed)
        except ValueError:
            continue
        sources[path, observed] = {"path": path, "observedOn": observed}
    return list(sources.values())


def _state(value: object) -> str:
    return value if value in STATES else "unknown"


def _number(value: object) -> int | float | None:
    if type(value) is int and abs(value) <= 10**20:
        return value
    return value if type(value) is float and math.isfinite(value) else None


def _observer_measurement(check: dict, name: str, now: datetime, *, fresh: bool) -> dict:
    job = check.get("backup_job")
    if name == "backup_job" and valid_acti_backup_job(job):
        completed = job["completed_at"]
        return {"backupJob": {"state": job["state"], "exitCode": job["exit_code"],
                              "timerActive": job["timer_active"],
                              "completedAt": datetime.fromtimestamp(completed, timezone.utc).isoformat()
                              if completed is not None else None}}
    repo = check.get("backup_repository")
    if name == "repository_capacity" and valid_acti_backup_repository(repo):
        measured = datetime.fromtimestamp(repo["checked_at"], timezone.utc)
        if timedelta(0) <= now - measured <= ACTI_BACKUP_WATCHDOG_MAX_AGE:
            return {"backupRepository": {
                "checkedAt": measured.isoformat(), "usedBytes": repo["used_bytes"], "freeGiB": repo["free_gib"],
                "maximumBytes": ACTI_BACKUP_MAX_REPOSITORY_BYTES, "minimumFreeGiB": ACTI_BACKUP_MIN_FREE_GIB,
            }}
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
    if fresh and name == "backup_snapshot_fresh" and valid_backup_snapshot_at(stamp := check.get("backup_snapshot_at")):
        snapshot = datetime.fromtimestamp(stamp, timezone.utc)
        if snapshot <= now:
            result["backupSnapshotAt"] = snapshot.isoformat()
    if valid_observer_disk_capacity(name, capacity := check.get("disk_capacity"), observed):
        result["diskCapacity"] = {"freeBytes": capacity["free_bytes"], "totalBytes": capacity["total_bytes"]}
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


def public_probe_transition(value: object, reachability: dict, now: datetime) -> dict:
    if not isinstance(value, dict) or reachability.get("source") != "Проверка сервиса":
        return {}
    before, after = value.get("from"), value.get("to")
    previous = _time(value.get("previousCheckedAt"))
    current = _time(value.get("checkedAt"))
    latest = _time(reachability.get("checkedAt"))
    if (before not in ("reachable", "unreachable") or after not in ("reachable", "unreachable")
            or before == after or after != reachability.get("state")
            or previous is None or current is None or latest is None
            or not timedelta(0) < current - previous <= SERVICE_PROBE_MAX_AGE
            or not now - PROBE_TRANSITION_MAX_AGE <= current <= latest <= now):
        return {}
    return {"from": before, "to": after, "previousCheckedAt": previous.isoformat(), "checkedAt": current.isoformat()}


def _public_port(row: dict, now: datetime) -> dict:
    stamp = _time(row.get("checkedAt"))
    source = row.get("source")
    max_age = MAX_AGE
    if source == "Redfish":
        max_age = REDFISH_PAIR_MAX_AGE
    elif source == WINDOWS_ADAPTER_SOURCE:
        max_age = ENDPOINT_PAIR_MAX_AGE
    fresh = observation_is_fresh(row.get("checkedAt"), now, max_age=max_age)
    state = "unknown" if source == "Proxmox" else row.get("state")
    speed = row.get("speedBps")
    result = {
        "name": _text(row.get("name"), 64),
        "state": state if fresh and state in ("up", "down", "disabled") else "unknown",
        "speedBps": speed if fresh and state == "up" and type(speed) is int and 0 < speed <= 10**15 else None,
        "checkedAt": stamp.isoformat() if stamp is not None and stamp <= now else None,
        "stale": not fresh,
    }
    label = row.get("ifAlias")
    if (fresh and isinstance(label, str) and re.fullmatch(r"[\w .()+/#-]{1,64}", label) and label.strip()):
        result["configuredLabel"] = {"text": label.strip(), "checkedAt": result["checkedAt"]}
    module = row.get("transceiver")
    if fresh and isinstance(module, dict) and observation_is_fresh(module.get("checkedAt"), now, max_age=TRANSCEIVER_MAX_AGE):
        fields = {key: value for key in ("vendor", "formFactor", "media")
                  if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,31}", value := _text(module.get(key), 32))}
        if fields.get("formFactor"):
            result["transceiver"] = {"checkedAt": _time(module["checkedAt"]).isoformat(), **fields}
            nominal = module.get("nominalBps")
            if type(nominal) is int and 0 < nominal <= 10**12:
                result["transceiver"]["nominalBps"] = nominal
            power = module.get("opticalPower")
            if isinstance(power, dict) and power.get("state") in ("available", "unavailable"):
                readings = {key: value for key in ("rxDbm", "txDbm")
                            if (value := _number(power.get(key))) is not None and -100 <= value <= 30}
                if power["state"] == "available" and readings:
                    result["transceiver"]["opticalPower"] = {"state": "available", **readings}
                elif power["state"] == "unavailable":
                    result["transceiver"]["opticalPower"] = {"state": "unavailable"}
    mode = row.get("routerLink") if source == "RouterOS" else row.get("linkMode")
    if (result["state"] == "up" and isinstance(mode, dict)
            and observation_is_fresh(mode.get("checkedAt"), now, max_age=PORT_LINK_CHECK_MAX_AGE)):
        duplex = mode.get("duplex")
        autoneg = mode.get("autoNegotiation")
        details = {"duplex": duplex} if duplex in ("full", "half") else {}
        if type(autoneg) is bool:
            details["autoNegotiation"] = autoneg
        if details:
            result["linkMode"] = {"checkedAt": _time(mode["checkedAt"]).isoformat(), **details}
        if source == "RouterOS" and type(rate := mode.get("speedBps")) is int and 0 < rate <= 10**15:
            result.update(speedBps=rate, speedCheckedAt=_time(mode["checkedAt"]).isoformat())
    stp = row.get("stpPort")
    if (fresh and isinstance(stp, dict) and stp.get("state") in BRIDGE_STP_PORT_STATES.values()
            and observation_is_fresh(stp.get("checkedAt"), now, max_age=STP_ROOT_PATH_MAX_AGE)):
        result["stpPort"] = {"checkedAt": _time(stp["checkedAt"]).isoformat(), "state": stp["state"]}
        if type(stp.get("enabled")) is bool:
            result["stpPort"]["enabled"] = stp["enabled"]
    lldp = row.get("lldpPort")
    if (fresh and isinstance(lldp, dict) and lldp.get("admin") in LLDP_ADMIN_STATES.values()
            and observation_is_fresh(lldp.get("checkedAt"), now, max_age=PORT_LINK_CHECK_MAX_AGE)):
        result["lldpPort"] = {"checkedAt": _time(lldp["checkedAt"]).isoformat(), "admin": lldp["admin"],
                              **{key: value for key in ("rxFrames", "txFrames")
                                 if type(value := lldp.get(key)) is int and 0 <= value < 2**32}}
        delta = lldp.get("delta")
        if result["state"] == "up" and isinstance(delta, dict):
            end, start = _time(lldp["checkedAt"]), _time(delta.get("startedAt"))
            keys = ("rxFrames", "txFrames")
            if (start and timedelta(seconds=30) <= end - start <= PORT_LINK_CHECK_MAX_AGE
                    and all(type(delta.get(key)) is int and 0 <= delta[key] <= result["lldpPort"].get(key, -1)
                            for key in keys)):
                result["lldpPort"]["delta"] = {"startedAt": start.isoformat(),
                                                "intervalSeconds": round((end - start).total_seconds(), 2),
                                                **{key: delta[key] for key in keys}}
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
            if "portId" in reading and neighbor.get("portIdSubtype") in LLDP_PORT_ID_SUBTYPES.values():
                reading["portIdSubtype"] = neighbor["portIdSubtype"]
            device = neighbor.get("inventoryDeviceId")
            if (re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", reading.get("chassisId", ""))
                    and isinstance(device, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", device)):
                reading["inventoryDeviceId"] = device
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
    if source in ("RouterOS", "Proxmox", "Proxmox · sysfs", "Redfish", WINDOWS_ADAPTER_SOURCE):
        result["source"] = source
    router_neighbors = row.get("routerNeighbors")
    if (source == "RouterOS" and result["state"] == "up" and isinstance(router_neighbors, dict)
            and observation_is_fresh(row.get("checkedAt"), now, max_age=ROUTER_NEIGHBOR_MAX_AGE)):
        readings = router_neighbors.get("devices")
        devices = []
        for mac, reading in list(readings.items())[:MAX_ROUTER_NEIGHBORS] if isinstance(readings, dict) else ():
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) or not isinstance(reading, dict):
                continue
            device = {"mac": mac}
            device.update({key: value for key in ("name", "platform")
                           if (value := _text(reading.get(key), 64)) and re.fullmatch(r"[\w .:/-]+", value)})
            if (address := _network_address(reading.get("address"))) and "/" not in address:
                device["address"] = address
            devices.append(device)
        if devices:
            total = router_neighbors.get("total")
            result["routerNeighbors"] = {"checkedAt": result["checkedAt"], "devices": devices,
                                         "total": total if type(total) is int and len(devices) <= total <= 65535 else len(devices)}
    if fresh and source in ("Proxmox", "Proxmox · sysfs") and type(row.get("proxmoxActive")) is bool:
        result["proxmoxActive"] = row["proxmoxActive"]
    if telemetry := _public_port_telemetry(row.get("telemetry"), result, now):
        result["telemetry"] = telemetry
        if silence := _public_rx_silence(row.get("rxSilence"), telemetry):
            result["rxSilence"] = silence
        counters = row.get("rxErrorCounters")
        if (telemetry.get("rxErrors", 0) > 0 and isinstance(counters, dict)
                and observation_is_fresh(counters.get("checkedAt"), now, max_age=PORT_LINK_CHECK_MAX_AGE)
                and _time(counters["checkedAt"]) >= _time(telemetry["checkedAt"])):
            readings = {key: value for key in RX_ERROR_COLUMNS
                        if type(value := counters.get(key)) is int and 0 <= value < 2**32}
            if "ifInErrors" in readings and len(readings) > 1:
                readings.update({key: value for key in PAUSE_FRAME_COLUMNS
                                 if type(value := counters.get(key)) is int and 0 <= value < 2**32})
                if isinstance(mode := counters.get("pauseOperMode"), str) and mode in PAUSE_MODES.values():
                    readings["pauseOperMode"] = mode
                result["rxErrorCounters"] = {"checkedAt": _time(counters["checkedAt"]).isoformat(), **readings}
    if memberships := _public_port_vlans(row.get("vlanMemberships"), result):
        result["vlanMemberships"] = memberships
    elif (isinstance(collection := row.get("vlanCollection"), dict) and collection.get("state") == "empty"
          and observation_is_fresh(collection.get("checkedAt"), now, max_age=VLAN_AUDIT_MAX_AGE)):
        result["vlanCollection"] = {"state": "empty", "checkedAt": _time(collection["checkedAt"]).isoformat()}
    if fdb_vlans := _public_port_fdb_vlans(row.get("fdbVlans"), result):
        result["fdbVlans"] = fdb_vlans
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
    age = sample.get("stateAgeSeconds")
    if state != "disabled" and type(age) in (int, float) and 0 <= age < 2**32 / 100:
        port["stateSince"] = (stamp - timedelta(seconds=age)).isoformat()
    endpoint = sample.get("endpointMac")
    if state == "up" and isinstance(endpoint, dict):
        device, mac = _text(endpoint.get("deviceId"), 160), _text(endpoint.get("mac"), 17)
        if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_:.-]{0,159}", device) and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            port["endpointMac"] = {"deviceId": device, "mac": mac, "checkedAt": stamp.isoformat()}
    if state != "up":
        for key in ("lldpChassisCount", "lldpNeighborCount", "lldpNeighbors", "lldpCheckedAt",
                    "fdbLearned", "fdbVlans", "telemetry", "rxErrorCounters", "rxSilence", "linkMode"):
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
    for key in PORT_COUNTER_KEYS:
        value = sample.get(key)
        if type(value) is int and 0 <= value < 2**53:
            metrics[key] = value
    return {"checkedAt": port["checkedAt"], "intervalSeconds": interval, **metrics} if metrics else {}


def _public_rx_silence(value: object, telemetry: dict) -> dict:
    if not isinstance(value, dict) or telemetry.get("rxBps") != 0 or telemetry.get("txBps", 0) <= 0:
        return {}
    started, checked = _time(value.get("startedAt")), _time(value.get("checkedAt"))
    intervals, sent = value.get("intervalCount"), value.get("txBytes")
    if (started is None or checked is None or checked.isoformat() != telemetry["checkedAt"]
            or not timedelta(seconds=telemetry["intervalSeconds"]) < checked - started <= RX_SILENCE_MAX_WINDOW
            or type(intervals) is not int or not 2 <= intervals <= RX_SILENCE_MAX_INTERVALS
            or type(sent) is not int or not 0 < sent < 2**53):
        return {}
    return {"startedAt": started.isoformat(), "checkedAt": checked.isoformat(),
            "intervalCount": intervals, "txBytes": sent}


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
    if record not in ("A", "AAAA", "SOA", "SRV") or not re.fullmatch(r"\.|(?:[A-Za-z0-9_-]{1,63}\.){1,127}", name):
        return {}
    result = {"name": name, "record": record}
    rcode, transport = value.get("rcode"), value.get("transport")
    if transport in ("UDP", "TCP"):
        result["transport"] = transport
    expected = value.get("expectedAddresses")
    if record in ("A", "AAAA") and isinstance(expected, list):
        addresses = [address for item in expected[:16] if (address := _network_address(item))
                     and "/" not in address and (":" in address) == (record == "AAAA")]
        if addresses:
            result["expectedAddresses"] = addresses
    if isinstance(rcode, str) and re.fullmatch(r"[A-Z0-9]{1,16}", rcode) and "transport" in result:
        result["rcode"] = rcode
        addresses = value.get("addresses")
        if record in ("A", "AAAA") and isinstance(addresses, list):
            result["addresses"] = [address for item in addresses[:16] if (address := _network_address(item))
                                   and "/" not in address and (":" in address) == (record == "AAAA")]
        if record == "SRV":
            records = [{"target": item["target"], "port": item["port"]} for item in _rows(value.get("srvRecords"), 16)
                       if isinstance(item.get("target"), str) and len(item["target"]) <= 254
                       and re.fullmatch(r"(?:[A-Za-z0-9-]{1,63}\.){1,127}", item["target"])
                       and type(item.get("port")) is int and 1 <= item["port"] <= 65535]
            if records:
                result["srvRecords"] = records
    return result


def _public_arp_details(arp: object) -> dict:
    if not isinstance(arp, dict) or arp.get("state") not in ("no_reply", "matched", "different_mac", "unconfirmed"):
        return {}
    interface = arp.get("interface")
    if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        return {}
    try:
        address, source = (str(ipaddress.IPv4Address(arp.get(key))) for key in ("address", "sourceIP"))
    except ValueError:
        return {}
    return {"state": arp["state"], "address": address, "sourceIP": source, "interface": interface}


def _public_service_check(check: dict, now: datetime) -> dict:
    path = _text(check.get("path"))
    port = check.get("port")
    backup = check.get("method") == BACKUP_PROBE_METHOD and check.get("source") == "Proxmox"
    pbs_storage = check.get("method") == PBS_STORAGE_METHOD and check.get("source") == "Proxmox"
    local_storage = check.get("method") == LOCAL_STORAGE_METHOD and check.get("source") == "Proxmox"
    current_probe = (check.get("source") == "UI_VPN" and check.get("required") is True
                     or check.get("source") == "RouterOS" and check.get("method") == PPPOE_INTERNET_METHOD)
    windows_probe = check.get("source") == WINDOWS_PROBE_SOURCE and check.get("method") in ("DNS", "HTTP")
    max_age = (ROUTE_RECEIPT_MAX_AGE if windows_probe else SERVICE_PROBE_MAX_AGE
               if backup or pbs_storage or local_storage or current_probe else MAX_AGE)
    result = {
        **_public_reachability(check, now, max_age=max_age),
        "port": port if type(port) is int and 1 <= port <= 65535 else None,
        "target": _network_address(check.get("target")), "via": _network_address(check.get("via")),
        "path": path if re.fullmatch(r"/[A-Za-z0-9._/-]{0,159}", path) and not path.startswith("//") else "",
    }
    interface = check.get("managementInterface")
    if (result["source"] == "UI_VPN" and not result["stale"] and isinstance(interface, dict)
            and interface.get("source") == "SNMP · ARP"
            and re.fullmatch(r"vlan[1-9][0-9]{0,3}", _text(interface.get("name")), re.IGNORECASE)
            and observation_is_fresh(check.get("identityCheckedAt"), now)):
        result["managementInterface"] = {"name": interface["name"], "source": interface["source"]}
    if (result["method"] == SNMP_COLLECTION_METHOD and result["source"] == "Network Observer"
            and not result["stale"] and check.get("reason") in (
                "snmp_fdb_unavailable", "snmp_collection_failed", "snmp_collection_partial", "snmp_collection_unconfirmed",
            )):
        result["reason"] = check["reason"]
        if result["reason"] == "snmp_collection_partial" and isinstance(outcomes := check.get("snmpOutcomes"), dict):
            failures = [{"capability": capability, "outcome": outcomes[capability]}
                        for capability in sorted(OPTIONAL_SWITCH_CAPABILITIES)
                        if outcomes.get(capability) in (SnmpOutcome.TIMEOUT, SnmpOutcome.AUTH_OR_VIEW_FAILURE, SnmpOutcome.PARSE_ERROR)]
            if failures:
                result["snmpFailures"] = failures
    pppoe = check.get("pppoe")
    if (result["method"] == PPPOE_METHOD and not result["stale"] and isinstance(pppoe, dict)
            and pppoe.get("state") in ("connected", "disconnected", "disabled")):
        session, parent = _text(pppoe.get("session"), 32), _text(pppoe.get("parent"), 32)
        if INTERFACE_NAME.fullmatch(session) and INTERFACE_NAME.fullmatch(parent):
            result["pppoe"] = {"session": session, "parent": parent, "state": pppoe["state"]}
            link = pppoe.get("parentLink")
            if (isinstance(link, dict) and link.get("state") in ("up", "down", "disabled")
                    and observation_is_fresh(link.get("checkedAt"), now, max_age=PPPOE_PARENT_LINK_MAX_AGE)):
                result["pppoe"]["parentLink"] = {"state": link["state"], "source": "RouterOS",
                                                 "checkedAt": _time(link["checkedAt"]).isoformat()}
    reason = check.get("reason")
    storage_field = "pbsStorage" if pbs_storage else "localStorage" if local_storage else ""
    if storage_field and isinstance(detail := check.get(storage_field), dict):
        storage, node = _text(detail.get("id"), 64), _text(detail.get("node"), 64)
        kind = detail.get("type")
        if PVE_STORAGE_ID.fullmatch(storage) and INTERFACE_NAME.fullmatch(node) and (pbs_storage or kind in LOCAL_STORAGE_TYPES):
            result[storage_field] = {"id": storage, "node": node}
            if local_storage:
                result[storage_field]["type"] = kind
            if not result["stale"]:
                total, used, available = (detail.get(key) for key in ("totalBytes", "usedBytes", "availableBytes"))
                if (result["state"] == "reachable" and all(type(value) is int for value in (total, used, available))
                        and 0 < total <= 2**53 - 1 and 0 <= used <= total and 0 <= available <= total):
                    result[storage_field].update(totalBytes=total, usedBytes=used, availableBytes=available)
                if reason in ("pbs_storage_permission", "pbs_storage_disabled", "pbs_storage_inactive", "pbs_storage_unconfirmed"):
                    result["reason"] = reason
                if local_storage and reason in ("pve_storage_permission", "pve_storage_excluded",
                                                "pve_storage_inactive", "pve_storage_unconfirmed"):
                    result["reason"] = reason
    ipsec = check.get("ipsecPolicy")
    if result["method"] == "IPsec фаза 2" and result["source"] == "MikroTik IPsec" and isinstance(ipsec, dict):
        remote = _network_address(ipsec.get("remoteNetwork"))
        directions = []
        for row in _rows(ipsec.get("directions"), 2):
            source = _text(row.get("source"), 64)
            if not source:
                continue
            at = row.get("checkedAt")
            detail = {"source": source, "state": "unknown", "checkedAt": None, "reason": "ipsec_observation_unavailable"}
            if observation_is_fresh(at, now, max_age=SERVICE_PROBE_MAX_AGE):
                state, failure = row.get("state"), row.get("reason")
                if state == "reachable":
                    detail = {"source": source, "state": state, "checkedAt": _time(at).isoformat()}
                elif state == "unreachable" and failure in ("ipsec_policy_missing", "ipsec_phase2_not_established"):
                    detail.update(state=state, checkedAt=_time(at).isoformat(), reason=failure)
                elif state == "unknown" and failure == "ipsec_ssh_unavailable":
                    detail.update(checkedAt=_time(at).isoformat(), reason=failure)
            directions.append(detail)
        if remote and len(directions) == 2 and directions[0]["source"] != directions[1]["source"]:
            result["ipsecPolicy"] = {"remoteNetwork": remote, "directions": directions}
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
    if reason == "timeout" and result["method"] in ("HTTP", "HTTPS", "DNS", "SMB2", "PostgreSQL SSLRequest", "TCP", "Zabbix API"):
        result["reason"] = reason
    if reason == "tcp_connection_refused" and result["method"] in ("TCP", "RDP Negotiation", "SIP OPTIONS (TCP)") and result["state"] == "unreachable":
        result["reason"] = reason
    if result["method"] == "RDP Negotiation":
        security, failure = check.get("rdpSecurity"), check.get("rdpFailureCode")
        if result["state"] == "unknown" and reason in ("timeout", "network_error", "unexpected_response", "probe_configuration"):
            result["reason"] = reason
        if result["state"] == "reachable" and security in ("TLS", "CredSSP"):
            result["rdpSecurity"] = security
        if result["state"] == "unreachable" and reason == "rdp_negotiation_rejected" and type(failure) is int and 1 <= failure <= 7:
            result.update(reason=reason, rdpFailureCode=failure)
    if result["method"] == "NTP (UDP)":
        if reason in ("ntp_unsynchronized", "ntp_rate_limited", "ntp_access_denied",
                      "ntp_route_mismatch", "ntp_route_unconfirmed", "timeout",
                      "unexpected_response", "transport_error", "probe_configuration"):
            result["reason"] = reason
    if check.get("supplemental") is True:
        result["supplemental"] = True
    elif check.get("required") is True:
        result["required"] = True
        if check.get("component") is True:
            result["component"] = True
    if (check.get("skipped") is True and result["checkedAt"] and result["state"] == "unknown"
            and reason in ("probe_target_unconfirmed", "probe_target_mismatch", "probe_host_stopped")):
        if (not result["stale"] and result["source"] == "UI_VPN" and reason == "probe_target_unconfirmed"
                and (arp := _public_arp_details(check.get("arpDiagnostic")))):
            result["arpDiagnostic"] = arp
        return {**result, "target": "", "skipped": True, "reason": reason}
    identified_icmp = result["method"] in ("ICMP · LLDP + ARP", "ICMP · ARP + FDB")
    if identified_icmp or (result["source"] == "UI_VPN" and "identityCheckedAt" in check):
        identity_at = check.get("identityCheckedAt")
        if observation_is_fresh(identity_at, now):
            result["identityCheckedAt"] = _time(identity_at).isoformat()
        else:
            result.update(state="unknown", stale=True)
    if result["method"] == "NTP (UDP)" and result["source"] == "UI_VPN" and not result["stale"]:
        ntp = check.get("ntp")
        if isinstance(ntp, dict):
            version, stratum, leap = (ntp.get(key) for key in ("version", "stratum", "leapIndicator"))
            if (type(version) is int and version in (3, 4) and type(stratum) is int and 0 <= stratum <= 255
                    and type(leap) is int and 0 <= leap <= 3):
                result["ntp"] = {"version": version, "stratum": stratum, "leapIndicator": leap}
                code = ntp.get("kissCode")
                if stratum == 0 and code in ("RATE", "DENY", "RSTR"):
                    result["ntp"]["kissCode"] = code
    icmp = identified_icmp or result["method"] in ("ICMP", "ICMP адреса из инвентаря", "ICMP · VLAN", PPPOE_INTERNET_METHOD)
    if icmp or (result["method"] == "IPMI LAN (UDP)" and result["source"] == "UI_VPN"
                and result["state"] == "reachable" and not result["stale"]):
        round_trip = check.get("roundTripMs")
        if type(round_trip) in (int, float) and 0 <= round_trip <= 3000:
            result["roundTripMs"] = round_trip
    if icmp:
        if reason in ("icmp_no_echo_reply", "icmp_reply_unconfirmed", "icmp_unreachable", "icmp_probe_error",
                      "icmp_source_ssh_unavailable",
                      "icmp_route_unconfirmed", "icmp_route_mismatch"):
            result["reason"] = reason
    sip = result["method"] in ("SIP OPTIONS (UDP)", "SIP OPTIONS (TCP)")
    if sip and reason in ("sip_route_mismatch", "sip_route_unconfirmed"):
        result["reason"] = reason
    if icmp or sip or result["method"] in ("DNS", "NTP (UDP)"):
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
    if result["method"] in ("ICMP · VLAN", "DNS", "NTP (UDP)") and result["source"] == "UI_VPN":
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
                peer = vlan.get("peer")
                if isinstance(peer, dict) and not result["stale"]:
                    asset = _text(peer.get("asset"), 160)
                    port = _text(peer.get("guestPort"), 12)
                    state = peer.get("state")
                    if (re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_:.-]{0,159}", asset)
                            and re.fullmatch(r"net[0-9]{1,3}", port)
                            and state in ("matched", "mismatch", "unconfirmed")):
                        result["vlanTransit"]["peer"] = {"asset": asset, "guestPort": port, "state": state}
        if reason in ("vlan_probe_error", "vlan_interface_missing", "vlan_id_mismatch",
                      "vlan_link_down", "vlan_address_mismatch", "vlan_route_mismatch",
                      "vlan_peer_identity_mismatch", "vlan_peer_identity_unconfirmed"):
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
    if result["method"] in ("HTTP", "HTTPS", "WinRM HTTP", "Zabbix API"):
        host = check.get("httpHost")
        if result["method"] == "HTTP" and isinstance(host, str) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            result["httpHost"] = host
        status = check.get("httpStatus")
        if type(status) is int and 100 <= status <= 599 and (not windows_probe or not result["stale"]):
            result["httpStatus"] = status
        if (result["method"] in ("HTTP", "HTTPS") and result["source"] == "UI_VPN"
                and status == 401 and result["state"] == "reachable" and not result["stale"]
                and check.get("httpAuthChallenge") == "Digest"):
            result["httpAuthChallenge"] = "Digest"
        version = check.get("redfishVersion")
        if (result["method"] == "HTTPS" and result["path"] == "/redfish/v1/" and status == 200
                and result["state"] == "reachable" and not result["stale"]
                and isinstance(version, str) and re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version)):
            result["redfishVersion"] = version
        version = check.get("zabbixVersion")
        if (result["method"] == "Zabbix API" and status == 200 and result["state"] == "reachable"
                and not result["stale"] and isinstance(version, str)
                and re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version)):
            result["zabbixVersion"] = version
        if reason in (
            "http_status", "http_content_type", "http_content_encoding", "http_body_limit", "http_invalid_json",
            "http_reported_unavailable", "http_payload_mismatch", "http_certificate_pin",
            "http_tls_certificate", "http_tls_error", "http_bad_response", "http_connection_refused",
            "http_connection_reset", "http_configuration", "oidc_rs256_key_missing",
        ):
            result["reason"] = reason
        if result["method"] == "WinRM HTTP" and reason in ("winrm_auth_required", "timeout", "probe_configuration"):
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
            if (windows_probe and not result["stale"] and "rcode" in diagnostic
                    and type(match := check["dns"].get("answersMatch")) is bool):
                diagnostic["answersMatch"] = match
            if windows_probe and reason == "dns_rcode":
                result["reason"] = reason
            if reason in ("dns_no_answer", "dns_address_mismatch", "dns_srv_mismatch", "dns_unexpected_source",
                          "dns_route_unconfirmed", "dns_route_mismatch", "dns_truncated"):
                result["reason"] = reason
            if (reason == "dns_unexpected_source" and result["state"] == "unreachable"
                    and diagnostic.get("transport") == "UDP"
                    and isinstance(responder := check["dns"].get("unexpectedResponder"), dict)):
                address = _network_address(responder.get("address"))
                responder_port = responder.get("port")
                if address and "/" not in address and type(responder_port) is int and 1 <= responder_port <= 65535:
                    reply = _public_dns_check({
                        "name": diagnostic["name"], "record": diagnostic["record"], "transport": "UDP",
                        "rcode": responder.get("rcode"), "addresses": responder.get("addresses"),
                    })
                    details = {key: reply[key] for key in ("rcode", "addresses") if key in reply}
                    if details.get("addresses") and type(responder.get("matchesExpectedAddresses")) is bool:
                        details["matchesExpectedAddresses"] = responder["matchesExpectedAddresses"]
                    diagnostic["unexpectedResponder"] = {"address": address, "port": responder_port, **details}
    if result["method"] in ("OpenVPN Management", "OpenVPN UDP-сокет"):
        configured_port = check.get("configuredPort")
        sessions = check.get("sessionCount")
        if type(configured_port) is int and 1 <= configured_port <= 65535:
            result["configuredPort"] = configured_port
        binding = check.get("localUdpSocket")
        if "configuredPort" in result and not result["stale"] and isinstance(binding, dict):
            state, addresses = binding.get("state"), binding.get("addresses")
            if state in ("unbound", "unknown"):
                result["localUdpSocket"] = {"state": state}
            elif state == "bound" and isinstance(addresses, list) and 1 <= len(addresses) <= 8:
                clean = ["*" if address == "*" else _network_address(address) for address in addresses]
                if all(address and "/" not in address for address in clean):
                    result["localUdpSocket"] = {"state": state, "addresses": clean}
        if result["method"] == "OpenVPN Management" and result["checkedAt"]:
            if type(sessions) is int and 0 <= sessions <= 4096 and type(check.get("daemonReady")) is bool:
                result.update(sessionCount=sessions, daemonReady=check["daemonReady"])
            if reason in ("openvpn_management_unavailable", "openvpn_management_incomplete",
                          "openvpn_daemon_unconfirmed", "openvpn_no_active_sessions"):
                result["reason"] = reason
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
        route_source = _text(check.get("routeSource"), 64)
        if result["source"] == "Network Observer" and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", route_source):
            result["routeSource"] = route_source
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
    rtsp = check.get("rtspStatus")
    if result["method"] == "RTSP OPTIONS":
        if type(rtsp) is int and 100 <= rtsp <= 599:
            result["rtspStatus"] = rtsp
        if reason == "rtsp_connection_refused" or (rtsp == 401 and reason == "rtsp_auth_required"):
            result["reason"] = reason
    if result["method"] in {"Сертификат TLS", "Рукопожатие TLS"} or (result["method"] == "HTTPS" and not result["stale"]):
        expires = _time(check.get("tlsExpiresAt"))
        version = check.get("tlsVersion")
        if expires:
            result["tlsExpiresAt"] = expires.isoformat()
        if version in ("TLSv1.2", "TLSv1.3"):
            result["tlsVersion"] = version
    if result["method"] == "Рукопожатие TLS" and reason in {
        "probe_configuration", "tls_handshake_rejected", "tls_handshake_unconfirmed",
        "tls_connection_refused", "timeout", "transport_error",
    }:
        result["reason"] = reason
    if result["method"] == "Сертификат TLS":
        if reason in {"probe_configuration", "tls_certificate_pin", "tls_certificate_expired",
                      "tls_certificate_not_yet_valid", "tls_certificate_unconfirmed",
                      "tls_certificate_verification_failed", "tls_connection_refused",
                      "timeout", "transport_error"}:
            result["reason"] = reason
        if (check.get("required") is True and result["state"] == "reachable" and not result["stale"]
                and expires is not None and timedelta(0) <= expires - now <= timedelta(days=30)):
            result["reason"] = "tls_certificate_expiring"
    if result["method"] == "LDAPS RootDSE" and reason in {
        "probe_configuration", "ldaps_response_unconfirmed", "ldaps_naming_context_mismatch",
        "ldaps_tls_certificate", "ldaps_connection_refused", "ldaps_transport_unconfirmed",
    }:
        result["reason"] = reason
    if result["method"] == "FTP FEAT":
        reply = check.get("ftpReply")
        if type(reply) is int and 100 <= reply <= 599:
            result["ftpReply"] = reply
        if reason in {"timeout", "transport_error", "ftp_connection_refused", "ftp_unexpected_reply", "ftp_invalid_reply"}:
            result["reason"] = reason
    if result["method"] == "SSH" and result["source"] == "UI_VPN" and reason in {
        "timeout", "transport_error", "ssh_connection_refused", "ssh_identification_invalid",
        "ssh_closed_before_identification",
    }:
        result["reason"] = reason
    if (result["method"] == "SSH" and result["source"] == "UI_VPN" and not result["stale"]
            and check.get("sshTcpConnected") is True):
        result["sshTcpConnected"] = True
    attempts = check.get("attempts")
    if type(attempts) is int and (
        (sip and 1 <= attempts <= 3)
        or (result["method"] in ("HTTP", "HTTPS", "SSH", "TCP") and result["source"] == "UI_VPN" and attempts == 2)
    ):
        result["attempts"] = attempts
        if (result["method"] in ("TCP", "HTTP", "HTTPS") and result["source"] == "UI_VPN"
                and attempts == 2 and check.get("firstAttemptReason") == "timeout"):
            result["firstAttemptReason"] = "timeout"
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
    for keys in (GUEST_NETWORK_RATE_FIELDS, ("diskReadBytesPerSecond", "diskWriteBytesPerSecond")):
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
    endpoint = row.get("endpointMemory")
    if isinstance(endpoint, dict) and observation_is_fresh(endpoint.get("checkedAt"), now, max_age=GUEST_AGENT_HEALTH_MAX_AGE):
        available = endpoint.get("availableBytes")
        if headroom := _memory_headroom(available, result):
            result["memoryHeadroom"] = {**headroom, "availableBytes": available, "source": "Endpoint Agent",
                                        "checkedAt": _time(endpoint["checkedAt"]).isoformat()}
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
            if isinstance(rtsp := entry.get("rtsp"), dict) and observation_is_fresh(
                    rtsp.get("checkedAt"), now, max_age=SERVICE_PROBE_MAX_AGE):
                check = _public_service_check({**rtsp, "source": "UI_VPN", "method": "RTSP OPTIONS",
                                               "port": 554, "path": "/"}, now)
                device["rtsp"] = {key: check[key] for key in ("state", "checkedAt", "rtspStatus", "reason") if key in check}
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


def _public_firmware(value: object, now: datetime) -> dict:
    if not isinstance(value, dict) or not observation_is_fresh(value.get("checkedAt"), now, max_age=LLDP_FIRMWARE_MAX_AGE):
        return {}
    product, version, build = (value.get(key) for key in ("product", "version", "build"))
    observer, port = _text(value.get("observerId")), _text(value.get("observerPort"), 64)
    if (product not in ("RouterOS", "SWT-1318P") or not observer or not port
            or not isinstance(version, str) or not re.fullmatch(FIRMWARE_VERSION, version)):
        return {}
    if build is not None and (product != "SWT-1318P" or not isinstance(build, str)
                              or not re.fullmatch(FIRMWARE_BUILD, build)):
        return {}
    return {"product": product, "version": version, "source": "LLDP", "checkedAt": _time(value["checkedAt"]).isoformat(),
            "observerId": observer, "observerPort": port, **({"build": build} if build is not None else {})}


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
    if isinstance(supplied, dict) and (address := _network_address(supplied.get("Адрес управления"))):
        properties["Адрес управления"] = address
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
    history_source = properties.get("Источник сбора", "")
    for port, raw_port in zip(ports, port_rows):
        _apply_port_link_check(port, raw_port, now)
        key = _text(raw_port.get("key"))
        if (not port["stale"]
                and label_counts[port_label_key(port["name"])] == 1
                and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", history_source)):
            if row.get("kind") == NETWORK_KINDS[0] and re.fullmatch(r"(?:ifindex|physical):[1-9][0-9]{0,9}", key):
                port["history"] = {"source": history_source, "interface": key}
            elif port.get("source") == "RouterOS" and INTERFACE_NAME.fullmatch(port["name"]):
                port["history"] = {"source": history_source, "interface": port["name"]}
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
    ambiguous = {name for name in required_names if check_counts[name] > 1}
    checks = [check for check in checks if _text(check.get("name"), 64) not in ambiguous]
    checks.extend({"name": name} for name in required_names if check_counts[name] != 1)
    service_checks = [_public_service_check(check, now) for check in _rows(row.get("serviceChecks"), 16)]
    root = row.get("stpRoot")
    stp_root = {}
    if row.get("kind") == NETWORK_KINDS[0] and isinstance(root, dict):
        local_port = _text(root.get("localPort"), 64)
        bridge = _text(root.get("rootBridgeMac"), 17)
        if (observation_is_fresh(root.get("checkedAt"), now, max_age=STP_ROOT_PATH_MAX_AGE)
                and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", bridge)
                and sum(port["name"] == local_port and port["state"] == "up" for port in ports) == 1):
            stp_root = {"localPort": local_port, "rootBridgeMac": bridge,
                        "checkedAt": _time(root["checkedAt"]).isoformat()}
            if root_id := _text(root.get("rootDeviceId")):
                stp_root["rootDeviceId"] = root_id
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
                designated_port = _text(stp.get("designatedPortName"), 64)
                designated_at = stp.get("designatedPortCheckedAt")
                if designated_port and observation_is_fresh(designated_at, now, max_age=STP_ROOT_PATH_MAX_AGE):
                    stp_path.update(designatedPortName=designated_port, designatedPortCheckedAt=_time(designated_at).isoformat())
    downstream = (_public_downstream(row.get("downstream"), ports, stp_path, now)
                  if row.get("kind") == NETWORK_KINDS[0] else {})
    firmware = _public_firmware(row.get("firmware"), now) if row.get("kind") in NETWORK_KINDS else {}
    reachability = _service_reachability(row.get("reachability"), service_checks, now)
    power = row.get("hardwarePower")
    hardware_power = {}
    if (row.get("kind") == "Сервер" and isinstance(power, dict)
            and power.get("state") in ("On", "Off", "PoweringOn", "PoweringOff")
            and observation_is_fresh(power.get("checkedAt"), now, max_age=SERVICE_PROBE_MAX_AGE)
            and re.fullmatch(r"[a-z0-9-]{1,64}", _text(power.get("controllerId"), 65))):
        hardware_power = {"state": power["state"], "controllerId": power["controllerId"],
                          "source": "Redfish", "checkedAt": _time(power["checkedAt"]).isoformat()}
        if power.get("restorePolicy") in ("AlwaysOff", "AlwaysOn", "LastState"):
            hardware_power["restorePolicy"] = power["restorePolicy"]
        last_reset = _time(power.get("lastResetAt"))
        if last_reset and last_reset <= _time(power["checkedAt"]):
            hardware_power["lastResetAt"] = last_reset.isoformat()
        for key in ("health", "healthRollup"):
            if power.get(key) in ("OK", "Warning", "Critical"):
                hardware_power[key] = power[key]
        memory = power.get("totalSystemMemoryGiB")
        if type(memory) in (int, float) and 0 < memory <= 1_048_576:
            hardware_power["totalSystemMemoryGiB"] = memory
        if power["state"] == "Off" and reachability["state"] != "reachable":
            reachability = {"state": "stopped", "source": "Redfish", "method": "Состояние питания",
                            "checkedAt": hardware_power["checkedAt"], "stale": False}
    transition = public_probe_transition(row.get("probeTransition"), reachability, now) if row.get("kind") == "Сервис" else {}
    return {
        **{key: _text(row.get(key)) for key in ("id", "name", "kind", "site", "origin", "pveHost")},
        "guest": row.get("guest") is True,
        "vmid": row.get("vmid") if type(row.get("vmid")) is int else None,
        "aliases": [_text(value) for value in aliases[:12] if isinstance(value, str)] if isinstance(aliases, list) else [],
        "sourceStatus": next((state for state in STATES if any(source["status"] == state for source in fresh)), "unknown"),
        "reachability": reachability,
        **({"hardwarePower": hardware_power} if hardware_power else {}),
        **({"probeTransition": transition} if transition else {}),
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
        **({"stpRoot": stp_root} if stp_root else {}),
        **({"downstream": downstream} if downstream else {}),
        **({"firmware": firmware} if firmware else {}),
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
             **_observer_measurement(check, name, now, fresh=bool(observer and not observer["stale"])),
             "latency": _number(check.get("latency"))}
            for check in checks
            for name in [_text(check.get("name"), 64)]
        ],
    }


def _attach_guest_observer_measurements(nodes: dict, links: list[dict]) -> None:
    metrics = {"c_disk_free", "root_disk_free", "data_disk_free",
               "windows_memory_available_bytes", "windows_memory_available_percent",
               "linux_memory_available_bytes", "linux_memory_available_percent"}
    hosts = defaultdict(set)
    for edge in links:
        if (_is_service_attachment(edge) and nodes[edge["b"]]["kind"] == "Сервис"
                and nodes[edge["a"]]["kind"] != "Сервис"):
            hosts[edge["b"]].add(edge["a"])
    for service_id, candidates in hosts.items():
        if len(candidates) != 1:
            continue
        host_id, = candidates
        guest = nodes[host_id]
        if not guest["guest"] or not any(source["name"] == "Proxmox" and source["label"] == "Запущена"
                                         and not source["stale"] for source in guest["sources"]):
            continue
        checks = nodes[service_id]["checks"]
        counts = Counter(check["name"] for check in checks)
        guest["checks"].extend(
            {**check, "required": False, "sourceNodeId": service_id}
            for check in checks
            if check["name"] in metrics and counts[check["name"]] == 1
            and not check["stale"] and check.get("observed") is not None
        )


def _attach_acti_backup_job(nodes: dict, links: list[dict]) -> None:
    app_id, backup_id = "role:acti", "role:acti_backup"
    if not any(link["a"] == app_id and link["b"] == backup_id and link["confirmed"]
               and link["kind"] == "Зависимость сервиса" for link in links):
        return
    jobs = [check for check in nodes[app_id]["checks"] if check["name"] == "backup_job"]
    backup_checks = nodes[backup_id]["checks"]
    if len(jobs) == 1 and "backupJob" in jobs[0] and not any(check["name"] == "backup_job" for check in backup_checks):
        backup_checks.append({**jobs[0], "required": False, "sourceNodeId": app_id})


def _attach_backup_scope(nodes: dict) -> None:
    service = nodes.get(BACKUP_SERVICE_ID)
    if not service or service["kind"] != "Сервис":
        return
    guests = [node for node in nodes.values() if "backupCoverage" in node]
    storages = {node["backupCoverage"]["storage"] for node in guests}
    if len(storages) != 1:
        return
    storage, = storages
    running = [node for node in guests if _guest_power(node) == "running"]

    def scope(group):
        counts = Counter(node["backupCoverage"]["state"] for node in group)
        return {"total": len(group), "scheduled": counts["scheduled"],
                "notScheduled": counts["not_scheduled"], "unknown": counts["unknown"]}

    gaps = [{**{key: node[key] for key in ("id", "name", "vmid")}, "state": node["backupCoverage"]["state"]}
            for node in running if node["backupCoverage"]["state"] != "scheduled"]
    gaps.sort(key=lambda row: (row["state"] != "not_scheduled", row["vmid"], row["id"]))
    service["backupScope"] = {"storage": storage, **scope(guests), "running": scope(running), "runningGaps": gaps[:64]}


def _service_check_status(check: dict) -> str:
    if check.get("reason") == "tls_certificate_expiring":
        return "warn"
    return {"reachable": "ok", "unreachable": "critical"}.get(check["state"], "unknown")


def _map_statuses(nodes: dict, links: list[dict]) -> None:
    services = {key: set() for key in nodes}
    consumers = {key: set() for key in nodes}
    cluster_members = defaultdict(set)
    placements = defaultdict(set)
    controller_port_faults = set()
    for edge in links:
        if (edge["confirmed"] and edge["kind"] == "Узел кластера" and nodes[edge["a"]]["kind"] == CLUSTER_KIND
                and nodes[edge["b"]]["kind"] == "Гипервизор"):
            cluster_members[edge["a"]].add(edge["b"])
        if (edge["confirmed"] and edge["kind"] == "Управление оборудованием"
                and nodes[edge["a"]].get("managementPortErrors")
                and nodes[edge["b"]]["kind"] in ("Сервер", "Гипервизор")
                and not nodes[edge["b"]]["guest"]):
            controller_port_faults.add(edge["b"])
        if edge["confirmed"] and edge["kind"] in SERVICE_LINKS and nodes[edge["b"]]["kind"] == "Сервис":
            services[edge["a"]].add(edge["b"])
            consumers[edge["b"]].add(edge["a"])
            if _is_service_attachment(edge) and nodes[edge["a"]]["kind"] != "Сервис":
                placements[edge["b"]].add(edge["a"])

    for service_id, hosts in placements.items():
        service = nodes[service_id]
        if len(hosts) == 1 and service["reachability"]["state"] == "unknown":
            host_id, = hosts
            host = nodes[host_id]
            reachability = host["reachability"]
            if (reachability["source"] == "Redfish" and reachability["state"] == "stopped"
                    and (power := host.get("hardwarePower"))):
                service["reachability"] = {
                    **reachability, "stoppedBy": {"hostId": host_id, "controllerId": power["controllerId"]},
                }

    local_issues = {}
    check_state = {"reachable": "ok", "unreachable": "critical"}
    for key, node in nodes.items():
        checks = [check["status"] for check in node["checks"] if check.get("required")]
        checks.extend(_service_check_status(check) for check in node["serviceChecks"] if check.get("required"))
        if any(disk["smartState"] == "critical" for disk in node.get("hardwareDisks", {}).get("disks", [])):
            checks.append("critical")
        if any(node.get("hardwarePower", {}).get(key) in ("Warning", "Critical") for key in ("health", "healthRollup")):
            checks.append("warn")
        if any(pool["health"] in ZFS_PROBLEM_STATES for pool in node.get("zfsPools", {}).get("pools", [])):
            checks.append("warn")
        if any(pool["capacityStatus"] == "warn" for pool in node.get("lvmThinPools", {}).get("pools", [])):
            checks.append("warn")
        if capacity := node.get("resourceCapacity"):
            checks.extend(capacity[key]["status"] for key in ("root", "swap"))
            if memory := capacity.get("memoryHeadroom"):
                checks.append(memory["status"])
        checks.extend(report["status"] for report in node.get("lacpHealth", []))
        if node.get("managementPortErrors") or key in controller_port_faults:
            checks.append("warn")
        if coverage := node.get("backupScope", {}).get("running"):
            if coverage["notScheduled"]:
                checks.append("warn")
            elif coverage["unknown"]:
                checks.append("unknown")
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

    for cluster_id, members in cluster_members.items():
        cluster = nodes[cluster_id]
        health = {state: sorted(member for member in members if nodes[member]["mapStatus"] == state) for state in STATES}
        cluster["clusterMemberHealth"] = health
        if cluster["reachability"]["state"] == "reachable":
            if health["warn"] or health["critical"]:
                cluster["status"] = cluster["mapStatus"] = "warn"
            elif health["unknown"] and cluster["mapStatus"] == "ok":
                cluster["status"] = cluster["mapStatus"] = "unknown"


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
        lacp = {"side": side, "aggregate": aggregate, "member": member, "partnerPort": int(partner[1]),
                "partnerInterfaceState": "unconfirmed"}
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
            histories = {port_label_key(label): port["history"] for port in nodes[switch_id]["ports"]
                         if "history" in port for label in (port["name"], *port.get("aliases", []))}
            for name in names:
                port = port_states.get(switch_id, {}).get(port_label_key(name), {})
                sample = forwarding.get((node_id, switch_id, aggregate.casefold(), name.casefold()))
                at = port.get("checkedAt")
                if (port.get("state") in {"down", "disabled"} and observation_is_fresh(at, now, max_age=LACP_HEALTH_MAX_AGE)
                        and (not sample or _time(at) >= _time(sample[0]))):
                    members.append({"name": name, "status": port["state"], "checkedAt": at})
                elif sample:
                    member = {"name": name, "status": "forwarding", "checkedAt": sample[0],
                              "partnerPort": sample[1], "partnerInterfaceState": "unconfirmed"}
                    if (port.get("state") == "up" and port.get("speedBps")
                            and observation_is_fresh(at, now, max_age=LACP_HEALTH_MAX_AGE)):
                        member.update(speedBps=port["speedBps"], linkCheckedAt=at)
                    members.append(member)
                else:
                    members.append({"name": name, "status": "unknown"})
                if port and (history := histories.get(port_label_key(port["name"]))):
                    members[-1]["history"] = history
            states = {member["status"] for member in members}
            aggregate_port = port_states.get(switch_id, {}).get(port_label_key(aggregate), {})
            aggregate_link = {"state": "unknown"}
            if (aggregate_port.get("state") in {"up", "down", "disabled"}
                    and observation_is_fresh(aggregate_port.get("checkedAt"), now, max_age=LACP_HEALTH_MAX_AGE)):
                aggregate_link = {key: aggregate_port[key] for key in ("state", "checkedAt", "speedBps")
                                  if aggregate_port.get(key) is not None}
            fault = aggregate_link["state"] in {"down", "disabled"}
            states.add(aggregate_link["state"])
            status = "warn" if states & {"down", "disabled"} else "unknown" if "unknown" in states else "ok"
            nodes[node_id].setdefault("lacpHealth", []).append({
                "switchId": switch_id, "aggregate": aggregate, "members": members,
                "status": status, "aggregateLink": aggregate_link,
                **({"aggregateLinkFault": aggregate_link} if fault else {}),
            })


def _compare_link_ports(ports: dict) -> dict:
    if set(ports) != {"a", "b"} or any(port["state"] == "unknown" for port in ports.values()):
        return {}
    a, b = ports["a"], ports["b"]
    up_count = sum(port["state"] == "up" for port in (a, b))
    if up_count == 2 and a["speedBps"] and b["speedBps"]:
        first, last = sorted(_time(port.get("speedCheckedAt", port["checkedAt"])) for port in (a, b))
        if last - first <= timedelta(minutes=2):
            state = "speed_mismatch" if a["speedBps"] != b["speedBps"] else "both_up"
            return {"state": state, "checkedAt": first.isoformat()}
    first, last = sorted((_time(a["checkedAt"]), _time(b["checkedAt"])))
    if last - first > timedelta(minutes=2):
        return {}
    if up_count == 2:
        state = "both_up"
    else:
        state = "one_down" if up_count else "both_down"
    return {"state": state, "checkedAt": first.isoformat()}


def _link_ports_down(ports: dict) -> dict:
    down = sorted(side for side, port in ports.items() if port["state"] in {"down", "disabled"})
    if not down:
        return {}
    return {"state": "port_down", "downSides": down,
            "checkedAt": min(ports[side]["checkedAt"] for side in down)}


def _audit_link_vlans(expected: object, ports: dict, now: datetime) -> list[dict]:
    if not isinstance(expected, dict):
        return []
    intent = {}
    for mode in ("tagged", "untagged"):
        ids = expected.get(mode, [])
        if not isinstance(ids, list) or len(ids) > 32:
            return []
        for vid in ids:
            if type(vid) is not int or not 1 <= vid <= 4094 or vid in intent:
                return []
            intent[vid] = mode

    observations = {vid: {} for vid in intent}
    for side, port in ports.items():
        if port["state"] != "up":
            continue
        if collection := port.get("vlanCollection"):
            for readings in observations.values():
                readings[side] = {"vlanCollection": collection}
        for field, value, timestamp in (("vlanMemberships", "egress", "membershipCheckedAt"),
                                         ("fdbVlans", "learnedMacCount", "fdbCheckedAt")):
            sample = port.get(field, {})
            if not observation_is_fresh(sample.get("checkedAt"), now, max_age=VLAN_AUDIT_MAX_AGE):
                continue
            for reading in sample["vlans"]:
                if reading["id"] in observations and reading.get(value):
                    side_observation = observations[reading["id"]].setdefault(side, {})
                    side_observation.update({value: reading[value], timestamp: sample["checkedAt"]})

    results = []
    for vid, mode in sorted(intent.items()):
        observations_by_side = observations[vid]
        actual = [reading["egress"] for reading in observations_by_side.values() if "egress" in reading]
        state = "mismatch" if any(egress != mode for egress in actual) else "confirmed" if len(actual) == 2 else "unconfirmed"
        results.append({"id": vid, "expected": mode, "state": state, "ports": observations_by_side})
    return results


def _link_port_alerts(evidence: list[dict]) -> list[dict]:
    alerts = {}
    for report in evidence:
        if not (report.get("pairEvidence") or report.get("lacp")):
            continue
        ports = report.get("portStates", {})
        comparison = report.get("portComparison")
        if comparison:
            if comparison["state"] == "both_up":
                continue
            alert = comparison
        else:
            alert = _link_ports_down(ports)
            if not alert:
                continue
        a, b = (ports.get(side, {}).get("name", report[side]) for side in ("a", "b"))
        alerts[(port_label_key(a), port_label_key(b))] = {"portA": a, "portB": b, **alert}
    return list(alerts.values())


def _summarize_port_counters(nodes: dict, topology_pairs: tuple | None, *,
                             port_nodes: dict | None = None, service_ports: dict | None = None) -> dict:
    measured = 0
    affected = []
    selected = nodes if port_nodes is None else port_nodes
    port_by_key = {}
    for node in selected.values():
        for port in node["ports"]:
            telemetry = port.get("telemetry", {})
            if not any(key in telemetry for key in PORT_COUNTER_KEYS):
                continue
            measured += 1
            if any(telemetry.get(key, 0) for key in PORT_COUNTER_KEYS):
                row = {"deviceId": node["id"], "deviceName": node["name"], "port": port["name"],
                       "telemetry": telemetry}
                row.update({key: port[key] for key in ("configuredLabel", "rxErrorCounters", "history") if key in port})
                affected.append(row)
                port_by_key[node["id"], port["name"]] = port

    def severity(row):
        counters = row["telemetry"]
        errors = counters.get("rxErrors", 0) + counters.get("txErrors", 0)
        discards = counters.get("rxDiscards", 0) + counters.get("txDiscards", 0)
        return -errors, -discards, row["deviceId"], row["port"]

    affected.sort(key=severity)
    ports = affected[:64]
    if service_ports:
        by_port = {
            (device_id, port_label_key(group["port"])): group["statusCounts"]
            for device_id, groups in service_ports.items() for group in groups
        }
        for row in ports:
            device_id = row["deviceId"]
            port = port_by_key[device_id, row["port"]]
            for label in (port["name"], *port.get("aliases", [])):
                if counts := by_port.get((device_id, port_label_key(label))):
                    row["linkedStatusCounts"] = counts
                    break
    if ports and topology_pairs:
        _, inventory, _, pending, current = topology_pairs
        canonical_ports = {
            (device_id, port_label_key(label)): port["name"]
            for device_id, node in nodes.items() for port in node["ports"]
            for label in (port["name"], *port.get("aliases", []))
        }
        peers_by_port = defaultdict(dict)
        for evidence, pairs in (("current", current), ("verified_inventory", inventory), ("unconfirmed", pending)):
            for pair in pairs:
                for side, remote in (("A", "B"), ("B", "A")):
                    local_id, peer_id = pair[side.lower()], pair[remote.lower()]
                    if not pair[f"port{side}"]:
                        continue
                    local_port, peer_port = pair[f"port{side}"], pair[f"port{remote}"]
                    local_port = canonical_ports.get((local_id, port_label_key(local_port)), local_port)
                    peer_port = canonical_ports.get((peer_id, port_label_key(peer_port)), peer_port)
                    peers = peers_by_port[local_id, port_label_key(local_port)]
                    peers.setdefault((peer_id, port_label_key(peer_port)), {
                        "id": peer_id, "port": peer_port, "evidence": evidence,
                        "name": nodes[peer_id]["name"],
                    })
        evidence_rank = {"current": 0, "verified_inventory": 1, "unconfirmed": 2}
        for row in ports:
            device_id = row["deviceId"]
            port = port_by_key[device_id, row["port"]]
            candidates = sorted(
                (peer for name in (port["name"], *port.get("aliases", []))
                 for peer in peers_by_port.get((device_id, port_label_key(name)), {}).values()),
                key=lambda peer: (evidence_rank[peer["evidence"]], peer["id"], port_label_key(peer["port"])),
            )
            unique = {}
            for peer in candidates:
                unique.setdefault((peer["id"], port_label_key(peer["port"])), peer)
            if unique:
                row["peers"] = list(unique.values())[:8]
    return {"measuredPorts": measured, "affectedPorts": len(affected), "ports": ports}


def _summarize_port_rx_silence(nodes: dict, pending: list[dict]) -> dict:
    ports = [
        {"deviceId": node["id"], "deviceName": node["name"], "port": port["name"], "rxSilence": port["rxSilence"],
         **({"configuredLabel": port["configuredLabel"]} if "configuredLabel" in port else {})}
        for node in nodes.values() if node["kind"] == NETWORK_KINDS[0]
        for port in node["ports"] if "rxSilence" in port
    ]
    if ports:
        peers_by_port = defaultdict(dict)
        for pair in pending:
            for side, remote in (("A", "B"), ("B", "A")):
                port = pair[f"port{side}"]
                if port:
                    peer = {"id": pair[remote.lower()], "name": pair[f"name{remote}"], "port": pair[f"port{remote}"]}
                    peers_by_port[pair[side.lower()], port_label_key(port)][peer["id"], peer["port"]] = peer
        for row in ports:
            node = nodes[row["deviceId"]]
            port = next(port for port in node["ports"] if port["name"] == row["port"])
            peers = {}
            for name in (port["name"], *port.get("aliases", [])):
                peers.update(peers_by_port.get((node["id"], port_label_key(name)), {}))
            if peers:
                row["pendingPeers"] = [peers[key] for key in sorted(peers)[:8]]
    ports.sort(key=lambda row: (-row["rxSilence"]["txBytes"], row["deviceId"], row["port"]))
    return {"total": len(ports), "ports": ports[:64]}


def _archived_router_peer(edge: dict) -> dict:
    archived = {report["b"]: report for report in edge["portEvidence"]
                if report["source"] == "GitHub" and not report["confirmed"] and not report["a"] and report["b"]}
    if len(archived) != 1:
        return {}
    port, = archived
    report = archived[port]
    return {"nodeId": edge["b"], "port": port, "checkedAt": report["at"],
            **({"inventorySources": report["inventorySources"]} if "inventorySources" in report else {})}


def _compare_port_traffic(ports: dict) -> dict:
    if not all(side in ports for side in ("a", "b")):
        return {}
    a, b = (ports[side].get("telemetry", {}) for side in ("a", "b"))
    if not all("rxBps" in sample and "txBps" in sample for sample in (a, b)):
        return {}
    a_end, b_end = (_time(sample["checkedAt"]) for sample in (a, b))
    a_start = a_end - timedelta(seconds=a["intervalSeconds"])
    b_start = b_end - timedelta(seconds=b["intervalSeconds"])
    overlap = (min(a_end, b_end) - max(a_start, b_start)).total_seconds()
    if overlap < 0.75 * max(a["intervalSeconds"], b["intervalSeconds"]):
        return {}

    def direction(tx: float, rx: float) -> dict:
        return {"txBps": tx, "rxBps": rx,
                "differencePercent": round(100 * abs(tx - rx) / max(tx, rx), 2) if tx or rx else 0}

    return {"overlapSeconds": round(overlap, 2), "checkedAtA": a["checkedAt"], "checkedAtB": b["checkedAt"],
            "aToB": direction(a["txBps"], b["rxBps"]), "bToA": direction(b["txBps"], a["rxBps"])}


def _mark_conflicting_port_pairs(nodes: dict, links: list[dict]) -> None:
    aliases = {(node["id"], port_label_key(alias)): port_label_key(port["name"])
               for node in nodes.values() for port in node["ports"] for alias in port.get("aliases", [])}
    peers = defaultdict(set)
    candidates = []
    for edge in links:
        if edge["kind"] != "Сетевое соединение" or not edge["confirmed"]:
            continue
        for report in edge["portEvidence"]:
            if report.get("pairEvidence") != "current":
                continue
            a, b = ((edge[side], port_label_key(report[side])) for side in ("a", "b"))
            a, b = (a[0], aliases.get(a, a[1])), (b[0], aliases.get(b, b[1]))
            peers[a].add(b)
            peers[b].add(a)
            candidates.append((edge, report, (a, b)))
    affected = {}
    for edge, report, ends in candidates:
        sides = [side for side, endpoint in zip(("a", "b"), ends) if len(peers[endpoint]) > 1]
        if not sides:
            continue
        report["conflictingPortSides"] = sides
        report["confirmed"] = False
        report.pop("pairEvidence")
        report.pop("portComparison", None)
        affected[id(edge)] = edge
    for edge in affected.values():
        edge["confirmed"] = any(report.get("pairEvidence") == "current" or report.get("lacp")
                                for report in edge["portEvidence"])
        edge.pop("portAlerts", None)
        if edge["confirmed"] and (alerts := _link_port_alerts(edge["portEvidence"])):
            edge["portAlerts"] = alerts


def _topology_port_pairs(nodes: dict, links: list[dict]) -> tuple:
    port_aliases = {
        (node["id"], port_label_key(alias)): port_label_key(port["name"])
        for node in nodes.values()
        for port in node["ports"]
        for alias in port.get("aliases", [])
    }
    port_names = {node_id: {port_label_key(port["name"]) for port in node["ports"]} for node_id, node in nodes.items()}
    canonical_ports = {(node["id"], port_label_key(port["name"])): port["name"]
                       for node in nodes.values() for port in node["ports"]}
    histories = {(node["id"], port_label_key(port["name"])): port["history"]
                 for node in nodes.values() for port in node["ports"] if "history" in port}
    unnamed = {"", "-", "unknown", "неизвестно"}

    def port_key(node_id, label):
        key = port_label_key(label)
        return port_aliases.get((node_id, key), key)

    paths = {}
    bridge_mac_ports = defaultdict(dict)
    for link in links:
        if link["confirmed"] and link["kind"] in ("Путь по MAC-таблице", SHARED_LLDP_KIND):
            for report in link["portEvidence"]:
                if not report["confirmed"]:
                    continue
                paths.setdefault(frozenset((link["a"], link["b"])), []).append((link["a"], report))
                learned = report.get("learnedEndpoint")
                if report["source"] != "netctl FDB" or not learned:
                    continue
                switch, bridge = learned["switchId"], learned["deviceId"]
                side = "a" if link["a"] == switch else "b"
                state = report.get("portStates", {}).get(side, {})
                if state.get("state") != "up" or state.get("stale"):
                    continue
                port = state["name"]
                ports = bridge_mac_ports[bridge, learned["mac"]]
                key = switch, port_key(switch, port)
                if key not in ports or ports[key]["checkedAt"] < report["at"]:
                    ports[key] = {"bridgeDeviceId": bridge, "switchId": switch, "port": port,
                                  "checkedAt": report["at"]}

    counts = {"current": 0, "verifiedInventory": 0, "unconfirmed": 0}
    pending = {}
    known_ports = set()
    alerts = []
    inventory_pairs = []
    current_pairs = {}

    def remember_ports(a, b, port_a, port_b):
        for device, peer, label in ((a, b, port_a), (b, a, port_b)):
            if (key := port_key(device, label)) not in unnamed:
                known_ports.add((device, peer, key))

    def observations(report):
        return {
            side: {key: port[key] for key in ("name", "state", "speedBps", "speedCheckedAt", "checkedAt", "stateSince", "source", "linkMode",
                                              "stpPort", "telemetry", "rxErrorCounters", "rxSilence", "fdbLearned", "transceiver",
                                              "configuredLabel", "lldpPort") if key in port}
            for side, port in report.get("portStates", {}).items() if port["state"] != "unknown"
        }

    for link in links:
        if link["kind"] != "Сетевое соединение":
            continue
        a, b = link["a"], link["b"]
        alerts.extend({"a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"], **alert}
                      for alert in link.get("portAlerts", []))
        reports = link["portEvidence"]
        current = [r for r in reports if link["confirmed"] and r.get("pairEvidence") == "current"]
        lacp_members = [r for r in reports if link["confirmed"] and r.get("lacp")]
        inventory = [r for r in reports if r.get("pairEvidence") == "verified_inventory"]
        for report in current:
            if report["source"] == "SNMP LACP + ARP" or not report["at"]:
                continue
            ends = (a, port_key(a, report["a"])), (b, port_key(b, report["b"]))
            pair, sources = current_pairs.setdefault(tuple(sorted(ends)), (
                {"a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"],
                 "portA": canonical_ports.get(ends[0], report["a"]),
                 "portB": canonical_ports.get(ends[1], report["b"])}, {},
            ))
            source, at = report["source"], report["at"]
            for side, device in (("a", a), ("b", b)):
                state = report.get("portStates", {}).get(side)
                if not state or state["stale"] or state["state"] == "unknown":
                    continue
                pair_side = "a" if pair["a"] == device else "b"
                states = pair.setdefault("portStates", {})
                if state["checkedAt"] > states.get(pair_side, {}).get("checkedAt", ""):
                    states[pair_side] = {key: state[key] for key in
                                         ("state", "speedBps", "checkedAt", "stateSince", "source", "speedCheckedAt") if key in state}
            if source not in sources or at > sources[source]["checkedAt"]:
                expires = _time(at) + PORT_EVIDENCE_MAX_AGE.get(source, MAX_AGE)
                sources[source] = {"source": source, "checkedAt": at, "expiresAt": expires.isoformat()}
                if "windowsAdapter" in report:
                    sources[source]["windowsAdapter"] = report["windowsAdapter"]
        for report in current + inventory + lacp_members:
            remember_ports(a, b, report["a"], report["b"])
            if lacp := report.get("lacp"):
                side, peer = ("a", "b") if lacp["side"] == "a" else ("b", "a")
                remember_ports(link[side], link[peer], lacp["member"], "")
        for report in inventory:
            endpoint_macs = {}
            port_states = {}
            port_diagnostics = {}
            for side, peer in (("a", "b"), ("b", "a")):
                state = report.get("portStates", {}).get(side, {})
                if state and not state["stale"] and state["state"] != "unknown":
                    port_states[side] = {key: state[key] for key in
                                         ("state", "speedBps", "checkedAt", "stateSince", "source", "speedCheckedAt") if key in state}
                    telemetry = state.get("telemetry", {})
                    if any(telemetry.get(key, 0) > 0 for key in PORT_COUNTER_KEYS):
                        diagnostics = {"telemetry": telemetry}
                        if counters := state.get("rxErrorCounters"):
                            diagnostics["rxErrorCounters"] = counters
                        if history := histories.get((link[side], port_key(link[side], report[side]))):
                            diagnostics["history"] = history
                        port_diagnostics[side] = diagnostics
                endpoint = state.get("endpointMac")
                if (state.get("state") == "up" and not state["stale"]
                        and endpoint and endpoint["deviceId"] == link[peer]):
                    endpoint_macs[side] = endpoint
            fdb_observations = []
            for origin, reading in paths.get(frozenset((a, b)), []):
                learned = reading.get("learnedEndpoint")
                if reading["source"] != "netctl FDB" or not learned or not reading["at"]:
                    continue
                switch = learned["switchId"]
                side = "a" if switch == a else "b"
                local = reading["a" if switch == origin else "b"]
                if not local or port_key(switch, local) != port_key(switch, report[side]):
                    continue
                observation = {**learned, "port": report[side], "checkedAt": reading["at"]}
                if address := reading.get("managementAddress"):
                    observation["managementAddress"] = address
                if observation not in fdb_observations:
                    fdb_observations.append(observation)
            inventory_pairs.append({
                "a": a, "b": b, "portA": report["a"], "portB": report["b"],
                "inventorySources": report.get("inventorySources", []),
                "unmeasuredSides": [side for side in ("a", "b") if side not in port_states],
                **({"portStates": port_states} if port_states else {}),
                **({"portDiagnostics": port_diagnostics} if port_diagnostics else {}),
                **({"fdbObservations": fdb_observations[:8]} if fdb_observations else {}),
                **({"endpointMacObservations": endpoint_macs} if endpoint_macs else {}),
            })
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
                    or any(covers(declared, r) for r in current + lacp_members)):
                continue
            related = []
            for origin, report in paths.get(frozenset((a, b)), []):
                pa, pb = (report["a"], report["b"]) if origin == a else (report["b"], report["a"])
                if ((pa and port_key(a, pa) == port_key(a, declared["a"]))
                        or (pb and port_key(b, pb) == port_key(b, declared["b"]))):
                    related.append({"portA": pa, "portB": pb, "source": report["source"], "checkedAt": report["at"],
                                    **{key: report[key] for key in ("stpPaths", "learnedEndpoint") if key in report}})
            lldp = {side: {"checkedAt": port["lldpCheckedAt"], "neighbors": port["lldpNeighbors"]}
                    for side, port in declared.get("portStates", {}).items() if port.get("lldpNeighbors")}
            reading = observations(declared)
            inventory_only = [side for side in ("a", "b")
                              if side not in reading and port_label_key(declared[side]) not in unnamed]
            remember_ports(a, b, declared["a"], declared["b"])
            pending[(a, b, declared["a"], declared["b"])] = {
                "a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"],
                "portA": declared["a"], "portB": declared["b"], "observedPaths": related[:8],
                "missingPortSides": [side for side in ("a", "b") if port_label_key(declared[side]) in unnamed],
                "identifiedPeerSides": [side for side, path_port in (("a", "portA"), ("b", "portB"))
                                        if side in declared.get("lldpPeers", {})
                                        or any(path[path_port]
                                               and port_key(link[side], path[path_port]) == port_key(link[side], declared[side])
                                               and (path["source"] == RECIPROCAL_MAC_SOURCE
                                                    or path.get("learnedEndpoint", {}).get("switchId") == link[side])
                                               for path in related)],
                **({"inventorySources": declared["inventorySources"]} if "inventorySources" in declared else {}),
                **({"inventoryPortSides": inventory_only} if inventory_only else {}),
                **({"portObservations": reading} if reading else {}),
                **({"lldpObservations": lldp} if lldp else {}),
                **({"lldpPeers": declared["lldpPeers"]} if "lldpPeers" in declared else {}),
            }
    pending_keys = {(row["a"], row["b"], port_key(row["a"], row["portA"]), port_key(row["b"], row["portB"])): row
                    for row in pending.values()}
    for link in links:
        a, b = link["a"], link["b"]
        for report in link["portEvidence"]:
            if not (sides := report.get("conflictingPortSides")):
                continue
            key = a, b, port_key(a, report["a"]), port_key(b, report["b"])
            if key not in pending_keys:
                port_a = canonical_ports.get((a, key[2]), report["a"])
                port_b = canonical_ports.get((b, key[3]), report["b"])
                row = {"a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"],
                       "portA": port_a, "portB": port_b, "observedPaths": [], "missingPortSides": [],
                       "identifiedPeerSides": [], "portObservations": observations(report)}
                pending[a, b, port_a, port_b] = pending_keys[key] = row
            row = pending_keys[key]
            row["conflictingPortSides"] = sides
            reading = {"portA": report["a"], "portB": report["b"], "source": report["source"], "checkedAt": report["at"]}
            if reading not in row["observedPaths"] and len(row["observedPaths"]) < 8:
                row["observedPaths"].append(reading)
            remember_ports(a, b, report["a"], report["b"])
    for link in links:
        if link["kind"] not in ("Транзитный сегмент", "Путь по MAC-таблице"):
            continue
        a, b = link["a"], link["b"]
        reports = link["portEvidence"]
        peer_record = _archived_router_peer(link)
        peer_port = peer_record.get("port", "")
        for report in reports:
            port = report["a"]
            if (report["source"] not in ("MikroTik · ARP", "MikroTik · ARP + FDB") or not report["confirmed"]
                    or not port or report["b"] or (a, b, port_key(a, port)) in known_ports):
                continue
            reading = observations(report)
            pending[a, b, port, peer_port] = {
                "a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"],
                "portA": port, "portB": peer_port, "basis": "router_attachment",
                "missingPortSides": [] if peer_port else ["b"], "identifiedPeerSides": ["a"],
                "observedPaths": [{"portA": port, "portB": "", "source": report["source"], "checkedAt": report["at"]}],
                **({"archivedPortSides": ["b"], "archivedPortAt": {"b": peer_record["checkedAt"]}} if peer_port else {}),
                **({"inventorySources": peer_record["inventorySources"]} if "inventorySources" in peer_record else {}),
                **({"portObservations": reading} if reading else {}),
            }
    discovered = {}
    for reports in paths.values():
        for origin, report in reports:
            if not (learned := report.get("learnedEndpoint")):
                continue
            switch, device = learned["switchId"], learned["deviceId"]
            side, peer = ("a", "b") if origin == switch else ("b", "a")
            port = report[side]
            key = switch, device, port_key(switch, port)
            if key in known_ports or port_key(device, report[peer]) not in unnamed:
                continue
            if key in discovered and report["at"] <= discovered[key]["observedPaths"][0]["checkedAt"]:
                continue
            reading = observations(report).get(side)
            lldp_peers = report.get("lldpPeers", {}).get(side)
            discovered[key] = {
                "a": switch, "b": device, "nameA": nodes[switch]["name"], "nameB": nodes[device]["name"],
                "portA": port, "portB": "", "basis": "learned_endpoint",
                "missingPortSides": ["b"], "identifiedPeerSides": ["a"],
                "observedPaths": [{"portA": port, "portB": "", "source": report["source"],
                                   "checkedAt": report["at"], "learnedEndpoint": learned}],
                **({"portObservations": {"a": reading}} if reading else {}),
                **({"lldpPeers": {"a": lldp_peers}} if lldp_peers else {}),
            }
    shared_inventory = defaultdict(dict)
    shared_port_keys = set()
    for link in links:
        if link["kind"] != SHARED_LLDP_KIND:
            continue
        a, b = link["a"], link["b"]
        for report in link["portEvidence"]:
            port = report["a"]
            key = a, b, port_key(a, port)
            if key[2] not in unnamed and (report["source"] == "GitHub" or report["confirmed"]):
                shared_port_keys.add((a, key[2]))
            if (report["source"] == "GitHub" and not report["confirmed"]
                    and key[2] not in unnamed and (peer_key := port_key(b, report["b"])) not in unnamed):
                entry = shared_inventory[key].setdefault(peer_key, {"port": report["b"]})
                sources = inventory_link_sources(entry.get("inventorySources", []) + report.get("inventorySources", []))
                if sources:
                    entry["inventorySources"] = sources
                continue
            if (not link["confirmed"] or report["source"] != SHARED_LLDP_SOURCE
                    or not report["confirmed"] or not port or report["b"]
                    or key in known_ports):
                continue
            observed_path = {"portA": port, "portB": "", "source": SHARED_LLDP_SOURCE, "checkedAt": report["at"]}
            if row := discovered.get(key):
                if row["basis"] == "learned_endpoint" and observed_path not in row["observedPaths"]:
                    if len(row["observedPaths"]) < 8:
                        row["observedPaths"].append(observed_path)
                    if peers := report.get("lldpPeers", {}).get("a"):
                        combined = row.setdefault("lldpPeers", {}).get("a", []) + peers
                        row["lldpPeers"]["a"] = [peer for index, peer in enumerate(combined)
                                                  if peer not in combined[:index]][:16]
                continue
            reading = observations(report)
            discovered[key] = {
                "a": a, "b": b, "nameA": nodes[a]["name"], "nameB": nodes[b]["name"],
                "portA": port, "portB": "", "basis": "shared_lldp",
                "missingPortSides": ["b"], "identifiedPeerSides": ["a"],
                "observedPaths": [observed_path],
                **({"portObservations": reading} if reading else {}),
                **({"lldpPeers": report["lldpPeers"]} if "lldpPeers" in report else {}),
            }
    for key, row in discovered.items():
        if (key[0], key[2]) in shared_port_keys:
            row["sharedPort"] = True
        if declared := shared_inventory.get(key):
            row["inventoryPeerPorts"] = [declared[peer] for peer in sorted(declared)[:8]]
        pending[row["a"], row["b"], row["portA"], ""] = row
    shared_lldp_ports = {
        (node_id, port_label_key(port["name"])): port
        for node_id, node in nodes.items() for port in node["ports"]
        if (node_id, port_label_key(port["name"])) in shared_port_keys
        and port["state"] == "up" and not port["stale"] and port.get("lldpCheckedAt")
    }
    device_names = Counter(node["name"].casefold() for node in nodes.values())
    verified_pairs = []
    def attach_history(pair):
        history = {}
        for side, label in (("a", "portA"), ("b", "portB")):
            device = pair[side]
            if reading := histories.get((device, port_key(device, pair[label]))):
                history[side] = reading
        if history:
            pair["portHistory"] = history

    for _, (pair, sources) in sorted(current_pairs.items()):
        attach_history(pair)
        ports = pair.get("portStates", {})
        health = _compare_link_ports(ports) or _link_ports_down(ports) or {"state": "unconfirmed"}
        verified_pairs.append({**pair, "linkHealth": health,
                               "evidence": [sources[source] for source in sorted(sources)]})
    by_port = defaultdict(list)
    for pair in verified_pairs:
        for side, field in (("a", "portA"), ("b", "portB")):
            by_port[pair[side], port_key(pair[side], pair[field])].append(pair)
    for row in pending.values():
        attach_history(row)
        ports = row.get("portObservations", {})
        row["linkHealth"] = _compare_link_ports(ports) or _link_ports_down(ports) or {"state": "unconfirmed"}
        if any(path["source"] == RECIPROCAL_MAC_SOURCE for path in row["observedPaths"]):
            if traffic := _compare_port_traffic(ports):
                row["trafficComparison"] = traffic
        if row.get("sharedPort") and not any(path["source"] == SHARED_LLDP_SOURCE for path in row["observedPaths"]):
            port = shared_lldp_ports.get((row["a"], port_key(row["a"], row["portA"])), {})
            name = row["nameB"].casefold()
            candidates = [
                {**neighbor, "checkedAt": port["lldpCheckedAt"]}
                for neighbor in port.get("lldpNeighbors", [])
                if device_names[name] == 1 and neighbor.get("systemName", "").casefold() == name
                and neighbor.get("inventoryDeviceId", row["b"]) == row["b"]
            ]
            if candidates:
                row["unconfirmedLldpCandidates"] = candidates[:8]
        multi_mac_sides = [side for side, port in row.get("portObservations", {}).items()
                           if port.get("fdbLearned", {}).get("learnedMacCount", 0) > 1]
        if multi_mac_sides:
            row["multiMacPortSides"] = sorted(multi_mac_sides)
        connections = []
        mac_observations = {}
        for reading in row["observedPaths"]:
            for stp in reading.get("stpPaths", ()):
                bridge, port = stp.get("bridgeDeviceId"), stp.get("designatedPortName")
                for key, seen in bridge_mac_ports.get((bridge, stp["designatedBridgeMac"]), {}).items():
                    mac_observations[bridge, *key] = seen
                if not bridge or not port:
                    continue
                matches = by_port.get((bridge, port_key(bridge, port)), [])
                other = row["b"] if stp["deviceId"] == row["a"] else row["a"]
                if len(matches) != 1:
                    continue
                pair, = matches
                if {pair["a"], pair["b"]} == {bridge, other} and pair not in connections:
                    connections.append(pair)
        if connections:
            row["stpBridgeConnections"] = connections
        if mac_observations:
            row["stpBridgeMacObservations"] = [mac_observations[key] for key in sorted(mac_observations)[:12]]
        arp_diagnostics = {}
        for side in ("a", "b"):
            checks = nodes[row[side]]["serviceChecks"]
            readings = {check["arpDiagnostic"]["address"]: {**check["arpDiagnostic"], "checkedAt": check["checkedAt"]}
                        for check in sorted(checks, key=lambda check: check["checkedAt"] or "")
                        if check.get("supplemental") and not check["stale"] and "arpDiagnostic" in check}
            if readings:
                arp_diagnostics[side] = [readings[address] for address in sorted(readings)[:4]]
        if arp_diagnostics:
            row["arpDiagnostics"] = arp_diagnostics
        stopped_endpoints = {}
        for side in ("a", "b"):
            node = nodes[row[side]]
            power = node.get("hardwarePower", {})
            if power.get("state") == "Off" and node["reachability"]["state"] == "stopped":
                stopped_endpoints[side] = {key: power[key] for key in ("controllerId", "checkedAt")}
        if stopped_endpoints:
            row["stoppedEndpoints"] = stopped_endpoints
        gaps = []
        if row.get("missingPortSides"):
            gaps.append("missing_port_name")
        logical_interfaces = {}
        for side, observer in (("a", "b"), ("b", "a")):
            if side not in row.get("missingPortSides", []):
                continue
            readings = {(peer["portId"], peer["checkedAt"]) for peer in row.get("lldpPeers", {}).get(observer, [])
                        if peer.get("portIdSubtype") == "interface_name"
                        and re.fullmatch(r"bond[0-9]+", peer.get("portId", ""), re.IGNORECASE)}
            if readings:
                logical_interfaces[side] = [{"name": name, "checkedAt": stamp} for name, stamp in sorted(readings)]
        if logical_interfaces:
            row["logicalPeerInterfaces"] = logical_interfaces
            gaps.append("logical_lldp_interface")
        silent_sides = []
        for side, port in ports.items():
            lldp = port.get("lldpPort", {})
            if (port["state"] == "up" and lldp.get("admin") in {"rx_only", "tx_rx"}
                    and lldp.get("delta", {}).get("rxFrames") == 0):
                silent_sides.append(side)
        if silent_sides:
            row["lldpNoRxSides"] = sorted(silent_sides)
            gaps.append("no_lldp_rx")
        if row.get("archivedPortSides"):
            gaps.append("archived_port")
        if row.get("sharedPort"):
            gaps.append("shared_switch_port")
        if row.get("multiMacPortSides"):
            gaps.append("multiple_learned_macs")
        if not row["observedPaths"] and not row.get("identifiedPeerSides"):
            gaps.append("no_live_peer_identity")
        if stopped_endpoints:
            gaps.append("endpoint_powered_off")
        if row.get("conflictingPortSides"):
            gaps.append("conflicting_port_pairs")
        row["confirmationGaps"] = gaps or ["physical_pair_unconfirmed"]
    return counts, inventory_pairs, alerts, [pending[key] for key in sorted(pending)], verified_pairs


def _lacp_partner_interface_gaps(nodes: dict) -> list[dict]:
    return [
        {"id": node["id"], "name": node["name"], "switchId": report["switchId"],
         "aggregate": report["aggregate"], "switchPort": member["name"],
         "partnerPort": member["partnerPort"], "checkedAt": member["checkedAt"]}
        for node in nodes.values() for report in node.get("lacpHealth", []) for member in report["members"]
        if member.get("partnerInterfaceState") == "unconfirmed"
    ]


def _summarize_shared_ports(pending: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for row in pending:
        switch_id, peer = row["a"], row["b"]
        port = port_label_key(row["portA"])
        fdb_readings = [
            path for path in row["observedPaths"]
            if path["source"] == "netctl FDB" and path["checkedAt"]
            and port_label_key(path.get("portA", "")) == port
            and path.get("learnedEndpoint", {}).get("switchId") == switch_id
            and path["learnedEndpoint"].get("deviceId") == peer
        ]
        if row.get("sharedPort") or fdb_readings:
            groups[switch_id, port].append((row, fdb_readings))
    result = []
    for (switch_id, _), rows in sorted(groups.items()):
        observations = {}
        for row, fdb_readings in rows:
            peer = row["b"]
            observation = observations.setdefault(peer, {"id": peer, "name": row["nameB"]})
            readings = {
                "fdbCheckedAt": (path["checkedAt"] for path in fdb_readings),
                "lldpCheckedAt": (path["checkedAt"] for path in row["observedPaths"]
                                  if path["source"] == SHARED_LLDP_SOURCE),
                "lldpCandidateCheckedAt": (candidate["checkedAt"] for candidate in row.get("unconfirmedLldpCandidates", [])),
            }
            for key, stamps in readings.items():
                if latest := max((stamp for stamp in stamps if stamp), default=""):
                    observation[key] = max(latest, observation.get(key, ""))
            values = {"fdbMacs": {path["learnedEndpoint"]["mac"] for path in fdb_readings
                                  if path["learnedEndpoint"].get("mac")}}
            for prefix, advertisements in (
                ("lldp", row.get("lldpPeers", {}).get("a", [])),
                ("lldpCandidate", row.get("unconfirmedLldpCandidates", [])),
            ):
                values[prefix + "PortIds"] = {item["portId"] for item in advertisements
                                              if item.get("portIdSubtype") == "interface_name" and item.get("portId")}
                values[prefix + "ChassisMacs"] = {item["chassisId"] for item in advertisements
                                                  if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",
                                                                  item.get("chassisId", ""))}
            for key, entries in values.items():
                if entries:
                    observation[key] = sorted(entries.union(observation.get(key, [])))[:8]
        peers = sorted(observations)
        lldp_peers = [peer for peer in peers if "lldpCheckedAt" in observations[peer]]
        fdb_peers = [peer for peer in peers if "fdbCheckedAt" in observations[peer]]
        if len(fdb_peers) < 2 and not any(row.get("sharedPort") for row, _ in rows):
            continue
        result.append({"switchId": switch_id, "port": rows[0][0]["portA"], "peerTotal": len(peers),
                       "peerIds": peers[:64], "liveLldpPeerIds": lldp_peers[:64], "liveFdbPeerIds": fdb_peers[:64],
                       "peerObservations": [observations[peer] for peer in peers[:64]]})
    return result


def _summarize_pair_measurement_gaps(pairs: list[dict]) -> dict:
    gaps = []
    for pair in pairs:
        missing = sorted({"a", "b"} - pair.get("portStates", {}).keys())
        if missing:
            gaps.append({**{key: pair[key] for key in ("a", "b", "portA", "portB")}, "missingSides": missing})
    return {"currentPairMeasurementGapTotal": len(gaps), "currentPairMeasurementGaps": gaps[:64]}


def summarize_topology(graph: dict, *, node_id: str | None = None, port_name: str | None = None) -> dict:
    nodes = {node["id"]: node for node in graph["nodes"]}
    topology_pairs = _topology_port_pairs(nodes, graph["links"])
    counts, inventory_pairs, alerts, pending, current_pairs = topology_pairs
    port_aliases = {
        (node["id"], port_label_key(alias)): port_label_key(port["name"])
        for node in nodes.values() for port in node["ports"] for alias in port.get("aliases", [])
    }

    def pair_key(row):
        ends = [(row[side], port_label_key(row[field])) for side, field in (("a", "portA"), ("b", "portB"))]
        return tuple(sorted((device, port_aliases.get((device, port), port)) for device, port in ends))

    current_keys = {pair_key(row) for row in current_pairs}
    inventory_by_key = {pair_key(row): row for row in inventory_pairs}
    inventory_only = [row for key, row in inventory_by_key.items() if key not in current_keys]
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    lacp_gaps = _lacp_partner_interface_gaps(nodes)
    lacp = [{"id": node["id"], "name": node["name"], **report}
            for node in nodes.values() for report in node.get("lacpHealth", [])]
    vlan_audits = [
        {"a": link["a"], "b": link["b"], "portA": report["a"], "portB": report["b"], "vlans": report["vlanAudit"]}
        for link in graph["links"] for report in link["portEvidence"] if report.get("vlanAudit")
    ]
    shared_ports = _summarize_shared_ports(pending)
    downstream = [{"id": node["id"], "name": node["name"], **node["downstream"]}
                  for node in nodes.values() if "downstream" in node]
    if node_id is not None:
        node = nodes.get(node_id)
        keys = {port_label_key(port_name)} if port_name else set()
        ports = []
        for port in node["ports"] if node else []:
            aliases = {port_label_key(label) for label in (port["name"], *port.get("aliases", []))}
            if not port_name or keys & aliases:
                ports.append(port)
                keys.update(aliases)

        def matches(pair):
            return node is not None and any(
                pair[side] == node_id and (not port_name or port_label_key(pair[field]) in keys)
                for side, field in (("a", "portA"), ("b", "portB"))
            )

        current = [row for row in current_pairs if matches(row)]
        archived = [row for row in inventory_only if matches(row)]
        gaps = [row for row in pending if matches(row)]
        stp_related_gaps = [row for row in pending if not matches(row) and (
            any(matches(pair) for pair in row.get("stpBridgeConnections", []))
            or any(observation["switchId"] == node_id
                   and (not port_name or port_label_key(observation["port"]) in keys)
                   for observation in row.get("stpBridgeMacObservations", []))
        )]
        port_alerts = [row for row in alerts if matches(row)]
        partner_gaps = [row for row in lacp_gaps if (
            row["switchId"] == node_id and (not port_name or any(
                port_label_key(row[field]) in keys for field in ("switchPort", "aggregate")
            )) or row["id"] == node_id and not port_name
        )]
        aggregates = [report for report in lacp if (
            report["switchId"] == node_id and (not port_name or port_label_key(report["aggregate"]) in keys
                                               or any(port_label_key(member["name"]) in keys for member in report["members"]))
            or report["id"] == node_id and not port_name
        )]
        attached_guests = []
        uplinks = {}
        if node and node["kind"] in (NETWORK_KINDS[0], "Гипервизор"):
            guests = _guest_attachments(nodes, graph["links"], [key for key, item in nodes.items() if item["guest"]])
            by_switch = _guest_switch_attachments(guests)
            if node["kind"] == "Гипервизор":
                attached_guests = [row for rows in by_switch.values() for row in rows
                                   if row["hypervisor"]["id"] == node_id and (
                                       not port_name or port_label_key(row["physicalPair"]["hostPort"]) in keys)]
                uplinks = _confirmed_guest_uplinks(guests, hypervisor_id=node_id, port_keys=keys if port_name else None)
            else:
                attached_guests = [row for row in by_switch.get(node_id, [])
                                   if not port_name or port_label_key(row["switchPort"]) in keys]
                uplinks = _confirmed_guest_uplinks(guests, switch_id=node_id, port_keys=keys if port_name else None)
        scoped_nodes = {node_id: {**node, "ports": ports}} if node else {}
        return {**metadata, "topologyAudit": {
            "node": _attachment_node(node) if node else None, "portName": port_name, "ports": ports,
            "currentPairTotal": len(current), "currentPairs": current[:64],
            "currentPairLinkCounts": dict(Counter(row["linkHealth"]["state"] for row in current)),
            **_summarize_pair_measurement_gaps(current),
            "inventoryPairs": [row for row in inventory_pairs if matches(row)][:64],
            "inventoryOnlyPairTotal": len(archived), "inventoryOnlyPairs": archived[:64],
            "pendingTotal": len(gaps), "pending": gaps[:64],
            "pendingPairLinkCounts": dict(Counter(row["linkHealth"]["state"] for row in gaps)),
            "confirmationGapCounts": dict(Counter(reason for row in gaps for reason in row["confirmationGaps"])),
            "stpRelatedPendingTotal": len(stp_related_gaps), "stpRelatedPending": stp_related_gaps[:64],
            "portAlertTotal": len(port_alerts), "portAlerts": port_alerts[:64],
            "portCounterAudit": _summarize_port_counters(
                nodes, topology_pairs, port_nodes=scoped_nodes, service_ports=graph.get("servicePorts")),
            "portRxSilenceAudit": _summarize_port_rx_silence(scoped_nodes, pending),
            "vlanAudits": [row for row in vlan_audits if matches(row)][:64],
            "downstreamSwitches": [row for row in downstream if (
                row["id"] == node_id and not port_name or row["upstreamId"] == node_id
                and (not port_name or port_label_key(row["port"]) in keys)
            )][:MAX_DOWNSTREAM_SWITCHES],
            "downstreamDevicesOnPort": [
                device for device in (node or {}).get("downstream", {}).get("devices", [])
                if port_name and port_label_key(device.get("switchPort", {}).get("name", "")) in keys
            ],
            "lacpHealth": aggregates[:64],
            "servicePorts": [row for row in graph.get("servicePorts", {}).get(node_id, [])
                             if not port_name or port_label_key(row["port"]) in keys],
            "guestAttachmentTotal": len(attached_guests), "guestAttachments": attached_guests[:128],
            **uplinks,
            "sharedPorts": [row for row in shared_ports if row["switchId"] == node_id
                            and (not port_name or port_label_key(row["port"]) in keys)][:64],
            "lacpPartnerInterfaceGapTotal": len(partner_gaps), "lacpPartnerInterfaceGaps": partner_gaps[:64],
        }}
    stp = [{"id": node["id"], "name": node["name"], **node["stpRootPath"]}
           for node in nodes.values() if "stpRootPath" in node]
    roots = [{"id": node["id"], "name": node["name"], **node["stpRoot"]}
             for node in nodes.values() if "stpRoot" in node]
    collection_issues = [
        {"id": node["id"], "name": node["name"], "state": check["state"],
         "checkedAt": check["checkedAt"], "stale": check["stale"],
         **{key: check[key] for key in ("reason", "snmpFailures") if key in check}}
        for node in nodes.values() if node["kind"] == NETWORK_KINDS[0]
        for check in node["serviceChecks"] if check["method"] == SNMP_COLLECTION_METHOD and check["state"] != "reachable"
    ]
    return {**metadata, "topologyAudit": {"directLinks": counts, "pendingTotal": len(pending),
                                        "pendingPairLinkCounts": dict(Counter(
                                            row["linkHealth"]["state"] for row in pending)),
                                        "confirmationGapCounts": dict(Counter(
                                            reason for row in pending for reason in row["confirmationGaps"])),
                                        "currentPairTotal": len(current_pairs), "currentPairs": current_pairs[:64],
                                        "currentPairLinkCounts": dict(Counter(
                                            row["linkHealth"]["state"] for row in current_pairs)),
                                        **_summarize_pair_measurement_gaps(current_pairs),
                                        "inventoryPairs": inventory_pairs[:64],
                                        "inventoryOnlyPairTotal": len(inventory_only), "inventoryOnlyPairs": inventory_only[:64],
                                        "portAlertTotal": len(alerts), "portAlerts": alerts[:64],
                                        "portCounterAudit": graph.get("portCounterAudit") or _summarize_port_counters(nodes, topology_pairs),
                                        "portRxSilenceAudit": graph.get("portRxSilenceAudit") or _summarize_port_rx_silence(nodes, pending),
                                        "stpRootPaths": stp, "stpRoots": roots, "vlanAudits": vlan_audits[:64],
                                        "lacpHealth": lacp[:64],
                                        "lacpPartnerInterfaceGapTotal": len(lacp_gaps),
                                        "lacpPartnerInterfaceGaps": lacp_gaps[:64],
                                        "switchCollectionIssueTotal": len(collection_issues),
                                        "switchCollectionIssues": collection_issues[:64],
                                        "downstreamSwitches": downstream[:MAX_DOWNSTREAM_SWITCHES],
                                        "sharedPorts": shared_ports[:64],
                                        "pending": pending[:64]}}


def _attachment_node(node: dict) -> dict:
    return {key: node[key] for key in ("id", "name", "kind", "vmid", "mapStatus", "firmware", "hardwarePower")
            if node.get(key) is not None}


def _guest_ipv4_observations(value: object, now: datetime) -> list[dict]:
    observations = []
    for row in _rows(value, 8):
        address = row.get("address")
        max_age = ROUTE_RECEIPT_MAX_AGE if row.get("source") == "Windows" and row.get("method") == "ARP · DNS" else MAX_AGE
        if not isinstance(address, str) or not observation_is_fresh(row.get("checkedAt"), now, max_age=max_age):
            continue
        try:
            address = str(ipaddress.IPv4Address(address))
        except ValueError:
            continue
        source, method = _text(row.get("source"), 64), _text(row.get("method"), 64)
        if source and method:
            observations.append({"address": address, "checkedAt": _time(row["checkedAt"]).isoformat(),
                                 "source": source, "method": method})
    return observations


def _attach_address_aliases(nodes: dict, links: list[dict]) -> None:
    placements = defaultdict(list)
    for edge in links:
        if (edge["confirmed"] and edge["kind"] == "Размещение ВМ"
                and nodes[edge["a"]]["kind"] == "Гипервизор" and nodes[edge["b"]]["guest"]):
            placements[edge["b"]].append(edge)

    for node_id, node in nodes.items():
        addresses = []
        management = node["properties"].get("Адрес управления")
        if management and "/" not in management:
            addresses.append(management)
        if len(placements.get(node_id, ())) == 1:
            placement, = placements[node_id]
            addresses.extend(reading["address"] for report in placement["portEvidence"] if report["b"]
                             for reading in report.get("virtual", {}).get("ipv4Observations", ()))
        if addresses:
            node["aliases"] = list(dict.fromkeys([*node["aliases"], *addresses]))


def _attachment_vlan_memberships(interface: dict, match: dict, ports: dict, now: datetime) -> dict:
    if (vid := match.get("vlan")) is not None:
        basis = "guest_mac"
    elif (vid := interface.get("vlan")) is not None:
        basis = "configured_tag"
    elif (vid := interface.get("localNeighbor", {}).get("vlan")) is not None:
        basis = "local_neighbor"
    else:
        return {}
    observations = {}
    for side, port in ports.items():
        sample = port.get("vlanMemberships", {})
        if (port.get("state") != "up"
                or not observation_is_fresh(sample.get("checkedAt"), now, max_age=VLAN_AUDIT_MAX_AGE)):
            continue
        reading = next((row for row in sample["vlans"] if row["id"] == vid), None)
        if reading:
            observations[side] = {"egress": reading["egress"], "pvid": reading["pvid"],
                                  "source": port.get("source") or "SNMP", "checkedAt": sample["checkedAt"]}
    return {"id": vid, "basis": basis, "ports": observations} if observations else {}


def _guest_power(node: dict) -> str:
    if node["reachability"]["state"] == "stopped":
        return "stopped"
    proxmox = next((source for source in node["sources"] if source["name"] == "Proxmox" and not source["stale"]), {})
    return {"Запущена": "running", "Выключена": "stopped", "Приостановлена": "paused",
            "Гостевая ОС ещё не запущена": "prelaunch"}.get(proxmox.get("label"), "unknown")


def _guest_attachments(nodes: dict, links: list[dict], guest_ids: list[str], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    placements = defaultdict(list)
    physical = _current_physical_port_pairs(links, include_port_states=True)
    histories = {(node_id, port_label_key(port["name"])): port["history"]
                 for node_id, node in nodes.items() for port in node["ports"] if "history" in port}
    local_neighbors = defaultdict(list)
    selected_guests = set(guest_ids)
    for edge in links:
        if not edge["confirmed"]:
            continue
        a, b = edge["a"], edge["b"]
        if edge["kind"] == "Размещение ВМ" and b in selected_guests and nodes[a]["kind"] == "Гипервизор":
            placements[b].append(edge)
        elif edge["kind"] == "Цель проверки" and a in selected_guests and nodes[b]["kind"] == "Сервис":
            for check in nodes[b]["serviceChecks"]:
                vlan = check.get("vlanTransit", {})
                peer = vlan.get("peer", {})
                if (check["source"] == "UI_VPN" and check["state"] == "reachable" and not check["stale"]
                        and check.get("target") and peer.get("asset") == a and peer.get("state") == "matched"):
                    local_neighbors[a, peer["guestPort"]].append({
                        "vlan": vlan["id"], "interface": vlan["interface"],
                        "peerAddress": check["target"], "checkedAt": check["checkedAt"],
                    })

    guests = {}
    for guest_id in guest_ids:
        candidates = placements[guest_id]
        node = nodes[guest_id]
        guest = {"guest": _attachment_node(node), "hypervisor": None, "interfaces": [], "power": _guest_power(node),
                 "placement": "ambiguous" if len(candidates) > 1 else "unconfirmed"}
        if "backupCoverage" in node:
            guest["backupCoverage"] = node["backupCoverage"]
        guests[guest_id] = guest
        io = node.get("guestIo", {})
        if all(key in io for key in GUEST_NETWORK_RATE_FIELDS):
            guest["networkTraffic"] = {"source": "Proxmox", **{
                key: io[key] for key in (*GUEST_NETWORK_RATE_FIELDS, "checkedAt", "intervalSeconds")
            }}
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
            if "bridgeVlanMode" in virtual:
                interface["bridgeVlanConfig"] = {"mode": virtual["bridgeVlanMode"],
                                                 "source": "Proxmox API", "checkedAt": report["at"]}
            if "vlan" in report:
                interface["vlan"] = report["vlan"]
            if "ipv4Observations" in virtual:
                interface["ipv4Observations"] = virtual["ipv4Observations"]
            if "arpDiagnostic" in virtual:
                interface["arpDiagnostic"] = virtual["arpDiagnostic"]
            neighbors = local_neighbors[guest_id, interface["guestPort"]]
            if len(neighbors) == 1 and not virtual["linkDisabled"] and virtual["bridgeActive"] is True:
                interface["localNeighbor"], = neighbors
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
                    pair = physical.get((switch_id, port_label_key(match["port"])))
                    uplinks = {port_label_key(name) for name in virtual["uplinks"]}
                    if (pair and pair["hostId"] == host_id and nodes[switch_id]["kind"] == NETWORK_KINDS[0]
                            and port_label_key(pair["hostPort"]) in uplinks):
                        observation["physicalPair"] = {
                            field: pair[field] for field in ("hostPort", "switchPort", "source", "checkedAt")
                        }
                        switch_name = pair["portStates"]["switch"].get("name", pair["switchPort"])
                        if history := histories.get((switch_id, port_label_key(switch_name))):
                            observation["switchPortHistory"] = history
                        port_links = {
                            side: {field: port[field] for field in
                                   ("state", "speedBps", "checkedAt", "speedCheckedAt", "source") if field in port}
                            for side, port in pair["portStates"].items() if port.get("state") == "up"
                        }
                        if port_links:
                            observation["uplinkPortLinks"] = port_links
                        comparison = _compare_link_ports({
                            side: port_links[end] for side, end in (("a", "host"), ("b", "switch"))
                            if end in port_links
                        })
                        observation["uplinkLinkHealth"] = comparison or {"state": "unconfirmed"}
                        if vlans := _attachment_vlan_memberships(interface, match, pair["portStates"], now):
                            observation["vlanMemberships"] = vlans
                        if telemetry := pair["portStates"]["switch"].get("telemetry"):
                            observation["switchPortTelemetry"] = telemetry
                interface["switchObservations"].append(observation)
            mac_ports = {(row["switch"]["id"], port_label_key(row["switchPort"])): row["switchPort"]
                         for row in interface["switchObservations"] if row["basis"] == "guest_mac"}
            if len(mac_ports) > 1:
                interface["ambiguousSwitchPorts"] = [{"switchId": switch, "port": label}
                                                     for (switch, _), label in sorted(mac_ports.items())]
    return guests


def _guest_switch_attachments(guests: dict) -> dict:
    attached = defaultdict(list)
    for guest in guests.values():
        for interface in guest["interfaces"]:
            if interface.get("ambiguousSwitchPorts"):
                continue
            for match in interface["switchObservations"]:
                if "physicalPair" in match:
                    attached[match["switch"]["id"]].append({
                        "guest": guest["guest"], "hypervisor": guest["hypervisor"],
                        "guestPort": interface["guestPort"], "bridge": interface["bridge"], **match,
                    })
    return dict(attached)


def _node_link_checks(node: dict) -> list[dict]:
    methods = {"Точка доступа": "MAC ping · L2", "Рабочая станция": "Агент на связи"}
    return [{field: check[field] for field in ("method", "source", "state", "checkedAt")}
            for check in node["serviceChecks"] if check["method"] == methods.get(node["kind"])
            and (check["method"] != "Агент на связи" or check["source"] == "Endpoint Platform")
            and check["checkedAt"] and not check["stale"]]


def _is_current_access_point_pair(switch: dict, device: dict, report: dict, switch_side: str, device_side: str) -> bool:
    return (switch["kind"] == NETWORK_KINDS[0] and device["kind"] == "Точка доступа"
            and report.get("pairEvidence") == "current" and report["source"] == "LLDP UI_VPN"
            and bool(report[switch_side] and report[device_side]))


def _physical_attachments(nodes: dict, links: list[dict], host_ids: list[str]) -> list[dict]:
    if not host_ids:
        return []
    connections = {host_id: [] for host_id in host_ids}
    controllers = defaultdict(dict)
    controller_services = defaultdict(set)
    pending_by_node = defaultdict(list)
    _, inventory_pairs, _, pending, current_pairs = _topology_port_pairs(nodes, links)
    inventory_by_node = defaultdict(list)
    current_by_node = defaultdict(list)
    for pairs, index in ((inventory_pairs, inventory_by_node), (current_pairs, current_by_node)):
        for pair in pairs:
            for side in ("a", "b"):
                index[pair[side]].append(pair)
    for pair in pending:
        for side in ("a", "b"):
            pending_by_node[pair[side]].append(pair)
    for edge in links:
        if (_is_service_attachment(edge) and nodes[edge["a"]]["kind"] == "Контроллер управления"
                and nodes[edge["b"]]["kind"] == "Сервис"):
            controller_services[edge["a"]].add(edge["b"])
        if (edge["kind"] == "Управление оборудованием" and edge["b"] in connections
                and nodes[edge["a"]]["kind"] == "Контроллер управления"):
            candidates = controllers[edge["b"]]
            candidates[edge["a"]] = candidates.get(edge["a"], False) or edge["confirmed"]
        direct = edge["kind"] == "Сетевое соединение"
        if not direct and (edge["kind"] not in ("Путь по MAC-таблице", "Транзитный сегмент", SHARED_LLDP_KIND)
                           or not edge["confirmed"]):
            continue
        for host_side, peer_side in (("a", "b"), ("b", "a")):
            host_id, peer = edge[host_side], nodes[edge[peer_side]]
            if host_id not in connections or peer["guest"] or peer["kind"] in ("Сервис", CLUSTER_KIND):
                continue
            readings = []
            for report in edge["portEvidence"]:
                if not direct and not report["confirmed"]:
                    continue
                reading = {"hostPort": report[host_side], "peerPort": report[peer_side], "source": report["source"],
                           "checkedAt": report["at"], "confirmed": report["confirmed"]}
                reading.update({key: report[key] for key in ("pairEvidence", "learnedEndpoint", "inventorySources", "windowsAdapter")
                                if key in report})
                sides = {host_side: "host", peer_side: "peer"}
                if conflict := report.get("conflictingPortSides"):
                    reading["conflictingPortSides"] = [sides[side] for side in conflict]
                if port_states := report.get("portStates"):
                    reading["portStates"] = {
                        sides[side]: {key: state[key] for key in ("name", "state", "speedBps", "checkedAt",
                                                                "stale", "source", "configuredLabel", "linkMode", "rxSilence",
                                                                "transceiver", "lldpPort", "endpointMac",
                                                                "telemetry", "rxErrorCounters", "fdbLearned")
                                      if key in state}
                        for side, state in port_states.items()
                    }
                if lldp_peers := report.get("lldpPeers"):
                    reading["lldpPeers"] = {sides[side]: value for side, value in lldp_peers.items()}
                if direct and edge["confirmed"]:
                    for switch_side, device_side in ((host_side, peer_side), (peer_side, host_side)):
                        device = nodes[edge[device_side]]
                        if (_is_current_access_point_pair(nodes[edge[switch_side]], device, report, switch_side, device_side)
                                and (checks := _node_link_checks(device))):
                            reading["linkChecks"] = [{"nodeId": device["id"], **check} for check in checks]
                            break
                if lacp := report.get("lacp"):
                    reading["lacp"] = {"side": sides[lacp["side"]],
                                       **{key: lacp[key] for key in ("aggregate", "member", "partnerPort", "polledAt",
                                                                      "partnerInterfaceState", "aggregateState")
                                          if key in lacp}}
                readings.append(reading)
            connections[host_id].append({"peer": _attachment_node(peer), "kind": edge["kind"],
                                         "confirmed": edge["confirmed"], "ports": readings})
    for group in connections.values():
        group.sort(key=lambda row: (row["kind"] != "Сетевое соединение", not row["confirmed"], row["peer"]["id"]))
    observed_ports = _observed_management_ports(links, nodes) if controllers else {}

    def port_pairs(node_id):
        current = current_by_node[node_id]
        inventory = inventory_by_node[node_id]
        open_pairs = pending_by_node[node_id]
        return {"currentPortPairTotal": len(current), "currentPortPairs": current[:24],
                "inventoryPairTotal": len(inventory), "inventoryPairs": inventory[:24],
                "pendingPortPairTotal": len(open_pairs), "pendingPortPairs": open_pairs[:24]}

    return [{"host": _attachment_node(nodes[host_id]), "connectionTotal": len(group), "connections": group[:24],
             **port_pairs(host_id),
             **({"managementControllers": [
                 {"node": _attachment_node(nodes[controller]), "confirmed": confirmed,
                  **({"managementPortErrors": errors}
                     if (errors := nodes[controller].get("managementPortErrors")) else {}),
                  "servicePaths": _management_service_paths(nodes[controller], controller, {}, observed_ports),
                  "serviceTotal": len(controller_services[controller]),
                  "services": [{"node": _attachment_node(nodes[service]),
                                "serviceChecks": nodes[service]["serviceChecks"]}
                               for service in sorted(controller_services[controller])[:12]],
                  **port_pairs(controller)}
                 for controller, confirmed in sorted(controllers[host_id].items(), key=lambda item: (not item[1], item[0]))[:12]
             ]} if host_id in controllers else {}),
             **({"lacpHealth": nodes[host_id]["lacpHealth"]} if "lacpHealth" in nodes[host_id] else {})}
            for host_id, group in connections.items()]


def _attachment_service_checks(service: dict):
    listener_ports = {check["configuredPort"] for check in service["serviceChecks"]
                        if check["method"] == "OpenVPN UDP-сокет" and check["source"] == "UI_VPN"
                        and "configuredPort" in check}
    for check in service["serviceChecks"]:
        yield check
        socket = check.get("localUdpSocket", {})
        port = check.get("configuredPort")
        if check["source"] != "UI_VPN" or port is None or socket.get("state") != "bound":
            continue
        if (check["method"] == "OpenVPN UDP-сокет" and check["state"] == "reachable"
                or check["method"] == "OpenVPN Management" and port not in listener_ports):
            listener = {**check, "port": port, "state": "reachable",
                        "method": "Локальный UDP-сокет", "localListener": True}
            listener.pop("reason", None)
            for address in dict.fromkeys(socket["addresses"]):
                if address not in ("*", "0.0.0.0", "::"):
                    yield {**listener, "target": address}


def _attachment_probe_location(check: dict) -> dict:
    return {"target": check["target"], "port": check["port"], "method": check["method"],
            "checkedAt": check["checkedAt"], "state": check["state"],
            **({"path": check["path"]} if check.get("path") else {}),
            **{key: check[key] for key in ("reason", "errorSource", "roundTripMs", "httpStatus", "responseCode", "rtspStatus", "dns", "ntp",
                                           "rdpSecurity", "rdpFailureCode", "tlsExpiresAt", "tlsVersion", "zabbixVersion",
                                           "smbDialect", "smbSigningRequired", "postgresqlTls", "redfishVersion", "ftpReply",
                                           "sshTcpConnected", "localRoute", "httpAuthChallenge")
               if key in check}}


def _windows_client_attachments(nodes: dict, links: list[dict]) -> dict:
    stations = defaultdict(set)
    pairs = defaultdict(lambda: defaultdict(dict))
    for edge in links:
        if not edge["confirmed"]:
            continue
        a, b = edge["a"], edge["b"]
        if (edge["kind"] == "Источник проверки" and nodes[a]["kind"] == "Рабочая станция"
                and nodes[b]["kind"] == "Сервис"):
            stations[b].add(a)
        if edge["kind"] != "Сетевое соединение":
            continue
        for station_side, switch_side in (("a", "b"), ("b", "a")):
            station, switch = edge[station_side], edge[switch_side]
            if nodes[station]["kind"] != "Рабочая станция" or nodes[switch]["kind"] != NETWORK_KINDS[0]:
                continue
            for report in edge["portEvidence"]:
                adapter = report.get("windowsAdapter")
                if report.get("pairEvidence") != "current" or report["source"] != ENDPOINT_PAIR_SOURCE or not adapter:
                    continue
                station_port, switch_port = report[station_side], report[switch_side]
                key = (station_port, switch, switch_port, adapter["ifIndex"])
                candidates = pairs[station][adapter["checkedAt"]]
                if key not in candidates or report["at"] > candidates[key]["checkedAt"]:
                    candidates[key] = {"stationId": station, "stationPort": station_port, "switchId": switch,
                                       "switchPort": switch_port, "source": ENDPOINT_PAIR_SOURCE, "checkedAt": report["at"]}
    return {service: {stamp: next(iter(candidates.values())) for stamp, candidates in pairs[next(iter(sources))].items()
                      if len(candidates) == 1}
            for service, sources in stations.items() if len(sources) == 1}


def _service_attachment_paths(service: dict, guests: dict, client_attachments: dict | None = None) -> list[dict]:
    addresses = defaultdict(list)
    neighbors = defaultdict(list)
    for guest in guests.values():
        for adapter in guest["interfaces"]:
            if adapter["linkDisabled"] or adapter["bridgeActive"] is not True:
                continue
            observed = {}
            for reading in adapter.get("ipv4Observations", []):
                ip, checked_at = reading["address"], reading["checkedAt"]
                observed[ip] = max(observed.get(ip, checked_at), checked_at)
            for ip, checked_at in observed.items():
                addresses[ip].append((guest, adapter, checked_at))
            if neighbor := adapter.get("localNeighbor"):
                key = (neighbor["peerAddress"], guest["guest"]["id"], adapter["guestPort"],
                       neighbor["vlan"], neighbor["interface"])
                neighbors[key].append((guest, adapter, neighbor["checkedAt"]))

    paths = []
    for check in _attachment_service_checks(service):
        windows_dns = check["source"] == WINDOWS_PROBE_SOURCE and check["method"] == "DNS" and check.get("required")
        windows = windows_dns or (check["source"] == WINDOWS_PROBE_SOURCE and check["method"] == "HTTP"
                                  and check.get("supplemental"))
        if (not (check["source"] == "UI_VPN" or windows) or not check["checkedAt"]
                or check["stale"] or check.get("skipped") or (windows and check["state"] == "unknown")):
            continue
        target = check.get("target")
        client = (client_attachments or {}).get(check["checkedAt"]) if windows else None
        path = _attachment_probe_location(check)
        if windows:
            path["source"] = WINDOWS_PROBE_SOURCE
            if check.get("via"):
                path["via"] = check["via"]
        if client:
            path["clientAttachment"] = client
        client_only = windows_dns and target and client is not None
        if client_only:
            paths.append(path)
        vlan = check.get("vlanTransit")
        gateway = None
        if vlan:
            peer = vlan.get("peer", {})
            if peer.get("state") != "matched":
                continue
            candidates = neighbors.get((target, peer["asset"], peer["guestPort"], vlan["id"], vlan["interface"]), [])
        else:
            route = check.get("localRoute", {})
            next_hop = route.get("gateway")
            if (target and next_hop and next_hop != target
                    and route.get("state") == "reachable" and next_hop == route.get("expectedGateway")
                    and route.get("sourceIP") and route.get("interface")):
                gateway = next_hop
            candidates = addresses.get(gateway or target, [])
        if len(candidates) != 1:
            continue
        guest, adapter, address_at = candidates[0]
        if adapter.get("ambiguousSwitchPorts"):
            continue
        if check.get("localListener"):
            local = [reading["checkedAt"] for reading in adapter.get("ipv4Observations", [])
                     if reading["address"] == target and reading["source"] == "UI_VPN"
                     and reading["method"].startswith("Локальный интерфейс ")]
            if not local:
                continue
            address_at = max(local)
        bases = {"guest_mac", "bridge_uplink"} if vlan else {"guest_mac"}
        observations = [row for row in adapter["switchObservations"]
                        if row["basis"] in bases and "physicalPair" in row]
        if len(observations) != 1:
            continue
        observation, = observations
        if telemetry := observation.get("switchPortTelemetry"):
            path["switchPortTelemetry"] = telemetry
        if history := observation.get("switchPortHistory"):
            path["switchPortHistory"] = history
        if port_links := observation.get("uplinkPortLinks"):
            path["uplinkPortLinks"] = port_links
        path["uplinkLinkHealth"] = observation["uplinkLinkHealth"]
        path.update({"addressCheckedAt": address_at,
                      "guestId": guest["guest"]["id"], "guestPort": adapter["guestPort"], "bridge": adapter["bridge"],
                      "hypervisorId": guest["hypervisor"]["id"], "switchId": observation["switch"]["id"],
                      "physicalPair": observation["physicalPair"],
                      **({"destinationVlan": observation["vlanMemberships"]}
                         if gateway is None and vlan is None and "vlanMemberships" in observation else {}),
                      **({"localListener": True} if check.get("localListener") else {}),
                      **({"localNeighbor": adapter["localNeighbor"]} if vlan else {}),
                      **({"gateway": gateway} if gateway else {})})
        if not client_only:
            paths.append(path)
    return paths


def _is_service_attachment(edge: dict) -> bool:
    return edge["confirmed"] and edge["kind"] in {"Размещение", "Цель проверки"}


def _management_port_paths(nodes: dict, links: list[dict]) -> dict:
    paths = defaultdict(dict)
    physical = {}
    for edge in links:
        if (not edge["confirmed"] or {nodes[edge["a"]]["kind"], nodes[edge["b"]]["kind"]}
                != {"Гипервизор", NETWORK_KINDS[0]}):
            continue
        host_side = "a" if nodes[edge["a"]]["kind"] == "Гипервизор" else "b"
        switch_side = "b" if host_side == "a" else "a"
        host, switch = edge[host_side], edge[switch_side]
        for report in edge["portEvidence"]:
            key = (switch, report[host_side], report[switch_side])
            if report.get("pairEvidence") == "current":
                physical_key = (host, key)
                physical[physical_key] = max(physical.get(physical_key, report["at"]), report["at"])
            if not report["confirmed"] or not (address := report.get("managementAddress")):
                continue
            pair = paths[host, address]
            if key not in pair or pair[key]["checkedAt"] < report["at"]:
                pair[key] = {"hostPort": key[1], "switchPort": key[2], "source": report["source"], "checkedAt": report["at"]}
    confirmed = {}
    for (host, address), pairs in paths.items():
        if len(pairs) != 1:
            continue
        (key, pair), = pairs.items()
        if physical_at := physical.get((host, key)):
            confirmed[host, address] = (key[0], {**pair, "checkedAt": min(pair["checkedAt"], physical_at)})
    return confirmed


def _current_physical_port_pairs(links: list[dict], *, include_port_states: bool = False) -> dict:
    peers = defaultdict(dict)
    for edge in links:
        if edge["kind"] != "Сетевое соединение" or not edge["confirmed"]:
            continue
        for report in edge["portEvidence"]:
            if (not report["confirmed"] or report.get("pairEvidence") != "current" or report["source"] == "SNMP LACP + ARP"
                    or any(port["state"] in {"down", "disabled"} for port in report.get("portStates", {}).values())):
                continue
            for local, remote in (("a", "b"), ("b", "a")):
                endpoint = (edge[local], port_label_key(report[local]))
                peer = (edge[remote], port_label_key(report[remote]))
                previous = peers[endpoint].get(peer)
                if previous is None or report["at"] > previous["checkedAt"]:
                    pair = {"hostId": edge[remote], "hostPort": report[remote],
                            "switchPort": report[local], "source": report["source"], "checkedAt": report["at"]}
                    if include_port_states:
                        states = report.get("portStates", {})
                        pair["portStates"] = {"host": states.get(remote, {}), "switch": states.get(local, {})}
                    peers[endpoint][peer] = pair
    return {endpoint: next(iter(choices.values())) for endpoint, choices in peers.items()
            if len(choices) == 1 and len(peers[next(iter(choices))]) == 1}


def _attach_management_vlan_observations(nodes: dict, links: list[dict], now: datetime) -> None:
    physical = _current_physical_port_pairs(links)
    observations = defaultdict(dict)
    for edge in links:
        if not edge["confirmed"] or edge["kind"] not in {"Сетевое соединение", "Путь по MAC-таблице"}:
            continue
        for report in edge["portEvidence"]:
            if (not report["confirmed"] or not (address := report.get("managementAddress"))
                    or report["source"] != "netctl FDB + Proxmox" or not (vlan := report.get("vlan"))
                    or not observation_is_fresh(report["at"], now, max_age=VLAN_AUDIT_MAX_AGE)):
                continue
            side, peer = ("a", "b") if nodes[edge["a"]]["kind"] == NETWORK_KINDS[0] else ("b", "a")
            key = edge[side], port_label_key(report[side])
            pair = physical.get(key)
            if not pair or pair["hostId"] != edge[peer] or port_label_key(pair["hostPort"]) != port_label_key(report[peer]):
                continue
            stamps = observations[*key, vlan]
            stamps[address] = max(stamps.get(address, ""), report["at"])
    if not observations:
        return
    for edge in links:
        side, peer = ("a", "b") if nodes[edge["a"]]["kind"] == NETWORK_KINDS[0] else ("b", "a")
        for report in edge["portEvidence"]:
            for vlan in report.get("vlanAudit", []):
                key = edge[side], port_label_key(report[side])
                candidates = observations.get((*key, vlan["id"]), {})
                pair = physical.get(key)
                if (len(candidates) == 1 and pair and pair["hostId"] == edge[peer]
                        and port_label_key(pair["hostPort"]) == port_label_key(report[peer])):
                    (address, checked_at), = candidates.items()
                    vlan["managementObservation"] = {"address": address, "switchSide": side, "checkedAt": checked_at}


def _observed_management_ports(links: list[dict], nodes: dict) -> dict:
    candidates = defaultdict(dict)
    physical = _current_physical_port_pairs(links)
    histories = {(node_id, port_label_key(port["name"])): port["history"]
                 for node_id, node in nodes.items() if node["kind"] == NETWORK_KINDS[0]
                 for port in node["ports"] if "history" in port}
    for edge in links:
        if edge["kind"] not in {"Путь по MAC-таблице", "Транзитный сегмент", "Сетевое соединение"} or not edge["confirmed"]:
            continue
        for report in edge["portEvidence"]:
            address = report.get("managementAddress")
            if not report["confirmed"] or not address:
                continue
            if lacp := report.get("lacp"):
                state = lacp.get("aggregateState", {})
                if state.get("state") != "up" or state["stale"]:
                    continue
                switch = edge[lacp["side"]]
                host = edge["b" if lacp["side"] == "a" else "a"]
                aggregate = lacp["aggregate"]
                health = next((row for row in nodes[host].get("lacpHealth", [])
                               if row["switchId"] == switch and port_label_key(row["aggregate"]) == port_label_key(aggregate)), {})
                members = [member for member in health.get("members", []) if member["status"] == "forwarding"]
                if not any(port_label_key(member["name"]) == port_label_key(lacp["member"])
                           and member["partnerPort"] == lacp["partnerPort"] for member in members):
                    continue
                key = switch, port_label_key(aggregate), "lacp"
                paths = candidates[host, address]
                previous = paths.get(key, {}).get("lacpAttachment", {})
                if report["at"] > previous.get("checkedAt", ""):
                    paths[key] = {"lacpAttachment": {"switchId": switch, "aggregate": aggregate,
                                                    "checkedAt": report["at"], "source": report["source"],
                                                    "members": members, "aggregateState": state}}
                continue
            if edge["kind"] == "Сетевое соединение":
                continue
            if report["source"] in {"MikroTik · ARP", "MikroTik · ARP + FDB"}:
                side, field, id_key = "a", "routerAttachment", "routerId"
            elif (endpoint := report.get("learnedEndpoint")) and report["source"] == "netctl FDB":
                side = "a" if edge["a"] == endpoint["switchId"] else "b"
                field, id_key = "switchAttachment", "switchId"
            else:
                continue
            port_state = report.get("portStates", {}).get(side, {})
            if port_state.get("state") != "up":
                continue
            device, port = edge[side], report[side]
            host = edge["b" if side == "a" else "a"]
            ports = candidates[host, address]
            key = (device, port_label_key(port))
            if key not in ports or ports[key][field]["checkedAt"] < report["at"]:
                attachment = {id_key: device, "port": port, "source": report["source"], "checkedAt": report["at"]}
                attachment["portLink"] = {key: port_state[key] for key in
                                          ("state", "speedBps", "checkedAt", "speedCheckedAt", "source", "linkMode")
                                          if key in port_state}
                if telemetry := port_state.get("telemetry"):
                    attachment["telemetry"] = telemetry
                if field == "routerAttachment":
                    if not report["b"] and (archived := _archived_router_peer(edge)):
                        attachment["archivedPeer"] = archived
                if field == "switchAttachment":
                    if history := histories.get((device, port_label_key(port_state["name"]))):
                        attachment["history"] = history
                    if counters := port_state.get("rxErrorCounters"):
                        attachment["rxErrorCounters"] = counters
                    peers = [peer for peer in report.get("lldpPeers", {}).get(side, [])
                             if peer.get("chassisId") == endpoint["mac"] and peer.get("portId")]
                    if peers:
                        attachment["lldpPeers"] = peers
                pair = physical.get(key)
                if field == "switchAttachment" and pair and pair["hostId"] == host:
                    attachment["physicalPair"] = pair
                ports[key] = {field: attachment}
    return {key: next(iter(ports.values())) for key, ports in candidates.items() if len(ports) == 1}


def _attach_management_ports(nodes: dict, links: list[dict]) -> None:
    paths = defaultdict(list)
    for (host, address), path in sorted(_observed_management_ports(links, nodes).items()):
        if attachment := path.get("routerAttachment"):
            router_paths = nodes[host].setdefault("managementRouterPaths", [])
            if len(router_paths) < 16:
                router_paths.append({"address": address, **attachment})
        if attachment := path.get("switchAttachment"):
            paths[host].append(attachment)
    for host, attachments in paths.items():
        if len(attachments) != 1:
            continue
        attachment, = attachments
        node = nodes[host]
        location = {key: attachment[key] for key in ("switchId", "port", "source", "checkedAt")}
        node["managementSwitchPort"] = {**location, **{
            key: attachment[key] for key in ("portLink", "physicalPair") if key in attachment
        }}
        telemetry = attachment.get("telemetry", {})
        if node["kind"] != "Контроллер управления" or not (telemetry.get("rxErrors") or telemetry.get("txErrors")):
            continue
        switch = attachment["switchId"]
        label = port_label_key(attachment["port"])
        ports = [port for port in nodes[switch]["ports"] if label in {
            port_label_key(name) for name in [port["name"], *port.get("aliases", [])]
        }]
        if len(ports) != 1:
            continue
        learned = ports[0].get("fdbLearned", {})
        if (learned.get("partial") is False and learned.get("learnedMacCount") == 1
                and learned.get("checkedAt") == telemetry["checkedAt"]
                and abs(_time(attachment["checkedAt"]) - _time(telemetry["checkedAt"])) <= timedelta(seconds=30)):
            node["managementPortErrors"] = {**location, "telemetry": telemetry}
            if counters := attachment.get("rxErrorCounters"):
                node["managementPortErrors"]["rxErrorCounters"] = counters
            if history := ports[0].get("history"):
                node["managementPortErrors"]["history"] = history


def _management_service_paths(service: dict, host: str, management: dict, observed_ports: dict,
                              nodes: dict | None = None) -> list[dict]:
    paths = []
    for check in service["serviceChecks"]:
        if not check["checkedAt"] or check["stale"] or check.get("skipped"):
            continue
        if (nodes is not None and check["method"] == "Маршрут" and check["source"] == "Network Observer"
                and check["state"] == "reachable" and check.get("routeSource")):
            router = observed_ports.get((host, check["via"]), {}).get("routerAttachment")
            if router and nodes[router["routerId"]]["properties"].get("Источник сбора") == check["routeSource"]:
                paths.append({**_attachment_probe_location(check), "via": check["via"], "source": check["source"],
                              "addressCheckedAt": router["checkedAt"], "routerAttachment": router})
            continue
        if check["source"] != "UI_VPN":
            continue
        if matched := management.get((host, check["target"])):
            switch, pair = matched
            paths.append({**_attachment_probe_location(check), "addressCheckedAt": pair["checkedAt"],
                          "management": True, "hypervisorId": host, "switchId": switch, "physicalPair": pair})
        elif attachment := observed_ports.get((host, check["target"])):
            observation, = attachment.values()
            asset_icmp = (service["kind"] != "Сервис" and check["method"] == "ICMP · ARP + FDB"
                          and observation["source"] == "netctl FDB"
                          and check.get("identityCheckedAt") == observation["checkedAt"])
            service_probe = service["kind"] == "Сервис" and (
                check["port"] is not None or (check["method"] == "ICMP" and observation["source"] == "MikroTik · ARP")
            )
            if asset_icmp or service_probe:
                paths.append({**_attachment_probe_location(check), "addressCheckedAt": observation["checkedAt"],
                              **attachment})
    return paths


def _transit_service_paths(service: dict, hosts: set, observed_ports: dict) -> list[dict]:
    if len(hosts) != 2 or not service["id"].startswith("transit:"):
        return []
    return [path for host in sorted(hosts) for path in _management_service_paths(service, host, {}, observed_ports)
            if (router := path.get("routerAttachment")) and router["source"] == "MikroTik · ARP"
            and router["routerId"] in hosts - {host}]


def _physical_service_port_evidence(nodes: dict, links: list[dict]) -> dict:
    evidence = defaultdict(set)
    for edge in links:
        if not edge["confirmed"]:
            continue
        for report in edge["portEvidence"]:
            endpoint = report.get("learnedEndpoint")
            if not endpoint or not report["confirmed"]:
                continue
            switch, host = endpoint["switchId"], endpoint["deviceId"]
            side = "a" if edge["a"] == switch else "b"
            port = report[side]
            if port and not nodes[host]["guest"]:
                evidence[host].add((switch, port, "host_mac"))
    for host, node in nodes.items():
        for aggregate in node.get("lacpHealth", []):
            switch, name = aggregate["switchId"], aggregate["aggregate"]
            forwarding = [member["name"] for member in aggregate["members"] if member["status"] == "forwarding"]
            evidence[host].update((switch, member, "host_lacp") for member in forwarding)
            if forwarding and any(port_label_key(port["name"]) == port_label_key(name)
                                  and port["state"] == "up" and not port["stale"]
                                  for port in nodes[switch]["ports"]):
                evidence[host].add((switch, name, "host_lacp"))
    return evidence


def _map_attachments(nodes: dict, links: list[dict], now: datetime, *, endpoint_keys: dict[str, str] | None = None) -> dict:
    guests = _guest_attachments(nodes, links, [key for key, node in nodes.items() if node["guest"]], now)
    service_hosts = defaultdict(set)
    service_guests = defaultdict(dict)
    for edge in links:
        host, service = edge["a"], edge["b"]
        if nodes[service]["kind"] == "Сервис" and _is_service_attachment(edge):
            service_hosts[service].add(host)
            if host in guests:
                service_guests[service][host] = guests[host]
    client_attachments = _windows_client_attachments(nodes, links)
    service_paths = {
        service: paths for service, targets in service_guests.items()
        if len(targets) <= 12 and (paths := _service_attachment_paths(nodes[service], targets, client_attachments.get(service)))
    }
    management = _management_port_paths(nodes, links)
    observed_ports = _observed_management_ports(links, nodes)
    for service, hosts in service_hosts.items():
        if len(hosts) == 1:
            host, = hosts
            if paths := _management_service_paths(nodes[service], host, management, observed_ports, nodes):
                service_paths[service] = paths
        elif paths := _transit_service_paths(nodes[service], hosts, observed_ports):
            service_paths[service] = paths
    for node_id in sorted({host for host, _ in observed_ports}):
        if paths := _management_service_paths(nodes[node_id], node_id, {}, observed_ports):
            service_paths[node_id] = paths
    port_services = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    port_names = {}
    path_checks = defaultdict(set)
    link_checks = {key: checks for key, node in nodes.items() if (checks := _node_link_checks(node))}

    def check_key(check):
        dns = check.get("dns", {})
        return (check.get("target"), check.get("port"), check["method"], check.get("path") or "", check["checkedAt"],
                dns.get("transport", ""), dns.get("name", ""), dns.get("record", ""))

    def record(switch, port, service, basis):
        key = port_label_key(port)
        port_names.setdefault((switch, key), port)
        port_services[switch][key][service].add(basis)

    for edge in links:
        if not edge["confirmed"] or edge["kind"] != "Сетевое соединение":
            continue
        for side, peer in (("a", "b"), ("b", "a")):
            switch, device = edge[side], edge[peer]
            if nodes[switch]["kind"] != NETWORK_KINDS[0] or not link_checks.get(device):
                continue
            for report in edge["portEvidence"]:
                if _is_current_access_point_pair(nodes[switch], nodes[device], report, side, peer):
                    record(switch, report[side], device, "lldp_peer")
                if report.get("pairEvidence") not in ("current", "verified_inventory") or not endpoint_keys:
                    continue
                port_state = report.get("portStates", {}).get(side, {})
                endpoint = port_state.get("endpointMac", {})
                if (nodes[device]["kind"] == "Рабочая станция" and endpoint.get("deviceId") == device
                        and endpoint_keys.get(device, "").lower() == "mac:" + endpoint["mac"]
                        and port_state["state"] == "up" and not port_state["stale"]):
                    record(switch, report[side], device, "endpoint_mac")

    for service, paths in service_paths.items():
        for path in paths:
            if attachment := path.get("routerAttachment"):
                router, port = attachment["routerId"], attachment["port"]
                record(router, port, service, "router_arp" if attachment["source"] == "MikroTik · ARP" else "router_mac")
                path_checks[router, port_label_key(port), service].add(check_key(path))
                continue
            if attachment := path.get("switchAttachment"):
                switch, port = attachment["switchId"], attachment["port"]
                record(switch, port, service, "switch_mac")
                path_checks[switch, port_label_key(port), service].add(check_key(path))
                continue
            if attachment := path.get("lacpAttachment"):
                switch = attachment["switchId"]
                for port in [attachment["aggregate"], *(member["name"] for member in attachment["members"])]:
                    record(switch, port, service, "host_lacp")
                    path_checks[switch, port_label_key(port), service].add(check_key(path))
                continue
            if "physicalPair" not in path:
                continue
            if path.get("management"):
                basis = "host_management"
            elif path.get("gateway"):
                basis = "guest_gateway"
            elif path.get("localListener"):
                basis = "guest_local_udp"
            else:
                basis = "guest_path"
            switch, port = path["switchId"], path["physicalPair"]["switchPort"]
            record(switch, port, service, basis)
            path_checks[switch, port_label_key(port), service].add(check_key(path))
    evidence = _physical_service_port_evidence(nodes, links)
    for service, hosts in service_hosts.items():
        if len(hosts) == 1:
            host, = hosts
            for switch, port, basis in sorted(evidence.get(host, ())):
                record(switch, port, service, basis)

    def service_row(switch, port, key, bases):
        node = nodes[key]
        backup_checks = {}
        if key == BACKUP_SERVICE_ID:
            states = Counter(
                "unknown" if check["stale"] else check["state"]
                for check in node["serviceChecks"] if check["method"] == BACKUP_PROBE_METHOD
                and check["source"] == "Proxmox" and "backupVmid" in check and check.get("required")
            )
            if states:
                backup_checks = {"passed": states["reachable"], "failed": states["unreachable"],
                                 "unconfirmed": states.total() - states["reachable"] - states["unreachable"]}
        selected = path_checks.get((switch, port, key), set())
        physical = "switch_mac" not in bases and bool(bases & {"host_mac", "host_lacp"})
        probes = {}
        for check in _attachment_service_checks(node):
            identity = check_key(check)
            target, number, method, path, checked_at, transport, dns_name, dns_record = identity
            local = check.get("localListener") is True
            selected_path = identity in selected
            route = method == "Маршрут" and check["source"] == "Network Observer"
            if (not target or (number is None and not selected_path)
                    or not method or not checked_at or check["stale"] or check.get("skipped")
                    or (check["source"] != "UI_VPN" and not route)
                    or not (selected_path or (physical and not local and not route))):
                continue
            transport = "UDP" if local else transport
            probe = probes.setdefault((target, number or 0, method, transport, path, dns_name, dns_record), {
                "target": target, "port": number, "method": method,
                **({"path": path} if path else {}),
                **({"transport": transport} if transport else {}),
                **({"dns": {"name": dns_name, "record": dns_record}} if dns_name else {}),
                **({"localListener": True} if local else {}),
                "passed": 0, "failed": 0, "unconfirmed": 0, "lastCheckedByOutcome": {},
            })
            count = {"reachable": "passed", "unreachable": "failed"}.get(check["state"], "unconfirmed")
            probe[count] += 1
            latest = probe["lastCheckedByOutcome"]
            latest[count] = max(latest.get(count, ""), checked_at)
            if count != "passed" and (reason := check.get("reason")):
                issue = {"state": check["state"], "reason": reason}
                if error_source := check.get("errorSource"):
                    issue["errorSource"] = error_source
                issues = probe.setdefault("issues", [])
                if issue not in issues:
                    issues.append(issue)
            if method == "IPMI LAN (UDP)" and "roundTripMs" in check:
                probe.setdefault("roundTripSamplesMs", []).append(check["roundTripMs"])
            code = check.get("httpStatus") or check.get("responseCode") or check.get("rtspStatus") or check.get("ftpReply")
            if code is not None:
                codes = probe.setdefault("responseCodes", [])
                if code not in codes:
                    codes.append(code)
            if security := check.get("rdpSecurity"):
                modes = probe.setdefault("rdpSecurityModes", [])
                if security not in modes:
                    modes.append(security)
            for field in ("zabbixVersion", "redfishVersion"):
                if version := check.get(field):
                    versions = probe.setdefault(field + "s", [])
                    if version not in versions:
                        versions.append(version)
            if dialect := check.get("smbDialect"):
                negotiation = {"dialect": dialect, "signingRequired": check["smbSigningRequired"]}
                negotiations = probe.setdefault("smbNegotiations", [])
                if negotiation not in negotiations:
                    negotiations.append(negotiation)
            if tls_state := check.get("postgresqlTls"):
                tls_result = {"state": tls_state}
                if version := check.get("tlsVersion"):
                    tls_result["version"] = version
                tls_results = probe.setdefault("postgresqlTlsResults", [])
                if tls_result not in tls_results:
                    tls_results.append(tls_result)
            if expires := check.get("tlsExpiresAt"):
                certificate = {"expiresAt": expires}
                if version := check.get("tlsVersion"):
                    certificate["version"] = version
                certificates = probe.setdefault("tlsCertificates", [])
                if certificate not in certificates:
                    certificates.append(certificate)
        observer_issues = [check for check in node["checks"] if check.get("required") and check["status"] != "ok"]
        dependencies = node["serviceAvailability"]
        return {**_attachment_node(node), "basis": sorted(bases),
                **({"dependencies": dependencies} if any(dependencies.values()) else {}),
                **({"observerIssues": observer_issues[:6], "observerIssueTotal": len(observer_issues)}
                   if observer_issues else {}),
                **({"backupChecks": backup_checks} if backup_checks else {}),
                **({"backupScope": node["backupScope"]} if "backupScope" in node else {}),
                **({"linkChecks": link_checks[key]} if bases & {"lldp_peer", "endpoint_mac"} else {}),
                **({"probeEndpoints": [probes[entry] for entry in sorted(probes)]} if probes else {})}

    service_ports = {
        switch: [{"port": port_names[switch, port], "total": len(ids),
                  "statusCounts": {**dict.fromkeys(("critical", "warn", "unknown", "ok"), 0),
                                   **Counter(nodes[key]["mapStatus"] for key in ids)},
                  "services": [service_row(switch, port, key, ids[key]) for key in sorted(ids)]}
                 for port, ids in sorted(ports.items())]
        for switch, ports in port_services.items()
    }
    return {"guestAttachments": guests, "servicePaths": service_paths, "servicePorts": service_ports}


def summarize_guest_attachment(graph: dict, node_id: str) -> dict:
    nodes = {node["id"]: node for node in graph["nodes"]}
    anchor = nodes.get(node_id)
    links = graph["links"]
    targets = set()
    if anchor and anchor["kind"] == "Сервис":
        targets.update(edge["a"] for edge in links if edge["b"] == node_id and _is_service_attachment(edge))
    elif anchor:
        targets.add(node_id)
    guest_ids = {key for key in targets if nodes[key]["guest"]}
    host_ids = sorted(key for key in targets if key not in guest_ids and nodes[key]["kind"] not in ("Сервис", CLUSTER_KIND))
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    detail = {}
    if anchor and anchor["kind"] in ("Гипервизор", CLUSTER_KIND):
        if anchor["kind"] == CLUSTER_KIND:
            host_ids = sorted({edge["b"] for edge in links if edge["a"] == node_id and edge["confirmed"]
                               and edge["kind"] == "Узел кластера" and nodes[edge["b"]]["kind"] == "Гипервизор"})
        detail.update({key: anchor[key] for key in (
            "resourceCapacity", "hardwareDisks", "zfsPools", "lvmThinPools", "clusterMemberHealth",
        ) if key in anchor})
        members = set(host_ids)
        candidates = {edge["b"] for edge in links if edge["a"] in members
                      and edge["confirmed"] and edge["kind"] == "Размещение ВМ" and nodes[edge["b"]]["guest"]}
        hosted = {key: guest for key, guest in _guest_attachments(nodes, links, sorted(candidates)).items()
                  if guest["placement"] == "confirmed" and guest["hypervisor"]["id"] in members}
        guest_ids = set(hosted)
        guests = dict(list(hosted.items())[:12])
        detail.update(_confirmed_guest_uplinks(hosted))
        detail.update(_running_without_network(nodes, hosted))
    else:
        guests = _guest_attachments(nodes, links, sorted(guest_ids)[:12])
    if anchor:
        detail["checks"] = anchor["checks"]
        detail["serviceChecks"] = anchor["serviceChecks"]
        detail["reachability"] = anchor["reachability"]
        detail.update({key: anchor[key] for key in ("backupCoverage", "backupScope") if key in anchor})
        if "managementRouterPaths" in anchor:
            detail["managementRouterPaths"] = anchor["managementRouterPaths"]
    if anchor and anchor["kind"] == "Сервис":
        dependency_ids = sorted({edge["b"] for edge in links
                                 if edge["a"] == node_id and edge["confirmed"]
                                 and edge["kind"] in SERVICE_LINKS and nodes[edge["b"]]["kind"] == "Сервис"})
        detail["serviceAvailability"] = anchor["serviceAvailability"]
        detail["dependencyTotal"] = len(dependency_ids)
        detail["dependencies"] = [_attachment_node(nodes[key]) for key in dependency_ids[:24]]
        if "probeTransition" in anchor:
            detail["probeTransition"] = anchor["probeTransition"]
    if anchor and anchor["kind"] == "Сервис" and len(guest_ids) <= 12:
        detail["servicePaths"] = _service_attachment_paths(anchor, guests, _windows_client_attachments(nodes, links).get(node_id))
        if len(targets) == 1 and len(host_ids) == 1:
            detail["servicePaths"].extend(_management_service_paths(
                anchor, host_ids[0], _management_port_paths(nodes, links), _observed_management_ports(links, nodes), nodes,
            ))
        elif len(targets) == len(host_ids) == 2:
            detail["servicePaths"].extend(_transit_service_paths(anchor, targets, _observed_management_ports(links, nodes)))
    elif anchor and anchor["kind"] in NETWORK_KINDS[:2]:
        attachments = _map_attachments(nodes, links, datetime.now(timezone.utc))
        detail["servicePorts"] = graph.get("servicePorts", attachments["servicePorts"]).get(node_id, [])
        if anchor["kind"] == NETWORK_KINDS[0]:
            detail.update(_confirmed_guest_uplinks(attachments["guestAttachments"], switch_id=node_id))
        if paths := attachments["servicePaths"].get(node_id):
            detail["servicePaths"] = paths
    elif anchor and not anchor["guest"]:
        if paths := _management_service_paths(anchor, node_id, {}, _observed_management_ports(links, nodes)):
            detail["servicePaths"] = paths
    if anchor and anchor["kind"] not in ("Сервис", CLUSTER_KIND):
        service_hosts = defaultdict(set)
        for edge in links:
            if (_is_service_attachment(edge) and nodes[edge["a"]]["kind"] != "Сервис"
                    and nodes[edge["b"]]["kind"] == "Сервис"):
                service_hosts[edge["b"]].add(edge["a"])
        service_ids = sorted(key for key, hosts in service_hosts.items() if node_id in hosts)
        detail["serviceTotal"] = len(service_ids)
        detail["services"] = []
        management_ports = _observed_management_ports(links, nodes) if service_ids and not anchor["guest"] else {}
        management_paths = _management_port_paths(nodes, links) if service_ids and not anchor["guest"] else {}
        for key in service_ids[:24]:
            service = nodes[key]
            paths = []
            if service_hosts[key] == {node_id}:
                if anchor["guest"]:
                    paths = _service_attachment_paths(service, guests)
                else:
                    paths = _management_service_paths(service, node_id, management_paths, management_ports, nodes)
            elif not anchor["guest"]:
                paths = _transit_service_paths(service, service_hosts[key], management_ports)
            detail["services"].append({
                "node": _attachment_node(service), "checks": service["checks"],
                "serviceChecks": service["serviceChecks"], "servicePaths": paths,
                **({"backupScope": service["backupScope"]} if "backupScope" in service else {}),
            })
    return {**metadata, "attachment": {"node": _attachment_node(anchor) if anchor else None,
                                       "guestTotal": len(guest_ids), "guests": list(guests.values()),
                                       "physicalHostTotal": len(host_ids),
                                       "physicalHosts": _physical_attachments(nodes, links, host_ids[:12]),
                                       **detail}}


def _has_no_guest_network(attachment: dict, network: dict) -> bool:
    return (attachment["power"] == "running" and network["enabled"] == 0
            and network["configured"] == network["disabled"]
            and all(interface["linkDisabled"] for interface in attachment["interfaces"]))


def _running_without_network(nodes: dict, guests: dict) -> dict:
    rows = []
    for guest_id, attachment in guests.items():
        network = nodes[guest_id].get("guestNetwork")
        if network and _has_no_guest_network(attachment, network):
            rows.append({"guest": attachment["guest"], "hypervisor": attachment["hypervisor"], "guestNetwork": network})
    rows.sort(key=lambda row: (row["guest"]["vmid"], row["guest"]["id"]))
    return {"runningWithoutNetworkTotal": len(rows), "runningWithoutNetwork": rows[:64]}


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
    guest_counts = dict.fromkeys(("running", "stopped", "prelaunch", "paused", "unknown"), 0)
    interface_counts = dict.fromkeys((*evidence_order.values(), "local_neighbor_with_physical_pair",
                                      "local_neighbor", "ambiguous_switch_port", "unconfirmed", "inactive"), 0)
    gaps = []
    for attachment in guests.values():
        power = attachment["power"]
        inactive = power in {"stopped", "prelaunch", "paused"}
        guest_counts[power] += 1

        incomplete = []
        for interface in attachment["interfaces"]:
            if inactive or interface["linkDisabled"]:
                state = "inactive"
            elif "ambiguousSwitchPorts" in interface:
                state = "ambiguous_switch_port"
            else:
                evidence = {(row["basis"], "physicalPair" in row) for row in interface["switchObservations"]}
                state = next((label for key, label in evidence_order.items() if key in evidence), "unconfirmed")
                if "localNeighbor" in interface:
                    if state == "bridge_with_physical_pair":
                        state = "local_neighbor_with_physical_pair"
                    elif state in {"bridge_uplink", "unconfirmed"}:
                        state = "local_neighbor"
            interface_counts[state] += 1
            if state not in {"guest_mac_with_physical_pair", "local_neighbor_with_physical_pair", "inactive"}:
                incomplete.append({"guestPort": interface["guestPort"], "bridge": interface["bridge"], "state": state})
                if state == "ambiguous_switch_port":
                    incomplete[-1]["switchPorts"] = interface["ambiguousSwitchPorts"]
                if "arpDiagnostic" in interface:
                    incomplete[-1]["arpDiagnostic"] = interface["arpDiagnostic"]
        network = nodes[attachment["guest"]["id"]].get("guestNetwork")
        if network and _has_no_guest_network(attachment, network):
            continue
        active_ports = {interface["guestPort"] for interface in attachment["interfaces"] if not interface["linkDisabled"]}
        missing_config = network and (network["configured"] != network["enabled"] + network["disabled"]
                                      or len(active_ports) != network["enabled"])
        if not inactive and (incomplete or not active_ports or missing_config):
            gaps.append({"guest": attachment["guest"], "hypervisor": attachment["hypervisor"],
                         "power": power, "placement": attachment["placement"], "interfaces": incomplete,
                         **({"networkTraffic": attachment["networkTraffic"]} if "networkTraffic" in attachment else {})})

    gaps.sort(key=lambda gap: (gap["power"] != "running", gap["guest"]["id"]))
    without_network = _running_without_network(nodes, guests)
    incomplete_running = sum(gap["power"] == "running" for gap in gaps)
    disconnected_running = without_network["runningWithoutNetworkTotal"]
    running_coverage = {"confirmed": guest_counts["running"] - incomplete_running - disconnected_running,
                        "incomplete": incomplete_running, "withoutNetwork": disconnected_running}
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    return {**metadata, "attachmentAudit": {"guestCounts": guest_counts, "interfaceCounts": interface_counts,
                                            "runningNetworkCoverage": running_coverage,
                                            "gapTotal": len(gaps), "gaps": gaps[:64],
                                            **_confirmed_guest_uplinks(guests),
                                            **without_network}}


def _confirmed_guest_uplinks(guests: dict, *, switch_id: str | None = None, hypervisor_id: str | None = None,
                             port_keys: set[str] | None = None) -> dict:
    running = {key: guest for key, guest in guests.items() if guest["power"] == "running"}
    uplink_groups = defaultdict(list)
    for device_id, attachments in _guest_switch_attachments(running).items():
        if switch_id is not None and device_id != switch_id:
            continue
        for row in attachments:
            if hypervisor_id is not None and row["hypervisor"]["id"] != hypervisor_id:
                continue
            pair = row["physicalPair"]
            port = port_label_key(pair["switchPort"])
            scoped_port = port_label_key(pair["hostPort"]) if hypervisor_id is not None else port
            if port_keys is not None and scoped_port not in port_keys:
                continue
            key = (device_id, port, row["hypervisor"]["id"],
                   port_label_key(pair["hostPort"]))
            uplink_groups[key].append(row)
    confirmed_uplinks = []
    for _, rows in sorted(uplink_groups.items()):
        first = rows[0]
        interfaces = {(row["guest"]["id"], row["guestPort"]): {
            key: row[key] for key in ("guest", "guestPort", "bridge", "basis")
        } for row in rows}
        confirmed_uplinks.append({
            "switch": first["switch"], "hypervisor": first["hypervisor"], **first["physicalPair"],
            **({"uplinkPortLinks": first["uplinkPortLinks"]} if "uplinkPortLinks" in first else {}),
            "uplinkLinkHealth": first["uplinkLinkHealth"],
            "guestTotal": len({guest_id for guest_id, _ in interfaces}),
            "interfaceTotal": len(interfaces),
            "interfaces": [interfaces[key] for key in sorted(interfaces)[:64]],
        })
    return {"confirmedUplinkTotal": len(confirmed_uplinks), "confirmedUplinks": confirmed_uplinks[:64]}


def summarize_services(graph: dict, *, host_id: str | None = None, service_ids: set[str] | None = None,
                       offset: int = 0) -> dict:
    nodes = {node["id"]: node for node in graph["nodes"]}
    hosts = {}
    for link in graph["links"]:
        if (_is_service_attachment(link)
                and nodes[link["a"]]["kind"] != "Сервис" and nodes[link["b"]]["kind"] == "Сервис"):
            hosts.setdefault(link["b"], set()).add(link["a"])

    priority = {"critical": 0, "warn": 1, "unknown": 2, "ok": 3}
    counts = dict.fromkeys(priority, 0)
    services = []
    service_rows = {}
    for node in nodes.values():
        if node["kind"] != "Сервис":
            continue
        state = node["mapStatus"]
        checks = [
            {"check": check["name"], "label": check.get("label", check["name"]),
             "required": check.get("required") is True,
             "status": check["status"], "source": "Server Observer",
             **{key: check[key] for key in ("checkedAt", "stale", "error", "unit", "observed", "warningThreshold",
                                           "backupJob", "backupRepository", "backupSnapshotAt", "diskCapacity", "sourceNodeId")
                if key in check}}
            for check in node["checks"] if check.get("required") or check["status"] in ("critical", "warn")
        ]
        checks.extend(
            {"check": check["method"], "status": _service_check_status(check),
             "required": check.get("required") is True,
             **{key: check[key] for key in ("source", "checkedAt", "stale", "reason", "path", "port", "target",
                                            "pppoe", "rtspStatus", "ftpReply", "tlsExpiresAt", "tlsVersion",
                                            "dns", "ntp", "localRoute", "vlanTransit", "identityCheckedAt", "errorSource",
                                            "responseCode", "attempts", "firstAttemptReason", "ipsecPolicy", "configuredPort", "localUdpSocket",
                                            "sessionCount", "daemonReady", "arpDiagnostic", "sshTcpConnected")
                if key in check and check[key] is not None and check[key] != ""}}
            for check in node["serviceChecks"] if check.get("required") or (
                state == "unknown" and check.get("supplemental") and check["state"] != "reachable"
            )
        )
        totals = Counter(check["status"] for check in checks if check["required"])
        issues = sorted((check for check in checks if check["status"] != "ok"),
                        key=lambda check: (not check["required"], priority[check["status"]]))
        row = {
            "id": node["id"], "name": node["name"], "status": state, "reachability": node["reachability"],
            **({"probeTransition": node["probeTransition"]} if "probeTransition" in node else {}),
            "hosts": sorted(hosts.get(node["id"], ())), "dependencies": node["serviceAvailability"],
            "requiredChecks": {"passed": totals["ok"], "failed": totals["critical"] + totals["warn"],
                               "unconfirmed": totals["unknown"]},
            "issueTotal": len(issues), "issues": issues[:6],
            **({"backupScope": node["backupScope"]} if "backupScope" in node else {}),
        }
        service_rows[node["id"]] = row
        if ((service_ids is None or node["id"] in service_ids)
                and (host_id is None or host_id in hosts.get(node["id"], ()))):
            counts[state] += 1
            services.append(row)
    services.sort(key=lambda node: (priority[node["status"]], node["name"].casefold(), node["id"]))
    recent_transitions = [
        {**{key: row[key] for key in ("id", "name", "status", "hosts")}, **row["probeTransition"]}
        for row in services if row.get("probeTransition")
    ]
    recent_transitions.sort(key=lambda row: row["checkedAt"], reverse=True)
    metadata = {key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph}
    end = offset + 128
    page = services[offset:end]
    dependency_ids_by_service = {
        row["id"]: [key for group in ("unavailable", "degraded", "unknown")
                    for key in row["dependencies"][group] if key in service_rows]
        for row in page
    }
    path_rows = {row["id"]: row for row in page}
    path_rows.update((key, service_rows[key]) for keys in dependency_ids_by_service.values() for key in keys[:8])
    guest_ids = sorted({host for row in path_rows.values() if row["status"] != "ok" or row["issues"]
                        for host in row["hosts"] if nodes[host]["guest"]})
    guests = {}
    if guest_ids:
        guests = _guest_attachments(nodes, graph["links"], guest_ids)
        running = {key: guest for key, guest in guests.items() if guest["power"] == "running"}
        uplinks = defaultdict(list)
        for switch_id, attachments in _guest_switch_attachments(running).items():
            for attachment in attachments:
                guest_id = attachment["guest"]["id"]
                uplinks[guest_id].append({
                    "guestId": guest_id, "guestPort": attachment["guestPort"], "bridge": attachment["bridge"],
                    "hypervisorId": attachment["hypervisor"]["id"], "switchId": switch_id,
                    "basis": attachment["basis"], **attachment["physicalPair"],
                })
        for row in page:
            if row["status"] != "ok":
                paths = [path for host in row["hosts"] for path in uplinks.get(host, ())]
                if paths:
                    row.update(guestUplinkTotal=len(paths), guestUplinks=paths[:8])
    path_candidates = [row for row in path_rows.values() if row["issues"] and len(row["hosts"]) == 1]
    if path_candidates:
        management = _management_port_paths(nodes, graph["links"])
        observed_ports = _observed_management_ports(graph["links"], nodes)
        for row in path_candidates:
            host, = row["hosts"]
            service = nodes[row["id"]]
            paths = _management_service_paths(service, host, management, observed_ports, nodes)
            if host in guests:
                paths.extend(_service_attachment_paths(service, {host: guests[host]}))
            for issue in row["issues"]:
                if issue["source"] not in ("UI_VPN", "Network Observer"):
                    continue
                for path in paths:
                    if (issue["source"] != path.get("source", "UI_VPN")
                            or issue.get("target") != path["target"] or issue.get("port") != path["port"]
                            or issue["check"] != path["method"] or issue.get("checkedAt") != path["checkedAt"]
                            or issue.get("path") != path.get("path") or issue.get("dns") != path.get("dns")):
                        continue
                    if router := path.get("routerAttachment"):
                        node_id, port, evidence = router["routerId"], router["port"], router
                    elif switch := path.get("switchAttachment"):
                        node_id, port, evidence = switch["switchId"], switch["port"], switch
                    elif pair := path.get("physicalPair"):
                        node_id, port, evidence = path["switchId"], pair["switchPort"], pair
                    else:
                        continue
                    issue["portObservation"] = {"nodeId": node_id, "port": port, "source": evidence["source"],
                                                "checkedAt": evidence["checkedAt"]}
                    break
    for row in page:
        dependency_ids = dependency_ids_by_service[row["id"]]
        if dependency_ids:
            dependencies = [service_rows[key] for key in dependency_ids[:8]]
            row["dependencyIssueTotal"] = len(dependency_ids)
            row["dependencyIssues"] = [
                {**{key: dependency[key] for key in ("id", "name", "status", "issueTotal")},
                 **({"issue": dependency["issues"][0]} if dependency["issues"] else {})}
                for dependency in dependencies
            ]
    return {**metadata, "serviceAudit": {
        "total": len(services), "counts": counts, "offset": offset,
        "recentTransitionTotal": len(recent_transitions), "recentTransitions": recent_transitions[:16],
        "nextOffset": end if end < len(services) else None, "services": page,
    }}


def _agent_ipv4_comparison(network: dict, attachment: dict) -> dict:
    observed = defaultdict(list)
    for guest in attachment["guests"]:
        if guest["placement"] != "confirmed":
            continue
        for interface in guest["interfaces"]:
            if interface["linkDisabled"]:
                continue
            for row in interface.get("ipv4Observations", []):
                observed[row["address"]].append((guest, interface, row))
    if not observed:
        return {}
    reported = defaultdict(list)
    for interface in network["interfaces"]:
        for address in interface["ipv4"]:
            reported[address].append(interface.get("name"))
    matched = sorted(observed.keys() & reported.keys())
    paths = []
    for address in matched:
        candidates = observed[address]
        if len(candidates) != 1:
            continue
        (guest, interface, row), = candidates
        ports = [port for port in interface["switchObservations"] if port["basis"] == "guest_mac"]
        if len(ports) != 1:
            continue
        port, = ports
        if "physicalPair" not in port:
            continue
        names = reported[address]
        paths.append({"address": address, "guestPort": interface["guestPort"], "bridge": interface["bridge"],
                      "hypervisorId": guest["hypervisor"]["id"], "addressCheckedAt": row["checkedAt"],
                      "switchId": port["switch"]["id"], "switchCheckedAt": port["checkedAt"],
                      "physicalPair": port["physicalPair"],
                      **({"endpointInterface": names[0]} if len(names) == 1 and names[0] else {})})
    return {"matched": matched, "endpointOnly": sorted(reported.keys() - observed.keys()),
            "observedOnly": sorted(observed.keys() - reported.keys()), **({"matchedPaths": paths} if paths else {})}


def load_infrastructure_agent_audit(path: Path, *, node_id: str | None = None) -> dict:
    adapter = None
    identities = None
    try:
        adapter = get_endpoint_context_adapter()
        identities = adapter.list_agent_network_identities()
    except EndpointPlatformServiceError:
        pass
    try:
        graph = load_infrastructure_map(
            path, agent_identities=identities,
            load_agent_presence=(lambda: adapter.list_device_presences()) if adapter is not None else None,
            load_agent_profiles=(lambda device_id, profiles: adapter.read_observed_profiles(device_id, profiles))
            if adapter is not None else None,
            agent_node_id=node_id,
        )
    finally:
        if adapter is not None:
            adapter.close()
    result = {**{key: graph[key] for key in ("availability", "snapshotAt", "git", "collectionIssues") if key in graph},
              "agentAudit": graph.get("agentAudit", {"sourceState": "unavailable"})}
    node = next((item for item in graph["nodes"] if item["id"] == node_id), None)
    if node and (node["guest"] or node["kind"] in ("Гипервизор", "Сервис")):
        attachment = summarize_guest_attachment(graph, node_id)["attachment"]
        result["attachment"] = attachment
        if node["kind"] == "Сервис":
            result["serviceAudit"] = summarize_services(graph, service_ids={node_id})["serviceAudit"]
            dependency_ids = {edge["b"] for edge in graph["links"] if edge["a"] == node_id
                              and edge["confirmed"] and edge["kind"] in SERVICE_LINKS}
            if dependency_ids:
                result["dependencyAudit"] = summarize_services(graph, service_ids=dependency_ids)["serviceAudit"]
        else:
            result["serviceAudit"] = summarize_services(graph, host_id=node_id)["serviceAudit"]
        for entry in result["agentAudit"].get("guests", []):
            network = entry.get("network")
            if not network or network["stale"] or not network["interfaces"]:
                continue
            if comparison := _agent_ipv4_comparison(network, attachment):
                entry["ipv4Comparison"] = comparison
                local_services = entry.get("health", {}).get("services", [])
                if any(service["name"] == "sshd" for service in local_services):
                    service_ids = {edge["b"] for edge in graph["links"]
                                   if edge["a"] == entry["id"] and _is_service_attachment(edge)}
                    guests = {guest["guest"]["id"]: guest for guest in attachment["guests"]}
                    checks = [
                        {"serviceId": service["id"], "localService": "sshd",
                         **{key: check[key] for key in ("method", "target", "port", "state", "checkedAt", "reason")
                            if key in check}}
                        for service in graph["nodes"] if service["id"] in service_ids and service["kind"] == "Сервис"
                        for check in _service_attachment_paths(service, guests)
                        if check["method"] == "SSH" and check["port"] is not None and "gateway" not in check
                        and check["target"] in comparison["matched"]
                    ]
                    if checks:
                        entry["networkServiceChecks"] = checks[:16]
    return result


def _guest_agent_exclusion(node: dict, snapshot_fresh: bool) -> str:
    proxmox = next((source for source in node["sources"] if source["name"] == "Proxmox"), None)
    if not snapshot_fresh or (proxmox and proxmox["stale"]):
        return "proxmox_stale"
    if not proxmox or proxmox["label"] != "Запущена":
        return {
            "Выключена": "guest_stopped",
            "Приостановлена": "guest_paused",
            "Гостевая ОС ещё не запущена": "guest_not_started",
            "Шаблон": "guest_template",
        }.get(proxmox["label"] if proxmox else "", "proxmox_unconfirmed")
    network = node.get("guestNetwork")
    if not network or network["configured"] > network["enabled"] + network["disabled"]:
        return "network_config_unconfirmed"
    return "no_enabled_network_adapter" if network["enabled"] == 0 else "no_unique_network_identity"


def _memory_headroom(available: object, capacity: dict) -> dict:
    total = capacity.get("memory", {}).get("totalBytes")
    if type(total) is not int or type(available) is not int or not 0 <= available <= total < 2**53 or total == 0:
        return {}
    return {"availablePercent": round(100 * available / total, 2),
            "warningThreshold": MEMORY_AVAILABLE_WARNING_PERCENT,
            "status": "warn" if 100 * available < MEMORY_AVAILABLE_WARNING_PERCENT * total else "ok",
            "totalBytes": total, "capacityCheckedAt": capacity["checkedAt"]}


def _guest_agent_health(snapshot: object, now: datetime, *, platform: str | None = None,
                        capacity: dict | None = None) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get("profile") != "health_v1":
        return {}
    checked_at = snapshot.get("collected_at")
    if not observation_is_fresh(checked_at, now, max_age=GUEST_AGENT_HEALTH_MAX_AGE):
        return {}
    sections = snapshot.get("sections")
    if not isinstance(sections, dict):
        return {}
    resources = sections.get("resources")
    if not isinstance(resources, dict):
        resources = {}
    warnings = snapshot.get("warnings", [])
    metrics = {label: value for key, label in (("free_bytes", "memoryAvailableBytes"), ("uptime_seconds", "uptimeSeconds"))
               if type(value := resources.get(key)) is int and 0 < value < 2**53}
    if capacity and observation_is_fresh(capacity.get("checkedAt"), now, max_age=RESOURCE_CAPACITY_MAX_AGE):
        available = resources.get("free_bytes")
        if (available != 0 or isinstance(warnings, (list, tuple)) and "source_unavailable" not in warnings) and (
                headroom := _memory_headroom(available, capacity)):
            metrics["memoryAvailableBytes"] = available
            metrics["memoryHeadroom"] = headroom
    load = resources.get("load_1m")
    if (platform == "linux" and type(load) in (int, float) and 0 <= load < 2**53
            and isinstance(warnings, (list, tuple)) and "source_unavailable" not in warnings):
        metrics["loadAverage1m"] = load
    reports = _rows(sections.get("services"), 64)
    services = []
    for name in GUEST_AGENT_SERVICE_NAMES:
        states = [report.get("status") for report in reports if report.get("name") == name]
        if len(states) == 1 and states[0] in ("active", "inactive", "failed", "unknown"):
            services.append({"name": name, "status": states[0]})
    if services:
        metrics["services"] = services
    return {"checkedAt": _time(checked_at).isoformat(), **metrics} if metrics else {}


def _guest_agent_network(snapshot: object, now: datetime) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get("profile") != "network_v1":
        return {}
    checked_at = _time(snapshot.get("collected_at"))
    sections = snapshot.get("sections")
    if checked_at is None or checked_at > now or not isinstance(sections, dict):
        return {}
    snapshot_at = checked_at
    observed_at = _time(snapshot.get("observed_at"))
    if observed_at is not None and snapshot_at <= observed_at <= now:
        checked_at = observed_at
    interfaces = defaultdict(set)
    for row in _rows(sections.get("interfaces"), 64):
        name = _text(row.get("name"), 64).strip()
        addresses = row.get("addresses")
        if not name.isprintable() or not isinstance(addresses, list):
            continue
        for address in addresses[:16]:
            if not isinstance(address, str) or len(address) > 64:
                continue
            try:
                ip = ipaddress.IPv4Interface(address).ip
            except ValueError:
                continue
            if not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved):
                interfaces[name].add(ip)
    return {"checkedAt": checked_at.isoformat(), "stale": now - checked_at > GUEST_AGENT_NETWORK_MAX_AGE,
            **({"snapshotAt": snapshot_at.isoformat()} if checked_at != snapshot_at else {}),
            **({"reason": "no_reported_ipv4"} if not interfaces else {}),
            "interfaces": [{"name": name, "ipv4": [str(ip) for ip in sorted(addresses)]}
                           for name, addresses in sorted(interfaces.items())]}


def _guest_agent_os(snapshot: object, now: datetime) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get("profile") != "inventory_v1":
        return {}
    collected_at = _time(snapshot.get("collected_at"))
    sections = snapshot.get("sections")
    system = sections.get("system") if isinstance(sections, dict) else None
    if collected_at is None or collected_at > now or not isinstance(system, dict):
        return {}
    platform = system.get("platform")
    if platform not in ("linux", "windows"):
        return {}
    fields = {
        key: value for key, source, limit in (
            ("name", "os_name", 80), ("version", "os_version", 64),
            ("build", "os_build", 32), ("architecture", "architecture", 32),
        )
        if (value := _text(system.get(source), limit).strip()) and value.isprintable()
    }
    return {"collectedAt": collected_at.isoformat(), "platform": platform, **fields}


def _guest_agent_presence(identity: dict, now: datetime, *, verified_enrollment: bool = False) -> tuple[datetime | None, str]:
    from .inventory.endpoint import CANDIDATE_MAX_AGE, STATE_MAX_AGE

    online = identity.get("online")
    if online is not True:
        return None, "endpoint_reports_offline" if online is False else "endpoint_presence_missing"
    last_seen = _time(identity.get("last_seen_at"))
    if last_seen is None or last_seen > now:
        return None, "endpoint_last_seen_missing"
    if now - last_seen > STATE_MAX_AGE:
        return None, "endpoint_last_seen_stale"
    if not verified_enrollment:
        baseline = _time(identity.get("baseline_collected_at"))
        if baseline is None or baseline > now:
            return None, "endpoint_network_baseline_missing"
        if now - baseline > CANDIDATE_MAX_AGE:
            return None, "endpoint_network_baseline_stale"
    return last_seen, ""


def _reobserved_agent_baseline(snapshot: object, identity: dict, now: datetime) -> datetime | None:
    from .inventory.endpoint import CANDIDATE_MAX_AGE

    if not isinstance(snapshot, dict) or snapshot.get("profile") != "baseline_v1":
        return None
    collected = _time(snapshot.get("collected_at"))
    observed = _time(snapshot.get("observed_at"))
    if (not collected or collected != _time(identity.get("baseline_collected_at"))
            or not observed or not collected <= observed <= now or now - observed > CANDIDATE_MAX_AGE):
        return None
    sections = snapshot.get("sections")
    if not isinstance(sections, dict):
        return None
    macs = {key for row in _rows(sections.get("interfaces"), 64)
            if isinstance(key := row.get("stable_key"), str) and re.fullmatch(r"mac-[0-9a-f]{12}", key)}
    return observed if macs and macs == set(identity.get("baseline_mac_keys", [])) else None


def _summarize_agent_audit(nodes: dict, keys: dict, conflicts: set[str], identities: list[dict], now: datetime,
                           *, snapshot_fresh: bool, enrollments: dict[str, str], device_presences: list[dict],
                           hypervisor_evidence: dict[str, str],
                           load_agent_profiles: Callable[[UUID, tuple[str, ...]], dict] | None = None,
                           selected_node: str | None = None, collect_hypervisor_health: bool = False) -> dict:
    from .inventory.endpoint import CANDIDATE_MAX_AGE

    by_id = {row["id"]: row for row in identities if isinstance(row, dict)
             and isinstance(row.get("id"), str) and 0 < len(row["id"]) <= 255}
    if len(by_id) != len(identities) or len(by_id) > 1000:
        return {"sourceState": "unavailable"}
    historical = {identity_id for identity_id, row in by_id.items()
                  if row.get("online") is False and (last_seen := _time(row.get("last_seen_at"))) is not None
                  and now - last_seen > CANDIDATE_MAX_AGE}
    by_mac = defaultdict(set)
    for identity_id, row in by_id.items():
        mac_keys = row.get("baseline_mac_keys")
        for key in mac_keys if isinstance(mac_keys, list) else []:
            if isinstance(key, str) and re.fullmatch(r"mac-[0-9a-f]{12}", key):
                by_mac[key].add(identity_id)
    owners = Counter(key for values in keys.values() for key in values)
    conflicts = conflicts | {node_id for node_id, values in keys.items() if any(owners[key] > 1 for key in values)}
    matches = {node_id: set().union(*(by_mac[key] for key in values if owners[key] == 1))
               for node_id, values in keys.items()}
    enrolled_ids = set(enrollments.values())
    verified = {row["id"]: row for row in device_presences if isinstance(row, dict)
                and isinstance(row.get("id"), str) and row["id"] in enrolled_ids and row.get("retired_at") is None}
    for node_id, enrollment in enrollments.items():
        if enrollment in verified:
            matches.setdefault(node_id, set()).add(enrollment)
    for node_id in conflicts:
        matches.setdefault(node_id, set())
    nodes_by_identity = Counter(identity_id for values in matches.values() for identity_id in values)
    guests, hypervisors = [], []
    baseline_reads_remaining = 8
    for node_id, node in nodes.items():
        hypervisor = node["kind"] == "Гипервизор"
        if not hypervisor and (not node["guest"] or node["vmid"] is None):
            continue
        entries = hypervisors if hypervisor else guests
        entry = {key: node[key] for key in ("id", "name")}
        if not hypervisor:
            entry["vmid"] = node["vmid"]
        candidates = matches.get(node_id)
        if candidates is None:
            reason = _guest_agent_exclusion(node, snapshot_fresh) if not hypervisor else (
                "management_mac_unconfirmed" if snapshot_fresh else "proxmox_stale"
            )
            entries.append({**entry, "state": "not_eligible", "reason": reason})
            continue
        entry.update(state="ambiguous", registrations=len(candidates))
        enrollment = enrollments.get(node_id)
        same_mac = len(candidates) > 1 and any(candidates <= by_mac[key] for key in keys.get(node_id, ()))
        if (enrollment in candidates and candidates - {enrollment} <= historical and same_mac
                and _guest_agent_presence(verified.get(enrollment, {}), now, verified_enrollment=True)[0] is not None):
            candidates = {enrollment}
        if node_id in conflicts:
            entry["reason"] = "duplicate_guest_mac"
        elif enrollment and candidates - {enrollment}:
            entry["reason"] = "enrollment_registration_conflict"
        elif not candidates:
            entry.update(state="unmatched", reason="enrollment_presence_unconfirmed" if enrollment else "no_matching_registration")
        else:
            active_mac_registration = len(candidates) > 1
            if active_mac_registration:
                # Ignore historical duplicates only while the same VM MAC has a single current registration.
                current = candidates - historical
                if len(current) != 1:
                    entries.append({**entry, "reason": "multiple_registrations"})
                    continue
                active_id, = current
                if _guest_agent_presence(by_id[active_id], now)[0] is None or not same_mac:
                    entries.append({**entry, "reason": "multiple_registrations"})
                    continue
                candidates = current
            identity_id, = candidates
            if nodes_by_identity[identity_id] > 1:
                entry["reason"] = "registration_matches_multiple_guests"
            else:
                entry["state"] = "matched"
                explicit = identity_id == enrollment and identity_id in verified
                identity = by_id.get(identity_id) or verified[identity_id]
                if explicit:
                    entry["identitySource"] = "verified_enrollment"
                elif hypervisor:
                    entry.update(identitySource="proxmox_management_mac", identityCheckedAt=hypervisor_evidence[node_id])
                elif active_mac_registration:
                    entry["identitySource"] = "active_mac_registration"
                presence = verified[identity_id] if explicit else identity
                last_seen, presence_reason = _guest_agent_presence(presence, now, verified_enrollment=explicit)
                if (presence_reason == "endpoint_network_baseline_stale" and load_agent_profiles is not None
                        and baseline_reads_remaining and (selected_node is None or node_id == selected_node)):
                    baseline_reads_remaining -= 1
                    try:
                        baseline = load_agent_profiles(UUID(identity_id), ("baseline_v1",)).get("baseline_v1")
                    except (EndpointPlatformServiceError, ValueError):
                        baseline = None
                    if observed_at := _reobserved_agent_baseline(baseline, identity, now):
                        last_seen = _time(presence["last_seen_at"])
                        entry["baselineObservedAt"] = observed_at.isoformat()
                entry["presence"] = "online" if last_seen is not None else "unconfirmed"
                if last_seen is not None:
                    entry["lastSeenAt"] = last_seen.isoformat()
                else:
                    entry["presenceReason"] = presence_reason
                profile_rows = _rows(identity.get("profiles"), 5)
                snapshots = {}
                if (explicit and identity_id not in by_id and load_agent_profiles is not None
                        and (selected_node is None or node_id == selected_node)):
                    try:
                        snapshots = load_agent_profiles(UUID(identity_id), GUEST_AGENT_PROFILES)
                    except EndpointPlatformServiceError:
                        snapshots = {}
                    profile_rows = [{"profile": name, "collected_at": snapshot.get("collected_at")}
                                    for name, snapshot in snapshots.items() if isinstance(snapshot, dict)]
                reports = defaultdict(set)
                for row in profile_rows:
                    profile = row.get("profile")
                    collected = _time(row.get("collected_at"))
                    if profile in GUEST_AGENT_PROFILES and collected is not None and collected <= now:
                        reports[profile].add(collected)
                profiles = [{"profile": name, "collectedAt": next(iter(reports[name])).isoformat()}
                            for name in GUEST_AGENT_PROFILES if len(reports[name]) == 1]
                if profiles:
                    entry["contextProfiles"] = profiles
                health_times = reports.get("health_v1", set())
                entry["healthProfileState"] = "unconfirmed"
                if len(health_times) == 1:
                    health_at, = health_times
                    entry["healthProfileState"] = "fresh" if now - health_at <= GUEST_AGENT_HEALTH_MAX_AGE else "stale"
                if ((node_id == selected_node or collect_hypervisor_health and hypervisor)
                        and entry["presence"] == "online" and load_agent_profiles is not None):
                    wanted = ["health_v1"]
                    if node_id == selected_node:
                        wanted.extend(profile for profile in ("inventory_v1", "network_v1") if reports.get(profile))
                    missing = tuple(profile for profile in wanted if profile not in snapshots)
                    if missing:
                        try:
                            snapshots.update(load_agent_profiles(UUID(identity_id), missing))
                        except (EndpointPlatformServiceError, ValueError):
                            pass
                    operating_system = _guest_agent_os(snapshots.get("inventory_v1"), now)
                    if operating_system:
                        entry["operatingSystem"] = operating_system
                    if health := _guest_agent_health(snapshots.get("health_v1"), now, platform=operating_system.get("platform"),
                                                     capacity=nodes[node_id].get("resourceCapacity")):
                        entry["health"] = health
                    if network := _guest_agent_network(snapshots.get("network_v1"), now):
                        entry["network"] = network
        entries.append(entry)
    counts = Counter(row["state"] for row in guests)
    health_coverage = {}
    for name, entries in (("guests", guests), ("hypervisors", hypervisors)):
        states = Counter(row["healthProfileState"] for row in entries if row["state"] == "matched")
        health_coverage[name] = {state: states[state] for state in ("fresh", "stale", "unconfirmed")}
    return {"sourceState": "ready", "total": len(guests), "eligible": len(guests) - counts["not_eligible"],
            "matched": counts["matched"], "ambiguous": counts["ambiguous"], "unmatched": counts["unmatched"],
            "notEligible": counts["not_eligible"],
            "healthProfileCoverage": health_coverage,
            "guests": sorted((row for row in guests if selected_node is None or row["id"] == selected_node),
                             key=lambda row: (row["vmid"], row["id"])),
            "hypervisors": sorted((row for row in hypervisors if selected_node is None or row["id"] == selected_node),
                                  key=lambda row: row["id"])}


def load_infrastructure_map(
    path: Path, now: datetime | None = None, *, db: Session | None = None,
    agent_identities: list[dict] | None = None, include_guest_attachments: bool = False,
    include_service_ports: bool = False,
    include_port_pairs: bool = False,
    include_counter_service_counts: bool = False,
    load_agent_presence: Callable[[], list[dict]] | None = None,
    load_agent_profiles: Callable[[UUID, tuple[str, ...]], dict] | None = None,
    agent_node_id: str | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    empty = {
        "availability": "missing", "snapshotAt": None, "nodes": [], "links": [],
        "clusterId": "", "nodeOrder": [], "overviewGuests": [], "switchKinds": list(NETWORK_KINDS), "git": "",
        **({"servicePorts": {}} if include_service_ports else {}),
        **({"guestSwitchAttachments": {}} if include_service_ports and include_port_pairs else {}),
        **({"currentPortPairs": [], "inventoryPairs": [], "pendingPortPairs": [],
            "lacpPartnerInterfaceGaps": []} if include_port_pairs else {}),
        **({"guestAttachments": {}, "servicePaths": {}, "servicePorts": {}, "inventoryPairs": [],
            "currentPortPairTotal": 0, "currentPortPairs": [],
            "currentPairMeasurementGapTotal": 0, "currentPairMeasurementGaps": [],
            "pendingPortPairTotal": 0, "pendingPortPairs": [], "pendingPortPairLinkCounts": {},
            "lacpPartnerInterfaceGapTotal": 0, "lacpPartnerInterfaceGaps": []} if include_guest_attachments else {}),
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
    agent_conflicts = set()
    agent_enrollments = {}
    hypervisor_evidence = {}
    lacp_expectations = {}
    for row in _rows(raw.get("nodes"), 600):
        node = _public_node(row, now)
        if node["id"] and node["name"] and node["id"] not in nodes:
            nodes[node["id"]] = node
            if expected := _rows(row.get("lacpExpectations"), 8):
                lacp_expectations[node["id"]] = expected
            port_rows = _rows(row.get("ports"), 500)
            if node["kind"] in (*NETWORK_KINDS[:2], "Гипервизор", "Контроллер управления"):
                port_states[node["id"]] = index_port_states(port_rows, now)
            elif node["kind"] == "Рабочая станция":
                port_states[node["id"]] = index_port_states(
                    [port for port in port_rows if port.get("source") == WINDOWS_ADAPTER_SOURCE], now,
                )
            key = _text(row.get("endpointKey"))
            if node["kind"] == "Рабочая станция" and re.fullmatch(r"mac:(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", key):
                endpoint_keys[node["id"]] = key
            keys = row.get("agentMatchKeys")
            if (agent_identities is not None and node["kind"] == "Гипервизор" and now - stamp <= MAX_AGE
                    and observation_is_fresh(row.get("agentMatchCheckedAt"), now)
                    and any(s["name"] == "Proxmox" and s["label"] == "В сети" and not s["stale"] for s in node["sources"])
                    and isinstance(keys, list) and len(keys) == 1
                    and isinstance(keys[0], str) and re.fullmatch(r"mac-[0-9a-f]{12}", keys[0])):
                agent_keys[node["id"]] = {keys[0]}
                hypervisor_evidence[node["id"]] = _time(row["agentMatchCheckedAt"]).isoformat()
            elif (agent_identities is not None and node["kind"] != "Гипервизор"
                    and node["guest"] and node["vmid"] is not None
                    and now - stamp <= MAX_AGE
                    and any(s["name"] == "Proxmox" and s["label"] == "Запущена" and not s["stale"] for s in node["sources"])):
                if row.get("agentMatchConflict") is True:
                    agent_conflicts.add(node["id"])
                if isinstance(keys, list):
                    valid = {key for key in keys[:32] if isinstance(key, str) and re.fullmatch(r"mac-[0-9a-f]{12}", key)}
                    if valid:
                        agent_keys[node["id"]] = valid
                        enrollment = row.get("agentEnrollmentId")
                        if isinstance(enrollment, str) and GUEST_ENROLLMENT_ID.fullmatch(enrollment):
                            agent_enrollments[node["id"]] = enrollment
    for node_id, node in nodes.items():
        observer = node.get("firmware", {}).get("observerId")
        if observer and (observer == node_id or nodes.get(observer, {}).get("kind") != NETWORK_KINDS[0]):
            node.pop("firmware")
        root = node.get("stpRoot", {})
        root_id = root.get("rootDeviceId")
        if root_id == node_id or nodes.get(root_id, {}).get("kind") not in NETWORK_KINDS[:2]:
            root.pop("rootDeviceId", None)
        stp = node.get("stpRootPath", {})
        bridge_id = stp.get("bridgeDeviceId")
        if bridge_id == node_id or nodes.get(bridge_id, {}).get("kind") not in NETWORK_KINDS[:2]:
            stp.pop("bridgeDeviceId", None)
        remote_port = port_states.get(bridge_id, {}).get(port_label_key(stp.get("designatedPortName", "")), {})
        if "bridgeDeviceId" not in stp or remote_port.get("state") != "up":
            stp.pop("designatedPortName", None)
            stp.pop("designatedPortCheckedAt", None)
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
                max_age = PORT_EVIDENCE_MAX_AGE.get(source, MAX_AGE)
                evidence.append({
                    "a": _text(report.get("a"), 64), "b": _text(report.get("b"), 64), "source": source,
                    "at": observed.isoformat() if observed else None,
                    "confirmed": report.get("confirmed") is True and (
                        source == "GitHub" or observation_is_fresh(report.get("at"), now, max_age=max_age)),
                })
                if source == "GitHub" and (references := inventory_link_sources(report.get("inventorySources"))):
                    evidence[-1]["inventorySources"] = references
                learned = report.get("learnedEndpoint")
                if (edge["kind"] == "Путь по MAC-таблице" and evidence[-1]["confirmed"]
                        and source in {"netctl FDB", "netctl FDB + Proxmox"} and isinstance(learned, dict)):
                    switch_id = _text(learned.get("switchId"), 160)
                    device_id = _text(learned.get("deviceId"), 160)
                    mac = learned.get("mac")
                    side = "a" if edge["a"] == switch_id else "b"
                    if ({switch_id, device_id} == {edge["a"], edge["b"]}
                            and nodes[switch_id]["kind"] == NETWORK_KINDS[0]
                            and evidence[-1][side] and isinstance(mac, str)
                            and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)):
                        evidence[-1]["learnedEndpoint"] = {"switchId": switch_id, "deviceId": device_id, "mac": mac}
                        if source == "netctl FDB" and not evidence[-1]["b" if side == "a" else "a"]:
                            address = _network_address(report.get("managementAddress"))
                            if address and ":" not in address and "/" not in address:
                                evidence[-1]["managementAddress"] = address
                paired = edge["kind"] == "Сетевое соединение" or source in {RECIPROCAL_MAC_SOURCE, "netctl FDB + Proxmox"}
                observed_attachment = (source in {"netctl FDB", "MikroTik · ARP", "MikroTik · ARP + FDB"}
                                       and evidence[-1]["confirmed"])
                both_ports = paired and evidence[-1]["a"] and evidence[-1]["b"]
                if (source == "netctl FDB + Proxmox" and both_ports and evidence[-1]["confirmed"]
                        and {nodes[edge["a"]]["kind"], nodes[edge["b"]]["kind"]} == {"Гипервизор", NETWORK_KINDS[0]}):
                    address = _network_address(report.get("managementAddress"))
                    if address and ":" not in address and "/" not in address:
                        evidence[-1]["managementAddress"] = address
                if ((source, edge["kind"]) in {("MikroTik · ARP + FDB", "Путь по MAC-таблице"),
                                              ("MikroTik · ARP", "Транзитный сегмент")} and observed_attachment
                        and nodes[edge["a"]]["kind"] == NETWORK_KINDS[1] and evidence[-1]["a"] and not evidence[-1]["b"]):
                    address = _network_address(report.get("managementAddress"))
                    if address and ":" not in address and "/" not in address:
                        evidence[-1]["managementAddress"] = address
                if (edge["kind"] == "Сетевое соединение" and both_ports and evidence[-1]["confirmed"]
                        and all(evidence[-1][side].strip().casefold() not in {"", "unknown", "неизвестно", "-"}
                                for side in ("a", "b"))):
                    if source == "GitHub":
                        evidence[-1]["pairEvidence"] = "verified_inventory"
                    elif source in CURRENT_PORT_PAIR_SOURCES:
                        evidence[-1]["pairEvidence"] = "current"
                    adapter = report.get("windowsAdapter")
                    if source == ENDPOINT_PAIR_SOURCE and isinstance(adapter, dict):
                        index = adapter.get("ifIndex")
                        adapter_at, switch_at = (_time(adapter.get(key)) for key in ("checkedAt", "switchCheckedAt"))
                        if (type(index) is int and 0 < index <= 0xFFFFFFFF and adapter_at and switch_at
                                and min(adapter_at, switch_at) == observed
                                and max(adapter_at, switch_at) <= now):
                            evidence[-1]["windowsAdapter"] = {
                                "ifIndex": index, "checkedAt": adapter_at.isoformat(), "switchCheckedAt": switch_at.isoformat(),
                            }
                if source == "SNMP LACP + ARP":
                    polled = _time(report.get("lacpPolledAt", report.get("at")))
                    evidence[-1]["confirmed"] = bool(evidence[-1]["confirmed"] and observed and polled
                                                     and observed <= polled <= now
                                                     and now - polled <= LACP_HEALTH_MAX_AGE
                                                     and now - observed <= LACP_PARTNER_MAX_AGE)
                    if edge["kind"] == "Сетевое соединение" and both_ports and evidence[-1]["confirmed"]:
                        _attach_lacp_port_states(evidence[-1], edge, nodes, port_states)
                        if "lacp" in evidence[-1]:
                            evidence[-1]["lacp"]["polledAt"] = polled.isoformat()
                            address = _network_address(report.get("managementAddress"))
                            if address and ":" not in address and "/" not in address:
                                evidence[-1]["managementAddress"] = address
                    evidence[-1]["confirmed"] = "lacp" in evidence[-1]
                elif edge["kind"] == "Сетевое соединение" or both_ports or source == SHARED_LLDP_SOURCE or observed_attachment:
                    states = {}
                    for side in ("a", "b"):
                        port = port_states.get(edge[side], {}).get(port_label_key(evidence[-1][side]))
                        if port and (port["state"] != "unknown" or "proxmoxActive" in port):
                            states[side] = port
                    if states:
                        evidence[-1]["portStates"] = states
                    if (edge["kind"] == "Сетевое соединение"
                            or (source == SHARED_LLDP_SOURCE and evidence[-1]["confirmed"])
                            or (observed_attachment and "learnedEndpoint" in evidence[-1])):
                        lldp_peers = {}
                        for side, peer_side in (("a", "b"), ("b", "a")):
                            port = states.get(side, {})
                            alternate_chassis = (report.get("sharedLldpChassis")
                                                 if source == SHARED_LLDP_SOURCE and side == "a" else None)
                            matches = [
                                {"localPort": port["name"], "checkedAt": port["lldpCheckedAt"],
                                 **{key: neighbor[key] for key in ("chassisId", "portId", "portIdSubtype") if key in neighbor}}
                                for neighbor in port.get("lldpNeighbors", [])
                                if neighbor.get("inventoryDeviceId") == edge[peer_side]
                                or (alternate_chassis and not neighbor.get("inventoryDeviceId")
                                    and neighbor.get("chassisId") == alternate_chassis)
                            ]
                            if matches:
                                lldp_peers[side] = matches
                        if lldp_peers:
                            evidence[-1]["lldpPeers"] = lldp_peers
                if source == RECIPROCAL_MAC_SOURCE and evidence[-1]["confirmed"]:
                    stp_paths = []
                    for side, port in evidence[-1].get("portStates", {}).items():
                        node_id = edge[side]
                        stp = nodes[node_id].get("stpRootPath", {})
                        if port["state"] == "up" and stp.get("localPort") == port["name"]:
                            stp_paths.append({**stp, "deviceId": node_id})
                    if stp_paths:
                        evidence[-1]["stpPaths"] = stp_paths
                if evidence[-1].get("pairEvidence") == "verified_inventory":
                    audit = _audit_link_vlans(report.get("expectedVlans"), evidence[-1].get("portStates", {}), now)
                    if audit:
                        evidence[-1]["vlanAudit"] = audit
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
                    if (evidence[-1]["confirmed"] and evidence[-1]["a"]
                            and virtual.get("bridgeVlanMode") in BRIDGE_VLAN_CONFIG_MODES):
                        evidence[-1]["virtual"]["bridgeVlanMode"] = virtual["bridgeVlanMode"]
                    if (evidence[-1]["confirmed"] and not evidence[-1]["virtual"]["linkDisabled"]
                            and (ipv4_observations := _guest_ipv4_observations(virtual.get("ipv4Observations"), now))):
                        evidence[-1]["virtual"]["ipv4Observations"] = ipv4_observations
                    if (evidence[-1]["confirmed"] and not evidence[-1]["virtual"]["linkDisabled"]
                            and (reading := _public_arp_details(virtual.get("arpDiagnostic")))):
                        arp = virtual["arpDiagnostic"]
                        at, identity = _time(arp.get("checkedAt")), _time(arp.get("identityCheckedAt"))
                        if (at and identity and observation_is_fresh(arp["checkedAt"], now, max_age=SERVICE_PROBE_MAX_AGE)
                                and observation_is_fresh(arp["identityCheckedAt"], at)):
                            evidence[-1]["virtual"]["arpDiagnostic"] = {
                                **reading, "checkedAt": at.isoformat(), "identityCheckedAt": identity.isoformat(),
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
            if edge["source"] == PPPOE_SOURCE:
                confirmed = confirmed and observation_is_fresh(row.get("observedAt"), now, max_age=SERVICE_PROBE_MAX_AGE)
            elif edge["source"] == "SNMP LACP + ARP":
                confirmed = confirmed and any(report["confirmed"] for report in evidence)
            elif edge["source"] in {"netctl", "LLDP UI_VPN", "LLDP · двустороннее", "netctl FDB",
                                  "netctl FDB + Proxmox", "Proxmox", "MikroTik · ARP",
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
    _mark_conflicting_port_pairs(nodes, links)
    _attach_management_vlan_observations(nodes, links, now)
    if db is not None and endpoint_keys and now - stamp <= MAX_AGE:
        _attach_endpoint_presence(db, endpoint_keys, nodes, now)
    _attach_address_aliases(nodes, links)
    if lacp_expectations:
        _attach_lacp_health(nodes, lacp_expectations, links, port_states, now)
    _attach_guest_observer_measurements(nodes, links)
    _attach_acti_backup_job(nodes, links)
    _attach_backup_scope(nodes)
    _attach_management_ports(nodes, links)
    _map_statuses(nodes, links)
    lacp_services = defaultdict(set)
    for edge in links:
        host, service = nodes[edge["a"]], nodes[edge["b"]]
        if "lacpHealth" in host and service["kind"] == "Сервис" and _is_service_attachment(edge):
            lacp_services[host["id"]].add(service["id"])
    for host_id, service_ids in lacp_services.items():
        hosted = [_attachment_node(nodes[key]) for key in sorted(service_ids)[:24]]
        for report in nodes[host_id]["lacpHealth"]:
            report.update(hostedServiceTotal=len(service_ids), hostedServices=hosted)
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
    device_presences = []
    if agent_enrollments and load_agent_presence is not None:
        try:
            device_presences = load_agent_presence()
        except EndpointPlatformServiceError:
            pass
    attachments = {}
    has_affected_ports = any(
        any(port.get("telemetry", {}).get(key, 0) for key in PORT_COUNTER_KEYS)
        for node in nodes.values() for port in node["ports"]
    )
    topology_pairs = _topology_port_pairs(nodes, links) if (
        include_guest_attachments or include_port_pairs or has_affected_ports or any(
        "rxSilence" in port
        for node in nodes.values() for port in node["ports"]
    )) else None
    counter_service_ports = None
    if include_guest_attachments:
        attachments = _map_attachments(nodes, links, now, endpoint_keys=endpoint_keys)
        _, inventory_pairs, _, pending, current_pairs = topology_pairs
        lacp_gaps = _lacp_partner_interface_gaps(nodes)
        attachments.update(
            guestSwitchAttachments=_guest_switch_attachments(attachments["guestAttachments"]),
            **_confirmed_guest_uplinks(attachments["guestAttachments"]),
            **_running_without_network(nodes, attachments["guestAttachments"]),
            inventoryPairs=inventory_pairs,
            currentPortPairTotal=len(current_pairs),
            currentPortPairs=current_pairs[:64],
            **_summarize_pair_measurement_gaps(current_pairs),
            sharedPorts=_summarize_shared_ports(pending),
            pendingPortPairTotal=len(pending),
            pendingPortPairLinkCounts=dict(Counter(row["linkHealth"]["state"] for row in pending)),
            pendingPortPairs=[
                {**{key: row[key] for key in ("a", "b", "nameA", "nameB", "portA", "portB")},
                 "observedPaths": [
                     {key: reading[key] for key in ("portA", "portB", "source", "checkedAt")}
                     for reading in row["observedPaths"]
                 ],
                 "observedSources": sorted({reading["source"] for reading in row["observedPaths"]}),
                 "observedSourceTimes": {
                     reading["source"]: reading["checkedAt"]
                     for reading in sorted(row["observedPaths"], key=lambda item: item["checkedAt"] or "")
                     if reading["checkedAt"]
                 },
                 "identifiedPeerSides": row["identifiedPeerSides"],
                 "confirmationGaps": row["confirmationGaps"],
                 "linkHealth": row["linkHealth"],
                 "stpPaths": list({
                     path["deviceId"]: path
                     for reading in row["observedPaths"] for path in reading.get("stpPaths", [])
                 }.values()),
                 "lldpPortIds": sorted({peer["portId"] for peers in row.get("lldpPeers", {}).values()
                                        for peer in peers if peer.get("portId")}),
                 "portObservations": {
                     side: {key: port[key] for key in ("name", "state", "speedBps", "speedCheckedAt", "checkedAt", "stateSince", "rxSilence",
                                                       "fdbLearned", "lldpPort", "telemetry", "rxErrorCounters",
                                                       "linkMode", "transceiver") if key in port}
                     for side, port in row.get("portObservations", {}).items()
                 },
                 **{key: row[key] for key in ("archivedPortSides", "archivedPortAt", "inventoryPortSides", "inventorySources",
                                             "inventoryPeerPorts", "lldpPeers", "lldpObservations", "unconfirmedLldpCandidates", "multiMacPortSides",
                                             "stpBridgeConnections", "stpBridgeMacObservations", "arpDiagnostics",
                                             "trafficComparison", "stoppedEndpoints", "conflictingPortSides",
                                             "logicalPeerInterfaces", "lldpNoRxSides", "portHistory") if key in row}}
                for row in pending[:64]
            ],
            lacpPartnerInterfaceGapTotal=len(lacp_gaps),
            lacpPartnerInterfaceGaps=lacp_gaps[:64],
        )
    elif include_service_ports or (include_counter_service_counts and has_affected_ports):
        mapped = _map_attachments(nodes, links, now, endpoint_keys=endpoint_keys)
        counter_service_ports = mapped["servicePorts"]
        if include_service_ports:
            attachments["servicePorts"] = counter_service_ports
        if include_service_ports and include_port_pairs:
            attachments["guestSwitchAttachments"] = _guest_switch_attachments(mapped["guestAttachments"])
    if include_port_pairs:
        _, inventory_pairs, _, pending, current_pairs = topology_pairs
        attachments.update(currentPortPairs=current_pairs, inventoryPairs=inventory_pairs, pendingPortPairs=pending,
                           lacpPartnerInterfaceGaps=_lacp_partner_interface_gaps(nodes))
    selected_agent_node = agent_node_id
    if agent_identities is not None and nodes.get(agent_node_id, {}).get("kind") == "Сервис":
        hosts = {edge["a"] for edge in links if edge["b"] == agent_node_id and _is_service_attachment(edge)}
        if len(hosts) == 1:
            selected_agent_node, = hosts
    return {
        **empty, "availability": "stale" if now - stamp > MAX_AGE else "ready",
        "snapshotAt": stamp.isoformat(), "nodes": list(nodes.values()), "links": links,
        "portCounterAudit": _summarize_port_counters(
            nodes, topology_pairs, service_ports=attachments.get("servicePorts", counter_service_ports)),
        "portRxSilenceAudit": _summarize_port_rx_silence(nodes, topology_pairs[3] if topology_pairs else []),
        "clusterId": cluster_id, "nodeOrder": node_ids("nodeOrder"),
        "overviewGuests": node_ids("overviewGuests"),
        "git": revision if re.fullmatch(r"[0-9a-f]{40}", revision) else "",
        **({"collectionIssues": issues} if issues else {}),
        **({"agentAudit": _summarize_agent_audit(
            nodes, agent_keys, agent_conflicts, agent_identities, now, snapshot_fresh=now - stamp <= MAX_AGE,
            enrollments=agent_enrollments, device_presences=device_presences, load_agent_profiles=load_agent_profiles,
            hypervisor_evidence=hypervisor_evidence, selected_node=selected_agent_node,
        )}
           if agent_identities is not None else {}),
        **attachments,
    }
