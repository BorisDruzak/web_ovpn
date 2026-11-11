from __future__ import annotations

import json
import math
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_SNAPSHOT_BYTES = 1_000_000
MAX_AGE = timedelta(minutes=25)
STATES = ("critical", "warn", "ok", "unknown")
NETWORK_KINDS = ("Коммутатор", "Маршрутизатор", "Точка доступа", "Сетевое устройство")
REACHABILITY_STATES = ("reachable", "unreachable", "stopped")
SERVICE_LINKS = {"Размещение", "Цель проверки"}
REQUIRED_SERVICE_CHECKS = {
    "role:directum": "directumrx_active",
    "role:file_server": "smb_active",
    "role:active_directory": "ntds_active",
}
PUBLIC_PROPERTIES = {
    "Модель", "VMID", "Размещение по GitHub", "Источник сбора",
    "Порты (линк поднят / всего)", "Записи MAC-таблицы", "Соседство LLDP",
    "Подключение", "Привязка", "Кворум", "Узлы", "Состояние узла",
    "Привязка Directum", "Состояние ВМ", "Узел Proxmox", "Память (выделено)",
    "Память по Proxmox", "CPU по Proxmox",
}
RUNTIME_PROPERTIES = {
    "Состояние ВМ", "Состояние узла", "Кворум", "Память по Proxmox", "CPU по Proxmox",
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
    aliases = row.get("aliases")
    return {
        **{key: _text(row.get(key)) for key in ("id", "name", "kind", "site", "origin", "pveHost")},
        "guest": row.get("guest") is True,
        "vmid": row.get("vmid") if type(row.get("vmid")) is int else None,
        "aliases": [_text(value) for value in aliases[:12] if isinstance(value, str)] if isinstance(aliases, list) else [],
        "status": next((state for state in STATES if any(source["status"] == state for source in fresh)), "unknown"),
        "reachability": _public_reachability(row.get("reachability"), now),
        "sources": sources,
        "properties": properties,
        "checks": [
            {"name": _text(check.get("name"), 64), "status": _state(check.get("status")) if fresh else "unknown",
             "observed": _number(check.get("observed")), "latency": _number(check.get("latency"))}
            for check in _rows(row.get("checks"), 80)
        ],
    }


def _map_statuses(nodes: dict, links: list[dict]) -> None:
    services = {key: set() for key in nodes}
    for edge in links:
        if edge["confirmed"] and edge["kind"] in SERVICE_LINKS and nodes[edge["b"]]["kind"] == "Сервис":
            services[edge["a"]].add(edge["b"])

    for key, check_name in REQUIRED_SERVICE_CHECKS.items():
        node = nodes.get(key)
        if not node or node["reachability"]["state"] != "unknown":
            continue
        observer = next((source for source in node["sources"]
                         if source["name"] == "Server Observer" and not source["stale"]), None)
        if observer and any(check["name"] == check_name and check["status"] == "critical" for check in node["checks"]):
            node["reachability"] = {
                "state": "unreachable", "source": "Server Observer", "method": "Состояние обязательной службы",
                "checkedAt": observer["at"], "stale": False,
            }

    for key, node in nodes.items():
        states = {peer: nodes[peer]["reachability"]["state"] for peer in sorted(services[key])}
        unavailable = [peer for peer, state in states.items() if state in {"unreachable", "stopped"}]
        unknown = [peer for peer, state in states.items() if state == "unknown"]
        state = node["reachability"]["state"]
        node["serviceAvailability"] = {"unavailable": unavailable, "unknown": unknown}
        if state in {"unreachable", "stopped"}:
            node["mapStatus"] = "critical"
        elif state == "reachable" and unavailable:
            node["mapStatus"] = "warn"
        elif state == "reachable" and not unknown:
            node["mapStatus"] = "ok"
        else:
            node["mapStatus"] = "unknown"


def load_infrastructure_map(path: Path, now: datetime | None = None) -> dict:
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
    for row in _rows(raw.get("nodes"), 600):
        node = _public_node(row, now)
        if node["id"] and node["name"]:
            nodes.setdefault(node["id"], node)
    links = []
    for row in _rows(raw.get("links"), 2400):
        edge = {key: _text(row.get(key)) for key in ("a", "b", "kind", "source", "details")}
        if edge["a"] in nodes and edge["b"] in nodes and edge["a"] != edge["b"]:
            links.append({**edge, "confirmed": row.get("confirmed") is True})
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
