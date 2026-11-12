from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import threading
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, TypeAdapter, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import write_audit
from .models import WebAuditLog
from .network_actions import acquire_network_action
from .network_capture_store import create_capture
from .network_probe_profiles import ProfileId, load_probe_profiles
from .network_throughput import run_throughput
from .netctl_client import NetctlError, run_netctl

SOURCE_PATTERN = r"^[A-Za-z0-9._-]+$"
ASSET_PATTERN = r"^[^\x00-\x1f\x7f]+$"
IP_ROUTE_PATH = "/usr/sbin/ip"
TRACEPATH_PATH = "/usr/bin/tracepath"
TRACE_MAX_HOPS = 12
TRACE_TIMEOUT_SECONDS = 18
ROUTE_FIELDS = ("dst", "gateway", "dev", "prefsrc", "src", "table", "type", "metric")

CHECKS = (
    {"check": "linux_route", "title": "Маршрут VPN-сервера", "active": False},
    {"check": "asset_route", "title": "Маршрут от сетевого актива", "active": False},
    {"check": "trace_route", "title": "Трассировка до наблюдаемого узла", "active": True},
    {"check": "source_test", "title": "Связь с источником Network Observer", "active": True},
    {"check": "iperf3", "title": "Замер пропускной способности iperf3", "active": True},
    {"check": "pcap_capture", "title": "Захват PCAP для Wireshark", "active": True},
    {"check": "loop_check", "title": "Признаки L2-петель", "active": False},
)
AUDIT_PREFIX = "network-check-"
_throughput_lock = threading.Lock()


class CheckInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LinuxRouteCheck(CheckInput):
    check: Literal["linux_route"]
    destination: IPvAnyAddress


class AssetRouteCheck(CheckInput):
    check: Literal["asset_route"]
    asset_key: str = Field(min_length=1, max_length=255, pattern=ASSET_PATTERN)
    destination: IPvAnyAddress
    protocol: Literal["tcp", "udp", "icmp"] = "tcp"
    port: int | None = Field(default=None, ge=1, le=65535)

    @model_validator(mode="after")
    def validate_protocol_port(self):
        if self.protocol == "icmp" and self.port is not None:
            raise ValueError("ICMP does not use ports")
        return self


class SourceTestCheck(CheckInput):
    check: Literal["source_test"]
    source: str = Field(min_length=1, max_length=128, pattern=SOURCE_PATTERN)


class TraceRouteCheck(CheckInput):
    check: Literal["trace_route"]
    destination: ipaddress.IPv4Address


class IperfCheck(CheckInput):
    check: Literal["iperf3"]
    profile: ProfileId
    direction: Literal["send", "receive"] = "send"


class CaptureCheck(CheckInput):
    check: Literal["pcap_capture"]
    profile: ProfileId


class LoopCheck(CheckInput):
    check: Literal["loop_check"]
    source: str | None = Field(default=None, max_length=128, pattern=SOURCE_PATTERN)


NetworkCheck = Annotated[
    LinuxRouteCheck | AssetRouteCheck | SourceTestCheck | TraceRouteCheck | IperfCheck | CaptureCheck | LoopCheck,
    Field(discriminator="check"),
]
NETWORK_CHECK_INPUT = TypeAdapter(NetworkCheck)

CHECK_STATUS_LABELS = {
    "route_found": "Маршрут найден",
    "no_route": "Маршрут не найден",
    "allowed": "Политика разрешает маршрут",
    "blocked": "Политика блокирует маршрут",
    "unknown": "Недостаточно подтверждённых данных",
    "ok": "Источник ответил",
    "not_found": "Объект не найден или отключён",
    "unavailable": "Проверка недоступна",
    "failed": "Проверка завершилась ошибкой",
    "reached": "Назначение ответило на трассировку",
    "partial": "Получена неполная трассировка",
    "not_monitored": "Узел не входит в мониторинг",
    "rate_limited": "Повторите эту проверку через 5 минут",
    "measured": "Замер пропускной способности завершён",
    "captured": "Захват сохранён",
    "empty_capture": "Захват завершён без совпавших пакетов",
    "busy": "Проверка занята. Повторите позже",
    "timeout": "Истекло время проверки",
    "suspected_loop": "Есть признаки возможной L2-петли",
    "mac_flapping": "Обнаружено повторное перемещение MAC",
    "no_evidence": "Признаки петли не выявлены в наблюдениях",
    "insufficient_data": "Для оценки петель недостаточно наблюдений",
    "no_sources": "Нет подходящих источников наблюдений",
}


def lookup_linux_route(destination: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict:
    address = str(destination)
    if "%" in address:
        return {"status": "unavailable", "result": {}}
    try:
        completed = subprocess.run(
            [IP_ROUTE_PATH, "-j", f"-{destination.version}", "route", "get", address],
            capture_output=True, text=True, timeout=5, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable", "result": {}}
    if completed.returncode:
        error = completed.stderr.lower()
        absent = "network is unreachable" in error or "no route to host" in error
        return {"status": "no_route" if absent else "failed", "result": {}}
    try:
        rows = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "failed", "result": {}}
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {"status": "failed", "result": {}}
    route = {key: rows[0][key] for key in ROUTE_FIELDS if key in rows[0]}
    return {"status": "route_found", "result": route}


def _asset_route(check: AssetRouteCheck) -> dict:
    args = ["path", "explain", f"--asset-key={check.asset_key}",
            f"--destination={check.destination}", "--protocol", check.protocol]
    if check.port is not None:
        args.extend(("--port", str(check.port)))
    try:
        result = run_netctl(args, timeout=15).get("explanation")
    except NetctlError as exc:
        return {"status": _netctl_lookup_status(exc, "asset not found"), "result": {}}
    except (OSError, UnicodeError):
        return {"status": "unavailable", "result": {}}
    if not isinstance(result, dict):
        return {"status": "unavailable", "result": {}}
    return {"status": result.get("verdict", "unknown"), "result": result}


def _source_test(check: SourceTestCheck) -> dict:
    try:
        sources = run_netctl(["sources", "list"], timeout=10).get("sources", [])
    except (NetctlError, OSError, UnicodeError):
        return {"status": "unavailable", "result": {}}
    if not any(row.get("name") == check.source and row.get("enabled") for row in sources if isinstance(row, dict)):
        return {"status": "not_found", "result": {}}
    try:
        result = run_netctl(["sources", "test", "--no-update", "--", check.source], timeout=35)
    except (NetctlError, OSError, UnicodeError):
        return {"status": "failed", "result": {}}
    reading = result.get("result", {})
    status = reading.get("status", result.get("status")) if isinstance(reading, dict) else result.get("status")
    return {"status": "ok" if status == "ok" else "failed", "result": {}}


def host_availability_action_error(host: object, valid_ip: str) -> tuple[int, str] | None:
    if not isinstance(host, dict) or str(host.get("ip") or "") != valid_ip:
        return 404, "host target not found"
    availability = host.get("availability")
    if not isinstance(availability, dict) or str(availability.get("state") or "") == "not_monitored":
        return 403, "host target is not monitored"
    return None


def _netctl_lookup_status(exc: NetctlError, not_found_message: str) -> str:
    try:
        error = json.loads(exc.stdout or "{}")
    except (TypeError, ValueError):
        return "unavailable"
    return "not_found" if isinstance(error, dict) and error.get("message") == not_found_message else "unavailable"


def trace_linux_route(destination: ipaddress.IPv4Address) -> dict:
    address = str(destination)
    try:
        host = run_netctl(["hosts", "inspect", address, "--availability-only"], timeout=10).get("host")
    except NetctlError as exc:
        return {"status": _netctl_lookup_status(exc, "host not found"), "result": {}}
    except (OSError, UnicodeError):
        return {"status": "unavailable", "result": {}}
    denial = host_availability_action_error(host, address)
    if denial is not None:
        return {"status": "not_found" if denial[0] == 404 else "not_monitored", "result": {}}
    timed_out = False
    returncode = 0
    try:
        completed = subprocess.run(
            [TRACEPATH_PATH, "-4", "-n", "-m", str(TRACE_MAX_HOPS), address],
            capture_output=True, text=True, timeout=TRACE_TIMEOUT_SECONDS, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        output = completed.stdout
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("ascii", errors="replace")
        timed_out = True
    except OSError:
        return {"status": "unavailable", "result": {}}
    hops = []
    reached = False
    for line in output.splitlines():
        match = re.match(r"^\s*(\d{1,2})\??:\s+(\S+)(.*)$", line)
        if match is None or not 1 <= int(match[1]) <= TRACE_MAX_HOPS:
            continue
        try:
            responder = str(ipaddress.IPv4Address(match[2]))
        except ValueError:
            if match[2] != "no" or match[3].strip() != "reply":
                continue
            responder = None
        delay = re.search(r"\b(\d+\.\d+)ms\b", match[3]) if responder else None
        hops.append({"hop": int(match[1]), "address": responder, "rtt_ms": float(delay[1]) if delay else None})
        reached |= responder == address and re.search(r"\breached\b", match[3]) is not None
    status = "reached" if reached else ("failed" if returncode and not hops else "partial")
    return {"status": status, "result": {"hops": hops, "timed_out": timed_out, "max_hops": TRACE_MAX_HOPS}}


def loop_diagnostics(source: str | None) -> dict:
    args = ["switches", "loops"]
    if source:
        args.append(f"--source={source}")
    try:
        result = run_netctl(args, timeout=15).get("loops")
    except (NetctlError, OSError, UnicodeError):
        return {"status": "unavailable", "result": {}}
    if not isinstance(result, dict):
        return {"status": "unavailable", "result": {}}
    return {"status": result.get("status", "insufficient_data"), "result": result}


def _iperf_check(check: IperfCheck) -> dict:
    profile = load_probe_profiles().throughput.get(check.profile)
    if profile is None:
        return {"status": "not_found", "result": {}}
    if not _throughput_lock.acquire(blocking=False):
        return {"status": "busy", "result": {}}
    try:
        reading = run_throughput(
            profile.peer, profile.port, check.direction,
            duration_seconds=profile.duration_seconds, bitrate_mbps=profile.bitrate_mbps,
        )
        status = "measured" if reading["status"] == "ok" else reading["status"]
        result = {
            "point": "vpn_server",
            **profile.model_dump(),
            "direction": check.direction,
            **(reading.get("result") or {}),
        }
        return {"status": status, "result": result}
    finally:
        _throughput_lock.release()


def _capture_check(check: CaptureCheck, owner: str | None) -> dict:
    profile = load_probe_profiles().capture.get(check.profile)
    if profile is None or owner is None:
        return {"status": "not_found", "result": {}}
    return create_capture(owner, profile)


def execute_network_check(check: NetworkCheck, *, allowed: bool = True, capture_owner: str | None = None) -> dict:
    if isinstance(check, SourceTestCheck):
        target = check.source
    elif isinstance(check, IperfCheck):
        target = f"{check.profile} · {check.direction}"
    elif isinstance(check, CaptureCheck):
        target = check.profile
    elif isinstance(check, LoopCheck):
        target = check.source or "Все коммутаторы"
    elif isinstance(check, AssetRouteCheck):
        target = f"{check.asset_key} → {check.destination}"
    else:
        target = str(check.destination)
    if not allowed:
        evidence = {"status": "rate_limited", "result": {}}
    elif isinstance(check, LinuxRouteCheck):
        evidence = lookup_linux_route(check.destination)
    elif isinstance(check, AssetRouteCheck):
        evidence = _asset_route(check)
    elif isinstance(check, TraceRouteCheck):
        evidence = trace_linux_route(check.destination)
    elif isinstance(check, IperfCheck):
        evidence = _iperf_check(check)
    elif isinstance(check, CaptureCheck):
        evidence = _capture_check(check, capture_owner)
    elif isinstance(check, LoopCheck):
        evidence = loop_diagnostics(check.source)
    else:
        evidence = _source_test(check)
    return {"check": check.check, "target": target, "checked_at": datetime.now(UTC).isoformat(), **evidence}


def run_audited_network_check(db: Session, request: Request, actor: str, check: NetworkCheck) -> dict:
    action = AUDIT_PREFIX + check.check
    active = isinstance(check, (SourceTestCheck, TraceRouteCheck, IperfCheck, CaptureCheck))
    owner = ("service:" if request.url.path.startswith("/api/v1/") else "user:") + actor
    throttle_action = f"{action}:{check.profile}:{check.direction}" if isinstance(check, IperfCheck) else action
    allowed = not active or acquire_network_action(db, owner, throttle_action, datetime.now(UTC)).accepted
    result = execute_network_check(check, allowed=allowed, capture_owner=owner)
    write_audit(db, request, actor, action, result["status"], result["target"])
    return result


def interface_history_args(source: str, interface: str) -> list[str]:
    return ["interfaces", "diagnostics", f"--source={source}", f"--interface={interface}"]


def list_network_check_runs(db: Session, actor: str, limit: int) -> list[dict]:
    actions = [AUDIT_PREFIX + item["check"] for item in CHECKS]
    rows = db.scalars(
        select(WebAuditLog)
        .where(WebAuditLog.actor == actor, WebAuditLog.action.in_(actions))
        .order_by(WebAuditLog.ts.desc(), WebAuditLog.id.desc())
        .limit(limit)
    )
    return [{
        "check": row.action.removeprefix(AUDIT_PREFIX),
        "status": row.result,
        "target": row.message,
        "checked_at": row.ts.replace(tzinfo=row.ts.tzinfo or UTC).isoformat(),
        "request_id": row.request_id,
    } for row in rows]
