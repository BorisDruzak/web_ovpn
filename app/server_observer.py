"""Read-only server-health collection plus redacted snapshot helpers.

Runtime topology is accepted only from the local collector configuration and is
stripped before a snapshot is persisted or returned to the web application.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from time import perf_counter
from typing import Any, Callable


ALLOWED_ROLES = frozenset(
    {
        "file_server",
        "directum",
        "active_directory",
        "nextcloud",
        "onlyoffice",
        "opnsense_dns",
    }
)
ALLOWED_SOURCES = frozenset({"gateway", "vpn_path", "target"})
STALE_AFTER = timedelta(minutes=15)
SSH_TIMEOUT_SECONDS = 20
OBSERVER_KEY_PATH = "/etc/openvpn-web/server-observer.key"
OBSERVER_KNOWN_HOSTS_PATH = "/etc/openvpn-web/server-observer.known_hosts"
SNAPSHOT_FILE_MODE = 0o640
SNAPSHOT_REPLACE_ATTEMPTS = 3
SNAPSHOT_REPLACE_RETRY_SECONDS = 0.01
_PUBLIC_CHECK_FIELDS = frozenset(
    {"name", "source", "status", "observed", "expected", "latency_ms", "error"}
)
_STATUS_PRIORITY = {"ok": 0, "warn": 1, "critical": 2, "error": 3}
_SAFE_CHECK_NAMES = re.compile(r"[a-z][a-z0-9_]{0,63}$")
_SAFE_SSH_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
_SAFE_SSH_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")
_SAFE_VALUE_STRINGS = frozenset(
    {
        "active",
        "inactive",
        "available",
        "unavailable",
        "installed",
        "maintenance",
        "needs_db_upgrade",
        "success",
        "failure",
    }
)
_SAFE_ERROR_CATEGORIES = frozenset(
    {"timeout", "transport", "parse", "unexpected_response"}
)

# These are fixed, read-only remote probes.  Runtime configuration may select a
# target and route, but can never supply a remote command.
def _powershell_probe(body: str, role: str) -> str:
    body = f"{body} # server_observer:{role}"
    encoded = base64.b64encode(body.encode("utf-16le")).decode("ascii")
    return f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"


_ROLE_PROBES = {
    "file_server": _powershell_probe(
        "$running={param([string]$n)"
        "$s=Get-Service -Name $n -ErrorAction SilentlyContinue;[bool]($s -and $s.Status -eq 'Running')};"
        "$e=Get-CimInstance Win32_LogicalDisk -Filter 'DeviceID=\"E:\"' -ErrorAction Stop;"
        "[pscustomobject]@{data_free_percent=[math]::Round(100*$e.FreeSpace/$e.Size,2);"
        "services=@{sshd=[bool](& $running 'sshd');smb=[bool](& $running 'LanmanServer')}}|ConvertTo-Json "
        "-Compress",
        "file_server",
    ),
    "directum": _powershell_probe(
        "$running={param([string]$n)"
        "$s=Get-Service -Name $n -ErrorAction SilentlyContinue;[bool]($s -and $s.Status -eq 'Running')};"
        "$c=Get-CimInstance Win32_LogicalDisk -Filter 'DeviceID=\"C:\"' -ErrorAction Stop;"
        "$logs=Get-ChildItem -LiteralPath 'C:\\rxdata\\logs' -File -Recurse -ErrorAction SilentlyContinue|"
        "Measure-Object -Property Length -Sum;"
        "[pscustomobject]@{free_percent=[math]::Round(100*$c.FreeSpace/$c.Size,2);"
        "log_bytes=[int64]$logs.Sum;"
        "services=@{directumrx=[bool](& $running 'DirectumRX');"
        "mongo=[bool](& $running 'MongoDB');rabbitmq=[bool](& $running 'RabbitMQ');"
        "redis=[bool](& $running 'Redis');iis=[bool](& $running 'W3SVC');dns=[bool](& $running 'DNS')}}|ConvertTo-Json "
        "-Compress",
        "directum",
    ),
    "active_directory": _powershell_probe(
        "$running={param([string]$n)"
        "$s=Get-Service -Name $n -ErrorAction SilentlyContinue;[bool]($s -and $s.Status -eq 'Running')};"
        "$c=Get-CimInstance Win32_LogicalDisk -Filter 'DeviceID=\"C:\"' -ErrorAction Stop;"
        "[pscustomobject]@{free_percent=[math]::Round(100*$c.FreeSpace/$c.Size,2);"
        "services=@{dns=[bool](& $running 'DNS');"
        "ntds=[bool](& $running 'NTDS');adws=[bool](& $running 'ADWS')};"
        "internal_dns=[bool](Resolve-DnsName localhost -ErrorAction SilentlyContinue);external_dns="
        "[bool](Resolve-DnsName example.com -ErrorAction SilentlyContinue)}|ConvertTo-Json -Compress",
        "active_directory",
    ),
    "nextcloud": (
        "php -r '$s=json_decode(shell_exec(\"curl -kfsS https://127.0.0.1/status.php\"),true);"
        "$d=static function($p){return round(100*disk_free_space($p)/disk_total_space($p),2);};"
        "$a=static function($n){return trim(shell_exec(\"systemctl is-active $n\"))===\"active\";};"
        "$p=static function(){return trim(shell_exec(\"pgrep -f php-fpm\"))!==\"\";};"
        "echo json_encode([\"installed\"=>$s[\"installed\"],\"maintenance\"=>$s[\"maintenance\"],"
        "\"needsDbUpgrade\"=>$s[\"needsDbUpgrade\"],\"free_percent\"=>$d(\"/\"),"
        "\"data_free_percent\"=>$d(\"/var/www/nextcloud\"),\"services\"=>[\"nginx\"=>$a(\"nginx\"),"
        "\"php\"=>$p(),\"postgresql\"=>$a(\"postgresql\"),\"redis\"=>$a(\"redis\")]]);' "
        "# server_observer:nextcloud"
    ),
    "onlyoffice": (
        "sh -c 'printf \"{\\\"free_percent\\\":%s,\\\"https_ok\\\":%s,\\\"services\\\":{\\\"docker\\\":%s,\\\"containerd\\\":%s}}\\n\" "
        "\"$(set -- $(df -P / | tail -1); used=$(echo \"$5\" | tr -d %); echo $((100-used)))\" "
        "\"$(curl -kfsS https://127.0.0.1/healthcheck | grep -qx true && printf true || printf false)\" "
        "\"$(systemctl is-active --quiet docker && printf true || printf false)\" "
        "\"$(systemctl is-active --quiet containerd && printf true || printf false)\"' "
        "# server_observer:onlyoffice"
    ),
    "opnsense_dns": (
        "sh -c 'printf \"{\\\"adguard_listener\\\":%s,\\\"adguard_query\\\":%s,\\\"services\\\":{\\\"unbound\\\":%s},"
        "\\\"internal_dns\\\":%s,\\\"external_dns\\\":%s}\\n\" "
        "\"$(pgrep -x AdGuardHome >/dev/null && printf true || printf false)\" "
        "\"$(drill @127.0.0.1 example.com >/dev/null 2>&1 && printf true || printf false)\" "
        "\"$(pgrep -x unbound >/dev/null && printf true || printf false)\" "
        "\"$(drill @127.0.0.1 localhost >/dev/null 2>&1 && printf true || printf false)\" "
        "\"$(drill @127.0.0.1 example.com >/dev/null 2>&1 && printf true || printf false)\"' "
        "# server_observer:opnsense_dns"
    ),
}

_ROLE_CHECK_NAMES = {
    "file_server": ("sshd_active", "smb_active", "data_disk_free"),
    "directum": (
        "c_disk_free", "rxdata_log_bytes", "directumrx_active", "mongo_active",
        "rabbitmq_active", "redis_active", "iis_active", "dns_active",
    ),
    "active_directory": (
        "c_disk_free", "dns_active", "ntds_active", "adws_active", "internal_dns",
        "external_dns",
    ),
    "nextcloud": (
        "nextcloud_status", "root_disk_free", "data_disk_free", "nginx_active",
        "php_active", "postgresql_active", "redis_active",
    ),
    "onlyoffice": ("https_healthcheck", "docker_active", "containerd_active", "root_disk_free"),
    "opnsense_dns": (
        "adguard_listener", "adguard_query", "unbound_active", "internal_dns", "external_dns",
    ),
}


def parse_utc(value: str) -> datetime:
    """Parse a UTC ISO-8601 timestamp ending in ``Z``."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp must be an ISO-8601 UTC value ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo != timezone.utc:
        raise ValueError("timestamp must be UTC")
    return parsed


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def load_runtime_config(path: Path) -> dict[str, Any]:
    """Load local-only topology after rejecting unsafe target definitions."""
    try:
        config = _require_mapping(json.loads(path.read_text(encoding="utf-8")), "config")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime config must be valid JSON") from exc
    _validate_runtime_config(config)
    return config


def _validate_runtime_config(config: dict[str, Any]) -> None:
    if set(config) != {"ssh_key", "tunnel_source", "targets"}:
        raise ValueError("config fields must be ssh_key, tunnel_source, and targets only")
    if config["ssh_key"] != OBSERVER_KEY_PATH:
        raise ValueError("config.ssh_key must use the canonical observer key")
    if not isinstance(config["tunnel_source"], str) or not config["tunnel_source"]:
        raise ValueError("config.tunnel_source must be a non-empty string")
    targets = config.get("targets")
    if not isinstance(targets, list):
        raise ValueError("config.targets must be a list")
    for target in targets:
        _validate_runtime_target(target)


def _validate_runtime_target(value: Any) -> None:
    target = _require_mapping(value, "target")
    if set(target) != {"role", "host", "user", "checks"}:
        raise ValueError("target fields must be role, host, user, and checks only")
    if target["role"] not in ALLOWED_ROLES:
        raise ValueError("target role is not allowed")
    if not isinstance(target["user"], str) or not _SAFE_SSH_USER.fullmatch(target["user"]):
        raise ValueError("target user must be a safe SSH destination component")
    if not isinstance(target["host"], str) or not _SAFE_SSH_HOST.fullmatch(target["host"]):
        raise ValueError("target host must be a safe SSH destination component")
    if not isinstance(target["checks"], list):
        raise ValueError("target checks must be a list")
    for check in target["checks"]:
        check_mapping = _require_mapping(check, "check")
        if set(check_mapping) != {"name", "source"}:
            raise ValueError("check fields must be name and source only")
        if not isinstance(check_mapping["name"], str) or not _SAFE_CHECK_NAMES.fullmatch(
            check_mapping["name"]
        ):
            raise ValueError("check name must be a safe identifier")
        if check_mapping.get("source") not in ALLOWED_SOURCES:
            raise ValueError("check source is not allowed")


def classify_disk(free_percent: float) -> str:
    if free_percent < 10:
        return "critical"
    if free_percent < 15:
        return "warn"
    return "ok"


def classify_directum_logs(size_bytes: int) -> str:
    if size_bytes >= 30 * 1024**3:
        return "critical"
    if size_bytes >= 20 * 1024**3:
        return "warn"
    return "ok"


def collect(
    config: dict[str, Any],
    runner: Callable[..., subprocess.CompletedProcess[str]],
    now: datetime,
) -> dict[str, Any]:
    """Collect one read-only, allow-listed JSON probe for every configured role."""
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")
    config = _require_mapping(config, "config")
    _validate_runtime_config(config)
    ssh_key = config.get("ssh_key")
    if ssh_key != OBSERVER_KEY_PATH:
        raise ValueError("config.ssh_key must use the canonical observer key")
    tunnel_source = config.get("tunnel_source")
    if not isinstance(tunnel_source, str) or not tunnel_source:
        raise ValueError("config.tunnel_source must be a non-empty string")
    targets = config.get("targets")
    if not isinstance(targets, list):
        raise ValueError("config.targets must be a list")

    collected_targets = []
    for configured_target in targets:
        _validate_runtime_target(configured_target)
        role = configured_target["role"]
        source = _probe_source(configured_target)
        command = _ssh_command(configured_target, ssh_key, tunnel_source, source)
        started = perf_counter()
        try:
            completed = runner(
                command,
                capture_output=True,
                text=True,
                shell=False,
                timeout=SSH_TIMEOUT_SECONDS,
                errors="replace",
            )
            latency_ms = round((perf_counter() - started) * 1000, 3)
            if not isinstance(completed, subprocess.CompletedProcess) or completed.returncode != 0:
                raise _ProbeFailure("transport")
            payload = _parse_probe_payload(completed.stdout)
            checks = _checks_from_payload(role, source, payload, latency_ms)
        except subprocess.TimeoutExpired:
            checks = _failure_checks(role, source, "timeout")
        except _ProbeFailure as exc:
            checks = _failure_checks(role, source, exc.category)
        except (OSError, subprocess.SubprocessError, TypeError):
            checks = _failure_checks(role, source, "transport")
        except Exception:
            checks = _failure_checks(role, source, "transport")
        collected_targets.append({"role": role, "checks": checks})

    timestamp = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return public_snapshot({"collected_at": timestamp, "targets": collected_targets})


class _ProbeFailure(Exception):
    def __init__(self, category: str) -> None:
        self.category = category


def _probe_source(target: dict[str, Any]) -> str:
    """Select the only source that affects the SSH transport for a role probe."""
    sources = [check["source"] for check in target["checks"]]
    if "vpn_path" in sources:
        return "vpn_path"
    return sources[0] if sources else "target"


def _ssh_command(
    target: dict[str, Any], ssh_key: str, tunnel_source: str, source: str
) -> list[str]:
    command = ["ssh", "-F", "/dev/null"]
    if source == "vpn_path":
        command.extend(["-b", tunnel_source])
    command.extend(
        [
            "-n",
            "-i",
            ssh_key,
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={OBSERVER_KNOWN_HOSTS_PATH}",
            "-o",
            "StrictHostKeyChecking=yes",
            "--",
            f"{target['user']}@{target['host']}",
            _ROLE_PROBES[target["role"]],
        ]
    )
    return command


def _parse_probe_payload(stdout: Any) -> dict[str, Any]:
    if not isinstance(stdout, str):
        raise _ProbeFailure("parse")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise _ProbeFailure("parse") from exc
    if not isinstance(payload, dict):
        raise _ProbeFailure("unexpected_response")
    return payload


def _checks_from_payload(
    role: str, source: str, payload: dict[str, Any], latency_ms: float
) -> list[dict[str, Any]]:
    _require_role_payload(role, payload)
    checks: list[dict[str, Any]] = []
    if role == "file_server":
        _append_service_check(checks, source, payload, "sshd", "sshd_active", latency_ms)
        _append_service_check(checks, source, payload, "smb", "smb_active", latency_ms)
        _append_disk_check(checks, source, payload, "data_free_percent", "data_disk_free", latency_ms)
    elif role == "directum":
        _append_disk_check(checks, source, payload, "free_percent", "c_disk_free", latency_ms)
        _append_log_check(checks, source, payload, latency_ms)
        for service, name in (
            ("directumrx", "directumrx_active"), ("mongo", "mongo_active"),
            ("rabbitmq", "rabbitmq_active"), ("redis", "redis_active"),
            ("iis", "iis_active"), ("dns", "dns_active"),
        ):
            _append_service_check(checks, source, payload, service, name, latency_ms)
    elif role == "active_directory":
        _append_disk_check(checks, source, payload, "free_percent", "c_disk_free", latency_ms)
        for service, name in (("dns", "dns_active"), ("ntds", "ntds_active"), ("adws", "adws_active")):
            _append_service_check(checks, source, payload, service, name, latency_ms)
        _append_boolean_check(checks, source, payload, "internal_dns", "internal_dns", latency_ms)
        _append_boolean_check(checks, source, payload, "external_dns", "external_dns", latency_ms)
    elif role == "nextcloud":
        _append_nextcloud_status(checks, source, payload, latency_ms)
        _append_disk_check(checks, source, payload, "free_percent", "root_disk_free", latency_ms)
        _append_disk_check(checks, source, payload, "data_free_percent", "data_disk_free", latency_ms)
        for service, name in (
            ("nginx", "nginx_active"), ("php", "php_active"),
            ("postgresql", "postgresql_active"), ("redis", "redis_active"),
        ):
            _append_service_check(checks, source, payload, service, name, latency_ms)
    elif role == "onlyoffice":
        _append_boolean_check(checks, source, payload, "https_ok", "https_healthcheck", latency_ms)
        _append_service_check(checks, source, payload, "docker", "docker_active", latency_ms)
        _append_service_check(checks, source, payload, "containerd", "containerd_active", latency_ms)
        _append_disk_check(checks, source, payload, "free_percent", "root_disk_free", latency_ms)
    elif role == "opnsense_dns":
        _append_boolean_check(checks, source, payload, "adguard_listener", "adguard_listener", latency_ms)
        _append_boolean_check(checks, source, payload, "adguard_query", "adguard_query", latency_ms)
        _append_service_check(checks, source, payload, "unbound", "unbound_active", latency_ms)
        _append_boolean_check(checks, source, payload, "internal_dns", "internal_dns", latency_ms)
        _append_boolean_check(checks, source, payload, "external_dns", "external_dns", latency_ms)
    if not checks:
        raise _ProbeFailure("unexpected_response")
    return checks


def _require_role_payload(role: str, payload: dict[str, Any]) -> None:
    number_fields = {
        "file_server": ("data_free_percent",),
        "directum": ("free_percent", "log_bytes"),
        "active_directory": ("free_percent",),
        "nextcloud": ("free_percent", "data_free_percent"),
        "onlyoffice": ("free_percent",),
        "opnsense_dns": (),
    }
    boolean_fields = {
        "file_server": (),
        "directum": (),
        "active_directory": ("internal_dns", "external_dns"),
        "nextcloud": ("installed", "maintenance", "needsDbUpgrade"),
        "onlyoffice": ("https_ok",),
        "opnsense_dns": (
            "adguard_listener", "adguard_query", "internal_dns", "external_dns",
        ),
    }
    service_fields = {
        "file_server": ("sshd", "smb"),
        "directum": ("directumrx", "mongo", "rabbitmq", "redis", "iis", "dns"),
        "active_directory": ("dns", "ntds", "adws"),
        "nextcloud": ("nginx", "php", "postgresql", "redis"),
        "onlyoffice": ("docker", "containerd"),
        "opnsense_dns": ("unbound",),
    }
    for field in number_fields[role]:
        value = payload.get(field)
        if not _is_safe_nonnegative_number(value) or (field != "log_bytes" and value > 100):
            raise _ProbeFailure("unexpected_response")
        if field == "log_bytes" and not isinstance(value, int):
            raise _ProbeFailure("unexpected_response")
    for field in boolean_fields[role]:
        if not isinstance(payload.get(field), bool):
            raise _ProbeFailure("unexpected_response")
    services = payload.get("services")
    if not isinstance(services, dict):
        raise _ProbeFailure("unexpected_response")
    for service in service_fields[role]:
        if not isinstance(services.get(service), bool):
            raise _ProbeFailure("unexpected_response")


def _append_disk_check(
    checks: list[dict[str, Any]], source: str, payload: dict[str, Any], key: str, name: str, latency_ms: float
) -> None:
    if key not in payload:
        return
    value = payload[key]
    if not _is_safe_nonnegative_number(value) or value > 100:
        raise _ProbeFailure("unexpected_response")
    checks[:] = [check for check in checks if check["name"] != name]
    checks.append({"name": name, "source": source, "status": classify_disk(value), "observed": value,
                   "expected": 15, "latency_ms": latency_ms})


def _append_log_check(
    checks: list[dict[str, Any]], source: str, payload: dict[str, Any], latency_ms: float
) -> None:
    if "log_bytes" not in payload:
        return
    value = payload["log_bytes"]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _ProbeFailure("unexpected_response")
    checks.append({"name": "rxdata_log_bytes", "source": source,
                   "status": classify_directum_logs(value), "observed": value,
                   "expected": 20 * 1024**3, "latency_ms": latency_ms})


def _append_service_check(
    checks: list[dict[str, Any]], source: str, payload: dict[str, Any], service: str, name: str,
    latency_ms: float,
) -> None:
    services = payload.get("services")
    if services is None:
        return
    if not isinstance(services, dict) or service not in services or not isinstance(services[service], bool):
        raise _ProbeFailure("unexpected_response")
    _append_boolean_value(checks, source, name, services[service], latency_ms)


def _append_boolean_check(
    checks: list[dict[str, Any]], source: str, payload: dict[str, Any], key: str, name: str,
    latency_ms: float,
) -> None:
    if key not in payload:
        return
    value = payload[key]
    if not isinstance(value, bool):
        raise _ProbeFailure("unexpected_response")
    _append_boolean_value(checks, source, name, value, latency_ms)


def _append_boolean_value(
    checks: list[dict[str, Any]], source: str, name: str, value: bool, latency_ms: float
) -> None:
    checks.append({"name": name, "source": source, "status": "ok" if value else "critical",
                   "observed": "success" if value else "failure", "expected": "success",
                   "latency_ms": latency_ms})


def _append_nextcloud_status(
    checks: list[dict[str, Any]], source: str, payload: dict[str, Any], latency_ms: float
) -> None:
    fields = ("installed", "maintenance", "needsDbUpgrade")
    if not any(field in payload for field in fields):
        return
    if any(not isinstance(payload.get(field), bool) for field in fields):
        raise _ProbeFailure("unexpected_response")
    if not payload["installed"]:
        observed, status = "unavailable", "critical"
    elif payload["needsDbUpgrade"]:
        observed, status = "needs_db_upgrade", "critical"
    elif payload["maintenance"]:
        observed, status = "maintenance", "warn"
    else:
        observed, status = "installed", "ok"
    checks.append({"name": "nextcloud_status", "source": source, "status": status,
                   "observed": observed, "expected": "installed", "latency_ms": latency_ms})


def _failure_checks(role: str, source: str, category: str) -> list[dict[str, Any]]:
    return [
        {"name": name, "source": source, "status": "error", "error": category}
        for name in _ROLE_CHECK_NAMES[role]
    ]


def _combined_status(statuses: list[str]) -> str:
    known = [status for status in statuses if status in _STATUS_PRIORITY]
    return max(known, key=_STATUS_PRIORITY.__getitem__) if known else "ok"


def public_check(check: dict[str, Any]) -> dict[str, Any]:
    """Return only a check's API-safe fields, discarding raw probe material."""
    allowed_fields = {
        "name", "source", "status", "observed", "expected", "latency_ms", "error"
    }
    if not set(check) <= allowed_fields:
        raise ValueError("check fields are not allowed")
    name = check.get("name")
    if not isinstance(name, str) or not _SAFE_CHECK_NAMES.fullmatch(name):
        raise ValueError("check name must be a safe identifier")
    source = check.get("source")
    if source not in ALLOWED_SOURCES:
        raise ValueError("check source is not allowed")

    public = {"name": name, "source": source}
    status = check.get("status")
    if status is not None:
        if status not in _STATUS_PRIORITY:
            raise ValueError("check status is not allowed")
        public["status"] = status
    for field in ("observed", "expected"):
        if field in check and _is_safe_public_value(check[field]):
            public[field] = check[field]
    if "latency_ms" in check and _is_safe_nonnegative_number(check["latency_ms"]):
        public["latency_ms"] = check["latency_ms"]
    if check.get("error") in _SAFE_ERROR_CATEGORIES:
        public["error"] = check["error"]
    return public


def _is_safe_public_value(value: Any) -> bool:
    return (
        value is None
        or isinstance(value, bool)
        or _is_safe_nonnegative_number(value)
        or (isinstance(value, str) and value in _SAFE_VALUE_STRINGS)
    )


def _is_safe_nonnegative_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def public_target(target: dict[str, Any]) -> dict[str, Any]:
    """Return a target row without runtime topology or command output."""
    if not set(target) <= {"role", "checks", "status"}:
        raise ValueError("target fields are not allowed")
    role = target.get("role")
    if role not in ALLOWED_ROLES:
        raise ValueError("target role is not allowed")
    raw_checks = target.get("checks")
    if not isinstance(raw_checks, list):
        raise ValueError("target checks must be a list")
    checks = [public_check(_require_mapping(check, "check")) for check in raw_checks]
    status = target.get("status") or _combined_status(
        [str(check.get("status", "ok")) for check in checks]
    )
    if status not in _STATUS_PRIORITY:
        raise ValueError("target status is not allowed")
    return {"role": role, "checks": checks, "status": status}


def public_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return the complete persisted/API snapshot with no topology or raw output."""
    if not set(snapshot) <= {"collected_at", "targets", "overall"}:
        raise ValueError("snapshot fields are not allowed")
    collected_at = snapshot.get("collected_at")
    parse_utc(collected_at)
    raw_targets = snapshot.get("targets")
    if not isinstance(raw_targets, list):
        raise ValueError("snapshot targets must be a list")
    targets = [public_target(_require_mapping(target, "target")) for target in raw_targets]
    overall = snapshot.get("overall") or _combined_status(
        [str(target["status"]) for target in targets]
    )
    if overall not in _STATUS_PRIORITY:
        raise ValueError("overall status is not allowed")
    return {"collected_at": collected_at, "overall": overall, "targets": targets}


def snapshot_status(snapshot: dict[str, Any], now: datetime) -> str:
    """Return stale after the fifteen-minute collection grace period."""
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")
    collected_at = parse_utc(snapshot["collected_at"])
    if now - collected_at > STALE_AFTER:
        return "stale"
    return snapshot.get("overall") or _combined_status(
        [str(target.get("status", "ok")) for target in snapshot.get("targets", [])]
    )


def write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    """Atomically persist an API-safe snapshot without exposing collector inputs."""
    public = public_snapshot(snapshot)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        mode = SNAPSHOT_FILE_MODE

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            json.dump(public, temporary_file, sort_keys=True)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, mode)
        for attempt in range(SNAPSHOT_REPLACE_ATTEMPTS):
            try:
                os.replace(temporary_path, path)
                break
            except PermissionError:
                if attempt == SNAPSHOT_REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(SNAPSHOT_REPLACE_RETRY_SECONDS)
    except Exception:
        try:
            temporary_path.unlink()
        except (FileNotFoundError, OSError):
            pass
        raise


def load_snapshot(path: Path, now: datetime) -> dict[str, Any]:
    """Load a public snapshot, returning generic status for absent or invalid files."""
    try:
        snapshot = public_snapshot(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {"overall": "stale", "targets": []}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return {"overall": "error", "targets": []}
    snapshot["overall"] = snapshot_status(snapshot, now)
    return snapshot
