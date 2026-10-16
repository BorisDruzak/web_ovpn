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
import sys
import tempfile
import time
from time import perf_counter
from typing import Any, Callable
from urllib.parse import urlsplit


ALLOWED_ROLES = frozenset(
    {
        "file_server",
        "directum",
        "active_directory",
        "nextcloud",
        "onlyoffice",
        "opnsense_dns",
        "acti",
        "acti_backup",
    }
)
ALLOWED_SOURCES = frozenset({"gateway", "vpn_path", "target"})
STALE_AFTER = timedelta(minutes=15)
# Permit minor NTP skew, but never accept materially future evidence as fresh.
FUTURE_TOLERANCE = timedelta(minutes=2)
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
COLLECTOR_FAILURE_CLASSES = frozenset(
    {"config", "ssh", "probe", "snapshot_write", "internal"}
)
COLLECTOR_FAILURE_MESSAGES = {
    "config": "Collector configuration is invalid",
    "ssh": "SSH connection failed",
    "probe": "Server health probe failed",
    "snapshot_write": "Server health snapshot could not be saved",
    "internal": "Collector failed",
}
ACTI_CA_PATH = "/etc/openvpn-web/acti-ca.crt"
ACTI_SERVICES = ("frontend", "api", "postgres", "redis", "worker", "keycloak")
ACTI_FLAGS = ("worker_heartbeat", "mounts_verified", "storage_capacity", "outbox_healthy", "backup_fresh", "backup_check_fresh")
ACTI_BACKUP_FLAGS = ("watchdog_fresh", "backup_snapshot_fresh", "repository_capacity")
ACTI_HTTPS_CHECKS = (
    ("https_live", "/api/v1/health/live"),
    ("https_ready", "/api/v1/health/ready"),
    ("oidc_discovery", "/idp/realms/acti/.well-known/openid-configuration"),
)
# A child process enforces a wall-clock deadline even during DNS/header reads.
# http.client never follows redirects or ambient proxy/cookie configuration.
_ACTI_HTTPS_PROBE = r'''import http.client,ssl,sys
connection=None
try:
 context=ssl.create_default_context(cafile=sys.argv[4])
 connection=http.client.HTTPSConnection(sys.argv[1],int(sys.argv[2]),timeout=2.5,context=context)
 connection.request('GET',sys.argv[3],headers={'Accept':'application/json'})
 response=connection.getresponse()
 if response.status!=200 or response.getheader('Content-Type','').split(';')[0].strip().lower()!='application/json':sys.exit(3)
 body=response.read(16385)
 if len(body)>16384:sys.exit(3)
 sys.stdout.buffer.write(body)
except TimeoutError:sys.exit(2)
except Exception:sys.exit(4)
finally:
 if connection is not None:connection.close()
'''

# These are fixed, read-only remote probes.  Runtime configuration may select a
# target and route, but can never supply a remote command.
def _powershell_probe(body: str, role: str) -> str:
    body = f"{body} # server_observer:{role}"
    encoded = base64.b64encode(body.encode("utf-16le")).decode("ascii")
    return f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"


_ACTI_BACKUP_BODY = " ".join(line.strip() for line in r'''
$ErrorActionPreference='Stop';$e=Get-EventLog -LogName Application -Source ACTIBackup -Newest 1;
$r=@{format='acti-backup-observer-v1';services=@{};watchdog_fresh=$false;backup_snapshot_fresh=$false;repository_capacity=$false};
try{
function N($v){$null-ne$v-and$v-isnot[bool]-and($v-is[int]-or$v-is[long]-or$v-is[double]-or$v-is[decimal])-and![double]::IsNaN($v)-and![double]::IsInfinity($v)-and$v-ge 0};
function T($v){if($v-is[string]-and$v-match'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?Z$'){try{[datetimeoffset]::Parse($v,[cultureinfo]::InvariantCulture)}catch{}}};
$p=$e.Message|ConvertFrom-Json;$k='format,checked_utc,check_only,status,event_id,snapshot_count,newest_snapshot_utc,snapshot_age_hours,repository_bytes,repository_entries,free_gib,maximum_age_hours,minimum_free_gib,maximum_repository_gib,issues'.Split(',');
$ok=@(Compare-Object $k @($p.PSObject.Properties.Name)).Count-eq 0-and[regex]::Matches($e.Message,'"[^"\\]+"\s*:').Count-eq$k.Count;
foreach($n in 'event_id','snapshot_count','repository_bytes','repository_entries','free_gib','maximum_age_hours','minimum_free_gib','maximum_repository_gib'){$ok=$ok-and(N $p.$n)};
$ok=$ok-and$p.format-eq'acti-backup-watchdog-v1'-and$p.check_only-is[bool]-and!$p.check_only-and$p.issues-is[array]-and$e.EventID-eq$p.event_id;
$ok=$ok-and(($p.event_id-eq 1000-and$p.status-eq'healthy'-and$p.issues.Count-eq 0)-or($p.event_id-in 1002,1003,1004-and$p.status-eq'unhealthy'-and$p.issues.Count-gt 0));
$ok=$ok-and@($p.issues|Where-Object{$_-notin'free_space_limit','repository_size_limit','snapshot_missing','snapshot_timestamp_invalid','snapshot_stale'}).Count-eq 0;
$ok=$ok-and$p.snapshot_count-eq[math]::Floor($p.snapshot_count)-and$p.repository_entries-eq[math]::Floor($p.repository_entries)-and$p.repository_bytes-eq[math]::Floor($p.repository_bytes);
$a=T $p.checked_utc;$z=[datetimeoffset]::UtcNow;$t=[datetimeoffset]$e.TimeGenerated.ToUniversalTime();
$fresh=$ok-and$null-ne$a-and($z-$a).TotalHours-le 30-and($z-$a).TotalMinutes-ge -5-and($z-$t).TotalHours-le 30-and($z-$t).TotalMinutes-ge -5-and[math]::Abs(($a-$t).TotalMinutes)-le 5;
if($fresh){$r.watchdog_fresh=$true;$r.repository_capacity=$p.free_gib-ge 100-and$p.repository_bytes-le 322122547200;
$s=T $p.newest_snapshot_utc;$r.backup_snapshot_fresh=$p.snapshot_count-gt 0-and(N $p.snapshot_age_hours)-and$p.snapshot_age_hours-le 30-and$null-ne$s-and($z-$s).TotalHours-ge 0-and($z-$s).TotalHours-le 30-and[math]::Abs(($a-$s).TotalHours-$p.snapshot_age_hours)-le(1.0/12)}
}catch{};$r|ConvertTo-Json -Compress
'''.splitlines())


_ROLE_PROBES = {
    "acti": "/usr/bin/sudo -n /usr/local/sbin/acti-v3-observe",
    "acti_backup": _powershell_probe(_ACTI_BACKUP_BODY, "acti_backup"),
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
    "acti": tuple(service + "_active" for service in ACTI_SERVICES) + ACTI_FLAGS,
    "acti_backup": ACTI_BACKUP_FLAGS,
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
            payload = _parse_probe_payload(completed.stdout, strict=role in {"acti", "acti_backup"})
            checks = _checks_from_payload(role, source, payload, latency_ms)
        except subprocess.TimeoutExpired:
            checks = _failure_checks(role, source, "timeout")
        except _ProbeFailure as exc:
            checks = _failure_checks(role, source, exc.category)
        except (OSError, subprocess.SubprocessError, TypeError):
            checks = _failure_checks(role, source, "transport")
        except Exception:
            checks = _failure_checks(role, source, "transport")
        if role == "acti":
            checks.extend(_acti_https_checks(configured_target["host"]))
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


def _strict_json(stdout: Any) -> dict[str, Any]:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("non-finite JSON number")

    try:
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8")
        if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > 16384:
            raise _ProbeFailure("unexpected_response")
        value = json.loads(
            stdout, object_pairs_hook=unique_pairs, parse_constant=reject_constant
        )
    except (ValueError, UnicodeError) as exc:
        raise _ProbeFailure("parse") from exc
    if not isinstance(value, dict):
        raise _ProbeFailure("unexpected_response")
    return value


def _acti_https_checks(host: str) -> list[dict[str, Any]]:
    checks = []
    deadline = perf_counter() + 10
    for name, path in ACTI_HTTPS_CHECKS:
        started = perf_counter()
        try:
            timeout = min(3, deadline - started)
            if timeout <= 0:
                raise _ProbeFailure("timeout")
            command = [
                sys.executable,
                "-I",
                "-c",
                _ACTI_HTTPS_PROBE,
                host,
                "443",
                path,
                ACTI_CA_PATH,
            ]
            completed = subprocess.run(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
            if completed.returncode != 0:
                raise _ProbeFailure(
                    {2: "timeout", 3: "unexpected_response"}.get(
                        completed.returncode, "transport"
                    )
                )
            payload = _strict_json(completed.stdout)
            _validate_acti_https(name, payload, host)
            _append_boolean_value(
                checks,
                "gateway",
                name,
                True,
                round((perf_counter() - started) * 1000, 3),
            )
        except subprocess.TimeoutExpired:
            checks.append(
                {
                    "name": name,
                    "source": "gateway",
                    "status": "error",
                    "error": "timeout",
                }
            )
        except _ProbeFailure as exc:
            checks.append(
                {
                    "name": name,
                    "source": "gateway",
                    "status": "error",
                    "error": exc.category,
                }
            )
        except Exception:
            checks.append(
                {
                    "name": name,
                    "source": "gateway",
                    "status": "error",
                    "error": "transport",
                }
            )
    return checks


def _validate_acti_https(name: str, payload: dict[str, Any], host: str) -> None:
    valid = False
    if name == "https_live":
        valid = payload == {"status": "live"}
    elif name == "https_ready":
        fields = {"database", "redis", "storage"}
        checks = payload.get("checks")
        valid = (
            set(payload) == {"status", "checks"}
            and payload["status"] == "ready"
            and isinstance(checks, dict)
            and set(checks) == fields
            and all(value is True for value in checks.values())
        )
    elif name == "oidc_discovery":
        realm = "https://" + host + "/idp/realms/acti"
        required = {"authorization_endpoint", "token_endpoint", "jwks_uri"}
        valid = payload.get("issuer") == realm and required <= set(payload)
        endpoints = [
            value
            for key, value in payload.items()
            if key.endswith("_endpoint") or key in {"jwks_uri", "check_session_iframe"}
        ]
        if "mtls_endpoint_aliases" in payload:
            aliases = payload["mtls_endpoint_aliases"]
            if not isinstance(aliases, dict) or any(
                not key.endswith("_endpoint") for key in aliases
            ):
                raise _ProbeFailure("unexpected_response")
            endpoints.extend(aliases.values())
        for value in endpoints:
            if not isinstance(value, str):
                valid = False
                break
            parsed = urlsplit(value)
            if (
                parsed.scheme != "https"
                or parsed.netloc != host
                or not parsed.path.startswith("/idp/realms/acti/")
                or parsed.query
                or parsed.fragment
                or "%" in parsed.path
                or any(part in {".", ".."} for part in parsed.path.split("/"))
            ):
                valid = False
                break
    if not valid:
        raise _ProbeFailure("unexpected_response")


def _parse_probe_payload(stdout: Any, *, strict: bool = False) -> dict[str, Any]:
    if strict:
        return _strict_json(stdout)
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
    if role == "acti_backup":
        for name in ACTI_BACKUP_FLAGS:
            _append_boolean_check(checks, source, payload, name, name, latency_ms)
    elif role == "acti":
        for service in ACTI_SERVICES:
            _append_service_check(checks, source, payload, service, service + "_active", latency_ms)
        for name in ACTI_FLAGS:
            _append_boolean_check(checks, source, payload, name, name, latency_ms)
    elif role == "file_server":
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
    if role == "acti_backup":
        if (set(payload) != {"format", "services", *ACTI_BACKUP_FLAGS}
            or payload.get("format") != "acti-backup-observer-v1"
            or payload.get("services") != {}
            or any(type(payload.get(field)) is not bool for field in ACTI_BACKUP_FLAGS)):
            raise _ProbeFailure("unexpected_response")
        return
    if role == "acti":
        services = payload.get("services")
        if (set(payload) != {"format", "services", *ACTI_FLAGS} or payload.get("format") != "acti-observer-v1"
            or not isinstance(services, dict) or set(services) != set(ACTI_SERVICES)
            or any(type(value) is not bool for value in services.values())
            or any(type(payload.get(field)) is not bool for field in ACTI_FLAGS)):
            raise _ProbeFailure("unexpected_response")
        return
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


def public_collector(collector: dict[str, Any]) -> dict[str, str]:
    """Return the fixed, non-diagnostic collector failure record."""
    if set(collector) != {"status", "failure_class", "message"}:
        raise ValueError("collector fields are not allowed")
    if collector.get("status") != "error":
        raise ValueError("collector status is not allowed")
    failure_class = collector.get("failure_class")
    if failure_class not in COLLECTOR_FAILURE_CLASSES:
        raise ValueError("collector failure class is not allowed")
    message = collector.get("message")
    if message != COLLECTOR_FAILURE_MESSAGES[failure_class]:
        raise ValueError("collector message is not allowed")
    return {"status": "error", "failure_class": failure_class, "message": message}


def public_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return the complete persisted/API snapshot with no topology or raw output."""
    if not set(snapshot) <= {"collected_at", "targets", "overall", "collector"}:
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
    public = {"collected_at": collected_at, "overall": overall, "targets": targets}
    if "collector" in snapshot:
        public["collector"] = public_collector(_require_mapping(snapshot["collector"], "collector"))
    return public


def snapshot_status(snapshot: dict[str, Any], now: datetime) -> str:
    """Return stale after the fifteen-minute collection grace period."""
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")
    collected_at = parse_utc(snapshot["collected_at"])
    if now - collected_at > STALE_AFTER or collected_at - now > FUTURE_TOLERANCE:
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


def load_snapshot_result(path: Path, now: datetime) -> dict[str, Any]:
    """Load a public snapshot together with its safe freshness state."""
    try:
        snapshot = public_snapshot(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {"snapshot": {"overall": "stale", "targets": []}, "freshness": "missing"}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return {"snapshot": {"overall": "error", "targets": []}, "freshness": "invalid"}
    freshness = "stale" if snapshot_status(snapshot, now) == "stale" else "current"
    return {"snapshot": snapshot, "freshness": freshness}


def load_snapshot(path: Path, now: datetime) -> dict[str, Any]:
    """Load a public snapshot with the established overall-status compatibility behavior."""
    result = load_snapshot_result(path, now)
    snapshot = dict(result["snapshot"])
    if result["freshness"] == "stale":
        snapshot["overall"] = "stale"
    return snapshot
