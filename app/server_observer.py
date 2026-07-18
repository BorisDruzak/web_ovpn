"""Value-only contract and storage helpers for server health snapshots.

This module deliberately has no network or process-execution capability.  Runtime
topology is accepted only from the local collector configuration and is stripped
before a snapshot is persisted or returned to the web application.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re
from typing import Any


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
_PUBLIC_CHECK_FIELDS = frozenset(
    {"name", "source", "status", "observed", "expected", "latency_ms", "error"}
)
_STATUS_PRIORITY = {"ok": 0, "warn": 1, "critical": 2, "error": 3}
_SAFE_CHECK_NAMES = re.compile(r"[a-z][a-z0-9_]{0,63}$")
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
    except json.JSONDecodeError as exc:
        raise ValueError("runtime config must be valid JSON") from exc

    targets = config.get("targets")
    if not isinstance(targets, list):
        raise ValueError("config.targets must be a list")
    for target in targets:
        _validate_runtime_target(target)
    return config


def _validate_runtime_target(value: Any) -> None:
    target = _require_mapping(value, "target")
    if set(target) != {"role", "host", "user", "checks"}:
        raise ValueError("target fields must be role, host, user, and checks only")
    if target["role"] not in ALLOWED_ROLES:
        raise ValueError("target role is not allowed")
    if not all(isinstance(target[field], str) and target[field] for field in ("host", "user")):
        raise ValueError("target host and user must be non-empty strings")
    if not isinstance(target["checks"], list):
        raise ValueError("target checks must be a list")
    for check in target["checks"]:
        check_mapping = _require_mapping(check, "check")
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


def _combined_status(statuses: list[str]) -> str:
    known = [status for status in statuses if status in _STATUS_PRIORITY]
    return max(known, key=_STATUS_PRIORITY.__getitem__) if known else "ok"


def public_check(check: dict[str, Any]) -> dict[str, Any]:
    """Return only a check's API-safe fields, discarding raw probe material."""
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
    temporary_path = path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps(public, sort_keys=True), encoding="utf-8")
    temporary_path.replace(path)


def load_snapshot(path: Path, now: datetime) -> dict[str, Any]:
    """Load a public snapshot, returning generic status for absent or invalid files."""
    try:
        snapshot = public_snapshot(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {"overall": "stale", "targets": []}
    except (json.JSONDecodeError, ValueError, TypeError):
        return {"overall": "error", "targets": []}
    snapshot["overall"] = snapshot_status(snapshot, now)
    return snapshot
