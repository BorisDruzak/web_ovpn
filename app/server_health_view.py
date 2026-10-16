"""Redacted, read-only view model for the server-health snapshot."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from app.server_observer import load_snapshot_result, parse_utc


_DEFAULT_COLLECTOR = {"status": "ok", "failure_class": "", "message": ""}
_STATUSES = ("ok", "warn", "critical", "error")
_CHECK_FIELDS = ("name", "status", "observed", "expected", "latency_ms")


def build_server_health_view(path: Path, now: datetime) -> dict[str, Any]:
    """Build a presentation-only model from one validated snapshot read."""
    result = load_snapshot_result(path, now)
    snapshot = result["snapshot"]
    freshness = result["freshness"]
    collected_at = snapshot.get("collected_at")
    age_seconds = _age_seconds(collected_at, now) if freshness in {"current", "stale"} else None

    targets = [
        _target_view(target, collected_at)
        for target in snapshot.get("targets", [])
    ]
    summary = {status: 0 for status in _STATUSES}
    for target in targets:
        summary[target["status"]] += 1

    return {
        "freshness": freshness,
        "collected_at": collected_at if age_seconds is not None else None,
        "age_seconds": age_seconds,
        "collector": dict(snapshot.get("collector", _DEFAULT_COLLECTOR)),
        "summary": summary,
        "targets": targets,
    }


def _age_seconds(collected_at: Any, now: datetime) -> int | None:
    if not isinstance(collected_at, str):
        return None
    return int((now - parse_utc(collected_at)).total_seconds())


def _target_view(target: dict[str, Any], collected_at: str | None) -> dict[str, Any]:
    checks = [_check_view(check) for check in target["checks"]]
    return {
        "role": target["role"],
        "status": target["status"],
        "problem_count": sum(check["status"] in {"warn", "critical", "error"} for check in checks),
        "observed_at": collected_at,
        "checks": checks,
    }


def _check_view(check: dict[str, Any]) -> dict[str, Any]:
    rendered = {
        field: check[field]
        for field in _CHECK_FIELDS
        if field in check
    }
    rendered.setdefault("status", "ok")
    if "error" in check:
        rendered["message"] = check["error"]
    return rendered
