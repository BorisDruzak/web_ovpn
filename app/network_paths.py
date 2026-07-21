"""Pure, read-only evaluation of registered OpenVPN-to-server paths."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .server_observer import ALLOWED_ROLES


STALE_AFTER = timedelta(minutes=15)
# Evidence may be a little ahead while hosts synchronize their clocks. Larger
# forward jumps are treated as corrupt/stale rather than fresh.
FUTURE_TOLERANCE = timedelta(minutes=2)
_STATUS_ORDER = {"ok": 0, "unknown": 1, "warn": 2, "stale": 3, "critical": 4, "error": 5}
_MATCHER_FIELDS = frozenset(
    {"table", "chain", "action", "src_address", "dst_address", "src_address_list", "dst_address_list", "comment_contains"}
)
_SAFE_VERSION = re.compile(r"[0-9][A-Za-z0-9._+~-]{0,31}$")
_SAFE_CHANNELS = frozenset({"stable", "testing", "development", "long-term", "upgrade"})


@dataclass(frozen=True)
class PathDefinition:
    role: str
    router_source: str
    openvpn_pool: str
    target_cidr: str
    return_route: dict[str, str]
    address_lists: tuple[dict[str, str], ...]
    policy_matchers: tuple[dict[str, str], ...]


def load_role_registry(path: Path) -> set[str]:
    """Load the role-only local authority used by the read-only web adapter."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("server role registry must be valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"roles"} or not isinstance(value["roles"], list):
        raise ValueError("server role registry must contain roles only")
    roles = value["roles"]
    if any(not isinstance(role, str) or role not in ALLOWED_ROLES for role in roles):
        raise ValueError("server role registry roles must be allowed")
    if len(set(roles)) != len(roles):
        raise ValueError("server role registry roles must be unique")
    return set(roles)


def load_path_config(path: Path, roles: set[str]) -> dict[str, PathDefinition]:
    """Load strict local-only path definitions for already registered roles."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("network path config must be valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"paths"} or not isinstance(value["paths"], list):
        raise ValueError("network path config must contain paths only")

    definitions: dict[str, PathDefinition] = {}
    for raw_definition in value["paths"]:
        definition = _parse_definition(raw_definition, roles)
        if definition.role in definitions:
            raise ValueError("network path roles must be unique")
        definitions[definition.role] = definition
    return definitions


def _parse_definition(value: Any, roles: set[str]) -> PathDefinition:
    required = {"role", "router_source", "openvpn_pool", "target_cidr", "return_route", "address_lists", "policy_matchers"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("network path definition has invalid fields")
    role = value["role"]
    if not isinstance(role, str) or role not in roles:
        raise ValueError("network path role must be registered")
    router_source = _nonempty_string(value["router_source"], "router_source")
    openvpn_pool = _normal_cidr(value["openvpn_pool"], "openvpn_pool")
    target_cidr = _normal_cidr(value["target_cidr"], "target_cidr")
    return_route = _route_definition(value["return_route"])
    address_lists = _address_list_definitions(value["address_lists"])
    policy_matchers = _policy_matchers(value["policy_matchers"])
    return PathDefinition(role, router_source, openvpn_pool, target_cidr, return_route, address_lists, policy_matchers)


def _route_definition(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) not in ({"dst_address"}, {"dst_address", "gateway"}):
        raise ValueError("return_route must contain dst_address and optional gateway only")
    result = {"dst_address": _normal_cidr(value.get("dst_address"), "return_route.dst_address")}
    if "gateway" in value:
        result["gateway"] = _nonempty_string(value["gateway"], "return_route.gateway")
    return result


def _address_list_definitions(value: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list):
        raise ValueError("address_lists must be a list")
    definitions = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"list", "address"}:
            raise ValueError("address list matcher has invalid fields")
        definitions.append({"list": _normal_text(item["list"]), "address": _normal_address(item["address"], "address list address")})
    return tuple(definitions)


def _policy_matchers(value: Any) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list):
        raise ValueError("policy_matchers must be a list")
    definitions = []
    for item in value:
        if not isinstance(item, dict) or not {"table", "chain"} <= set(item) or not set(item) <= _MATCHER_FIELDS:
            raise ValueError("policy matcher has invalid fields")
        matcher = {key: _normal_matcher_value(key, item[key]) for key in item}
        definitions.append(matcher)
    return tuple(definitions)


def _normal_matcher_value(key: str, value: Any) -> str:
    if key in {"src_address", "dst_address"}:
        return _normal_address(value, key)
    return _normal_text(value)


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _normal_text(value: Any) -> str:
    return _nonempty_string(value, "value").casefold()


def _normal_cidr(value: Any, label: str) -> str:
    try:
        return str(ipaddress.ip_network(_nonempty_string(value, label), strict=False))
    except ValueError as exc:
        raise ValueError(f"{label} must be a CIDR") from exc


def _normal_address(value: Any, label: str) -> str:
    raw = _nonempty_string(value, label)
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise ValueError(f"{label} must be an IP address or CIDR") from exc


def evaluate_paths(
    definitions: dict[str, PathDefinition],
    runtime: dict[str, Any],
    collector: dict[str, Any],
    router_rows: dict[str, Any],
    server_health: dict[str, Any],
    now: datetime,
) -> list[dict[str, Any]]:
    """Evaluate saved evidence without performing network or system operations."""
    _require_utc(now)
    rows = []
    for role, definition in sorted(definitions.items()):
        if role != definition.role:
            raise ValueError("definition key must match its role")
        router_status, router_collected_at = _router_status(definition.router_source, router_rows, now)
        checks = [
            _openvpn_check(definition, runtime),
            _collector_check(collector),
            _router_check(router_status, router_collected_at),
            _return_route_check(definition, router_rows, router_status),
            _path_binding_check(definition),
        ]
        checks.extend(_address_list_checks(definition, router_rows, router_status))
        checks.extend(_policy_checks(definition, router_rows, router_status))
        checks.append(_server_health_check(role, server_health, now))
        rows.append(
            {
                "role": role,
                "status": worst_status(checks),
                "collected_at": _oldest_evidence_time(
                    definition, router_rows, server_health, router_collected_at, now
                ),
                "update_posture": update_posture_summary(
                    definition.router_source,
                    _mapping(_mapping(router_rows).get("update_posture_results")).get(
                        definition.router_source
                    ),
                    now,
                ),
                "checks": checks,
            }
        )
    return rows


def _openvpn_check(definition: PathDefinition, runtime: dict[str, Any]) -> dict[str, Any]:
    openvpn = _mapping(_mapping(runtime).get("sections")).get("openvpn")
    openvpn = _mapping(openvpn)
    active = openvpn.get("service_active") is True
    observed_pool = openvpn.get("server_network", openvpn.get("pool", openvpn.get("openvpn_pool")))
    pool_matches = observed_pool is not None and _same_address(observed_pool, definition.openvpn_pool)
    status = "ok" if active and pool_matches else "critical"
    observed = {"service_active": active}
    if observed_pool is not None:
        observed["pool_matches"] = pool_matches
    return _check("openvpn", status, observed, {"service_active": True, "pool": definition.openvpn_pool}, "OpenVPN service and expected pool")


def _collector_check(collector: dict[str, Any]) -> dict[str, Any]:
    enabled = _mapping(collector).get("enabled") is True
    active = _mapping(collector).get("active") is True
    return _check(
        "collector", "ok" if enabled and active else "error", {"enabled": enabled, "active": active},
        {"enabled": True, "active": True}, "Router evidence collector timer",
    )


def _router_status(source: str, router_rows: dict[str, Any], now: datetime) -> tuple[str, str]:
    rows = _mapping(router_rows)
    overall = rows.get("status")
    if overall in {"error", "stale"}:
        return overall, ""
    sources = rows.get("sources")
    if not isinstance(sources, list):
        return "stale", ""
    matching = [item for item in sources if isinstance(item, dict) and _normal_optional(item.get("source")) == _normal_text(source)]
    if not matching:
        return "unknown", ""
    state = matching[0]
    status = state.get("status")
    collected_at = _safe_timestamp(state.get("collected_at"))
    if status == "error":
        return "error", collected_at
    if not collected_at:
        return "stale", ""
    if status == "stale" or _is_stale(collected_at, now) or _has_stale_router_rows(rows, source, now):
        return "stale", collected_at
    if status == "ok":
        return "ok", collected_at
    return "unknown", collected_at


def _router_check(status: str, collected_at: str) -> dict[str, Any]:
    return _check("router_source", status, collected_at or "unavailable", "current enabled source", "Configured router source evidence")


def _return_route_check(definition: PathDefinition, router_rows: dict[str, Any], router_status: str) -> dict[str, Any]:
    matches = _matching_rows(_mapping(router_rows).get("routes"), definition.router_source, definition.return_route)
    if not matches:
        return _check("return_route", "critical", "absent", definition.return_route, "Expected active return route")
    enabled = any(
        _known_bool(row.get("active")) is True and _known_bool(row.get("disabled", False)) is False
        for row in matches
    )
    status = router_status if enabled and router_status in {"stale", "error"} else "ok" if enabled else "critical"
    return _check("return_route", status, "present" if enabled else "disabled", definition.return_route, "Expected active return route")


def _address_list_checks(definition: PathDefinition, router_rows: dict[str, Any], router_status: str) -> list[dict[str, Any]]:
    checks = []
    for index, matcher in enumerate(definition.address_lists, start=1):
        matches = _matching_rows(_mapping(router_rows).get("address_lists"), definition.router_source, matcher)
        enabled = any(_known_bool(row.get("disabled", False)) is False for row in matches)
        bound = _address_matcher_relations(definition, matcher)
        if not bound:
            status, observed = "critical", "unrelated"
        else:
            status = router_status if enabled and router_status in {"stale", "error"} else "ok" if enabled else "critical"
            observed = "present" if enabled else "absent"
        checks.append(_check(f"address_list:{index}", status, observed, matcher, "Required address-list membership"))
    return checks


def _policy_checks(definition: PathDefinition, router_rows: dict[str, Any], router_status: str) -> list[dict[str, Any]]:
    if not definition.policy_matchers:
        return [_check("policy", "unknown", "not configured", "declarative policy matcher", "No policy matcher is configured")]
    checks = []
    for index, matcher in enumerate(definition.policy_matchers, start=1):
        matches = _matching_rows(_mapping(router_rows).get("firewall_rules", _mapping(router_rows).get("rules")), definition.router_source, matcher)
        enabled = [row for row in matches if _known_bool(row.get("disabled", False)) is False]
        if not _policy_matcher_relations(definition, matcher):
            status, observed = "critical", "unrelated"
        elif not matches or not enabled:
            status, observed = "critical", "absent" if not matches else "disabled"
        elif router_status in {"stale", "error"}:
            status, observed = router_status, "present"
        elif _zero_counter(enabled):
            status, observed = "warn", "zero counter"
        else:
            status, observed = "ok", "present"
        checks.append(_check(f"policy:{index}", status, observed, matcher, "Required enabled firewall policy"))
    return checks


def _server_health_check(role: str, server_health: dict[str, Any], now: datetime) -> dict[str, Any]:
    health = _mapping(server_health)
    collected_at = _safe_timestamp(health.get("collected_at"))
    target = next((item for item in health.get("targets", []) if isinstance(item, dict) and item.get("role") == role), None)
    if not collected_at or _is_stale(collected_at, now) or target is None:
        status = "stale"
    else:
        status = target.get("status") if target.get("status") in _STATUS_ORDER else "unknown"
    observed = target.get("status") if target else "missing"
    return _check("server_health", status, observed, "current target health", "Matching Server Health result")


def _matching_rows(rows: Any, source: str, matcher: dict[str, str]) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict) and _row_matches(row, source, matcher)]


def _has_stale_router_rows(rows: dict[str, Any], source: str, now: datetime) -> bool:
    for key in ("routes", "address_lists", "firewall_rules", "rules"):
        collection = rows.get(key)
        if collection is None:
            continue
        if not isinstance(collection, list):
            return True
        for row in collection:
            if not isinstance(row, dict):
                continue
            if row.get("source") is not None and _normal_optional(row.get("source")) != _normal_text(source):
                continue
            timestamp = _safe_timestamp(row.get("last_seen_at"))
            if not timestamp or _is_stale(timestamp, now):
                return True
    return False


def _row_matches(row: dict[str, Any], source: str, matcher: dict[str, str]) -> bool:
    row_source = row.get("source")
    if not isinstance(row_source, str) or _normal_optional(row_source) != _normal_text(source):
        return False
    for key, expected in matcher.items():
        actual = row.get(key)
        if key == "comment_contains":
            if not isinstance(row.get("comment"), str) or expected not in row["comment"].casefold():
                return False
        elif actual is None:
            return False
        else:
            try:
                if _normal_for_key(key, actual) != expected:
                    return False
            except ValueError:
                return False
    return True


def _normal_for_key(key: str, value: Any) -> str:
    if key in {"dst_address", "src_address", "address"}:
        return _normal_address(value, key)
    return _normal_text(value)


def _normal_optional(value: Any) -> str:
    try:
        return _normal_text(value)
    except ValueError:
        return ""


def _same_address(value: Any, expected: str) -> bool:
    try:
        return _normal_address(value, "address") == expected
    except ValueError:
        return False


def _known_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return None


def _network_relates(value: Any, expected: str) -> bool:
    try:
        candidate = ipaddress.ip_network(_normal_address(value, "address"), strict=False)
        expected_network = ipaddress.ip_network(expected, strict=False)
    except ValueError:
        return False
    return candidate.version == expected_network.version and candidate.overlaps(expected_network)


def _address_matcher_relations(definition: PathDefinition, matcher: dict[str, str]) -> set[str]:
    relations = set()
    if _network_relates(matcher.get("address"), definition.openvpn_pool):
        relations.add("pool")
    if _network_relates(matcher.get("address"), definition.target_cidr):
        relations.add("target")
    return relations


def _list_relations(definition: PathDefinition, list_name: Any) -> set[str]:
    normalized = _normal_optional(list_name)
    relations = set()
    for matcher in definition.address_lists:
        if _normal_optional(matcher.get("list")) == normalized:
            relations.update(_address_matcher_relations(definition, matcher))
    return relations


def _policy_matcher_relations(definition: PathDefinition, matcher: dict[str, str]) -> set[str]:
    relations = set()
    for key in ("src_address", "dst_address"):
        value = matcher.get(key)
        if _network_relates(value, definition.openvpn_pool):
            relations.add("pool")
        if _network_relates(value, definition.target_cidr):
            relations.add("target")
    for key in ("src_address_list", "dst_address_list"):
        if key in matcher:
            relations.update(_list_relations(definition, matcher[key]))
    return relations


def _path_binding_check(definition: PathDefinition) -> dict[str, Any]:
    if not definition.policy_matchers:
        return _check(
            "target_binding",
            "unknown",
            "not configured",
            "OpenVPN pool to target policy",
            "No policy matcher is configured",
        )
    relations = set()
    for matcher in definition.policy_matchers:
        relations.update(_policy_matcher_relations(definition, matcher))
    bound = {"pool", "target"} <= relations
    return _check(
        "target_binding",
        "ok" if bound else "critical",
        "bound" if bound else "unrelated",
        "OpenVPN pool to target policy",
        "Policy evidence binds the configured path endpoints",
    )


def _zero_counter(rows: list[dict[str, Any]]) -> bool:
    counters = [row.get(name) for row in rows for name in ("packets", "bytes") if isinstance(row.get(name), (int, float)) and not isinstance(row.get(name), bool)]
    return bool(counters) and all(value == 0 for value in counters)


def _safe_timestamp(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00") if value.endswith("Z") else None
    except ValueError:
        parsed = None
    return value if parsed is not None and parsed.tzinfo == timezone.utc else ""


def _is_stale(value: str, now: datetime) -> bool:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return True
    return now - parsed > STALE_AFTER or parsed - now > FUTURE_TOLERANCE


def _parse_timestamp(value: Any) -> datetime | None:
    safe = _safe_timestamp(value)
    return datetime.fromisoformat(safe[:-1] + "+00:00") if safe else None


def _oldest_evidence_time(
    definition: PathDefinition,
    router_rows: dict[str, Any],
    server_health: dict[str, Any],
    router_collected_at: str,
    now: datetime,
) -> str:
    candidates = [router_collected_at, _safe_timestamp(_mapping(server_health).get("collected_at"))]
    row_sets = [
        _matching_rows(_mapping(router_rows).get("routes"), definition.router_source, definition.return_route),
    ]
    row_sets.extend(
        _matching_rows(_mapping(router_rows).get("address_lists"), definition.router_source, matcher)
        for matcher in definition.address_lists
    )
    row_sets.extend(
        _matching_rows(
            _mapping(router_rows).get("firewall_rules", _mapping(router_rows).get("rules")),
            definition.router_source,
            matcher,
        )
        for matcher in definition.policy_matchers
    )
    candidates.extend(_safe_timestamp(row.get("last_seen_at")) for rows in row_sets for row in rows)
    valid = []
    for timestamp in candidates:
        parsed = _parse_timestamp(timestamp)
        if parsed is not None and parsed - now <= FUTURE_TOLERANCE:
            valid.append((timestamp, parsed))
    return min(valid, key=lambda item: item[1])[0] if valid else ""


def _safe_version(value: Any) -> str:
    return value if isinstance(value, str) and _SAFE_VERSION.fullmatch(value) else ""


def update_posture_summary(source: str, payload: Any, now: datetime) -> dict[str, Any]:
    """Project one source's posture to the fixed, topology-free public contract."""
    _require_utc(now)
    data = _mapping(payload)
    posture = next(
        (
            row
            for row in data.get("update_posture", [])
            if isinstance(row, dict) and _normal_optional(row.get("source")) == _normal_text(source)
        ),
        None,
    )
    state = next(
        (
            row
            for row in data.get("sources", [])
            if isinstance(row, dict) and _normal_optional(row.get("source")) == _normal_text(source)
        ),
        None,
    )
    state_status = _mapping(state).get("status")
    if posture is None:
        timestamp = ""
        freshness = "unknown"
        if data.get("status") == "error" or state_status == "error":
            status = "error"
        elif data.get("status") == "stale" or state_status == "stale":
            status = "stale"
        else:
            status = "unknown"
    else:
        timestamp = _safe_timestamp(posture.get("last_seen_at"))
        source_timestamp = _safe_timestamp(_mapping(state).get("collected_at"))
        fresh = (
            bool(timestamp)
            and not _is_stale(timestamp, now)
            and bool(source_timestamp)
            and not _is_stale(source_timestamp, now)
        )
        freshness = "fresh" if fresh else "stale"
        status = "ok" if fresh else "stale"
    if data.get("status") == "error" or state_status == "error":
        status = "error"
    elif data.get("status") == "stale" or state_status == "stale":
        status = "stale"
    schedulers = _mapping(posture).get("schedulers")
    return {
        "installed_version": _safe_version(_mapping(posture).get("installed_version")),
        "channel": (
            _mapping(posture).get("channel")
            if _mapping(posture).get("channel") in _SAFE_CHANNELS
            else ""
        ),
        "routerboot_current_version": _safe_version(
            _mapping(posture).get("routerboot_current_version")
        ),
        "routerboot_upgrade_version": _safe_version(
            _mapping(posture).get("routerboot_upgrade_version")
        ),
        "scheduler_count": (
            sum(isinstance(scheduler, dict) for scheduler in schedulers)
            if isinstance(schedulers, list)
            else 0
        ),
        "collected_at": timestamp if freshness == "fresh" else "",
        "freshness": freshness,
        "status": status,
    }


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _require_utc(now: datetime) -> None:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")


def _check(name: str, status: str, observed: Any, expected: Any, message: str) -> dict[str, Any]:
    return {"name": name, "status": status, "observed": observed, "expected": expected, "message": message}


def worst_status(checks: list[dict[str, Any]]) -> str:
    return max((item["status"] for item in checks), key=_STATUS_ORDER.__getitem__, default="unknown")
