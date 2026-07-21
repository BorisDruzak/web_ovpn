"""Read-only, redacted adapter for registered VPN-to-server path evidence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .config import get_settings
from .netctl_client import NetctlError, run_netctl
from .network_paths import evaluate_paths, load_path_config
from .server_observer import load_snapshot
from .vpnctl_client import VpnctlError, run_vpnctl


def list_network_paths() -> list[dict[str, Any]]:
    """Evaluate configured paths from local snapshots and read-only CLI evidence."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    server_health = load_snapshot(settings.server_observer_snapshot_path, now)
    roles = {
        target["role"]
        for target in _rows(server_health.get("targets"))
        if isinstance(target.get("role"), str)
    }
    try:
        definitions = load_path_config(settings.network_paths_config_path, roles)
    except ValueError:
        return []
    if not definitions:
        return []

    runtime = _runtime_with_pool()
    collector = _netctl(["collector-status"])
    router_rows = _router_rows(definitions.values())
    try:
        evaluated = evaluate_paths(definitions, runtime, collector, router_rows, server_health, now)
    except (TypeError, ValueError):
        return []
    return [_public_path(row) for row in evaluated]


def get_network_path(role: str) -> dict[str, Any] | None:
    return next((row for row in list_network_paths() if row["role"] == role), None)


def _runtime_with_pool() -> dict[str, Any]:
    runtime = _vpnctl(["runtime-health"])
    server_config = _vpnctl(["server-config", "inspect"])
    settings = _mapping(server_config.get("settings"))
    sections = dict(_mapping(runtime.get("sections")))
    openvpn = dict(_mapping(sections.get("openvpn")))
    if isinstance(settings.get("server_network"), str):
        openvpn["server_network"] = settings["server_network"]
    sections["openvpn"] = openvpn
    return {**runtime, "sections": sections}


def _router_rows(definitions: Any) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {
        "sources": [],
        "routes": [],
        "address_lists": [],
        "firewall_rules": [],
    }
    sources = sorted({definition.router_source for definition in definitions})
    for source in sources:
        routes = _netctl(["routes", "list", "--source", source])
        address_lists = _netctl(["address-lists", "list", "--source", source])
        rows["routes"].extend(_rows(routes.get("routes")))
        rows["address_lists"].extend(_rows(address_lists.get("address_lists")))
        rows["sources"].extend(_rows(address_lists.get("sources")))
        for table in ("filter", "nat", "mangle"):
            rules = _netctl(["firewall-rules", "list", "--table", table, "--source", source])
            rows["firewall_rules"].extend(_rows(rules.get("firewall_rules")))
            if not rows["sources"]:
                rows["sources"].extend(_rows(rules.get("sources")))
    return rows


def _vpnctl(args: list[str]) -> dict[str, Any]:
    try:
        return run_vpnctl(args, timeout=15)
    except VpnctlError:
        return {}


def _netctl(args: list[str]) -> dict[str, Any]:
    try:
        return run_netctl(args, timeout=15)
    except NetctlError as exc:
        try:
            value = json.loads(exc.stdout)
        except (TypeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}


def _public_path(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": row.get("role") if isinstance(row.get("role"), str) else "",
        "status": row.get("status") if isinstance(row.get("status"), str) else "unknown",
        "collected_at": row.get("collected_at") if isinstance(row.get("collected_at"), str) else "",
        "checks": [
            {
                "name": check.get("name") if isinstance(check.get("name"), str) else "check",
                "status": check.get("status") if isinstance(check.get("status"), str) else "unknown",
                "message": check.get("message") if isinstance(check.get("message"), str) else "Evidence check",
            }
            for check in _rows(row.get("checks"))
        ],
    }


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
