from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .path_engine import PathExplanation, PathRequest, PathVerdict, explain_path
from .runtime_assets import get_runtime_asset_by_key, list_current_ip_observations


DEFAULT_PATH_FACT_MAX_AGE_SECONDS = 900


def _as_records(conn: sqlite3.Connection, query: str, params: tuple[object, ...]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for row in conn.execute(query, params).fetchall():
        item = dict(row)
        if "unsupported_matchers_json" in item:
            try:
                item["unsupported_matchers"] = tuple(json.loads(str(item.pop("unsupported_matchers_json") or "[]")))
            except (TypeError, ValueError, json.JSONDecodeError):
                item["unsupported_matchers"] = ("invalid_stored_matchers",)
        records.append(item)
    return records


def _facts_are_fresh(conn: sqlite3.Connection, source_id: int, max_age_seconds: int) -> bool:
    row = conn.execute(
        """SELECT status, finished_at FROM router_path_fact_runs
           WHERE source_id = ? ORDER BY id DESC LIMIT 1""",
        (source_id,),
    ).fetchone()
    if row is None or str(row["status"]) != "success":
        return False
    try:
        observed_at = datetime.fromisoformat(str(row["finished_at"]).replace("Z", "+00:00"))
    except ValueError:
        return False
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=UTC)
    return (datetime.now(UTC) - observed_at).total_seconds() <= max_age_seconds


def _unknown(asset_key: str, source_ips: tuple[str, ...], reason: str) -> PathExplanation:
    return PathExplanation(
        verdict=PathVerdict.UNKNOWN,
        source_asset_key=asset_key,
        source_ips=source_ips,
        enforcement_source="",
        selected_routing_table="main",
        selected_route=None,
        stages=(),
        unknown_reasons=(reason,),
        evidence=({"scope": "forward_only", "reverse_path_analyzed": False},),
    )


def explain_asset_path(
    conn: sqlite3.Connection,
    request: PathRequest,
    *,
    max_age_seconds: int = DEFAULT_PATH_FACT_MAX_AGE_SECONDS,
) -> PathExplanation | None:
    """Compose a read-only path explanation from one asset and one router source."""
    asset = get_runtime_asset_by_key(conn, request.asset_key)
    if asset is None:
        return None
    observations = list_current_ip_observations(conn, int(asset["id"]))
    source_ips = tuple(sorted({str(row["ip"]) for row in observations if row.get("ip")}))
    source_ids = {int(row["source_id"]) for row in observations if row.get("source_id") is not None}
    if len(source_ids) != 1:
        return _unknown(request.asset_key, source_ips, "no_router_source_context")
    source_id = next(iter(source_ids))
    facts_fresh = _facts_are_fresh(conn, source_id, max_age_seconds)
    routes = _as_records(conn, "SELECT * FROM network_routes WHERE source_id = ?", (source_id,))
    routing_rules = _as_records(conn, "SELECT * FROM router_routing_rules WHERE source_id = ? ORDER BY position, rule_key", (source_id,))
    filters = _as_records(conn, "SELECT * FROM router_filter_rules WHERE source_id = ? ORDER BY position, rule_key", (source_id,))
    nat_rules = _as_records(conn, "SELECT * FROM router_nat_rules WHERE source_id = ? ORDER BY position, rule_key", (source_id,))
    address_lists = _as_records(conn, "SELECT * FROM router_address_list_entries WHERE source_id = ? ORDER BY rule_key", (source_id,))
    ipsec_policies = _as_records(conn, "SELECT * FROM router_ipsec_policies WHERE source_id = ? ORDER BY position, rule_key", (source_id,))
    return explain_path(
        request,
        source_ips=source_ips,
        routes=routes,
        filter_rules=filters,
        routing_rules=routing_rules,
        nat_rules=nat_rules,
        address_lists=address_lists,
        ipsec_policies=ipsec_policies,
        facts_fresh=facts_fresh,
    )
