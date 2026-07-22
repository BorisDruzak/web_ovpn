from __future__ import annotations

import ipaddress
import sqlite3
from datetime import UTC, datetime
from typing import Any, Callable

from netctl.db import connect_read_only

from .store import add_plan_step, create_change_plan


def _is_fresh(value: str, max_age_seconds: int) -> bool:
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - observed).total_seconds() <= max_age_seconds


def resolve_asset_targets(
    conn: sqlite3.Connection,
    asset_key: str,
    *,
    enforcement_sources_by_site: dict[str, str],
    source_sla_seconds: int,
    anchor_check: Callable[[str], bool],
) -> list[dict[str, str]]:
    asset = conn.execute("SELECT id, provisional FROM assets WHERE asset_key = ?", (asset_key,)).fetchone()
    if asset is None or bool(asset["provisional"]):
        raise ValueError("asset is absent or provisional")
    collision = conn.execute(
        """SELECT 1 FROM runtime_identity_findings
           WHERE asset_id = ? AND status = 'open' AND finding_type LIKE '%collision%' LIMIT 1""",
        (asset["id"],),
    ).fetchone()
    if collision is not None:
        raise ValueError("asset has an open identity collision")
    rows = conn.execute(
        """SELECT observations.ip, observations.site, observations.source_id,
                  sources.name AS source_name, sources.site AS source_site,
                  sources.last_collect_at, sources.last_status
           FROM ip_observations AS observations
           JOIN network_sources AS sources ON sources.id = observations.source_id
           WHERE observations.asset_id = ? AND observations.is_current = 1
           ORDER BY observations.ip, sources.name""",
        (asset["id"],),
    ).fetchall()
    targets: list[dict[str, str]] = []
    for row in rows:
        try:
            address = ipaddress.ip_address(str(row["ip"]))
        except ValueError:
            continue
        if address.version != 4:
            continue
        site = str(row["site"] or row["source_site"] or "")
        enforcement_source = enforcement_sources_by_site.get(site)
        if not site or not enforcement_source:
            raise ValueError("current IP has unresolved enforcement point")
        if str(row["last_status"] or "") != "success" or not _is_fresh(str(row["last_collect_at"] or ""), source_sla_seconds):
            raise ValueError("source collection is stale or failed")
        if not anchor_check(enforcement_source):
            raise ValueError("Internet policy anchor pre-check failed")
        targets.append({"source": enforcement_source, "address": str(address), "site": site})
    unique = {(item["source"], item["address"], item["site"]): item for item in targets}
    if not unique:
        raise ValueError("asset has no current IPv4 observation")
    return [unique[key] for key in sorted(unique)]


def create_asset_internet_access_plan(
    netops_conn: sqlite3.Connection,
    netctl_db_url: str,
    *,
    plan_key: str,
    actor: str,
    asset_key: str,
    desired_state: str,
    reason: str,
    enforcement_sources_by_site: dict[str, str],
    source_sla_seconds: int,
    anchor_check: Callable[[str], bool],
) -> dict[str, Any]:
    if desired_state not in {"allow", "deny"}:
        raise ValueError("unknown desired state")
    context = connect_read_only(netctl_db_url)
    try:
        targets = resolve_asset_targets(context, asset_key, enforcement_sources_by_site=enforcement_sources_by_site, source_sla_seconds=source_sla_seconds, anchor_check=anchor_check)
    finally:
        context.close()
    action = "ensure_address_list_entry" if desired_state == "deny" else "remove_address_list_entry"
    rollback_action = "remove_address_list_entry" if desired_state == "deny" else "ensure_address_list_entry"
    rollback = {"steps": [{"adapter": "mikrotik", "operation": rollback_action, "target_key": item["source"], "request": {"address": item["address"], "asset_key": asset_key}} for item in targets]}
    plan = create_change_plan(
        netops_conn, plan_key=plan_key, actor=actor, reason=reason, subject_type="asset", subject_key=asset_key,
        operation_type="internet_access_set", desired_state={"internet_access": desired_state}, resolved_targets=targets,
        context_evidence_hash="0" * 64, precheck={"anchor": "validated"}, rollback=rollback,
    )
    for item in targets:
        add_plan_step(netops_conn, plan_key, adapter="mikrotik", operation=action, target_key=item["source"], request={"address": item["address"], "asset_key": asset_key})
    return plan
