from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any, Callable

from netctl.db import read_context_snapshot

from .store import add_plan_step, canonical_sha256, create_change_plan


DEFAULT_PLAN_TTL_SECONDS = 300
MAX_PLAN_TTL_SECONDS = 900
DEFAULT_IDENTITY_OBSERVATION_MAX_AGE_SECONDS = 900


def _is_fresh(value: str, max_age_seconds: int) -> bool:
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - observed).total_seconds() <= max_age_seconds


def _validate_security_thresholds(*, plan_ttl_seconds: int, identity_observation_max_age_seconds: int) -> None:
    if not 0 < plan_ttl_seconds <= MAX_PLAN_TTL_SECONDS:
        raise ValueError("plan TTL must be between one second and fifteen minutes")
    if not 0 < identity_observation_max_age_seconds <= MAX_PLAN_TTL_SECONDS:
        raise ValueError("identity observation maximum age must be between one second and fifteen minutes")


def resolve_asset_targets(
    conn: sqlite3.Connection,
    asset_key: str,
    *,
    enforcement_sources_by_site: dict[str, str],
    source_sla_seconds: int,
    anchor_check: Callable[[str], bool],
    identity_observation_max_age_seconds: int = DEFAULT_IDENTITY_OBSERVATION_MAX_AGE_SECONDS,
) -> list[dict[str, str]]:
    asset = conn.execute("SELECT id, provisional, status FROM assets WHERE asset_key = ?", (asset_key,)).fetchone()
    if asset is None or bool(asset["provisional"]) or str(asset["status"] or "").lower() == "retired":
        raise ValueError("asset is absent or provisional")
    collision = conn.execute(
        """SELECT 1 FROM runtime_identity_findings
           WHERE asset_id = ? AND status = 'open' AND finding_type LIKE '%collision%' LIMIT 1""",
        (asset["id"],),
    ).fetchone()
    if collision is not None:
        raise ValueError("asset has an open identity collision")
    ambiguous_attachment = conn.execute(
        """SELECT 1 FROM asset_attachment_resolutions
           WHERE asset_id = ? AND status IN ('ambiguous', 'uplink_only', 'unresolved') LIMIT 1""",
        (asset["id"],),
    ).fetchone()
    if ambiguous_attachment is not None:
        raise ValueError("asset attachment is ambiguous or unresolved")
    rows = conn.execute(
        """SELECT observations.id, observations.asset_interface_id, observations.ip, observations.site, observations.source_id,
                  sources.name AS source_name, sources.site AS source_site,
                  sources.last_collect_at, sources.last_status, observations.last_seen_at
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
        if not _is_fresh(str(row["last_seen_at"] or ""), identity_observation_max_age_seconds):
            raise ValueError("current IP observation is stale")
        duplicate = conn.execute(
            """SELECT 1 FROM ip_observations
               WHERE ip = ? AND is_current = 1 AND asset_id <> ? LIMIT 1""",
            (str(address), asset["id"]),
        ).fetchone()
        if duplicate is not None:
            raise ValueError("duplicate current IP is bound to another asset")
        site = str(row["site"] or row["source_site"] or "")
        enforcement_source = enforcement_sources_by_site.get(site)
        if not site or not enforcement_source:
            raise ValueError("current IP has unresolved enforcement point")
        if str(row["last_status"] or "") not in {"ok", "success"} or not _is_fresh(str(row["last_collect_at"] or ""), source_sla_seconds):
            raise ValueError("source collection is stale or failed")
        anchor = anchor_check(enforcement_source)
        if isinstance(anchor, dict):
            anchor_valid = bool(anchor.get("valid"))
            fingerprint = str(anchor.get("fingerprint") or "")
            address_list = str(anchor.get("anchor") or "")
        else:
            anchor_valid = bool(anchor)
            fingerprint = ""
            address_list = ""
        if not anchor_valid:
            raise ValueError("Internet policy anchor pre-check failed")
        targets.append({"source": enforcement_source, "address": str(address), "site": site,
                        "anchor_fingerprint": fingerprint, "address_list": address_list})
    unique = {(item["source"], item["address"], item["site"]): item for item in targets}
    if not unique:
        raise ValueError("asset has no current IPv4 observation")
    return [unique[key] for key in sorted(unique)]


def _asset_plan_basis(
    conn: sqlite3.Connection,
    asset_key: str,
    *,
    enforcement_sources_by_site: dict[str, str],
    source_sla_seconds: int,
    anchor_check: Callable[[str], bool],
    identity_observation_max_age_seconds: int,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Capture every context fact whose later change must invalidate an approved plan."""
    targets = resolve_asset_targets(
        conn, asset_key, enforcement_sources_by_site=enforcement_sources_by_site,
        source_sla_seconds=source_sla_seconds, anchor_check=anchor_check,
        identity_observation_max_age_seconds=identity_observation_max_age_seconds,
    )
    asset = conn.execute(
        "SELECT id, asset_key, provisional, status, updated_at FROM assets WHERE asset_key = ?", (asset_key,)
    ).fetchone()
    if asset is None:  # resolve_asset_targets above is intentionally the primary eligibility gate.
        raise ValueError("asset is absent or provisional")
    interfaces = [dict(row) for row in conn.execute(
        """SELECT id, mac, lifecycle, first_seen_at, last_seen_at
           FROM asset_interfaces WHERE asset_id = ? ORDER BY id""", (asset["id"],)
    ).fetchall()]
    observations = [dict(row) for row in conn.execute(
        """SELECT id, asset_interface_id, source_id, ip, first_seen_at, last_seen_at, is_current
           FROM ip_observations WHERE asset_id = ? AND is_current = 1 ORDER BY id""", (asset["id"],)
    ).fetchall()]
    source_ids = sorted({int(row["source_id"]) for row in observations if row["source_id"] is not None})
    sources = [dict(row) for row in conn.execute(
        """SELECT id, name, site, last_collect_at, last_status, updated_at
           FROM network_sources WHERE id IN ({}) ORDER BY id""".format(",".join("?" for _ in source_ids)), source_ids
    ).fetchall()] if source_ids else []
    attachments = [dict(row) for row in conn.execute(
        """SELECT asset_interface_id, asset_id, status, selected_source_id, selected_port_key,
                  selected_vlan_key, selected_vlan_id, correlation_run_id, last_seen_at
           FROM asset_attachment_resolutions WHERE asset_id = ? ORDER BY asset_interface_id""", (asset["id"],)
    ).fetchall()]
    heads = [dict(row) for row in conn.execute(
        """SELECT heads.context_id, heads.context_revision_id, revisions.sha256
           FROM context_heads AS heads
           JOIN context_revisions AS revisions ON revisions.id = heads.context_revision_id
           ORDER BY heads.context_id"""
    ).fetchall()]
    return targets, {
        "basis_version": 1,
        "context_heads": heads,
        "asset": dict(asset),
        "interfaces": interfaces,
        "ip_observations": observations,
        "source_health": sources,
        "attachments": attachments,
        "enforcement": [
            {"source": item["source"], "site": item["site"], "address_list": item["address_list"]}
            for item in targets
        ],
        "firewall_anchors": [
            {"source": item["source"], "fingerprint": item["anchor_fingerprint"]}
            for item in targets
        ],
    }


def _basis_changes(planned: dict[str, Any], current: dict[str, Any]) -> list[str]:
    dimensions = (
        ("context_heads", "context_head"), ("asset", "asset"),
        ("interfaces", "asset_interfaces"), ("ip_observations", "ip_observations"),
        ("source_health", "source_health"), ("attachments", "attachment_resolution"),
        ("enforcement", "enforcement_point"), ("firewall_anchors", "firewall_anchor_fingerprint"),
    )
    return [name for key, name in dimensions if planned.get(key) != current.get(key)]


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
    plan_ttl_seconds: int = DEFAULT_PLAN_TTL_SECONDS,
    identity_observation_max_age_seconds: int = DEFAULT_IDENTITY_OBSERVATION_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    if desired_state not in {"allow", "deny"}:
        raise ValueError("unknown desired state")
    _validate_security_thresholds(
        plan_ttl_seconds=plan_ttl_seconds,
        identity_observation_max_age_seconds=identity_observation_max_age_seconds,
    )
    with read_context_snapshot(netctl_db_url) as context:
        targets, plan_basis = _asset_plan_basis(
            context, asset_key, enforcement_sources_by_site=enforcement_sources_by_site,
            source_sla_seconds=source_sla_seconds, anchor_check=anchor_check,
            identity_observation_max_age_seconds=identity_observation_max_age_seconds,
        )
    action = "ensure_address_list_entry" if desired_state == "deny" else "remove_address_list_entry"
    rollback_action = "remove_address_list_entry" if desired_state == "deny" else "ensure_address_list_entry"
    rollback = {"steps": [{"adapter": "mikrotik", "operation": rollback_action, "target_key": item["source"], "request": {"address": item["address"], "asset_key": asset_key}} for item in targets]}
    plan = create_change_plan(
        netops_conn, plan_key=plan_key, actor=actor, reason=reason, subject_type="asset", subject_key=asset_key,
        operation_type="internet_access_set", desired_state={"internet_access": desired_state}, resolved_targets=targets,
        context_evidence_hash=canonical_sha256(plan_basis).removeprefix("sha256:"),
        precheck={"anchor": "validated", "plan_ttl_seconds": plan_ttl_seconds}, rollback=rollback,
        plan_basis=plan_basis,
    )
    for item in targets:
        add_plan_step(netops_conn, plan_key, adapter="mikrotik", operation=action, target_key=item["source"], request={"address": item["address"], "asset_key": asset_key})
    return plan


def changed_plan_preconditions(
    plan: sqlite3.Row,
    netctl_db_url: str,
    *,
    enforcement_sources_by_site: dict[str, str],
    source_sla_seconds: int,
    anchor_check: Callable[[str], bool],
    plan_ttl_seconds: int = DEFAULT_PLAN_TTL_SECONDS,
    identity_observation_max_age_seconds: int = DEFAULT_IDENTITY_OBSERVATION_MAX_AGE_SECONDS,
) -> list[str]:
    """Re-resolve the immutable asset target set immediately before writes."""
    _validate_security_thresholds(
        plan_ttl_seconds=plan_ttl_seconds,
        identity_observation_max_age_seconds=identity_observation_max_age_seconds,
    )
    try:
        created_at = datetime.fromisoformat(str(plan["created_at"]).replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            return ["plan_created_at"]
        age = (datetime.now(UTC) - created_at.astimezone(UTC)).total_seconds()
        if age < 0 or age > plan_ttl_seconds:
            return ["plan_expired"]
    except ValueError:
        return ["plan_created_at"]
    desired = json.loads(str(plan["desired_state_json"]))
    asset_key = str(desired.get("resolved_enforcement_asset_key") or plan["subject_key"])
    try:
        with read_context_snapshot(netctl_db_url) as context:
            current, current_basis = _asset_plan_basis(
                context, asset_key, enforcement_sources_by_site=enforcement_sources_by_site,
                source_sla_seconds=source_sla_seconds, anchor_check=anchor_check,
                identity_observation_max_age_seconds=identity_observation_max_age_seconds,
            )
            current_user_binding: dict[str, str] | None = None
            if str(plan["subject_type"]) == "user":
                from netctl.user_context import resolve_policy_asset_for_user

                resolved = resolve_policy_asset_for_user(context, str(plan["subject_key"]))
                if resolved is not None:
                    current_user_binding = {
                        "user_key": str(plan["subject_key"]),
                        "asset_key": str(resolved["asset_key"]),
                    }
    except ValueError as exc:
        return [str(exc)]
    try:
        planned_basis = json.loads(str(plan["plan_basis_json"]))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return ["plan_basis"]
    if str(plan["plan_basis_hash"] or "") != canonical_sha256(planned_basis):
        return ["plan_basis"]
    if str(plan["subject_type"]) == "user" and planned_basis.get("user_policy_binding") != current_user_binding:
        return ["user_policy_binding"]
    basis_changes = _basis_changes(planned_basis, current_basis)
    if basis_changes:
        return basis_changes
    planned = json.loads(str(plan["resolved_targets_json"]))
    if current != planned:
        return ["ip_observations"]
    return []


def create_user_internet_access_plan(
    netops_conn: sqlite3.Connection,
    netctl_db_url: str,
    *,
    plan_key: str,
    actor: str,
    user_key: str,
    desired_state: str,
    reason: str,
    enforcement_sources_by_site: dict[str, str],
    source_sla_seconds: int,
    anchor_check: Callable[[str], bool],
    plan_ttl_seconds: int = DEFAULT_PLAN_TTL_SECONDS,
    identity_observation_max_age_seconds: int = DEFAULT_IDENTITY_OBSERVATION_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Resolve only one confirmed primary asset, retaining user and asset provenance."""
    if desired_state not in {"allow", "deny"}:
        raise ValueError("unknown desired state")
    _validate_security_thresholds(
        plan_ttl_seconds=plan_ttl_seconds,
        identity_observation_max_age_seconds=identity_observation_max_age_seconds,
    )
    with read_context_snapshot(netctl_db_url) as context:
        from netctl.user_context import resolve_policy_asset_for_user

        resolved = resolve_policy_asset_for_user(context, user_key)
        if resolved is None:
            raise ValueError("user has no eligible confirmed primary asset")
        asset_key = resolved["asset_key"]
        targets, plan_basis = _asset_plan_basis(
            context, asset_key, enforcement_sources_by_site=enforcement_sources_by_site,
            source_sla_seconds=source_sla_seconds, anchor_check=anchor_check,
            identity_observation_max_age_seconds=identity_observation_max_age_seconds,
        )
        plan_basis["user_policy_binding"] = {"user_key": user_key, "asset_key": asset_key}
    action = "ensure_address_list_entry" if desired_state == "deny" else "remove_address_list_entry"
    rollback_action = "remove_address_list_entry" if desired_state == "deny" else "ensure_address_list_entry"
    plan = create_change_plan(
        netops_conn, plan_key=plan_key, actor=actor, reason=reason, subject_type="user", subject_key=user_key,
        operation_type="internet_access_set",
        desired_state={"internet_access": desired_state, "resolved_enforcement_asset_key": asset_key},
        resolved_targets=targets, context_evidence_hash=canonical_sha256(plan_basis).removeprefix("sha256:"),
        precheck={"anchor": "validated", "plan_ttl_seconds": plan_ttl_seconds}, plan_basis=plan_basis,
        rollback={"steps": [{"adapter": "mikrotik", "operation": rollback_action, "target_key": item["source"], "request": {"address": item["address"], "asset_key": asset_key}} for item in targets]},
    )
    for item in targets:
        add_plan_step(netops_conn, plan_key, adapter="mikrotik", operation=action, target_key=item["source"], request={"address": item["address"], "asset_key": asset_key})
    return plan
