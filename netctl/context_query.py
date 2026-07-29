from __future__ import annotations

import json
import sqlite3
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from .normalizer import normalize_mac
from .findings import findings_for_asset
from .runtime_assets import (
    get_runtime_asset_by_key,
    list_asset_interfaces,
    list_current_hostname_observations,
    list_current_ip_observations,
    resolve_best_hostname_observation,
)
from .util import utc_now


ATTACHMENT_REASON_LABELS = {
    "oper_status_unknown": "статус порта не получен",
    "competing_fdb": "есть конкурирующая FDB-запись",
    "verified_backbone_port": "это подтверждённый uplink",
    "partial_collection": "сбор коммутатора неполный",
}
MAX_ATTACHMENT_EVIDENCE_DEPTH = 16


def _asset_public(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        key: asset[key]
        for key in ("asset_key", "manual_name", "kind", "status", "site", "location", "display_name", "identity_method", "identity_confidence", "provisional")
        if key in asset
    }


def context_snapshot(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the bounded revision/run markers used by one context response."""
    head = conn.execute(
        "SELECT context_revision_id FROM context_heads ORDER BY context_id LIMIT 1"
    ).fetchone()
    runs = {
        str(row["run_type"]): int(row["id"])
        for row in conn.execute(
            """SELECT runs.id, runs.run_type FROM network_correlation_runs AS runs
               JOIN (
                   SELECT run_type, max(id) AS id FROM network_correlation_runs
                   WHERE status = 'success' GROUP BY run_type
               ) AS latest ON latest.id = runs.id"""
        )
    }
    cutoff = conn.execute(
        """SELECT max(value) FROM (
               SELECT max(last_seen_at) AS value FROM ip_observations WHERE is_current = 1
               UNION ALL
               SELECT max(last_seen_at) AS value FROM hostname_observations WHERE is_current = 1
           )"""
    ).fetchone()[0]
    return {
        "context_revision_id": int(head["context_revision_id"]) if head is not None else None,
        "topology_correlation_run_id": runs.get("topology"),
        "attachment_correlation_run_id": runs.get("attachments"),
        "observation_cutoff": str(cutoff or ""),
    }


def _port_peers(
    conn: sqlite3.Connection, asset_id: int, source_id: int, port_key: str, limit: int = 32,
) -> dict[str, Any]:
    if not 1 <= limit <= 32:
        raise ValueError("port peer limit must be between 1 and 32")
    interfaces_by_mac: dict[str, list[dict[str, Any]]] = {}
    for row in conn.execute(
        """SELECT interfaces.asset_id, interfaces.mac, assets.asset_key, assets.display_name
           FROM asset_interfaces AS interfaces
           JOIN assets ON assets.id = interfaces.asset_id
           WHERE interfaces.lifecycle = 'active' AND interfaces.mac IS NOT NULL
           ORDER BY assets.display_name, assets.asset_key, interfaces.id"""
    ):
        mac = normalize_mac(row["mac"])
        if mac is not None:
            interfaces_by_mac.setdefault(mac, []).append(dict(row))
    known: list[dict[str, Any]] = []
    unknown_macs: set[str] = set()
    for row in conn.execute(
        """SELECT mac, vlan_key, vlan_id FROM current_switch_fdb
           WHERE source_id = ? AND port_key = ? AND lower(status) NOT IN ('self', 'mgmt')
           ORDER BY mac, vlan_key""",
        (source_id, port_key),
    ):
        mac = normalize_mac(row["mac"])
        if mac is None:
            continue
        matched = interfaces_by_mac.get(mac, [])
        if any(int(item["asset_id"]) == asset_id for item in matched):
            continue
        if not matched:
            unknown_macs.add(mac)
            continue
        for peer in matched:
            known.append({
                "asset": {"asset_key": str(peer["asset_key"]), "display_name": str(peer["display_name"] or "")},
                "mac": mac, "vlan_key": str(row["vlan_key"]),
                "vlan_id": int(row["vlan_id"]) if row["vlan_id"] is not None else None,
            })
    known.sort(key=lambda item: (str(item["asset"]["display_name"]).lower(), str(item["asset"]["asset_key"]), str(item["mac"]), str(item["vlan_key"])))
    return {
        "items": known[:limit],
        "known_asset_count": len({str(item["asset"]["asset_key"]) for item in known}),
        "unknown_mac_count": len(unknown_macs),
        "truncated": len(known) > limit,
    }


def _attachment_evidence_items(evidence_json: object) -> list[dict[str, Any]]:
    """Decode collector evidence into dictionaries without exposing malformed input."""
    try:
        evidence = json.loads(str(evidence_json or "[]"))
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError):
        return []
    items = evidence if isinstance(evidence, list) else [evidence]
    return [item for item in items if isinstance(item, dict)]


def _nested_evidence_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Iteratively flatten only a bounded amount of untrusted evidence."""
    nested: list[dict[str, Any]] = []
    pending = [(item, 0) for item in reversed(items)]
    while pending:
        item, depth = pending.pop()
        nested.append(item)
        if depth >= MAX_ATTACHMENT_EVIDENCE_DEPTH:
            continue
        children: list[dict[str, Any]] = []
        for value in item.values():
            if isinstance(value, dict):
                children.append(value)
            elif isinstance(value, list):
                children.extend(entry for entry in value if isinstance(entry, dict))
        pending.extend((child, depth + 1) for child in reversed(children))
    return nested


def _attachment_reason(evidence_json: object) -> str:
    """Project allowlisted attachment evidence without exposing collector detail."""
    items = _nested_evidence_items(_attachment_evidence_items(evidence_json))
    for item in items:
        reason = item.get("reason")
        if isinstance(reason, str) and reason in ATTACHMENT_REASON_LABELS:
            return ATTACHMENT_REASON_LABELS[reason]
    for item in items:
        if item.get("oper_status") in {"", "unknown", None} and "oper_status" in item:
            return ATTACHMENT_REASON_LABELS["oper_status_unknown"]
        if item.get("verified_backbone_port") is True:
            return ATTACHMENT_REASON_LABELS["verified_backbone_port"]
        if item.get("collector_status") == "partial":
            return ATTACHMENT_REASON_LABELS["partial_collection"]
    return ""


def _competing_direct_candidates(evidence_json: object) -> set[tuple[int, str, str]]:
    """Identify distinct direct candidates stored by attachment reconciliation."""
    candidates: set[tuple[int, str, str]] = set()
    for item in _nested_evidence_items(_attachment_evidence_items(evidence_json)):
        if item.get("candidate_class") != "direct":
            continue
        source_id = item.get("switch_source_id")
        port_key = item.get("port_key")
        vlan_key = item.get("vlan_key")
        if isinstance(source_id, int) and isinstance(port_key, str) and isinstance(vlan_key, str):
            candidates.add((source_id, port_key, vlan_key))
    return candidates if len(candidates) > 1 else set()


def _attachment(conn: sqlite3.Connection, asset_id: int, asset_interface_id: int | None = None) -> dict[str, Any] | None:
    conditions = ["resolutions.asset_id = ?"]
    params: list[object] = [asset_id]
    if asset_interface_id is not None:
        conditions.append("resolutions.asset_interface_id = ?")
        params.append(asset_interface_id)
    row = conn.execute(
        f"""SELECT resolutions.status, resolutions.selected_source_id, resolutions.selected_port_key,
                  resolutions.selected_vlan_key, resolutions.selected_vlan_id, resolutions.confidence,
                  resolutions.last_seen_at, sources.name AS switch_name, sources.site AS switch_site,
                  sources.host AS switch_host, ports.name AS port_name, ports.alias AS port_alias,
                  ports.admin_status AS port_admin_status, ports.oper_status AS port_oper_status,
                  resolutions.evidence_json AS evidence_json
           FROM asset_attachment_resolutions AS resolutions
           LEFT JOIN network_sources AS sources ON sources.id = resolutions.selected_source_id
           LEFT JOIN switch_ports AS ports
             ON ports.source_id = resolutions.selected_source_id AND ports.port_key = resolutions.selected_port_key
           WHERE {' AND '.join(conditions)} ORDER BY confidence DESC, asset_interface_id LIMIT 1""",
        params,
    ).fetchone()
    if row is None:
        return None
    attachment = {key: row[key] for key in ("status", "selected_source_id", "selected_port_key", "selected_vlan_key", "selected_vlan_id", "confidence", "last_seen_at")}
    alternatives = conn.execute(
        f"""SELECT sources.name AS source, candidates.switch_source_id AS source_id,
                  candidates.port_key, candidates.vlan_key,
                  candidates.vlan_id, candidates.candidate_class,
                  candidates.topology_depth, candidates.score, candidates.observed_at,
                  candidates.evidence_json
           FROM asset_attachment_candidates AS candidates
           LEFT JOIN network_sources AS sources ON sources.id = candidates.switch_source_id
           WHERE candidates.asset_id = ? {"AND candidates.asset_interface_id = ?" if asset_interface_id is not None else ""}
           ORDER BY candidates.score DESC, candidates.observed_at DESC,
                    sources.name, candidates.port_key, candidates.vlan_key
           LIMIT 32""",
        (asset_id, asset_interface_id) if asset_interface_id is not None else (asset_id,),
    ).fetchall()
    competing_direct_candidates = _competing_direct_candidates(row["evidence_json"])
    attachment["alternatives"] = []
    for item in alternatives:
        alternative = dict(item)
        candidate_key = (
            int(alternative.pop("source_id")),
            str(alternative.get("port_key") or ""),
            str(alternative.get("vlan_key") or ""),
        )
        reason = _attachment_reason(alternative.pop("evidence_json", ""))
        if candidate_key in competing_direct_candidates:
            reason = ATTACHMENT_REASON_LABELS["competing_fdb"]
        if reason:
            alternative["reason"] = reason
        attachment["alternatives"].append(alternative)
    if competing_direct_candidates:
        attachment["reason"] = ATTACHMENT_REASON_LABELS["competing_fdb"]
    elif reason := _attachment_reason(row["evidence_json"]):
        attachment["reason"] = reason
    attachment["switch"] = None
    attachment["port"] = None
    attachment["vlan_membership"] = None
    attachment["port_peers"] = None
    if attachment["status"] != "confirmed":
        return attachment
    source_id = attachment["selected_source_id"]
    port_key = str(attachment["selected_port_key"] or "")
    if source_id is None or not port_key:
        return attachment
    attachment["switch"] = {"id": int(source_id), "name": str(row["switch_name"] or ""), "site": str(row["switch_site"] or ""), "host": str(row["switch_host"] or "")}
    attachment["port"] = {
        "key": port_key, "name": str(row["port_name"] or ""), "alias": str(row["port_alias"] or ""),
        "admin_status": str(row["port_admin_status"] or "unknown"), "oper_status": str(row["port_oper_status"] or "unknown"),
    }
    vlan_id = attachment["selected_vlan_id"]
    if vlan_id is not None:
        membership = conn.execute(
            """SELECT vlan_id, egress, untagged, pvid FROM current_switch_vlan_memberships
               WHERE source_id = ? AND port_key = ? AND vlan_id = ?""",
            (source_id, port_key, vlan_id),
        ).fetchone()
        if membership is not None:
            attachment["vlan_membership"] = {"vlan_id": int(membership["vlan_id"]), "egress": bool(membership["egress"]), "untagged": bool(membership["untagged"]), "pvid": bool(membership["pvid"])}
    attachment["port_peers"] = _port_peers(conn, asset_id, int(source_id), port_key)
    return attachment


def _owner(conn: sqlite3.Connection, asset_id: int) -> dict[str, Any]:
    timestamp = utc_now()
    rows = [dict(row) for row in conn.execute(
        """SELECT users.user_key, users.display_name, bindings.relation, bindings.status,
                  bindings.confidence, bindings.valid_from, bindings.valid_until, bindings.binding_source
           FROM user_asset_bindings AS bindings
           JOIN users ON users.id = bindings.user_id
           WHERE bindings.asset_id = ? AND users.status = 'active' AND bindings.status = 'confirmed'
             AND bindings.relation IN ('owner', 'primary_user', 'shared_user')
             AND bindings.valid_from <= ? AND (bindings.valid_until IS NULL OR bindings.valid_until > ?)
           ORDER BY users.user_key, bindings.id LIMIT 32""",
        (asset_id, timestamp, timestamp),
    )]
    shared = [row for row in rows if row["relation"] == "shared_user"]
    exclusive = [row for row in rows if row["relation"] in {"owner", "primary_user"}]
    if shared:
        status = "shared"
    elif len(exclusive) == 1:
        status = "confirmed"
    elif len(exclusive) > 1:
        status = "ambiguous"
    else:
        status = "none"
    return {"status": status, "bindings": rows}


def _intent(conn: sqlite3.Connection, asset_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT context_id, intent_stable_id, binding_source, confidence, status, last_seen_at
           FROM asset_intent_bindings WHERE asset_id = ?
           ORDER BY confidence DESC, last_seen_at DESC, id DESC LIMIT 1""",
        (asset_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def _source_health(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            "SELECT name AS source, last_collect_at, last_status FROM network_sources ORDER BY name, id LIMIT 64"
        )
    ]


def _topology_path(conn: sqlite3.Connection, attachment: dict[str, Any] | None) -> dict[str, Any]:
    if attachment is None or attachment.get("status") != "confirmed" or attachment.get("selected_source_id") is None:
        return {"nodes": [], "hops": [], "complete": False, "reason": "no_attachment"}
    roots: set[int] = set()
    for row in conn.execute("SELECT id, driver_options_json FROM network_sources"):
        try:
            options = json.loads(str(row["driver_options_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            options = {}
        if isinstance(options, dict) and options.get("topology_role") == "core":
            roots.add(int(row["id"]))
    start = int(attachment["selected_source_id"])
    adjacency: dict[int, list[tuple[int, dict[str, Any], bool]]] = {}
    for raw in conn.execute(
        """SELECT link_key, source_a_id, port_a_key, source_b_id, port_b_key, state, confidence
           FROM current_switch_links WHERE state != 'conflicting' ORDER BY link_key"""
    ):
        row = dict(raw)
        first, second = int(row["source_a_id"]), int(row["source_b_id"])
        adjacency.setdefault(first, []).append((second, row, True))
        adjacency.setdefault(second, []).append((first, row, False))
    queue: deque[tuple[int, list[int], list[tuple[dict[str, Any], bool]]]] = deque([(start, [start], [])])
    seen = {start}
    while queue:
        source_id, path, edges = queue.popleft()
        if source_id in roots:
            return {"nodes": path[:32], "hops": _path_hops(conn, edges[:31]), "complete": True, "reason": ""}
        for peer, edge, forward in sorted(adjacency.get(source_id, []), key=lambda item: (item[0], item[1]["link_key"])):
            if peer not in seen:
                seen.add(peer)
                queue.append((peer, path + [peer], edges + [(edge, forward)]))
    return {"nodes": [start], "hops": [], "complete": False, "reason": "no_core_path"}


def _path_hops(conn: sqlite3.Connection, edges: list[tuple[dict[str, Any], bool]]) -> list[dict[str, Any]]:
    sources = {
        int(row["id"]): {"id": int(row["id"]), "name": str(row["name"] or ""), "site": str(row["site"] or "")}
        for row in conn.execute("SELECT id, name, site FROM network_sources")
    }
    hops: list[dict[str, Any]] = []
    for edge, forward in edges:
        from_id, to_id = (int(edge["source_a_id"]), int(edge["source_b_id"])) if forward else (int(edge["source_b_id"]), int(edge["source_a_id"]))
        from_key, to_key = (str(edge["port_a_key"]), str(edge["port_b_key"])) if forward else (str(edge["port_b_key"]), str(edge["port_a_key"]))
        from_port = conn.execute("SELECT name FROM switch_ports WHERE source_id = ? AND port_key = ?", (from_id, from_key)).fetchone()
        to_port = conn.execute("SELECT name FROM switch_ports WHERE source_id = ? AND port_key = ?", (to_id, to_key)).fetchone()
        hops.append({
            "from": {**sources.get(from_id, {"id": from_id, "name": "", "site": ""}), "port": {"key": from_key, "name": str(from_port["name"] or "") if from_port is not None else ""}},
            "to": {**sources.get(to_id, {"id": to_id, "name": "", "site": ""}), "port": {"key": to_key, "name": str(to_port["name"] or "") if to_port is not None else ""}},
            "state": str(edge["state"]), "confidence": int(edge["confidence"]),
        })
    return hops


def _attachment_events(conn: sqlite3.Connection, asset_id: int) -> list[dict[str, Any]]:
    now = datetime.fromisoformat(utc_now().replace("Z", "+00:00")).astimezone(UTC)
    cutoff = (now - timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rows = conn.execute(
        """SELECT event_type, before_json, after_json, observed_at FROM asset_attachment_events
           WHERE asset_id = ? AND observed_at >= ? ORDER BY observed_at DESC, id DESC LIMIT 30""",
        (asset_id, cutoff),
    ).fetchall()
    return [{"event_type": str(row["event_type"]), "observed_at": str(row["observed_at"]), "before": _attachment_selection_public(row["before_json"]), "after": _attachment_selection_public(row["after_json"])} for row in rows]


def _attachment_selection_public(value: object) -> dict[str, Any]:
    try:
        raw = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    source_id, vlan_id, confidence = raw.get("selected_source_id"), raw.get("selected_vlan_id"), raw.get("confidence")
    return {
        "status": str(raw.get("status") or ""),
        "selected_source_id": int(source_id) if isinstance(source_id, int) and not isinstance(source_id, bool) else None,
        "selected_port_key": str(raw.get("selected_port_key") or ""), "selected_vlan_key": str(raw.get("selected_vlan_key") or ""),
        "selected_vlan_id": int(vlan_id) if isinstance(vlan_id, int) and not isinstance(vlan_id, bool) else None,
        "confidence": int(confidence) if isinstance(confidence, int) and not isinstance(confidence, bool) else None,
    }


def _freshness(conn: sqlite3.Connection) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for run_type, prefix in (("topology", "topology"), ("attachments", "attachment")):
        row = conn.execute(
            """SELECT finished_at, source_watermark_json FROM network_correlation_runs
               WHERE run_type = ? AND status = 'success' ORDER BY finished_at DESC, id DESC LIMIT 1""",
            (run_type,),
        ).fetchone()
        watermark: object = {}
        if row is not None:
            try:
                decoded = json.loads(str(row["source_watermark_json"] or "{}"))
                watermark = decoded if isinstance(decoded, dict) else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                watermark = {}
        result[f"{prefix}_reconciled_at"] = str(row["finished_at"] or "") if row is not None else ""
        result[f"{prefix}_source_watermark"] = watermark
    return result


def inspect_asset_context(conn: sqlite3.Connection, asset_key: str) -> dict[str, Any] | None:
    asset = get_runtime_asset_by_key(conn, asset_key)
    if asset is None:
        return None
    asset_id = int(asset["id"])
    attachment = _attachment(conn, asset_id)
    return {
        "asset": _asset_public(asset),
        "intent": _intent(conn, asset_id),
        "owner": _owner(conn, asset_id),
        "interfaces": [
            {
                **{key: item[key] for key in ("interface_key", "mac", "interface_type", "interface_name", "lifecycle") if key in item},
                "attachment": _attachment(conn, asset_id, int(item["id"])),
            }
            for item in list_asset_interfaces(conn, asset_id)[:32]
        ],
        "attachment": attachment,
        "network": {
            "ip_observations": list_current_ip_observations(conn, asset_id)[:64],
            "hostname_observations": list_current_hostname_observations(conn, asset_id)[:64],
            "best_hostname_observation": resolve_best_hostname_observation(
                conn, asset_id
            ),
        },
        "topology_path": _topology_path(conn, attachment),
        "attachment_events": _attachment_events(conn, asset_id),
        "freshness": _freshness(conn),
        "source_health": _source_health(conn),
        "findings": findings_for_asset(conn, asset_id),
        "evidence": {},
    }


def search_context_page(
    conn: sqlite3.Connection,
    query: str,
    limit: int = 25,
    after_kind: str = "",
    after_id: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if after_kind not in {"", "asset", "user"} or after_id < 0:
        raise ValueError("invalid search cursor")
    value = query.strip()
    if not value:
        return [], None
    normalized_mac = normalize_mac(value)
    params: list[object] = [value.lower(), value.lower(), value.lower(), value.lower()]
    conditions = ["lower(assets.asset_key) = ?", "lower(hostnames.hostname) = ?", "ips.ip = ?", "lower(intent_bindings.intent_stable_id) = ?"]
    if normalized_mac is not None:
        conditions.append("lower(replace(replace(interfaces.mac, ':', ''), '-', '')) = ?")
        params.append(normalized_mac.replace(":", "").lower())
    asset_cursor = " AND 1 = 0" if after_kind == "user" else " AND assets.id > ?" if after_kind == "asset" else ""
    asset_params: list[object] = [*params]
    if after_kind == "asset":
        asset_params.append(after_id)
    asset_params.append(limit + 1)
    asset_rows = conn.execute(
        f"""
        SELECT DISTINCT assets.id AS _cursor_id, assets.asset_key, assets.display_name, assets.kind, assets.site
        FROM assets
        LEFT JOIN asset_interfaces AS interfaces ON interfaces.asset_id = assets.id
        LEFT JOIN ip_observations AS ips ON ips.asset_id = assets.id AND ips.is_current = 1
        LEFT JOIN hostname_observations AS hostnames ON hostnames.asset_id = assets.id AND hostnames.is_current = 1
        LEFT JOIN asset_intent_bindings AS intent_bindings ON intent_bindings.asset_id = assets.id
        WHERE ({' OR '.join(conditions)}) {asset_cursor}
        ORDER BY assets.id
        LIMIT ?
        """,
        asset_params,
    ).fetchall()
    results = [dict(row) for row in asset_rows[:limit]]
    for item in results:
        item["bindings"] = _confirmed_asset_bindings(conn, str(item["asset_key"]))
        item.pop("_cursor_id", None)
    if len(asset_rows) > limit:
        return results, {"kind": "asset", "id": int(asset_rows[limit - 1]["_cursor_id"])}
    remaining = limit - len(results)
    if remaining == 0:
        return results, ({"kind": "asset", "id": int(asset_rows[-1]["_cursor_id"])} if asset_rows else None)
    user_cursor = " AND users.id > ?" if after_kind == "user" else ""
    user_params: list[object] = [value.lower(), value.lower()]
    if after_kind == "user":
        user_params.append(after_id)
    user_params.append(remaining + 1)
    users = conn.execute(
        """SELECT users.id AS _cursor_id, user_key, display_name, status
           FROM users
           WHERE (lower(user_key) = ? OR lower(display_name) = ?)""" + user_cursor + """
           ORDER BY users.id
           LIMIT ?""",
        user_params,
    ).fetchall()
    results.extend(
        {
            "result_type": "user",
            "user_key": row["user_key"],
            "display_name": row["display_name"],
            "status": row["status"],
            "bindings": _confirmed_user_bindings(conn, str(row["user_key"])),
        }
        for row in users[:remaining]
    )
    if len(users) > remaining:
        return results, {"kind": "user", "id": int(users[remaining - 1]["_cursor_id"])}
    return results, None


def search_context(conn: sqlite3.Connection, query: str, limit: int = 25) -> list[dict[str, Any]]:
    return search_context_page(conn, query, limit)[0]


def _confirmed_asset_bindings(conn: sqlite3.Connection, asset_key: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT users.user_key, users.display_name, bindings.relation, bindings.confidence
           FROM user_asset_bindings AS bindings
           JOIN users ON users.id = bindings.user_id
           JOIN assets ON assets.id = bindings.asset_id
           WHERE assets.asset_key = ? AND bindings.status = 'confirmed'
           ORDER BY users.user_key, bindings.id LIMIT 32""",
        (asset_key,),
    ).fetchall()
    return [dict(row) for row in rows]


def _confirmed_user_bindings(conn: sqlite3.Connection, user_key: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT assets.asset_key, bindings.relation
           FROM user_asset_bindings AS bindings
           JOIN users ON users.id = bindings.user_id
           JOIN assets ON assets.id = bindings.asset_id
           WHERE users.user_key = ? AND bindings.status = 'confirmed'
           ORDER BY assets.asset_key, bindings.id LIMIT 32""",
        (user_key,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_topology_context(
    conn: sqlite3.Connection,
    site: str = "",
    state: str = "",
    depth: int = 3,
) -> list[dict[str, Any]]:
    return topology_context(conn, site, state, depth)["links"]


def topology_context(
    conn: sqlite3.Connection,
    site: str = "",
    state: str = "",
    depth: int = 3,
    max_nodes: int = 250,
) -> dict[str, Any]:
    if not 1 <= depth <= 8:
        raise ValueError("depth must be between 1 and 8")
    if not 1 <= max_nodes <= 1000:
        raise ValueError("max_nodes must be between 1 and 1000")
    if state not in {"", "confirmed", "inferred", "ambiguous", "conflicting"}:
        raise ValueError("invalid topology state")
    conditions: list[str] = []
    params: list[object] = []
    if site:
        conditions.append("(source_a.site = ? OR source_b.site = ?)")
        params.extend([site, site])
    if state:
        conditions.append("links.state = ?")
        params.append(state)
    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = conn.execute(
        f"""
        SELECT links.link_key, links.port_a_key, links.port_b_key, links.state,
               links.confidence, links.first_seen_at, links.last_seen_at,
               links.source_a_id, links.source_b_id,
               source_a.name AS source_a, source_b.name AS source_b
        FROM current_switch_links AS links
        JOIN network_sources AS source_a ON source_a.id = links.source_a_id
        JOIN network_sources AS source_b ON source_b.id = links.source_b_id
        {where}
        ORDER BY links.link_key
        LIMIT 2048
        """,
        params,
    ).fetchall()
    roots: set[int] = set()
    for source in conn.execute("SELECT id, driver_options_json FROM network_sources"):
        try:
            options = json.loads(str(source["driver_options_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            options = {}
        if isinstance(options, dict) and options.get("topology_role") == "core":
            roots.add(int(source["id"]))
    adjacency: dict[int, set[int]] = {}
    for row in rows:
        first, second = int(row["source_a_id"]), int(row["source_b_id"])
        adjacency.setdefault(first, set()).add(second)
        adjacency.setdefault(second, set()).add(first)
    distances: dict[int, int] = {root: 0 for root in roots}
    queue: deque[int] = deque(sorted(roots))
    while queue:
        source_id = queue.popleft()
        if distances[source_id] >= depth:
            continue
        for peer in sorted(adjacency.get(source_id, set())):
            if peer not in distances:
                distances[peer] = distances[source_id] + 1
                queue.append(peer)
    links: list[dict[str, Any]] = []
    nodes: set[str] = set()
    truncated = False
    depth_truncated = False
    for row in rows:
        if roots and (distances.get(int(row["source_a_id"]), depth + 1) > depth or distances.get(int(row["source_b_id"]), depth + 1) > depth):
            depth_truncated = True
            continue
        link = dict(row)
        link.pop("source_a_id")
        link.pop("source_b_id")
        proposed = nodes | {str(link["source_a"]), str(link["source_b"])}
        if len(proposed) > max_nodes:
            truncated = True
            break
        links.append(link)
        nodes = proposed
    if len(rows) == 2048:
        truncated = True
    return {
        "links": links,
        "max_nodes": max_nodes,
        "node_count": len(nodes),
        "truncated": truncated or depth_truncated,
        "truncation_reason": "max_nodes" if truncated else "depth" if depth_truncated else "",
    }
