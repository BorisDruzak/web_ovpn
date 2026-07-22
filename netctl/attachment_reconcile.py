from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Sequence

from .attachment_candidates import AttachmentCandidate, attachment_candidates
from .normalizer import normalize_mac
from .source_identity import list_source_identities
from .topology_models import CurrentSwitchLink
from .topology_reconcile import topology_depths


@dataclass(frozen=True)
class AttachmentResolution:
    status: str
    selected: AttachmentCandidate | None
    confidence: int
    alternatives: tuple[AttachmentCandidate, ...]


def _candidate_order(candidate: AttachmentCandidate) -> tuple[object, ...]:
    return (
        -candidate.score,
        candidate.candidate_class != "direct",
        -(candidate.topology_depth if candidate.topology_depth is not None else -1),
        candidate.switch_source_id,
        candidate.port_key,
        candidate.vlan_key,
    )


def resolve_attachment(
    candidates: Sequence[AttachmentCandidate],
) -> AttachmentResolution:
    ordered = tuple(sorted(candidates, key=_candidate_order))
    if not ordered:
        return AttachmentResolution("unresolved", None, 0, ())
    if all(candidate.candidate_class == "uplink" for candidate in ordered):
        return AttachmentResolution("uplink_only", None, min(60, ordered[0].score), ordered)

    highest_direct = next(
        (candidate for candidate in ordered if candidate.candidate_class == "direct"),
        None,
    )
    if highest_direct is not None:
        next_score = max(
            (candidate.score for candidate in ordered if candidate != highest_direct),
            default=-100,
        )
        if highest_direct.score >= 75 and highest_direct.score - next_score >= 15:
            return AttachmentResolution(
                "confirmed", highest_direct, highest_direct.score, ordered
            )
    return AttachmentResolution("ambiguous", None, min(60, ordered[0].score), ordered)


def _candidate_public(candidate: AttachmentCandidate) -> dict[str, Any]:
    return {
        "asset_id": candidate.asset_id,
        "asset_interface_id": candidate.asset_interface_id,
        "switch_source_id": candidate.switch_source_id,
        "port_key": candidate.port_key,
        "vlan_key": candidate.vlan_key,
        "vlan_id": candidate.vlan_id,
        "candidate_class": candidate.candidate_class,
        "topology_depth": candidate.topology_depth,
        "score": candidate.score,
        "observed_at": candidate.observed_at,
        "evidence": list(candidate.evidence),
    }


def _current_links(conn: sqlite3.Connection) -> tuple[CurrentSwitchLink, ...]:
    return tuple(
        CurrentSwitchLink(
            str(row["link_key"]), int(row["source_a_id"]), str(row["port_a_key"]),
            int(row["source_b_id"]), str(row["port_b_key"]), str(row["state"]),
            int(row["confidence"]), str(row["intent_link_stable_id"]), str(row["last_seen_at"]), (),
        )
        for row in conn.execute("SELECT * FROM current_switch_links ORDER BY link_key")
    )


def _start_run(conn: sqlite3.Connection, observed_at: str) -> int:
    run_id = conn.execute(
        "INSERT INTO network_correlation_runs (run_type, started_at, status) VALUES ('attachments', ?, 'running')",
        (observed_at,),
    ).lastrowid
    conn.commit()
    return int(run_id)


def _eligible_interfaces(conn: sqlite3.Connection) -> dict[int, int]:
    eligible: dict[int, int] = {}
    rows = conn.execute(
        """
        SELECT interfaces.id AS interface_id, interfaces.asset_id, interfaces.mac, assets.site
        FROM asset_interfaces AS interfaces
        JOIN assets ON assets.id = interfaces.asset_id
        WHERE interfaces.lifecycle = 'active' AND interfaces.mac IS NOT NULL
          AND assets.status != 'retired'
        """
    ).fetchall()
    for row in rows:
        if normalize_mac(row["mac"]) is None:
            continue
        asset_id = int(row["asset_id"])
        observed = conn.execute(
            """
            SELECT 1 FROM ip_observations WHERE asset_id = ? AND is_current = 1
            UNION ALL
            SELECT 1 FROM hostname_observations WHERE asset_id = ? AND is_current = 1
            LIMIT 1
            """,
            (asset_id, asset_id),
        ).fetchone()
        successful_switch = conn.execute(
            """
            SELECT 1
            FROM network_sources AS sources
            JOIN switch_collection_runs AS runs ON runs.source_id = sources.id
            WHERE sources.site = ? AND runs.status = 'success'
            LIMIT 1
            """,
            (str(row["site"]),),
        ).fetchone()
        if observed is not None and successful_switch is not None:
            eligible[int(row["interface_id"])] = asset_id
    return eligible


def _write_candidates(
    conn: sqlite3.Connection, candidates: tuple[AttachmentCandidate, ...], run_id: int
) -> None:
    conn.execute("DELETE FROM asset_attachment_candidates")
    for candidate in candidates:
        conn.execute(
            """
            INSERT INTO asset_attachment_candidates (
                asset_interface_id, asset_id, switch_source_id, port_key, vlan_key,
                vlan_id, candidate_class, topology_depth, score, observed_at,
                correlation_run_id, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate.asset_interface_id, candidate.asset_id, candidate.switch_source_id,
                candidate.port_key, candidate.vlan_key, candidate.vlan_id,
                candidate.candidate_class, candidate.topology_depth, candidate.score,
                candidate.observed_at, run_id,
                json.dumps(list(candidate.evidence), sort_keys=True, separators=(",", ":")),
            ),
        )


def _resolution_public(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "asset_interface_id": int(row["asset_interface_id"]),
        "asset_id": int(row["asset_id"]), "status": str(row["status"]),
        "selected_source_id": row["selected_source_id"], "selected_port_key": str(row["selected_port_key"]),
        "selected_vlan_key": str(row["selected_vlan_key"]), "selected_vlan_id": row["selected_vlan_id"],
        "confidence": int(row["confidence"]),
    }


def _event_type(before: dict[str, Any], after: AttachmentResolution) -> str | None:
    if not before:
        return "attached" if after.status == "confirmed" else None
    if before["status"] == "ambiguous" and after.status == "confirmed":
        return "resolved_ambiguity"
    if after.status == "ambiguous" and before["status"] != "ambiguous":
        return "became_ambiguous"
    if before["status"] == "confirmed" and after.status != "confirmed":
        return "detached"
    if before["status"] == after.status == "confirmed" and after.selected is not None:
        if (before["selected_source_id"], before["selected_port_key"], before["selected_vlan_key"]) != (
            after.selected.switch_source_id, after.selected.port_key, after.selected.vlan_key
        ):
            return "moved"
    return None


def reconcile_attachments(conn: sqlite3.Connection, observed_at: str) -> dict[str, Any]:
    run_id = _start_run(conn, observed_at)
    try:
        identities = list_source_identities(conn)
        roots = {identity.source_id for identity in identities if identity.topology_role == "core"}
        candidates = attachment_candidates(conn, topology_depths(_current_links(conn), roots))
        eligible = _eligible_interfaces(conn)
        by_interface: dict[int, list[AttachmentCandidate]] = {
            interface_id: [] for interface_id in eligible
        }
        asset_by_interface = dict(eligible)
        for candidate in candidates:
            by_interface.setdefault(candidate.asset_interface_id, []).append(candidate)
            asset_by_interface[candidate.asset_interface_id] = candidate.asset_id
        resolutions = {
            interface_id: resolve_attachment(items)
            for interface_id, items in by_interface.items()
        }
        conn.execute("BEGIN IMMEDIATE")
        old = {
            int(row["asset_interface_id"]): row
            for row in conn.execute("SELECT * FROM asset_attachment_resolutions")
        }
        _write_candidates(conn, candidates, run_id)
        conn.execute(
            "DELETE FROM topology_findings WHERE finding_type IN ('attachment_ambiguous', 'attachment_uplink_only', 'attachment_unresolved')"
        )
        for interface_id, resolution in resolutions.items():
            candidate = resolution.selected
            asset_id = asset_by_interface[interface_id]
            before = _resolution_public(old.get(interface_id))
            after = {
                "asset_interface_id": interface_id, "asset_id": asset_id,
                "status": resolution.status,
                "selected_source_id": candidate.switch_source_id if candidate else None,
                "selected_port_key": candidate.port_key if candidate else "",
                "selected_vlan_key": candidate.vlan_key if candidate else "",
                "selected_vlan_id": candidate.vlan_id if candidate else None,
                "confidence": resolution.confidence,
            }
            first_seen = str(old[interface_id]["first_seen_at"]) if interface_id in old else observed_at
            conn.execute(
                """
                INSERT INTO asset_attachment_resolutions (
                    asset_interface_id, asset_id, status, selected_source_id, selected_port_key,
                    selected_vlan_key, selected_vlan_id, confidence, first_seen_at, last_seen_at,
                    correlation_run_id, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_interface_id) DO UPDATE SET
                    asset_id=excluded.asset_id, status=excluded.status,
                    selected_source_id=excluded.selected_source_id, selected_port_key=excluded.selected_port_key,
                    selected_vlan_key=excluded.selected_vlan_key, selected_vlan_id=excluded.selected_vlan_id,
                    confidence=excluded.confidence, last_seen_at=excluded.last_seen_at,
                    correlation_run_id=excluded.correlation_run_id, evidence_json=excluded.evidence_json
                """,
                (interface_id, asset_id, resolution.status, after["selected_source_id"], after["selected_port_key"],
                 after["selected_vlan_key"], after["selected_vlan_id"], resolution.confidence, first_seen,
                 observed_at, run_id, json.dumps([_candidate_public(item) for item in resolution.alternatives], sort_keys=True, separators=(",", ":"))),
            )
            if (event_type := _event_type(before, resolution)) is not None:
                conn.execute(
                    """INSERT INTO asset_attachment_events (
                        asset_interface_id, asset_id, event_type, before_json, after_json, observed_at, correlation_run_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (interface_id, asset_id, event_type, json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True), observed_at, run_id),
                )
            finding_type = {
                "ambiguous": "attachment_ambiguous",
                "uplink_only": "attachment_uplink_only",
                "unresolved": "attachment_unresolved",
            }.get(resolution.status)
            if finding_type is not None:
                conn.execute(
                    """INSERT INTO topology_findings (
                        finding_key, finding_type, severity, status, asset_id,
                        first_seen_at, last_seen_at, details_json
                    ) VALUES (?, ?, 'warning', 'open', ?, ?, ?, ?)""",
                    (f"{finding_type.replace('_', '-')}:{interface_id}", finding_type, asset_id,
                     observed_at, observed_at,
                     json.dumps({"resolution": after, "alternatives": [_candidate_public(item) for item in resolution.alternatives]}, sort_keys=True, separators=(",", ":"))),
                )
        counts = {status: sum(item.status == status for item in resolutions.values()) for status in ("confirmed", "ambiguous", "uplink_only", "unresolved")}
        counts.update(candidates=len(candidates), resolutions=len(resolutions))
        conn.execute("UPDATE network_correlation_runs SET status='success', finished_at=?, counts_json=? WHERE id=?", (observed_at, json.dumps(counts, sort_keys=True), run_id))
        conn.commit()
        return {"run_id": run_id, "counts": counts}
    except Exception as exc:
        if conn.in_transaction:
            conn.rollback()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE network_correlation_runs SET status='failed', finished_at=?, error_class=?, error_message=? WHERE id=?", (observed_at, type(exc).__name__, str(exc), run_id))
        conn.commit()
        raise
