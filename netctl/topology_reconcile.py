from __future__ import annotations

import json
import sqlite3
from collections import defaultdict, deque
from dataclasses import asdict
from typing import Any, Iterable

from .source_identity import SourceIdentity, list_source_identities
from .topology_evidence import collect_link_evidence
from .topology_models import CurrentSwitchLink, LinkEndpoint, LinkEvidence


def _canonical_evidence(evidence: LinkEvidence) -> LinkEvidence | None:
    first, second = evidence.endpoint_a, evidence.endpoint_b
    if first.source_id == second.source_id:
        return None
    if first.source_id < second.source_id:
        return evidence
    return LinkEvidence(
        LinkEndpoint(second.source_id, second.port_key),
        LinkEndpoint(first.source_id, first.port_key),
        evidence.evidence_type,
        evidence.confidence,
        evidence.observed_at,
        evidence.intent_link_stable_id,
        evidence.details,
    )


def _evidence_key(evidence: LinkEvidence) -> tuple[object, ...]:
    return (
        evidence.evidence_type,
        evidence.endpoint_a.source_id,
        evidence.endpoint_a.port_key,
        evidence.endpoint_b.source_id,
        evidence.endpoint_b.port_key,
        evidence.intent_link_stable_id,
        evidence.observed_at,
        json.dumps(evidence.details, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    )


def _link_key(source_a_id: int, port_a_key: str, source_b_id: int, port_b_key: str) -> str:
    return f"{source_a_id}:{port_a_key}|{source_b_id}:{port_b_key}"


def _aggregate_pair(
    pair: tuple[int, int], evidence: list[LinkEvidence], observed_at: str
) -> CurrentSwitchLink:
    evidence = sorted(evidence, key=_evidence_key)
    a_ports = sorted({item.endpoint_a.port_key for item in evidence if item.endpoint_a.port_key})
    b_ports = sorted({item.endpoint_b.port_key for item in evidence if item.endpoint_b.port_key})
    conflicting = len(a_ports) > 1 or len(b_ports) > 1
    port_a_key = a_ports[0] if len(a_ports) == 1 else ""
    port_b_key = b_ports[0] if len(b_ports) == 1 else ""
    evidence_types = {item.evidence_type for item in evidence}
    intent_ids = sorted({item.intent_link_stable_id for item in evidence if item.intent_link_stable_id})
    intent_link_stable_id = intent_ids[0] if len(intent_ids) == 1 else ""

    if conflicting:
        state, confidence = "conflicting", 0
    elif "intent" in evidence_types and ({"lldp_chassis_mac", "fdb_management_mac"} & evidence_types):
        state = "confirmed"
        confidence = min(100, max(item.confidence for item in evidence) + 10)
    elif "lldp_chassis_mac" in evidence_types:
        state, confidence = "inferred", 85
    elif "fdb_management_mac" in evidence_types:
        state, confidence = "inferred", 70
    elif "intent" in evidence_types:
        state, confidence = "inferred", (60 if port_a_key and port_b_key else 45)
    else:
        state, confidence = "ambiguous", 0

    return CurrentSwitchLink(
        _link_key(pair[0], port_a_key, pair[1], port_b_key),
        pair[0],
        port_a_key,
        pair[1],
        port_b_key,
        state,
        confidence,
        intent_link_stable_id,
        observed_at,
        tuple(evidence),
    )


def aggregate_link_evidence(
    evidence: Iterable[LinkEvidence], observed_at: str
) -> tuple[CurrentSwitchLink, ...]:
    by_pair: dict[tuple[int, int], list[LinkEvidence]] = defaultdict(list)
    for item in evidence:
        if (canonical := _canonical_evidence(item)) is not None:
            by_pair[(canonical.endpoint_a.source_id, canonical.endpoint_b.source_id)].append(canonical)
    return tuple(
        _aggregate_pair(pair, by_pair[pair], observed_at)
        for pair in sorted(by_pair)
    )


def topology_depths(
    links: Iterable[CurrentSwitchLink], roots: set[int]
) -> dict[int, int]:
    ordered_roots = sorted(roots)
    if not ordered_roots:
        return {}
    adjacency: dict[int, set[int]] = defaultdict(set)
    for link in links:
        if link.state == "conflicting":
            continue
        adjacency[link.source_a_id].add(link.source_b_id)
        adjacency[link.source_b_id].add(link.source_a_id)
    depths = {root: 0 for root in ordered_roots}
    queue: deque[int] = deque(ordered_roots)
    while queue:
        source_id = queue.popleft()
        for peer_id in sorted(adjacency[source_id]):
            if peer_id not in depths:
                depths[peer_id] = depths[source_id] + 1
                queue.append(peer_id)
    return depths


def _evidence_public(evidence: LinkEvidence) -> dict[str, Any]:
    return {
        "endpoint_a": asdict(evidence.endpoint_a),
        "endpoint_b": asdict(evidence.endpoint_b),
        "evidence_type": evidence.evidence_type,
        "confidence": evidence.confidence,
        "observed_at": evidence.observed_at,
        "intent_link_stable_id": evidence.intent_link_stable_id,
        "details": evidence.details,
    }


def link_public(link: CurrentSwitchLink) -> dict[str, Any]:
    return {
        "link_key": link.link_key,
        "source_a_id": link.source_a_id,
        "port_a_key": link.port_a_key,
        "source_b_id": link.source_b_id,
        "port_b_key": link.port_b_key,
        "state": link.state,
        "confidence": link.confidence,
        "intent_link_stable_id": link.intent_link_stable_id,
        "observed_at": link.observed_at,
        "evidence": [_evidence_public(item) for item in link.evidence],
    }


def _row_public(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "link_key": str(row["link_key"]),
        "source_a_id": int(row["source_a_id"]),
        "port_a_key": str(row["port_a_key"]),
        "source_b_id": int(row["source_b_id"]),
        "port_b_key": str(row["port_b_key"]),
        "state": str(row["state"]),
        "confidence": int(row["confidence"]),
        "intent_link_stable_id": str(row["intent_link_stable_id"]),
        "evidence": json.loads(str(row["evidence_json"])),
    }


def _semantic_equal(before: dict[str, Any], after: CurrentSwitchLink) -> bool:
    public = link_public(after)
    public.pop("observed_at")
    return before == public


def _events(
    old_rows: list[sqlite3.Row], links: tuple[CurrentSwitchLink, ...]
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    old = {_row_public(row)["link_key"]: _row_public(row) for row in old_rows}
    new = {link.link_key: link for link in links}
    old_pairs: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    new_pairs: dict[tuple[int, int], list[CurrentSwitchLink]] = defaultdict(list)
    for row in old.values():
        old_pairs[(row["source_a_id"], row["source_b_id"])].append(row)
    for link in new.values():
        new_pairs[(link.source_a_id, link.source_b_id)].append(link)
    events: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for pair in sorted(set(old_pairs) | set(new_pairs)):
        previous, current = old_pairs.get(pair, []), new_pairs.get(pair, [])
        if len(previous) == len(current) == 1:
            before, after = previous[0], current[0]
            if before["link_key"] != after.link_key or not _semantic_equal(before, after):
                events.append(("changed", before, link_public(after)))
            continue
        for before in previous:
            events.append(("disappeared", before, {}))
        for after in current:
            events.append(("appeared", {}, link_public(after)))
    return events


def _context_revision_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute(
        "SELECT context_revision_id FROM context_heads ORDER BY context_id LIMIT 1"
    ).fetchone()
    return int(row[0]) if row is not None else None


def _insert_run(conn: sqlite3.Connection, observed_at: str) -> int:
    cursor = conn.execute(
        """
        INSERT INTO network_correlation_runs (
            run_type, started_at, status, context_revision_id, source_watermark_json
        ) VALUES ('topology', ?, 'running', ?, '{}')
        """,
        (observed_at, _context_revision_id(conn)),
    )
    conn.commit()
    return int(cursor.lastrowid)


def _replace_current_links(
    conn: sqlite3.Connection,
    links: tuple[CurrentSwitchLink, ...],
    run_id: int,
    observed_at: str,
) -> int:
    old_rows = conn.execute("SELECT * FROM current_switch_links ORDER BY link_key").fetchall()
    old_by_key = {str(row["link_key"]): row for row in old_rows}
    events = _events(old_rows, links)
    conn.execute("DELETE FROM current_switch_links")
    for link in links:
        previous = old_by_key.get(link.link_key)
        first_seen_at = str(previous["first_seen_at"]) if previous is not None else observed_at
        conn.execute(
            """
            INSERT INTO current_switch_links (
                link_key, source_a_id, port_a_key, source_b_id, port_b_key, state,
                confidence, intent_link_stable_id, first_seen_at, last_seen_at,
                correlation_run_id, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                link.link_key,
                link.source_a_id,
                link.port_a_key,
                link.source_b_id,
                link.port_b_key,
                link.state,
                link.confidence,
                link.intent_link_stable_id,
                first_seen_at,
                observed_at,
                run_id,
                json.dumps([_evidence_public(item) for item in link.evidence], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            ),
        )
    for event_type, before, after in events:
        link_key = str(after.get("link_key") or before.get("link_key"))
        conn.execute(
            """
            INSERT INTO switch_link_events (
                link_key, event_type, before_json, after_json, observed_at, correlation_run_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                link_key,
                event_type,
                json.dumps(before, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                json.dumps(after, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                observed_at,
                run_id,
            ),
        )
    return len(events)


def _replace_findings(
    conn: sqlite3.Connection, links: tuple[CurrentSwitchLink, ...], observed_at: str
) -> int:
    conn.execute("DELETE FROM topology_findings WHERE finding_type = 'incompatible_link_evidence'")
    conflicts = [link for link in links if link.state == "conflicting"]
    for link in conflicts:
        conn.execute(
            """
            INSERT INTO topology_findings (
                finding_key, finding_type, severity, status, source_id,
                first_seen_at, last_seen_at, details_json
            ) VALUES (?, 'incompatible_link_evidence', 'error', 'open', ?, ?, ?, ?)
            """,
            (
                f"incompatible-link:{link.source_a_id}:{link.source_b_id}",
                link.source_a_id,
                observed_at,
                observed_at,
                json.dumps(link_public(link), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            ),
        )
    return len(conflicts)


def reconcile_topology(conn: sqlite3.Connection, observed_at: str) -> dict[str, Any]:
    run_id = _insert_run(conn, observed_at)
    try:
        identities = list_source_identities(conn)
        links = aggregate_link_evidence(collect_link_evidence(conn, identities), observed_at)
        conn.execute("BEGIN IMMEDIATE")
        event_count = _replace_current_links(conn, links, run_id, observed_at)
        finding_count = _replace_findings(conn, links, observed_at)
        state_counts = {state: sum(link.state == state for link in links) for state in ("confirmed", "inferred", "ambiguous", "conflicting")}
        counts = {**state_counts, "links": len(links), "events": event_count, "findings": finding_count}
        conn.execute(
            """
            UPDATE network_correlation_runs
            SET status = 'success', finished_at = ?, counts_json = ?
            WHERE id = ?
            """,
            (observed_at, json.dumps(counts, sort_keys=True, separators=(",", ":")), run_id),
        )
        conn.commit()
        roots = {identity.source_id for identity in identities if identity.topology_role == "core"}
        return {"run_id": run_id, "counts": counts, "depths": topology_depths(links, roots)}
    except Exception as exc:
        if conn.in_transaction:
            conn.rollback()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE network_correlation_runs
            SET status = 'failed', finished_at = ?, error_class = ?, error_message = ?
            WHERE id = ?
            """,
            (observed_at, type(exc).__name__, str(exc), run_id),
        )
        conn.commit()
        raise
