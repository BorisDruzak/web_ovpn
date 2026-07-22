from __future__ import annotations

import json
import sqlite3
from collections import defaultdict

from .normalizer import normalize_mac
from .source_identity import SourceIdentity
from .topology_models import LinkEndpoint, LinkEvidence


def backbone_evidence(
    conn: sqlite3.Connection, *, site: str = "", limit: int = 100,
) -> list[dict[str, object]]:
    """Expose bounded, redacted evidence summaries for current source pairs."""
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    conditions: list[str] = []
    params: list[object] = []
    if site:
        conditions.append("(source_a.site = ? OR source_b.site = ?)")
        params.extend((site, site))
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    rows = conn.execute(
        """
        SELECT links.link_key, links.state, links.confidence, links.port_a_key, links.port_b_key,
               links.evidence_json, source_a.name AS source_a, source_b.name AS source_b
        FROM current_switch_links AS links
        JOIN network_sources AS source_a ON source_a.id = links.source_a_id
        JOIN network_sources AS source_b ON source_b.id = links.source_b_id
        """ + where + " ORDER BY links.link_key LIMIT ?",
        (*params, limit),
    ).fetchall()
    result: list[dict[str, object]] = []
    for row in rows:
        try:
            evidence = json.loads(str(row["evidence_json"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            evidence = []
        evidence_types = {
            str(item.get("evidence_type") or "") for item in evidence if isinstance(item, dict)
        }
        result.append({
            "source_a": str(row["source_a"]), "source_b": str(row["source_b"]),
            "state": str(row["state"]), "confidence": int(row["confidence"]),
            "intent": "intent" in evidence_types,
            "management_mac": "fdb_management_mac" in evidence_types,
            "lldp": "lldp_chassis_mac" in evidence_types,
            "ports_resolved": bool(row["port_a_key"] and row["port_b_key"]),
            "conflicting": str(row["state"]) == "conflicting",
        })
    return result


def _normalized_pair(
    first: LinkEndpoint, second: LinkEndpoint
) -> tuple[LinkEndpoint, LinkEndpoint] | None:
    if first.source_id == second.source_id:
        return None
    return (first, second) if first.source_id < second.source_id else (second, first)


def _resolve_port(conn: sqlite3.Connection, source_id: int, reference: object) -> str:
    if not isinstance(reference, str) or not reference.strip():
        return ""
    value = reference.strip()
    exact = conn.execute(
        "SELECT port_key FROM switch_ports WHERE source_id = ? AND port_key = ?",
        (source_id, value),
    ).fetchone()
    if exact is not None:
        return str(exact[0])
    name_rows = conn.execute(
        "SELECT port_key FROM switch_ports WHERE source_id = ? AND lower(name) = lower(?)",
        (source_id, value),
    ).fetchall()
    if len(name_rows) == 1:
        return str(name_rows[0][0])
    alias_rows = conn.execute(
        "SELECT port_key FROM switch_ports WHERE source_id = ? AND lower(alias) = lower(?)",
        (source_id, value),
    ).fetchall()
    return str(alias_rows[0][0]) if len(alias_rows) == 1 else ""


def _identity_by_intent(
    identities: tuple[SourceIdentity, ...]
) -> dict[tuple[str, str], SourceIdentity]:
    grouped: dict[tuple[str, str], list[SourceIdentity]] = defaultdict(list)
    for identity in identities:
        if identity.intent_context_id and identity.intent_stable_id:
            grouped[(identity.intent_context_id, identity.intent_stable_id)].append(identity)
    return {key: values[0] for key, values in grouped.items() if len(values) == 1}


def _identity_by_management_mac(
    identities: tuple[SourceIdentity, ...]
) -> dict[str, SourceIdentity]:
    grouped: dict[str, list[SourceIdentity]] = defaultdict(list)
    for identity in identities:
        for mac in identity.management_macs:
            if (normalized := normalize_mac(mac)) is not None:
                grouped[normalized].append(identity)
    return {key: values[0] for key, values in grouped.items() if len(values) == 1}


def intent_link_evidence(
    conn: sqlite3.Connection, identities: tuple[SourceIdentity, ...]
) -> tuple[LinkEvidence, ...]:
    by_intent = _identity_by_intent(identities)
    evidence: list[LinkEvidence] = []
    rows = conn.execute(
        """
        SELECT heads.context_id, links.stable_id, links.endpoint_a_json, links.endpoint_b_json
        FROM context_heads AS heads
        JOIN intent_links AS links
          ON links.context_revision_id = heads.context_revision_id
         AND links.lifecycle = 'active'
         AND links.relation = 'CONNECTED_TO'
        ORDER BY heads.context_id, links.stable_id
        """
    ).fetchall()
    for row in rows:
        try:
            first = json.loads(str(row["endpoint_a_json"]))
            second = json.loads(str(row["endpoint_b_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(first, dict) or not isinstance(second, dict):
            continue
        context_id = str(row["context_id"])
        first_identity = by_intent.get((context_id, str(first.get("device") or "")))
        second_identity = by_intent.get((context_id, str(second.get("device") or "")))
        if first_identity is None or second_identity is None:
            continue
        pair = _normalized_pair(
            LinkEndpoint(first_identity.source_id, _resolve_port(conn, first_identity.source_id, first.get("interface"))),
            LinkEndpoint(second_identity.source_id, _resolve_port(conn, second_identity.source_id, second.get("interface"))),
        )
        if pair is None:
            continue
        confidence = 90 if pair[0].port_key and pair[1].port_key else 65
        evidence.append(LinkEvidence(pair[0], pair[1], "intent", confidence, "", str(row["stable_id"]), {}))
    return tuple(evidence)


def fdb_management_mac_evidence(
    conn: sqlite3.Connection, identities: tuple[SourceIdentity, ...]
) -> tuple[LinkEvidence, ...]:
    by_source = {identity.source_id: identity for identity in identities}
    by_mac = _identity_by_management_mac(identities)
    evidence: list[LinkEvidence] = []
    for row in conn.execute(
        "SELECT source_id, mac, port_key, last_seen_at FROM current_switch_fdb ORDER BY source_id, mac"
    ):
        remote = by_mac.get(normalize_mac(row["mac"]) or "")
        local = by_source.get(int(row["source_id"]))
        if local is None or remote is None:
            continue
        pair = _normalized_pair(
            LinkEndpoint(local.source_id, _resolve_port(conn, local.source_id, row["port_key"])),
            LinkEndpoint(remote.source_id, ""),
        )
        if pair is not None:
            evidence.append(LinkEvidence(pair[0], pair[1], "fdb_management_mac", 70, str(row["last_seen_at"]), "", {"mac": normalize_mac(row["mac"])}))
    return tuple(evidence)


def lldp_link_evidence(
    conn: sqlite3.Connection, identities: tuple[SourceIdentity, ...]
) -> tuple[LinkEvidence, ...]:
    by_source = {identity.source_id: identity for identity in identities}
    by_mac = _identity_by_management_mac(identities)
    evidence: list[LinkEvidence] = []
    for row in conn.execute(
        "SELECT source_id, local_port_key, chassis_id, port_id, observed_at FROM current_switch_lldp_neighbors ORDER BY source_id, local_port_key"
    ):
        remote = by_mac.get(normalize_mac(row["chassis_id"]) or "")
        local = by_source.get(int(row["source_id"]))
        if local is None or remote is None:
            continue
        pair = _normalized_pair(
            LinkEndpoint(local.source_id, _resolve_port(conn, local.source_id, row["local_port_key"])),
            LinkEndpoint(remote.source_id, _resolve_port(conn, remote.source_id, row["port_id"])),
        )
        if pair is not None:
            evidence.append(LinkEvidence(pair[0], pair[1], "lldp_chassis_mac", 90, str(row["observed_at"]), "", {"chassis_id": normalize_mac(row["chassis_id"])}))
    return tuple(evidence)


def collect_link_evidence(
    conn: sqlite3.Connection, identities: tuple[SourceIdentity, ...]
) -> tuple[LinkEvidence, ...]:
    evidence = [
        *intent_link_evidence(conn, identities),
        *fdb_management_mac_evidence(conn, identities),
        *lldp_link_evidence(conn, identities),
    ]
    return tuple(sorted(evidence, key=lambda item: (item.evidence_type, item.endpoint_a.source_id, item.endpoint_b.source_id, item.endpoint_a.port_key, item.endpoint_b.port_key, item.intent_link_stable_id)))
