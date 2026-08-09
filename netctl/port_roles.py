from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from .fdb_correlation import (
    DEFAULT_ACCESS_PORT_MAC_THRESHOLD,
    PortMacSummary,
    SubtreeCandidate,
    access_port_mac_thresholds,
    port_mac_summaries,
)
from .source_identity import SourceIdentity
from .topology_models import CurrentSwitchLink


ALLOWED_PORT_ROLES = frozenset(
    {"endpoint", "backbone", "downstream_bridge", "shared_edge", "unknown"}
)
_TOPOLOGY_ROLE_RANK = {"core": 0, "distribution": 1, "access": 2, "edge": 3}


@dataclass(frozen=True)
class PortRole:
    source_id: int
    port_key: str
    role: str
    confidence: int
    mac_count: int
    known_asset_count: int
    unique_vendor_count: int
    child_source_id: int | None
    evidence: tuple[dict[str, Any], ...]
    observed_at: str


def _link_port_keys(link: CurrentSwitchLink) -> tuple[tuple[int, str], ...]:
    keys = {
        (source_id, port_key)
        for source_id, port_key in (
            (link.source_a_id, link.port_a_key),
            (link.source_b_id, link.port_b_key),
            *(
                (endpoint.source_id, endpoint.port_key)
                for evidence in link.evidence
                for endpoint in (evidence.endpoint_a, evidence.endpoint_b)
            ),
        )
        if port_key
    }
    return tuple(sorted(keys))


def _parent_source(
    first_source_id: int,
    second_source_id: int,
    *,
    depths: Mapping[int, int],
    identities: Mapping[int, SourceIdentity],
) -> int | None:
    first_depth = depths.get(first_source_id)
    second_depth = depths.get(second_source_id)
    if first_depth is not None and second_depth is not None and first_depth != second_depth:
        return first_source_id if first_depth < second_depth else second_source_id
    first_rank = _TOPOLOGY_ROLE_RANK.get(
        identities.get(first_source_id).topology_role
        if identities.get(first_source_id) is not None
        else ""
    )
    second_rank = _TOPOLOGY_ROLE_RANK.get(
        identities.get(second_source_id).topology_role
        if identities.get(second_source_id) is not None
        else ""
    )
    if first_rank is not None and second_rank is not None and first_rank != second_rank:
        return first_source_id if first_rank < second_rank else second_source_id
    return None


def _topology_assignments(
    links: Iterable[CurrentSwitchLink],
    *,
    depths: Mapping[int, int],
    identities: Mapping[int, SourceIdentity],
    subtree_candidates: Iterable[SubtreeCandidate],
) -> tuple[
    dict[tuple[int, str], tuple[int, str, int, int | None, dict[str, Any]]],
    set[tuple[int, str]],
]:
    assignments: dict[
        tuple[int, str], tuple[int, str, int, int | None, dict[str, Any]]
    ] = {}
    conflicts: set[tuple[int, str]] = set()

    def assign(
        key: tuple[int, str],
        priority: int,
        role: str,
        confidence: int,
        child_source_id: int | None,
        evidence: dict[str, Any],
    ) -> None:
        current = assignments.get(key)
        candidate = (priority, role, confidence, child_source_id, evidence)
        if current is None or priority > current[0]:
            assignments[key] = candidate
            return
        if priority == current[0] and candidate[1:4] != current[1:4]:
            conflicts.add(key)

    for link in sorted(
        links,
        key=lambda item: (
            item.source_a_id,
            item.port_a_key,
            item.source_b_id,
            item.port_b_key,
            item.link_key,
        ),
    ):
        endpoints = (
            (link.source_a_id, link.port_a_key, link.source_b_id),
            (link.source_b_id, link.port_b_key, link.source_a_id),
        )
        if link.state == "conflicting":
            conflicts.update(_link_port_keys(link))
            continue
        evidence_types = {item.evidence_type for item in link.evidence}
        if link.state == "confirmed":
            for source_id, port_key, peer_id in endpoints:
                if port_key:
                    assign(
                        (source_id, port_key),
                        300,
                        "backbone",
                        100,
                        None,
                        {"type": "confirmed_topology", "peer_source_id": peer_id},
                    )
            continue
        if "intent" in evidence_types:
            for source_id, port_key, peer_id in endpoints:
                if port_key:
                    assign(
                        (source_id, port_key),
                        275,
                        "backbone",
                        95,
                        None,
                        {"type": "intent_topology", "peer_source_id": peer_id},
                    )
            continue
        if "lldp_chassis_mac" in evidence_types:
            parent_id = _parent_source(
                link.source_a_id,
                link.source_b_id,
                depths=depths,
                identities=identities,
            )
            for source_id, port_key, peer_id in endpoints:
                if not port_key:
                    continue
                is_parent = source_id == parent_id
                assign(
                    (source_id, port_key),
                    250,
                    "downstream_bridge" if is_parent else "backbone",
                    95,
                    peer_id if is_parent else None,
                    {
                        "type": "lldp_child_switch" if is_parent else "lldp_backbone",
                        "peer_source_id": peer_id,
                    },
                )
            continue
        management_sides = {
            endpoint.source_id
            for item in link.evidence
            if item.evidence_type == "fdb_management_mac"
            for endpoint in (item.endpoint_a, item.endpoint_b)
            if endpoint.port_key
        }
        if {link.source_a_id, link.source_b_id} <= management_sides:
            for source_id, port_key, peer_id in endpoints:
                if port_key:
                    assign(
                        (source_id, port_key),
                        225,
                        "backbone",
                        95,
                        None,
                        {
                            "type": "bidirectional_management_fdb",
                            "peer_source_id": peer_id,
                        },
                    )
            continue
        if "fdb_subtree" in evidence_types:
            continue
        if link.state == "inferred":
            one_sided_management = "fdb_management_mac" in evidence_types
            for source_id, port_key, peer_id in endpoints:
                if port_key:
                    assign(
                        (source_id, port_key),
                        125 if one_sided_management else 200,
                        "backbone",
                        70 if one_sided_management else 95,
                        None,
                        {
                            "type": (
                                "one_sided_management_fdb"
                                if one_sided_management
                                else "non_conflicting_topology"
                            ),
                            "peer_source_id": peer_id,
                        },
                    )
    for candidate in sorted(
        subtree_candidates,
        key=lambda item: (
            item.parent_source_id,
            item.parent_port_key,
            item.child_source_id,
            item.child_port_key,
        ),
    ):
        assign(
            (candidate.parent_source_id, candidate.parent_port_key),
            150,
            "downstream_bridge",
            candidate.confidence,
            candidate.child_source_id,
            candidate.evidence,
        )
        if candidate.child_port_key:
            assign(
                (candidate.child_source_id, candidate.child_port_key),
                150,
                "backbone",
                candidate.confidence,
                None,
                {
                    "type": "fdb_subtree_backbone",
                    "peer_source_id": candidate.parent_source_id,
                    **{
                        key: value
                        for key, value in candidate.evidence.items()
                        if key != "type"
                    },
                },
            )
    return assignments, conflicts


def _density_role(summary: PortMacSummary, threshold: int) -> PortRole:
    base_evidence = {
        "mac_count": summary.mac_count,
        "known_asset_count": summary.known_asset_count,
        "unique_vendor_count": summary.unique_vendor_count,
        "access_port_mac_threshold": threshold,
        "switch_management_mac_seen": summary.switch_management_mac_seen,
    }
    if summary.mac_count == 1 and not summary.switch_management_mac_seen:
        role, confidence, decision = "endpoint", 80, "single_endpoint"
    elif summary.mac_count >= threshold:
        role, confidence, decision = "shared_edge", 70, "mac_density"
    elif summary.mac_count >= 4:
        role, confidence, decision = "shared_edge", 65, "moderate_mac_density"
    elif summary.mac_count >= 2:
        role, confidence, decision = "shared_edge", 55, "small_multi_mac"
    elif summary.switch_management_mac_seen:
        role, confidence, decision = "unknown", 20, "switch_management_mac_seen"
    else:
        role, confidence, decision = "unknown", 0, "no_learned_macs"
    return PortRole(
        summary.source_id,
        summary.port_key,
        role,
        confidence,
        summary.mac_count,
        summary.known_asset_count,
        summary.unique_vendor_count,
        None,
        ({"type": decision, **base_evidence},),
        summary.observed_at,
    )


def infer_port_roles(
    conn: sqlite3.Connection,
    *,
    links: Iterable[CurrentSwitchLink],
    identities: Iterable[SourceIdentity],
    depths: Mapping[int, int],
    observed_at: str,
    subtree_candidates: Iterable[SubtreeCandidate] = (),
) -> tuple[PortRole, ...]:
    """Infer one deterministic current role for every observed or linked switch port."""
    identities = tuple(identities)
    identity_by_source = {item.source_id: item for item in identities}
    summaries = {
        (item.source_id, item.port_key): item
        for item in port_mac_summaries(conn, identities)
    }
    links = tuple(links)
    for link in links:
        for source_id, port_key in _link_port_keys(link):
            if (source_id, port_key) not in summaries:
                summaries[(source_id, port_key)] = PortMacSummary(
                    source_id, port_key, 0, 0, 0, False, observed_at
                )
    thresholds = access_port_mac_thresholds(conn)
    assignments, conflicts = _topology_assignments(
        links,
        depths=depths,
        identities=identity_by_source,
        subtree_candidates=subtree_candidates,
    )
    roles: list[PortRole] = []
    for key, summary in sorted(summaries.items()):
        role = _density_role(
            summary, thresholds.get(summary.source_id, DEFAULT_ACCESS_PORT_MAC_THRESHOLD)
        )
        if key in conflicts:
            roles.append(
                replace(
                    role,
                    role="unknown",
                    confidence=20,
                    child_source_id=None,
                    evidence=(
                        {"type": "topology_conflict", "density_role": role.role},
                        *role.evidence,
                    ),
                    observed_at=observed_at,
                )
            )
            continue
        assignment = assignments.get(key)
        if assignment is not None:
            _, assigned_role, confidence, child_source_id, evidence = assignment
            roles.append(
                replace(
                    role,
                    role=assigned_role,
                    confidence=confidence,
                    child_source_id=child_source_id,
                    evidence=(evidence, *role.evidence),
                    observed_at=observed_at,
                )
            )
        else:
            roles.append(replace(role, observed_at=observed_at))
    return tuple(roles)


def replace_current_port_roles(
    conn: sqlite3.Connection,
    roles: Iterable[PortRole],
    *,
    correlation_run_id: int,
) -> int:
    roles = tuple(roles)
    conn.execute("DELETE FROM current_switch_port_roles")
    conn.executemany(
        """
        INSERT INTO current_switch_port_roles (
            source_id, port_key, role, confidence, mac_count,
            known_asset_count, unique_vendor_count, child_source_id,
            evidence_json, observed_at, correlation_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                role.source_id,
                role.port_key,
                role.role,
                role.confidence,
                role.mac_count,
                role.known_asset_count,
                role.unique_vendor_count,
                role.child_source_id,
                json.dumps(
                    list(role.evidence),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                role.observed_at,
                correlation_run_id,
            )
            for role in roles
        ],
    )
    return len(roles)
