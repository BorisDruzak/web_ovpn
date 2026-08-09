from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable

from .normalizer import normalize_mac
from .source_identity import SourceIdentity
from .topology_models import CurrentSwitchLink, LinkEndpoint, LinkEvidence


DEFAULT_ACCESS_PORT_MAC_THRESHOLD = 10
MIN_SUBTREE_LEAF_MACS = 4
MIN_SUBTREE_COVERAGE = 0.80


@dataclass(frozen=True)
class PortMacSummary:
    source_id: int
    port_key: str
    mac_count: int
    known_asset_count: int
    unique_vendor_count: int
    switch_management_mac_seen: bool
    observed_at: str


@dataclass(frozen=True)
class SubtreeCandidate:
    parent_source_id: int
    parent_port_key: str
    child_source_id: int
    child_source: str
    child_port_key: str
    child_leaf_mac_count: int
    matched_mac_count: int
    coverage: float
    child_management_mac_seen: bool
    confidence: int
    observed_at: str

    @property
    def evidence(self) -> dict[str, Any]:
        return {
            "type": "fdb_subtree",
            "child_source": self.child_source,
            "child_leaf_mac_count": self.child_leaf_mac_count,
            "matched_mac_count": self.matched_mac_count,
            "coverage": self.coverage,
            "child_management_mac_seen": self.child_management_mac_seen,
        }


def _valid_leaf_mac(value: object) -> str | None:
    mac = normalize_mac(value)
    if mac is None:
        return None
    octets = bytes.fromhex(mac.replace(":", ""))
    if not any(octets) or octets[0] & 1:
        return None
    return mac


def _known_backbone_ports(
    links: Iterable[CurrentSwitchLink],
) -> frozenset[tuple[int, str]]:
    ports: set[tuple[int, str]] = set()
    for link in links:
        if link.state in {"ambiguous", "conflicting"}:
            continue
        for source_id, port_key in (
            (link.source_a_id, link.port_a_key),
            (link.source_b_id, link.port_b_key),
            *(
                (endpoint.source_id, endpoint.port_key)
                for evidence in link.evidence
                for endpoint in (evidence.endpoint_a, evidence.endpoint_b)
            ),
        ):
            if port_key:
                ports.add((source_id, port_key))
    return frozenset(ports)


def _learned_port_macs(
    conn: sqlite3.Connection,
) -> tuple[
    dict[int, dict[str, frozenset[str]]],
    dict[tuple[int, str], str],
]:
    grouped: dict[int, dict[str, set[str]]] = {}
    observed_at: dict[tuple[int, str], str] = {}
    for row in conn.execute(
        """
        SELECT source_id, port_key, mac, status, last_seen_at
        FROM current_switch_fdb
        ORDER BY source_id, port_key, mac
        """
    ):
        if str(row["status"] or "").lower() != "learned":
            continue
        mac = _valid_leaf_mac(row["mac"])
        if mac is None:
            continue
        source_id, port_key = int(row["source_id"]), str(row["port_key"])
        grouped.setdefault(source_id, {}).setdefault(port_key, set()).add(mac)
        key = (source_id, port_key)
        observed_at[key] = max(
            observed_at.get(key, ""), str(row["last_seen_at"] or "")
        )
    return (
        {
            source_id: {
                port_key: frozenset(macs)
                for port_key, macs in sorted(ports.items())
            }
            for source_id, ports in sorted(grouped.items())
        },
        observed_at,
    )


def fdb_subtree_candidates(
    conn: sqlite3.Connection,
    identities: Iterable[SourceIdentity],
    *,
    known_links: Iterable[CurrentSwitchLink] = (),
) -> tuple[SubtreeCandidate, ...]:
    """Correlate child leaf sets with parent ports without guessing remote ports."""
    identities = tuple(sorted(identities, key=lambda item: item.source_id))
    by_source = {item.source_id: item for item in identities}
    management_macs = {
        mac
        for identity in identities
        for value in identity.management_macs
        if (mac := _valid_leaf_mac(value)) is not None
    }
    port_macs, port_observed_at = _learned_port_macs(conn)
    backbone_ports = _known_backbone_ports(known_links)
    candidates_by_child: dict[int, list[SubtreeCandidate]] = {}

    for child in identities:
        child_ports = port_macs.get(child.source_id, {})
        child_leaf_macs = frozenset(
            mac
            for port_key, macs in child_ports.items()
            if (child.source_id, port_key) not in backbone_ports
            for mac in macs
            if mac not in management_macs
        )
        if len(child_leaf_macs) < MIN_SUBTREE_LEAF_MACS:
            continue
        child_management_macs = {
            mac
            for value in child.management_macs
            if (mac := _valid_leaf_mac(value)) is not None
        }
        for parent_source_id, parent_ports in sorted(port_macs.items()):
            if parent_source_id == child.source_id or parent_source_id not in by_source:
                continue
            parent_management_macs = {
                mac
                for value in by_source[parent_source_id].management_macs
                if (mac := _valid_leaf_mac(value)) is not None
            }
            reverse_ports = sorted(
                port_key
                for port_key, macs in child_ports.items()
                if macs & parent_management_macs
            )
            child_port_key = reverse_ports[0] if len(reverse_ports) == 1 else ""
            for parent_port_key, parent_port_macs in sorted(parent_ports.items()):
                intersection = child_leaf_macs & parent_port_macs
                coverage = len(intersection) / len(child_leaf_macs)
                if coverage < MIN_SUBTREE_COVERAGE:
                    continue
                candidate = SubtreeCandidate(
                    parent_source_id=parent_source_id,
                    parent_port_key=parent_port_key,
                    child_source_id=child.source_id,
                    child_source=child.source_name,
                    child_port_key=child_port_key,
                    child_leaf_mac_count=len(child_leaf_macs),
                    matched_mac_count=len(intersection),
                    coverage=coverage,
                    child_management_mac_seen=bool(
                        parent_port_macs & child_management_macs
                    ),
                    confidence=round(coverage * 100),
                    observed_at=max(
                        port_observed_at.get((parent_source_id, parent_port_key), ""),
                        *(
                            port_observed_at.get((child.source_id, port_key), "")
                            for port_key in child_ports
                        ),
                    ),
                )
                candidates_by_child.setdefault(child.source_id, []).append(candidate)

    selected: list[SubtreeCandidate] = []
    for child_source_id in sorted(candidates_by_child):
        candidates = candidates_by_child[child_source_id]
        if any(item.child_management_mac_seen for item in candidates):
            candidates = [item for item in candidates if item.child_management_mac_seen]
        selected.extend(candidates)
    return tuple(
        sorted(
            selected,
            key=lambda item: (
                item.child_source_id,
                -int(item.child_management_mac_seen),
                -item.coverage,
                item.parent_source_id,
                item.parent_port_key,
            ),
        )
    )


def fdb_subtree_link_evidence(
    candidates: Iterable[SubtreeCandidate],
    *,
    stronger_links: Iterable[CurrentSwitchLink] = (),
) -> tuple[LinkEvidence, ...]:
    """Return complete link evidence only when the reverse child port is proven."""
    occupied_ports: dict[tuple[int, str], set[int]] = {}
    for link in stronger_links:
        if link.state in {"ambiguous", "conflicting"}:
            continue
        evidence_types = {item.evidence_type for item in link.evidence}
        management_sides = {
            endpoint.source_id
            for item in link.evidence
            if item.evidence_type == "fdb_management_mac"
            for endpoint in (item.endpoint_a, item.endpoint_b)
            if endpoint.port_key
        }
        if not (
            evidence_types & {"intent", "lldp_chassis_mac"}
            or {link.source_a_id, link.source_b_id} <= management_sides
        ):
            continue
        for source_id, port_key, peer_source_id in (
            (link.source_a_id, link.port_a_key, link.source_b_id),
            (link.source_b_id, link.port_b_key, link.source_a_id),
        ):
            if port_key:
                occupied_ports.setdefault((source_id, port_key), set()).add(
                    peer_source_id
                )

    def contradicts_stronger_link(candidate: SubtreeCandidate) -> bool:
        return any(
            peers and peer_source_id not in peers
            for key, peer_source_id in (
                (
                    (candidate.parent_source_id, candidate.parent_port_key),
                    candidate.child_source_id,
                ),
                (
                    (candidate.child_source_id, candidate.child_port_key),
                    candidate.parent_source_id,
                ),
            )
            if (peers := occupied_ports.get(key)) is not None
        )

    eligible_by_child: dict[int, list[SubtreeCandidate]] = {}
    for candidate in candidates:
        if candidate.child_port_key and not contradicts_stronger_link(candidate):
            eligible_by_child.setdefault(candidate.child_source_id, []).append(candidate)

    winners: list[SubtreeCandidate] = []
    for child_source_id in sorted(eligible_by_child):
        eligible = eligible_by_child[child_source_id]
        best_rank = max(
            (int(item.child_management_mac_seen), item.coverage)
            for item in eligible
        )
        best = [
            item
            for item in eligible
            if (int(item.child_management_mac_seen), item.coverage) == best_rank
        ]
        if len(best) == 1:
            winners.append(best[0])

    evidence = [
        LinkEvidence(
            LinkEndpoint(candidate.parent_source_id, candidate.parent_port_key),
            LinkEndpoint(candidate.child_source_id, candidate.child_port_key),
            "fdb_subtree",
            candidate.confidence,
            candidate.observed_at,
            "",
            candidate.evidence,
        )
        for candidate in winners
    ]
    return tuple(
        sorted(
            evidence,
            key=lambda item: (
                item.endpoint_a.source_id,
                item.endpoint_a.port_key,
                item.endpoint_b.source_id,
                item.endpoint_b.port_key,
            ),
        )
    )


def _active_assets_by_mac(conn: sqlite3.Connection) -> dict[str, frozenset[int]]:
    grouped: dict[str, set[int]] = {}
    for row in conn.execute(
        """
        SELECT asset_id, mac
        FROM asset_interfaces
        WHERE lifecycle = 'active' AND mac IS NOT NULL
        ORDER BY asset_id, id
        """
    ):
        mac = normalize_mac(row["mac"])
        if mac is not None:
            grouped.setdefault(mac, set()).add(int(row["asset_id"]))
    return {mac: frozenset(asset_ids) for mac, asset_ids in grouped.items()}


def port_mac_summaries(
    conn: sqlite3.Connection,
    identities: Iterable[SourceIdentity],
) -> tuple[PortMacSummary, ...]:
    """Aggregate current valid FDB rows without inferring a downstream device."""
    assets_by_mac = _active_assets_by_mac(conn)
    management_macs = {
        normalized
        for identity in identities
        for value in identity.management_macs
        if (normalized := normalize_mac(value)) is not None
    }
    ports: dict[tuple[int, str], dict[str, object]] = {}
    for row in conn.execute(
        """
        SELECT source_id, port_key, last_seen_at
        FROM switch_ports
        ORDER BY source_id, port_key
        """
    ):
        ports[(int(row["source_id"]), str(row["port_key"]))] = {
            "macs": set(),
            "observed_at": str(row["last_seen_at"] or ""),
        }
    for row in conn.execute(
        """
        SELECT source_id, port_key, mac, status, last_seen_at
        FROM current_switch_fdb
        ORDER BY source_id, port_key, mac
        """
    ):
        if str(row["status"] or "").lower() != "learned":
            continue
        mac = normalize_mac(row["mac"])
        if mac is None:
            continue
        key = (int(row["source_id"]), str(row["port_key"]))
        entry = ports.setdefault(key, {"macs": set(), "observed_at": ""})
        macs = entry["macs"]
        if isinstance(macs, set):
            macs.add(mac)
        entry["observed_at"] = max(
            str(entry["observed_at"] or ""), str(row["last_seen_at"] or "")
        )

    summaries: list[PortMacSummary] = []
    for (source_id, port_key), entry in sorted(ports.items()):
        macs = frozenset(entry["macs"] if isinstance(entry["macs"], set) else ())
        known_asset_ids = {
            asset_id for mac in macs for asset_id in assets_by_mac.get(mac, ())
        }
        summaries.append(
            PortMacSummary(
                source_id=source_id,
                port_key=port_key,
                mac_count=len(macs),
                known_asset_count=len(known_asset_ids),
                unique_vendor_count=len({mac[:8] for mac in macs}),
                switch_management_mac_seen=bool(macs & management_macs),
                observed_at=str(entry["observed_at"] or ""),
            )
        )
    return tuple(summaries)


def access_port_mac_thresholds(conn: sqlite3.Connection) -> dict[int, int]:
    """Read the existing per-source SNMP threshold, defaulting to its canonical 10."""
    thresholds: dict[int, int] = {}
    for row in conn.execute(
        "SELECT id, driver_options_json FROM network_sources ORDER BY id"
    ):
        threshold = DEFAULT_ACCESS_PORT_MAC_THRESHOLD
        try:
            options = json.loads(str(row["driver_options_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            options = {}
        if isinstance(options, dict):
            candidate = options.get("access_port_mac_threshold")
            if type(candidate) is int and candidate >= 1:
                threshold = candidate
        thresholds[int(row["id"])] = threshold
    return thresholds
