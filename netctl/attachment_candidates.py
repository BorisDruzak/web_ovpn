from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Mapping

from .normalizer import normalize_mac
from .switch_eligibility import authoritative_fdb_run


@dataclass(frozen=True)
class AttachmentCandidate:
    asset_id: int
    asset_interface_id: int
    switch_source_id: int
    port_key: str
    vlan_key: str
    vlan_id: int | None
    candidate_class: str
    topology_depth: int | None
    score: int
    observed_at: str
    evidence: tuple[dict[str, Any], ...]


def _active_interfaces(conn: sqlite3.Connection) -> dict[str, tuple[tuple[int, int], ...]]:
    by_mac: dict[str, list[tuple[int, int]]] = {}
    for row in conn.execute(
        """
        SELECT id, asset_id, mac
        FROM asset_interfaces
        WHERE lifecycle = 'active' AND mac IS NOT NULL
        ORDER BY asset_id, id
        """
    ):
        if (mac := normalize_mac(row["mac"])) is not None:
            by_mac.setdefault(mac, []).append((int(row["asset_id"]), int(row["id"])))
    return {mac: tuple(values) for mac, values in by_mac.items()}


def _backbone_ports(conn: sqlite3.Connection) -> set[tuple[int, str]]:
    ports: set[tuple[int, str]] = set()
    for row in conn.execute(
        """
        SELECT source_a_id, port_a_key, source_b_id, port_b_key
        FROM current_switch_links
        WHERE state != 'conflicting'
        """
    ):
        if str(row["port_a_key"]):
            ports.add((int(row["source_a_id"]), str(row["port_a_key"])))
        if str(row["port_b_key"]):
            ports.add((int(row["source_b_id"]), str(row["port_b_key"])))
    return ports


def _score(
    candidate_class: str,
    topology_depth: int | None,
    vlan_id: int | None,
    oper_status: str,
    successful_run: bool,
    verified_backbone_port: bool,
) -> int:
    score = {"direct": 60, "uplink": 20, "unknown": 35}[candidate_class]
    if topology_depth is not None:
        score += min(topology_depth * 5, 20)
    if vlan_id is not None:
        score += 5
    if oper_status == "up":
        score += 5
    if successful_run:
        score += 5
    if verified_backbone_port:
        score -= 20
    return max(0, min(100, score))


def attachment_candidates(
    conn: sqlite3.Connection,
    depths: Mapping[int, int],
) -> tuple[AttachmentCandidate, ...]:
    """Derive FDB attachment candidates without changing any stored state."""
    interfaces_by_mac = _active_interfaces(conn)
    backbone_ports = _backbone_ports(conn)
    runtime_asset_by_source = {
        int(row["source_id"]): int(row["runtime_asset_id"])
        for row in conn.execute(
            "SELECT source_id, runtime_asset_id FROM switch_devices WHERE runtime_asset_id IS NOT NULL"
        )
    }
    candidates: list[AttachmentCandidate] = []
    rows = conn.execute(
        """
        SELECT f.source_id, f.vlan_key, f.vlan_id, f.mac, f.port_key, f.status,
               f.last_seen_at, f.collector_run_id, p.oper_status,
               runs.status AS collector_status, runs.outcomes_json
        FROM current_switch_fdb AS f
        LEFT JOIN switch_ports AS p
          ON p.source_id = f.source_id AND p.port_key = f.port_key
        LEFT JOIN switch_collection_runs AS runs
          ON runs.id = f.collector_run_id AND runs.source_id = f.source_id
        ORDER BY f.source_id, f.vlan_key, f.mac, f.port_key
        """
    ).fetchall()
    for row in rows:
        if str(row["status"]).lower() in {"self", "mgmt"}:
            continue
        mac = normalize_mac(row["mac"])
        if mac is None:
            continue
        interfaces = interfaces_by_mac.get(mac, ())
        source_id = int(row["source_id"])
        runtime_asset_id = runtime_asset_by_source.get(source_id)
        port_key = str(row["port_key"])
        verified_backbone_port = (source_id, port_key) in backbone_ports
        candidate_class = (
            "uplink"
            if verified_backbone_port
            else ("direct" if row["oper_status"] is not None else "unknown")
        )
        topology_depth = depths.get(source_id)
        vlan_id = int(row["vlan_id"]) if row["vlan_id"] is not None else None
        successful_run = authoritative_fdb_run(row)
        if not successful_run:
            continue
        for asset_id, interface_id in interfaces:
            if asset_id == runtime_asset_id:
                continue
            evidence = (
                {
                    "collector_run_id": int(row["collector_run_id"]),
                    "collector_status": str(row["collector_status"] or ""),
                    "fdb_mac": mac,
                    "fdb_status": str(row["status"]),
                    "oper_status": str(row["oper_status"] or "unknown"),
                    "verified_backbone_port": verified_backbone_port,
                },
            )
            candidates.append(
                AttachmentCandidate(
                    asset_id=asset_id,
                    asset_interface_id=interface_id,
                    switch_source_id=source_id,
                    port_key=port_key,
                    vlan_key=str(row["vlan_key"]),
                    vlan_id=vlan_id,
                    candidate_class=candidate_class,
                    topology_depth=topology_depth,
                    score=_score(
                        candidate_class,
                        topology_depth,
                        vlan_id,
                        str(row["oper_status"] or "unknown"),
                        successful_run,
                        verified_backbone_port,
                    ),
                    observed_at=str(row["last_seen_at"]),
                    evidence=evidence,
                )
            )
    return tuple(
        sorted(
            candidates,
            key=lambda item: (
                item.asset_interface_id,
                item.switch_source_id,
                item.vlan_key,
                item.port_key,
            ),
        )
    )
