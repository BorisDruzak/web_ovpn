from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from .normalizer import normalize_mac
from .source_identity import SourceIdentity


DEFAULT_ACCESS_PORT_MAC_THRESHOLD = 10
_IGNORED_FDB_STATUSES = frozenset({"invalid", "self", "mgmt"})


@dataclass(frozen=True)
class PortMacSummary:
    source_id: int
    port_key: str
    mac_count: int
    known_asset_count: int
    unique_vendor_count: int
    switch_management_mac_seen: bool
    observed_at: str


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
        if str(row["status"] or "").lower() in _IGNORED_FDB_STATUSES:
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
