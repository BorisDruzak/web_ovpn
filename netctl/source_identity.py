from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import TOPOLOGY_ROLES, normalize_generic_driver_options, normalize_snmp_driver_options
from .normalizer import normalize_mac
from .switch_eligibility import has_authoritative_fdb


_AUTHORITATIVE_FDB_MAX_AGE = timedelta(hours=24)


def _run_is_stale(row: sqlite3.Row | None) -> bool:
    if row is None:
        return False
    raw = str(row["finished_at"] or row["started_at"] or "")
    try:
        observed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return True
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    return observed < datetime.now(UTC) - _AUTHORITATIVE_FDB_MAX_AGE


@dataclass(frozen=True)
class SourceIdentity:
    source_id: int
    source_name: str
    driver: str
    topology_role: str
    runtime_asset_id: int | None
    runtime_asset_key: str
    intent_context_id: str
    intent_stable_id: str
    management_macs: tuple[str, ...]


def _driver_options(driver: str, raw_options: object) -> dict[str, Any]:
    try:
        decoded = json.loads(str(raw_options or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(decoded, dict):
        return {}
    try:
        if driver == "snmp_switch":
            return normalize_snmp_driver_options(decoded)
        return normalize_generic_driver_options(decoded)
    except ValueError:
        return {}


def _configured_string(options: dict[str, Any], key: str) -> str:
    value = options.get(key, "")
    return value if isinstance(value, str) else ""


def _asset_row(conn: sqlite3.Connection, asset_id: int | None) -> sqlite3.Row | None:
    if asset_id is None:
        return None
    return conn.execute(
        "SELECT id, asset_key FROM assets WHERE id = ?", (asset_id,)
    ).fetchone()


def _asset_for_key(conn: sqlite3.Connection, asset_key: str) -> sqlite3.Row | None:
    if not asset_key:
        return None
    return conn.execute(
        "SELECT id, asset_key FROM assets WHERE asset_key = ?", (asset_key,)
    ).fetchone()


def _active_intent_binding(
    conn: sqlite3.Connection, context_id: str, stable_id: str
) -> tuple[str, str]:
    if not context_id or not stable_id:
        return "", ""
    row = conn.execute(
        """
        SELECT 1
        FROM context_heads AS heads
        JOIN intent_assets AS assets
          ON assets.context_revision_id = heads.context_revision_id
         AND assets.stable_id = ?
         AND assets.lifecycle = 'active'
        WHERE heads.context_id = ?
        """,
        (stable_id, context_id),
    ).fetchone()
    if row is None:
        return "", ""
    return context_id, stable_id


def _management_macs(conn: sqlite3.Connection, asset_id: int | None) -> tuple[str, ...]:
    if asset_id is None:
        return ()
    macs = {
        normalized
        for row in conn.execute(
            """
            SELECT mac
            FROM asset_interfaces
            WHERE asset_id = ? AND lifecycle = 'active' AND mac IS NOT NULL
            """,
            (asset_id,),
        )
        if (normalized := normalize_mac(row[0])) is not None
    }
    return tuple(sorted(macs))


def list_source_identities(conn: sqlite3.Connection) -> tuple[SourceIdentity, ...]:
    """Return source identity evidence without creating or confirming bindings."""
    rows = conn.execute(
        """
        SELECT sources.id, sources.name, sources.driver, sources.driver_options_json,
               devices.runtime_asset_id AS switch_runtime_asset_id
        FROM network_sources AS sources
        LEFT JOIN switch_devices AS devices ON devices.source_id = sources.id
        ORDER BY sources.name, sources.id
        """
    ).fetchall()
    identities: list[SourceIdentity] = []
    for row in rows:
        source_id = int(row["id"])
        source_name = str(row["name"])
        driver = str(row["driver"])
        options = _driver_options(driver, row["driver_options_json"])
        runtime_asset_key = _configured_string(options, "runtime_asset_key")
        switch_asset_id = row["switch_runtime_asset_id"] if driver == "snmp_switch" else None
        asset = _asset_row(conn, switch_asset_id)
        if asset is None:
            asset = _asset_for_key(conn, runtime_asset_key)
        runtime_asset_id = int(asset["id"]) if asset is not None else None
        if asset is not None:
            runtime_asset_key = str(asset["asset_key"])
        context_id, stable_id = _active_intent_binding(
            conn,
            _configured_string(options, "intent_context_id"),
            _configured_string(options, "intent_stable_id"),
        )
        topology_role = _configured_string(options, "topology_role")
        if topology_role not in TOPOLOGY_ROLES:
            topology_role = "unknown"
        identities.append(
            SourceIdentity(
                source_id=source_id,
                source_name=source_name,
                driver=driver,
                topology_role=topology_role,
                runtime_asset_id=runtime_asset_id,
                runtime_asset_key=runtime_asset_key,
                intent_context_id=context_id,
                intent_stable_id=stable_id,
                management_macs=_management_macs(conn, runtime_asset_id),
            )
        )
    return tuple(identities)


def source_readiness(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Summarize why a configured source can or cannot contribute topology evidence."""
    records: list[dict[str, Any]] = []
    identities = list_source_identities(conn)
    management_mac_owners: dict[str, int] = {}
    for identity in identities:
        for mac in identity.management_macs:
            management_mac_owners[mac] = management_mac_owners.get(mac, 0) + 1
    for identity in identities:
        source = conn.execute(
            "SELECT site FROM network_sources WHERE id = ?", (identity.source_id,)
        ).fetchone()
        run = conn.execute(
            """SELECT id, started_at, finished_at, status, outcomes_json FROM switch_collection_runs
               WHERE source_id = ? ORDER BY id DESC LIMIT 1""",
            (identity.source_id,),
        ).fetchone()
        latest_fdb_run_id = (
            int(run["id"]) if run is not None and has_authoritative_fdb(run["status"], run["outcomes_json"]) else None
        )
        port_count = int(conn.execute(
            "SELECT count(*) FROM switch_ports WHERE source_id = ?", (identity.source_id,)
        ).fetchone()[0])
        reasons: list[str] = []
        if identity.topology_role == "unknown":
            reasons.append("missing_topology_role")
        if identity.runtime_asset_id is None:
            reasons.append("missing_runtime_asset_binding")
        if not identity.intent_context_id or not identity.intent_stable_id:
            reasons.append("missing_intent_binding")
        if not identity.management_macs:
            reasons.append("missing_management_mac")
        if any(management_mac_owners.get(mac, 0) > 1 for mac in identity.management_macs):
            reasons.append("ambiguous_management_mac")
        if identity.driver == "snmp_switch" and latest_fdb_run_id is None:
            reasons.append("no_authoritative_fdb")
        elif identity.driver == "snmp_switch" and _run_is_stale(run):
            reasons.append("stale_authoritative_fdb")
        if identity.driver == "snmp_switch" and port_count == 0:
            reasons.append("no_port_inventory")
        records.append({
            "source": identity.source_name, "driver": identity.driver,
            "site": str(source["site"] or "") if source is not None else "",
            "topology_role": identity.topology_role,
            "runtime_asset_status": "ready" if identity.runtime_asset_id is not None else "missing",
            "intent_binding_status": "ready" if identity.intent_context_id and identity.intent_stable_id else "missing",
            "management_mac_count": len(identity.management_macs),
            "latest_authoritative_fdb_run_id": latest_fdb_run_id,
            "known_switch_port_count": port_count,
            "eligible_for_topology": not reasons,
            "blocking_reasons": reasons or ["ready"],
        })
    return records
