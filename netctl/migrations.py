from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Callable
from typing import Any

from .normalizer import normalize_mac
from .util import utc_now


def _migration_1(conn: sqlite3.Connection) -> None:
    for statement in """
        CREATE TABLE context_import_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_id TEXT NOT NULL DEFAULT '',
            context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
            base_context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
            input_sha256 TEXT NOT NULL DEFAULT '',
            git_sha TEXT NOT NULL,
            source_path TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL CHECK (status IN (
                'running',
                'success_imported',
                'success_noop_same_content',
                'success_activated_existing_content',
                'validation_error',
                'db_error'
            )),
            errors_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX context_import_runs_context_started_idx
            ON context_import_runs(context_id, started_at DESC, id DESC);

        CREATE TABLE context_heads (
            context_id TEXT PRIMARY KEY,
            context_revision_id INTEGER NOT NULL
                REFERENCES context_revisions(id) ON DELETE RESTRICT,
            activated_by_import_run_id INTEGER NOT NULL
                REFERENCES context_import_runs(id) ON DELETE RESTRICT,
            activated_at TEXT NOT NULL
        );

        CREATE TABLE intent_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_sites_revision_lifecycle_idx ON intent_sites(context_revision_id, lifecycle);
        CREATE INDEX intent_sites_revision_hash_idx ON intent_sites(context_revision_id, canonical_hash);

        CREATE TABLE intent_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_locations_revision_lifecycle_idx ON intent_locations(context_revision_id, lifecycle);
        CREATE INDEX intent_locations_revision_hash_idx ON intent_locations(context_revision_id, canonical_hash);

        CREATE TABLE intent_segments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_segments_revision_lifecycle_idx ON intent_segments(context_revision_id, lifecycle);
        CREATE INDEX intent_segments_revision_hash_idx ON intent_segments(context_revision_id, canonical_hash);

        CREATE TABLE intent_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_assets_revision_lifecycle_idx ON intent_assets(context_revision_id, lifecycle);
        CREATE INDEX intent_assets_revision_hash_idx ON intent_assets(context_revision_id, canonical_hash);

        CREATE TABLE intent_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_services_revision_lifecycle_idx ON intent_services(context_revision_id, lifecycle);
        CREATE INDEX intent_services_revision_hash_idx ON intent_services(context_revision_id, canonical_hash);

        CREATE TABLE intent_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            stable_id TEXT NOT NULL,
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'retired')),
            canonical_json TEXT NOT NULL,
            canonical_hash TEXT NOT NULL,
            origin_context_revision_id INTEGER NOT NULL REFERENCES context_revisions(id) ON DELETE RESTRICT,
            relation TEXT NOT NULL CHECK (relation IN (
                'CONNECTED_TO', 'MEMBER_OF', 'ROUTED_VIA', 'RUNS_ON', 'USED_BY',
                'LOCATED_AT', 'CAN_ACCESS', 'AFFECTED_BY', 'RESOLVED_BY'
            )),
            endpoint_a_json TEXT NOT NULL,
            endpoint_b_json TEXT NOT NULL,
            UNIQUE(context_revision_id, stable_id)
        );
        CREATE INDEX intent_links_revision_lifecycle_idx ON intent_links(context_revision_id, lifecycle);
        CREATE INDEX intent_links_revision_hash_idx ON intent_links(context_revision_id, canonical_hash);
        """.split(";"):
        if statement.strip():
            conn.execute(statement)


def _migration_2(conn: sqlite3.Connection) -> None:
    for statement in """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_key TEXT NOT NULL UNIQUE,
            identity_method TEXT NOT NULL CHECK (identity_method IN ('mac_seed', 'provisional_legacy', 'manual')),
            kind TEXT NOT NULL DEFAULT 'unknown',
            status TEXT NOT NULL DEFAULT 'unknown',
            site TEXT NOT NULL DEFAULT '',
            location TEXT NOT NULL DEFAULT '',
            display_name TEXT NOT NULL DEFAULT '',
            identity_confidence INTEGER NOT NULL CHECK (identity_confidence BETWEEN 0 AND 100),
            provisional INTEGER NOT NULL CHECK (provisional IN (0, 1)),
            legacy_comment TEXT NOT NULL DEFAULT '',
            legacy_evidence_json TEXT NOT NULL DEFAULT '[]',
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE asset_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
            interface_key TEXT NOT NULL,
            mac TEXT,
            interface_type TEXT NOT NULL DEFAULT '',
            interface_name TEXT NOT NULL DEFAULT '',
            lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'retired')),
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(asset_id, interface_key)
        );

        CREATE TABLE ip_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
            asset_interface_id INTEGER REFERENCES asset_interfaces(id) ON DELETE RESTRICT,
            site TEXT NOT NULL DEFAULT '',
            source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
            source_key TEXT NOT NULL,
            ip TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
            observation_source TEXT NOT NULL,
            UNIQUE(asset_id, ip, source_key, observation_source)
        );

        CREATE TABLE hostname_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
            hostname TEXT NOT NULL,
            source_id INTEGER REFERENCES network_sources(id) ON DELETE RESTRICT,
            source_key TEXT NOT NULL,
            source_type TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
            UNIQUE(asset_id, hostname, source_key, source_type)
        );

        CREATE TABLE asset_intent_bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
            context_id TEXT NOT NULL,
            intent_stable_id TEXT NOT NULL,
            last_verified_context_revision_id INTEGER REFERENCES context_revisions(id) ON DELETE RESTRICT,
            binding_source TEXT NOT NULL,
            confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
            status TEXT NOT NULL CHECK (status IN ('candidate', 'confirmed', 'rejected', 'retired')),
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(asset_id, context_id, intent_stable_id, binding_source)
        );

        CREATE TABLE asset_tag_bindings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
            tag TEXT NOT NULL,
            binding_source TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(asset_id, tag, binding_source)
        );

        CREATE TABLE legacy_host_asset_mappings (
            legacy_network_host_id INTEGER PRIMARY KEY REFERENCES network_hosts(id) ON DELETE RESTRICT,
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
            mapping_kind TEXT NOT NULL CHECK (mapping_kind IN ('mac', 'provisional')),
            migrated_at TEXT NOT NULL
        );

        CREATE TABLE runtime_asset_migration_reports (
            migration_version INTEGER PRIMARY KEY,
            completed_at TEXT NOT NULL,
            legacy_host_count INTEGER NOT NULL,
            mapped_legacy_host_count INTEGER NOT NULL,
            mac_asset_count INTEGER NOT NULL,
            provisional_asset_count INTEGER NOT NULL,
            interface_count INTEGER NOT NULL,
            ip_observation_count INTEGER NOT NULL,
            hostname_observation_count INTEGER NOT NULL,
            tag_binding_count INTEGER NOT NULL,
            unresolved_legacy_host_ids_json TEXT NOT NULL DEFAULT '[]',
            unresolved_observation_ids_json TEXT NOT NULL DEFAULT '[]',
            unresolved_tag_records_json TEXT NOT NULL DEFAULT '[]',
            aggregation_conflicts_json TEXT NOT NULL DEFAULT '[]'
        );

        CREATE INDEX assets_site_last_seen_idx ON assets(site, last_seen_at DESC);
        CREATE INDEX asset_interfaces_mac_idx ON asset_interfaces(mac) WHERE mac IS NOT NULL;
        CREATE INDEX ip_observations_current_ip_idx ON ip_observations(ip, is_current, last_seen_at DESC);
        CREATE INDEX ip_observations_asset_current_idx ON ip_observations(asset_id, is_current, last_seen_at DESC);
        CREATE INDEX hostname_observations_current_hostname_idx ON hostname_observations(hostname, is_current, last_seen_at DESC);
        CREATE INDEX asset_intent_bindings_asset_idx ON asset_intent_bindings(asset_id, status);
        CREATE INDEX asset_tag_bindings_tag_idx ON asset_tag_bindings(tag, asset_id);
        """.split(";"):
        if statement.strip():
            conn.execute(statement)

    migration_time = utc_now()
    host_rows = _dict_rows(
        conn.execute(
            """
            SELECT id, ip, mac, hostname, display_name, category, device_key,
                   device_type, device_evidence_json, status, site, first_seen_at,
                   last_seen_at, last_source, comment
            FROM network_hosts
            ORDER BY id
            """
        )
    )
    source_ids = {
        str(row[0]): int(row[1])
        for row in conn.execute("SELECT name, id FROM network_sources ORDER BY name, id")
    }
    grouped_hosts: dict[str, list[dict[str, Any]]] = {}
    aggregation_conflicts: list[dict[str, Any]] = []

    for host in host_rows:
        column_mac = normalize_mac(host["mac"])
        device_key = str(host["device_key"] or "")
        device_key_mac = normalize_mac(device_key.removeprefix("mac:")) if device_key.startswith("mac:") else None
        resolved_mac = column_mac or device_key_mac
        if column_mac and device_key_mac and column_mac != device_key_mac:
            aggregation_conflicts.append(
                {
                    "device_key_mac": device_key_mac,
                    "legacy_network_host_id": int(host["id"]),
                    "mac_column": column_mac,
                    "type": "mac_disagreement",
                }
            )
        host["_resolved_mac"] = resolved_mac
        asset_key = f"mac:{resolved_mac}" if resolved_mac else f"legacy-host:{host['id']}"
        grouped_hosts.setdefault(asset_key, []).append(host)

    for asset_key in sorted(grouped_hosts):
        hosts = grouped_hosts[asset_key]
        effective_times = [_effective_host_times(host, migration_time) for host in hosts]
        first_seen_at = min(first for first, _last in effective_times)
        last_seen_at = max(last for _first, last in effective_times)
        representative = max(
            hosts,
            key=lambda host: (_effective_host_times(host, migration_time)[1], int(host["id"])),
        )
        resolved_mac = representative["_resolved_mac"]
        provisional = resolved_mac is None
        evidence = _legacy_evidence(hosts)
        representative_values = _legacy_representative_values(representative, asset_key)
        aggregation_conflicts.extend(
            _legacy_aggregation_conflicts(
                asset_key,
                hosts,
                representative,
                representative_values,
            )
        )
        cursor = conn.execute(
            """
            INSERT INTO assets (
                asset_key, identity_method, kind, status, site, location,
                display_name, identity_confidence, provisional, legacy_comment,
                legacy_evidence_json, first_seen_at, last_seen_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset_key,
                "provisional_legacy" if provisional else "mac_seed",
                representative_values["kind"],
                representative_values["status"],
                representative_values["site"],
                representative_values["display_name"],
                20 if provisional else 100,
                1 if provisional else 0,
                representative_values["comment"],
                evidence,
                first_seen_at,
                last_seen_at,
                migration_time,
                migration_time,
            ),
        )
        asset_id = int(cursor.lastrowid)
        interface_key = f"legacy-host:{representative['id']}:unknown" if provisional else asset_key
        interface_cursor = conn.execute(
            """
            INSERT INTO asset_interfaces (
                asset_id, interface_key, mac, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (asset_id, interface_key, resolved_mac, first_seen_at, last_seen_at),
        )
        interface_id = int(interface_cursor.lastrowid)

        for host in sorted(hosts, key=lambda item: int(item["id"])):
            host_first_seen_at, host_last_seen_at = _effective_host_times(host, migration_time)
            source_name = str(host["last_source"] or "").strip()
            source_id = source_ids.get(source_name) if source_name else None
            source_key = f"legacy-network-host:{host['id']}"
            conn.execute(
                """
                INSERT INTO legacy_host_asset_mappings (
                    legacy_network_host_id, asset_id, mapping_kind, migrated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (int(host["id"]), asset_id, "provisional" if provisional else "mac", migration_time),
            )
            conn.execute(
                """
                INSERT INTO ip_observations (
                    asset_id, asset_interface_id, site, source_id, source_key, ip,
                    first_seen_at, last_seen_at, is_current, observation_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'legacy_network_host')
                """,
                (
                    asset_id,
                    interface_id,
                    _first_nonblank(host["site"], ""),
                    source_id,
                    source_key,
                    str(host["ip"]),
                    host_first_seen_at,
                    host_last_seen_at,
                ),
            )
            hostname = str(host["hostname"] or "").strip()
            if hostname:
                conn.execute(
                    """
                    INSERT INTO hostname_observations (
                        asset_id, hostname, source_id, source_key, source_type,
                        first_seen_at, last_seen_at, is_current
                    ) VALUES (?, ?, ?, ?, 'legacy_network_host', ?, ?, 1)
                    """,
                    (
                        asset_id,
                        hostname,
                        source_id,
                        source_key,
                        host_first_seen_at,
                        host_last_seen_at,
                    ),
                )

    host_asset_ids = {
        int(row[0]): int(row[1])
        for row in conn.execute(
            """
            SELECT legacy_network_host_id, asset_id
            FROM legacy_host_asset_mappings
            ORDER BY legacy_network_host_id
            """
        )
    }
    mac_asset_ids: dict[str, set[int]] = {}
    ip_asset_ids: dict[str, set[int]] = {}
    for host in host_rows:
        asset_id = host_asset_ids[int(host["id"])]
        resolved_mac = host["_resolved_mac"]
        if resolved_mac:
            mac_asset_ids.setdefault(str(resolved_mac), set()).add(asset_id)
        ip = str(host["ip"] or "").strip()
        if ip:
            ip_asset_ids.setdefault(ip, set()).add(asset_id)

    unresolved_tags: list[dict[str, Any]] = []
    tag_rows = _dict_rows(
        conn.execute(
            """
            SELECT device_key, tags_json
            FROM network_device_tags
            ORDER BY device_key
            """
        )
    )
    for tag_row in tag_rows:
        device_key = str(tag_row["device_key"] or "")
        raw_tags_json = str(tag_row["tags_json"] or "")
        try:
            parsed_tags = json.loads(raw_tags_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_tags = None
        if not isinstance(parsed_tags, list):
            unresolved_tags.append(
                {
                    "device_key": device_key,
                    "raw_tags_json": raw_tags_json,
                    "reason": "malformed_tags_json",
                }
            )
            continue

        asset_matches: set[int]
        if device_key.startswith("mac:"):
            tag_mac = normalize_mac(device_key.removeprefix("mac:"))
            if tag_mac is None:
                unresolved_tags.append(
                    {
                        "device_key": device_key,
                        "raw_tags_json": raw_tags_json,
                        "reason": "invalid_mac_device_key",
                    }
                )
                continue
            asset_matches = mac_asset_ids.get(tag_mac, set())
        elif device_key.startswith("ip:"):
            tag_ip = _normalize_ip(device_key.removeprefix("ip:"))
            if tag_ip is None:
                unresolved_tags.append(
                    {
                        "device_key": device_key,
                        "raw_tags_json": raw_tags_json,
                        "reason": "invalid_ip_device_key",
                    }
                )
                continue
            asset_matches = ip_asset_ids.get(tag_ip, set())
        else:
            unresolved_tags.append(
                {
                    "device_key": device_key,
                    "raw_tags_json": raw_tags_json,
                    "reason": "unsupported_device_key",
                }
            )
            continue

        if len(asset_matches) != 1:
            unresolved_tags.append(
                {
                    "device_key": device_key,
                    "raw_tags_json": raw_tags_json,
                    "reason": (
                        "unmatched_device_key"
                        if not asset_matches
                        else "ambiguous_device_key"
                    ),
                }
            )
            continue

        asset_id = next(iter(asset_matches))
        normalized_tags = sorted(
            {
                normalized
                for item in parsed_tags
                if (normalized := _normalize_legacy_list_item(item))
            }
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO asset_tag_bindings (
                asset_id, tag, binding_source, first_seen_at, last_seen_at
            ) VALUES (?, ?, 'legacy_manual_tag', ?, ?)
            """,
            [
                (asset_id, tag, migration_time, migration_time)
                for tag in normalized_tags
            ],
        )

    asset_sites = {
        int(row[0]): str(row[1] or "")
        for row in conn.execute("SELECT id, site FROM assets ORDER BY id")
    }
    valid_source_ids = {
        int(row[0]) for row in conn.execute("SELECT id FROM network_sources ORDER BY id")
    }
    unresolved_observations: list[dict[str, Any]] = []
    observation_rows = _dict_rows(
        conn.execute(
            """
            SELECT id, host_id, source_id, observed_at, observation_type,
                   ip, mac, hostname
            FROM host_observations
            ORDER BY id
            """
        )
    )
    for observation in observation_rows:
        asset_id = host_asset_ids.get(observation["host_id"])
        raw_mac = str(observation["mac"] or "").strip()
        normalized_mac = normalize_mac(raw_mac)
        mac_matches = mac_asset_ids.get(normalized_mac, set()) if normalized_mac else set()
        observation_ip = str(observation["ip"] or "").strip()
        hostname = str(observation["hostname"] or "").strip()
        ip_matches = ip_asset_ids.get(observation_ip, set()) if observation_ip else set()
        if asset_id is None and len(mac_matches) == 1:
            asset_id = next(iter(mac_matches))
        if asset_id is None and len(ip_matches) == 1:
            asset_id = next(iter(ip_matches))
        if asset_id is None:
            unresolved_observations.append(
                {
                    "observation_id": int(observation["id"]),
                    "reason": _unresolved_observation_reason(
                        observation,
                        normalized_mac=normalized_mac,
                        mac_match_count=len(mac_matches),
                        observation_ip=observation_ip,
                        ip_match_count=len(ip_matches),
                    ),
                }
            )
            continue
        if raw_mac and not observation_ip and not hostname:
            unresolved_observations.append(
                {
                    "observation_id": int(observation["id"]),
                    "reason": (
                        "unsupported_mac_only_observation" if normalized_mac else "invalid_mac"
                    ),
                }
            )
            continue

        original_source_id = observation["source_id"]
        source_id = (
            int(original_source_id)
            if original_source_id in valid_source_ids
            else None
        )
        source_key = f"legacy-host-observation:{observation['id']}"
        observation_type = str(observation["observation_type"])
        observed_at = str(observation["observed_at"])
        if observation_ip:
            conn.execute(
                """
                INSERT INTO ip_observations (
                    asset_id, site, source_id, source_key, ip, first_seen_at,
                    last_seen_at, is_current, observation_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    asset_id,
                    asset_sites[asset_id],
                    source_id,
                    source_key,
                    observation_ip,
                    observed_at,
                    observed_at,
                    observation_type,
                ),
            )
        if hostname:
            conn.execute(
                """
                INSERT INTO hostname_observations (
                    asset_id, hostname, source_id, source_key, source_type,
                    first_seen_at, last_seen_at, is_current
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    asset_id,
                    hostname,
                    source_id,
                    source_key,
                    observation_type,
                    observed_at,
                    observed_at,
                ),
            )

    counts = {
        "legacy_host_count": len(host_rows),
        "mapped_legacy_host_count": conn.execute(
            "SELECT COUNT(*) FROM legacy_host_asset_mappings"
        ).fetchone()[0],
        "mac_asset_count": conn.execute(
            "SELECT COUNT(*) FROM assets WHERE identity_method = 'mac_seed'"
        ).fetchone()[0],
        "provisional_asset_count": conn.execute(
            "SELECT COUNT(*) FROM assets WHERE identity_method = 'provisional_legacy'"
        ).fetchone()[0],
        "interface_count": conn.execute("SELECT COUNT(*) FROM asset_interfaces").fetchone()[0],
        "ip_observation_count": conn.execute("SELECT COUNT(*) FROM ip_observations").fetchone()[0],
        "hostname_observation_count": conn.execute(
            "SELECT COUNT(*) FROM hostname_observations"
        ).fetchone()[0],
        "tag_binding_count": conn.execute("SELECT COUNT(*) FROM asset_tag_bindings").fetchone()[0],
    }
    conn.execute(
        """
        INSERT INTO runtime_asset_migration_reports (
            migration_version, completed_at, legacy_host_count,
            mapped_legacy_host_count, mac_asset_count, provisional_asset_count,
            interface_count, ip_observation_count, hostname_observation_count,
            tag_binding_count, unresolved_legacy_host_ids_json,
            unresolved_observation_ids_json, unresolved_tag_records_json,
            aggregation_conflicts_json
        ) VALUES (2, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?)
        """,
        (
            migration_time,
            counts["legacy_host_count"],
            counts["mapped_legacy_host_count"],
            counts["mac_asset_count"],
            counts["provisional_asset_count"],
            counts["interface_count"],
            counts["ip_observation_count"],
            counts["hostname_observation_count"],
            counts["tag_binding_count"],
            json.dumps(
                unresolved_observations,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            json.dumps(
                unresolved_tags,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            json.dumps(aggregation_conflicts, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        ),
    )


def _dict_rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    columns = [description[0] for description in cursor.description or ()]
    return [dict(row) if isinstance(row, sqlite3.Row) else dict(zip(columns, row, strict=True)) for row in cursor]


def _effective_host_times(host: dict[str, Any], migration_time: str) -> tuple[str, str]:
    first_seen_at = _first_nonblank(host["first_seen_at"], host["last_seen_at"], migration_time)
    last_seen_at = _first_nonblank(host["last_seen_at"], host["first_seen_at"], migration_time)
    return first_seen_at, last_seen_at


def _unresolved_observation_reason(
    observation: dict[str, Any],
    *,
    normalized_mac: str | None,
    mac_match_count: int,
    observation_ip: str,
    ip_match_count: int,
) -> str:
    reasons: list[str] = []
    if observation["host_id"] is not None:
        reasons.append("host_id_not_mapped")
    raw_mac = str(observation["mac"] or "").strip()
    if raw_mac and not normalized_mac:
        reasons.append("invalid_mac")
    elif normalized_mac:
        reasons.append("mac_not_mapped" if mac_match_count == 0 else "mac_mapping_not_unique")
    if observation_ip:
        reasons.append("ip_not_mapped" if ip_match_count == 0 else "ip_mapping_not_unique")
    return ",".join(reasons) or "no_identity_fields"


def _first_nonblank(*values: Any) -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _legacy_representative_values(host: dict[str, Any], asset_key: str) -> dict[str, str]:
    return {
        "kind": _first_nonblank(host["device_type"], host["category"], "unknown"),
        "status": _first_nonblank(host["status"], "unknown"),
        "site": _first_nonblank(host["site"], ""),
        "display_name": _first_nonblank(
            host["display_name"],
            host["hostname"],
            host["ip"],
            asset_key,
        ),
        "comment": _first_nonblank(host["comment"], ""),
    }


def _legacy_aggregation_conflicts(
    asset_key: str,
    hosts: list[dict[str, Any]],
    representative: dict[str, Any],
    selected_values: dict[str, str],
) -> list[dict[str, Any]]:
    if len(hosts) < 2:
        return []
    conflicts: list[dict[str, Any]] = []
    selected_source_host_id = int(representative["id"])
    for field in sorted(selected_values):
        selected_value = selected_values[field]
        alternative_sources: dict[str, list[int]] = {}
        for host in hosts:
            value = _legacy_representative_values(host, asset_key)[field]
            if value and value != selected_value:
                alternative_sources.setdefault(value, []).append(int(host["id"]))
        if not alternative_sources:
            continue
        conflicts.append(
            {
                "alternatives": [
                    {
                        "source_host_ids": sorted(source_host_ids),
                        "value": value,
                    }
                    for value, source_host_ids in sorted(alternative_sources.items())
                ],
                "asset_key": asset_key,
                "field": field,
                "selected_source_host_id": selected_source_host_id,
                "selected_value": selected_value,
                "type": "same_mac_aggregation_conflict",
            }
        )
    return conflicts


def _normalize_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _normalize_legacy_list_item(item: Any) -> str:
    if isinstance(item, str):
        return item.strip()
    return json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _legacy_evidence(hosts: list[dict[str, Any]]) -> str:
    evidence: set[str] = set()
    for host in hosts:
        raw_evidence_json = str(host["device_evidence_json"] or "[]")
        try:
            items = json.loads(raw_evidence_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            if raw_evidence_json.strip():
                evidence.add(raw_evidence_json)
            continue
        if isinstance(items, list):
            evidence.update(
                normalized
                for item in items
                if (normalized := _normalize_legacy_list_item(item))
            )
        elif raw_evidence_json.strip():
            evidence.add(raw_evidence_json)
    return json.dumps(sorted(evidence), ensure_ascii=False, separators=(",", ":"))


MIGRATIONS: tuple[tuple[int, Callable[[sqlite3.Connection], None]], ...] = (
    (1, _migration_1),
    (2, _migration_2),
)


def apply_migrations(conn: sqlite3.Connection) -> None:
    conn.execute("SAVEPOINT apply_migrations")
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        applied_versions = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
        for version, migration in sorted(MIGRATIONS):
            if version not in applied_versions:
                migration(conn)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, utc_now()),
                )
        conn.execute("RELEASE SAVEPOINT apply_migrations")
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT apply_migrations")
        conn.execute("RELEASE SAVEPOINT apply_migrations")
        raise
