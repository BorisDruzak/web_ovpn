from __future__ import annotations

import ipaddress
import json
import sqlite3
from typing import Any

from .normalizer import normalize_mac


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _normalize_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _nonblank(value: Any) -> str:
    return str(value or "").strip()


def _max_timestamp(left: str, right: str) -> str:
    return max(left, right)


def _upsert_finding(
    conn: sqlite3.Connection,
    *,
    finding_key: str,
    finding_type: str,
    severity: str,
    observed_at: str,
    details: dict[str, Any],
    asset_id: int | None = None,
    source_id: int | None = None,
) -> bool:
    existing = conn.execute(
        "SELECT status FROM runtime_identity_findings WHERE finding_key = ?",
        (finding_key,),
    ).fetchone()
    conn.execute(
        """
        INSERT INTO runtime_identity_findings (
            finding_key, finding_type, severity, status, asset_id, source_id,
            first_seen_at, last_seen_at, details_json
        ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)
        ON CONFLICT(finding_key) DO UPDATE SET
            finding_type = excluded.finding_type,
            severity = excluded.severity,
            status = CASE
                WHEN runtime_identity_findings.status = 'resolved' THEN 'open'
                ELSE runtime_identity_findings.status
            END,
            asset_id = excluded.asset_id,
            source_id = excluded.source_id,
            last_seen_at = excluded.last_seen_at,
            details_json = excluded.details_json
        """,
        (
            finding_key,
            finding_type,
            severity,
            asset_id,
            source_id,
            observed_at,
            observed_at,
            _canonical_json(details),
        ),
    )
    return existing is None or str(existing["status"]) == "resolved"


def _upsert_mac_asset(
    conn: sqlite3.Connection,
    *,
    mac: str,
    host: dict[str, Any],
    source: dict[str, Any],
    observed_at: str,
) -> tuple[int, bool]:
    asset_key = f"mac:{mac}"
    existing = conn.execute(
        "SELECT * FROM assets WHERE asset_key = ?",
        (asset_key,),
    ).fetchone()
    kind = _nonblank(host.get("device_type") or host.get("kind")) or "unknown"
    site = _nonblank(host.get("site") or source.get("site"))
    display_name = _nonblank(host.get("display_name") or host.get("hostname"))

    if existing is None:
        cursor = conn.execute(
            """
            INSERT INTO assets (
                asset_key, identity_method, kind, status, site, display_name,
                identity_confidence, provisional, first_seen_at, last_seen_at,
                created_at, updated_at
            ) VALUES (?, 'mac_seed', ?, ?, ?, ?, 100, 0, ?, ?, ?, ?)
            """,
            (
                asset_key,
                kind,
                _nonblank(host.get("status")) or "unknown",
                site,
                display_name,
                observed_at,
                observed_at,
                observed_at,
                observed_at,
            ),
        )
        return int(cursor.lastrowid), True

    updates = {
        "kind": str(existing["kind"]),
        "site": str(existing["site"]),
        "display_name": str(existing["display_name"]),
    }
    if not updates["kind"].strip() or updates["kind"] == "unknown":
        updates["kind"] = kind
    if not updates["site"].strip():
        updates["site"] = site
    if not updates["display_name"].strip():
        updates["display_name"] = display_name
    conn.execute(
        """
        UPDATE assets
        SET kind = ?, site = ?, display_name = ?, last_seen_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            updates["kind"],
            updates["site"],
            updates["display_name"],
            _max_timestamp(str(existing["last_seen_at"]), observed_at),
            _max_timestamp(str(existing["updated_at"]), observed_at),
            int(existing["id"]),
        ),
    )
    return int(existing["id"]), False


def _upsert_interface(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    mac: str,
    host: dict[str, Any],
    observed_at: str,
) -> tuple[int, bool]:
    interface_key = f"mac:{mac}"
    existing = conn.execute(
        """
        SELECT * FROM asset_interfaces
        WHERE asset_id = ? AND interface_key = ?
        """,
        (asset_id, interface_key),
    ).fetchone()
    interface_name = _nonblank(host.get("interface"))
    if existing is None:
        cursor = conn.execute(
            """
            INSERT INTO asset_interfaces (
                asset_id, interface_key, mac, interface_name, lifecycle,
                first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, 'active', ?, ?)
            """,
            (
                asset_id,
                interface_key,
                mac,
                interface_name,
                observed_at,
                observed_at,
            ),
        )
        return int(cursor.lastrowid), True

    conn.execute(
        """
        UPDATE asset_interfaces
        SET mac = ?, interface_name = CASE
                WHEN trim(interface_name) = '' THEN ? ELSE interface_name
            END,
            lifecycle = 'active', last_seen_at = ?
        WHERE id = ?
        """,
        (
            mac,
            interface_name,
            _max_timestamp(str(existing["last_seen_at"]), observed_at),
            int(existing["id"]),
        ),
    )
    return int(existing["id"]), False


def _upsert_ip_observation(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    interface_id: int,
    source_id: int,
    source_key: str,
    ip: str,
    site: str,
    observed_at: str,
) -> None:
    conn.execute(
        """
        INSERT INTO ip_observations (
            asset_id, asset_interface_id, site, source_id, source_key, ip,
            first_seen_at, last_seen_at, is_current, observation_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'collector_host')
        ON CONFLICT(asset_id, ip, source_key, observation_source) DO UPDATE SET
            asset_interface_id = excluded.asset_interface_id,
            site = excluded.site,
            source_id = excluded.source_id,
            first_seen_at = min(ip_observations.first_seen_at, excluded.first_seen_at),
            last_seen_at = excluded.last_seen_at,
            is_current = 1
        """,
        (
            asset_id,
            interface_id,
            site,
            source_id,
            source_key,
            ip,
            observed_at,
            observed_at,
        ),
    )


def _upsert_hostname_observation(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    source_id: int,
    source_key: str,
    hostname: str,
    observed_at: str,
) -> None:
    conn.execute(
        """
        INSERT INTO hostname_observations (
            asset_id, hostname, source_id, source_key, source_type,
            first_seen_at, last_seen_at, is_current
        ) VALUES (?, ?, ?, ?, 'collector_host', ?, ?, 1)
        ON CONFLICT(asset_id, hostname, source_key, source_type) DO UPDATE SET
            source_id = excluded.source_id,
            first_seen_at = min(hostname_observations.first_seen_at, excluded.first_seen_at),
            last_seen_at = excluded.last_seen_at,
            is_current = 1
        """,
        (
            asset_id,
            hostname,
            source_id,
            source_key,
            observed_at,
            observed_at,
        ),
    )


def sync_runtime_hosts(
    conn: sqlite3.Connection,
    *,
    source: dict[str, Any],
    hosts: list[dict[str, Any]],
    observed_at: str,
) -> dict[str, int]:
    """Synchronize a successful normalized host snapshot into runtime identity.

    Transaction ownership belongs to the caller. In particular, this function never
    commits, so a later collector integration can atomically roll back all writes.
    """

    source_id = int(source["id"])
    source_key = f"network-source:{source_id}"
    previous_ip_assets = {
        str(row["ip"]): int(row["asset_id"])
        for row in conn.execute(
            """
            SELECT ip, asset_id
            FROM ip_observations
            WHERE source_key = ?
              AND observation_source = 'collector_host'
              AND is_current = 1
            """,
            (source_key,),
        )
    }

    conn.execute(
        """
        UPDATE ip_observations SET is_current = 0
        WHERE source_key = ? AND observation_source = 'collector_host' AND is_current = 1
        """,
        (source_key,),
    )
    conn.execute(
        """
        UPDATE hostname_observations SET is_current = 0
        WHERE source_key = ? AND source_type = 'collector_host' AND is_current = 1
        """,
        (source_key,),
    )
    active_ip_only_keys = {
        f"unresolved-ip-only:{source_id}:{ip}"
        for host in hosts
        if (ip := _normalize_ip(host.get("ip"))) is not None
        and normalize_mac(host.get("mac")) is None
    }
    stale_ip_only_keys = {
        str(row["finding_key"])
        for row in conn.execute(
            """
            SELECT finding_key
            FROM runtime_identity_findings
            WHERE finding_type = 'unresolved_ip_only_runtime'
              AND source_id = ? AND status != 'resolved'
            """,
            (source_id,),
        )
        if str(row["finding_key"]) not in active_ip_only_keys
    }
    if stale_ip_only_keys:
        conn.executemany(
            """
            UPDATE runtime_identity_findings
            SET status = 'resolved', last_seen_at = ?
            WHERE finding_key = ?
            """,
            [
                (observed_at, finding_key)
                for finding_key in sorted(stale_ip_only_keys)
            ],
        )
    resolved_ip_only = len(stale_ip_only_keys)

    counts = {
        "assets_created": 0,
        "assets_reused": 0,
        "interfaces_created": 0,
        "interfaces_reused": 0,
        "ip_observations": 0,
        "hostname_observations": 0,
        "ip_only_hosts": 0,
        "movement_findings": 0,
    }
    touched_asset_ids: set[int] = set()

    for host in hosts:
        ip = _normalize_ip(host.get("ip"))
        if ip is None:
            continue
        mac = normalize_mac(host.get("mac"))
        if mac is None:
            counts["ip_only_hosts"] += 1
            _upsert_finding(
                conn,
                finding_key=f"unresolved-ip-only:{source_id}:{ip}",
                finding_type="unresolved_ip_only_runtime",
                severity="warning",
                source_id=source_id,
                observed_at=observed_at,
                details={
                    "ip": ip,
                    "source_id": source_id,
                    "source_key": source_key,
                },
            )
            continue

        asset_id, asset_created = _upsert_mac_asset(
            conn,
            mac=mac,
            host=host,
            source=source,
            observed_at=observed_at,
        )
        counts["assets_created" if asset_created else "assets_reused"] += 1
        touched_asset_ids.add(asset_id)
        interface_id, interface_created = _upsert_interface(
            conn,
            asset_id=asset_id,
            mac=mac,
            host=host,
            observed_at=observed_at,
        )
        counts[
            "interfaces_created" if interface_created else "interfaces_reused"
        ] += 1
        site = _nonblank(host.get("site") or source.get("site"))
        _upsert_ip_observation(
            conn,
            asset_id=asset_id,
            interface_id=interface_id,
            source_id=source_id,
            source_key=source_key,
            ip=ip,
            site=site,
            observed_at=observed_at,
        )
        counts["ip_observations"] += 1

        hostname = _nonblank(host.get("hostname"))
        if hostname:
            _upsert_hostname_observation(
                conn,
                asset_id=asset_id,
                source_id=source_id,
                source_key=source_key,
                hostname=hostname,
                observed_at=observed_at,
            )
            counts["hostname_observations"] += 1

        previous_asset_id = previous_ip_assets.get(ip)
        if previous_asset_id is not None and previous_asset_id != asset_id:
            finding_key = (
                f"ip-moved:{source_id}:{ip}:{previous_asset_id}:{asset_id}"
            )
            if _upsert_finding(
                conn,
                finding_key=finding_key,
                finding_type="historical_identity_conflict",
                severity="warning",
                asset_id=asset_id,
                source_id=source_id,
                observed_at=observed_at,
                details={
                    "ip": ip,
                    "new_asset_id": asset_id,
                    "old_asset_id": previous_asset_id,
                    "source_id": source_id,
                },
            ):
                counts["movement_findings"] += 1

    finding_counts = recompute_runtime_identity_findings(
        conn,
        observed_at=observed_at,
    )
    counts["findings_opened"] = finding_counts["opened"]
    counts["findings_resolved"] = finding_counts["resolved"] + resolved_ip_only
    counts["assets_touched"] = len(touched_asset_ids)
    counts["ips_current"] = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM ip_observations
            WHERE source_key = ? AND observation_source = 'collector_host'
              AND is_current = 1
            """,
            (source_key,),
        ).fetchone()[0]
    )
    counts["hostnames_current"] = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM hostname_observations
            WHERE source_key = ? AND source_type = 'collector_host'
              AND is_current = 1
            """,
            (source_key,),
        ).fetchone()[0]
    )
    return counts


def recompute_runtime_identity_findings(
    conn: sqlite3.Connection,
    *,
    observed_at: str,
) -> dict[str, int]:
    """Recompute current global identity conflicts without deleting history."""

    active_keys: set[str] = set()
    opened = 0

    mac_collision_rows = conn.execute(
        """
        SELECT assets.id AS asset_id, asset_interfaces.mac AS mac
        FROM assets
        JOIN asset_interfaces
          ON asset_interfaces.asset_id = assets.id
         AND asset_interfaces.interface_key = assets.asset_key
        JOIN ip_observations ON ip_observations.asset_id = assets.id
        WHERE assets.identity_method = 'mac_seed'
          AND asset_interfaces.mac IS NOT NULL
          AND ip_observations.observation_source = 'collector_host'
          AND ip_observations.is_current = 1
          AND trim(ip_observations.site) != ''
        GROUP BY assets.id, asset_interfaces.mac
        HAVING COUNT(DISTINCT ip_observations.site) > 1
        ORDER BY assets.id, asset_interfaces.mac
        """
    ).fetchall()
    for row in mac_collision_rows:
        asset_id = int(row["asset_id"])
        mac = str(row["mac"])
        sites = [
            str(site_row[0])
            for site_row in conn.execute(
                """
                SELECT DISTINCT site
                FROM ip_observations
                WHERE asset_id = ? AND observation_source = 'collector_host'
                  AND is_current = 1 AND trim(site) != ''
                ORDER BY site
                """,
                (asset_id,),
            )
        ]
        finding_key = f"mac-site-collision:{asset_id}:{mac}"
        active_keys.add(finding_key)
        opened += int(
            _upsert_finding(
                conn,
                finding_key=finding_key,
                finding_type="mac_identity_collision",
                severity="warning",
                asset_id=asset_id,
                observed_at=observed_at,
                details={"asset_id": asset_id, "mac": mac, "sites": sites},
            )
        )

    duplicate_ip_rows = conn.execute(
        """
        SELECT ip
        FROM ip_observations
        WHERE observation_source = 'collector_host' AND is_current = 1
        GROUP BY ip
        HAVING COUNT(DISTINCT asset_id) > 1
        ORDER BY ip
        """
    ).fetchall()
    for row in duplicate_ip_rows:
        ip = str(row["ip"])
        asset_ids = [
            int(asset_row[0])
            for asset_row in conn.execute(
                """
                SELECT DISTINCT asset_id
                FROM ip_observations
                WHERE ip = ? AND observation_source = 'collector_host'
                  AND is_current = 1
                ORDER BY asset_id
                """,
                (ip,),
            )
        ]
        finding_key = f"duplicate-current-ip:{ip}"
        active_keys.add(finding_key)
        opened += int(
            _upsert_finding(
                conn,
                finding_key=finding_key,
                finding_type="duplicate_current_ip",
                severity="warning",
                observed_at=observed_at,
                details={"asset_ids": asset_ids, "ip": ip},
            )
        )

    active_keys.update(
        str(row["finding_key"])
        for row in conn.execute(
            """
            SELECT finding_key
            FROM runtime_identity_findings
            WHERE finding_type = 'unresolved_ip_only_runtime'
              AND status != 'resolved' AND last_seen_at = ?
            """,
            (observed_at,),
        )
    )

    existing_rows = conn.execute(
        """
        SELECT finding_key
        FROM runtime_identity_findings
        WHERE finding_type IN (
            'mac_identity_collision',
            'duplicate_current_ip',
            'unresolved_ip_only_runtime'
        )
          AND status != 'resolved'
        """
    ).fetchall()
    stale_keys = {
        str(row["finding_key"])
        for row in existing_rows
        if str(row["finding_key"]) not in active_keys
    }
    if stale_keys:
        conn.executemany(
            """
            UPDATE runtime_identity_findings
            SET status = 'resolved', last_seen_at = ?
            WHERE finding_key = ?
            """,
            [(observed_at, finding_key) for finding_key in sorted(stale_keys)],
        )

    open_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM runtime_identity_findings WHERE status = 'open'"
        ).fetchone()[0]
    )
    return {
        "active": len(active_keys),
        "opened": opened,
        "open": open_count,
        "resolved": len(stale_keys),
    }
