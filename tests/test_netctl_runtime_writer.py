from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from netctl.db import connect
from netctl.runtime_writer import (
    recompute_runtime_identity_findings,
    sync_runtime_hosts,
)
from netctl.store import save_collection


@pytest.fixture
def runtime_conn(tmp_path: Path) -> sqlite3.Connection:
    conn = connect(f"sqlite:///{(tmp_path / 'runtime.sqlite').as_posix()}")
    yield conn
    conn.close()


def _source(source_id: int, *, site: str) -> dict[str, Any]:
    return {"id": source_id, "name": f"source-{source_id}", "site": site}


def _seed_source(conn: sqlite3.Connection, source: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO network_sources (
            id, name, driver, host, port, username, secret_ref, site,
            created_at, updated_at
        ) VALUES (?, ?, 'test', '127.0.0.1', 1, 'test', 'TEST_SECRET', ?, ?, ?)
        """,
        (
            source["id"],
            source["name"],
            source["site"],
            "2026-07-18T00:00:00Z",
            "2026-07-18T00:00:00Z",
        ),
    )


def _host(
    ip: str,
    mac: str | None,
    *,
    hostname: str = "runtime-host",
    display_name: str = "Runtime host",
    kind: str = "pc",
    site: str = "",
) -> dict[str, Any]:
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "display_name": display_name,
        "device_type": kind,
        "site": site,
        "interface": "bridge-lan",
    }


def _finding(conn: sqlite3.Connection, finding_key: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM runtime_identity_findings WHERE finding_key = ?",
        (finding_key,),
    ).fetchone()
    assert row is not None
    return row


def _collection_snapshot(
    ip: str = "192.0.2.90",
    mac: str = "00:11:22:33:44:90",
) -> dict[str, Any]:
    return {
        "identity": [{"name": "test-router"}],
        "interfaces": [],
        "routes": [],
        "dhcp_leases": [
            {
                "ip": ip,
                "mac": mac,
                "hostname": "collected-host",
                "status": "bound",
            }
        ],
        "arp": [
            {
                "ip": ip,
                "mac": mac,
                "interface": "bridge-lan",
                "complete": True,
            }
        ],
        "neighbors": [],
        "bridge_hosts": [],
        "firewall_address_lists": [],
    }


def test_successful_collection_commits_legacy_and_runtime_together(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(20, site="central")
    _seed_source(runtime_conn, source)
    runtime_conn.commit()

    counts = save_collection(
        runtime_conn,
        source,
        _collection_snapshot(),
        "2026-07-18T04:00:00Z",
    )

    assert runtime_conn.execute("SELECT COUNT(*) FROM network_hosts").fetchone()[0] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0] == 1
    assert counts["runtime_assets_touched"] == 1
    assert counts["runtime_ips_current"] == 1
    assert counts["runtime_hostnames_current"] == 1
    assert counts["runtime_findings_open"] == 0


def test_runtime_writer_exception_rolls_back_all_collection_writes(
    runtime_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netctl.store as store

    source = _source(21, site="central")
    _seed_source(runtime_conn, source)
    runtime_conn.commit()

    def fail_after_runtime_writes(
        conn: sqlite3.Connection,
        *,
        source: dict[str, Any],
        hosts: list[dict[str, Any]],
        observed_at: str,
    ) -> dict[str, int]:
        sync_runtime_hosts(
            conn,
            source=source,
            hosts=hosts,
            observed_at=observed_at,
        )
        raise RuntimeError("runtime writer failure")

    monkeypatch.setattr(
        store,
        "sync_runtime_hosts",
        fail_after_runtime_writes,
        raising=False,
    )

    with pytest.raises(RuntimeError, match="runtime writer failure"):
        save_collection(
            runtime_conn,
            source,
            _collection_snapshot(),
            "2026-07-18T04:00:00Z",
        )

    for table in (
        "network_hosts",
        "host_observations",
        "arp_entries",
        "dhcp_leases",
        "assets",
        "asset_interfaces",
        "ip_observations",
        "hostname_observations",
        "collection_runs",
        "network_events",
    ):
        assert runtime_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    source_row = runtime_conn.execute(
        "SELECT last_collect_at, last_status, last_error FROM network_sources WHERE id = ?",
        (source["id"],),
    ).fetchone()
    assert tuple(source_row) == (None, None, None)


def test_failed_status_does_not_demote_current_runtime_rows(
    runtime_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import netctl.store as store

    source = _source(22, site="central")
    _seed_source(runtime_conn, source)
    runtime_conn.commit()
    save_collection(
        runtime_conn,
        source,
        _collection_snapshot(),
        "2026-07-18T04:00:00Z",
    )

    def unexpected_runtime_call(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        raise AssertionError("runtime writer must not run for failed collection")

    monkeypatch.setattr(store, "sync_runtime_hosts", unexpected_runtime_call)
    monkeypatch.setattr(
        store,
        "recompute_runtime_identity_findings",
        unexpected_runtime_call,
    )

    counts = save_collection(
        runtime_conn,
        source,
        _collection_snapshot(ip="192.0.2.91", mac="00:11:22:33:44:91"),
        "2026-07-18T05:00:00Z",
        status="error",
        message="collector unavailable",
    )

    assert runtime_conn.execute(
        "SELECT COUNT(*) FROM ip_observations WHERE is_current = 1"
    ).fetchone()[0] == 1
    assert runtime_conn.execute(
        "SELECT COUNT(*) FROM hostname_observations WHERE is_current = 1"
    ).fetchone()[0] == 1
    assert counts["runtime_assets_touched"] == 0
    assert counts["runtime_ips_current"] == 0
    assert counts["runtime_hostnames_current"] == 0
    assert counts["runtime_findings_open"] == 0


def test_same_successful_collection_snapshot_is_runtime_idempotent(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(23, site="central")
    _seed_source(runtime_conn, source)
    runtime_conn.commit()
    snapshot = _collection_snapshot()

    save_collection(runtime_conn, source, snapshot, "2026-07-18T04:00:00Z")
    second = save_collection(runtime_conn, source, snapshot, "2026-07-18T05:00:00Z")

    assert runtime_conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM asset_interfaces").fetchone()[0] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM ip_observations").fetchone()[0] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM hostname_observations").fetchone()[0] == 1
    assert second["runtime_assets_touched"] == 1
    assert second["runtime_ips_current"] == 1
    assert second["runtime_hostnames_current"] == 1


def test_new_mac_creates_asset_and_interface_then_reuses_them(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(1, site="central")
    _seed_source(runtime_conn, source)

    first = sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.10", "00-11-22-33-44-55")],
        observed_at="2026-07-18T01:00:00Z",
    )
    second = sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.11", "00:11:22:33:44:55")],
        observed_at="2026-07-18T02:00:00Z",
    )

    asset = runtime_conn.execute("SELECT * FROM assets").fetchone()
    interface = runtime_conn.execute("SELECT * FROM asset_interfaces").fetchone()
    assert first["assets_created"] == 1
    assert second["assets_created"] == 0
    assert second["assets_touched"] == 1
    assert second["ips_current"] == 1
    assert second["hostnames_current"] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM asset_interfaces").fetchone()[0] == 1
    assert (asset["asset_key"], asset["identity_method"], asset["provisional"]) == (
        "mac:00:11:22:33:44:55",
        "mac_seed",
        0,
    )
    assert (interface["asset_id"], interface["interface_key"], interface["mac"]) == (
        asset["id"],
        "mac:00:11:22:33:44:55",
        "00:11:22:33:44:55",
    )
    assert asset["first_seen_at"] == "2026-07-18T01:00:00Z"
    assert asset["last_seen_at"] == "2026-07-18T02:00:00Z"


def test_successful_snapshot_demotes_only_that_source_current_rows(
    runtime_conn: sqlite3.Connection,
) -> None:
    source_a = _source(1, site="central")
    source_b = _source(2, site="branch")
    _seed_source(runtime_conn, source_a)
    _seed_source(runtime_conn, source_b)
    host = _host("192.0.2.20", "00:11:22:33:44:20", hostname="shared")
    sync_runtime_hosts(runtime_conn, source=source_a, hosts=[host], observed_at="2026-07-18T01:00:00Z")
    sync_runtime_hosts(runtime_conn, source=source_b, hosts=[host], observed_at="2026-07-18T01:01:00Z")

    sync_runtime_hosts(runtime_conn, source=source_a, hosts=[], observed_at="2026-07-18T02:00:00Z")

    ip_rows = runtime_conn.execute(
        "SELECT source_key, is_current FROM ip_observations ORDER BY source_key"
    ).fetchall()
    hostname_rows = runtime_conn.execute(
        "SELECT source_key, is_current FROM hostname_observations ORDER BY source_key"
    ).fetchall()
    assert [tuple(row) for row in ip_rows] == [
        ("network-source:1", 0),
        ("network-source:2", 1),
    ]
    assert [tuple(row) for row in hostname_rows] == [
        ("network-source:1", 0),
        ("network-source:2", 1),
    ]


def test_ip_moving_to_new_mac_preserves_history_and_records_provenance(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(3, site="central")
    _seed_source(runtime_conn, source)
    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.30", "00:11:22:33:44:30")],
        observed_at="2026-07-18T01:00:00Z",
    )
    old_asset_id = runtime_conn.execute(
        "SELECT id FROM assets WHERE asset_key = 'mac:00:11:22:33:44:30'"
    ).fetchone()[0]

    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.30", "00:11:22:33:44:31")],
        observed_at="2026-07-18T02:00:00Z",
    )
    new_asset_id = runtime_conn.execute(
        "SELECT id FROM assets WHERE asset_key = 'mac:00:11:22:33:44:31'"
    ).fetchone()[0]

    rows = runtime_conn.execute(
        "SELECT asset_id, is_current FROM ip_observations WHERE ip = '192.0.2.30' ORDER BY asset_id"
    ).fetchall()
    assert old_asset_id != new_asset_id
    assert [tuple(row) for row in rows] == [(old_asset_id, 0), (new_asset_id, 1)]
    finding = _finding(
        runtime_conn,
        f"ip-moved:3:192.0.2.30:{old_asset_id}:{new_asset_id}",
    )
    assert (finding["finding_type"], finding["severity"], finding["status"]) == (
        "historical_identity_conflict",
        "warning",
        "open",
    )
    assert json.loads(finding["details_json"])["ip"] == "192.0.2.30"


def test_ip_only_host_stays_legacy_and_finding_resolves_when_mac_appears(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(4, site="central")
    _seed_source(runtime_conn, source)
    runtime_conn.execute(
        """
        INSERT INTO network_hosts (ip, mac, hostname, site, first_seen_at, last_seen_at)
        VALUES ('192.0.2.40', NULL, 'legacy-only', 'central', ?, ?)
        """,
        ("2026-07-17T00:00:00Z", "2026-07-17T00:00:00Z"),
    )

    counts = sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.40", None)],
        observed_at="2026-07-18T01:00:00Z",
    )

    assert counts["ip_only_hosts"] == 1
    assert runtime_conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0
    assert runtime_conn.execute("SELECT COUNT(*) FROM network_hosts").fetchone()[0] == 1
    assert _finding(runtime_conn, "unresolved-ip-only:4:192.0.2.40")["status"] == "open"

    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.40", "00:11:22:33:44:40")],
        observed_at="2026-07-18T02:00:00Z",
    )

    assert runtime_conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1
    assert _finding(runtime_conn, "unresolved-ip-only:4:192.0.2.40")["status"] == "resolved"


def test_persistent_ip_only_condition_preserves_acknowledged_status(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(11, site="central")
    _seed_source(runtime_conn, source)
    host = _host("192.0.2.41", None)
    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[host],
        observed_at="2026-07-18T01:00:00Z",
    )
    runtime_conn.execute(
        """
        UPDATE runtime_identity_findings SET status = 'acknowledged'
        WHERE finding_key = 'unresolved-ip-only:11:192.0.2.41'
        """
    )

    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[host],
        observed_at="2026-07-18T02:00:00Z",
    )

    assert _finding(
        runtime_conn, "unresolved-ip-only:11:192.0.2.41"
    )["status"] == "acknowledged"


def test_later_snapshot_from_other_source_does_not_resolve_ip_only_finding(
    runtime_conn: sqlite3.Connection,
) -> None:
    source_a = _source(12, site="central")
    source_b = _source(13, site="branch")
    _seed_source(runtime_conn, source_a)
    _seed_source(runtime_conn, source_b)
    sync_runtime_hosts(
        runtime_conn,
        source=source_a,
        hosts=[_host("192.0.2.42", None)],
        observed_at="2026-07-18T01:00:00Z",
    )

    sync_runtime_hosts(
        runtime_conn,
        source=source_b,
        hosts=[],
        observed_at="2026-07-18T02:00:00Z",
    )

    finding = _finding(runtime_conn, "unresolved-ip-only:12:192.0.2.42")
    assert finding["source_id"] == 12
    assert finding["status"] == "open"


def test_collector_fills_blank_fields_but_does_not_overwrite_manual_values(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(5, site="collector-site")
    _seed_source(runtime_conn, source)
    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.50", "00:11:22:33:44:50", hostname="first", display_name="First", kind="pc")],
        observed_at="2026-07-18T01:00:00Z",
    )
    runtime_conn.execute(
        """
        UPDATE assets
        SET kind = 'server', site = 'manual-site', display_name = 'Manual name',
            identity_method = 'manual', updated_at = '2026-07-18T01:30:00Z'
        WHERE asset_key = 'mac:00:11:22:33:44:50'
        """
    )

    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.50", "00:11:22:33:44:50", hostname="changed", display_name="Changed", kind="camera", site="other")],
        observed_at="2026-07-18T02:00:00Z",
    )

    asset = runtime_conn.execute(
        "SELECT * FROM assets WHERE asset_key = 'mac:00:11:22:33:44:50'"
    ).fetchone()
    assert (asset["kind"], asset["site"], asset["display_name"], asset["identity_method"]) == (
        "server",
        "manual-site",
        "Manual name",
        "manual",
    )
    assert asset["last_seen_at"] == "2026-07-18T02:00:00Z"


def test_same_mac_in_multiple_sites_opens_collision_then_marks_it_resolved(
    runtime_conn: sqlite3.Connection,
) -> None:
    source_a = _source(6, site="central")
    source_b = _source(7, site="branch")
    _seed_source(runtime_conn, source_a)
    _seed_source(runtime_conn, source_b)
    host = _host("192.0.2.60", "00:11:22:33:44:60")
    sync_runtime_hosts(runtime_conn, source=source_a, hosts=[host], observed_at="2026-07-18T01:00:00Z")
    sync_runtime_hosts(runtime_conn, source=source_b, hosts=[host], observed_at="2026-07-18T01:01:00Z")

    finding = runtime_conn.execute(
        "SELECT * FROM runtime_identity_findings WHERE finding_type = 'mac_identity_collision'"
    ).fetchone()
    assert finding is not None
    assert finding["status"] == "open"
    assert json.loads(finding["details_json"])["sites"] == ["branch", "central"]

    sync_runtime_hosts(runtime_conn, source=source_b, hosts=[], observed_at="2026-07-18T02:00:00Z")

    assert _finding(runtime_conn, finding["finding_key"])["status"] == "resolved"


def test_same_current_ip_on_different_assets_opens_duplicate_then_resolves(
    runtime_conn: sqlite3.Connection,
) -> None:
    source_a = _source(8, site="central")
    source_b = _source(9, site="branch")
    _seed_source(runtime_conn, source_a)
    _seed_source(runtime_conn, source_b)
    sync_runtime_hosts(
        runtime_conn,
        source=source_a,
        hosts=[_host("192.0.2.70", "00:11:22:33:44:70")],
        observed_at="2026-07-18T01:00:00Z",
    )
    sync_runtime_hosts(
        runtime_conn,
        source=source_b,
        hosts=[_host("192.0.2.70", "00:11:22:33:44:71")],
        observed_at="2026-07-18T01:01:00Z",
    )

    finding = runtime_conn.execute(
        "SELECT * FROM runtime_identity_findings WHERE finding_type = 'duplicate_current_ip'"
    ).fetchone()
    assert finding is not None
    assert finding["status"] == "open"
    assert len(json.loads(finding["details_json"])["asset_ids"]) == 2
    assert recompute_runtime_identity_findings(
        runtime_conn, observed_at="2026-07-18T01:02:00Z"
    )["open"] >= 1

    sync_runtime_hosts(runtime_conn, source=source_b, hosts=[], observed_at="2026-07-18T02:00:00Z")

    assert _finding(runtime_conn, finding["finding_key"])["status"] == "resolved"


def test_source_snapshot_resolves_ip_only_but_keeps_historical_movement_open(
    runtime_conn: sqlite3.Connection,
) -> None:
    source = _source(10, site="central")
    _seed_source(runtime_conn, source)
    sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[_host("192.0.2.80", None)],
        observed_at="2026-07-18T01:00:00Z",
    )
    runtime_conn.execute(
        """
        INSERT INTO runtime_identity_findings (
            finding_key, finding_type, severity, status, source_id,
            first_seen_at, last_seen_at, details_json
        ) VALUES (
            'ip-moved:10:192.0.2.81:1:2', 'historical_identity_conflict',
            'warning', 'open', 10, ?, ?, '{}'
        )
        """,
        ("2026-07-18T01:00:00Z", "2026-07-18T01:00:00Z"),
    )

    counts = sync_runtime_hosts(
        runtime_conn,
        source=source,
        hosts=[],
        observed_at="2026-07-18T02:00:00Z",
    )
    recompute_runtime_identity_findings(
        runtime_conn, observed_at="2026-07-18T03:00:00Z"
    )

    assert counts["findings_resolved"] >= 1
    assert _finding(runtime_conn, "unresolved-ip-only:10:192.0.2.80")["status"] == "resolved"
    assert _finding(runtime_conn, "ip-moved:10:192.0.2.81:1:2")["status"] == "open"
