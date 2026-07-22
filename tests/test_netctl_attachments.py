from __future__ import annotations

import sqlite3
from pathlib import Path


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _attachment_db(tmp_path: Path) -> sqlite3.Connection:
    from netctl.db import connect

    conn = connect(_db_url(tmp_path / "attachments.sqlite"))
    now = "2026-07-22T08:00:00Z"
    conn.executemany(
        """
        INSERT INTO assets (
            id, asset_key, identity_method, identity_confidence, provisional,
            first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (?, ?, 'manual', 100, 0, ?, ?, ?, ?)
        """,
        [
            (1, "mac:C0:9B:F4:61:4B:CD", now, now, now, now),
            (2, "mac:AA:AA:AA:AA:AA:02", now, now, now, now),
            (3, "mac:AA:AA:AA:AA:AA:03", now, now, now, now),
        ],
    )
    conn.executemany(
        """
        INSERT INTO asset_interfaces (
            id, asset_id, interface_key, mac, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (1, 1, "endpoint", "c0:9b:f4:61:4b:cd", now, now),
            (2, 2, "mgmt", "AA:AA:AA:AA:AA:02", now, now),
            (3, 3, "mgmt", "AA:AA:AA:AA:AA:03", now, now),
        ],
    )
    conn.executemany(
        """
        INSERT INTO network_sources (
            id, name, driver, host, port, username, secret_ref, tls,
            verify_tls, enabled, created_at, updated_at
        ) VALUES (?, ?, 'snmp_switch', '127.0.0.1', 161, '', 'env:TEST', 0, 0, 1, ?, ?)
        """,
        [(10, "access", now, now), (11, "distribution", now, now)],
    )
    conn.executemany(
        """
        INSERT INTO switch_devices (source_id, runtime_asset_id, updated_at)
        VALUES (?, ?, ?)
        """,
        [(10, 2, now), (11, 3, now)],
    )
    conn.executemany(
        """
        INSERT INTO switch_collection_runs (id, source_id, started_at, finished_at, status)
        VALUES (?, ?, ?, ?, 'success')
        """,
        [(100, 10, now, now), (101, 11, now, now)],
    )
    conn.executemany(
        """
        INSERT INTO switch_ports (
            source_id, port_key, name, oper_status, last_seen_at, collector_run_id
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (10, "physical:48", "port48", "up", now, 100),
            (10, "physical:23", "ge23", "up", now, 100),
            (11, "physical:1", "uplink", "up", now, 101),
        ],
    )
    topology_run = conn.execute(
        """
        INSERT INTO network_correlation_runs (run_type, started_at, finished_at, status)
        VALUES ('topology', ?, ?, 'success')
        """,
        (now, now),
    ).lastrowid
    conn.execute(
        """
        INSERT INTO current_switch_links (
            link_key, source_a_id, port_a_key, source_b_id, port_b_key, state,
            confidence, first_seen_at, last_seen_at, correlation_run_id
        ) VALUES ('10:physical:23|11:physical:1', 10, 'physical:23', 11, 'physical:1',
            'confirmed', 100, ?, ?, ?)
        """,
        (now, now, topology_run),
    )
    conn.commit()
    return conn


def _insert_fdb(
    conn: sqlite3.Connection,
    *,
    source_id: int = 10,
    vlan_key: str = "20",
    vlan_id: int | None = 20,
    mac: str = "C0:9B:F4:61:4B:CD",
    port_key: str = "physical:48",
    status: str = "learned",
    collector_run_id: int = 100,
) -> None:
    now = "2026-07-22T08:00:00Z"
    conn.execute(
        """
        INSERT INTO current_switch_fdb (
            source_id, vlan_key, vlan_id, mac, port_key, status,
            first_seen_at, last_seen_at, collector_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (source_id, vlan_key, vlan_id, mac, port_key, status, now, now, collector_run_id),
    )
    conn.commit()


def test_attachment_candidates_classify_and_score_direct_and_uplink(tmp_path: Path) -> None:
    from netctl.attachment_candidates import attachment_candidates

    conn = _attachment_db(tmp_path)
    try:
        _insert_fdb(conn)
        _insert_fdb(conn, vlan_key="30", vlan_id=30, port_key="physical:23")

        candidates = attachment_candidates(conn, {10: 2, 11: 1})

        assert [(item.vlan_key, item.candidate_class, item.topology_depth, item.score) for item in candidates] == [
            ("20", "direct", 2, 85),
            ("30", "uplink", 2, 25),
        ]
    finally:
        conn.close()


def test_attachment_candidates_normalize_mac_preserve_vlans_and_ignore_self_or_invalid(tmp_path: Path) -> None:
    from netctl.attachment_candidates import attachment_candidates

    conn = _attachment_db(tmp_path)
    try:
        _insert_fdb(conn, mac="c0-9b-f4-61-4b-cd")
        _insert_fdb(conn, vlan_key="21", vlan_id=21, mac="C0:9B:F4:61:4B:CD")
        _insert_fdb(conn, vlan_key="22", vlan_id=22, mac="AA:AA:AA:AA:AA:02", status="mgmt")
        _insert_fdb(conn, vlan_key="23", vlan_id=23, mac="invalid-mac")

        candidates = attachment_candidates(conn, {})

        assert [(item.asset_interface_id, item.vlan_key, item.topology_depth) for item in candidates] == [
            (1, "20", None),
            (1, "21", None),
        ]
        assert conn.execute("SELECT mac FROM asset_interfaces WHERE id = 1").fetchone()[0] == "c0:9b:f4:61:4b:cd"
    finally:
        conn.close()


def test_attachment_candidates_keep_last_successful_fdb_after_a_failed_run(tmp_path: Path) -> None:
    from netctl.attachment_candidates import attachment_candidates

    conn = _attachment_db(tmp_path)
    try:
        _insert_fdb(conn)
        conn.execute(
            """
            INSERT INTO switch_collection_runs (id, source_id, started_at, finished_at, status)
            VALUES (102, 10, '2026-07-22T08:01:00Z', '2026-07-22T08:01:00Z', 'failed')
            """
        )
        conn.commit()

        candidates = attachment_candidates(conn, {})

        assert [(item.port_key, item.score) for item in candidates] == [("physical:48", 75)]
    finally:
        conn.close()


def _candidate(
    *,
    source_id: int = 10,
    port_key: str = "physical:48",
    candidate_class: str = "direct",
    depth: int | None = 2,
    score: int = 85,
):
    from netctl.attachment_candidates import AttachmentCandidate

    return AttachmentCandidate(
        asset_id=1,
        asset_interface_id=1,
        switch_source_id=source_id,
        port_key=port_key,
        vlan_key="20",
        vlan_id=20,
        candidate_class=candidate_class,
        topology_depth=depth,
        score=score,
        observed_at="2026-07-22T08:00:00Z",
        evidence=(),
    )


def test_attachment_resolution_uses_confirmed_ambiguous_uplink_and_unresolved_rules() -> None:
    from netctl.attachment_reconcile import resolve_attachment

    confirmed = resolve_attachment((_candidate(score=85), _candidate(source_id=11, score=65)))
    assert (confirmed.status, confirmed.confidence, confirmed.selected.port_key) == ("confirmed", 85, "physical:48")

    ambiguous = resolve_attachment((_candidate(score=85), _candidate(source_id=11, score=74)))
    assert (ambiguous.status, ambiguous.confidence, ambiguous.selected) == ("ambiguous", 60, None)

    same_depth = resolve_attachment((_candidate(score=85), _candidate(source_id=11, score=84, depth=2)))
    assert same_depth.status == "ambiguous"

    uplink_only = resolve_attachment((_candidate(candidate_class="uplink", score=45),))
    assert (uplink_only.status, uplink_only.confidence, uplink_only.selected) == ("uplink_only", 45, None)

    unresolved = resolve_attachment(())
    assert (unresolved.status, unresolved.confidence, unresolved.selected) == ("unresolved", 0, None)


def test_reconcile_attachments_persists_candidates_and_a_move(
    tmp_path: Path, monkeypatch
) -> None:
    from netctl import attachment_reconcile

    conn = _attachment_db(tmp_path)
    try:
        first = (_candidate(port_key="physical:48", score=85),)
        monkeypatch.setattr(attachment_reconcile, "attachment_candidates", lambda _conn, _depths: first)
        monkeypatch.setattr(attachment_reconcile, "list_source_identities", lambda _conn: ())
        created = attachment_reconcile.reconcile_attachments(conn, "2026-07-22T08:00:00Z")
        assert created["counts"]["confirmed"] == 1
        assert conn.execute(
            "SELECT selected_port_key FROM asset_attachment_resolutions WHERE asset_interface_id = 1"
        ).fetchone()[0] == "physical:48"
        assert conn.execute("SELECT event_type FROM asset_attachment_events").fetchone()[0] == "attached"

        moved = (_candidate(port_key="physical:47", score=85),)
        monkeypatch.setattr(attachment_reconcile, "attachment_candidates", lambda _conn, _depths: moved)
        attachment_reconcile.reconcile_attachments(conn, "2026-07-22T08:01:00Z")
        assert conn.execute(
            "SELECT event_type FROM asset_attachment_events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0] == "moved"
    finally:
        conn.close()
