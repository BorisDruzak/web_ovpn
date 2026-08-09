from __future__ import annotations

import json
from pathlib import Path

import pytest


NOW = "2026-08-09T10:00:00Z"


def _db_url(path: Path) -> str:
    return f"sqlite:///{path.as_posix()}"


def _subtree_db(tmp_path: Path):
    from netctl.db import connect

    conn = connect(_db_url(tmp_path / "fdb-subtree.sqlite"))
    conn.executemany(
        """
        INSERT INTO assets (
            id, asset_key, identity_method, identity_confidence, provisional,
            first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES (?, ?, 'manual', 100, 0, ?, ?, ?, ?)
        """,
        [
            (100, "mac:AA:AA:AA:AA:AA:01", NOW, NOW, NOW, NOW),
            (200, "mac:B2:B2:B2:B2:B2:02", NOW, NOW, NOW, NOW),
            (300, "mac:CC:CC:CC:CC:CC:03", NOW, NOW, NOW, NOW),
        ],
    )
    conn.executemany(
        """
        INSERT INTO asset_interfaces (
            asset_id, interface_key, mac, first_seen_at, last_seen_at
        ) VALUES (?, 'mgmt', ?, ?, ?)
        """,
        [
            (100, "AA:AA:AA:AA:AA:01", NOW, NOW),
            (200, "B2:B2:B2:B2:B2:02", NOW, NOW),
            (300, "CC:CC:CC:CC:CC:03", NOW, NOW),
        ],
    )
    conn.executemany(
        """
        INSERT INTO network_sources (
            id, name, driver, host, port, username, secret_ref, tls,
            verify_tls, enabled, driver_options_json, created_at, updated_at
        ) VALUES (?, ?, 'snmp_switch', '127.0.0.1', 161, '', 'env:TEST',
                  0, 0, 1, ?, ?, ?)
        """,
        [
            (1, "parent", '{"topology_role":"distribution"}', NOW, NOW),
            (2, "css326-floor2", '{"topology_role":"access"}', NOW, NOW),
            (3, "known-peer", '{"topology_role":"access"}', NOW, NOW),
        ],
    )
    conn.executemany(
        "INSERT INTO switch_devices (source_id, runtime_asset_id, updated_at) VALUES (?, ?, ?)",
        [(1, 100, NOW), (2, 200, NOW), (3, 300, NOW)],
    )
    conn.executemany(
        """
        INSERT INTO switch_collection_runs (
            id, source_id, started_at, finished_at, status, outcomes_json
        ) VALUES (?, ?, ?, ?, 'success', '{"fdb":"success_with_rows"}')
        """,
        [(11, 1, NOW, NOW), (22, 2, NOW, NOW), (33, 3, NOW, NOW)],
    )
    ports = [
        (1, "physical:10", 11),
        (1, "physical:11", 11),
        (1, "physical:12", 11),
        (2, "physical:1", 22),
        (2, "physical:2", 22),
        (2, "physical:3", 22),
        (2, "physical:4", 22),
        (3, "physical:1", 33),
    ]
    conn.executemany(
        """
        INSERT INTO switch_ports (
            source_id, port_key, name, oper_status, last_seen_at, collector_run_id
        ) VALUES (?, ?, '', 'up', ?, ?)
        """,
        [(source_id, port_key, NOW, run_id) for source_id, port_key, run_id in ports],
    )

    def fdb(
        source_id: int,
        vlan_key: str,
        mac: str,
        port_key: str,
        status: str,
        run_id: int,
    ) -> tuple[object, ...]:
        return (source_id, vlan_key, mac, port_key, status, NOW, NOW, run_id)

    leaf_macs = [
        "10:00:00:00:00:01",
        "10:00:00:00:00:02",
        "10:00:00:00:00:03",
        "10:00:00:00:00:04",
    ]
    rows = [
        fdb(2, "1", "AA:AA:AA:AA:AA:01", "physical:1", "learned", 22),
        fdb(2, "1", "10:00:00:00:00:99", "physical:1", "learned", 22),
        fdb(2, "1", leaf_macs[0], "physical:2", "learned", 22),
        fdb(2, "1", leaf_macs[1], "physical:2", "learned", 22),
        fdb(2, "1", leaf_macs[2], "physical:3", "learned", 22),
        fdb(2, "1", leaf_macs[3], "physical:3", "learned", 22),
        fdb(2, "1", "B2:B2:B2:B2:B2:02", "physical:2", "learned", 22),
        fdb(2, "1", "01:00:5E:00:00:01", "physical:2", "learned", 22),
        fdb(2, "1", "FF:FF:FF:FF:FF:FF", "physical:2", "learned", 22),
        fdb(2, "1", "00:00:00:00:00:00", "physical:2", "learned", 22),
        fdb(2, "1", "20:00:00:00:00:01", "physical:3", "self", 22),
        fdb(2, "1", "20:00:00:00:00:02", "physical:3", "invalid", 22),
        *[
            fdb(1, "1", mac, "physical:10", "learned", 11)
            for mac in leaf_macs
        ],
        fdb(1, "1", "B2:B2:B2:B2:B2:02", "physical:10", "learned", 11),
        *[
            fdb(1, "3", mac, "physical:11", "learned", 11)
            for mac in leaf_macs[:3]
        ],
        *[
            fdb(1, "2", mac, "physical:12", "learned", 11)
            for mac in leaf_macs
        ],
    ]
    conn.executemany(
        """
        INSERT INTO current_switch_fdb (
            source_id, vlan_key, mac, port_key, status,
            first_seen_at, last_seen_at, collector_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    return conn


def _known_backbone_link():
    from netctl.topology_models import CurrentSwitchLink, LinkEndpoint, LinkEvidence

    evidence = LinkEvidence(
        LinkEndpoint(2, "physical:1"),
        LinkEndpoint(3, "physical:1"),
        "lldp_chassis_mac",
        90,
        NOW,
        "",
        {},
    )
    return CurrentSwitchLink(
        "2:physical:1|3:physical:1",
        2,
        "physical:1",
        3,
        "physical:1",
        "inferred",
        85,
        "",
        NOW,
        (evidence,),
    )


def _lldp_link(
    parent_source_id: int,
    parent_port_key: str,
    child_source_id: int,
    child_port_key: str,
):
    from netctl.topology_models import CurrentSwitchLink, LinkEndpoint, LinkEvidence

    evidence = LinkEvidence(
        LinkEndpoint(parent_source_id, parent_port_key),
        LinkEndpoint(child_source_id, child_port_key),
        "lldp_chassis_mac",
        90,
        NOW,
        "",
        {},
    )
    return CurrentSwitchLink(
        f"{parent_source_id}:{parent_port_key}|{child_source_id}:{child_port_key}",
        parent_source_id,
        parent_port_key,
        child_source_id,
        child_port_key,
        "inferred",
        85,
        "",
        NOW,
        (evidence,),
    )


def _one_sided_management_link():
    from netctl.topology_models import CurrentSwitchLink, LinkEndpoint, LinkEvidence

    evidence = LinkEvidence(
        LinkEndpoint(1, "physical:10"),
        LinkEndpoint(2, ""),
        "fdb_management_mac",
        70,
        NOW,
        "",
        {"mac": "B2:B2:B2:B2:B2:02"},
    )
    return CurrentSwitchLink(
        "1:physical:10|2:",
        1,
        "physical:10",
        2,
        "",
        "inferred",
        70,
        "",
        NOW,
        (evidence,),
    )


def _add_second_upstream_candidate(
    conn,
    *,
    match_backbone_leaf: bool,
) -> None:
    leaf_macs = [
        "10:00:00:00:00:01",
        "10:00:00:00:00:02",
        "10:00:00:00:00:03",
        "10:00:00:00:00:04",
    ]
    conn.execute(
        """INSERT INTO current_switch_fdb (
               source_id, vlan_key, mac, port_key, status,
               first_seen_at, last_seen_at, collector_run_id
           ) VALUES (1, '4', '10:00:00:00:00:99', 'physical:10',
                     'learned', ?, ?, 11)""",
        (NOW, NOW),
    )
    parent_macs = [*leaf_macs, "B2:B2:B2:B2:B2:02"]
    if match_backbone_leaf:
        parent_macs.append("10:00:00:00:00:99")
    conn.executemany(
        """INSERT INTO current_switch_fdb (
               source_id, vlan_key, mac, port_key, status,
               first_seen_at, last_seen_at, collector_run_id
           ) VALUES (3, ?, ?, 'physical:1', 'learned', ?, ?, 33)""",
        [
            (str(index + 1), mac, NOW, NOW)
            for index, mac in enumerate(parent_macs)
        ],
    )
    conn.execute(
        """INSERT INTO current_switch_fdb (
               source_id, vlan_key, mac, port_key, status,
               first_seen_at, last_seen_at, collector_run_id
           ) VALUES (2, '4', 'CC:CC:CC:CC:CC:03', 'physical:1',
                     'learned', ?, ?, 22)""",
        (NOW, NOW),
    )


def test_subtree_candidates_filter_leaf_noise_apply_threshold_and_prefer_management_mac(
    tmp_path: Path,
) -> None:
    """Including backbone/self/management/invalid rows would inflate the leaf set."""
    from netctl.fdb_correlation import fdb_subtree_candidates
    from netctl.source_identity import list_source_identities

    conn = _subtree_db(tmp_path)
    try:
        candidates = fdb_subtree_candidates(
            conn,
            list_source_identities(conn),
            known_links=(_known_backbone_link(),),
        )

        assert len(candidates) == 1
        candidate = candidates[0]
        assert (
            candidate.parent_source_id,
            candidate.parent_port_key,
            candidate.child_source_id,
            candidate.child_port_key,
        ) == (1, "physical:10", 2, "physical:1")
        assert candidate.confidence == 100
        assert candidate.evidence == {
            "type": "fdb_subtree",
            "child_source": "css326-floor2",
            "child_leaf_mac_count": 4,
            "matched_mac_count": 4,
            "coverage": 1.0,
            "child_management_mac_seen": True,
        }
    finally:
        conn.close()


def test_subtree_candidate_never_fabricates_ambiguous_reverse_port(
    tmp_path: Path,
) -> None:
    """A parent management MAC learned on two child ports proves neither uplink."""
    from netctl.fdb_correlation import (
        fdb_subtree_candidates,
        fdb_subtree_link_evidence,
    )
    from netctl.source_identity import list_source_identities

    conn = _subtree_db(tmp_path)
    try:
        conn.execute(
            """INSERT INTO current_switch_fdb (
                   source_id, vlan_key, mac, port_key, status,
                   first_seen_at, last_seen_at, collector_run_id
               ) VALUES (2, '2', 'AA:AA:AA:AA:AA:01', 'physical:4',
                         'learned', ?, ?, 22)""",
            (NOW, NOW),
        )
        candidates = fdb_subtree_candidates(
            conn,
            list_source_identities(conn),
            known_links=(_known_backbone_link(),),
        )

        assert len(candidates) == 1
        assert candidates[0].child_port_key == ""
        assert fdb_subtree_link_evidence(candidates) == ()
    finally:
        conn.close()


def test_one_sided_subtree_sets_only_parent_port_role(
    tmp_path: Path,
) -> None:
    """A suspected child may enrich the parent role but never invent a child uplink."""
    from netctl.fdb_correlation import fdb_subtree_candidates
    from netctl.port_roles import infer_port_roles
    from netctl.source_identity import list_source_identities

    conn = _subtree_db(tmp_path)
    try:
        conn.execute(
            """INSERT INTO current_switch_fdb (
                   source_id, vlan_key, mac, port_key, status,
                   first_seen_at, last_seen_at, collector_run_id
               ) VALUES (2, '2', 'AA:AA:AA:AA:AA:01', 'physical:4',
                         'learned', ?, ?, 22)""",
            (NOW, NOW),
        )
        identities = list_source_identities(conn)
        links = (_known_backbone_link(), _one_sided_management_link())
        candidates = fdb_subtree_candidates(
            conn, identities, known_links=links
        )

        roles = infer_port_roles(
            conn,
            links=links,
            identities=identities,
            depths={1: 0, 2: 1, 3: 1},
            observed_at=NOW,
            subtree_candidates=candidates,
        )

        by_port = {(item.source_id, item.port_key): item for item in roles}
        parent = by_port[(1, "physical:10")]
        assert (
            parent.role,
            parent.confidence,
            parent.child_source_id,
            parent.evidence[0],
        ) == (
            "downstream_bridge",
            100,
            2,
            {
                "type": "fdb_subtree",
                "child_source": "css326-floor2",
                "child_leaf_mac_count": 4,
                "matched_mac_count": 4,
                "coverage": 1.0,
                "child_management_mac_seen": True,
            },
        )
        assert by_port[(2, "physical:4")].role != "backbone"
    finally:
        conn.close()


def test_stronger_lldp_role_is_not_replaced_by_subtree_candidate(
    tmp_path: Path,
) -> None:
    """Subtree evidence on an occupied LLDP port must not silently change its child."""
    from netctl.fdb_correlation import fdb_subtree_candidates
    from netctl.port_roles import infer_port_roles
    from netctl.source_identity import list_source_identities

    conn = _subtree_db(tmp_path)
    try:
        identities = list_source_identities(conn)
        lldp = _lldp_link(1, "physical:10", 3, "physical:1")
        links = (_known_backbone_link(), lldp)
        candidates = fdb_subtree_candidates(
            conn, identities, known_links=links
        )

        roles = infer_port_roles(
            conn,
            links=links,
            identities=identities,
            depths={1: 0, 2: 1, 3: 1},
            observed_at=NOW,
            subtree_candidates=candidates,
        )

        parent = next(
            item
            for item in roles
            if item.source_id == 1 and item.port_key == "physical:10"
        )
        assert (parent.role, parent.confidence, parent.child_source_id) == (
            "downstream_bridge",
            95,
            3,
        )
        assert parent.evidence[0]["type"] == "lldp_child_switch"
    finally:
        conn.close()


def test_complete_subtree_does_not_reuse_port_occupied_by_stronger_link(
    tmp_path: Path,
) -> None:
    """Pair-local aggregation must not create a second link on an LLDP port."""
    from netctl.fdb_correlation import (
        fdb_subtree_candidates,
        fdb_subtree_link_evidence,
    )
    from netctl.source_identity import list_source_identities

    conn = _subtree_db(tmp_path)
    try:
        identities = list_source_identities(conn)
        links = (
            _known_backbone_link(),
            _lldp_link(1, "physical:10", 3, "physical:1"),
        )
        candidates = fdb_subtree_candidates(
            conn, identities, known_links=links
        )

        assert len(candidates) == 1
        assert candidates[0].child_source_id == 2
        assert fdb_subtree_link_evidence(
            candidates, stronger_links=links
        ) == ()
    finally:
        conn.close()


def test_equal_upstream_candidates_do_not_create_multiple_complete_links(
    tmp_path: Path,
) -> None:
    """One exact child uplink does not prove which equal upstream parent is direct."""
    from netctl.fdb_correlation import (
        fdb_subtree_candidates,
        fdb_subtree_link_evidence,
    )
    from netctl.source_identity import list_source_identities

    conn = _subtree_db(tmp_path)
    try:
        _add_second_upstream_candidate(conn, match_backbone_leaf=True)

        candidates = fdb_subtree_candidates(
            conn, list_source_identities(conn)
        )
        child_candidates = [
            item for item in candidates if item.child_source_id == 2
        ]

        assert [
            (item.parent_source_id, item.coverage, item.child_port_key)
            for item in child_candidates
        ] == [
            (1, 1.0, "physical:1"),
            (3, 1.0, "physical:1"),
        ]
        assert not [
            item
            for item in fdb_subtree_link_evidence(candidates)
            if {item.endpoint_a.source_id, item.endpoint_b.source_id} & {2}
        ]
    finally:
        conn.close()


def test_unique_complete_winner_drives_matching_child_backbone_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A weaker candidate must not conflict with the selected child uplink role."""
    from netctl import topology_reconcile

    conn = _subtree_db(tmp_path)
    try:
        _add_second_upstream_candidate(conn, match_backbone_leaf=False)
        monkeypatch.setattr(
            topology_reconcile,
            "collect_link_evidence",
            lambda _conn, _identities: (),
        )

        topology_reconcile.reconcile_topology(conn, NOW, {})

        links = conn.execute(
            """SELECT source_a_id, port_a_key, source_b_id, port_b_key
               FROM current_switch_links
               WHERE source_a_id = 1 AND source_b_id = 2"""
        ).fetchall()
        assert [tuple(row) for row in links] == [
            (1, "physical:10", 2, "physical:1")
        ]
        role = conn.execute(
            """SELECT role, confidence, evidence_json
               FROM current_switch_port_roles
               WHERE source_id = 2 AND port_key = 'physical:1'"""
        ).fetchone()
        assert (role["role"], role["confidence"]) == ("backbone", 100)
        assert json.loads(str(role["evidence_json"]))[0] == {
            "child_leaf_mac_count": 5,
            "child_management_mac_seen": True,
            "child_source": "css326-floor2",
            "coverage": 1.0,
            "matched_mac_count": 5,
            "peer_source_id": 1,
            "type": "fdb_subtree_backbone",
        }
    finally:
        conn.close()


def test_equal_ambiguous_parents_do_not_publish_arbitrary_child_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No complete winner means no fabricated child backbone or peer evidence."""
    from netctl import topology_reconcile

    conn = _subtree_db(tmp_path)
    try:
        _add_second_upstream_candidate(conn, match_backbone_leaf=True)
        monkeypatch.setattr(
            topology_reconcile,
            "collect_link_evidence",
            lambda _conn, _identities: (),
        )

        topology_reconcile.reconcile_topology(conn, NOW, {})

        assert conn.execute(
            """SELECT count(*) FROM current_switch_links
               WHERE source_a_id = 1 AND source_b_id = 2"""
        ).fetchone()[0] == 0
        role = conn.execute(
            """SELECT role, child_source_id, evidence_json
               FROM current_switch_port_roles
               WHERE source_id = 2 AND port_key = 'physical:1'"""
        ).fetchone()
        evidence = json.loads(str(role["evidence_json"]))
        assert role["role"] != "backbone"
        assert role["child_source_id"] is None
        assert all(item.get("type") != "fdb_subtree_backbone" for item in evidence)
        assert all("peer_source_id" not in item for item in evidence)
    finally:
        conn.close()


def test_reconcile_does_not_persist_subtree_on_lldp_occupied_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reconciliation must apply the cross-pair occupied-port guard."""
    from netctl import topology_reconcile

    conn = _subtree_db(tmp_path)
    lldp = _lldp_link(1, "physical:10", 3, "physical:1")
    try:
        monkeypatch.setattr(
            topology_reconcile,
            "collect_link_evidence",
            lambda _conn, _identities: lldp.evidence,
        )

        topology_reconcile.reconcile_topology(conn, NOW, {})

        pairs = [
            (int(row[0]), int(row[1]))
            for row in conn.execute(
                """SELECT source_a_id, source_b_id
                   FROM current_switch_links ORDER BY source_a_id, source_b_id"""
            )
        ]
        assert pairs == [(1, 3)]
        role = conn.execute(
            """SELECT role, child_source_id
               FROM current_switch_port_roles
               WHERE source_id = 1 AND port_key = 'physical:10'"""
        ).fetchone()
        assert tuple(role) == ("downstream_bridge", 3)
    finally:
        conn.close()


def test_reconcile_adds_complete_subtree_link_only_from_exact_reverse_port(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One reverse FDB port promotes a subtree role hint to a complete inferred link."""
    from netctl.topology_reconcile import reconcile_topology

    conn = _subtree_db(tmp_path)
    try:
        conn.execute(
            """DELETE FROM current_switch_fdb
               WHERE source_id = 1 AND port_key != 'physical:12'"""
        )

        result = reconcile_topology(conn, NOW, {})

        link = conn.execute(
            """SELECT port_a_key, port_b_key, state, confidence, evidence_json
               FROM current_switch_links
               WHERE source_a_id = 1 AND source_b_id = 2"""
        ).fetchone()
        assert tuple(link[:4]) == ("physical:12", "physical:1", "inferred", 100)
        assert {
            item["evidence_type"]
            for item in json.loads(str(link["evidence_json"]))
        } == {"fdb_management_mac", "fdb_subtree"}
        role = conn.execute(
            """SELECT role, confidence, child_source_id, evidence_json
               FROM current_switch_port_roles
               WHERE source_id = 1 AND port_key = 'physical:12'"""
        ).fetchone()
        assert tuple(role[:3]) == ("downstream_bridge", 100, 2)
        assert json.loads(str(role["evidence_json"]))[0]["type"] == "fdb_subtree"
        assert result["counts"]["links"] == 1

        import netctl.cli as cli

        assert cli.main(
            [
                "--json",
                "--db",
                _db_url(tmp_path / "fdb-subtree.sqlite"),
                "switches",
                "port-roles",
                "--source",
                "parent",
            ]
        ) == 0
        payload = json.loads(capsys.readouterr().out)
        downstream = next(
            item
            for item in payload["port_roles"]
            if item["port_key"] == "physical:12"
        )
        assert downstream["child_source"] == "css326-floor2"
        assert downstream["evidence"][0] == {
            "type": "fdb_subtree",
            "child_source": "css326-floor2",
            "child_leaf_mac_count": 4,
            "matched_mac_count": 4,
            "coverage": 1.0,
            "child_management_mac_seen": False,
        }
    finally:
        conn.close()
