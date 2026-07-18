from __future__ import annotations

import json

import pytest


def test_observer_categories_match_canonical_schema_contract():
    import netctl.context_classifier as classifier

    assert getattr(classifier, "OBSERVER_CATEGORIES", None) == frozenset(
        {
            "local_device",
            "site_device",
            "vpn_client",
            "telephony",
            "mgmt",
            "vipnet_transit",
            "wan",
            "noise",
            "unknown",
        }
    )


def _activate_segments(conn, segments: list[dict[str, object]], *, revision: int = 1) -> None:
    context_id = "classifier-test"
    revision_row = conn.execute(
        """
        INSERT INTO context_revisions
            (context_id, schema_version, sha256, source_path, validated_at, git_sha,
             status, error_json, counts_json, validation_order)
        VALUES (?, '2.2.0', ?, 'context.yaml', ?, ?, 'ok', '[]', '{}', ?)
        """,
        (context_id, f"sha-{revision}", f"2026-07-18T00:00:0{revision}Z", f"git-{revision}", revision),
    )
    revision_id = int(revision_row.lastrowid)
    run_row = conn.execute(
        """
        INSERT INTO context_import_runs
            (context_id, context_revision_id, base_context_revision_id, input_sha256,
             git_sha, source_path, started_at, finished_at, status, errors_json)
        VALUES (?, ?, NULL, ?, ?, 'context.yaml', ?, ?, 'success_imported', '[]')
        """,
        (
            context_id,
            revision_id,
            f"sha-{revision}",
            f"git-{revision}",
            f"2026-07-18T00:00:0{revision}Z",
            f"2026-07-18T00:00:0{revision}Z",
        ),
    )
    for segment in segments:
        canonical_json = json.dumps(segment, sort_keys=True, separators=(",", ":"))
        conn.execute(
            """
            INSERT INTO intent_segments
                (context_revision_id, stable_id, lifecycle, canonical_json,
                 canonical_hash, origin_context_revision_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                revision_id,
                segment["id"],
                segment.get("lifecycle", "active"),
                canonical_json,
                f"hash-{revision}-{segment['id']}",
                revision_id,
            ),
        )
    conn.execute(
        """
        INSERT INTO context_heads
            (context_id, context_revision_id, activated_by_import_run_id, activated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(context_id) DO UPDATE SET
            context_revision_id=excluded.context_revision_id,
            activated_by_import_run_id=excluded.activated_by_import_run_id,
            activated_at=excluded.activated_at
        """,
        (context_id, revision_id, int(run_row.lastrowid), f"2026-07-18T00:00:0{revision}Z"),
    )
    conn.commit()


def _source(conn):
    from netctl.db import get_source, upsert_source

    source = {
        "name": "classifier-source",
        "driver": "mock",
        "host": "10.0.0.1",
        "port": 8729,
        "username": "observer",
        "secret_ref": "classifier-source",
        "tls": False,
        "verify_tls": False,
        "site": "test-site",
        "role": "router",
        "enabled": True,
    }
    upsert_source(conn, source)
    return get_source(conn, source["name"])


def test_longest_prefix_wins():
    from netctl.context_classifier import SegmentRule, classify_address

    import ipaddress

    rules = [
        SegmentRule("wide", ipaddress.ip_network("10.0.0.0/8"), "wan", "edge"),
        SegmentRule("specific", ipaddress.ip_network("10.20.0.0/16"), "site_device", "north"),
    ]

    assert classify_address(
        "10.20.1.9", rules=rules, source={}, has_name=True, network_infra=False
    ) == "site_device"


def test_active_context_cidr_change_changes_classification_without_python_change(tmp_path):
    from netctl.context_classifier import classify_address, load_active_segment_rules
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(
            conn,
            [{"id": "branch", "cidr": "10.30.0.0/24", "observer_category": "site_device", "site": "branch"}],
            revision=1,
        )
        before = load_active_segment_rules(conn)
        assert classify_address("10.31.0.10", rules=before, source={}, has_name=True, network_infra=False) == "unknown"

        _activate_segments(
            conn,
            [{"id": "branch", "cidr": "10.31.0.0/24", "observer_category": "site_device", "site": "branch"}],
            revision=2,
        )
        after = load_active_segment_rules(conn)
        assert classify_address("10.31.0.10", rules=after, source={}, has_name=True, network_infra=False) == "site_device"
    finally:
        conn.close()


def test_new_site_and_retired_segments_are_loaded_from_active_revision(tmp_path):
    from netctl.context_classifier import classify_address, load_active_segment_rules
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(
            conn,
            [
                {"id": "new-site", "cidr": "10.40.0.0/24", "observer_category": "site_device", "site": "east"},
                {"id": "old-site", "cidr": "10.41.0.0/24", "observer_category": "site_device", "site": "west", "lifecycle": "retired"},
            ],
        )

        rules = load_active_segment_rules(conn)

        assert [(rule.segment_id, rule.site) for rule in rules] == [("new-site", "east")]
        assert classify_address("10.40.0.7", rules=rules, source={}, has_name=True, network_infra=False) == "site_device"
        assert classify_address("10.41.0.7", rules=rules, source={}, has_name=True, network_infra=False) == "unknown"
    finally:
        conn.close()


def test_missing_observer_category_returns_unknown(tmp_path):
    from netctl.context_classifier import classify_address, load_active_segment_rules
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(conn, [{"id": "uncategorized", "cidr": "10.50.0.0/24", "site": "test"}])
        rules = load_active_segment_rules(conn)
        assert classify_address("10.50.0.7", rules=rules, source={}, has_name=True, network_infra=False) == "unknown"
    finally:
        conn.close()


def test_network_infra_overrides_endpoint_category_and_unnamed_local_remains_unknown():
    import ipaddress

    from netctl.context_classifier import SegmentRule, classify_address

    rules = [SegmentRule("lan", ipaddress.ip_network("10.60.0.0/24"), "local_device", "main")]

    assert classify_address("10.60.0.8", rules=rules, source={}, has_name=True, network_infra=True) == "network_infra"
    assert classify_address("10.60.0.9", rules=rules, source={}, has_name=False, network_infra=False) == "unknown"


def test_malformed_active_segment_is_rejected(tmp_path):
    from netctl.context_classifier import load_active_segment_rules
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(conn, [{"id": "bad", "cidr": "not-a-network", "observer_category": "wan"}])
        with pytest.raises(ValueError, match="active segment bad"):
            load_active_segment_rules(conn)
    finally:
        conn.close()


@pytest.mark.parametrize("category", ["unapproved", " local_device", "local_device "])
def test_invalid_active_category_aborts_collection_without_writes(tmp_path, category):
    from netctl.db import connect
    from netctl.store import save_collection

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        source = _source(conn)
        assert source is not None
        _activate_segments(
            conn,
            [{"id": "invalid-category", "cidr": "10.80.0.0/24", "observer_category": category}],
        )
        before = "\n".join(conn.iterdump())

        with pytest.raises(
            ValueError,
            match=r"malformed active segment invalid-category: invalid observer_category",
        ):
            save_collection(
                conn,
                source,
                {
                    "dhcp_leases": [
                        {"ip": "10.80.0.8", "hostname": "workstation", "status": "bound"}
                    ],
                    "arp": [],
                    "neighbors": [],
                    "bridge_hosts": [],
                },
                "2026-07-18T01:00:00Z",
            )

        assert "\n".join(conn.iterdump()) == before
        assert conn.execute("SELECT COUNT(*) FROM collection_runs").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM network_events").fetchone()[0] == 0
    finally:
        conn.close()


@pytest.mark.parametrize("active", [False, True])
def test_collection_records_context_classifier_fallback_state(tmp_path, active):
    from netctl.db import connect
    from netctl.store import save_collection

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        source = _source(conn)
        assert source is not None
        if active:
            _activate_segments(
                conn,
                [{"id": "test-lan", "cidr": "10.70.0.0/24", "observer_category": "local_device", "site": "test"}],
            )
        counts = save_collection(
            conn,
            source,
            {
                "dhcp_leases": [{"ip": "10.70.0.8", "hostname": "workstation", "status": "bound"}],
                "arp": [],
                "neighbors": [],
                "bridge_hosts": [],
            },
            "2026-07-18T01:00:00Z",
        )

        assert counts["context_classifier_fallback"] is (not active)
        fallback_events = conn.execute(
            "SELECT severity, event_type FROM network_events WHERE event_type = 'context_classifier_fallback'"
        ).fetchall()
        assert len(fallback_events) == (0 if active else 1)
        if not active:
            assert dict(fallback_events[0]) == {
                "severity": "warning",
                "event_type": "context_classifier_fallback",
            }
    finally:
        conn.close()
