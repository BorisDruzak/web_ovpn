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


def _activate_segments(
    conn,
    segments: list[dict[str, object]],
    *,
    revision: int = 1,
    context_id: str = "classifier-test",
) -> None:
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


def test_multiple_eligible_context_heads_fail_closed(tmp_path):
    from netctl.context_classifier import load_active_segment_rules
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(
            conn,
            [{"id": "first-lan", "cidr": "10.31.0.0/24", "observer_category": "local_device"}],
            context_id="first-context",
        )
        _activate_segments(
            conn,
            [{"id": "second-lan", "cidr": "10.32.0.0/24", "observer_category": "site_device"}],
            revision=2,
            context_id="second-context",
        )

        with pytest.raises(
            ValueError,
            match=r"multiple active network contexts: first-context, second-context",
        ):
            load_active_segment_rules(conn)
    finally:
        conn.close()


def test_context_segment_site_change_updates_legacy_and_runtime_observation_rows(tmp_path):
    from netctl.db import connect
    from netctl.store import save_collection

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        source = _source(conn)
        assert source is not None
        snapshot = {
            "dhcp_leases": [
                {
                    "ip": "10.33.0.8",
                    "mac": "00:11:22:33:44:55",
                    "hostname": "workstation",
                    "status": "bound",
                }
            ],
            "arp": [],
            "neighbors": [],
            "bridge_hosts": [],
        }
        _activate_segments(
            conn,
            [{"id": "branch", "cidr": "10.33.0.0/24", "observer_category": "site_device", "site": "west"}],
        )
        save_collection(conn, source, snapshot, "2026-07-18T01:00:00Z")

        assert conn.execute(
            "SELECT site FROM network_hosts WHERE ip = '10.33.0.8'"
        ).fetchone()[0] == "west"
        assert conn.execute(
            "SELECT site FROM ip_observations WHERE ip = '10.33.0.8' AND is_current = 1"
        ).fetchone()[0] == "west"

        _activate_segments(
            conn,
            [{"id": "branch", "cidr": "10.33.0.0/24", "observer_category": "site_device", "site": "east"}],
            revision=2,
        )
        save_collection(conn, source, snapshot, "2026-07-18T02:00:00Z")

        legacy = conn.execute(
            "SELECT category, site FROM network_hosts WHERE ip = '10.33.0.8'"
        ).fetchone()
        runtime = conn.execute(
            "SELECT site FROM ip_observations WHERE ip = '10.33.0.8' AND is_current = 1"
        ).fetchone()
        assert tuple(legacy) == ("site_device", "east")
        assert runtime[0] == "east"
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


def test_active_availability_segments_are_ipv4_and_have_bounded_tcp_ports(tmp_path):
    from netctl.context_classifier import load_active_availability_segments
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(
            conn,
            [
                {
                    "id": "m-arhiv-lan",
                    "cidr": "192.168.99.0/24",
                    "observer_category": "site_device",
                    "availability_monitoring": True,
                    "availability_tcp_ports": [22, 443],
                }
            ],
        )

        assert [
            (
                rule.network.with_prefixlen,
                rule.availability_tcp_ports,
                rule.availability_interval_minutes,
            )
            for rule in load_active_availability_segments(conn)
        ] == [("192.168.99.0/24", (22, 443), 5)]
    finally:
        conn.close()


def test_setting_enables_only_known_ipv4_segment_without_storing_cidr(tmp_path):
    """A persisted override must identify its canonical target by stable ID alone."""
    from netctl.availability_settings import (
        list_availability_settings,
        load_active_availability_segments,
        set_availability_setting,
    )
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(
            conn,
            [
                {"id": "office", "cidr": "192.0.2.0/24"},
                {"id": "vpn", "cidr": "2001:db8::/64"},
            ],
        )

        setting = set_availability_setting(
            conn, "office", enabled=True, tcp_ports=(443,), interval_minutes=10
        )

        assert setting["segment_id"] == "office"
        assert "cidr" not in setting
        assert list_availability_settings(conn) == [setting]
        assert "cidr" not in {
            str(row[1]) for row in conn.execute("PRAGMA table_info(availability_segment_settings)")
        }
        assert [
            (
                str(rule.network),
                rule.availability_tcp_ports,
                rule.availability_interval_minutes,
            )
            for rule in load_active_availability_segments(conn)
        ] == [("192.0.2.0/24", (443,), 10)]
    finally:
        conn.close()


def test_setting_rejects_unknown_ipv6_and_invalid_interval(tmp_path):
    """A setting may only target a current canonical IPv4 segment with an allowed cadence."""
    from netctl.availability_settings import set_availability_setting
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(conn, [{"id": "ipv6", "cidr": "2001:db8::/64"}])

        with pytest.raises(ValueError, match="active IPv4 segment"):
            set_availability_setting(
                conn, "ipv6", enabled=True, tcp_ports=(), interval_minutes=5
            )
        with pytest.raises(ValueError, match="interval"):
            set_availability_setting(
                conn, "missing", enabled=True, tcp_ports=(), interval_minutes=7
            )
    finally:
        conn.close()


def test_setting_rejects_invalid_prospective_effective_rules_without_persisting(tmp_path):
    """Enabling a broad canonical segment must not poison the effective rule loader."""
    from netctl.availability_settings import (
        list_availability_settings,
        set_availability_setting,
    )
    from netctl.context_classifier import load_active_availability_segments
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(
            conn,
            [
                {"id": "office-wide", "cidr": "192.0.0.0/16"},
                {
                    "id": "office",
                    "cidr": "192.0.2.0/24",
                    "availability_monitoring": True,
                },
            ],
        )

        with pytest.raises(ValueError, match="at least /24"):
            set_availability_setting(
                conn,
                "office-wide",
                enabled=True,
                tcp_ports=(443,),
                interval_minutes=10,
            )

        assert list_availability_settings(conn) == []
        assert [str(rule.network) for rule in load_active_availability_segments(conn)] == [
            "192.0.2.0/24"
        ]
    finally:
        conn.close()


@pytest.mark.parametrize(
    "ports",
    [(), (22,), (22, 443, 8443)],
)
def test_setting_accepts_up_to_three_unique_valid_tcp_ports(tmp_path, ports):
    """The override must retain the collector's existing bounded TCP fallback policy."""
    from netctl.availability_settings import set_availability_setting
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(conn, [{"id": "office", "cidr": "192.0.2.0/24"}])

        setting = set_availability_setting(
            conn, "office", enabled=False, tcp_ports=ports, interval_minutes=5
        )

        assert setting["tcp_ports"] == ports
    finally:
        conn.close()


@pytest.mark.parametrize(
    "ports",
    [(22, 80, 443, 8443), (443, 443), (0,), (65536,), (True,)],
)
def test_setting_rejects_invalid_tcp_ports(tmp_path, ports):
    """Unbounded, duplicate, boolean, or out-of-range ports must not reach persistence."""
    from netctl.availability_settings import set_availability_setting
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(conn, [{"id": "office", "cidr": "192.0.2.0/24"}])

        with pytest.raises(ValueError, match="tcp_ports"):
            set_availability_setting(
                conn, "office", enabled=True, tcp_ports=ports, interval_minutes=5
            )
    finally:
        conn.close()


@pytest.mark.parametrize(
    "segment, reason",
    [
        (
            {"id": "v6", "cidr": "2001:db8::/64", "availability_monitoring": True},
            "availability monitoring requires an IPv4 cidr",
        ),
        (
            {
                "id": "too-many",
                "cidr": "192.0.2.0/24",
                "availability_monitoring": True,
                "availability_tcp_ports": [22, 80, 443, 8443],
            },
            "availability_tcp_ports must contain at most 3 ports",
        ),
        (
            {"id": "monitoring-string", "cidr": "192.0.2.0/24", "availability_monitoring": "true"},
            "availability_monitoring must be a boolean",
        ),
        (
            {
                "id": "ports-string",
                "cidr": "192.0.2.0/24",
                "availability_monitoring": True,
                "availability_tcp_ports": "443",
            },
            "availability_tcp_ports must be a list",
        ),
        (
            {
                "id": "ports-without-monitoring",
                "cidr": "192.0.2.0/24",
                "availability_monitoring": False,
                "availability_tcp_ports": [443],
            },
            "availability_tcp_ports requires availability_monitoring to be true",
        ),
        (
            {
                "id": "duplicate-port",
                "cidr": "192.0.2.0/24",
                "availability_monitoring": True,
                "availability_tcp_ports": [443, 443],
            },
            "availability_tcp_ports must not contain duplicates",
        ),
        (
            {
                "id": "bool-port",
                "cidr": "192.0.2.0/24",
                "availability_monitoring": True,
                "availability_tcp_ports": [True],
            },
            "availability_tcp_ports must contain integers",
        ),
        (
            {
                "id": "low-port",
                "cidr": "192.0.2.0/24",
                "availability_monitoring": True,
                "availability_tcp_ports": [0],
            },
            "availability_tcp_ports must contain ports in 1..65535",
        ),
        (
            {
                "id": "high-port",
                "cidr": "192.0.2.0/24",
                "availability_monitoring": True,
                "availability_tcp_ports": [65536],
            },
            "availability_tcp_ports must contain ports in 1..65535",
        ),
        (
            {
                "id": "host-bits",
                "cidr": "192.0.2.1/24",
                "availability_monitoring": True,
            },
            "availability cidr must be canonical",
        ),
        (
            {
                "id": "leading-zero-prefix",
                "cidr": "192.0.2.0/024",
                "availability_monitoring": True,
            },
            "availability cidr must be canonical",
        ),
        (
            {
                "id": "dotted-netmask",
                "cidr": "192.0.2.0/255.255.255.0",
                "availability_monitoring": True,
            },
            "availability cidr must be canonical",
        ),
        (
            {
                "id": "leading-whitespace",
                "cidr": " 192.0.2.0/24",
                "availability_monitoring": True,
            },
            "availability cidr must be canonical",
        ),
        (
            {
                "id": "trailing-whitespace",
                "cidr": "192.0.2.0/24 ",
                "availability_monitoring": True,
            },
            "availability cidr must be canonical",
        ),
        (
            {
                "id": "too-broad",
                "cidr": "192.0.2.0/23",
                "availability_monitoring": True,
            },
            "availability cidr must be at least /24",
        ),
    ],
)
def test_invalid_availability_segment_fails_closed(segment, reason, tmp_path):
    from netctl.context_classifier import load_active_availability_segments
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(conn, [segment])

        with pytest.raises(ValueError, match=reason):
            load_active_availability_segments(conn)
    finally:
        conn.close()


@pytest.mark.parametrize(
    "segments",
    [
        [
            {"id": "duplicate-a", "cidr": "192.0.2.0/24", "availability_monitoring": True},
            {"id": "duplicate-b", "cidr": "192.0.2.0/24", "availability_monitoring": True},
        ],
        [
            {"id": "overlap-a", "cidr": "192.0.2.0/24", "availability_monitoring": True},
            {"id": "overlap-b", "cidr": "192.0.2.0/25", "availability_monitoring": True},
        ],
    ],
)
def test_ambiguous_duplicate_or_overlapping_availability_scopes_fail_closed(tmp_path, segments):
    """Multiple policies for one target make the authorized probe scope ambiguous."""
    from netctl.context_classifier import load_active_availability_segments
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(conn, segments)
        with pytest.raises(ValueError, match="availability cidrs must not overlap"):
            load_active_availability_segments(conn)
    finally:
        conn.close()


def test_availability_target_limit_is_checked_without_expanding_addresses(tmp_path):
    """Many individually safe networks must be rejected before their host iterators are materialized."""
    from netctl.context_classifier import load_active_availability_segments
    from netctl.db import connect

    conn = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    try:
        _activate_segments(
            conn,
            [
                {
                    "id": f"segment-{index}",
                    "cidr": f"10.{index}.0.0/24",
                    "availability_monitoring": True,
                }
                for index in range(17)
            ],
        )
        with pytest.raises(ValueError, match="availability target limit 4096"):
            load_active_availability_segments(conn)
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
