from __future__ import annotations

import sqlite3

import pytest


OLD = "2026-06-01T00:00:00Z"
CUTOFF = "2026-06-26T00:00:00Z"
NEW = "2026-07-01T00:00:00Z"


@pytest.fixture
def conn(tmp_path):
    from netctl.db import connect

    connection = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    connection.execute(
        """INSERT INTO network_sources
           (id, name, driver, host, port, username, secret_ref, tls, verify_tls,
            created_at, updated_at)
           VALUES (1, 'switch-a', 'snmp_switch', '192.0.2.1', 161, '', '', 0, 0, ?, ?)""",
        (OLD, OLD),
    )
    connection.execute(
        """INSERT INTO assets
           (asset_key, identity_method, identity_confidence, provisional,
            first_seen_at, last_seen_at, created_at, updated_at)
           VALUES ('mac:001122334455', 'mac_seed', 100, 0, ?, ?, ?, ?)""",
        (OLD, NEW, OLD, NEW),
    )
    connection.execute(
        """INSERT INTO asset_interfaces
           (asset_id, interface_key, mac, first_seen_at, last_seen_at)
           VALUES (1, 'mac:001122334455', '00:11:22:33:44:55', ?, ?)""",
        (OLD, NEW),
    )
    connection.execute(
        "INSERT INTO network_hosts (id, ip) VALUES (1, '192.0.2.2')"
    )
    connection.executemany(
        """INSERT INTO collection_runs (id, source_id, started_at, finished_at, status)
           VALUES (?, 1, ?, ?, ?)""",
        [(1, OLD, OLD, 'ok'), (2, OLD, OLD, 'failed'), (3, NEW, NEW, 'failed')],
    )
    connection.executemany(
        """INSERT INTO switch_collection_runs
           (id, source_id, started_at, finished_at, status)
           VALUES (?, 1, ?, ?, ?)""",
        [(10, OLD, OLD, 'success'), (11, OLD, OLD, 'failed'), (12, NEW, NEW, 'failed')],
    )
    connection.execute(
        """INSERT INTO switch_ports (source_id, port_key, last_seen_at, collector_run_id)
           VALUES (1, 'ether1', ?, 12)""",
        (NEW,),
    )
    connection.execute(
        """INSERT INTO current_switch_fdb
           (source_id, vlan_key, mac, port_key, first_seen_at, last_seen_at, collector_run_id)
           VALUES (1, '1', '00:11:22:33:44:55', 'ether1', ?, ?, 12)""",
        (OLD, NEW),
    )
    connection.executemany(
        """INSERT INTO network_correlation_runs
           (id, run_type, started_at, finished_at, status)
           VALUES (?, ?, ?, ?, 'success')""",
        [(20, 'topology', OLD, OLD), (21, 'attachments', OLD, OLD),
         (22, 'topology', NEW, NEW), (23, 'attachments', NEW, NEW)],
    )
    connection.execute(
        """INSERT INTO asset_attachment_resolutions
           (asset_interface_id, asset_id, status, confidence, first_seen_at, last_seen_at,
            correlation_run_id)
           VALUES (1, 1, 'confirmed', 100, ?, ?, 23)""",
        (OLD, NEW),
    )
    connection.execute(
        """INSERT INTO asset_attachment_candidates
           (asset_interface_id, asset_id, switch_source_id, port_key, vlan_key,
            candidate_class, score, observed_at, correlation_run_id)
           VALUES (1, 1, 1, 'ether1', '1', 'direct', 100, ?, 23)""",
        (NEW,),
    )
    connection.executemany(
        "INSERT INTO host_observations (host_id, source_id, observed_at, observation_type) VALUES (1, 1, ?, 'arp')",
        [(OLD,), (OLD,), (NEW,)],
    )
    connection.execute(
        """INSERT INTO network_events (ts, source_id, host_id, severity, event_type, message)
           VALUES (?, 1, 1, 'info', 'test', 'old')""",
        (OLD,),
    )
    connection.execute(
        """INSERT INTO ip_observations
           (asset_id, source_key, ip, first_seen_at, last_seen_at, is_current, observation_source)
           VALUES (1, 'fixture', '192.0.2.2', ?, ?, 0, 'collector_host')""",
        (OLD, OLD),
    )
    connection.execute(
        """INSERT INTO hostname_observations
           (asset_id, hostname, source_key, source_type, first_seen_at, last_seen_at, is_current)
           VALUES (1, 'old-host', 'fixture', 'collector_host', ?, ?, 0)""",
        (OLD, OLD),
    )
    connection.execute(
        """INSERT INTO switch_fdb_events
           (source_id, vlan_key, mac, event_type, observed_at, collector_run_id)
           VALUES (1, '1', '00:11:22:33:44:55', 'appeared', ?, 10)""",
        (OLD,),
    )
    connection.execute(
        """INSERT INTO switch_link_events
           (link_key, event_type, observed_at, correlation_run_id)
           VALUES ('old-link', 'appeared', ?, 20)""",
        (OLD,),
    )
    connection.execute(
        """INSERT INTO asset_attachment_events
           (asset_interface_id, asset_id, event_type, observed_at, correlation_run_id)
           VALUES (1, 1, 'attached', ?, 21)""",
        (OLD,),
    )
    connection.executemany(
        """INSERT INTO router_path_fact_runs (id, source_id, started_at, finished_at, status)
           VALUES (?, 1, ?, ?, 'success')""",
        [(30, OLD, OLD), (31, NEW, NEW)],
    )
    connection.execute(
        """INSERT INTO router_routing_rules
           (source_id, rule_key, position, observed_at, collector_run_id)
           VALUES (1, 'rule-a', 0, ?, 31)""",
        (NEW,),
    )
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def ids(conn: sqlite3.Connection, table: str) -> set[int]:
    return {int(row[0]) for row in conn.execute(f"SELECT id FROM {table}")}


def test_retention_dry_run_counts_candidates_without_writes(conn):
    """Deleting during dry-run would make the safety preview destructive."""
    from netctl.retention import retention_report

    report = retention_report(conn, CUTOFF)

    assert report["delete"]["host_observations"] == 2
    assert report["delete"]["switch_fdb_events"] == 1
    assert report["delete"]["asset_attachment_events"] == 1
    assert report["delete"]["collection_runs"] == 1
    assert report["keep"]["switch_collection_runs_current_reference"] == 1
    assert report["keep"]["switch_collection_runs_last_success"] == 1
    assert conn.execute("SELECT count(*) FROM host_observations").fetchone()[0] == 3


def test_retention_apply_removes_expired_rows_but_keeps_current_and_last_success(conn):
    """Removing protected run IDs would violate current state foreign keys and recovery history."""
    from netctl.retention import apply_retention

    result = apply_retention(conn, CUTOFF)

    assert result["deleted"]["switch_fdb_events"] == 1
    assert result["deleted"]["asset_attachment_events"] == 1
    assert ids(conn, "collection_runs") == {1, 3}
    assert ids(conn, "switch_collection_runs") == {10, 12}
    assert ids(conn, "network_correlation_runs") == {22, 23}
    assert ids(conn, "router_path_fact_runs") == {31}
    assert apply_retention(conn, CUTOFF)["total_deleted"] == 0


def test_retention_rolls_back_all_deletes_when_the_second_delete_fails(conn):
    """Committing each family separately would leave FDB events deleted after a later failure."""
    from netctl.retention import apply_retention

    before = {
        table: ids(conn, table)
        for table in ("switch_fdb_events", "switch_link_events", "asset_attachment_events", "host_observations")
    }
    conn.execute(
        """CREATE TRIGGER fixture_abort_retention_link_delete
           BEFORE DELETE ON switch_link_events
           BEGIN SELECT RAISE(ABORT, 'fixture abort'); END"""
    )

    with pytest.raises(sqlite3.DatabaseError, match="fixture abort"):
        apply_retention(conn, CUTOFF)

    assert {table: ids(conn, table) for table in before} == before


def test_retention_rejects_naive_or_invalid_cutoff(conn):
    """Accepting local or malformed timestamps would prune an indeterminate date range."""
    from netctl.retention import retention_report

    with pytest.raises(ValueError, match="UTC"):
        retention_report(conn, "2026-06-26T00:00:00")
    with pytest.raises(ValueError, match="cutoff"):
        retention_report(conn, "not-a-time")
