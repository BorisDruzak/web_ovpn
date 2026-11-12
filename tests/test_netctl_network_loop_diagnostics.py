from contextlib import closing
from datetime import UTC, datetime

import pytest

from netctl.db import connect, connect_read_only

NOW = datetime(2026, 11, 12, 12, 30, tzinfo=UTC)
MAC = "00:11:22:33:44:55"
PORT_A = "ifindex:1"
PORT_B = "ifindex:2"


def read(conn, source=None):
    from netctl.network_loop_diagnostics import read_loop_diagnostics

    return read_loop_diagnostics(conn, source, now=NOW)


@pytest.fixture
def database(tmp_path):
    url = f"sqlite:///{(tmp_path / 'runtime.sqlite').as_posix()}"
    with closing(connect(url)) as conn:
        yield conn, url


def add_source(conn, source_id, name, *, driver="snmp_switch", enabled=True):
    conn.execute(
        """
        INSERT INTO network_sources
            (id, name, driver, host, port, username, secret_ref, site, enabled, created_at, updated_at)
        VALUES (?, ?, ?, '127.0.0.1', 1, '', '', 'test-site', ?, '', '')
        """,
        (source_id, name, driver, int(enabled)),
    )


def add_collection(conn, source_id, at, *, status="success"):
    return conn.execute(
        "INSERT INTO switch_collection_runs (source_id, started_at, status) VALUES (?, ?, ?)",
        (source_id, at, status),
    ).lastrowid


def add_event(conn, source_id, at, old, new, *, vlan=20, event_type="moved"):
    run = add_collection(conn, source_id, at)
    conn.execute(
        """
        INSERT INTO switch_fdb_events
            (source_id, vlan_key, vlan_id, mac, event_type, old_port_key, new_port_key, observed_at, collector_run_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (source_id, f"vid:{vlan}" if vlan else "legacy:unknown", vlan, MAC, event_type, old, new, at, run),
    )


def add_stp_sample(conn, source_id, at, counter):
    conn.execute(
        """
        INSERT INTO current_switch_stp_state
            (source_id, protocol, root_bridge_mac, root_port_key, root_path_cost, topology_changes, observed_at)
        VALUES (?, 'rstp', '00:00:00:00:00:AA', 'ifindex:10', 10, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET topology_changes = excluded.topology_changes,
            observed_at = excluded.observed_at
        """,
        (source_id, counter, at),
    )


def test_reversal_and_stp_change_report_suspected_loop_using_read_only_connection(database):
    conn, url = database
    add_source(conn, 1, "switch")
    add_event(conn, 1, "2026-11-12T12:05:00Z", PORT_A, PORT_B)
    add_event(conn, 1, "2026-11-12T12:10:00Z", PORT_B, PORT_A)
    add_stp_sample(conn, 1, "2026-11-12T12:05:00Z", 5)
    add_stp_sample(conn, 1, "2026-11-12T12:10:00Z", 7)
    conn.commit()

    with closing(connect_read_only(url)) as read_conn:
        result = read(read_conn, "switch")

    assert result["status"] == "suspected_loop"
    [switch] = result["sources"]
    assert switch["source"] == "switch"
    assert switch["status"] == "suspected_loop"
    assert switch["coverage"]["broadcast"]["status"] == "unavailable"
    [evidence] = switch["evidence"]
    assert evidence["mac"] == MAC
    assert evidence["vlan_id"] == 20
    assert evidence["ports"] == [PORT_A, PORT_B]
    assert [evidence["first_observed_at"], evidence["last_observed_at"]] == [
        "2026-11-12T12:05:00Z", "2026-11-12T12:10:00Z",
    ]
    assert [(move["old_port_key"], move["new_port_key"]) for move in evidence["moves"]] == [
        (PORT_A, PORT_B), (PORT_B, PORT_A),
    ]
    [stp] = evidence["stp_events"]
    assert stp["changes_delta"] == 2


@pytest.mark.parametrize(
    ("previous_at", "change_at", "counter"),
    [
        ("2026-11-12T12:05:00Z", "2026-11-12T12:10:00Z", 2),
        ("2026-11-12T12:22:00Z", "2026-11-12T12:30:00Z", 7),
        ("2026-11-12T11:50:00Z", "2026-11-12T12:10:00Z", 7),
    ],
)
def test_stp_reset_distant_change_or_wide_observation_gap_does_not_strengthen_reversal(
    database, previous_at, change_at, counter,
):
    conn, _ = database
    add_source(conn, 1, "switch")
    add_event(conn, 1, "2026-11-12T12:05:00Z", PORT_A, PORT_B)
    add_event(conn, 1, "2026-11-12T12:10:00Z", PORT_B, PORT_A)
    add_stp_sample(conn, 1, previous_at, 5)
    add_stp_sample(conn, 1, change_at, counter)

    result = read(conn)

    assert result["status"] == "mac_flapping"
    [evidence] = result["sources"][0]["evidence"]
    assert evidence["stp_events"] == []


def test_moves_across_sources_vlans_or_a_disappearance_do_not_form_a_reversal(database):
    conn, _ = database
    add_source(conn, 1, "switch-a")
    add_source(conn, 2, "switch-b")
    add_source(conn, 3, "router", driver="mikrotik_ssh")
    add_source(conn, 4, "disabled", enabled=False)
    add_event(conn, 1, "2026-11-12T12:05:00Z", PORT_A, PORT_B)
    add_event(conn, 1, "2026-11-12T12:06:00Z", PORT_B, PORT_A, vlan=30)
    add_event(conn, 2, "2026-11-12T12:07:00Z", PORT_B, PORT_A)
    add_event(conn, 1, "2026-11-12T12:08:00Z", PORT_B, "", event_type="disappeared")
    add_event(conn, 1, "2026-11-12T12:09:00Z", "", PORT_B, event_type="appeared")
    add_event(conn, 1, "2026-11-12T12:10:00Z", PORT_B, PORT_A)
    add_stp_sample(conn, 1, "2026-11-12T12:10:00Z", 5)

    result = read(conn)

    assert [(item["source"], item["status"], item["evidence"]) for item in result["sources"]] == [
        ("switch-a", "no_evidence", []),
        ("switch-b", "insufficient_data", []),
    ]
    assert read(conn, "router")["status"] == "no_sources"
    assert read(conn, "disabled")["sources"] == []


def test_old_future_slow_and_vlan_unmapped_moves_do_not_form_a_reversal(database):
    conn, _ = database
    add_source(conn, 1, "switch")
    add_event(conn, 1, "2026-11-12T11:29:00Z", PORT_A, PORT_B)
    add_event(conn, 1, "2026-11-12T11:31:00Z", PORT_B, PORT_A)
    add_event(conn, 1, "2026-11-12T12:00:00Z", PORT_A, PORT_B)
    add_event(conn, 1, "2026-11-12T12:31:00Z", PORT_B, PORT_A)
    add_event(conn, 1, "2026-11-12T12:10:00Z", PORT_A, PORT_B, vlan=None)
    add_event(conn, 1, "2026-11-12T12:15:00Z", PORT_B, PORT_A, vlan=None)
    add_stp_sample(conn, 1, "2026-11-12T12:30:00Z", 5)

    result = read(conn)

    [switch] = result["sources"]
    assert switch["evidence"] == []
    assert switch["coverage"]["fdb"]["unmapped_moves"] == 2
    assert switch["coverage"]["fdb"]["last_observed_at"] == "2026-11-12T12:15:00Z"


def test_missing_stp_or_failed_fdb_poll_is_insufficient_data(database):
    conn, _ = database
    add_source(conn, 1, "switch")
    add_event(conn, 1, "2026-11-12T12:05:00Z", PORT_A, PORT_B)
    add_collection(conn, 1, "2026-11-12T12:25:00Z", status="failed")

    result = read(conn)

    assert result["status"] == "insufficient_data"
    [switch] = result["sources"]
    assert switch["coverage"]["fdb"]["status"] == "insufficient"
    assert switch["coverage"]["fdb"]["last_observed_at"] == "2026-11-12T12:05:00Z"
    assert switch["coverage"]["stp"]["status"] == "unavailable"


def test_saved_switch_state_reports_stale_coverage_after_history_has_aged_out(database):
    conn, _ = database
    add_source(conn, 1, "switch")
    at = "2026-11-12T09:00:00Z"
    conn.execute(
        "INSERT INTO switch_devices (source_id, last_success_at, updated_at) VALUES (1, ?, ?)",
        (at, at),
    )
    add_stp_sample(conn, 1, at, 5)

    result = read(conn)

    assert result["status"] == "insufficient_data"
    coverage = result["sources"][0]["coverage"]
    for signal in ("fdb", "stp"):
        assert coverage[signal]["status"] == "stale"
        assert coverage[signal]["last_observed_at"] == at


def test_event_limit_surfaces_incomplete_scan(database, monkeypatch):
    from netctl import network_loop_diagnostics

    monkeypatch.setattr(network_loop_diagnostics, "MAX_FDB_EVENTS", 2)
    conn, _ = database
    add_source(conn, 1, "switch")
    add_event(conn, 1, "2026-11-12T12:00:00Z", PORT_A, PORT_B)
    add_event(conn, 1, "2026-11-12T12:05:00Z", PORT_B, PORT_A)
    add_event(conn, 1, "2026-11-12T12:10:00Z", PORT_A, "ifindex:3")
    add_stp_sample(conn, 1, "2026-11-12T12:10:00Z", 5)

    result = read(conn)

    assert result["status"] == "insufficient_data"
    assert result["truncated"] is True
    [switch] = result["sources"]
    assert switch["truncated"] is True
    assert switch["coverage"]["fdb"]["events_read"] == 2
    assert switch["coverage"]["fdb"]["truncated"] is True
