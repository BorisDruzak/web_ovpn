from contextlib import closing
from datetime import UTC, datetime
from subprocess import CompletedProcess

from netctl.db import connect
from netctl.network_diagnostics import read_diagnostics
from netctl.store import save_collection


def seed_source(conn, source_id, name, driver):
    conn.execute(
        """INSERT INTO network_sources
           (id, name, driver, host, port, username, secret_ref, site, created_at, updated_at)
           VALUES (?, ?, ?, '127.0.0.1', 1, '', '', '', '', '')""",
        (source_id, name, driver),
    )
    conn.commit()
    return {"id": source_id, "name": name, "driver": driver, "site": ""}


def test_router_history_uses_valid_deltas_and_leaves_a_gap_after_reset(tmp_path, monkeypatch):
    from netctl import store

    with closing(connect(f"sqlite:///{(tmp_path / 'runtime.sqlite').as_posix()}")) as conn:
        source = seed_source(conn, 1, "router", "mikrotik_api")
        for minute, rx, tx in [(0, 100, 200), (5, 400, 800), (10, 30, 50), (15, None, 60)]:
            observed_at = f"2026-11-12T12:{minute:02}:00Z"
            monkeypatch.setattr(store, "utc_now", lambda: observed_at)
            save_collection(conn, source, {"interfaces": [{
                "name": "wan", "type": "ether", "running": True,
                "rx_bytes": rx, "tx_bytes": tx,
            }]}, observed_at)
        result = read_diagnostics(conn, "router", "wan", now=datetime(2026, 11, 12, 12, 16, tzinfo=UTC))

    assert result["interfaces"][0]["key"] == "wan"
    assert [(point["rx_bps"], point["tx_bps"]) for point in result["points"]] == [
        (None, None), (8, 16), (None, None), (None, None),
    ]


def test_switch_history_derives_errors_and_records_only_stp_changes(tmp_path):
    with closing(connect(f"sqlite:///{(tmp_path / 'runtime.sqlite').as_posix()}")) as conn:
        seed_source(conn, 1, "switch", "snmp_switch")
        for run, minute, errors, topology in [(1, 0, 3, 7), (2, 5, 5, 7), (3, 10, 5, 9)]:
            at = f"2026-11-12T12:{minute:02}:00Z"
            conn.execute(
                """INSERT INTO switch_collection_runs (id, source_id, started_at, status)
                   VALUES (?, 1, ?, 'success')""", (run, at),
            )
            conn.execute(
                """INSERT INTO switch_port_counter_samples
                   (source_id, collector_run_id, port_key, if_index, observed_at,
                    sys_uptime_ticks, octet_counter_bits, in_octets, out_octets, in_errors, speed_bps)
                   VALUES (1, ?, 'ifindex:2', 2, ?, ?, 64, ?, ?, ?, ?)""",
                (run, at, 100_000 + minute * 6000, str(minute * 3_750_000_000),
                 str(minute * 750_000_000), errors, 1_000_000_000 if run < 3 else 100_000_000),
            )
            conn.execute(
                """INSERT INTO current_switch_stp_state VALUES
                   (1, 'rstp', '00:11:22:33:44:55', 'ifindex:2', 10, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET topology_changes=excluded.topology_changes,
                   observed_at=excluded.observed_at""", (topology, at),
            )
        conn.execute(
            """INSERT INTO switch_ports (source_id, port_key, name, speed_bps, last_seen_at, collector_run_id)
               VALUES (1, 'ifindex:2', 'uplink', 100000000, '2026-11-12T12:10:00Z', 3)""",
        )
        result = read_diagnostics(conn, "switch", "ifindex:2", now=datetime(2026, 11, 12, 12, 11, tzinfo=UTC))

    assert result["points"][1]["in_errors_delta"] == 2
    assert result["points"][1]["rx_bps"] == 500_000_000
    assert [event["event_type"] for event in result["stp_events"]] == ["changed", "observed"]
    assert result["stp_events"][0]["changes_delta"] == 2


def test_routeros_ssh_reads_structured_counters_with_full_interface_name(monkeypatch):
    from netctl.drivers import mikrotik_ssh

    def run(command, **kwargs):
        output = {
            "/interface print terse": "0 R name=ether1-wan type=ether",
            mikrotik_ssh.INTERFACE_COUNTER_COMMAND: "ether1-wan|12345|8000|30|20",
        }.get(command[-1], "")
        return CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(mikrotik_ssh.subprocess, "run", run)
    driver = mikrotik_ssh.MikroTikSshDriver({"host": "127.0.0.1", "username": "observer"}, {})
    [port] = driver.collect()["interfaces"]

    assert (port["name"], port["type"], port["rx_bytes"], port["tx_bytes"]) == ("ether1-wan", "ether", 12345, 8000)
