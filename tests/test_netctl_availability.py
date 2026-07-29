from __future__ import annotations

import errno
import json

import pytest


OLD = "2026-06-01T00:00:00Z"
NEW = "2026-07-01T00:00:00Z"
NOW = "2026-07-29T12:00:00Z"


def _projection_segment(conn, cidr: str = "203.0.113.0/24") -> None:
    """Add one approved monitored segment without changing collector fixtures."""
    revision = conn.execute("SELECT id FROM context_revisions WHERE context_id = 'availability-test'").fetchone()[0]
    conn.execute(
        """INSERT INTO intent_segments
           (context_revision_id, stable_id, lifecycle, canonical_json, canonical_hash, origin_context_revision_id)
           VALUES (?, 'projection', 'active', ?, 'projection-hash', ?)""",
        (revision, json.dumps({"id": "projection", "cidr": cidr, "availability_monitoring": True}, sort_keys=True), revision),
    )


def _projection_host(conn, *, ip: str = "203.0.113.8", mac: str | None = None, status: str = "online") -> dict:
    conn.execute(
        """INSERT INTO network_hosts
           (ip, mac, category, status, first_seen_at, last_seen_at, last_source, tags_json)
           VALUES (?, ?, 'unknown', ?, ?, ?, 'test', '{}')""",
        (ip, mac, status, NOW, NOW),
    )
    return dict(conn.execute("SELECT * FROM network_hosts WHERE ip = ?", (ip,)).fetchone())


def _negative_projection_run(conn, ip: str = "203.0.113.8") -> None:
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    _projection_segment(conn)
    conn.commit()
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "203.0.113.0/24", started=NOW, finished=NOW,
            results=[AvailabilityResult(ip, "unreachable", None)],
            target_count=1,
        ),
    )


def _fresh_passive(conn, source: str, *, ip: str, mac: str) -> int:
    source_id = conn.execute(
        """INSERT INTO network_sources
           (name, driver, host, port, username, secret_ref, enabled, created_at, updated_at,
            last_collect_at, last_status)
           VALUES (?, ?, '192.0.2.254', ?, '', '', 1, ?, ?, ?, ?)""",
        (
            f"{source}-projection",
            "snmp_switch" if source == "snmp_fdb" else "mikrotik_api",
            161 if source == "snmp_fdb" else 8729,
            NOW,
            NOW,
            NOW,
            "success" if source == "snmp_fdb" else "ok",
        ),
    ).lastrowid
    if source == "mikrotik_arp":
        conn.execute(
            "INSERT INTO arp_entries (source_id, ip, mac, complete, last_seen_at) VALUES (?, ?, ?, 1, ?)",
            (source_id, ip, mac, NOW),
        )
    elif source == "mikrotik_dhcp":
        conn.execute(
            "INSERT INTO dhcp_leases (source_id, ip, mac, status, last_seen_at) VALUES (?, ?, ?, 'bound', ?)",
            (source_id, ip, mac, NOW),
        )
    elif source == "mikrotik_bridge":
        conn.execute(
            """INSERT INTO bridge_hosts (source_id, mac, bridge, interface, last_seen_at)
               VALUES (?, ?, 'bridge', 'ether2', ?)""",
            (source_id, mac, NOW),
        )
    elif source == "snmp_fdb":
        run_id = conn.execute(
            """INSERT INTO switch_collection_runs (source_id, started_at, finished_at, status, outcomes_json)
               VALUES (?, ?, ?, 'success', '{}')""",
            (source_id, NOW, NOW),
        ).lastrowid
        conn.execute(
            """INSERT INTO current_switch_fdb
               (source_id, vlan_key, mac, port_key, status, first_seen_at, last_seen_at, collector_run_id)
               VALUES (?, '1', ?, 'physical:1', 'learned', ?, ?, ?)""",
            (source_id, mac, NOW, NOW, run_id),
        )
    else:
        raise AssertionError(source)
    return int(source_id)


def test_complete_arp_without_mac_is_not_online_or_seen(conn):
    """Treating a complete empty-MAC ARP row as passive evidence would revive false online hosts."""
    from netctl.availability import project_host_availability

    host = _projection_host(conn)
    _negative_projection_run(conn, host["ip"])
    conn.execute("INSERT INTO arp_entries (ip, mac, complete, last_seen_at) VALUES (?, '', 1, ?)", (host["ip"], NOW))

    assert project_host_availability(conn, host, now=NOW)["status"] == "offline"


@pytest.mark.parametrize("passive_source", ("mikrotik_arp", "mikrotik_dhcp", "mikrotik_bridge", "snmp_fdb"))
def test_fresh_valid_mac_passive_evidence_yields_seen_after_negative_probe(conn, passive_source):
    """Dropping any approved fresh passive source would hide a currently observed device."""
    from netctl.availability import project_host_availability

    host = _projection_host(conn, mac="AA:BB:CC:DD:EE:08")
    _negative_projection_run(conn, host["ip"])
    _fresh_passive(conn, passive_source, ip=host["ip"], mac=host["mac"])

    availability = project_host_availability(conn, host, now=NOW)

    assert availability["status"] == "seen"
    assert availability["availability"]["passive_evidence"] == [passive_source]


@pytest.mark.parametrize("passive_source", ("mikrotik_arp", "mikrotik_dhcp", "mikrotik_bridge", "snmp_fdb"))
@pytest.mark.parametrize("unhealthy_state", ("failed", "stale"))
def test_unhealthy_passive_source_cannot_yield_seen(conn, passive_source, unhealthy_state):
    """A fresh row cannot substitute for the current source collection being healthy and fresh."""
    from netctl.availability import project_host_availability

    host = _projection_host(conn, mac="AA:BB:CC:DD:EE:08")
    _negative_projection_run(conn, host["ip"])
    source_id = _fresh_passive(conn, passive_source, ip=host["ip"], mac=host["mac"])
    if unhealthy_state == "failed":
        conn.execute("UPDATE network_sources SET last_status = 'error' WHERE id = ?", (source_id,))
    else:
        conn.execute("UPDATE network_sources SET last_collect_at = ? WHERE id = ?", (OLD, source_id))

    projected = project_host_availability(conn, host, now=NOW)

    assert projected["status"] == "offline"
    assert projected["availability"]["passive_evidence"] == []


def test_missing_or_failed_current_run_is_stale_not_offline(conn):
    """Classifying missing or failed scans as offline would mistake collector failure for endpoint failure."""
    from netctl.availability import AvailabilityRun, project_host_availability, save_availability_run

    host = _projection_host(conn)
    _projection_segment(conn)
    conn.commit()
    assert project_host_availability(conn, host, now=NOW)["status"] == "stale"

    save_availability_run(conn, AvailabilityRun.failed("203.0.113.0/24", started=NOW, finished=NOW, error_class="deadline_exceeded"))
    assert project_host_availability(conn, host, now=NOW)["status"] == "stale"


def test_live_openvpn_connection_precedes_nonmonitored_cidr_eligibility(conn):
    """Checking CIDR first would hide a live tunnel endpoint outside active monitoring."""
    from netctl.availability import project_host_availability

    host = _projection_host(conn, ip="203.0.113.8", status="seen")
    host["openvpn_connected"] = True

    projected = project_host_availability(conn, host, now=NOW)

    assert projected["status"] == "connected"
    assert projected["availability"] is None


def test_historical_connected_status_does_not_substitute_for_live_openvpn_marker(conn):
    """A persisted connected label is historical metadata, not current OpenVPN management evidence."""
    from netctl.availability import project_host_availability

    host = _projection_host(conn, status="connected")
    _projection_segment(conn)
    conn.commit()

    assert project_host_availability(conn, host, now=NOW)["status"] == "stale"


def test_nonmonitored_historical_connected_status_is_not_projected_as_live_connection(conn):
    """Passing through a stored connected label would fabricate a live tunnel outside monitoring."""
    from netctl.availability import project_host_availability

    host = _projection_host(conn, ip="203.0.113.8", status="connected")

    projected = project_host_availability(conn, host, now=NOW)

    assert projected["status"] == "seen"
    assert projected["availability"] is None


def availability_segment(cidr: str, *, ports: tuple[int, ...] = ()):
    """Build literal canonical-policy input for collector behavior tests."""
    from ipaddress import ip_network
    from netctl.context_classifier import SegmentRule

    return SegmentRule("availability-test", ip_network(cidr), "unknown", "", True, ports)


class FakeExecutor:
    """External probe boundary only; collector and storage stay real."""

    def __init__(self, *, icmp=None, tcp=None, clock=None):
        self.icmp = icmp or {}
        self.tcp = tcp or {}
        self.calls = []
        self.now = clock or (lambda: 0.0)

    def ping(self, ip):
        self.calls.append(("icmp", ip))
        return self.icmp.get(ip, False)

    def connect(self, ip, port):
        self.calls.append(("tcp", ip, port))
        return self.tcp.get((ip, port), False)


def test_target_expansion_deduplicates_overlap_and_excludes_ipv4_network_and_broadcast():
    """Using the broad policy for an overlap would probe TCP ports not authorized for that host."""
    from netctl.availability import expand_targets

    targets = expand_targets((
        availability_segment("192.0.2.0/30", ports=(443,)),
        availability_segment("192.0.2.2/31", ports=(22,)),
    ))

    assert [(target.ip, target.tcp_ports) for target in targets] == [
        ("192.0.2.1", (443,)),
        ("192.0.2.2", (22,)),
        ("192.0.2.3", (22,)),
    ]


def test_tcp_is_attempted_only_after_icmp_failure_and_first_success_wins():
    """Trying TCP before ICMP or after a success would violate the bounded probe policy."""
    from netctl.availability import ProbeTarget, probe_target

    executor = FakeExecutor(
        icmp={"192.0.2.1": False},
        tcp={("192.0.2.1", 22): False, ("192.0.2.1", 443): True},
    )

    result = probe_target(ProbeTarget("192.0.2.1", (22, 443), "192.0.2.0/30"), executor)

    assert result.active_method == "tcp:443"
    assert executor.calls == [
        ("icmp", "192.0.2.1"),
        ("tcp", "192.0.2.1", 22),
        ("tcp", "192.0.2.1", 443),
    ]


def test_subprocess_ping_uses_fixed_numeric_argv_without_a_shell(monkeypatch):
    """Interpolating the address into a shell command would turn a probe into command execution."""
    import subprocess
    from netctl.availability import SubprocessPing

    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert SubprocessPing()("192.0.2.1") is True
    assert calls == [
        (["ping", "-n", "-c", "1", "-W", "1", "192.0.2.1"],
         {"shell": False, "capture_output": True, "text": True, "timeout": 2, "check": False})
    ]


def test_subprocess_ping_preserves_negative_reply_but_rejects_infrastructure_failure(monkeypatch):
    """Only ping's documented no-reply exit may become an ordinary negative address result."""
    import subprocess
    from netctl.availability import SubprocessPing

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, stdout="", stderr=""),
    )
    assert SubprocessPing()("192.0.2.1") is False

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 2, stdout="", stderr="unusable"),
    )
    with pytest.raises(RuntimeError, match="ping_executor_error"):
        SubprocessPing()("192.0.2.1")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError("ping missing")),
    )
    with pytest.raises(OSError):
        SubprocessPing()("192.0.2.1")


@pytest.mark.parametrize(
    "negative_errno",
    (errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EHOSTUNREACH),
)
def test_socket_connector_preserves_allowlisted_target_negative(
    monkeypatch, negative_errno
):
    """A refused, timed-out, or host-unreachable target is an ordinary negative probe."""
    import socket
    from netctl.availability import SocketConnector

    class RefusedSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, timeout):
            assert timeout == 1

        def connect(self, address):
            assert address == ("192.0.2.1", 443)
            raise OSError(negative_errno, "negative target result")

    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: RefusedSocket())
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: RefusedSocket())
    assert SocketConnector()("192.0.2.1", 443) is False


def test_socket_connector_waits_for_a_bounded_tcp_connection(monkeypatch):
    """A non-blocking connect_ex can report EAGAIN before the TCP handshake finishes."""
    import socket
    from netctl.availability import SocketConnector

    calls = []

    class ConnectedSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, timeout):
            assert timeout == 1

        def connect(self, address):
            calls.append(address)

    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: ConnectedSocket())

    assert SocketConnector()("192.0.2.1", 443) is True
    assert calls == [("192.0.2.1", 443)]


def test_socket_connector_propagates_socket_lifecycle_oserror(monkeypatch):
    """Failing to allocate the probe socket is an executor failure."""
    import socket
    from netctl.availability import SocketConnector

    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("socket resources exhausted")),
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("socket resources exhausted")),
    )
    with pytest.raises(OSError):
        SocketConnector()("192.0.2.1", 443)


def test_socket_connector_rejects_infrastructure_errno(monkeypatch):
    """A local network failure must not be published as a negative target result."""
    import socket
    from netctl.availability import SocketConnector

    class InfrastructureFailureSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, timeout):
            assert timeout == 1

        def connect(self, address):
            assert address == ("192.0.2.1", 443)
            raise OSError(errno.ENETDOWN, "local network failure")

    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: InfrastructureFailureSocket(),
    )

    with pytest.raises(OSError) as exc_info:
        SocketConnector()("192.0.2.1", 443)

    assert exc_info.value.errno == errno.ENETDOWN


def test_bucket_never_constructs_more_than_64_worker_threads(monkeypatch):
    """Increasing worker capacity would make an approved /24 an unbounded load spike."""
    import concurrent.futures
    import netctl.availability as availability

    workers = []

    class RecordingPool:
        def __init__(self, *, max_workers):
            workers.append(max_workers)

        def submit(self, fn, *args):
            future = concurrent.futures.Future()
            future.set_result(fn(*args))
            return future

        def shutdown(self, **_kwargs):
            return None

    monkeypatch.setattr(availability, "ThreadPoolExecutor", RecordingPool)
    targets = tuple(
        availability.ProbeTarget(f"192.0.2.{index}", (), "192.0.2.0/24")
        for index in range(1, 66)
    )
    executor = availability.ProbeExecutor(lambda _ip: True, lambda _ip, _port: False, lambda: 0.0)

    _, error = availability._collect_bucket(targets, executor)

    assert error == ""
    assert workers == [64]


def test_deadline_failure_keeps_current_results_and_persists_no_partial_success(conn, monkeypatch):
    """A deadline after the first address must not replace the previous complete CIDR state."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, ProbeExecutor, collect_availability, current_availability_results, save_availability_run

    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=OLD, finished=OLD,
            results=[AvailabilityResult("192.0.2.1", "reachable", "icmp"), AvailabilityResult("192.0.2.2", "reachable", "icmp")],
        ),
    )
    clock_values = iter((0.0, 91.0))
    executor = ProbeExecutor(lambda _ip: True, lambda _ip, _port: True, lambda: next(clock_values, 91.0))

    collection = collect_availability(conn, executor, now=lambda: NEW)

    assert collection.status == "failed"
    assert collection.error_class == "deadline_exceeded"
    assert current_availability_results(conn, "192.0.2.0/30")["192.0.2.1"].state == "reachable"
    assert [tuple(row) for row in conn.execute("SELECT status FROM availability_runs ORDER BY id")] == [("success",), ("failed",)]


def test_socket_infrastructure_errno_fails_collection_without_replacing_current(conn, monkeypatch):
    """A local TCP failure must preserve the last complete current state."""
    import netctl.availability as availability

    conn.execute(
        "UPDATE intent_segments SET canonical_json = ? WHERE stable_id = 'availability-a'",
        (
            json.dumps(
                {
                    "id": "availability-a",
                    "cidr": "192.0.2.0/30",
                    "availability_monitoring": True,
                    "availability_tcp_ports": [443],
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        ),
    )
    conn.commit()
    availability.save_availability_run(
        conn,
        availability.AvailabilityRun.success(
            "192.0.2.0/30",
            started=OLD,
            finished=OLD,
            results=[
                availability.AvailabilityResult("192.0.2.1", "reachable", "icmp"),
                availability.AvailabilityResult("192.0.2.2", "reachable", "icmp"),
            ],
        ),
    )

    class InfrastructureFailureSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def connect(self, _address):
            raise OSError(errno.ENETDOWN, "local network failure")

    monkeypatch.setattr(
        availability.socket,
        "socket",
        lambda *_args, **_kwargs: InfrastructureFailureSocket(),
    )
    executor = availability.ProbeExecutor(
        lambda _ip: False,
        availability.SocketConnector(),
        lambda: 0.0,
    )

    collection = availability.collect_availability(conn, executor, now=lambda: NEW)

    assert collection.status == "failed"
    assert collection.error_class == "executor_error"
    assert {
        ip: (result.state, result.method)
        for ip, result in availability.current_availability_results(
            conn, "192.0.2.0/30"
        ).items()
    } == {
        "192.0.2.1": ("reachable", "icmp"),
        "192.0.2.2": ("reachable", "icmp"),
    }
    assert [
        tuple(row)
        for row in conn.execute(
            """SELECT status, error_class
               FROM availability_runs
               WHERE cidr = '192.0.2.0/30'
               ORDER BY id"""
        )
    ] == [("success", ""), ("failed", "executor_error")]


def test_second_cidr_persistence_failure_rolls_back_every_current_result(conn):
    """A later CIDR storage error must not leave the first CIDR published under a failed collection."""
    from netctl.availability import ProbeExecutor, collect_availability

    conn.execute(
        """
        CREATE TRIGGER reject_second_availability_result
        BEFORE INSERT ON availability_results
        WHEN NEW.cidr = '198.51.100.0/30'
        BEGIN SELECT RAISE(ABORT, 'second cidr persistence failure'); END
        """
    )
    executor = ProbeExecutor(lambda _ip: True, lambda _ip, _port: False, lambda: 0.0)

    collection = collect_availability(conn, executor, now=lambda: NEW)

    assert collection.status == "failed"
    assert collection.error_class == "context_unavailable"
    assert [tuple(row) for row in conn.execute("SELECT cidr, ip FROM availability_results ORDER BY cidr, ip")] == []
    assert [tuple(row) for row in conn.execute("SELECT cidr, status FROM availability_runs ORDER BY id")] == [
        ("192.0.2.0/30", "failed"),
        ("198.51.100.0/30", "failed"),
    ]


def test_submit_failure_returns_sanitized_executor_error_and_persists_failed_run(conn, monkeypatch):
    """A pool submit error must fail closed instead of escaping through the recovery CLI."""
    import netctl.availability as availability

    class SubmitFailurePool:
        def __init__(self, *, max_workers):
            assert max_workers == 64

        def submit(self, *_args):
            raise OSError("internal pool detail")

        def shutdown(self, **_kwargs):
            return None

    monkeypatch.setattr(availability, "ThreadPoolExecutor", SubmitFailurePool)
    executor = availability.ProbeExecutor(lambda _ip: True, lambda _ip, _port: False, lambda: 0.0)

    collection = availability.collect_availability(conn, executor, now=lambda: NEW)

    assert collection.status == "failed"
    assert collection.error_class == "executor_error"
    assert collection.summary["completed"] == 0
    assert conn.execute("SELECT count(*) FROM availability_results").fetchone()[0] == 0
    assert [tuple(row) for row in conn.execute("SELECT status, error_class FROM availability_runs")] == [
        ("failed", "executor_error"),
    ]


def test_availability_collect_publishes_only_completed_canonical_targets(conn):
    """Publishing a result for a probe-only address would create unverified network inventory."""
    from netctl.availability import ProbeExecutor, collect_availability

    executor = FakeExecutor(icmp={"192.0.2.1": True, "192.0.2.2": False})
    collection = collect_availability(
        conn,
        ProbeExecutor(executor.ping, executor.connect, executor.now),
        now=lambda: NEW,
    )

    assert collection.status == "success"
    assert collection.summary == {"targets": 4, "completed": 4, "reachable": 1, "unreachable": 3}
    assert [tuple(row) for row in conn.execute(
        "SELECT ip, active_state FROM availability_results ORDER BY cidr, ip"
    )] == [
        ("192.0.2.1", "reachable"),
        ("192.0.2.2", "unreachable"),
        ("198.51.100.1", "unreachable"),
        ("198.51.100.2", "unreachable"),
    ]
    assert conn.execute("SELECT count(*) FROM network_hosts").fetchone()[0] == 0


def test_dashboard_includes_availability_counts_last_success_and_failure_health(conn, monkeypatch):
    """The dashboard must expose historical status and run health instead of only current hosts."""
    import netctl.store as store
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    _projection_host(conn, ip="192.0.2.1")
    _projection_host(conn, ip="198.51.100.1")
    conn.commit()
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30",
            started=NOW,
            finished=NOW,
            results=[
                AvailabilityResult("192.0.2.1", "unreachable", None),
                AvailabilityResult("192.0.2.2", "unreachable", None),
            ],
        ),
    )
    save_availability_run(
        conn,
        AvailabilityRun.failed(
            "198.51.100.0/30",
            started=NOW,
            finished=NOW,
            error_class="executor_error",
            target_count=2,
        ),
    )
    monkeypatch.setattr(store, "utc_now", lambda: NOW)

    dashboard = store.dashboard_summary(conn)

    assert dashboard["summary"]["offline"] == 1
    assert dashboard["summary"]["stale"] == 1
    assert dashboard["availability"] == {
        "failed_or_incomplete_count": 1,
        "last_successful_runs": [
            {
                "cidr": "192.0.2.0/30",
                "finished_at": NOW,
                "target_count": 2,
                "completed_target_count": 2,
            },
            {
                "cidr": "198.51.100.0/30",
                "finished_at": None,
                "target_count": 0,
                "completed_target_count": 0,
            },
        ],
    }


@pytest.fixture
def conn(tmp_path):
    from netctl.db import connect

    connection = connect(f"sqlite:///{(tmp_path / 'netctl.sqlite').as_posix()}")
    revision = connection.execute(
        """INSERT INTO context_revisions
           (context_id, schema_version, sha256, source_path, validated_at, git_sha,
            status, error_json, counts_json, validation_order)
           VALUES ('availability-test', '2.2.0', 'availability-sha', 'context.yaml',
                   ?, 'availability-git', 'ok', '[]', '{}', 1)""",
        (OLD,),
    ).lastrowid
    import_run = connection.execute(
        """INSERT INTO context_import_runs
           (context_id, context_revision_id, input_sha256, git_sha, source_path,
            started_at, finished_at, status, errors_json)
           VALUES ('availability-test', ?, 'availability-sha', 'availability-git',
                   'context.yaml', ?, ?, 'success_imported', '[]')""",
        (revision, OLD, OLD),
    ).lastrowid
    for segment_id, cidr in (("availability-a", "192.0.2.0/30"), ("availability-b", "198.51.100.0/30")):
        connection.execute(
            """INSERT INTO intent_segments
               (context_revision_id, stable_id, lifecycle, canonical_json,
                canonical_hash, origin_context_revision_id)
               VALUES (?, ?, 'active', ?, ?, ?)""",
            (
                revision,
                segment_id,
                json.dumps(
                    {"id": segment_id, "cidr": cidr, "availability_monitoring": True},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                f"hash-{segment_id}",
                revision,
            ),
        )
    connection.execute(
        """INSERT INTO context_heads
           (context_id, context_revision_id, activated_by_import_run_id, activated_at)
           VALUES ('availability-test', ?, ?, ?)""",
        (revision, import_run, OLD),
    )
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def test_successful_run_replaces_only_its_cidr_current_results(conn):
    """Replacing all current rows after a failed CIDR run would discard known availability."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, current_availability_results, save_availability_run

    first = AvailabilityRun.success(
        "192.0.2.0/30",
        started=OLD,
        finished=OLD,
        results=[
            AvailabilityResult("192.0.2.1", "reachable", "icmp"),
            AvailabilityResult("192.0.2.2", "unreachable", None),
        ],
    )
    save_availability_run(conn, first)
    save_availability_run(
        conn,
        AvailabilityRun.failed("192.0.2.0/30", started=NEW, error_class="deadline_exceeded"),
    )

    current = current_availability_results(conn, "192.0.2.0/30")
    assert current["192.0.2.1"].method == "icmp"
    assert current["192.0.2.2"].state == "unreachable"
    assert [tuple(row) for row in conn.execute("SELECT status FROM availability_runs ORDER BY id")] == [("success",), ("failed",)]


def test_successful_run_replaces_only_matching_cidr(conn):
    """A successful scan must not replace another CIDR's current result set."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, current_availability_results, save_availability_run

    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=OLD, finished=OLD,
            results=[AvailabilityResult("192.0.2.1", "reachable", "icmp"), AvailabilityResult("192.0.2.2", "reachable", "icmp")],
        ),
    )
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "198.51.100.0/30", started=OLD, finished=OLD,
            results=[AvailabilityResult("198.51.100.1", "unreachable", None), AvailabilityResult("198.51.100.2", "reachable", "tcp")],
        ),
    )
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=NEW, finished=NEW,
            results=[AvailabilityResult("192.0.2.1", "unreachable", None), AvailabilityResult("192.0.2.2", "reachable", "icmp")],
        ),
    )

    assert current_availability_results(conn, "192.0.2.0/30")["192.0.2.1"].state == "unreachable"
    assert current_availability_results(conn, "198.51.100.0/30")["198.51.100.1"].state == "unreachable"


def test_incomplete_success_rolls_back_run_results_and_events(conn):
    """Persisting an incomplete success would allow a partial scan to become current state."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    complete = AvailabilityRun.success(
        "192.0.2.0/30", started=OLD, finished=OLD,
        results=[AvailabilityResult("192.0.2.1", "reachable", "icmp"), AvailabilityResult("192.0.2.2", "reachable", "icmp")],
    )
    save_availability_run(conn, complete)
    incomplete = AvailabilityRun.success(
        "192.0.2.0/30", started=NEW, finished=NEW,
        results=[AvailabilityResult("192.0.2.1", "unreachable", None)],
        target_count=2,
    )

    with pytest.raises(ValueError, match="completed"):
        save_availability_run(conn, incomplete)

    assert [tuple(row) for row in conn.execute("SELECT id FROM availability_runs")] == [(1,)]
    assert [tuple(row) for row in conn.execute("SELECT ip, active_state FROM availability_results ORDER BY ip")] == [
        ("192.0.2.1", "reachable"),
        ("192.0.2.2", "reachable"),
    ]
    assert conn.execute("SELECT count(*) FROM availability_result_events").fetchone()[0] == 2


def test_unchanged_active_results_do_not_create_duplicate_change_events(conn):
    """Treating a new check timestamp as a state change would grow non-compact event history."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    results = [
        AvailabilityResult("192.0.2.1", "reachable", "icmp"),
        AvailabilityResult("192.0.2.2", "unreachable", None),
    ]
    save_availability_run(conn, AvailabilityRun.success("192.0.2.0/30", started=OLD, finished=OLD, results=results))
    save_availability_run(conn, AvailabilityRun.success("192.0.2.0/30", started=NEW, finished=NEW, results=results))

    assert conn.execute("SELECT count(*) FROM availability_result_events").fetchone()[0] == 2


def test_ipv6_cidr_is_rejected_before_active_segment_matching(conn):
    """An IPv6 run must not enter storage even if policy matching later changes."""
    from netctl.availability import AvailabilityRun, save_availability_run

    with pytest.raises(ValueError, match="IPv4"):
        save_availability_run(
            conn,
            AvailabilityRun.failed("2001:db8::/64", started=OLD, error_class="deadline_exceeded"),
        )

    assert conn.execute("SELECT count(*) FROM availability_runs").fetchone()[0] == 0


def test_failure_class_change_without_active_change_does_not_create_event(conn):
    """Failure diagnostics are metadata, not a change in active state or active method."""
    from netctl.availability import AvailabilityResult, AvailabilityRun, save_availability_run

    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=OLD, finished=OLD,
            results=[
                AvailabilityResult("192.0.2.1", "reachable", "icmp"),
                AvailabilityResult("192.0.2.2", "unreachable", None, failure_class="timeout"),
            ],
        ),
    )
    save_availability_run(
        conn,
        AvailabilityRun.success(
            "192.0.2.0/30", started=NEW, finished=NEW,
            results=[
                AvailabilityResult("192.0.2.1", "reachable", "icmp"),
                AvailabilityResult("192.0.2.2", "unreachable", None, failure_class="refused"),
            ],
        ),
    )

    assert conn.execute("SELECT count(*) FROM availability_result_events").fetchone()[0] == 2
