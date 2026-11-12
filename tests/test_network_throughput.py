import json
import subprocess

import pytest

from app.network_throughput import run_throughput


def _iperf_output(*, reverse=False, retransmits=4):
    sender = {"bits_per_second": 9_250_000, "sender": not reverse}
    if retransmits is not None:
        sender["retransmits"] = retransmits
    return json.dumps(
        {
            "end": {
                "sum_sent": sender,
                "sum_received": {"bits_per_second": 8_750_000, "sender": not reverse},
            },
        }
    ).encode()


@pytest.mark.parametrize("connected", [[], [{"local_port": 4444}]])
def test_retries_only_a_refused_connection_before_a_test_started(monkeypatch, connected):
    first = json.dumps({
        "start": {"connected": connected}, "intervals": [], "end": {},
        "error": "unable to connect to server: Connection refused",
    }).encode()
    calls = []
    monkeypatch.setattr("time.sleep", lambda _: None)

    def run(argv, **kwargs):
        calls.append(kwargs["timeout"])
        if len(calls) == 1:
            return subprocess.CompletedProcess(argv, 1, stdout=first)
        return subprocess.CompletedProcess(argv, 0, stdout=_iperf_output())

    monkeypatch.setattr(subprocess, "run", run)
    result = run_throughput("192.0.2.10", 5202, "send", duration_seconds=4, bitrate_mbps=5)
    if connected:
        assert len(calls) == 1 and result["status"] == "failed"
    else:
        assert len(calls) == 2 and calls[1] <= calls[0]
        assert result["status"] == "ok" and result["result"]["preconnect_retries"] == 1


@pytest.mark.parametrize("direction, reverse", [("send", False), ("receive", True)])
def test_uses_one_paced_tcp_stream_and_reports_both_endpoints(
    monkeypatch, direction, reverse
):
    def run(argv, *, stdin, stdout, stderr, timeout, check):
        assert argv == [
            "iperf3",
            "--client",
            "192.0.2.10",
            "--port",
            "5202",
            "--time",
            "10",
            "--bitrate",
            "50000000",
            "--parallel",
            "1",
            "--connect-timeout",
            "2000",
            "--interval",
            "0",
            "--json",
        ] + (["--reverse"] if reverse else [])
        assert stdin == stderr == subprocess.DEVNULL
        assert stdout == subprocess.PIPE
        assert timeout == 15
        return subprocess.CompletedProcess(
            argv, 0, stdout=_iperf_output(reverse=reverse)
        )

    monkeypatch.setattr(subprocess, "run", run)

    assert run_throughput(
        "192.0.2.10",
        5202,
        direction,
        duration_seconds=10,
        bitrate_mbps=50,
    ) == {
        "status": "ok",
        "result": {"sender_mbps": 9.25, "receiver_mbps": 8.75, "retransmits": 4},
    }


@pytest.mark.parametrize(
    "field, value",
    [
        ("peer", "iperf.example.org"),
        ("peer", "192.0.2.10 "),
        ("peer", "224.0.0.1"),
        ("peer", "ff02::1"),
        ("peer", "::ffff:e000:1"),
        ("peer", "2001:0db8::1"),
        ("peer", "fe80::1%eth0"),
        ("peer", "0.0.0.0"),
        ("peer", "255.255.255.255"),
        ("port", 0),
        ("port", 65536),
        ("port", "5201"),
        ("direction", "both"),
        ("duration_seconds", 0),
        ("duration_seconds", 11),
        ("duration_seconds", True),
        ("bitrate_mbps", 0),
        ("bitrate_mbps", 51),
        ("bitrate_mbps", 5.5),
        ("source_address", "2001:db8::1"),
        ("source_address", "192.000.2.20"),
        ("source_address", "239.0.0.1"),
        ("source_address", "0.0.0.0"),
        ("source_address", "192.0.2.20%eth0"),
        ("bind_interface", "eth0"),
    ],
)
def test_rejects_invalid_profile_before_starting_process(monkeypatch, field, value):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: pytest.fail("unexpected traffic")
    )
    profile = {
        "peer": "192.0.2.10",
        "port": 5201,
        "direction": "send",
        "duration_seconds": 5,
        "bitrate_mbps": 10,
    }
    profile[field] = value

    with pytest.raises(ValueError):
        run_throughput(**profile)


@pytest.mark.parametrize(
    "interface", ["-eth0", "eth0;id", "eth0 eth1", "eth0\n", "x" * 16, "", True]
)
def test_rejects_invalid_interface_with_valid_source(monkeypatch, interface):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **kw: pytest.fail("unexpected traffic")
    )

    with pytest.raises(ValueError):
        run_throughput(
            "192.0.2.10",
            5201,
            "send",
            duration_seconds=5,
            bitrate_mbps=10,
            source_address="192.0.2.20",
            bind_interface=interface,
        )


def _connected_output(connected):
    report = json.loads(_iperf_output())
    report["start"] = {"connected": connected}
    return json.dumps(report).encode()


@pytest.mark.parametrize(
    "direction, source, peer, reported_source, interface",
    [
        ("send", "192.0.2.20", "192.0.2.10", "192.0.2.20", "vlan20.3"),
        ("receive", "192.0.2.20", "192.0.2.10", "192.0.2.20", "vlan20.3"),
        ("receive", "2001:db8::2", "2001:db8::1", "2001:0db8:0:0:0:0:0:2", None),
    ],
)
def test_reports_confirmed_socket_endpoints_for_source_bound_traffic(
    monkeypatch,
    direction,
    source,
    peer,
    reported_source,
    interface,
):
    def run(argv, **kwargs):
        assert argv[2] == peer
        assert ("--reverse" in argv) == (direction == "receive")
        flags = ["--bind", source] + (["--bind-dev", interface] if interface else [])
        assert argv[-len(flags) :] == flags
        assert ("--bind-dev" in argv) == (interface is not None)
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=_connected_output(
                [
                    {
                        "socket": 5,
                        "local_host": reported_source,
                        "local_port": 49152,
                        "remote_host": peer,
                        "remote_port": 5201,
                    }
                ]
            ),
        )

    monkeypatch.setattr(subprocess, "run", run)

    assert run_throughput(
        peer,
        5201,
        direction,
        duration_seconds=5,
        bitrate_mbps=10,
        source_address=source,
        bind_interface=interface,
    ) == {
        "status": "ok",
        "result": {"sender_mbps": 9.25, "receiver_mbps": 8.75, "retransmits": 4},
        "connection": {
            "source_address": source,
            "peer_address": peer,
            "peer_port": 5201,
        },
    }


_VALID_SOCKET = {
    "local_host": "192.0.2.20",
    "remote_host": "192.0.2.10",
    "remote_port": 5201,
}


@pytest.mark.parametrize(
    "stdout",
    [
        _iperf_output(),
        _connected_output([]),
        _connected_output([_VALID_SOCKET, _VALID_SOCKET]),
        _connected_output(_VALID_SOCKET),
        _connected_output([{"remote_host": "192.0.2.10", "remote_port": 5201}]),
        _connected_output([dict(_VALID_SOCKET, local_host="192.0.2.30")]),
        _connected_output([dict(_VALID_SOCKET, remote_host="192.0.2.30")]),
        _connected_output([dict(_VALID_SOCKET, remote_port=5202)]),
        _connected_output([dict(_VALID_SOCKET, remote_port="5201")]),
        _connected_output([dict(_VALID_SOCKET, remote_port=5201.0)]),
    ],
)
def test_source_bound_measurement_requires_exactly_one_matching_socket(
    monkeypatch, stdout
):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout=stdout),
    )

    assert run_throughput(
        "192.0.2.10",
        5201,
        "send",
        duration_seconds=5,
        bitrate_mbps=10,
        source_address="192.0.2.20",
    ) == {"status": "failed", "result": None}


def test_allows_canonical_ipv6_and_preserves_missing_retransmits(monkeypatch):
    def run(argv, **kwargs):
        assert argv[2] == "2001:db8::1"
        return subprocess.CompletedProcess(
            argv, 0, stdout=_iperf_output(retransmits=None)
        )

    monkeypatch.setattr(subprocess, "run", run)

    assert (
        run_throughput(
            "2001:db8::1",
            5201,
            "send",
            duration_seconds=1,
            bitrate_mbps=1,
        )["result"]["retransmits"]
        is None
    )


@pytest.mark.parametrize(
    "error, status",
    [
        (FileNotFoundError("internal path"), "unavailable"),
        (PermissionError("internal path"), "unavailable"),
        (
            subprocess.TimeoutExpired(
                "internal command", 15, output=b"internal output"
            ),
            "timeout",
        ),
    ],
)
def test_reports_execution_errors_without_subprocess_details(
    monkeypatch, error, status
):
    def run(*args, **kwargs):
        raise error

    monkeypatch.setattr(subprocess, "run", run)

    assert run_throughput(
        "192.0.2.10",
        5201,
        "send",
        duration_seconds=5,
        bitrate_mbps=10,
    ) == {"status": status, "result": None}


@pytest.mark.parametrize(
    "returncode, stdout",
    [
        (1, _iperf_output()),
        (0, b"\xff not JSON"),
        (0, b'{"error": "private peer error"}'),
        (0, b'{"end": {"sum_sent": {"bits_per_second": 1}, "sum_received": null}}'),
        (
            0,
            b'{"end": {"sum_sent": {"bits_per_second": NaN}, "sum_received": {"bits_per_second": 1}}}',
        ),
        (
            0,
            b'{"end": {"sum_sent": {"bits_per_second": true}, "sum_received": {"bits_per_second": 1}}}',
        ),
        (
            0,
            b'{"end": {"sum_sent": {"bits_per_second": -1}, "sum_received": {"bits_per_second": 1}}}',
        ),
        (0, _iperf_output(retransmits=-1)),
    ],
)
def test_rejects_failed_or_invalid_measurements(monkeypatch, returncode, stdout):
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout)

    monkeypatch.setattr(subprocess, "run", run)

    assert run_throughput(
        "192.0.2.10",
        5201,
        "send",
        duration_seconds=5,
        bitrate_mbps=10,
    ) == {"status": "failed", "result": None}
