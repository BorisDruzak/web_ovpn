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
