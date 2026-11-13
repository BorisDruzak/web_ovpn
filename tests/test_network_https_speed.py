import json
import subprocess

import pytest

from app.network_https_speed import run_https_speed


PEER = "162.159.140.220"


@pytest.mark.parametrize("direction", ["send", "receive"])
@pytest.mark.parametrize("source_address", [None, "192.0.2.10"])
def test_https_speed_pins_tls_peer_and_caps_transfer(monkeypatch, direction, source_address):
    upload = direction == "send"
    size = 500_000

    def run(argv, **kwargs):
        assert argv[1] == "--disable"
        assert argv[argv.index("--resolve") + 1] == f"speed.cloudflare.com:443:{PEER}"
        assert argv[argv.index("--noproxy") + 1] == "*"
        assert "--location" not in argv and "--insecure" not in argv
        if source_address is None:
            assert "--interface" not in argv
        else:
            assert argv[argv.index("--interface") + 1] == source_address
        assert kwargs["timeout"] == 13
        if upload:
            assert argv[-1] == "https://speed.cloudflare.com/__up"
            assert kwargs["input"] == bytes(size)
        else:
            assert argv[-1] == f"https://speed.cloudflare.com/__down?bytes={size}"
            assert argv[argv.index("--max-filesize") + 1] == str(size)
        output = {
            "http_status": 200, "bytes_up": size if upload else 0,
            "bytes_down": 0 if upload else size, "duration": 0.5,
            "peer": PEER, "source": "192.0.2.10", "source_port": 42013,
        }
        return subprocess.CompletedProcess(argv, 0, json.dumps(output).encode(), b"")

    monkeypatch.setattr(subprocess, "run", run)
    assert run_https_speed(PEER, direction, size, source_address=source_address) == {
        "status": "measured",
        "result": {
            "mbps": 8.0, "duration_seconds": 0.5,
            "transferred_bytes": size, "source_address": "192.0.2.10", "source_port": 42013,
        },
    }


@pytest.mark.parametrize("override", [
    {"peer": "162.159.140.221"},
    {"http_status": 302},
    {"bytes_down": 99_999},
    {"duration": 0}, {"source_port": 0},
])
def test_https_speed_rejects_incomplete_or_mismatched_transfer(monkeypatch, override):
    output = {
        "http_status": 200, "bytes_up": 0, "bytes_down": 100_000,
        "duration": 1, "peer": PEER, "source": "192.0.2.10", "source_port": 42013, **override,
    }
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs:
        subprocess.CompletedProcess(argv, 0, json.dumps(output).encode(), b""))
    assert run_https_speed(PEER, "receive", 100_000) == {"status": "failed", "result": {}}


def test_https_speed_rejects_a_different_observed_source(monkeypatch):
    output = {
        "http_status": 200, "bytes_down": 100_000, "duration": 1,
        "peer": PEER, "source": "192.0.2.20", "source_port": 42013,
    }
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs:
        subprocess.CompletedProcess(argv, 0, json.dumps(output).encode(), b""))
    assert run_https_speed(PEER, "receive", 100_000, source_address="192.0.2.10") == {
        "status": "failed", "result": {},
    }


@pytest.mark.parametrize("peer,direction,size", [
    ("127.0.0.1", "receive", 100_000),
    ("224.0.0.1", "receive", 100_000),
    (PEER, "receive", 10_000_001),
    (PEER, "send", 5_000_001),
])
def test_https_speed_rejects_invalid_configuration(peer, direction, size):
    with pytest.raises(ValueError):
        run_https_speed(peer, direction, size)
