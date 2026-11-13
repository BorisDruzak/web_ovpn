from __future__ import annotations

import os
import ipaddress
import struct
import subprocess
from io import BytesIO

import pytest


PROFILE = {
    "interface": "eth0",
    "peer": "2001:0DB8::1",
    "protocol": "tcp",
    "port": 443,
    "duration_seconds": 8,
    "max_packets": 25,
    "max_kib": 32,
}
PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1)
PCAP_PACKET = struct.pack("<IIII", 0, 0, 60, 110) + bytes(60)


@pytest.mark.parametrize("version,protocol", [(4, "tcp"), (6, "tcp"), (4, "udp")])
def test_capture_summary_counts_directions_and_tcp_resets(version, protocol):
    from app.network_capture import summarize_capture

    local, peer = ("192.0.2.1", "192.0.2.2") if version == 4 else ("2001:db8::1", "2001:db8::2")
    protocol_number = 6 if protocol == "tcp" else 17

    def frame(source, target, source_port, target_port, rst=False):
        transport = struct.pack("!HH", source_port, target_port)
        transport += bytes(8) + bytes([0x50, 4 if rst else 0]) + bytes(6) if protocol == "tcp" else bytes(4)
        addresses = ipaddress.ip_address(source).packed + ipaddress.ip_address(target).packed
        if version == 4:
            ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(transport), 0, 0, 64, protocol_number, 0)
            ethernet = bytes(12) + b"\x81\x00\x00\x14\x08\x00"
        else:
            ip = struct.pack("!IHBB", 0x60000000, len(transport), protocol_number, 64)
            ethernet = bytes(12) + b"\x86\xdd"
        packet = ethernet + ip + addresses + transport
        return struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet

    pcap = PCAP_HEADER + frame(local, peer, 40001, 443) + frame(peer, local, 443, 40001, True) + PCAP_PACKET
    expected = {"to_peer": 1, "from_peer": 1, "unclassified": 1}
    if protocol == "tcp":
        expected["tcp_resets"] = 1
    assert summarize_capture(BytesIO(pcap), len(pcap), peer=peer, port=443, protocol=protocol) == expected


def test_capture_runs_fixed_dumpcap_and_reports_pcap_metadata(monkeypatch, tmp_path):
    from app import network_capture

    monkeypatch.setattr(network_capture.socket, "if_nametoindex", lambda _name: 2)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        kwargs["stdout"].write(PCAP_HEADER + PCAP_PACKET)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(network_capture.subprocess, "run", run)
    output = tmp_path / "capture.pcap"

    assert network_capture.capture_packets(output, **PROFILE) == {
        "status": "ok",
        "size_bytes": 100,
        "packets": 1,
    }
    assert output.read_bytes() == PCAP_HEADER + PCAP_PACKET
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    [(command, options)] = calls
    assert command == [
        "/usr/bin/dumpcap", "-P", "-q", "-p", "-i", "eth0",
        "-f", "tcp and ((src host 2001:db8::1 and src port 443) or "
        "(dst host 2001:db8::1 and dst port 443))",
        "-s", "96", "-a", "duration:8", "-a", "filesize:32", "-c", "25",
        "-w", "-",
    ]
    assert options["shell"] is False
    assert options["cwd"] == tmp_path
    assert options["timeout"] == 13
    assert options["stderr"] == subprocess.DEVNULL
    assert options["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize(
    "profile_override",
    [
        {"interface": "any"},
        {"interface": "-"},
        {"interface": "1"},
        {"interface": "rpcap://remote/eth0"},
        {"peer": "example.org"},
        {"peer": "192.0.2.1 or host 192.0.2.2"},
        {"peer": "fe80::1%eth0"},
        {"port": 65536},
        {"protocol": "icmp"},
        {"duration_seconds": True},
        {"duration_seconds": 61},
        {"max_packets": 10001},
        {"max_kib": 2049},
    ],
)
def test_rejects_invalid_profile_before_opening_output(tmp_path, profile_override):
    from app import network_capture

    output = tmp_path / "capture.pcap"

    result = network_capture.capture_packets(output, **(PROFILE | profile_override))

    assert result == {"status": "error", "error": "invalid_profile"}
    assert not output.exists()


def test_rejects_unknown_interface_before_opening_output(monkeypatch, tmp_path):
    from app import network_capture

    def unknown_interface(_name):
        raise OSError("interface not found")

    monkeypatch.setattr(network_capture.socket, "if_nametoindex", unknown_interface)
    output = tmp_path / "capture.pcap"

    assert network_capture.capture_packets(output, **PROFILE) == {
        "status": "error",
        "error": "capture_interface_unavailable",
    }
    assert not output.exists()


def test_never_overwrites_an_existing_output(monkeypatch, tmp_path):
    from app import network_capture

    monkeypatch.setattr(network_capture.socket, "if_nametoindex", lambda _name: 2)
    output = tmp_path / "capture.pcap"
    output.write_bytes(b"previous artifact")

    assert network_capture.capture_packets(output, **PROFILE) == {
        "status": "error",
        "error": "capture_output_unavailable",
    }
    assert output.read_bytes() == b"previous artifact"


def test_small_file_budget_caps_packet_count_before_spawn(monkeypatch, tmp_path):
    from app import network_capture

    monkeypatch.setattr(network_capture.socket, "if_nametoindex", lambda _name: 2)
    packet_limits = []

    def run(command, **kwargs):
        packet_limits.append(command[command.index("-c") + 1])
        kwargs["stdout"].write(PCAP_HEADER)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(network_capture.subprocess, "run", run)
    output = tmp_path / "capture.pcap"

    assert network_capture.capture_packets(output, **(PROFILE | {"max_kib": 1})) == {
        "status": "ok",
        "size_bytes": 24,
        "packets": 0,
    }
    assert packet_limits == ["8"]


@pytest.mark.parametrize(
    ("failure", "expected_error"),
    [
        ("exit", "capture_failed"),
        ("timeout", "capture_timeout"),
        ("unavailable", "dumpcap_unavailable"),
        ("malformed", "capture_invalid_output"),
        ("oversized", "capture_invalid_output"),
        ("too_many_packets", "capture_invalid_output"),
    ],
)
def test_failed_capture_removes_partial_file_and_hides_diagnostics(
    monkeypatch, tmp_path, failure, expected_error
):
    from app import network_capture

    monkeypatch.setattr(network_capture.socket, "if_nametoindex", lambda _name: 2)

    def run(command, **kwargs):
        if failure == "oversized":
            kwargs["stdout"].write(bytes(32769))
        elif failure == "too_many_packets":
            kwargs["stdout"].write(PCAP_HEADER + PCAP_PACKET * 26)
        else:
            kwargs["stdout"].write(PCAP_HEADER + PCAP_PACKET[:-1])
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 13, stderr=b"private details")
        if failure == "unavailable":
            raise FileNotFoundError("private details")
        return subprocess.CompletedProcess(
            command, 1 if failure == "exit" else 0, stderr=b"private details"
        )

    monkeypatch.setattr(network_capture.subprocess, "run", run)
    output = tmp_path / "capture.pcap"

    assert network_capture.capture_packets(output, **PROFILE) == {
        "status": "error",
        "error": expected_error,
    }
    assert not output.exists()
