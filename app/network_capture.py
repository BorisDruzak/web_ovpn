"""Run a bounded, single-interface capture from a server-owned profile."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Literal


CAPTURE_MAX_DURATION_SECONDS = 60
CAPTURE_MAX_PACKETS = 10_000
CAPTURE_MAX_KIB = 2048
CAPTURE_SNAPLEN = 96

_DUMPCAP = "/usr/bin/dumpcap"
_INTERFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", re.ASCII)
_PCAP_HEADER_SIZE = 24
_PCAP_RECORD_HEADER_SIZE = 16
_PCAP_MAGIC_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}


def _bounded_int(value: int, maximum: int) -> bool:
    return type(value) is int and 1 <= value <= maximum


def _error(code: str) -> dict[str, str | int]:
    return {"status": "error", "error": code}


def _open_output(output: Path) -> BinaryIO:
    if not output.is_absolute() or output.suffix != ".pcap":
        raise ValueError("Capture output must be an absolute .pcap path")
    parent = output.parent
    if parent.resolve(strict=True) != parent:
        raise ValueError("Capture directory must have a canonical path")
    if os.name == "posix":
        parent_stat = parent.stat()
        if parent_stat.st_uid != os.geteuid() or parent_stat.st_mode & 0o077:
            raise ValueError("Capture directory must be private to the service")

    # Exclusive creation prevents overwrites and symlink following at the leaf.
    descriptor = os.open(
        output, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600
    )
    return os.fdopen(descriptor, "rb+", buffering=0)


def _pcap_packet_count(
    stream: BinaryIO, size: int, max_packets: int, inspect: Callable[[int, bytes], None] | None = None,
) -> int | None:
    stream.seek(0)
    header = stream.read(_PCAP_HEADER_SIZE)
    endian = _PCAP_MAGIC_ENDIAN.get(header[:4])
    if endian is None or len(header) != _PCAP_HEADER_SIZE:
        return None
    major, minor, _, _, snaplen, linktype = struct.unpack(f"{endian}HHIIII", header[4:])
    if (major, minor) != (2, 4) or not 1 <= snaplen <= CAPTURE_SNAPLEN:
        return None

    packets = 0
    remaining = size - _PCAP_HEADER_SIZE
    while remaining:
        if remaining < _PCAP_RECORD_HEADER_SIZE or packets == max_packets:
            return None
        record = stream.read(_PCAP_RECORD_HEADER_SIZE)
        if len(record) != _PCAP_RECORD_HEADER_SIZE:
            return None
        _, _, captured, original = struct.unpack(f"{endian}IIII", record)
        remaining -= _PCAP_RECORD_HEADER_SIZE + captured
        if remaining < 0 or captured > min(original, snaplen):
            return None
        if inspect is None:
            stream.seek(captured, os.SEEK_CUR)
        else:
            frame = stream.read(captured)
            if len(frame) != captured:
                return None
            inspect(linktype & 0xFFFF, frame)
        packets += 1
    return packets


def _ethernet_transport(frame: bytes) -> tuple[bytes, bytes, int, bytes] | None:
    if len(frame) < 14:
        return None
    ether_type = frame[12:14]
    offset = 14
    for _ in range(2):
        if ether_type not in (b"\x81\x00", b"\x88\xa8") or len(frame) < offset + 4:
            break
        ether_type = frame[offset + 2:offset + 4]
        offset += 4
    packet = frame[offset:]
    if ether_type == b"\x08\x00" and len(packet) >= 20 and packet[0] >> 4 == 4:
        header_size = (packet[0] & 15) * 4
        total_size = int.from_bytes(packet[2:4], "big")
        if header_size < 20 or total_size < header_size or int.from_bytes(packet[6:8], "big") & 0x3FFF:
            return None
        return packet[12:16], packet[16:20], packet[9], packet[header_size:total_size]
    if ether_type == b"\x86\xdd" and len(packet) >= 40 and packet[0] >> 4 == 6:
        total_size = 40 + int.from_bytes(packet[4:6], "big")
        return packet[8:24], packet[24:40], packet[6], packet[40:total_size]
    return None


def summarize_capture(stream: BinaryIO, size: int, *, peer: str, port: int, protocol: str) -> dict | None:
    address = ipaddress.ip_address(peer).packed
    transport_number = {"tcp": 6, "udp": 17}[protocol]
    summary = {"from_peer": 0, "to_peer": 0, "unclassified": 0}
    if protocol == "tcp":
        summary["tcp_resets"] = 0

    def inspect(linktype: int, frame: bytes) -> None:
        parsed = _ethernet_transport(frame) if linktype == 1 else None
        if parsed is not None:
            source, target, transport, payload = parsed
            if transport == transport_number and len(payload) >= (20 if protocol == "tcp" else 8):
                source_port, target_port = struct.unpack_from("!HH", payload)
                from_peer = source == address and source_port == port
                to_peer = target == address and target_port == port
                if from_peer != to_peer:
                    summary["from_peer" if from_peer else "to_peer"] += 1
                    if protocol == "tcp" and payload[13] & 4:
                        summary["tcp_resets"] += 1
                    return
        summary["unclassified"] += 1

    if _pcap_packet_count(stream, size, CAPTURE_MAX_PACKETS, inspect) is None:
        return None
    return summary


def capture_filter_expression(address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int, protocol: Literal["tcp", "udp"]) -> str:
    return (
        f"{protocol} and ((src host {address} and src port {port}) or "
        f"(dst host {address} and dst port {port}))"
    )


def capture_packets(
    output: Path,
    *,
    interface: str,
    peer: str,
    port: int,
    protocol: Literal["tcp", "udp"],
    duration_seconds: int,
    max_packets: int,
    max_kib: int,
) -> dict[str, str | int]:
    """Capture to a new file in a canonical, service-owned private directory.

    The caller authorizes the profile and generates the output path under its
    private artifact directory. The snaplen keeps at most the first 96 bytes
    of each frame, which can include initial application bytes depending on
    the link, network and transport headers.
    """
    if (
        not isinstance(interface, str)
        or _INTERFACE.fullmatch(interface) is None
        or interface.isdecimal()
        or interface == "any"
        or not isinstance(peer, str)
        or "%" in peer
        or protocol not in ("tcp", "udp")
        or not _bounded_int(port, 65535)
        or not _bounded_int(duration_seconds, CAPTURE_MAX_DURATION_SECONDS)
        or not _bounded_int(max_packets, CAPTURE_MAX_PACKETS)
        or not _bounded_int(max_kib, CAPTURE_MAX_KIB)
    ):
        return _error("invalid_profile")
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return _error("invalid_profile")
    try:
        socket.if_nametoindex(interface)
    except OSError:
        return _error("capture_interface_unavailable")

    max_bytes = max_kib * 1024
    record_max_bytes = _PCAP_RECORD_HEADER_SIZE + CAPTURE_SNAPLEN
    # Dumpcap checks a decimal kB threshold after writing the last record.
    filesize_kb = (max_bytes - record_max_bytes + 1) // 1000
    if filesize_kb < 1:
        max_packets = min(max_packets, (max_bytes - _PCAP_HEADER_SIZE) // record_max_bytes)
        filesize_kb = 1
    command = [
        _DUMPCAP,
        "-P",
        "-q",
        "-p",
        "-i",
        interface,
        "-f",
        capture_filter_expression(address, port, protocol),
        "-s",
        str(CAPTURE_SNAPLEN),
        "-a",
        f"duration:{duration_seconds}",
        "-a",
        f"filesize:{filesize_kb}",
        "-c",
        str(max_packets),
        "-w",
        "-",
    ]

    try:
        stream = _open_output(output)
    except (OSError, ValueError):
        return _error("capture_output_unavailable")
    keep_output = False
    try:
        with stream:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.DEVNULL,
                cwd=output.parent,
                env={"LC_ALL": "C"},
                shell=False,
                check=False,
                timeout=duration_seconds + 5,
            )
            if result.returncode != 0:
                return _error("capture_failed")
            size = os.fstat(stream.fileno()).st_size
            if not _PCAP_HEADER_SIZE <= size <= max_bytes:
                return _error("capture_invalid_output")
            packets = _pcap_packet_count(stream, size, max_packets)
            if packets is None:
                return _error("capture_invalid_output")
        keep_output = True
        return {"status": "ok", "size_bytes": size, "packets": packets}
    except (FileNotFoundError, PermissionError):
        return _error("dumpcap_unavailable")
    except subprocess.TimeoutExpired:
        return _error("capture_timeout")
    except OSError:
        return _error("capture_failed")
    finally:
        if not keep_output:
            try:
                output.unlink(missing_ok=True)
            except OSError:
                pass
