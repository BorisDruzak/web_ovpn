"""Run a paced iperf3 test against an operator-configured peer."""

import ipaddress
import json
import math
import subprocess
from typing import Literal


def validate_throughput_profile(
    peer: str,
    port: int,
    *,
    duration_seconds: int,
    bitrate_mbps: int,
) -> None:
    if not isinstance(peer, str) or "%" in peer:
        raise ValueError("Throughput peer must be a canonical unicast IP literal")
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        raise ValueError(
            "Throughput peer must be a canonical unicast IP literal"
        ) from None
    if (
        str(address) != peer
        or address.is_multicast
        or address.is_unspecified
        or peer == "255.255.255.255"
        or (
            isinstance(address, ipaddress.IPv6Address)
            and (address.ipv4_mapped is not None or address.is_link_local)
        )
    ):
        raise ValueError("Throughput peer must be a canonical unicast IP literal")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Throughput port must be between 1 and 65535")
    if type(duration_seconds) is not int or not 1 <= duration_seconds <= 10:
        raise ValueError("Throughput duration must be between 1 and 10 seconds")
    if type(bitrate_mbps) is not int or not 1 <= bitrate_mbps <= 50:
        raise ValueError("Throughput target bitrate must be between 1 and 50 Mbps")


def _mbps(summary: dict) -> float:
    bps = summary["bits_per_second"]
    if type(bps) not in (int, float) or not math.isfinite(bps) or bps < 0:
        raise ValueError("Invalid measured bitrate")
    return bps / 1_000_000


def run_throughput(
    peer: str,
    port: int,
    direction: Literal["send", "receive"],
    *,
    duration_seconds: int,
    bitrate_mbps: int,
) -> dict:
    """Return both endpoint rates and the TCP sender's retransmit count."""
    validate_throughput_profile(
        peer, port, duration_seconds=duration_seconds, bitrate_mbps=bitrate_mbps
    )
    if direction not in ("send", "receive"):
        raise ValueError("Throughput direction must be send or receive")

    argv = [
        "iperf3",
        "--client",
        peer,
        "--port",
        str(port),
        "--time",
        str(duration_seconds),
        "--bitrate",
        str(bitrate_mbps * 1_000_000),
        "--parallel",
        "1",
        "--connect-timeout",
        "2000",
        "--interval",
        "0",
        "--json",
    ]
    if direction == "receive":
        argv.append("--reverse")
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=duration_seconds + 5,
            check=False,
        )
    except OSError:
        return {"status": "unavailable", "result": None}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "result": None}
    if completed.returncode:
        return {"status": "failed", "result": None}

    try:
        report = json.loads(completed.stdout)
        if "error" in report:
            return {"status": "failed", "result": None}
        sender = report["end"]["sum_sent"]
        receiver = report["end"]["sum_received"]
        retransmits = sender.get("retransmits")
        if retransmits is not None and (
            type(retransmits) is not int or retransmits < 0
        ):
            return {"status": "failed", "result": None}
        result = {
            "sender_mbps": _mbps(sender),
            "receiver_mbps": _mbps(receiver),
            "retransmits": retransmits,
        }
    except (
        AttributeError,
        KeyError,
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return {"status": "failed", "result": None}
    return {"status": "ok", "result": result}
