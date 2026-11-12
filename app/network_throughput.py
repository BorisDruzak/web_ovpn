"""Run a paced iperf3 test against an operator-configured peer."""

import ipaddress
import json
import math
import re
import subprocess
import time
from typing import Literal


def _unicast_address(
    value: str, field: str
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    error = f"Throughput {field} must be a canonical unicast IP literal"
    if not isinstance(value, str) or "%" in value:
        raise ValueError(error)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(error) from None
    if (
        str(address) != value
        or address.is_multicast
        or address.is_unspecified
        or value == "255.255.255.255"
        or (
            isinstance(address, ipaddress.IPv6Address)
            and (address.ipv4_mapped is not None or address.is_link_local)
        )
    ):
        raise ValueError(error)
    return address


def validate_throughput_profile(
    peer: str,
    port: int,
    *,
    duration_seconds: int,
    bitrate_mbps: int,
    source_address: str | None = None,
    bind_interface: str | None = None,
) -> None:
    address = _unicast_address(peer, "peer")
    if (
        source_address is not None
        and _unicast_address(source_address, "source").version != address.version
    ):
        raise ValueError("Throughput source and peer must use the same IP version")
    if bind_interface is not None and (
        source_address is None
        or not isinstance(bind_interface, str)
        or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", bind_interface)
    ):
        raise ValueError(
            "Throughput interface must be a valid name and requires a source address"
        )
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


def _confirmed_connection(
    report: dict, source_address: str, peer: str, port: int
) -> dict:
    connected = report["start"]["connected"]
    if not isinstance(connected, list) or len(connected) != 1:
        raise ValueError("Expected one iperf3 data stream")
    stream = connected[0]
    local_host, remote_host, remote_port = (
        stream["local_host"],
        stream["remote_host"],
        stream["remote_port"],
    )
    if (
        not isinstance(local_host, str)
        or not isinstance(remote_host, str)
        or str(ipaddress.ip_address(local_host)) != source_address
        or str(ipaddress.ip_address(remote_host)) != peer
        or type(remote_port) is not int
        or remote_port != port
    ):
        raise ValueError("iperf3 data stream does not match the configured endpoints")
    return {"source_address": source_address, "peer_address": peer, "peer_port": port}


def _connection_refused_before_transfer(completed: subprocess.CompletedProcess) -> bool:
    if not completed.returncode:
        return False
    try:
        report = json.loads(completed.stdout)
        error = report.get("error")
        return (
            isinstance(error, str)
            and error.startswith("unable to connect to server")
            and error.endswith("Connection refused")
            and report["start"]["connected"] == []
            and report["intervals"] == []
            and report["end"] == {}
        )
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
        return False


def run_throughput(
    peer: str,
    port: int,
    direction: Literal["send", "receive"],
    *,
    duration_seconds: int,
    bitrate_mbps: int,
    source_address: str | None = None,
    bind_interface: str | None = None,
) -> dict:
    """Return both endpoint rates and the TCP sender's retransmit count."""
    validate_throughput_profile(
        peer,
        port,
        duration_seconds=duration_seconds,
        bitrate_mbps=bitrate_mbps,
        source_address=source_address,
        bind_interface=bind_interface,
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
    if source_address is not None:
        argv.extend(("--bind", source_address))
    if bind_interface is not None:
        argv.extend(("--bind-dev", bind_interface))
    timeout = duration_seconds + 5
    deadline = time.monotonic() + timeout
    try:
        for attempt in range(2):
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
            if attempt or not _connection_refused_before_transfer(completed):
                break
            retry_delay = 0.5
            if deadline - time.monotonic() <= retry_delay:
                break
            time.sleep(retry_delay)
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                break
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
        response = {
            "status": "ok",
            "result": {
                "sender_mbps": _mbps(sender),
                "receiver_mbps": _mbps(receiver),
                "retransmits": retransmits,
            },
        }
        if source_address is not None:
            response["connection"] = _confirmed_connection(
                report, source_address, peer, port
            )
        if attempt:
            response["result"]["preconnect_retries"] = attempt
    except (
        AttributeError,
        KeyError,
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return {"status": "failed", "result": None}
    return response
