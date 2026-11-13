"""Bounded connectivity probes for configured local IPv4 paths."""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from time import monotonic

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdata

from .infrastructure_service_probes import _http_path, _valid_http_hostname

PROBE_TIMEOUT = 3.0
ROUTE_TIMEOUT = 2.0
ROUTE_FIELDS = (
    "dst",
    "gateway",
    "dev",
    "prefsrc",
    "src",
    "from",
    "table",
    "type",
    "metric",
)
DNS_TYPES = ("A", "AAAA", "CNAME", "SOA", "SRV", "TXT", "MX", "PTR")
LINUX_NEIGHBOR_STATES = (
    "incomplete", "reachable", "stale", "delay", "probe", "failed",
    "noarp", "permanent", "none", "not_cached",
)


def _ipv4(value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("IPv4 literal required")
    address = ipaddress.IPv4Address(value)
    if (
        value != str(address)
        or address.is_unspecified
        or address.is_multicast
        or int(address) == 0xFFFFFFFF
    ):
        raise ValueError("Unicast IPv4 literal required")


def _run_local(argv: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=timeout,
        env={**os.environ, "LC_ALL": "C"},
    )


def _kernel_route(target: str, source_address: str | None) -> dict:
    argv = ["/usr/sbin/ip", "-j", "-4", "route", "get", target]
    if source_address is not None:
        argv.extend(("from", source_address))
    try:
        completed = _run_local(argv, ROUTE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "result": {}}
    except OSError:
        return {"status": "unavailable", "result": {}}
    if completed.returncode:
        error = completed.stderr.lower()
        no_route = b"network is unreachable" in error or b"no route to host" in error
        return {"status": "no_route" if no_route else "failed", "result": {}}
    try:
        rows = json.loads(completed.stdout)
    except (ValueError, RecursionError):
        return {"status": "failed", "result": {}}
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {"status": "failed", "result": {}}
    result = {
        key: rows[0][key]
        for key in ROUTE_FIELDS
        if type(rows[0].get(key)) in (str, int)
    }
    if result.get("dst") != target:
        return {"status": "failed", "result": {}}
    return {"status": "route_found", "result": result}


def linux_neighbor_target(route_fields: dict) -> tuple[str, str] | None:
    address = route_fields.get("gateway", route_fields.get("dst"))
    interface = route_fields.get("dev")
    try:
        _ipv4(address)
    except ValueError:
        return None
    if not isinstance(interface, str) or not re.fullmatch(
        r"[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,31}", interface
    ):
        return None
    return address, interface


def _linux_neighbor(route: dict) -> dict | None:
    if route["status"] != "route_found":
        return None
    neighbor = linux_neighbor_target(route["result"])
    if neighbor is None:
        return None
    address, interface = neighbor
    argv = ["/usr/sbin/ip", "-j", "-4", "neigh", "show", "to", address, "dev", interface]
    try:
        completed = _run_local(argv, 1.0)
        if completed.returncode:
            return None
        rows = json.loads(completed.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError, RecursionError):
        return None
    if rows == []:
        state = "not_cached"
    elif (
        isinstance(rows, list)
        and len(rows) == 1
        and isinstance(rows[0], dict)
        and rows[0].get("dst") == address
        and rows[0].get("dev", interface) == interface
    ):
        state = rows[0].get("state")
        if isinstance(state, list) and len(state) == 1:
            state = state[0]
        if not isinstance(state, str) or state.lower() not in LINUX_NEIGHBOR_STATES:
            return None
        state = state.lower()
    else:
        return None
    return {"address": address, "interface": interface, "state": state}


def _icmp(
    target: str, source_address: str | None, mtu: int | None, evidence: dict
) -> str:
    argv = ["/usr/bin/ping", "-4", "-n", "-c", "1", "-W", "2"]
    if source_address is not None:
        argv.extend(("-I", source_address))
    if mtu is not None:
        evidence["mtu"] = mtu
        # IPv4 and ICMP echo headers account for 28 bytes of the requested packet size.
        argv.extend(("-M", "do", "-s", str(mtu - 28)))
    completed = _run_local([*argv, target], PROBE_TIMEOUT)
    if completed.returncode == 0:
        timing = re.search(rb"\btime=([0-9]+(?:\.[0-9]+)?) ms", completed.stdout)
        if timing:
            evidence["round_trip_ms"] = float(timing[1])
        return "reachable"

    diagnostic = (completed.stdout + completed.stderr).lower()
    if (
        b"message too long" in diagnostic
        or b"frag needed" in diagnostic
        or b"fragmentation needed" in diagnostic
    ):
        evidence["reason"] = "icmp_fragmentation_required"
        return "unreachable"
    if b"cannot assign requested address" in diagnostic:
        evidence["reason"] = "source_unavailable"
        return "unavailable"
    if b"operation not permitted" in diagnostic or b"permission denied" in diagnostic:
        evidence["reason"] = "probe_unavailable"
        return "unavailable"
    if b"unreachable" in diagnostic or b"time to live exceeded" in diagnostic:
        evidence["reason"] = "icmp_unreachable"
        return "unreachable"
    if completed.returncode == 1:
        evidence["reason"] = "icmp_no_echo_reply"
        return "timeout"
    evidence["reason"] = "icmp_probe_failed"
    return "failed"


def _remaining(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _http_status(
    connection: socket.socket, authority: str, path: str, deadline: float
) -> int | None:
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode(
            "ascii"
        )
    )
    connection.settimeout(_remaining(deadline))
    connection.sendall(request)
    buffer = b""
    remaining_bytes = 8192
    while remaining_bytes:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(min(1024, remaining_bytes))
        if not chunk:
            if remaining_bytes == 8192:
                raise EOFError
            break
        remaining_bytes -= len(chunk)
        buffer += chunk
        while b"\r\n" in buffer:
            line = buffer.split(b"\r\n", 1)[0]
            status = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?", line)
            if not status:
                return None
            code = int(status[1])
            if code >= 200 or code == 101:
                return code
            _, separator, remainder = buffer.partition(b"\r\n\r\n")
            if not separator:
                break
            buffer = remainder
    return None


def _check_http(
    connection: socket.socket,
    authority: str,
    path: str,
    deadline: float,
    expected_status: int,
    evidence: dict,
) -> str:
    evidence["expected_http_status"] = expected_status
    code = _http_status(connection, authority, path, deadline)
    if code is None:
        evidence["reason"] = "http_response_invalid"
        return "failed"
    evidence["http_status"] = code
    if code != expected_status:
        evidence["reason"] = "http_status_mismatch"
        return "unreachable"
    return "reachable"


def _tcp(
    target: str,
    port: int,
    source_address: str | None,
    protocol: str,
    server_name: str | None,
    tls_ca_file: str | None,
    path: str,
    expected_status: int,
    evidence: dict,
) -> str:
    deadline = monotonic() + PROBE_TIMEOUT
    context = None
    if tls_ca_file is not None:
        try:
            if not os.path.isfile(tls_ca_file):
                raise FileNotFoundError
            context = ssl.create_default_context(cafile=tls_ca_file)
        except (OSError, ValueError):
            evidence["reason"] = "tls_ca_unavailable"
            return "unavailable"
    elif protocol in ("tls", "https"):
        context = ssl.create_default_context()
    source = (source_address, 0) if source_address is not None else None
    name = server_name or target
    with socket.create_connection(
        (target, port), timeout=_remaining(deadline), source_address=source
    ) as connection:
        if protocol == "http":
            authority = name if port == 80 else f"{name}:{port}"
            return _check_http(
                connection, authority, path, deadline, expected_status, evidence
            )
        if context is None:
            return "reachable"
        connection.settimeout(_remaining(deadline))
        with context.wrap_socket(connection, server_hostname=name) as tls:
            evidence["tls_version"] = tls.version()
            expires = tls.getpeercert().get("notAfter")
            if expires is not None:
                try:
                    timestamp = ssl.cert_time_to_seconds(expires)
                    evidence["tls_expires_at"] = datetime.fromtimestamp(
                        timestamp, timezone.utc
                    ).isoformat()
                except (ValueError, OverflowError, OSError):
                    pass
            if protocol == "tls":
                return "reachable"
            authority = name if port == 443 else f"{name}:{port}"
            return _check_http(
                tls, authority, path, deadline, expected_status, evidence
            )


def _dns_request(
    name: str | None, record: str | None, expected_answers: tuple[str, ...]
) -> tuple:
    if (
        not isinstance(name, str)
        or len(name) > 253
        or not all(
            re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?", label)
            for label in name.removesuffix(".").split(".")
        )
    ):
        raise ValueError("Invalid DNS name")
    record = "A" if record is None else record
    if record not in DNS_TYPES:
        raise ValueError("Invalid DNS type")
    if (
        not isinstance(expected_answers, (tuple, list))
        or len(expected_answers) > 8
        or any(
            not isinstance(value, str) or not 1 <= len(value) <= 255
            for value in expected_answers
        )
    ):
        raise ValueError("Invalid DNS expectations")
    query = dns.message.make_query(name, record)
    expected = {dns.rdata.from_text("IN", record, value) for value in expected_answers}
    return query, expected


def _dns(
    target: str,
    port: int,
    source_address: str | None,
    query: dns.message.Message,
    expected: set,
    evidence: dict,
    transport: str | None,
) -> str:
    deadline = monotonic() + PROBE_TIMEOUT
    response = None
    if transport != "tcp":
        evidence["dns_transport"] = "UDP"
        try:
            response = dns.query.udp(
                query,
                target,
                timeout=_remaining(deadline),
                port=port,
                source=source_address,
                raise_on_truncation=True,
            )
        except dns.message.Truncated:
            if transport == "udp":
                evidence["reason"] = "dns_truncated"
                return "unreachable"
    if response is None:
        evidence["dns_transport"] = "TCP"
        response = dns.query.tcp(
            query,
            target,
            timeout=_remaining(deadline),
            port=port,
            source=source_address,
        )
    rcode = response.rcode()
    evidence["dns_rcode"] = dns.rcode.to_text(rcode)
    if rcode != dns.rcode.NOERROR:
        evidence["reason"] = "dns_rcode"
        return "unreachable"
    answers = response.resolve_chaining().answer
    evidence["dns_answer_count"] = len(answers) if answers else 0
    if not answers:
        evidence["reason"] = "dns_no_answer"
        return "unreachable"
    if expected:
        evidence["dns_answers_match"] = set(answers) == expected
        if not evidence["dns_answers_match"]:
            evidence["reason"] = "dns_answer_mismatch"
            return "unreachable"
    return "reachable"


def _transport_error(error: OSError) -> tuple[str, str]:
    if error.errno in (errno.EADDRNOTAVAIL, errno.ENODEV):
        return "unavailable", "source_unavailable"
    if isinstance(error, (FileNotFoundError, PermissionError)) or error.errno in (
        errno.EAFNOSUPPORT,
        errno.EPROTONOSUPPORT,
    ):
        return "unavailable", "probe_unavailable"
    if isinstance(error, ConnectionRefusedError):
        return "unreachable", "connection_refused"
    if isinstance(error, ConnectionError) or error.errno in (
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
    ):
        return "unreachable", "connection_unreachable"
    return "failed", "transport_error"


def probe_local_route(
    *,
    target: str,
    protocol: str,
    source_address: str | None = None,
    port: int | None = None,
    server_name: str | None = None,
    tls_ca_file: str | None = None,
    http_path: str | None = None,
    expected_http_status: int | None = None,
    dns_name: str | None = None,
    dns_type: str | None = None,
    dns_transport: str | None = None,
    expected_dns_answers: tuple[str, ...] = (),
    mtu: int | None = None,
) -> dict:
    """Probe the endpoint and report the kernel's route estimate separately."""
    started = monotonic()
    try:
        _ipv4(target)
        if source_address is not None:
            _ipv4(source_address)
        if protocol not in ("icmp", "tcp", "tls", "http", "https", "dns"):
            raise ValueError("Invalid protocol")
        if port is not None and (
            type(port) is not int or not 1 <= port <= 65535 or protocol == "icmp"
        ):
            raise ValueError("Invalid port")
        if protocol == "tcp" and port is None:
            raise ValueError("Missing TCP port")
        if mtu is not None and (
            type(mtu) is not int or not 68 <= mtu <= 9000 or protocol != "icmp"
        ):
            raise ValueError("Invalid MTU")
        if server_name is not None and (
            protocol not in ("tls", "http", "https")
            or not _valid_http_hostname(server_name)
        ):
            raise ValueError("Invalid server name")
        if protocol == "https" and server_name is None:
            raise ValueError("Missing HTTPS server name")
        if tls_ca_file is not None and (
            protocol not in ("tls", "https")
            or not isinstance(tls_ca_file, str)
            or not os.path.isabs(tls_ca_file)
            or "\0" in tls_ca_file
        ):
            raise ValueError("Invalid TLS CA file")
        if http_path is not None or expected_http_status is not None:
            if protocol not in ("http", "https"):
                raise ValueError("HTTP parameters require HTTP or HTTPS")
            if http_path is not None:
                _http_path(http_path)
            if expected_http_status is not None and (
                type(expected_http_status) is not int
                or not 200 <= expected_http_status <= 599
            ):
                raise ValueError("Invalid HTTP status")
        if protocol == "dns":
            if dns_transport not in (None, "udp", "tcp"):
                raise ValueError("Invalid DNS transport")
            query, expected = _dns_request(dns_name, dns_type, expected_dns_answers)
        elif dns_name is not None or dns_type is not None or dns_transport is not None or expected_dns_answers:
            raise ValueError("DNS parameters require DNS")
    except (ValueError, dns.exception.DNSException):
        return {
            "status": "unavailable",
            "evidence": {
                "reason": "invalid_configuration",
                "duration_ms": round((monotonic() - started) * 1000, 2),
            },
            "kernel_route": {"status": "not_run", "result": {}},
        }

    route = _kernel_route(target, source_address)
    started = monotonic()
    evidence: dict = {}
    try:
        if protocol == "icmp":
            status = _icmp(target, source_address, mtu, evidence)
        elif protocol == "dns":
            status = _dns(target, port or 53, source_address, query, expected, evidence, dns_transport)
        else:
            status = _tcp(
                target,
                port or (80 if protocol == "http" else 443),
                source_address,
                protocol,
                server_name,
                tls_ca_file,
                http_path or "/",
                expected_http_status or 200,
                evidence,
            )
    except (TimeoutError, subprocess.TimeoutExpired, dns.exception.Timeout):
        status, evidence["reason"] = "timeout", "timeout"
    except ssl.SSLCertVerificationError:
        status, evidence["reason"] = "unreachable", "tls_certificate_invalid"
    except ssl.SSLError:
        if "tls_version" in evidence:
            status, evidence["reason"] = "failed", "http_response_invalid"
        else:
            status, evidence["reason"] = "unreachable", "tls_handshake_failed"
    except EOFError:
        status, evidence["reason"] = "failed", "http_no_response"
    except dns.exception.DNSException:
        status, evidence["reason"] = "failed", "dns_response_invalid"
    except OSError as error:
        status, evidence["reason"] = _transport_error(error)
    evidence["duration_ms"] = round((monotonic() - started) * 1000, 2)
    if status in ("timeout", "unreachable"):
        neighbor = _linux_neighbor(route)
        if neighbor is not None:
            evidence["linux_neighbor"] = neighbor
    return {"status": status, "evidence": evidence, "kernel_route": route}
