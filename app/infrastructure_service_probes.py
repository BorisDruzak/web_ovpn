"""Bounded, unauthenticated checks for explicitly configured service endpoints."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import struct
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

TIMEOUT = 3
HTTP_BODY_LIMIT = 32 * 1024


def _http(ip: str, port: int, spec: dict) -> str:
    path = spec.get("path")
    if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9._/-]{0,159}", path) or path.startswith("//"):
        raise ValueError("invalid service probe path")
    body_expected = spec.get("body")
    body_marker = spec.get("body_contains")
    content_type = spec.get("content_type")
    if not all(isinstance(value, (str, type(None))) for value in (body_expected, body_marker, content_type)) or not (body_expected or body_marker or content_type):
        raise ValueError("HTTP probe requires a response contract")
    tls = spec["type"] == "https"
    connection = http.client.HTTPSConnection(ip, port, timeout=TIMEOUT) if tls else http.client.HTTPConnection(ip, port, timeout=TIMEOUT)
    try:
        connection.request("GET", path, headers={"Accept-Encoding": "identity"})
        response = connection.getresponse()
        if 500 <= response.status < 600:
            return "unreachable"
        if response.status != 200:
            return "unknown"
        if content_type and response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != content_type:
            return "unknown"
        if body_expected:
            payload = response.read(HTTP_BODY_LIMIT + 1)
            return "reachable" if payload.strip() == body_expected.encode() else "unknown"
        if body_marker:
            return "reachable" if body_marker.encode() in response.read(HTTP_BODY_LIMIT) else "unknown"
        return "reachable" if response.read(1) else "unknown"
    finally:
        connection.close()


def _dns(ip: str, port: int, spec: dict) -> str:
    record = spec.get("record")
    name = spec.get("name")
    if record not in {"A", "AAAA", "SOA"} or not isinstance(name, str) or not name.endswith("."):
        raise ValueError("invalid DNS probe contract")
    query = dns.message.make_query(name, record)
    response, _ = dns.query.udp_with_fallback(query, ip, timeout=TIMEOUT, port=port)
    rcode = response.rcode()
    if rcode in {dns.rcode.SERVFAIL, dns.rcode.NXDOMAIN}:
        return "unreachable"
    if rcode != dns.rcode.NOERROR:
        return "unknown"
    wanted = dns.rdatatype.from_text(record)
    return "reachable" if any(rrset.rdtype == wanted for rrset in response.answer) else "unreachable"


def _ldap(ip: str, port: int, spec: dict) -> str:
    naming_context = spec.get("naming_context")
    if not isinstance(naming_context, str) or not re.fullmatch(r"(?i)DC=[a-z0-9-]+(?:,DC=[a-z0-9-]+)+", naming_context):
        raise ValueError("invalid LDAP probe contract")
    authority = f"[{ip}]" if ":" in ip else ip
    result = subprocess.run([
        "/usr/bin/curl", "--silent", "--noproxy", "*", "--proto", "=ldap",
        "--connect-timeout", str(TIMEOUT), "--max-time", str(TIMEOUT),
        f"ldap://{authority}:{port}/?defaultNamingContext?base",
    ], capture_output=True, timeout=TIMEOUT + 1, check=False)
    if result.returncode in {7, 28}:
        return "unreachable"
    expected = ("defaultNamingContext: " + naming_context).lower().encode()
    answers = {line.strip().lower() for line in result.stdout.splitlines()}
    return "reachable" if result.returncode == 0 and expected in answers else "unknown"


def _smb(ip: str, port: int) -> str:
    # SMB2 NEGOTIATE validates protocol availability without authenticating or opening a share.
    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 14, 1)
    request = bytes(header) + struct.pack("<HHHHI16sQ4H", 36, len(dialects), 1, 0, 0, uuid.uuid4().bytes, 0, *dialects)
    with socket.create_connection((ip, port), timeout=TIMEOUT) as connection:
        connection.sendall(len(request).to_bytes(4, "big") + request)
        with connection.makefile("rb") as wire:
            length = int.from_bytes(wire.read(4), "big")
            if not 70 <= length <= 16384:
                return "unknown"
            response = wire.read(length)
    if len(response) != length or response[:4] != b"\xfeSMB":
        return "unknown"
    status, command = struct.unpack_from("<IH", response, 8)
    structure, _, dialect = struct.unpack_from("<HHH", response, 64)
    return "reachable" if status == command == 0 and structure == 65 and dialect in dialects else "unknown"


def _probe(spec: dict) -> str:
    try:
        ip = str(ipaddress.ip_address(spec["ip"]))
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return "unknown"
        protocol = spec["type"]
        if protocol in {"http", "https"}:
            return _http(ip, port, spec)
        if protocol == "dns":
            return _dns(ip, port, spec)
        if protocol == "ldap":
            return _ldap(ip, port, spec)
        if protocol == "smb":
            return _smb(ip, port)
    except (ssl.SSLError, http.client.HTTPException, KeyError, TypeError, ValueError):
        return "unknown"
    except (TimeoutError, ConnectionRefusedError, ConnectionResetError, dns.exception.Timeout):
        return "unreachable"
    except (OSError, dns.exception.DNSException, subprocess.TimeoutExpired):
        return "unknown"
    return "unknown"


def apply_service_probes(nodes: list[dict], configured: dict) -> None:
    targets = [(node, configured[node["id"]]) for node in nodes
               if node["kind"] == "Сервис" and node["id"] in configured]
    if not targets:
        return

    def check(target):
        node, specs = target
        if not isinstance(specs, list) or not specs or len(specs) > 4 or not all(isinstance(spec, dict) for spec in specs):
            return node, {}
        results = [_probe(spec) for spec in specs]
        state = "unreachable" if "unreachable" in results else "reachable" if all(s == "reachable" for s in results) else "unknown"
        methods = {"http": "HTTP", "https": "HTTPS", "dns": "DNS", "ldap": "LDAP", "smb": "SMB2"}
        method = " + ".join(dict.fromkeys(methods.get(spec.get("type"), "") for spec in specs))
        return node, {"state": state, "source": "Проверка сервиса", "method": method,
                      "checkedAt": datetime.now(timezone.utc).isoformat()}

    with ThreadPoolExecutor(max_workers=6) as pool:
        for node, observation in pool.map(check, targets):
            node["reachability"] = observation
