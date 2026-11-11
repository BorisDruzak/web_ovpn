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
from time import monotonic

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


def _openvpn_management() -> str:
    # A successful status response with a session confirms a live tunnel.
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        return "unknown"
    deadline = monotonic() + TIMEOUT
    with socket.socket(family) as connection:
        connection.settimeout(TIMEOUT)
        try:
            connection.connect("/run/openvpn/server.sock")
            connection.sendall(b"state\nstatus 3\n")
            connected = session_table = active_session = False
            with connection.makefile("rb") as wire:
                for _ in range(4096):
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        break
                    connection.settimeout(remaining)
                    line = wire.readline(4097)
                    if not line or len(line) > 4096:
                        break
                    if line.strip() == b"END" and session_table:
                        return "reachable" if connected and active_session else "unknown"
                    fields = line.split(b",", 3)
                    connected |= len(fields) == 4 and fields[0].isdigit() and fields[1:3] == [b"CONNECTED", b"SUCCESS"]
                    session_table |= line.startswith(b"HEADER\tCLIENT_LIST\t")
                    active_session |= line.startswith(b"CLIENT_LIST\t")
        except OSError:
            pass
    return "unknown"


def _sip_options(ip: str, port: int) -> str:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    destination = f"[{ip}]" if family == socket.AF_INET6 else ip
    transaction = uuid.uuid4().hex
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(TIMEOUT)
            connection.connect((ip, port))
            local, local_port, *_ = connection.getsockname()
            if family == socket.AF_INET6:
                local = f"[{local}]"
            uri = f"sip:{destination}:{port}"
            request = [
                f"OPTIONS {uri} SIP/2.0",
                f"Via: SIP/2.0/UDP {local}:{local_port};branch=z9hG4bK{transaction};rport",
                "Max-Forwards: 0", f"To: <{uri}>",
                f"From: <sip:monitor@{local}>;tag={transaction}", f"Call-ID: {transaction}",
                "CSeq: 1 OPTIONS", "Content-Length: 0", "", "",
            ]
            connection.sendall("\r\n".join(request).encode("ascii"))
            response = connection.recv(8192)
    except OSError:
        return "unknown"
    head = response.partition(b"\r\n\r\n")[0].split(b"\r\n")
    status = re.fullmatch(rb"SIP/2\.0 ([1-6][0-9]{2})(?: .*)?", head[0])
    headers = {}
    for line in head[1:]:
        name, separator, value = line.partition(b":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    if (not status or headers.get(b"call-id", headers.get(b"i")) != transaction.encode()
            or headers.get(b"cseq", b"").split() != [b"1", b"OPTIONS"]):
        return "unknown"
    code = int(status[1])
    if 200 <= code < 300:
        return "reachable"
    return "unreachable" if code in {500, 502, 503, 504} else "unknown"


def probe_icmp(ip: str) -> bool:
    ip = str(ipaddress.ip_address(ip))
    result = subprocess.run(["/usr/bin/ping", "-n", "-c", "1", "-W", "2", ip],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=TIMEOUT, check=False)
    return result.returncode == 0


def _probe(spec: dict) -> str:
    try:
        protocol = spec["type"]
        if protocol == "icmp":
            return "reachable" if probe_icmp(spec["ip"]) else "unknown"
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return "unknown"
        if protocol == "openvpn_management":
            return _openvpn_management()
        ip = str(ipaddress.ip_address(spec["ip"]))
        if protocol in {"http", "https"}:
            return _http(ip, port, spec)
        if protocol == "dns":
            return _dns(ip, port, spec)
        if protocol == "ldap":
            return _ldap(ip, port, spec)
        if protocol == "smb":
            return _smb(ip, port)
        if protocol == "sip_options":
            return _sip_options(ip, port)
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
            return node, None
        methods = {"http": "HTTP", "https": "HTTPS", "dns": "DNS", "ldap": "LDAP", "smb": "SMB2",
                   "openvpn_management": "OpenVPN Management (UDP)", "sip_options": "SIP OPTIONS (UDP)", "icmp": "ICMP"}
        checks = []
        required = []
        for spec in specs:
            protocol = spec.get("type")
            method = methods.get(protocol, "") if isinstance(protocol, str) else ""
            port = spec.get("port")
            observation = {
                "state": _probe(spec), "method": method,
                "port": port if type(port) is int and 1 <= port <= 65535 else None,
                "path": spec.get("path") if method in {"HTTP", "HTTPS"} else None,
                "target": spec.get("ip") if protocol in {"icmp", "sip_options"} else None,
                "checkedAt": datetime.now(timezone.utc).isoformat(),
            }
            checks.append(observation)
            if spec.get("supplemental") is not True:
                required.append(observation)
        node.setdefault("serviceChecks", []).extend(checks)
        if not required:
            return node, None
        results = [check["state"] for check in required]
        state = "unreachable" if "unreachable" in results else "reachable" if all(s == "reachable" for s in results) else "unknown"
        method = " + ".join(dict.fromkeys(check["method"] for check in required if check["method"]))
        return node, {"state": state, "source": "Проверка сервиса", "method": method,
                      "checkedAt": checks[-1]["checkedAt"]}

    with ThreadPoolExecutor(max_workers=6) as pool:
        for node, observation in pool.map(check, targets):
            if observation is not None:
                node["reachability"] = observation
