"""Bounded, unauthenticated checks for explicitly configured service endpoints."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
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

TIMEOUT = 3
HTTP_BODY_LIMIT = 32 * 1024
SIP_OPTIONS_WAIT = (0.5, 1.0, 1.5)


def _http_path(path: object) -> str:
    if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9._/-]{0,159}", path) or path.startswith("//"):
        raise ValueError("invalid service probe path")
    return path


def _http(ip: str, port: int, spec: dict) -> dict:
    path = _http_path(spec.get("path"))
    body_expected = spec.get("body")
    body_marker = spec.get("body_contains")
    content_type = spec.get("content_type")
    json_fields = spec.get("json_fields")
    json_unavailable = spec.get("json_unavailable")
    if (not all(isinstance(value, (str, type(None))) for value in (body_expected, body_marker, content_type))
            or not (body_expected or body_marker or content_type or json_fields)):
        raise ValueError("HTTP probe requires a response contract")
    if json_fields is not None or json_unavailable is not None:
        if json_fields is None or body_expected or body_marker:
            raise ValueError("invalid HTTP JSON response contract")
        for fields in (json_fields, json_unavailable):
            if fields is not None and (
                not isinstance(fields, dict) or not fields
                or any(not isinstance(key, str) or not key or not isinstance(value, str) for key, value in fields.items())
            ):
                raise ValueError("invalid HTTP JSON response fields")
        content_type = content_type or "application/json"
    tls = spec["type"] == "https"
    fingerprint = spec.get("tls_sha256")
    server_name = spec.get("tls_server_name")
    ca_file = spec.get("tls_ca_file")
    context = None
    if server_name is not None or ca_file is not None:
        if not tls or fingerprint is not None:
            raise ValueError("CA verification requires HTTPS without a pinned fingerprint")
        if server_name is not None and (
            not isinstance(server_name, str) or len(server_name) > 253
            or any(not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                   for label in server_name.split("."))
        ):
            raise ValueError("invalid HTTPS certificate name")
        if ca_file is not None and (not isinstance(ca_file, str) or not os.path.isabs(ca_file)):
            raise ValueError("HTTPS CA file requires an absolute path")
        context = ssl.create_default_context(cafile=ca_file)
    if fingerprint is not None:
        if not tls or not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
            raise ValueError("invalid HTTPS certificate fingerprint")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    connection = (http.client.HTTPSConnection(server_name or ip, port, timeout=TIMEOUT, context=context) if tls
                  else http.client.HTTPConnection(ip, port, timeout=TIMEOUT))
    observed = {}
    try:
        if server_name:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as transport:
                connection.sock = context.wrap_socket(transport, server_hostname=server_name)
        if fingerprint is not None:
            connection.connect()
            certificate = connection.sock.getpeercert(binary_form=True)
            if not certificate or hashlib.sha256(certificate).hexdigest() != fingerprint.lower():
                return {"state": "unknown", "reason": "http_certificate_pin"}
        connection.request("GET", path, headers={"Accept-Encoding": "identity"})
        response = connection.getresponse()
        observed["httpStatus"] = response.status
        if 500 <= response.status < 600:
            return {**observed, "state": "unreachable", "reason": "http_status"}
        if response.status != 200:
            return {**observed, "state": "unknown", "reason": "http_status"}
        if content_type and response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != content_type:
            return {**observed, "state": "unknown", "reason": "http_content_type"}
        if json_fields is not None:
            payload = response.read(HTTP_BODY_LIMIT + 1)
            if len(payload) > HTTP_BODY_LIMIT:
                return {**observed, "state": "unknown", "reason": "http_body_limit"}
            try:
                document = json.loads(payload)
            except (ValueError, RecursionError):
                return {**observed, "state": "unknown", "reason": "http_invalid_json"}
            if not isinstance(document, dict):
                return {**observed, "state": "unknown", "reason": "http_invalid_json"}
            if json_unavailable and all(document.get(key) == value for key, value in json_unavailable.items()):
                return {**observed, "state": "unreachable", "reason": "http_reported_unavailable"}
            matches = all(document.get(key) == value for key, value in json_fields.items())
        elif body_expected:
            payload = response.read(HTTP_BODY_LIMIT + 1)
            matches = payload.strip() == body_expected.encode()
        elif body_marker:
            matches = body_marker.encode() in response.read(HTTP_BODY_LIMIT)
        else:
            matches = bool(response.read(1))
        if matches:
            return {**observed, "state": "reachable"}
        return {**observed, "state": "unknown", "reason": "http_payload_mismatch"}
    except ssl.SSLCertVerificationError:
        return {**observed, "state": "unknown", "reason": "http_tls_certificate"}
    except ssl.SSLError:
        return {**observed, "state": "unknown", "reason": "http_tls_error"}
    except http.client.HTTPException:
        return {**observed, "state": "unknown", "reason": "http_bad_response"}
    except TimeoutError:
        return {**observed, "state": "unknown", "reason": "timeout"}
    except ConnectionRefusedError:
        return {**observed, "state": "unreachable", "reason": "http_connection_refused"}
    except ConnectionResetError:
        return {**observed, "state": "unreachable", "reason": "http_connection_reset"}
    except OSError:
        return {**observed, "state": "unknown", "reason": "transport_error"}
    finally:
        connection.close()


def _http_probe(spec: dict) -> dict:
    try:
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid HTTP probe port")
        return _http(str(ipaddress.ip_address(spec["ip"])), port, spec)
    except (KeyError, TypeError, ValueError, OSError):
        return {"state": "unknown", "reason": "http_configuration"}


def _zabbix_api(ip: str, port: int, spec: dict) -> str:
    path = _http_path(spec.get("path"))
    connection = http.client.HTTPConnection(ip, port, timeout=TIMEOUT)
    try:
        connection.request("POST", path, b'{"jsonrpc":"2.0","method":"apiinfo.version","params":[],"id":1}',
                           {"Content-Type": "application/json-rpc", "Accept-Encoding": "identity"})
        response = connection.getresponse()
        if 500 <= response.status < 600:
            return "unreachable"
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if response.status != 200 or content_type != "application/json":
            return "unknown"
        body = response.read(HTTP_BODY_LIMIT + 1)
        if len(body) > HTTP_BODY_LIMIT:
            return "unknown"
        payload = json.loads(body)
        if (isinstance(payload, dict) and payload.keys() == {"jsonrpc", "id", "result"}
                and payload["jsonrpc"] == "2.0" and type(payload["id"]) is int and payload["id"] == 1
                and isinstance(payload["result"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", payload["result"])):
            return "reachable"
        return "unknown"
    finally:
        connection.close()


def _dns_query(spec: dict) -> tuple[dns.message.QueryMessage, set[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    record = spec.get("record")
    name = spec.get("name")
    if record not in {"A", "AAAA", "SOA"} or not isinstance(name, str) or not name.endswith("."):
        raise ValueError("invalid DNS probe contract")
    expected = spec.get("expected_addresses")
    expected_ips = set()
    if expected is not None:
        if (record == "SOA" or not isinstance(expected, list) or not 1 <= len(expected) <= 16
                or not all(isinstance(value, str) for value in expected)):
            raise ValueError("invalid DNS address contract")
        expected_ips = {ipaddress.ip_address(value) for value in expected}
        if any(value.version != (4 if record == "A" else 6) for value in expected_ips):
            raise ValueError("DNS address family must match the record type")
    return dns.message.make_query(name, record), expected_ips


def _dns(spec: dict) -> dict:
    try:
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return {"state": "unknown"}
        ip = str(ipaddress.ip_address(spec["ip"]))
        query, expected = _dns_query(spec)
    except (KeyError, TypeError, ValueError, dns.exception.DNSException):
        return {"state": "unknown"}
    record = spec["record"]
    diagnostic = {"name": query.question[0].name.to_text(), "record": record}
    result = {"state": "unknown", "dns": diagnostic}
    try:
        response, used_tcp = dns.query.udp_with_fallback(query, ip, timeout=TIMEOUT, port=port)
        rcode = response.rcode()
        diagnostic.update(rcode=dns.rcode.to_text(rcode), transport="TCP" if used_tcp else "UDP")
        if rcode in {dns.rcode.SERVFAIL, dns.rcode.NXDOMAIN}:
            return {**result, "state": "unreachable"}
        if rcode != dns.rcode.NOERROR:
            return result
        answer = response.resolve_chaining().answer
        if not answer:
            return {**result, "state": "unreachable", "reason": "dns_no_answer"}
        if record in {"A", "AAAA"}:
            addresses = {ipaddress.ip_address(value.address) for value in answer}
            diagnostic["addresses"] = [str(address) for address in sorted(addresses)[:16]]
            if expected and addresses != expected:
                return {**result, "state": "unreachable", "reason": "dns_address_mismatch"}
        return {**result, "state": "reachable"}
    except (TimeoutError, dns.exception.Timeout):
        return {**result, "reason": "timeout"}
    except (ConnectionRefusedError, ConnectionResetError):
        return {**result, "state": "unreachable", "reason": "transport_error"}
    except OSError:
        return {**result, "reason": "transport_error"}
    except (ValueError, dns.exception.DNSException):
        return {**result, "reason": "unexpected_response"}


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
    if result.returncode == 7:
        return "unreachable"
    expected = ("defaultNamingContext: " + naming_context).lower().encode()
    answers = {line.strip().lower() for line in result.stdout.splitlines()}
    return "reachable" if result.returncode == 0 and expected in answers else "unknown"


def _smb(spec: dict) -> dict:
    # SMB2 NEGOTIATE validates protocol availability without authenticating or opening a share.
    dialects = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2"}
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 14, 1)
    request = bytes(header) + struct.pack("<HHHHI16sQ4H", 36, len(dialects), 1, 0, 0, uuid.uuid4().bytes, 0, *dialects)
    unexpected = {"state": "unknown", "reason": "unexpected_response"}
    try:
        ip = str(ipaddress.ip_address(spec["ip"]))
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return {"state": "unknown"}
        with socket.create_connection((ip, port), timeout=TIMEOUT) as connection:
            connection.sendall(len(request).to_bytes(4, "big") + request)
            deadline = monotonic() + TIMEOUT

            def read_exact(size):
                data = bytearray()
                while len(data) < size:
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    connection.settimeout(remaining)
                    chunk = connection.recv(size - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
                return data

            frame = read_exact(4)
            if len(frame) != 4 or frame[0] != 0:
                return unexpected
            length = int.from_bytes(frame, "big")
            if not 128 <= length <= 16384:
                return unexpected
            response = read_exact(length)
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except (ConnectionRefusedError, ConnectionResetError):
        return {"state": "unreachable", "reason": "transport_error"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}
    except (KeyError, TypeError, ValueError):
        return {"state": "unknown"}
    if len(response) != length or response[:4] != b"\xfeSMB":
        return unexpected
    header_size, _, status, command = struct.unpack_from("<HHIH", response, 4)
    flags, next_command, message_id = struct.unpack_from("<IIQ", response, 16)
    if header_size != 64 or status or command or (flags & 3) != 1 or next_command or message_id:
        return unexpected
    structure, security_mode, dialect = struct.unpack_from("<HHH", response, 64)
    buffer_offset, buffer_length = struct.unpack_from("<HH", response, 120)
    if structure != 65 or dialect not in dialects:
        return unexpected
    if buffer_length and not 128 <= buffer_offset <= length - buffer_length:
        return unexpected
    return {"state": "reachable", "smbDialect": dialects[dialect], "smbSigningRequired": bool(security_mode & 2)}


def _openvpn_management() -> dict:
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        return {"state": "unknown"}
    deadline = monotonic() + TIMEOUT
    try:
        with socket.socket(family) as connection:
            connection.settimeout(TIMEOUT)
            connection.connect("/run/openvpn/server.sock")
            connection.sendall(b"state\nstatus 3\n")
            connected = session_table = False
            sessions = 0
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
                        return {"state": "reachable" if connected and sessions else "unknown",
                                "daemonReady": connected, "sessionCount": sessions}
                    fields = line.split(b",", 3)
                    connected |= len(fields) == 4 and fields[0].isdigit() and fields[1:3] == [b"CONNECTED", b"SUCCESS"]
                    session_table |= line.startswith(b"HEADER\tCLIENT_LIST\t")
                    if session_table and line.startswith(b"CLIENT_LIST\t"):
                        sessions += 1
    except OSError:
        pass
    return {"state": "unknown"}


def _enable_udp_error_queue(connection: socket.socket, family: int) -> tuple[int, int] | None:
    if not hasattr(socket, "MSG_ERRQUEUE") or not hasattr(connection, "recvmsg"):
        return None
    # Linux UAPI values are needed on Python versions that lack these constants.
    level, option = ((socket.IPPROTO_IP, getattr(socket, "IP_RECVERR", 11)) if family == socket.AF_INET
                     else (socket.IPPROTO_IPV6, getattr(socket, "IPV6_RECVERR", 25)))
    try:
        connection.setsockopt(level, option, 1)
    except OSError:
        return None
    return level, option


def _sip_udp_failure(connection: socket.socket, option: tuple[int, int] | None,
                     family: int, ip: str, port: int, error: OSError) -> dict:
    fallback = {"state": "unknown", "reason": "connection_refused" if isinstance(error, ConnectionRefusedError)
                else "transport_error"}
    if option is None:
        return fallback
    try:
        connection.setblocking(False)
        _, ancillary, _, destination = connection.recvmsg(1, 128, socket.MSG_ERRQUEUE | getattr(socket, "MSG_DONTWAIT", 0))
    except OSError:
        return fallback
    ip = ip.split("%", 1)[0]
    if not isinstance(destination, tuple) or destination[:2] != (ip, port):
        return fallback

    # sock_extended_err (16 bytes), followed by the offender's sockaddr.
    origin, unreachable_type, port_code, start, end = (
        (2, 3, 3, 20, 24) if family == socket.AF_INET else (3, 1, 4, 24, 40)
    )
    for level, kind, payload in ancillary:
        if (level, kind) != option or len(payload) < end or struct.unpack_from("=H", payload, 16)[0] != family:
            continue
        _, observed_origin, observed_type, code = struct.unpack_from("=IBBB", payload)
        if (observed_origin, observed_type) != (origin, unreachable_type):
            continue
        offender = str(ipaddress.ip_address(payload[start:end]))
        if offender == ip and code == port_code:
            return {"state": "unreachable", "reason": "icmp_port_unreachable", "errorSource": offender}
        return {"state": "unknown", "reason": "icmp_rejected", "errorSource": offender}
    return fallback


def _sip_response_code(response: bytes, transaction: str) -> int | None:
    header, separator, _ = response.partition(b"\r\n\r\n")
    if not separator:
        return None
    status_line, *lines = header.split(b"\r\n")
    status = re.fullmatch(rb"SIP/2\.0 ([1-6][0-9]{2})(?: .*)?", status_line)
    headers = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        if separator:
            name = name.strip().lower()
            headers.setdefault({b"v": b"via", b"i": b"call-id"}.get(name, name), value.strip())
    via = headers.get(b"via", b"").split(b",", 1)[0]
    branch = re.search(rb"(?:^|;)\s*(?i:branch)\s*=\s*([^;\s]+)", via)
    if (status and branch and branch[1] == f"z9hG4bK{transaction}".encode("ascii")
            and headers.get(b"call-id") == transaction.encode("ascii")
            and headers.get(b"cseq", b"").split() == [b"1", b"OPTIONS"]):
        return int(status[1])
    return None


def _sip_options(spec: dict) -> dict:
    port = spec.get("port")
    try:
        ip = str(ipaddress.ip_address(spec["ip"]))
    except (KeyError, ValueError):
        return {"state": "unknown"}
    if type(port) is not int or not 1 <= port <= 65535:
        return {"state": "unknown"}
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    destination = f"[{ip}]" if family == socket.AF_INET6 else ip
    transaction = uuid.uuid4().hex
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(TIMEOUT)
            error_option = _enable_udp_error_queue(connection, family)
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
            payload = "\r\n".join(request).encode("ascii")
            incomplete = {"state": "unknown", "reason": "timeout"}
            for attempts, wait in enumerate(SIP_OPTIONS_WAIT, 1):
                deadline = monotonic() + wait
                connection.settimeout(wait)
                try:
                    connection.sendall(payload)
                    while (remaining := deadline - monotonic()) > 0:
                        connection.settimeout(remaining)
                        code = _sip_response_code(connection.recv(8192), transaction)
                        if code is None:
                            if "responseCode" not in incomplete:
                                incomplete["reason"] = "unexpected_response"
                            continue
                        if code < 200:
                            incomplete.update(reason="sip_response", responseCode=code)
                            continue
                        state = "reachable" if code < 300 else "unreachable" if code in {500, 502, 503, 504} else "unknown"
                        return {"state": state, "reason": "sip_response", "responseCode": code, "attempts": attempts}
                except TimeoutError:
                    continue
                except OSError as exc:
                    return {**_sip_udp_failure(connection, error_option, family, ip, port, exc), "attempts": attempts}
            return {**incomplete, "attempts": attempts}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}


def _ping(ip: str, *, source_ip: str | None = None) -> subprocess.CompletedProcess:
    ip = str(ipaddress.ip_address(ip))
    bind = ["-I", str(ipaddress.ip_address(source_ip))] if source_ip is not None else []
    return subprocess.run(["/usr/bin/ping", "-n", "-c", "1", "-W", "2", *bind, ip],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={**os.environ, "LC_ALL": "C"}, timeout=TIMEOUT, check=False)


def probe_icmp(ip: str, *, source_ip: str | None = None) -> bool:
    return _ping(ip, source_ip=source_ip).returncode == 0


def _icmp_check(ip: str) -> dict:
    try:
        ping = _ping(ip)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"state": "unknown", "reason": "icmp_probe_error"}
    if ping.returncode == 0:
        result = {"state": "reachable"}
        timing = re.search(rb"^\d+ bytes from [^\r\n]+: icmp_seq=\d+ [^\r\n]*\btime=([0-9]+(?:\.[0-9]+)?) ms",
                           ping.stdout, re.MULTILINE)
        if timing:
            result["roundTripMs"] = float(timing[1])
        return result
    if ping.returncode == 1:
        rejected = re.search(rb"^From ([a-fA-F0-9:.]+) icmp_seq=\d+ Destination[^\r\n]*[Uu]nreachable",
                             ping.stdout, re.MULTILINE)
        if rejected:
            try:
                sender = str(ipaddress.ip_address(rejected[1].decode("ascii")))
            except ValueError:
                pass
            else:
                return {"state": "unknown", "reason": "icmp_unreachable", "errorSource": sender}
        return {"state": "unknown", "reason": "icmp_no_echo_reply"}
    return {"state": "unknown", "reason": "icmp_probe_error"}


def _postgresql(spec: dict) -> dict:
    try:
        address = str(ipaddress.ip_address(spec["ip"]))
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return {"state": "unknown"}
        with socket.create_connection((address, port), timeout=TIMEOUT) as connection:
            connection.sendall(struct.pack("!II", 8, 80877103))  # PostgreSQL SSLRequest
            reply = connection.recv(1)
            if reply == b"N":
                return {"state": "reachable", "postgresqlTls": "declined"}
            if reply != b"S":
                return {"state": "unreachable", "reason": "unexpected_response"}
            # Check negotiation only. No PostgreSQL startup or authentication message is sent.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                with context.wrap_socket(connection) as encrypted:
                    return {"state": "reachable", "postgresqlTls": "negotiated", "tlsVersion": encrypted.version()}
            except OSError:
                return {"state": "unknown", "postgresqlTls": "failed", "reason": "postgresql_tls_handshake"}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except (ConnectionRefusedError, ConnectionResetError):
        return {"state": "unreachable", "reason": "transport_error"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}
    except (KeyError, ValueError, TypeError):
        return {"state": "unknown"}


def _probe(spec: dict) -> str:
    try:
        protocol = spec["type"]
        if protocol == "icmp":
            return _icmp_check(spec["ip"])["state"]
        if protocol == "dns":
            return _dns(spec)["state"]
        if protocol in {"http", "https"}:
            return _http_probe(spec)["state"]
        if protocol == "postgresql":
            return _postgresql(spec)["state"]
        if protocol == "smb":
            return _smb(spec)["state"]
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return "unknown"
        if protocol == "openvpn_management":
            return _openvpn_management()["state"]
        ip = str(ipaddress.ip_address(spec["ip"]))
        if protocol == "zabbix_api":
            return _zabbix_api(ip, port, spec)
        if protocol == "ldap":
            return _ldap(ip, port, spec)
    except (ssl.SSLError, http.client.HTTPException, KeyError, TypeError, ValueError):
        return "unknown"
    except (ConnectionRefusedError, ConnectionResetError):
        return "unreachable"
    except (OSError, dns.exception.DNSException, subprocess.TimeoutExpired):
        return "unknown"
    return "unknown"


def apply_service_probes(nodes: list[dict], configured: dict) -> None:
    targets = [(node, configured[node["id"]]) for node in nodes if node["id"] in configured]
    if not targets:
        return

    def check(target):
        node, specs = target
        if not isinstance(specs, list) or not specs or len(specs) > 4 or not all(isinstance(spec, dict) for spec in specs):
            return node, None
        skip_reason = ""
        if node["kind"] != "Сервис" or "probeTargetIP" in node:
            target_address = node.get("probeTargetIP")
            if not target_address:
                skip_reason = "probe_target_unconfirmed"
            elif any(spec.get("ip") != target_address for spec in specs):
                skip_reason = "probe_target_mismatch"
        methods = {"http": "HTTP", "https": "HTTPS", "dns": "DNS", "ldap": "LDAP", "smb": "SMB2",
                   "zabbix_api": "Zabbix API", "postgresql": "PostgreSQL SSLRequest",
                   "openvpn_management": "OpenVPN Management", "sip_options": "SIP OPTIONS (UDP)", "icmp": "ICMP"}
        checks = []
        primary = []
        for spec in specs:
            protocol = spec.get("type") if isinstance(spec.get("type"), str) else ""
            method = methods.get(protocol, "")
            supplemental = node["kind"] != "Сервис" or spec.get("supplemental") is True
            component = not supplemental and spec.get("component") is True
            if node["kind"] != "Сервис":
                method = "ICMP адреса из инвентаря"
            port = spec.get("port")
            valid_port = port if type(port) is int and 1 <= port <= 65535 else None
            if skip_reason:
                details = {"state": "unknown", "skipped": True, "reason": skip_reason}
            elif protocol == "openvpn_management" and valid_port is not None:
                details = {**_openvpn_management(), "configuredPort": valid_port}
                valid_port = None
            elif protocol == "sip_options":
                details = _sip_options(spec)
            elif protocol == "dns":
                details = _dns(spec)
            elif protocol == "icmp":
                details = _icmp_check(spec.get("ip"))
            elif protocol == "postgresql":
                details = _postgresql(spec)
            elif protocol == "smb":
                details = _smb(spec)
            elif protocol in {"http", "https"}:
                details = _http_probe(spec)
            else:
                details = {"state": _probe(spec)}
            if node["kind"] != "Сервис" and protocol == "icmp" and details["state"] == "reachable":
                details["reason"] = "icmp_identity_unconfirmed"
            observation = {
                **details,
                **({"supplemental": True} if supplemental else {"required": True}),
                **({"component": True} if component else {}),
                "source": "UI_VPN", "method": method,
                "port": valid_port,
                "path": spec.get("path") if protocol in {"http", "https", "zabbix_api"} else None,
                "target": spec.get("ip") if not skip_reason and (
                    protocol in {"icmp", "sip_options", "zabbix_api", "postgresql", "dns", "smb"} or "probeTargetIP" in node
                ) else None,
                "checkedAt": datetime.now(timezone.utc).isoformat(),
            }
            checks.append(observation)
            if not supplemental and not component and not skip_reason:
                primary.append(observation)
        node.setdefault("serviceChecks", []).extend(checks)
        if not primary:
            return node, None
        results = {check["state"] for check in primary}
        state = "reachable" if "reachable" in results else "unreachable" if results == {"unreachable"} else "unknown"
        method = " + ".join(dict.fromkeys(check["method"] for check in primary if check["method"]))
        return node, {"state": state, "source": "Проверка сервиса", "method": method,
                      "checkedAt": primary[-1]["checkedAt"]}

    with ThreadPoolExecutor(max_workers=6) as pool:
        for node, observation in pool.map(check, targets):
            if observation is not None:
                node["reachability"] = observation
