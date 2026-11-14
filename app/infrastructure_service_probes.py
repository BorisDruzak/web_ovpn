"""Bounded, unauthenticated checks for explicitly configured service endpoints."""

from __future__ import annotations

import base64
import gzip
import hashlib
import http.client
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import datetime, timezone
from html.parser import HTMLParser
from time import monotonic, sleep, time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import ldap3
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from ldap3.core.exceptions import LDAPException

TIMEOUT = 3
HTTP_BODY_LIMIT = 32 * 1024
SIP_OPTIONS_WAIT = (0.5, 1.0, 1.5)
IPMI_PORT = 623
RMCP_ASF_HEADER = bytes.fromhex("0600ff06000011be")
MAX_CONFIGURED_SERVICE_PROBES = 8
PROBE_METHODS = {
    "http": "HTTP", "https": "HTTPS", "dns": "DNS", "ldap": "LDAP", "ldaps": "LDAPS RootDSE", "smb": "SMB2",
    "tcp_connect": "TCP", "ntp": "NTP (UDP)", "winrm": "WinRM HTTP", "rdp_negotiation": "RDP Negotiation",
    "smb_mount": "SMB Mount", "zabbix_api": "Zabbix API", "postgresql": "PostgreSQL SSLRequest",
    "openvpn_management": "OpenVPN Management", "openvpn_tunnel": "OpenVPN TUN",
    "sip_options": "SIP OPTIONS (UDP)", "icmp": "ICMP", "vlan_transit": "ICMP · VLAN",
    "wireguard_policy": "Маршрут · WireGuard", "ipmi_lan": "IPMI LAN (UDP)", "rtsp_options": "RTSP OPTIONS",
    "ssh_identification": "SSH", "ftp_features": "FTP FEAT", "tls_certificate": "Сертификат TLS",
    "tls_handshake": "Рукопожатие TLS",
    "mongodb_ping": "MongoDB ping", "amqp_start": "AMQP Connection.Start", "redis_ping": "Redis PING",
}
DEPENDENCY_PROTOCOLS = {"mongodb_ping", "amqp_start", "redis_ping"}
LDAP_NAMING_CONTEXT = re.compile(r"DC=[a-z0-9-]+(?:,DC=[a-z0-9-]+)+", re.IGNORECASE)


def _http_path(path: object) -> str:
    if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9._/-]{0,159}", path) or path.startswith("//"):
        raise ValueError("invalid service probe path")
    return path


def _valid_http_hostname(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 253 and all(
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in value.split(".")
    )


class _AssetReferences(HTMLParser):
    _written_link = re.compile(r"""^[ \t]*document\.write\((['"])(<link[ \t][^<>\r\n]*>)\1\);[ \t]*\r?$""", re.M)

    def __init__(self, prefix: str, directory: str, *, stylesheet: bool):
        super().__init__()
        self.prefix = prefix
        self.directory = directory
        self.stylesheet = stylesheet
        suffix = ".css" if stylesheet else ".js"
        self.filename = re.compile(
            re.escape(directory + prefix) + r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,100}" + re.escape(suffix)
        )
        self.matches = []
        self.has_base = False
        self.inline_script = False

    def handle_starttag(self, tag, attrs):
        if tag == "base":
            self.has_base |= any(name == "href" for name, _ in attrs)
        if self.stylesheet:
            if tag == "script":
                self.inline_script = not any(name == "src" for name, _ in attrs)
                return
            if tag != "link" or [value.lower() for name, value in attrs if name == "rel" and value] != ["stylesheet"]:
                return
            attribute = "href"
        else:
            if tag != "script":
                return
            attribute = "src"
        sources = [value for name, value in attrs if name == attribute]
        if len(sources) == 1 and sources[0] and self.filename.fullmatch(sources[0]):
            self.matches.append(sources[0])

    def handle_endtag(self, tag):
        if tag == "script":
            self.inline_script = False

    def handle_data(self, data):
        if self.inline_script:
            for match in self._written_link.finditer(data):
                parser = _AssetReferences(self.prefix, self.directory, stylesheet=True)
                parser.feed(match[2])
                parser.close()
                self.matches.extend(parser.matches)


def _matches_json_fields(document: dict, fields: dict) -> bool:
    for path, expected in fields.items():
        value = document
        for key in path.split("."):
            value = value.get(key) if isinstance(value, dict) else None
        if type(value) is not type(expected) or value != expected:
            return False
    return True


def _redfish_root_version(document: dict) -> str | None:
    version = document.get("RedfishVersion")
    if document.get("Id") != "RootService" or not isinstance(version, str) or not re.fullmatch(
        r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", version,
    ):
        return None
    for collection in ("Managers", "Systems"):
        link = document.get(collection)
        if not isinstance(link, dict) or link.get("@odata.id") != f"/redfish/v1/{collection}":
            return None
    return version


def _oidc_rs256_key(key: dict) -> bool:
    kid = key.get("kid")
    if (key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256" or key.get("use", "sig") != "sig"
            or not isinstance(kid, str) or not kid.strip() or any(p in key for p in ("d", "p", "q", "dp", "dq", "qi", "oth"))):
        return False
    operations = key.get("key_ops")
    if operations is not None and (not isinstance(operations, list) or "verify" not in operations):
        return False
    exponent, modulus = key.get("e"), key.get("n")
    if not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,1400}", value)
               for value in (exponent, modulus)):
        return False
    try:
        e, n = (int.from_bytes(base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True), "big")
                for value in (exponent, modulus))
        return n % 2 == 1 and rsa.RSAPublicNumbers(e, n).public_key().key_size >= 2048
    except ValueError:
        return False


def _is_digest_challenge(value: str) -> bool:
    scheme, _, parameters = value.partition(" ")
    if scheme.lower() != "digest" or len(parameters) > 4096:
        return False
    parameter = re.compile(r'[ \t]*([a-zA-Z][a-zA-Z0-9_-]*)[ \t]*=[ \t]*'
                           r'("(?:[^"\\\r\n]|\\[^\r\n])*"|[!#$%&\x27*+\-.^_\x60|~0-9A-Za-z]+)'
                           r'[ \t]*(,|$)')
    seen = {}
    position = 0
    while position < len(parameters):
        match = parameter.match(parameters, position)
        if match is None or match[1].lower() in seen or match[3] and match.end() == len(parameters):
            return False
        seen[match[1].lower()] = match[2]
        position = match.end()
    return all(seen.get(name, "").startswith('"') and len(seen[name]) > 2 for name in ("realm", "nonce"))


def _http(ip: str, port: int, spec: dict, *, references: _AssetReferences | None = None,
          asset_type: str | None = None) -> dict:
    path = _http_path(spec.get("path"))
    body_expected = spec.get("body")
    body_marker = spec.get("body_contains")
    content_type = spec.get("content_type")
    json_fields = spec.get("json_fields")
    json_unavailable = spec.get("json_unavailable")
    redfish_root = spec.get("redfish_service_root", False)
    oidc_jwks = spec.get("oidc_rs256_jwks", False)
    basic_auth_realm = spec.get("basic_auth_realm")
    digest_challenge = spec.get("digest_auth_challenge", False)
    redirect_port = spec.get("https_redirect_port")
    allow_gzip = spec.get("allow_gzip", False)
    tls = spec["type"] == "https"
    if references is not None:
        content_type = "text/html"
    if asset_type is not None:
        content_type = asset_type
    if type(redfish_root) is not bool or (redfish_root and (
        not tls or path != "/redfish/v1/"
        or any(value is not None for value in (body_expected, body_marker, json_fields, json_unavailable))
        or content_type not in (None, "application/json")
    )):
        raise ValueError("invalid Redfish Service Root probe")
    if type(oidc_jwks) is not bool or (oidc_jwks and (
        not tls or redfish_root
        or any(value is not None for value in (body_expected, body_marker, json_fields, json_unavailable))
        or content_type not in (None, "application/json")
    )):
        raise ValueError("invalid OIDC JWKS probe")
    if redfish_root or oidc_jwks:
        content_type = "application/json"
    if type(allow_gzip) is not bool:
        raise ValueError("allow_gzip requires a boolean")
    if type(digest_challenge) is not bool:
        raise ValueError("digest_auth_challenge requires a boolean")
    if "https_redirect_port" in spec:
        if (type(redirect_port) is not int or not 1 <= redirect_port <= 65535 or tls
                or digest_challenge or redfish_root or oidc_jwks
                or any(value is not None for value in (body_expected, body_marker, content_type, json_fields,
                                                       json_unavailable, basic_auth_realm, spec.get("http_host")))):
            raise ValueError("invalid same-address HTTPS redirect contract")
    elif digest_challenge:
        if any(value is not None for value in (body_expected, body_marker, content_type, json_fields,
                                                json_unavailable, basic_auth_realm)):
            raise ValueError("invalid HTTP Digest authentication challenge contract")
    elif basic_auth_realm is not None:
        if (not tls or not (spec.get("tls_server_name") or spec.get("tls_sha256"))
                or not isinstance(basic_auth_realm, str)
                or not re.fullmatch(r"[A-Za-z0-9 _.-]{0,80}", basic_auth_realm)
                or any(value is not None for value in (body_expected, body_marker, content_type, json_fields, json_unavailable))):
            raise ValueError("invalid HTTPS Basic authentication challenge contract")
    elif (not all(isinstance(value, (str, type(None))) for value in (body_expected, body_marker, content_type))
            or not (body_expected or body_marker or content_type or json_fields)):
        raise ValueError("HTTP probe requires a response contract")
    if json_fields is not None or json_unavailable is not None:
        if json_fields is None or body_expected or body_marker:
            raise ValueError("invalid HTTP JSON response contract")
        for fields in (json_fields, json_unavailable):
            if fields is not None and (
                not isinstance(fields, dict) or not fields
                or any(not isinstance(key, str) or not all(key.split(".")) or type(value) not in (str, bool)
                       for key, value in fields.items())
            ):
                raise ValueError("invalid HTTP JSON response fields")
        content_type = content_type or "application/json"
    http_host = spec.get("http_host")
    if http_host is not None and (tls or not _valid_http_hostname(http_host)):
        raise ValueError("invalid HTTP host")
    fingerprint = spec.get("tls_sha256")
    server_name = spec.get("tls_server_name")
    ca_file = spec.get("tls_ca_file")
    report_tls_expiry = spec.get("report_tls_expiry", False)
    if type(report_tls_expiry) is not bool or (report_tls_expiry and (not tls or not server_name or fingerprint is not None)):
        raise ValueError("certificate expiry reporting requires name-validated HTTPS")
    context = None
    if server_name is not None or ca_file is not None:
        if not tls or fingerprint is not None:
            raise ValueError("CA verification requires HTTPS without a pinned fingerprint")
        if server_name is not None and not _valid_http_hostname(server_name):
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
    headers = {"Accept-Encoding": "gzip, identity" if allow_gzip else "identity"}
    if http_host is not None:
        observed["httpHost"] = http_host
        headers["Host"] = http_host if port == 80 else f"{http_host}:{port}"
    try:
        if server_name:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as transport:
                connection.sock = context.wrap_socket(transport, server_hostname=server_name)
            if report_tls_expiry:
                certificate = connection.sock.getpeercert() or {}
                expires = certificate.get("notAfter")
                if isinstance(expires, str):
                    try:
                        observed["tlsExpiresAt"] = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc).isoformat()
                    except (ValueError, OverflowError, OSError):
                        pass
                    else:
                        observed["tlsVersion"] = connection.sock.version()
        if fingerprint is not None:
            connection.connect()
            certificate = connection.sock.getpeercert(binary_form=True)
            if not certificate or hashlib.sha256(certificate).hexdigest() != fingerprint.lower():
                return {"state": "unknown", "reason": "http_certificate_pin"}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        observed["httpStatus"] = response.status
        if 500 <= response.status < 600:
            return {**observed, "state": "unreachable", "reason": "http_status"}
        if redirect_port is not None:
            if response.status not in (301, 302, 303, 307, 308):
                return {**observed, "state": "unreachable", "reason": "http_status"}
            host = f"[{ip}]" if ":" in ip else ip
            authority = host if redirect_port == 443 else f"{host}:{redirect_port}"
            locations = [value.strip() for name, value in response.getheaders() if name.lower() == "location"]
            if locations != [f"https://{authority}{path}"]:
                return {**observed, "state": "unreachable", "reason": "http_payload_mismatch"}
            return {**observed, "state": "reachable"}
        if digest_challenge or basic_auth_realm is not None:
            if response.status != 401:
                return {**observed, "state": "unknown", "reason": "http_status"}
            challenges = [value.strip() for name, value in response.getheaders() if name.lower() == "www-authenticate"]
            if digest_challenge:
                if any(map(_is_digest_challenge, challenges)):
                    return {**observed, "state": "reachable", "httpAuthChallenge": "Digest"}
                return {**observed, "state": "unknown", "reason": "http_payload_mismatch"}
            expected = (rf'(?i:Basic[ \t]+realm)[ \t]*=[ \t]*"{re.escape(basic_auth_realm)}"[ \t]*(?:,|$)'
                        if basic_auth_realm else r"(?i:Basic)$")
            if any(re.match(expected, value) for value in challenges):
                return {**observed, "state": "reachable"}
            return {**observed, "state": "unknown", "reason": "http_payload_mismatch"}
        if response.status != 200:
            return {**observed, "state": "unknown", "reason": "http_status"}
        if content_type:
            actual_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            allowed_types = (
                ("text/javascript", "application/javascript", "application/x-javascript")
                if asset_type == "text/javascript" else (content_type,)
            )
            if actual_type not in allowed_types:
                return {**observed, "state": "unknown", "reason": "http_content_type"}
        read = response.read
        if allow_gzip:
            encoding = response.getheader("Content-Encoding", "").strip().lower()
            if encoding == "gzip":
                compressed = read(HTTP_BODY_LIMIT + 1)
                if len(compressed) > HTTP_BODY_LIMIT:
                    return {**observed, "state": "unknown", "reason": "http_body_limit"}
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
                        decoded = stream.read(HTTP_BODY_LIMIT + 1)
                except (gzip.BadGzipFile, EOFError, zlib.error):
                    return {**observed, "state": "unknown", "reason": "http_content_encoding"}
                if len(decoded) > HTTP_BODY_LIMIT:
                    return {**observed, "state": "unknown", "reason": "http_body_limit"}
                read = io.BytesIO(decoded).read
            elif encoding not in ("", "identity"):
                return {**observed, "state": "unknown", "reason": "http_content_encoding"}
        if references is not None:
            payload = read(HTTP_BODY_LIMIT + 1)
            if len(payload) > HTTP_BODY_LIMIT:
                return {**observed, "state": "unknown", "reason": "http_body_limit"}
            references.feed(payload.decode("utf-8", errors="replace"))
            references.close()
            if references.has_base or len(references.matches) != 1:
                return {**observed, "state": "unreachable", "reason": "http_payload_mismatch"}
            return {**observed, "state": "reachable"}
        if json_fields is not None or redfish_root or oidc_jwks:
            payload = read(HTTP_BODY_LIMIT + 1)
            if len(payload) > HTTP_BODY_LIMIT:
                return {**observed, "state": "unknown", "reason": "http_body_limit"}
            try:
                document = json.loads(payload)
            except (ValueError, RecursionError):
                return {**observed, "state": "unknown", "reason": "http_invalid_json"}
            if not isinstance(document, dict):
                return {**observed, "state": "unknown", "reason": "http_invalid_json"}
            if redfish_root:
                if version := _redfish_root_version(document):
                    return {**observed, "state": "reachable", "redfishVersion": version}
                return {**observed, "state": "unknown", "reason": "http_payload_mismatch"}
            if oidc_jwks:
                keys = document.get("keys")
                if not isinstance(keys, list) or not all(isinstance(key, dict) for key in keys):
                    return {**observed, "state": "unknown", "reason": "http_payload_mismatch"}
                if any(_oidc_rs256_key(key) for key in keys):
                    return {**observed, "state": "reachable"}
                return {**observed, "state": "unreachable", "reason": "oidc_rs256_key_missing"}
            if json_unavailable and _matches_json_fields(document, json_unavailable):
                return {**observed, "state": "unreachable", "reason": "http_reported_unavailable"}
            matches = _matches_json_fields(document, json_fields)
        elif body_expected:
            payload = read(HTTP_BODY_LIMIT + 1)
            matches = payload.strip() == body_expected.encode()
        elif body_marker:
            matches = body_marker.encode() in read(HTTP_BODY_LIMIT)
        else:
            matches = bool(read(1))
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


def _http_asset_probe(address: str, port: int, spec: dict) -> dict:
    stylesheet = "stylesheet_href_prefix" in spec
    if ((stylesheet and ("script_src_prefix" in spec or "script_src_directory" in spec))
            or (not stylesheet and "stylesheet_href_directory" in spec)):
        raise ValueError("conflicting HTTP asset probe settings")
    prefix = spec["stylesheet_href_prefix" if stylesheet else "script_src_prefix"]
    path = _http_path(spec.get("path"))
    directory_key = "stylesheet_href_directory" if stylesheet else "script_src_directory"
    directory = _http_path(spec[directory_key]) if directory_key in spec else ""
    if (not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,31}\.?", prefix)
            or not (directory or path).endswith("/")
            or any(part in (".", "..") for candidate in (path, directory) for part in candidate.split("/"))
            or any(key in spec for key in ("body", "body_contains", "content_type", "json_fields",
                                           "json_unavailable", "basic_auth_realm", "digest_auth_challenge",
                                           "redfish_service_root", "oidc_rs256_jwks", "allow_gzip",
                                           "https_redirect_port"))):
        raise ValueError("invalid HTTP asset probe contract")
    references = _AssetReferences(prefix, directory, stylesheet=stylesheet)
    result = _http(address, port, spec, references=references)
    if result["state"] != "reachable":
        return result
    asset_path = _http_path(references.matches[0] if directory else path + references.matches[0])
    asset_type = "text/css" if stylesheet else "text/javascript"
    asset = _http(address, port, {**spec, "path": asset_path}, asset_type=asset_type)
    if (asset.get("httpStatus") in (404, 410)
            or asset.get("reason") in ("http_content_type", "http_payload_mismatch")):
        asset["state"] = "unreachable"
    return {**asset, "path": asset_path}


def _http_probe(spec: dict) -> dict:
    try:
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid HTTP probe port")
        retry_refused = spec.get("retry_connection_refused", False)
        if type(retry_refused) is not bool:
            raise ValueError("retry_connection_refused requires a boolean")
        address = str(ipaddress.ip_address(spec["ip"]))
        if any(key in spec for key in ("script_src_prefix", "stylesheet_href_prefix", "stylesheet_href_directory")):
            return _http_asset_probe(address, port, spec)
        result = _http(address, port, spec)
        if retry_refused and result.get("reason") == "http_connection_refused":
            sleep(2)
            return {**_http(address, port, spec), "attempts": 2}
        return result
    except (KeyError, TypeError, ValueError, OSError):
        return {"state": "unknown", "reason": "http_configuration"}


def _zabbix_api(spec: dict) -> dict:
    try:
        path = _http_path(spec.get("path"))
        address = str(ipaddress.ip_address(spec["ip"]))
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid Zabbix port")
    except (KeyError, ValueError):
        return {"state": "unknown", "reason": "http_configuration"}
    connection = http.client.HTTPConnection(address, port, timeout=TIMEOUT)
    observed = {}
    try:
        connection.request("POST", path, b'{"jsonrpc":"2.0","method":"apiinfo.version","params":[],"id":1}',
                           {"Content-Type": "application/json-rpc", "Accept-Encoding": "identity"})
        response = connection.getresponse()
        observed["httpStatus"] = response.status
        if 500 <= response.status < 600:
            return {**observed, "state": "unreachable", "reason": "http_status"}
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if response.status != 200 or content_type != "application/json":
            return {**observed, "state": "unknown", "reason": "http_status" if response.status != 200 else "http_content_type"}
        body = response.read(HTTP_BODY_LIMIT + 1)
        if len(body) > HTTP_BODY_LIMIT:
            return {**observed, "state": "unknown", "reason": "http_body_limit"}
        payload = json.loads(body)
        if (isinstance(payload, dict) and payload.keys() == {"jsonrpc", "id", "result"}
                and payload["jsonrpc"] == "2.0" and type(payload["id"]) is int and payload["id"] == 1
                and isinstance(payload["result"], str) and re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", payload["result"])):
            return {**observed, "state": "reachable", "zabbixVersion": payload["result"]}
        return {**observed, "state": "unknown", "reason": "http_payload_mismatch"}
    except (ValueError, UnicodeError):
        return {**observed, "state": "unknown", "reason": "http_invalid_json"}
    except (ConnectionRefusedError, ConnectionResetError) as exc:
        reason = "http_connection_refused" if isinstance(exc, ConnectionRefusedError) else "http_connection_reset"
        return {**observed, "state": "unreachable", "reason": reason}
    except TimeoutError:
        return {**observed, "state": "unknown", "reason": "timeout"}
    except (OSError, http.client.HTTPException):
        return {**observed, "state": "unknown", "reason": "http_bad_response"}
    finally:
        connection.close()


def _dns_query(spec: dict) -> tuple[dns.message.QueryMessage, set[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    record = spec.get("record")
    name = spec.get("name")
    if record not in {"A", "AAAA", "SOA", "SRV"} or not isinstance(name, str) or not name.endswith("."):
        raise ValueError("invalid DNS probe contract")
    expected = spec.get("expected_addresses")
    expected_ips = set()
    if expected is not None:
        if (record not in {"A", "AAAA"} or not isinstance(expected, list) or not 1 <= len(expected) <= 16
                or not all(isinstance(value, str) for value in expected)):
            raise ValueError("invalid DNS address contract")
        expected_ips = {ipaddress.ip_address(value) for value in expected}
        if any(value.version != (4 if record == "A" else 6) for value in expected_ips):
            raise ValueError("DNS address family must match the record type")
    return dns.message.make_query(name, record), expected_ips


def _expected_srv_records(spec: dict) -> set[tuple[str, int]]:
    values = spec.get("expected_srv_records")
    if values is None:
        return set()
    if spec.get("record") != "SRV" or not isinstance(values, list) or not 1 <= len(values) <= 16:
        raise ValueError("invalid DNS SRV contract")
    expected = set()
    for value in values:
        target = value.get("target") if isinstance(value, dict) else None
        port = value.get("port") if isinstance(value, dict) else None
        if (not isinstance(target, str) or not target.endswith(".") or not _valid_http_hostname(target[:-1])
                or type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("invalid DNS SRV target or port")
        expected.add((target.lower(), port))
    return expected


def _explicit_dns_udp(query: dns.message.QueryMessage, ip: str, port: int,
                      source: str | None) -> tuple[dns.message.Message | None, dict | None]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    expiration = time() + TIMEOUT
    unexpected = None
    unexpected_response = None
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        connection.setblocking(False)
        if source is not None:
            connection.bind((source, 0))
        dns.query.send_udp(connection, query, (ip, port), expiration)
        while time() < expiration:
            try:
                response, _, sender = dns.query.receive_udp(connection, expiration=expiration)
            except dns.exception.Timeout:
                break
            except dns.exception.DNSException:
                continue
            if not query.is_response(response):
                continue
            address = str(ipaddress.ip_address(sender[0]))
            if (address, sender[1]) == (ip, port):
                return response, None
            if response.question == query.question and unexpected is None:
                unexpected = {"address": address, "port": sender[1]}
                unexpected_response = response
    return unexpected_response, unexpected


def _dns(spec: dict, *, source: str | None = None) -> dict:
    transport = spec.get("transport", "auto")
    if transport not in ("auto", "udp", "tcp"):
        return {"state": "unknown"}
    try:
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return {"state": "unknown"}
        ip = str(ipaddress.ip_address(spec["ip"]))
        query, expected = _dns_query(spec)
        expected_srv = _expected_srv_records(spec)
    except (KeyError, TypeError, ValueError, dns.exception.DNSException):
        return {"state": "unknown"}
    record = spec["record"]
    diagnostic = {"name": query.question[0].name.to_text(), "record": record}
    if expected:
        diagnostic["expectedAddresses"] = [str(address) for address in sorted(expected)]
    if transport != "auto":
        diagnostic["transport"] = transport.upper()
    result = {"state": "unknown", "dns": diagnostic}
    options = {"timeout": TIMEOUT, "port": port}
    if source is not None:
        options["source"] = source
    if "route_via" in spec:
        route = _local_ipv4_route(ip, spec["route_via"])
        result["localRoute"] = route
        if route["state"] != "reachable":
            reason = "dns_route_mismatch" if route["state"] == "unreachable" else "dns_route_unconfirmed"
            return {**result, "reason": reason}
        options["source"] = route["sourceIP"]
    try:
        if transport == "auto":
            response, used_tcp = dns.query.udp_with_fallback(query, ip, **options)
            diagnostic["transport"] = "TCP" if used_tcp else "UDP"
        elif transport == "udp":
            response, unexpected = _explicit_dns_udp(query, ip, port, options.get("source"))
            if unexpected:
                if response is not None:
                    rcode = response.rcode()
                    unexpected["rcode"] = dns.rcode.to_text(rcode)
                    if rcode == dns.rcode.NOERROR and record in ("A", "AAAA") and not (response.flags & dns.flags.TC):
                        try:
                            answer = response.resolve_chaining().answer
                            if answer:
                                addresses = {ipaddress.ip_address(value.address) for value in answer}
                                unexpected["addresses"] = [str(address) for address in sorted(addresses)[:16]]
                                if expected:
                                    unexpected["matchesExpectedAddresses"] = addresses == expected
                        except (ValueError, dns.exception.DNSException):
                            pass
                diagnostic["unexpectedResponder"] = unexpected
                return {**result, "state": "unreachable", "reason": "dns_unexpected_source"}
            if response is None:
                return {**result, "reason": "timeout"}
            if response.flags & dns.flags.TC:
                return {**result, "reason": "dns_truncated"}
        else:
            response = dns.query.tcp(query, ip, **options)
        rcode = response.rcode()
        diagnostic["rcode"] = dns.rcode.to_text(rcode)
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
        if record == "SRV":
            endpoints = {(value.target.canonicalize().to_text(), value.port) for value in answer}
            if any(target == "." or port == 0 for target, port in endpoints):
                return {**result, "state": "unreachable", "reason": "dns_no_answer"}
            diagnostic["srvRecords"] = [{"target": target, "port": port} for target, port in sorted(endpoints)[:16]]
            if expected_srv and endpoints != expected_srv:
                return {**result, "state": "unreachable", "reason": "dns_srv_mismatch"}
        return {**result, "state": "reachable"}
    except dns.query.UnexpectedSource:
        diagnostic["transport"] = "UDP"
        return {**result, "reason": "dns_unexpected_source"}
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
    if not isinstance(naming_context, str) or not LDAP_NAMING_CONTEXT.fullmatch(naming_context):
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


class _LdapsProbeTls(ldap3.Tls):
    """Verify the configured DNS name even when connecting to a fixed IP."""

    def __init__(self, context: ssl.SSLContext, server_name: str) -> None:
        super().__init__(validate=ssl.CERT_REQUIRED)
        self.context = context
        self.server_name = server_name

    def wrap_socket(self, connection, do_handshake=False):
        connection.socket = self.context.wrap_socket(
            connection.socket, server_hostname=self.server_name, do_handshake_on_connect=do_handshake,
        )
        return True


def _ldaps(spec: dict) -> dict:
    port, expected = spec.get("port"), spec.get("naming_context")
    name, ca_file = spec.get("tls_server_name"), spec.get("tls_ca_file")
    invalid = {"state": "unknown", "reason": "probe_configuration"}
    if (type(port) is not int or not 1 <= port <= 65535
            or not isinstance(expected, str) or not LDAP_NAMING_CONTEXT.fullmatch(expected)
            or not _valid_http_hostname(name) or not isinstance(ca_file, str) or not os.path.isabs(ca_file)):
        return invalid
    try:
        address = str(ipaddress.ip_address(spec.get("ip")))
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ValueError):
        return invalid
    server = ldap3.Server(address, port=port, use_ssl=True, tls=_LdapsProbeTls(context, name),
                          get_info=ldap3.NONE, connect_timeout=TIMEOUT)
    connection = ldap3.Connection(server, auto_referrals=False, read_only=True, receive_timeout=TIMEOUT)
    unknown = {"state": "unknown", "reason": "ldaps_response_unconfirmed"}
    try:
        connection.open(read_server_info=False)
        complete = connection.search(
            "", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["defaultNamingContext"],
            size_limit=1, time_limit=TIMEOUT,
        )
        if not complete or connection.result.get("result") != 0 or len(connection.response) != 1:
            return unknown
        entry, = connection.response
        if entry.get("type") != "searchResEntry" or entry.get("dn") != "":
            return unknown
        contexts = entry.get("attributes", {}).get("defaultNamingContext")
        if not isinstance(contexts, list) or len(contexts) != 1 or not isinstance(contexts[0], str):
            return unknown
        if contexts[0].casefold() != expected.casefold():
            return {"state": "unreachable", "reason": "ldaps_naming_context_mismatch"}
        return {"state": "reachable"}
    except ssl.SSLCertVerificationError:
        return {"state": "unreachable", "reason": "ldaps_tls_certificate"}
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "ldaps_connection_refused"}
    except (LDAPException, OSError):
        return {"state": "unknown", "reason": "ldaps_transport_unconfirmed"}
    finally:
        with suppress(LDAPException, OSError):
            if not connection.closed:
                connection.unbind()
            elif connection.socket is not None:
                connection.socket.close()


def _smb(spec: dict) -> dict:
    # SMB2 NEGOTIATE validates protocol availability without authenticating or opening a share.
    dialects = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2"}
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 14, 1)
    request = bytes(header) + struct.pack("<HHHHI16sQ4H", 36, len(dialects), 1, 0, 0, uuid.uuid4().bytes, 0, *dialects)
    unexpected = {"state": "unknown", "reason": "unexpected_response"}
    timeout_stage = "connect"
    try:
        ip = str(ipaddress.ip_address(spec["ip"]))
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            return {"state": "unknown"}
        with socket.create_connection((ip, port), timeout=TIMEOUT) as connection:
            timeout_stage = "protocol"
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
        return {"state": "unknown", "reason": "timeout", "timeoutStage": timeout_stage}
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


def _smb_mount(spec: dict) -> dict:
    name, path = spec.get("share"), spec.get("mount")
    unknown = {"state": "unknown", "reason": "smb_mount_probe"}
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.$-]{1,64}", name)
            or not isinstance(path, str) or not re.fullmatch(r"(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}){2,8}", path)):
        return unknown
    try:
        address = ipaddress.IPv4Address(spec["ip"])
    except (KeyError, ValueError, TypeError):
        return unknown
    share = {"smbShare": f"//{address}/{name}"}

    def current_mount() -> tuple[int | None, str]:
        payload = json.loads(subprocess.check_output(
            ["/usr/bin/findmnt", "-J", "-l", "-o", "ID,SOURCE,TARGET,FSTYPE"], timeout=TIMEOUT,
        ))
        rows = payload.get("filesystems") if isinstance(payload, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            return None, "smb_mount_probe"
        matches = [row for row in rows if row.get("target") == path]
        mounted = [row for row in matches if row.get("fstype") != "autofs"]
        if not mounted:
            return None, "smb_mount_idle" if matches else "smb_mount_missing"
        if len(mounted) != 1:
            return None, "smb_mount_probe"
        row, = mounted
        if row.get("fstype") not in ("cifs", "smb3") or str(row.get("source", "")).casefold() != share["smbShare"].casefold():
            return None, "smb_mount_source"
        mount_id = row.get("id")
        return (mount_id, "") if type(mount_id) is int and mount_id > 0 else (None, "smb_mount_probe")

    try:
        mount_id, reason = current_mount()
        if reason:
            state = "unreachable" if reason in ("smb_mount_missing", "smb_mount_source") else "unknown"
            return {**share, "state": state, "reason": reason}
        try:
            file_type = subprocess.check_output(
                ["/usr/bin/stat", "--cached=never", "--format=%F", "--", path], timeout=TIMEOUT,
                stderr=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C"},
            )
        except subprocess.CalledProcessError:
            file_type = b""
        if current_mount() != (mount_id, ""):
            return {**share, "state": "unknown", "reason": "smb_mount_changed"}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {**share, **unknown}
    if file_type.strip() != b"directory":
        return {**share, "state": "unreachable", "reason": "smb_mount_read"}
    return {**share, "state": "reachable"}


def _openvpn_management() -> dict:
    unavailable = {"state": "unknown", "reason": "openvpn_management_unavailable"}
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        return unavailable
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
                        observation = {"daemonReady": connected, "sessionCount": sessions}
                        if not connected:
                            return {**observation, "state": "unknown", "reason": "openvpn_daemon_unconfirmed"}
                        if not sessions:
                            return {**observation, "state": "unknown", "reason": "openvpn_no_active_sessions"}
                        return {**observation, "state": "reachable"}
                    fields = line.split(b",", 3)
                    connected |= len(fields) == 4 and fields[0].isdigit() and fields[1:3] == [b"CONNECTED", b"SUCCESS"]
                    session_table |= line.startswith(b"HEADER\tCLIENT_LIST\t")
                    if session_table and line.startswith(b"CLIENT_LIST\t"):
                        sessions += 1
    except OSError:
        return unavailable
    return {"state": "unknown", "reason": "openvpn_management_incomplete"}


def _openvpn_udp_socket(port: int) -> dict:
    try:
        listing = subprocess.check_output(["/usr/bin/ss", "-H", "-lun", f"sport = :{port}"], timeout=TIMEOUT)
        addresses = set()
        for line in listing.decode("ascii").splitlines():
            fields = line.split()
            if not fields:
                continue
            if len(fields) < 5 or fields[0] != "UNCONN":
                return {"state": "unknown"}
            host, _, observed_port = fields[3].rpartition(":")
            if observed_port != str(port):
                return {"state": "unknown"}
            host = host.removeprefix("[").removesuffix("]")
            addresses.add("*" if host == "*" else str(ipaddress.ip_address(host)))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"state": "unknown"}
    return {"state": "bound", "addresses": sorted(addresses)[:8]} if addresses else {"state": "unbound"}


def _openvpn_tunnel(spec: dict) -> dict:
    name, address = spec.get("interface"), spec.get("address")
    unknown = {"state": "unknown", "reason": "openvpn_tunnel_probe"}
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) or not isinstance(address, str):
        return unknown
    try:
        expected = ipaddress.IPv4Interface(address)
        rows = json.loads(subprocess.check_output(
            ["/usr/sbin/ip", "-j", "-d", "address", "show"], timeout=TIMEOUT,
        ))
    except (OSError, ValueError, subprocess.SubprocessError):
        return unknown
    if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("ifname"), str) for row in rows):
        return unknown
    target = {"tunnelInterface": name, "tunnelAddress": str(expected)}
    matches = [row for row in rows if row["ifname"] == name]
    if not matches:
        return {**target, "state": "unreachable", "reason": "openvpn_tunnel_missing"}
    if len(matches) != 1:
        return {**target, **unknown}
    link = matches[0]
    flags, link_info, addresses = link.get("flags"), link.get("linkinfo"), link.get("addr_info")
    if not isinstance(flags, list) or not isinstance(addresses, list) or any(not isinstance(row, dict) for row in addresses):
        return {**target, **unknown}
    if not isinstance(link_info, dict) or link_info.get("info_kind") != "tun":
        return {**target, "state": "unreachable", "reason": "openvpn_tunnel_kind"}
    tunnel = link_info.get("info_data")
    if not isinstance(tunnel, dict) or tunnel.get("type") not in ("tun", "tap"):
        return {**target, **unknown}
    if tunnel["type"] == "tap":
        return {**target, "state": "unreachable", "reason": "openvpn_tunnel_kind"}
    if "UP" not in flags or "LOWER_UP" not in flags:
        return {**target, "state": "unreachable", "reason": "openvpn_tunnel_down"}
    if not any(row.get("family") == "inet" and row.get("local") == str(expected.ip)
               and type(row.get("prefixlen")) is int and row["prefixlen"] == expected.network.prefixlen
               for row in addresses):
        return {**target, "state": "unreachable", "reason": "openvpn_tunnel_address"}
    return {**target, "state": "reachable"}


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


def _udp_failure(connection: socket.socket, option: tuple[int, int] | None,
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


def _tls_handshake(spec: dict) -> dict:
    port = spec.get("port")
    try:
        address = str(ipaddress.ip_address(spec.get("ip")))
    except ValueError:
        return {"state": "unknown", "reason": "probe_configuration"}
    if type(port) is not int or not 1 <= port <= 65535:
        return {"state": "unknown", "reason": "probe_configuration"}
    # Test negotiation only. No authentication or application data follows.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((address, port), timeout=TIMEOUT) as tcp:
            with context.wrap_socket(tcp, server_hostname=address) as tls:
                return {"state": "reachable", "tlsVersion": tls.version()}
    except ssl.SSLError as error:
        if "ALERT" in (error.reason or ""):
            return {"state": "unreachable", "reason": "tls_handshake_rejected"}
        return {"state": "unknown", "reason": "tls_handshake_unconfirmed"}
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "tls_connection_refused"}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}


def _tls_certificate(spec: dict) -> dict:
    pin, port = spec.get("tls_sha256"), spec.get("port")
    name, ca_file = spec.get("tls_server_name"), spec.get("tls_ca_file")
    invalid = {"state": "unknown", "reason": "probe_configuration"}
    if type(port) is not int or not 1 <= port <= 65535:
        return invalid
    try:
        address = str(ipaddress.ip_address(spec.get("ip")))
    except ValueError:
        return invalid

    if name is not None or ca_file is not None:
        if pin is not None or not _valid_http_hostname(name) or not isinstance(ca_file, str) or not os.path.isabs(ca_file):
            return invalid
        try:
            context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ValueError):
            return invalid
    else:
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
            return invalid
        # Read the leaf even after expiry, then verify its configured fingerprint.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((address, port), timeout=TIMEOUT) as tcp:
            with context.wrap_socket(tcp, server_hostname=name or address) as tls:
                certificate = tls.getpeercert(binary_form=True)
                if pin is not None and (not certificate or hashlib.sha256(certificate).hexdigest() != pin.lower()):
                    return {"state": "unknown", "reason": "tls_certificate_pin"}
                if not certificate:
                    return {"state": "unknown", "reason": "tls_certificate_unconfirmed"}
                peer = x509.load_der_x509_certificate(certificate)
                starts, expires = peer.not_valid_before_utc, peer.not_valid_after_utc
                version = tls.version()
    except ssl.SSLCertVerificationError:
        return {"state": "unreachable", "reason": "tls_certificate_verification_failed"}
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "tls_connection_refused"}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except (ssl.SSLError, ValueError):
        return {"state": "unknown", "reason": "tls_certificate_unconfirmed"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}

    observed = {"tlsExpiresAt": expires.isoformat(), "tlsVersion": version}
    now = datetime.now(timezone.utc)
    if now > expires:
        return {**observed, "state": "unreachable", "reason": "tls_certificate_expired"}
    if now < starts:
        return {**observed, "state": "unreachable", "reason": "tls_certificate_not_yet_valid"}
    return {**observed, "state": "reachable"}


def _read_ftp_reply(connection: socket.socket, deadline: float) -> int | None:
    code = b""
    buffer = b""
    remaining_bytes = 4096
    while remaining_bytes:
        remaining_time = deadline - monotonic()
        if remaining_time <= 0:
            raise TimeoutError
        connection.settimeout(remaining_time)
        chunk = connection.recv(remaining_bytes)
        if not chunk:
            break
        remaining_bytes -= len(chunk)
        buffer += chunk
        while b"\r\n" in buffer:
            line, _, buffer = buffer.partition(b"\r\n")
            if code:
                if line.startswith(code + b" "):
                    return int(code)
                continue
            first = re.match(rb"([1-5][0-9]{2})([ -])", line)
            if not first:
                return None
            code, separator = first.groups()
            if separator == b" ":
                return int(code)
    return None


def _ftp_features(spec: dict) -> dict:
    port = spec.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        return {"state": "unknown"}
    try:
        address = str(ipaddress.ip_address(spec.get("ip")))
    except ValueError:
        return {"state": "unknown"}
    try:
        with socket.create_connection((address, port), timeout=TIMEOUT) as connection:
            deadline = monotonic() + TIMEOUT
            code = _read_ftp_reply(connection, deadline)
            if code == 220:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise TimeoutError
                connection.settimeout(remaining)
                connection.sendall(b"FEAT\r\n")
                code = _read_ftp_reply(connection, deadline)
                if code == 211:
                    return {"state": "reachable", "ftpReply": code}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "ftp_connection_refused"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}
    if code == 421:
        return {"state": "unreachable", "ftpReply": code}
    if code is not None:
        return {"state": "unknown", "ftpReply": code, "reason": "ftp_unexpected_reply"}
    return {"state": "unknown", "reason": "ftp_invalid_reply"}


def _read_ssh_identification(spec: dict) -> dict:
    port = spec.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        return {"state": "unknown"}
    try:
        address = str(ipaddress.ip_address(spec.get("ip")))
    except ValueError:
        return {"state": "unknown"}

    invalid = {"state": "unknown", "reason": "ssh_identification_invalid", "sshTcpConnected": True}
    buffer = b""
    limit = budget = 1024
    deadline = monotonic() + TIMEOUT
    connected = {}
    try:
        with socket.create_connection((address, port), timeout=TIMEOUT) as connection:
            connected["sshTcpConnected"] = True
            while budget:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return {"state": "unknown", "reason": "timeout", **connected}
                connection.settimeout(remaining)
                chunk = connection.recv(budget)
                if not chunk:
                    if budget == limit:
                        return {"state": "unknown", "reason": "ssh_closed_before_identification", **connected}
                    break
                budget -= len(chunk)
                buffer += chunk
                while b"\n" in buffer:
                    line, _, buffer = buffer.partition(b"\n")
                    if line.startswith(b"SSH-"):
                        valid = len(line) < 255 and re.fullmatch(
                            rb"SSH-(?:2\.0|1\.99)-(?:[\x21-\x2c\x2e-\x7e]+|IPSSH-[0-9]+(?:\.[0-9]+){2})(?: [ -~]*)?\r?",
                            line,
                        )
                        return {"state": "reachable", **connected} if valid else invalid
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout", **connected}
    except ConnectionRefusedError:
        if not connected:
            return {"state": "unreachable", "reason": "ssh_connection_refused"}
        return {"state": "unknown", "reason": "transport_error", **connected}
    except OSError:
        return {"state": "unknown", "reason": "transport_error", **connected}
    return invalid


def _ssh_identification(spec: dict) -> dict:
    first = _read_ssh_identification(spec)
    early_close = "ssh_closed_before_identification"
    if spec.get("confirm_early_close") is not True or first.get("reason") != early_close:
        return first
    second = _read_ssh_identification(spec)
    if second.get("reason") == early_close:
        return {**second, "state": "unreachable", "attempts": 2}
    if second["state"] == "reachable":
        return {**second, "attempts": 2}
    return {**first, "attempts": 2}


def _rtsp_options(spec: dict) -> dict:
    port = spec.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        return {"state": "unknown"}
    try:
        ip = ipaddress.ip_address(spec.get("ip"))
        path = _http_path(spec.get("path"))
    except ValueError:
        return {"state": "unknown"}
    address = str(ip)
    authority = f"[{address}]" if ip.version == 6 else address
    cseq = str(uuid.uuid4().int % 2_147_483_646 + 1)
    request = f"OPTIONS rtsp://{authority}:{port}{path} RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n".encode("ascii")
    header = bytearray()
    try:
        with socket.create_connection((address, port), timeout=TIMEOUT) as connection:
            connection.sendall(request)
            deadline = monotonic() + TIMEOUT
            while b"\r\n\r\n" not in header and len(header) < 8192:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return {"state": "unknown", "reason": "timeout"}
                connection.settimeout(remaining)
                chunk = connection.recv(8192 - len(header))
                if not chunk:
                    break
                header.extend(chunk)
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "rtsp_connection_refused"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}
    head, delimiter, _ = bytes(header).partition(b"\r\n\r\n")
    line, *headers = head.split(b"\r\n")
    status = re.fullmatch(rb"RTSP/1\.0 ([1-5][0-9]{2})(?: [ -~]*)?", line)
    fields = [(name.strip().lower(), value.strip()) for field in headers
              for name, separator, value in [field.partition(b":")] if separator]
    if not delimiter or not status or [v for k, v in fields if k == b"cseq"] != [cseq.encode("ascii")]:
        return {"state": "unknown", "reason": "unexpected_response"}
    code = int(status[1])
    auth = code == 401 and any(re.match(rb"(?i)(?:Basic|Digest)\s+\S", value)
                               for name, value in fields if name == b"www-authenticate")
    if auth:
        return {"state": "reachable", "rtspStatus": code, "reason": "rtsp_auth_required"}
    state = "reachable" if 200 <= code < 300 else "unreachable" if code == 404 or code >= 500 else "unknown"
    return {"state": state, "rtspStatus": code}


def _ipmi_lan(spec: dict) -> dict:
    if spec.get("port") != IPMI_PORT or type(spec["port"]) is not int:
        return {"state": "unknown"}
    try:
        ip = ipaddress.ip_address(spec.get("ip"))
    except ValueError:
        return {"state": "unknown"}
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    tag = uuid.uuid4().bytes[0]
    request = RMCP_ASF_HEADER + bytes((0x80, tag, 0, 0))
    reply_prefix = RMCP_ASF_HEADER + bytes((0x40, tag, 0, 16))
    result = {"state": "unknown", "reason": "timeout"}
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(TIMEOUT)
            error_option = _enable_udp_error_queue(connection, family)
            connection.connect((str(ip), IPMI_PORT))
            try:
                started = monotonic()
                connection.sendall(request)
                deadline = started + TIMEOUT
                while (remaining := deadline - monotonic()) > 0:
                    connection.settimeout(remaining)
                    response = connection.recv(64)
                    if len(response) == 28 and response.startswith(reply_prefix) and response[20] & 0x80:
                        return {"state": "reachable", "roundTripMs": round((monotonic() - started) * 1000, 3)}
                    result["reason"] = "unexpected_response"
            except TimeoutError:
                return result
            except OSError as exc:
                return _udp_failure(connection, error_option, family, str(ip), IPMI_PORT, exc)
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}
    return result


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
    transport = spec.get("transport", "udp")
    try:
        ip = str(ipaddress.ip_address(spec["ip"]))
    except (KeyError, ValueError):
        return {"state": "unknown"}
    if type(port) is not int or not 1 <= port <= 65535 or transport not in ("udp", "tcp"):
        return {"state": "unknown"}
    probe = _sip_tcp if transport == "tcp" else _sip_udp
    if "route_via" in spec:
        route = _local_ipv4_route(ip, spec["route_via"])
        if route["state"] != "reachable":
            reason = "sip_route_mismatch" if route["state"] == "unreachable" else "sip_route_unconfirmed"
            return {"state": "unknown", "reason": reason, "localRoute": route}
        return {**probe(ip, port, source=route["sourceIP"]), "localRoute": route}
    return probe(ip, port)


def _sip_request(connection, ip: str, port: int, transaction: str, transport: str) -> bytes:
    local, local_port, *_ = connection.getsockname()
    if ":" in ip:
        ip, local = f"[{ip}]", f"[{local}]"
    uri = f"sip:{ip}:{port}"
    request = [
        f"OPTIONS {uri} SIP/2.0",
        f"Via: SIP/2.0/{transport} {local}:{local_port};branch=z9hG4bK{transaction};rport",
        "Max-Forwards: 0", f"To: <{uri}>",
        f"From: <sip:monitor@{local}>;tag={transaction}", f"Call-ID: {transaction}",
        "CSeq: 1 OPTIONS", "Content-Length: 0", "", "",
    ]
    return "\r\n".join(request).encode("ascii")


def _sip_final_response(code: int) -> dict:
    state = "reachable" if code < 300 else "unreachable" if code in {500, 502, 503, 504} else "unknown"
    return {"state": state, "reason": "sip_response", "responseCode": code}


def _sip_tcp(ip: str, port: int, *, source: str | None = None) -> dict:
    transaction = uuid.uuid4().hex
    deadline = monotonic() + TIMEOUT
    incomplete = {"state": "unknown", "reason": "unexpected_response"}
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT, source_address=(source, 0) if source else None) as connection:
            connection.settimeout(max(0.001, deadline - monotonic()))
            connection.sendall(_sip_request(connection, ip, port, transaction, "TCP"))
            buffer = b""
            received = 0
            while (remaining := deadline - monotonic()) > 0 and received < 32_768:
                connection.settimeout(remaining)
                chunk = connection.recv(min(8192, 32_768 - received))
                if not chunk:
                    return incomplete
                received += len(chunk)
                buffer = (buffer + chunk).lstrip(b"\r\n")
                while b"\r\n\r\n" in buffer:
                    header, separator, body = buffer.partition(b"\r\n\r\n")
                    lengths = re.findall(rb"(?im)^(?:content-length|l)[ \t]*:[ \t]*([0-9]{1,5})[ \t]*\r?$", header)
                    if len(lengths) != 1 or (length := int(lengths[0])) > 32_768:
                        return incomplete
                    if len(body) < length:
                        break
                    code = _sip_response_code(header + separator, transaction)
                    if code is not None and code >= 200:
                        return _sip_final_response(code)
                    if code is not None:
                        incomplete = {"state": "unknown", "reason": "sip_response", "responseCode": code}
                    buffer = body[length:].lstrip(b"\r\n")
            return incomplete
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "tcp_connection_refused"}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}


def _sip_udp(ip: str, port: int, *, source: str | None = None) -> dict:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    transaction = uuid.uuid4().hex
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(TIMEOUT)
            error_option = _enable_udp_error_queue(connection, family)
            if source is not None:
                connection.bind((source, 0))
            connection.connect((ip, port))
            payload = _sip_request(connection, ip, port, transaction, "UDP")
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
                        return {**_sip_final_response(code), "attempts": attempts}
                except TimeoutError:
                    continue
                except OSError as exc:
                    return {**_udp_failure(connection, error_option, family, ip, port, exc), "attempts": attempts}
            return {**incomplete, "attempts": attempts}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}


def _ping(ip: str, *, source_ip: str | None = None, interface: str | None = None) -> subprocess.CompletedProcess:
    ip = str(ipaddress.ip_address(ip))
    bind = ["-I", interface] if interface else []
    if source_ip is not None:
        bind.extend(("-I", str(ipaddress.ip_address(source_ip))))
    return subprocess.run(["/usr/bin/ping", "-n", "-c", "1", "-W", "2", *bind, ip],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={**os.environ, "LC_ALL": "C"}, timeout=TIMEOUT, check=False)


def probe_icmp(ip: str, *, source_ip: str | None = None) -> bool:
    return _ping(ip, source_ip=source_ip).returncode == 0


def _icmp_check(ip: str, *, source_ip: str | None = None, interface: str | None = None) -> dict:
    try:
        ping = _ping(ip, source_ip=source_ip, interface=interface)
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


def _ipv4_neighbor(address: str, interface: str) -> dict:
    rows = json.loads(subprocess.check_output(
        ["/usr/sbin/ip", "-j", "-4", "neigh", "show", "to", address, "dev", interface],
        timeout=TIMEOUT, stderr=subprocess.DEVNULL,
    ))
    if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get("dst") == address:
        return rows[0]
    return {}


def _local_vlan_peer(address: str, interface: str, expected_mac: str) -> str:
    try:
        neighbor = _ipv4_neighbor(address, interface)
        states = neighbor.get("state")
        if isinstance(states, list) and any(state in ("DELAY", "PROBE") for state in states):
            # Linux revalidates a cached neighbor shortly after using it.
            sleep(6)
            neighbor = _ipv4_neighbor(address, interface)
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unconfirmed"
    mac = neighbor.get("lladdr")
    if neighbor.get("state") != ["REACHABLE"] or not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        return "unconfirmed"
    return "matched" if mac.lower() == expected_mac else "mismatch"


def _local_vlan_transit(spec: dict) -> dict:
    name, vlan = spec.get("interface"), spec.get("vlan")
    unknown = {"state": "unknown", "reason": "vlan_probe_error"}
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) or type(vlan) is not int or not 1 <= vlan <= 4094:
        return unknown
    try:
        local = ipaddress.IPv4Interface(spec.get("address"))
        peer = ipaddress.IPv4Address(spec.get("ip"))
        if peer == local.ip or peer not in local.network:
            return unknown
        rows = json.loads(subprocess.check_output(
            ["/usr/sbin/ip", "-j", "-d", "address", "show"], timeout=TIMEOUT, stderr=subprocess.DEVNULL,
        ))
    except (OSError, ValueError, subprocess.SubprocessError):
        return unknown
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return unknown
    target = {"vlanTransit": {"interface": name, "id": vlan, "localAddress": str(local)}}
    matches = [row for row in rows if row.get("ifname") == name]
    if not matches:
        return {**target, "state": "unreachable", "reason": "vlan_interface_missing"}
    if len(matches) != 1:
        return {**target, **unknown}
    link, = matches
    flags, addresses, info = link.get("flags"), link.get("addr_info"), link.get("linkinfo")
    if not isinstance(flags, list) or not isinstance(addresses, list) or not all(isinstance(row, dict) for row in addresses):
        return {**target, **unknown}
    vlan_data = info.get("info_data") if isinstance(info, dict) and info.get("info_kind") == "vlan" else None
    if not isinstance(vlan_data, dict) or vlan_data.get("id") != vlan:
        return {**target, "state": "unreachable", "reason": "vlan_id_mismatch"}
    if "UP" not in flags or "LOWER_UP" not in flags:
        return {**target, "state": "unreachable", "reason": "vlan_link_down"}
    source, address = str(local.ip), str(peer)
    if not any(row.get("family") == "inet" and row.get("local") == source
               and row.get("prefixlen") == local.network.prefixlen for row in addresses):
        return {**target, "state": "unreachable", "reason": "vlan_address_mismatch"}
    try:
        route = json.loads(subprocess.check_output(
            ["/usr/sbin/ip", "-j", "-4", "route", "get", address, "from", source],
            timeout=TIMEOUT, stderr=subprocess.DEVNULL,
        ))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {**target, **unknown}
    if not isinstance(route, list) or len(route) != 1 or not isinstance(route[0], dict):
        return {**target, **unknown}
    row, = route
    if row.get("dev") != name or row.get("gateway") or row.get("dst") != address or row.get("from") != source:
        return {**target, "state": "unreachable", "reason": "vlan_route_mismatch"}
    result = _icmp_check(address, source_ip=source, interface=name)
    guest_port, mac = spec.get("peerGuestPort"), spec.get("peerMac")
    if (result["state"] == "reachable" and isinstance(guest_port, str) and re.fullmatch(r"net[0-9]{1,3}", guest_port)
            and isinstance(mac, str) and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)):
        state = _local_vlan_peer(address, name, mac)
        target["vlanTransit"]["peer"] = {"asset": spec.get("peerAsset"), "guestPort": guest_port, "state": state}
        if state == "mismatch":
            result = {"state": "unknown", "reason": "vlan_peer_identity_mismatch"}
    return {**target, **result}


def _probe_over_vlan(spec: dict, transit: dict) -> dict:
    if "route_via" in spec:
        return {"state": "unknown", "reason": "vlan_probe_error"}
    probe = {"dns": _dns, "ntp": _ntp}.get(spec["type"])
    if probe is None:
        return {"state": "unknown", "reason": "vlan_probe_error"}
    observation = _local_vlan_transit(transit)
    vlan = observation.get("vlanTransit", {})
    if observation["state"] != "reachable" or vlan.get("peer", {}).get("state") != "matched":
        reason = observation.get("reason", "")
        return {"state": "unknown", "reason": reason if reason.startswith("vlan_") else "vlan_peer_identity_unconfirmed",
                "vlanTransit": vlan}
    source = str(ipaddress.IPv4Interface(vlan["localAddress"]).ip)
    return {**probe(spec, source=source), "vlanTransit": vlan}


def _wireguard_policy(spec: dict) -> dict:
    ingress, interface = spec.get("ingress"), spec.get("interface")
    mark, table = spec.get("mark"), spec.get("table")
    unknown = {"state": "unknown", "reason": "wireguard_route_unconfirmed"}
    if (not all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) for name in (ingress, interface))
            or not all(type(value) is int and 1 <= value <= 0xffffffff for value in (mark, table))):
        return unknown
    details = {"ingress": ingress, "interface": interface, "mark": mark, "table": table}
    result = {"wireguardPolicy": details}
    try:
        source = str(ipaddress.IPv4Address(spec.get("peer")))
        destination = "192.0.2.1"
        rows = json.loads(subprocess.check_output(
            ["/usr/sbin/ip", "-j", "-4", "route", "get", destination, "from", source,
             "iif", ingress, "mark", str(mark)], timeout=TIMEOUT, stderr=subprocess.DEVNULL,
        ))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {**result, **unknown}
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return {**result, **unknown}
    row, = rows
    flags = row.get("flags")
    if not isinstance(flags, list):
        return {**result, **unknown}
    details["routeConfirmed"] = (row.get("dev") == interface and str(row.get("table")) == str(table)
                                 and row.get("iif") == ingress and row.get("from") == source
                                 and row.get("dst") == destination and row.get("mark") == mark and "linkdown" not in flags)
    if not details["routeConfirmed"]:
        return {**result, "state": "unreachable", "reason": "wireguard_route_mismatch"}
    unknown = {"state": "unknown", "reason": "wireguard_evidence_unavailable"}
    try:
        with open(spec["report"], "rb") as handle:
            data = handle.read(16_385)
        if len(data) > 16_384:
            return {**result, **unknown}
        evidence = json.loads(data)
        stamp = datetime.fromisoformat(evidence["checkedAt"])
        now = datetime.now(timezone.utc)
        if not 0 <= (now - stamp).total_seconds() <= 300:
            return {**result, **unknown}
    except (OSError, KeyError, TypeError, ValueError, RecursionError):
        return {**result, **unknown}
    markings = evidence.get("markers")
    observed_mark = markings.get(ingress) if isinstance(markings, dict) else None
    if type(observed_mark) is not int:
        return {**result, "state": "unknown", "reason": "wireguard_mark_unconfirmed"}
    details["markerConfirmed"] = observed_mark == mark
    if not details["markerConfirmed"]:
        return {**result, "state": "unreachable", "reason": "wireguard_mark_mismatch"}
    wireguard = evidence.get("wireguard")
    peer = wireguard.get(interface) if isinstance(wireguard, dict) else None
    if not isinstance(peer, dict) or type(peer.get("peerCount")) is not int:
        return {**result, **unknown}
    details["peerCount"] = peer["peerCount"]
    handshake = peer.get("latestHandshake")
    if type(handshake) is int and 0 < handshake <= int(now.timestamp()):
        details["latestHandshake"] = datetime.fromtimestamp(handshake, timezone.utc).isoformat()
    if peer["peerCount"] != 1 or "latestHandshake" not in details or now.timestamp() - handshake > 300:
        return {**result, "state": "unknown", "reason": "wireguard_handshake_unconfirmed"}
    return {**result, "state": "reachable"}


def _local_ipv4_route(ip: str, gateway: object, *, on_link: bool = False) -> dict:
    route = {"state": "unknown"}
    if not isinstance(ip, str) or (not on_link and not isinstance(gateway, str)):
        return route
    try:
        address = str(ipaddress.IPv4Address(ip))
        expected = "" if on_link else str(ipaddress.IPv4Address(gateway))
    except ValueError:
        return route
    if not on_link:
        route["expectedGateway"] = expected
    try:
        rows = json.loads(subprocess.check_output(
            ["/usr/sbin/ip", "-j", "-4", "route", "get", address], timeout=TIMEOUT, stderr=subprocess.DEVNULL,
        ))
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            return route
        row, = rows
        interface = row.get("dev")
        if row.get("dst") != address or not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
            return route
        if on_link and (row.get("via") or interface == "lo" or row.get("type", "unicast") != "unicast"):
            return route
        actual = str(ipaddress.IPv4Address(row["gateway"])) if row.get("gateway") else ""
        source = str(ipaddress.IPv4Address(row["prefsrc"]))
    except (KeyError, OSError, ValueError, subprocess.SubprocessError):
        return route
    route.update(state="reachable" if actual == expected else "unreachable",
                 gateway=actual, interface=interface, sourceIP=source)
    return route


def _local_arp_diagnostic(address: str, expected_mac: str) -> dict:
    route = _local_ipv4_route(address, None, on_link=True)
    if route["state"] != "reachable":
        return {}
    interface, source = route["interface"], route["sourceIP"]
    try:
        if _ping(address, source_ip=source, interface=interface).returncode not in (0, 1):
            return {}
        neighbor = _ipv4_neighbor(address, interface)
        state = neighbor.get("state")
        if state == ["INCOMPLETE"]:
            sleep(1.25)
            neighbor = _ipv4_neighbor(address, interface)
        elif state in (["DELAY"], ["PROBE"]):
            sleep(6)
            neighbor = _ipv4_neighbor(address, interface)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    state, mac = neighbor.get("state"), neighbor.get("lladdr")
    result = "unconfirmed"
    if state == ["FAILED"] and not mac:
        result = "no_reply"
    elif state == ["REACHABLE"] and isinstance(mac, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        result = "matched" if mac.lower() == expected_mac else "different_mac"
    return {"state": result, "address": address, "sourceIP": source, "interface": interface}


def _icmp_via_router(ip: str, gateway: object) -> dict:
    route = _local_ipv4_route(ip, gateway)
    if route["state"] != "reachable":
        reason = "icmp_route_mismatch" if route["state"] == "unreachable" else "icmp_route_unconfirmed"
        return {"state": "unknown", "reason": reason,
                **({"localRoute": route} if "expectedGateway" in route else {})}
    return {**_icmp_check(ip, source_ip=route["sourceIP"], interface=route["interface"]), "localRoute": route}


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


def _dependency_protocol_response(connection: socket.socket, protocol: str, deadline: float) -> bool:
    def read(size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError
            connection.settimeout(remaining)
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise EOFError
            data.extend(chunk)
        return bytes(data)

    if protocol == "redis_ping":
        connection.sendall(b"*1\r\n$4\r\nPING\r\n")
        return read(7) == b"+PONG\r\n"
    if protocol == "amqp_start":
        connection.sendall(b"AMQP\x00\x00\x09\x01")
        frame_type, channel, size = struct.unpack("!BHI", read(7))
        if frame_type != 1 or channel != 0 or not 18 <= size <= 16_384:
            return False
        frame = read(size + 1)
        return frame.startswith(b"\x00\x0a\x00\x0a\x00\x09") and frame[-1] == 0xce

    # An unauthenticated ping of a standalone MongoDB returns a single BSON {ok: 1.0}.
    request_id = uuid.uuid4().int % 2**31
    ping = b"\x10ping\0" + struct.pack("<i", 1) + b"\x02$db\0" + struct.pack("<i", 6) + b"admin\0\0"
    command = b"\0" * 5 + struct.pack("<i", len(ping) + 4) + ping
    connection.sendall(struct.pack("<4i", 16 + len(command), request_id, 0, 2013) + command)
    expected = b"\0" * 5 + struct.pack("<i", 17) + b"\x01ok\0" + struct.pack("<d", 1.0) + b"\0"
    length, _, response_to, opcode = struct.unpack("<4i", read(16))
    return (length == 16 + len(expected) and response_to == request_id and opcode == 2013
            and read(len(expected)) == expected)


def _dependency_protocol_probe(spec: dict) -> dict:
    try:
        address = str(ipaddress.ip_address(spec["ip"]))
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid service probe port")
        deadline = monotonic() + TIMEOUT
        with socket.create_connection((address, port), timeout=TIMEOUT) as connection:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError
            connection.settimeout(remaining)
            if _dependency_protocol_response(connection, spec["type"], deadline):
                return {"state": "reachable"}
        return {"state": "unknown", "reason": "unexpected_response"}
    except EOFError:
        return {"state": "unknown", "reason": "unexpected_response"}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except (ConnectionRefusedError, ConnectionResetError):
        return {"state": "unreachable", "reason": "transport_error"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}
    except (KeyError, TypeError, ValueError):
        return {"state": "unknown"}


def _winrm(spec: dict) -> dict:
    try:
        address = str(ipaddress.ip_address(spec.get("ip")))
    except ValueError:
        return {"state": "unknown", "reason": "probe_configuration"}
    if type(spec.get("port")) is not int or spec["port"] != 5985:
        return {"state": "unknown", "reason": "probe_configuration"}

    identify = (
        b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        b'<s:Header/><s:Body><i:Identify xmlns:i="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"/>'
        b'</s:Body></s:Envelope>'
    )
    connection = http.client.HTTPConnection(address, 5985, timeout=TIMEOUT)
    timeout_stage = "connect"
    try:
        connection.connect()
        timeout_stage = "protocol"
        connection.request("POST", "/wsman", body=identify, headers={"Content-Type": "application/soap+xml; charset=UTF-8"})
        response = connection.getresponse()
        status = response.status
        headers = response.getheaders()
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout", "timeoutStage": timeout_stage}
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "http_connection_refused"}
    except http.client.HTTPException:
        return {"state": "unknown", "reason": "http_bad_response"}
    except OSError:
        return {"state": "unknown", "reason": "transport_error"}
    finally:
        connection.close()

    observed = {"httpStatus": status}
    if 500 <= status < 600:
        return {**observed, "state": "unreachable", "reason": "http_status"}
    servers = [value.strip().lower() for name, value in headers if name.lower() == "server"]
    challenges = {challenge.strip().lower() for name, value in headers if name.lower() == "www-authenticate"
                  for challenge in value.split(",")}
    if status == 401 and servers == ["microsoft-httpapi/2.0"] and challenges & {"negotiate", "kerberos"}:
        return {**observed, "state": "reachable", "reason": "winrm_auth_required"}
    return {**observed, "state": "unknown", "reason": "unexpected_response"}


def _ntp(spec: dict, *, source: str | None = None) -> dict:
    try:
        address = ipaddress.ip_address(spec.get("ip"))
    except ValueError:
        return {"state": "unknown", "reason": "probe_configuration"}
    if type(spec.get("port")) is not int or spec["port"] != 123:
        return {"state": "unknown", "reason": "probe_configuration"}

    evidence = {}
    if "route_via" in spec:
        route = _local_ipv4_route(str(address), spec["route_via"])
        evidence["localRoute"] = route
        if route["state"] != "reachable":
            reason = "ntp_route_mismatch" if route["state"] == "unreachable" else "ntp_route_unconfirmed"
            return {**evidence, "state": "unknown", "reason": reason}
        source = route["sourceIP"]

    request = bytearray(48)
    request[0] = 0x23  # NTPv4 client mode
    seconds, fraction = divmod(time() + 2_208_988_800, 1)
    struct.pack_into("!II", request, 40, int(seconds) & 0xFFFFFFFF, int(fraction * 2**32))
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(TIMEOUT)
            if source is not None:
                connection.bind((source, 0))
            connection.connect((str(address), 123))
            connection.send(request)
            response = connection.recv(512)
    except TimeoutError:
        return {**evidence, "state": "unknown", "reason": "timeout"}
    except OSError:
        return {**evidence, "state": "unknown", "reason": "transport_error"}

    if (len(response) < 48 or response[0] & 7 != 4 or (response[0] >> 3) & 7 not in (3, 4)
            or response[24:32] != request[40:48]):
        return {**evidence, "state": "unknown", "reason": "unexpected_response"}
    ntp = {"version": (response[0] >> 3) & 7, "leapIndicator": response[0] >> 6, "stratum": response[1]}
    if ntp["stratum"] == 0:
        code = response[12:16]
        if code in (b"RATE", b"DENY", b"RSTR"):
            ntp["kissCode"] = code.decode("ascii")
            reason = "ntp_rate_limited" if code == b"RATE" else "ntp_access_denied"
            return {**evidence, "ntp": ntp, "state": "unreachable", "reason": reason}
    if ntp["leapIndicator"] == 3 or not 1 <= ntp["stratum"] <= 15:
        evidence["ntp"] = ntp
        return {**evidence, "state": "unreachable", "reason": "ntp_unsynchronized"}
    if not any(response[32:40]) or not any(response[40:48]):
        return {**evidence, "state": "unknown", "reason": "unexpected_response"}
    return {**evidence, "ntp": ntp, "state": "reachable"}


def _rdp_negotiation(spec: dict) -> dict:
    port = spec.get("port")
    try:
        ip = str(ipaddress.ip_address(spec["ip"]))
    except (KeyError, ValueError):
        return {"state": "unknown", "reason": "probe_configuration"}
    if type(port) is not int or not 1 <= port <= 65535:
        return {"state": "unknown", "reason": "probe_configuration"}
    # X.224 Connection Request with TLS and CredSSP; close after the server's selection.
    request = bytes.fromhex("03000013 0ee00000000000 0100080003000000")
    unexpected = {"state": "unknown", "reason": "unexpected_response"}
    timeout_stage = "connect"
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as connection:
            timeout_stage = "protocol"
            connection.sendall(request)
            with connection.makefile("rb") as stream:
                if stream.read(4) != b"\x03\x00\x00\x13":
                    return unexpected
                confirm = stream.read(15)
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "tcp_connection_refused"}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout", "timeoutStage": timeout_stage}
    except OSError:
        return {"state": "unknown", "reason": "network_error"}
    if len(confirm) != 15 or confirm[:4] != b"\x0e\xd0\x00\x00" or confirm[6] != 0:
        return unexpected
    kind, flags, length, value = struct.unpack("<BBHI", confirm[7:])
    if length != 8:
        return unexpected
    if kind == 2 and value in (1, 2):
        return {"state": "reachable", "rdpSecurity": "TLS" if value == 1 else "CredSSP"}
    if kind == 3 and flags == 0 and 1 <= value <= 7:
        return {"state": "unreachable", "reason": "rdp_negotiation_rejected", "rdpFailureCode": value}
    return unexpected


def _tcp_connect(spec: dict) -> dict:
    try:
        address = str(ipaddress.ip_address(spec["ip"]))
        port = spec["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid TCP port")
        with socket.create_connection((address, port), timeout=TIMEOUT):
            return {"state": "reachable"}
    except ConnectionRefusedError:
        return {"state": "unreachable", "reason": "tcp_connection_refused"}
    except TimeoutError:
        return {"state": "unknown", "reason": "timeout"}
    except (OSError, KeyError, TypeError, ValueError):
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
        service = node["kind"] == "Сервис"
        if (not isinstance(specs, list) or not 1 <= len(specs) <= MAX_CONFIGURED_SERVICE_PROBES
                or any(not isinstance(spec, dict) or not isinstance(spec.get("type"), str)
                       or spec["type"] not in PROBE_METHODS for spec in specs)):
            node.setdefault("serviceChecks", []).append({
                "state": "unknown", "reason": "probe_configuration", "source": "UI_VPN",
                "method": "Настройки проверки", "checkedAt": datetime.now(timezone.utc).isoformat(),
                **({"required": True} if service else {"supplemental": True}),
            })
            return node, None, (), ()
        skip_reason = ""
        if service and node.get("reachability", {}).get("state") == "stopped":
            skip_reason = "probe_host_stopped"
        elif not service or "probeTargetIP" in node:
            target_address = node.get("probeTargetIP")
            if not target_address:
                skip_reason = "probe_target_unconfirmed"
            elif any(spec.get("ip") != target_address for spec in specs):
                skip_reason = "probe_target_mismatch"
        checks = []
        primary = []
        blocked = []
        management_observation = None
        identity_method = node.get("probeTargetIdentityMethod")
        if identity_method not in ("ICMP · ARP + FDB", "ICMP · LACP + ARP", "ICMP · SNMP + ARP", "ICMP · опрос RouterOS"):
            identity_method = "ICMP · LLDP + ARP" if node["kind"] == "Коммутатор" else None
        identity_at = node.get("probeTargetIdentityAt") if service or identity_method else None
        for spec in specs:
            protocol = spec["type"]
            vlan = node.get("probeTargetVlan")
            method = PROBE_METHODS[protocol]
            if protocol == "sip_options" and spec.get("transport") == "tcp":
                method = "SIP OPTIONS (TCP)"
            supplemental = not service or spec.get("supplemental") is True
            component = not supplemental and spec.get("component") is True
            if node["kind"] != "Сервис":
                method = identity_method if identity_at else "ICMP адреса из инвентаря"
            port = spec.get("port")
            valid_port = port if type(port) is int and 1 <= port <= 65535 else None
            if skip_reason:
                details = {"state": "unknown", "skipped": True, "reason": skip_reason}
                if (not service and protocol == "icmp" and skip_reason == "probe_target_unconfirmed"
                        and "arp_expected_mac" in spec
                        and (arp := _local_arp_diagnostic(spec.get("ip"), spec["arp_expected_mac"]))):
                    details["arpDiagnostic"] = arp
            elif vlan:
                details = _probe_over_vlan(spec, vlan)
            elif protocol == "openvpn_management" and valid_port is not None:
                details = {**_openvpn_management(), "configuredPort": valid_port,
                           "localUdpSocket": _openvpn_udp_socket(valid_port)}
                valid_port = None
            elif protocol == "openvpn_tunnel":
                details = _openvpn_tunnel(spec)
            elif protocol == "sip_options":
                details = _sip_options(spec)
            elif protocol == "ipmi_lan":
                details = _ipmi_lan(spec)
            elif protocol == "rtsp_options":
                details = _rtsp_options(spec)
            elif protocol == "ftp_features":
                details = _ftp_features(spec)
            elif protocol == "tls_certificate":
                details = _tls_certificate(spec)
            elif protocol == "tls_handshake":
                details = _tls_handshake(spec)
            elif protocol == "ldaps":
                details = _ldaps(spec)
            elif protocol == "ssh_identification":
                details = _ssh_identification(spec)
            elif protocol in {"tcp_connect", "http", "https"}:
                probe = _tcp_connect if protocol == "tcp_connect" else _http_probe
                details = probe(spec)
                if (spec.get("retry_timeout") is True and details.get("reason") == "timeout"
                        and "attempts" not in details):
                    details = {**probe(spec), "attempts": 2, "firstAttemptReason": "timeout"}
            elif protocol == "rdp_negotiation":
                details = _rdp_negotiation(spec)
            elif protocol == "zabbix_api":
                details = _zabbix_api(spec)
            elif protocol == "ntp":
                details = _ntp(spec)
            elif protocol == "winrm":
                details = _winrm(spec)
            elif protocol == "dns":
                details = _dns(spec)
            elif protocol == "icmp":
                details = (_icmp_via_router(spec.get("ip"), spec["route_via"]) if "route_via" in spec
                           else _icmp_check(spec.get("ip")))
            elif protocol == "vlan_transit":
                details = _local_vlan_transit(spec)
            elif protocol == "wireguard_policy":
                details = _wireguard_policy(spec)
            elif protocol == "postgresql":
                details = _postgresql(spec)
            elif protocol in DEPENDENCY_PROTOCOLS:
                details = _dependency_protocol_probe(spec)
            elif protocol == "smb":
                details = _smb(spec)
            elif protocol == "smb_mount":
                details = _smb_mount(spec)
            else:
                details = {"state": _probe(spec)}
            if node["kind"] != "Сервис" and protocol == "icmp" and details["state"] == "reachable" and not identity_at:
                details["reason"] = "icmp_identity_unconfirmed"
            observation = {
                **details,
                **({"supplemental": True} if supplemental else {"required": True}),
                **({"component": True} if component else {}),
                "source": "UI_VPN", "method": method,
                "port": valid_port,
                "path": "/wsman" if protocol == "winrm" else (
                    details.get("path", spec.get("path")) if protocol in {"http", "https", "zabbix_api", "rtsp_options"} else None
                ),
                "target": spec.get("ip") if not skip_reason and (
                    protocol in {"icmp", "vlan_transit", "sip_options", "ipmi_lan", "rtsp_options", "ssh_identification", "ftp_features",
                                 "zabbix_api", "postgresql", "dns", "ldap", "ldaps", "smb", "tls_certificate", "tcp_connect",
                                 "ntp", "winrm", "rdp_negotiation", "tls_handshake"}
                    or protocol in DEPENDENCY_PROTOCOLS or "probeTargetIP" in node
                    or (protocol in {"http", "https"} and spec.get("report_target") is True
                        and details.get("reason") != "http_configuration")
                ) else None,
                "checkedAt": datetime.now(timezone.utc).isoformat(),
            }
            if identity_at and not skip_reason and (service or protocol == "icmp"):
                observation["identityCheckedAt"] = identity_at
                if interface := node.get("probeTargetManagementInterface"):
                    observation["managementInterface"] = {"name": interface, "source": "SNMP · ARP"}
                if not service and details["state"] == "reachable":
                    management_observation = {"state": "reachable", "source": "UI_VPN", "method": method,
                                              "checkedAt": identity_at}
            checks.append(observation)
            if (service and skip_reason == "probe_target_unconfirmed" and (asset := node.get("probeTargetArpAsset"))
                    and isinstance(spec.get("ip"), str)):
                blocked.append((asset, spec["ip"], observation))
            if service and protocol == "openvpn_management" and "localUdpSocket" in details:
                binding = details["localUdpSocket"]
                checks.append({
                    "state": {"bound": "reachable", "unbound": "unreachable", "unknown": "unknown"}[binding["state"]],
                    "source": "UI_VPN", "method": "OpenVPN UDP-сокет", "checkedAt": observation["checkedAt"],
                    "configuredPort": details["configuredPort"], "localUdpSocket": binding,
                    **({"supplemental": True} if supplemental else {"required": True, "component": True}),
                })
            if not supplemental and not component and not skip_reason:
                primary.append(observation)
        node.setdefault("serviceChecks", []).extend(checks)
        if not primary:
            return node, management_observation, checks, blocked
        results = {check["state"] for check in primary}
        state = "reachable" if "reachable" in results else "unreachable" if results == {"unreachable"} else "unknown"
        method = " + ".join(dict.fromkeys(check["method"] for check in primary if check["method"]))
        return node, {"state": state, "source": "Проверка сервиса", "method": method,
                      "checkedAt": primary[-1]["checkedAt"]}, checks, blocked

    asset_arp = {}
    blocked_checks = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        for node, observation, checks, blocked in pool.map(check, targets):
            if observation is not None:
                node["reachability"] = observation
            blocked_checks.extend(blocked)
            for item in checks:
                if node["kind"] != "Сервис" and (arp := item.get("arpDiagnostic")):
                    asset_arp[node["id"], arp["address"]] = arp
    for asset, address, item in blocked_checks:
        if arp := asset_arp.get((asset, address)):
            item["arpDiagnostic"] = arp
