"""Invoke a configured route probe on its own Linux origin over restricted SSH."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from time import monotonic

from .network_probe_profiles import PROFILE_ID_PATTERN, load_probe_profiles
from .network_route_local import probe_local_route

ORIGINS_PATH = Path("/etc/openvpn-web/route-probe-origins.json")
CREDENTIALS_DIR = Path("/etc/openvpn-web/route-probe-ssh")
SSH_TIMEOUT = 10.0
MAX_REPLY_BYTES = 8192
MAX_CONFIG_BYTES = 16384
ID_TOKEN = PROFILE_ID_PATTERN.removeprefix("^").removesuffix("$")
REMOTE_COMMAND = re.compile(rf"route-probe ({ID_TOKEN}) ({ID_TOKEN}) ([0-9a-f]{{64}})")
PROBE_STATUSES = ("reachable", "unreachable", "timeout", "unavailable", "failed")
ROUTE_STATUSES = (
    "route_found",
    "no_route",
    "timeout",
    "unavailable",
    "failed",
    "not_run",
)
PROBE_REASONS = {
    "tls_ca_unavailable",
    "invalid_configuration",
    "probe_unavailable",
    "source_unavailable",
    "icmp_unreachable",
    "icmp_no_echo_reply",
    "icmp_probe_failed",
    "icmp_fragmentation_required",
    "http_response_invalid",
    "http_status_mismatch",
    "http_no_response",
    "dns_rcode",
    "dns_no_answer",
    "dns_answer_mismatch",
    "connection_refused",
    "connection_unreachable",
    "transport_error",
    "timeout",
    "tls_certificate_invalid",
    "tls_handshake_failed",
    "dns_response_invalid",
    "origin_probe_not_configured",
    "profile_mismatch",
}


def _result(status: str, reason: str, started: float) -> dict:
    return {
        "status": status,
        "evidence": {
            "reason": reason,
            "duration_ms": round((monotonic() - started) * 1000, 2),
        },
        "kernel_route": {"status": "not_run", "result": {}},
    }


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(ID_TOKEN, value) is not None


def _digest(arguments: dict) -> str:
    if not isinstance(arguments, dict):
        raise ValueError("Probe arguments must be an object")
    canonical = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _root_owned(info: os.stat_result) -> bool:
    return os.name == "nt" or info.st_uid == 0


def _trusted(info: os.stat_result) -> bool:
    return _root_owned(info) and (os.name == "nt" or not info.st_mode & 0o022)


def _load_origin(origin: str) -> tuple[str, str, int]:
    directory = ORIGINS_PATH.parent.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or not _trusted(directory)
        or ORIGINS_PATH.is_symlink()
    ):
        raise ValueError("Untrusted origin configuration")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(ORIGINS_PATH, flags), "rb") as file:
        info = os.fstat(file.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or not _trusted(info)
            or not 0 < info.st_size <= MAX_CONFIG_BYTES
        ):
            raise ValueError("Untrusted origin configuration")
        data = file.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError("Oversized origin configuration")
    document = json.loads(data)
    if not isinstance(document, dict) or set(document) != {"origins"}:
        raise ValueError("Invalid origin configuration")
    origins = document["origins"]
    item = origins.get(origin) if isinstance(origins, dict) else None
    if not isinstance(item, dict) or item.keys() - {"host", "user", "port"}:
        raise ValueError("Origin not configured")
    host, user, port = item.get("host"), item.get("user"), item.get("port", 22)
    if not isinstance(host, str) or not _valid_ipv4(host):
        raise ValueError("Invalid origin host")
    address = ipaddress.IPv4Address(host)
    if address.is_multicast or address.is_unspecified or int(address) == 0xFFFFFFFF:
        raise ValueError("Invalid origin host")
    if (
        not isinstance(user, str)
        or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user)
        or user == "root"
    ):
        raise ValueError("Invalid origin user")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid origin port")
    return host, user, port


def _credentials(origin: str) -> tuple[Path, Path]:
    directory = CREDENTIALS_DIR.lstat()
    if not stat.S_ISDIR(directory.st_mode) or not _trusted(directory):
        raise ValueError("Untrusted SSH credential directory")
    identity, known_hosts = (
        CREDENTIALS_DIR / f"{origin}.key",
        CREDENTIALS_DIR / "known_hosts",
    )
    for file in (identity, known_hosts):
        info = file.lstat()
        if not stat.S_ISREG(info.st_mode) or not _trusted(info) or info.st_size == 0:
            raise ValueError("Untrusted SSH credential file")
        if file == identity and os.name != "nt" and info.st_mode & 0o007:
            raise ValueError("Origin identity accessible to other users")
    return identity, known_hosts


def _run_ssh(argv: list[str]) -> tuple[int, bytes]:
    deadline = monotonic() + SSH_TIMEOUT
    reply: Queue[bytes | OSError] = Queue(maxsize=1)
    with subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "LC_ALL": "C"},
    ) as process:

        def read() -> None:
            try:
                reply.put(process.stdout.read(MAX_REPLY_BYTES + 1))
            except OSError as error:
                reply.put(error)

        Thread(target=read, daemon=True).start()
        try:
            output = reply.get(timeout=max(0, deadline - monotonic()))
            if isinstance(output, OSError):
                raise output
            if len(output) > MAX_REPLY_BYTES:
                raise ValueError("Oversized origin reply")
            return process.wait(timeout=max(0, deadline - monotonic())), output
        except Empty:
            raise subprocess.TimeoutExpired(argv, SSH_TIMEOUT) from None
        finally:
            if process.poll() is None:
                process.kill()


def _valid_ipv4(value: object) -> bool:
    try:
        return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def _bounded_text(value: object, pattern: str) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _sanitize_reply(output: bytes, digest: str, target: object) -> dict:
    if len(output) > MAX_REPLY_BYTES:
        raise ValueError("Oversized origin reply")
    envelope = json.loads(output)
    if not isinstance(envelope, dict) or envelope.get("digest") != digest:
        raise ValueError("Origin reply does not match the probe")
    result = envelope["result"]
    status, evidence, route = (
        result["status"],
        result["evidence"],
        result["kernel_route"],
    )
    if (
        status not in PROBE_STATUSES
        or not isinstance(evidence, dict)
        or not isinstance(route, dict)
    ):
        raise ValueError("Invalid origin reply")
    route_status, fields = route["status"], route["result"]
    if route_status not in ROUTE_STATUSES or not isinstance(fields, dict):
        raise ValueError("Invalid origin route estimate")
    duration = evidence.get("duration_ms")
    if type(duration) not in (int, float) or not 0 <= duration <= 60_000:
        raise ValueError("Invalid origin probe duration")

    clean_evidence = {"duration_ms": duration}
    reason = evidence.get("reason")
    if isinstance(reason, str) and reason in PROBE_REASONS:
        clean_evidence["reason"] = reason
    for key, bounds in {
        "round_trip_ms": (0, 60_000),
        "mtu": (68, 9000),
        "http_status": (100, 599),
        "expected_http_status": (200, 599),
        "dns_answer_count": (0, 65535),
    }.items():
        value = evidence.get(key)
        allowed_types = (int, float) if key == "round_trip_ms" else (int,)
        if type(value) in allowed_types and bounds[0] <= value <= bounds[1]:
            clean_evidence[key] = value
    if type(evidence.get("dns_answers_match")) is bool:
        clean_evidence["dns_answers_match"] = evidence["dns_answers_match"]
    for key, pattern in {
        "tls_version": r"TLSv1(?:\.[0-3])?",
        "tls_expires_at": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+00:00",
        "dns_rcode": r"[A-Z0-9]{1,16}",
        "dns_transport": r"UDP|TCP",
    }.items():
        if _bounded_text(evidence.get(key), pattern):
            clean_evidence[key] = evidence[key]

    clean_route = {}
    if route_status == "route_found":
        if fields.get("dst") != target or not _valid_ipv4(target):
            raise ValueError("Origin route does not match the probe target")
        for key in ("dst", "gateway", "prefsrc", "src", "from"):
            if _valid_ipv4(fields.get(key)):
                clean_route[key] = fields[key]
        for key in ("dev", "type", "table"):
            if _bounded_text(fields.get(key), r"[A-Za-z0-9_.:@-]{1,32}"):
                clean_route[key] = fields[key]
        for key in ("metric", "table"):
            if type(fields.get(key)) is int and 0 <= fields[key] <= 0xFFFFFFFF:
                clean_route[key] = fields[key]
    return {
        "status": status,
        "evidence": clean_evidence,
        "kernel_route": {"status": route_status, "result": clean_route},
    }


def probe_remote_route(
    origin: str, profile_id: str, probe_id: str, expected_arguments: dict
) -> dict:
    """Run a matching predefined probe from an allowlisted Linux host."""
    started = monotonic()
    if not all(_valid_id(value) for value in (origin, profile_id, probe_id)):
        return _result("unavailable", "invalid_origin_configuration", started)
    try:
        digest = _digest(expected_arguments)
        host, user, port = _load_origin(origin)
        identity, known_hosts = _credentials(origin)
    except (OSError, ValueError, TypeError, RecursionError):
        return _result("unavailable", "origin_not_configured", started)

    options = (
        f"UserKnownHostsFile={known_hosts}",
        "GlobalKnownHostsFile=/dev/null",
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "VerifyHostKeyDNS=no",
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "PreferredAuthentications=publickey",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ConnectTimeout=3",
        "ConnectionAttempts=1",
    )
    argv = [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-4",
        "-nT",
        "-i",
        str(identity),
        "-p",
        str(port),
        "-l",
        user,
    ]
    for option in options:
        argv.extend(("-o", option))
    argv.extend(("--", host, f"route-probe {profile_id} {probe_id} {digest}"))
    try:
        exit_code, output = _run_ssh(argv)
        if exit_code == 255:
            return _result("unavailable", "origin_ssh_failed", started)
        if exit_code:
            return _result("failed", "origin_command_failed", started)
        return _sanitize_reply(output, digest, expected_arguments.get("target"))
    except subprocess.TimeoutExpired:
        return _result("timeout", "origin_timeout", started)
    except OSError:
        return _result("unavailable", "origin_ssh_failed", started)
    except (KeyError, TypeError, ValueError, RecursionError):
        return _result("failed", "invalid_origin_response", started)


def main() -> int:
    """Entry point for the origin's sshd forced command."""
    command = REMOTE_COMMAND.fullmatch(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    if command is None:
        return 2
    profile_id, probe_id, digest = command.groups()
    started = monotonic()
    profile = load_probe_profiles().routes.get(profile_id)
    probe = (
        next((probe for probe in profile.probes if probe.id == probe_id), None)
        if profile
        else None
    )
    if (
        probe is None
        or probe.router_source is not None
        or probe.agent_origin is not None
    ):
        result = _result("unavailable", "origin_probe_not_configured", started)
    else:
        arguments = probe.local_arguments()
        if _digest(arguments) == digest:
            result = probe_local_route(**arguments)
        else:
            result = _result("unavailable", "profile_mismatch", started)
    print(
        json.dumps(
            {"digest": digest, "result": result}, separators=(",", ":"), allow_nan=False
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
