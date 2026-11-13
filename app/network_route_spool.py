"""Receive bounded route measurements over a dedicated SSH forced command."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from .network_probe_profiles import RouteProbe, RouteProfile, load_probe_profiles
from .network_route_local import probe_local_route
from .network_route_receipt_timing import CLOCK_TOLERANCE, MAX_AGE
from .network_route_remote import _result, _sanitize_reply, _valid_id

SPOOL_PATH = Path("/var/lib/openvpn-route-probes")
MAX_RECEIPT_BYTES = 32_768


def utcnow() -> datetime:
    return datetime.now(UTC)


def _receipt_path(origin: str, profile: str) -> Path:
    if not _valid_id(origin) or not _valid_id(profile):
        raise ValueError("Invalid receipt identifiers")
    return SPOOL_PATH / origin / f"{profile}.json"


def _decode(payload: bytes) -> tuple[datetime, dict, object]:
    if not 0 < len(payload) <= MAX_RECEIPT_BYTES:
        raise ValueError("Invalid receipt size")
    document = json.loads(payload)
    if not isinstance(document, dict) or not {"measured_at", "probes"} <= set(document) <= {"measured_at", "probes", "adapter"}:
        raise ValueError("Invalid receipt envelope")
    stamp, probes = document["measured_at"], document["probes"]
    if not isinstance(stamp, str) or not isinstance(probes, dict):
        raise ValueError("Invalid receipt fields")
    measured = datetime.fromisoformat(stamp)
    if measured.tzinfo is None:
        raise ValueError("Receipt time must include an offset")
    return measured.astimezone(UTC), probes, document.get("adapter")


def _read(path: Path) -> tuple[datetime, dict, object]:
    with path.open("rb") as stream:
        return _decode(stream.read(MAX_RECEIPT_BYTES + 1))


def _measurement(envelope: dict, probe: RouteProbe) -> dict:
    sanitized = _sanitize_reply(
        json.dumps(envelope, allow_nan=False).encode(), probe.config_digest(), probe.target,
    )
    if sanitized["status"] == "reachable":
        route = sanitized["kernel_route"]
        fields = route["result"]
        if (
            route["status"] != "route_found"
            or fields.get("from", fields.get("prefsrc")) != probe.source_address
            or (probe.expected_kernel_interface and fields.get("dev") != probe.expected_kernel_interface)
            or (probe.expected_kernel_gateway and fields.get("gateway") != probe.expected_kernel_gateway)
        ):
            raise ValueError("Reachable receipt lacks expected route evidence")
        evidence = sanitized["evidence"]
        if probe.protocol in {"http", "https"} and evidence.get("http_status") != (probe.expected_http_status or 200):
            raise ValueError("Reachable receipt lacks the expected HTTP status")
        if probe.protocol == "dns" and (
            evidence.get("dns_rcode") != "NOERROR"
            or (probe.dns_transport and evidence.get("dns_transport") != probe.dns_transport.upper())
            or (probe.expected_dns_answers and evidence.get("dns_answers_match") is not True)
        ):
            raise ValueError("Reachable receipt lacks the expected DNS evidence")
    return sanitized


def _adapter_neighbors(results: dict, address: str, index: int) -> set[str]:
    targets = set()
    for envelope in results.values():
        result = envelope["result"]
        fields = result.get("kernel_route", {}).get("result", {})
        if (result["status"] != "reachable" or fields.get("from", fields.get("prefsrc")) != address
                or fields.get("dev") != f"ifindex-{index}"):
            continue
        target = fields.get("gateway", fields.get("dst"))
        try:
            targets.add(str(ipaddress.IPv4Address(target)))
        except ValueError:
            continue
    return targets


def _adapter_observation(value: object, results: dict) -> dict:
    if not isinstance(value, dict):
        return {}
    name, mac, index, address = (value.get(key) for key in ("name", "mac", "index", "address"))
    if (not isinstance(name, str) or not 0 < len(name) <= 64 or not name.isprintable()
            or not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac)
            or mac == "00:00:00:00:00:00" or type(index) is not int or not 0 < index <= 0xFFFFFFFF
            or not isinstance(address, str) or value.get("status") != "Up"):
        return {}
    try:
        ipaddress.IPv4Address(address)
    except ValueError:
        return {}
    for envelope in results.values():
        result = envelope["result"]
        fields = result.get("kernel_route", {}).get("result", {})
        if result["status"] == "reachable" and fields.get("from", fields.get("prefsrc")) == address and fields.get("dev") == f"ifindex-{index}":
            raw = value.get("neighbors")
            neighbors = {ip: raw[ip] for ip in sorted(_adapter_neighbors(results, address, index))[:16]
                         if isinstance(raw, dict) and isinstance(raw.get(ip), str)
                         and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", raw[ip])
                         and raw[ip] != "00:00:00:00:00:00" and not int(raw[ip][:2], 16) & 1}
            return {"name": name, "mac": mac, "index": index, "address": address, "status": "Up",
                    **({"neighbors": neighbors} if neighbors else {})}
    return {}


def _windows_adapter(results: dict) -> dict:
    if os.name != "nt":
        return {}
    endpoints = {
        (fields.get("from"), int(match[1]))
        for entry in results.values() if entry["result"]["status"] == "reachable"
        for fields in [entry["result"].get("kernel_route", {}).get("result", {})]
        if (match := re.fullmatch(r"ifindex-([0-9]{1,10})", fields.get("dev", ""))) and fields.get("from")
    }
    if len(endpoints) != 1:
        return {}
    ((address, index),) = endpoints
    command = ("[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); "
               f"Get-NetAdapter -Physical | Where-Object ifIndex -eq {index} | "
               "Select-Object Name,MacAddress,Status,@{n='Neighbors';e={@("
               f"Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex {index} -State Reachable | "
               "Select-Object -First 128 IPAddress,LinkLayerAddress)}} | ConvertTo-Json -Compress -Depth 4")
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    try:
        response = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", command],
                                  capture_output=True, timeout=3, check=True)
        row = json.loads(response.stdout.decode("utf-8-sig")) if len(response.stdout) <= 16384 else None
        if not isinstance(row, dict):
            return {}
        neighbors = {}
        peers = row.get("Neighbors")
        if isinstance(peers, dict):
            peers = [peers]
        for peer in peers if isinstance(peers, list) else []:
            if isinstance(peer, dict) and isinstance(peer.get("IPAddress"), str):
                neighbors[peer["IPAddress"]] = str(peer.get("LinkLayerAddress")).lower().replace("-", ":")
        return _adapter_observation({"name": row.get("Name"), "mac": str(row.get("MacAddress")).lower().replace("-", ":"),
                                     "status": row.get("Status"), "address": address, "index": index,
                                     "neighbors": neighbors}, results)
    except (OSError, subprocess.SubprocessError, ValueError, RecursionError):
        return {}


def store_receipt(origin: str, profile_id: str, profile: RouteProfile, payload: bytes, *, now: datetime) -> None:
    path = _receipt_path(origin, profile_id)
    measured, envelopes, adapter = _decode(payload)
    if not now - MAX_AGE <= measured <= now + CLOCK_TOLERANCE:
        raise ValueError("Receipt is outside the accepted time window")
    definitions = {probe.id: probe for probe in profile.probes if probe.push_origin == origin}
    if not definitions or definitions.keys() != envelopes.keys():
        raise ValueError("Receipt does not match the configured origin")
    clean = {probe_id: {"digest": probe.config_digest(), "result": _measurement(envelopes[probe_id], probe)}
             for probe_id, probe in definitions.items()}
    adapter = _adapter_observation(adapter, clean)
    with path.with_suffix(".lock").open("ab") as lock:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            previous_time, previous, previous_adapter = _read(path)
        except FileNotFoundError:
            pass
        else:
            if measured == previous_time and clean == previous and adapter == (previous_adapter or {}):
                return
            if measured <= previous_time:
                raise ValueError("Receipt is older than the stored result")
        fd, filename = tempfile.mkstemp(dir=path.parent)
        pending = Path(filename)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"measured_at": measured.isoformat(), "probes": clean,
                           **({"adapter": adapter} if adapter else {})}, stream, allow_nan=False)
                stream.flush()
                if os.name != "nt":
                    os.fchmod(stream.fileno(), 0o640)
                os.fsync(stream.fileno())
            pending.replace(path)
        finally:
            pending.unlink(missing_ok=True)


def _receipt_measurement(probe: RouteProbe, envelopes: dict, measured: datetime, now: datetime, started: float) -> dict:
    measured_at = measured.isoformat()
    try:
        if not now - MAX_AGE <= measured <= now + CLOCK_TOLERANCE:
            result = _result("unavailable", "origin_receipt_stale", started)
        else:
            envelope = envelopes.get(probe.id, {})
            if envelope.get("digest") != probe.config_digest():
                result = _result("unavailable", "profile_mismatch", started)
            else:
                result = {**_measurement(envelope, probe), "measured_at": measured_at}
    except (AttributeError, OSError, KeyError, TypeError, ValueError, RecursionError):
        return _result("unavailable", "origin_receipt_invalid", started)
    result["evidence"]["origin_measured_at"] = measured_at
    return result


def read_measurements(profile_id: str, profile: RouteProfile) -> dict[str, dict]:
    by_origin: dict[str, list[RouteProbe]] = {}
    for probe in profile.probes:
        if probe.push_origin:
            by_origin.setdefault(probe.push_origin, []).append(probe)
    results = {}
    now = utcnow()
    for origin, probes in by_origin.items():
        started = monotonic()
        try:
            measured, envelopes, _ = _read(_receipt_path(origin, profile_id))
        except FileNotFoundError:
            reason = "origin_receipt_missing"
        except (OSError, TypeError, ValueError, RecursionError, OverflowError):
            reason = "origin_receipt_invalid"
        else:
            results.update({
                probe.id: _receipt_measurement(probe, envelopes, measured, now, started) for probe in probes
            })
            continue
        results.update({probe.id: _result("unavailable", reason, started) for probe in probes})
    return results


def read_adapter_observation(origin: str, profile_id: str, profile: RouteProfile, now: datetime) -> dict:
    try:
        measured, envelopes, adapter = _read(_receipt_path(origin, profile_id))
        if not now - MAX_AGE <= measured <= now:
            return {}
        probes = {probe.id: probe for probe in profile.probes if probe.push_origin == origin}
        if not probes or probes.keys() != envelopes.keys():
            return {}
        current = {key: {"result": _receipt_measurement(probe, envelopes, measured, now, monotonic())}
                   for key, probe in probes.items()}
        if observation := _adapter_observation(adapter, current):
            return {**observation, "checkedAt": measured.isoformat()}
    except (AttributeError, OSError, TypeError, ValueError, RecursionError, OverflowError):
        pass
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("receive", "measure"))
    parser.add_argument("origin")
    parser.add_argument("profile")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    try:
        _receipt_path(args.origin, args.profile)
        if args.action == "receive":
            if args.config or os.environ.get("SSH_ORIGINAL_COMMAND"):
                raise ValueError("The receiver only accepts a receipt on standard input")
            profile = load_probe_profiles(routes_only=True).routes[args.profile]
            store_receipt(args.origin, args.profile, profile, sys.stdin.buffer.read(MAX_RECEIPT_BYTES + 1), now=utcnow())
        else:
            profile = RouteProfile.model_validate_json(args.config.read_bytes())
            probes = {probe.id: {"digest": probe.config_digest(), "result": probe_local_route(**probe.local_arguments())}
                      for probe in profile.probes if probe.push_origin == args.origin}
            if not probes:
                raise ValueError("No probes configured for this origin")
            adapter = _windows_adapter(probes)
            print(json.dumps({"measured_at": utcnow().isoformat(), "probes": probes,
                              **({"adapter": adapter} if adapter else {})}, allow_nan=False))
    except (AttributeError, OSError, KeyError, TypeError, ValueError, RecursionError):
        print("Route probe receipt rejected", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
