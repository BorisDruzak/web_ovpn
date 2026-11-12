from __future__ import annotations

import ipaddress
import re
import subprocess
from collections.abc import Callable
from contextlib import ExitStack
from time import monotonic

from .drivers.mikrotik_api import MikroTikApiDriver, RouterOSApiClient
from .drivers.mikrotik_ssh import MikroTikSshDriver
from .util import SOURCE_NAME_RE


PROBE_COUNT = 3
MAX_SSH_CONNECT_TIMEOUT = 8
MAX_OUTPUT_LENGTH = 16_384
MAX_FIRST_HOP_TIMEOUT = 4.0
PROBE_BUDGET = 20.0
SELECTOR = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")
SUMMARY = re.compile(r"sent=([0-9]{1,2})\s+received=([0-9]{1,2})(?:\s+(.*))?")
DURATION = re.compile(
    r"(?:(?P<s>[0-9]{1,6}(?:\.[0-9]{1,6})?)s)?"
    r"(?:(?P<ms>[0-9]{1,6}(?:\.[0-9]{1,6})?)ms)?"
    r"(?:(?P<us>[0-9]{1,6}(?:\.[0-9]{1,6})?)(?:us|µs))?"
)
PING_ERRORS = {
    "fragmentation needed and df set": "fragmentation_needed",
    "packet too large and cannot be fragmented": "packet_too_large",
    "no route to host": "no_route",
    "net unreachable": "net_unreachable",
    "host unreachable": "host_unreachable",
    "admin prohibited": "admin_prohibited",
    "ttl exceeded": "ttl_exceeded",
}
REJECTED_COMMAND = (
    "expected end of command", "syntax error", "unknown parameter", "unknown argument",
    "bad command name", "no such command", "not enough permissions",
    "input does not match any value of", "invalid value for argument", "failure:",
)


def _unicast_ipv4(value: str, field: str) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a unicast IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError(f"{field} must be a unicast IPv4 address") from None
    if address.packed[0] == 0 or address.is_loopback or address.is_multicast or address.is_reserved:
        raise ValueError(f"{field} must be a unicast IPv4 address")
    return address


def _duration_ms(text: str) -> float | None:
    match = DURATION.fullmatch(text)
    if match is None or not text:
        return None
    seconds, millis, micros = (float(value or 0) for value in match.groups())
    return round(seconds * 1000 + millis + micros / 1000, 6)


def _error_evidence(sequence: str, label: str, reply_fields: list[str]) -> dict | None:
    if sequence not in ("0", "1", "2") or label not in PING_ERRORS:
        return None
    responder = None
    # Local errors may put the destination in HOST. A received ICMP error
    # includes packet size, TTL and elapsed time alongside the responder.
    if len(reply_fields) == 4:
        host, size, ttl, elapsed = reply_fields
        if size.isdecimal() and ttl.isdecimal() and _duration_ms(elapsed) is not None:
            try:
                responder = str(ipaddress.IPv4Address(host))
            except ipaddress.AddressValueError:
                pass
    return {"sequence": int(sequence), "status": PING_ERRORS[label], "responder": responder}


def _metrics(summary: dict[str, str], errors: list[dict]) -> dict | None:
    received_text = summary.get("received", "")
    if summary.get("sent") != str(PROBE_COUNT) or received_text not in ("0", "1", "2", "3"):
        return None
    sent, received = PROBE_COUNT, int(received_text)
    metrics = {"sent": sent, "received": received, "packet_loss_pct": round((sent - received) * 100 / sent, 2)}
    if received:
        low, avg, high = (_duration_ms(summary.get(f"{key}-rtt", "")) for key in ("min", "avg", "max"))
        if low is not None and avg is not None and high is not None and low <= avg <= high:
            metrics["rtt_ms"] = {"min": low, "avg": avg, "max": high}
    if errors:
        metrics["icmp_errors"] = errors[:PROBE_COUNT]
    return metrics


def _read_ssh_metrics(output: str) -> dict | None:
    if len(output) > MAX_OUTPUT_LENGTH:
        return None
    lines = output.splitlines()
    summaries = [match for line in lines if (match := SUMMARY.fullmatch(line.strip()))]
    if not summaries:
        return None
    sent, received, details = summaries[-1].groups()
    stats = dict(re.findall(r"\b((?:min|avg|max)-rtt)=([^\s]+)", details or ""))
    errors = []
    for line in lines:
        fields = line.casefold().split(maxsplit=1)
        if len(fields) != 2:
            continue
        sequence, response = fields
        for label in PING_ERRORS:
            if response == label or response.endswith(" " + label):
                error = _error_evidence(sequence, label, response.removesuffix(label).split())
                if error:
                    errors.append(error)
                break
    return _metrics({"sent": sent, "received": received, **stats}, errors)


def _read_api_metrics(rows: list[dict[str, str]]) -> dict | None:
    summary = next((row for row in reversed(rows) if "sent" in row or "received" in row), {})
    errors = []
    for row in rows:
        error = _error_evidence(
            row.get("seq", ""), row.get("status", "").casefold(),
            [row.get(key, "") for key in ("host", "size", "ttl", "time")],
        )
        if error:
            errors.append(error)
    return _metrics(summary, errors)


def _rejected(output: str) -> bool:
    return any(line.strip().casefold().startswith(REJECTED_COMMAND) for line in output.splitlines())


def _first_hop_ssh(output: str) -> tuple[str, float | None] | None:
    if len(output) > MAX_OUTPUT_LENGTH:
        return None
    if _rejected(output):
        raise RuntimeError(output)
    for line in output.splitlines():
        fields = line.casefold().split()
        if len(fields) < 4 or fields[0] != "0" or fields[-2:] != ["ttl", "exceeded"]:
            continue
        try:
            host = _unicast_ipv4(fields[1], "first-hop responder")
        except ValueError:
            continue
        elapsed = _duration_ms(fields[4]) if len(fields) == 7 else None
        return str(host), elapsed
    return None


def _first_hop_api(
    client: RouterOSApiClient, words: list[str], timeout: float,
) -> tuple[str, float | None] | None:
    if client.sock is None:
        raise RuntimeError("RouterOS API connection is unavailable")
    client.sock.settimeout(timeout)
    for row in client.call(words):
        if row.get("seq", "0") != "0" or row.get("status", "").casefold() != "ttl exceeded":
            continue
        try:
            host = _unicast_ipv4(row.get("host", ""), "first-hop responder")
        except ValueError:
            continue
        return str(host), _duration_ms(row.get("time", ""))
    return None


def _measure_first_hop(
    evidence: dict,
    probe: Callable[[float], tuple[str, float | None] | None],
    deadline: float,
    transport: str,
) -> str | None:
    timeout = min(MAX_FIRST_HOP_TIMEOUT, deadline - monotonic())
    if timeout < 1:
        evidence.update(status="unknown", reason="probe_budget_exhausted")
        return None
    try:
        reply = probe(timeout)
    except (subprocess.TimeoutExpired, TimeoutError):
        evidence.update(status="timeout", reason=f"{transport}_timeout")
        return None
    except RuntimeError as exc:
        message = str(exc)
        if _rejected(message):
            evidence.update(status="unavailable", reason="routeros_rejected_probe")
        elif "connection timed out" in message.casefold():
            evidence.update(status="timeout", reason=f"{transport}_timeout")
        else:
            evidence.update(status="failed", reason=f"{transport}_failed")
        return None
    except (OSError, ValueError):
        evidence.update(status="failed", reason=f"{transport}_failed")
        return None
    if reply is None:
        evidence.update(status="unknown", reason="no_ttl_exceeded")
        return None
    responder, rtt = reply
    evidence.update(status="observed", reason="ttl_exceeded")
    if rtt is not None:
        evidence["rtt_ms"] = rtt
    return responder


def _observe_gateway_arp(client: RouterOSApiClient, target: str, interface: str, deadline: float) -> dict:
    timeout = min(2.0, deadline - monotonic())
    if client.sock is None or timeout <= 0:
        return {"status": "unavailable"}
    try:
        client.sock.settimeout(timeout)
        rows = client.call(["/ip/arp/print", "=.proplist=address,interface,status,complete,disabled",
                            f"?address={target}", f"?interface={interface}"])
    except TimeoutError:
        return {"status": "timeout"}
    except (OSError, RuntimeError, ValueError):
        return {"status": "unavailable"}
    matches = [row for row in rows if row.get("address") == target and row.get("interface") == interface
               and row.get("disabled") != "true"]
    if len(matches) != 1:
        return {"status": "ambiguous" if matches else "missing"}
    row = matches[0]
    state = row.get("status")
    states = {"reachable", "stale", "delay", "probe", "permanent", "incomplete", "failed"}
    complete = row.get("complete")
    return {"status": "observed", "state": state if state in states else "unknown",
            "resolved": {"true": True, "false": False}.get(complete)}


def probe_router_route(
    *,
    source: str,
    target: str,
    source_address: str | None = None,
    interface: str | None = None,
    routing_table: str | None = None,
    mtu: int | None = None,
    expected_first_hop: str | None = None,
    observe_neighbor: bool = False,
    sources: list[dict],
    secrets: dict,
) -> dict:
    """Run a bounded ICMP check for an operator-pinned target from a configured router."""
    if not isinstance(source, str) or not SOURCE_NAME_RE.fullmatch(source):
        raise ValueError("invalid router source name")
    destination = _unicast_ipv4(target, "target")
    origin = _unicast_ipv4(source_address, "source address") if source_address is not None else None
    expected_hop = (
        _unicast_ipv4(expected_first_hop, "expected first hop") if expected_first_hop is not None else None
    )
    for value, label in ((interface, "interface"), (routing_table, "routing table")):
        if value is not None and (not isinstance(value, str) or not SELECTOR.fullmatch(value)):
            raise ValueError(f"invalid router {label}")
    if mtu is not None and (type(mtu) is not int or not 68 <= mtu <= 9000):
        raise ValueError("MTU must be an integer from 68 through 9000")
    if type(observe_neighbor) is not bool or (observe_neighbor and (not interface or expected_hop)):
        raise ValueError("gateway ARP requires a bound interface and a direct gateway target")

    evidence = {
        "method": "routeros_ping",
        "source": source,
        "target": str(destination),
        "requested": {
            "source_address": str(origin) if origin is not None else None,
            "interface": interface, "routing_table": routing_table, "mtu": mtu,
        },
    }
    observed_path = None
    if observe_neighbor:
        evidence["gateway_arp"] = {"status": "unavailable"}
    first_hop = None
    if expected_hop is not None:
        first_hop = {"expected": str(expected_hop), "status": "unknown", "reason": "primary_probe_unavailable"}
        evidence["first_hop"] = first_hop

    def result(status: str, reason: str) -> dict:
        # Path evidence is limited to a TTL-exceeded reply to the TTL=1 probe.
        return {"status": status, "reason": reason, "observed_path": observed_path, "evidence": evidence}

    routers = [
        item for item in sources if item.get("name") == source
        and item.get("enabled") == 1 and item.get("driver") in {"mikrotik_ssh", "mikrotik_api"}
    ]
    if len(routers) != 1:
        return result("unavailable", "router_source_unavailable")
    router = dict(routers[0])
    username, host = router.get("username"), router.get("host")
    if (
        not isinstance(username, str) or not username or username.startswith("-")
        or not isinstance(host, str) or not host
    ):
        return result("unavailable", "router_source_unavailable")
    via_ssh = router["driver"] == "mikrotik_ssh"
    transport = "ssh" if via_ssh else "router_api"
    evidence["method"] = "routeros_ssh_ping" if via_ssh else "routeros_api_ping"
    arguments = ["interval=1s"]
    if origin is not None:
        arguments.append(f"src-address={origin}")
    if interface is not None:
        arguments.append(f"interface={interface}")
    if routing_table is not None:
        # Older RouterOS documentation lists routing-table. On versions that
        # reject it, an unbound ping or vrf would change the requested test.
        arguments.append(f"routing-table={routing_table}")
    if mtu is not None:
        arguments.append(f"size={mtu}")

    main_arguments = [f"address={destination}", f"count={PROBE_COUNT}", *arguments]
    hop_arguments = [f"address={destination}", "count=1", *arguments, "ttl=1"]
    deadline = monotonic() + PROBE_BUDGET
    try:
        if via_ssh:
            connect_timeout = int(router.get("ssh_connect_timeout") or MAX_SSH_CONNECT_TIMEOUT)
            router["ssh_connect_timeout"] = max(1, min(connect_timeout, MAX_SSH_CONNECT_TIMEOUT))
            command = ["/ping", *main_arguments]
            if mtu is not None:
                command.append("do-not-fragment")
            driver = MikroTikSshDriver(router, secrets)
            output = driver._run_read(" ".join(command))
            if _rejected(output):
                return result("unavailable", "routeros_rejected_probe")
            metrics = _read_ssh_metrics(output)
            if metrics is not None and first_hop is not None:
                hop_command = ["/ping", *hop_arguments]
                if mtu is not None:
                    hop_command.append("do-not-fragment")
                observed_path = _measure_first_hop(
                    first_hop,
                    lambda timeout: _first_hop_ssh(driver._run_read(" ".join(hop_command), timeout=timeout)),
                    deadline,
                    transport,
                )
        else:
            words = ["/ping", *(f"={argument}" for argument in main_arguments)]
            if mtu is not None:
                words.append("=do-not-fragment=")
            with ExitStack() as stack:
                # Register socket cleanup before login, which may trap.
                client = stack.push(MikroTikApiDriver(router, secrets)._client())
                client = client.__enter__()
                metrics = _read_api_metrics(client.call(words))
                if observe_neighbor:
                    evidence["gateway_arp"] = _observe_gateway_arp(client, str(destination), interface, deadline)
                if metrics is not None and first_hop is not None:
                    hop_words = ["/ping", *(f"={argument}" for argument in hop_arguments)]
                    if mtu is not None:
                        hop_words.append("=do-not-fragment=")
                    observed_path = _measure_first_hop(
                        first_hop, lambda timeout: _first_hop_api(client, hop_words, timeout), deadline, transport,
                    )
    except (subprocess.TimeoutExpired, TimeoutError):
        return result("timeout", f"{transport}_timeout")
    except FileNotFoundError:
        return result("unavailable", f"{transport}_unavailable")
    except RuntimeError as exc:
        error = str(exc)
        if _rejected(error):
            return result("unavailable", "routeros_rejected_probe")
        if not via_ssh and error.startswith("missing secret "):
            return result("unavailable", "router_api_credentials_unavailable")
        if "connection timed out" in error.casefold():
            return result("timeout", f"{transport}_timeout")
        return result("failed", f"{transport}_failed")
    except (OSError, ValueError):
        return result("failed", f"{transport}_failed")

    if metrics is None:
        return result("failed", "unexpected_ping_output")
    evidence.update(metrics)
    if metrics["received"]:
        return result("reachable", "icmp_reply")
    statuses = {error["status"] for error in metrics.get("icmp_errors", [])}
    if statuses & {"fragmentation_needed", "packet_too_large"}:
        return result("unreachable", "mtu_exceeded")
    return result("unreachable", "icmp_error" if statuses else "no_icmp_reply")
