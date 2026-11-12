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
MAX_TRACE_HOPS = 8
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


def _metrics(summary: dict[str, str], errors: list[dict], samples: list[tuple[int, float]]) -> dict | None:
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
    timings = dict(samples)
    if len(timings) == len(samples) <= received:
        deltas = [abs(timings[seq] - timings[seq - 1]) for seq in range(1, PROBE_COUNT)
                  if seq in timings and seq - 1 in timings]
        if deltas:
            metrics["rtt_variation"] = {"mean_abs_delta_ms": round(sum(deltas) / len(deltas), 6), "pairs": len(deltas)}
    return metrics


def _read_ssh_metrics(output: str, target: str) -> dict | None:
    if len(output) > MAX_OUTPUT_LENGTH:
        return None
    lines = output.splitlines()
    summaries = [match for line in lines if (match := SUMMARY.fullmatch(line.strip()))]
    if not summaries:
        return None
    sent, received, details = summaries[-1].groups()
    stats = dict(re.findall(r"\b((?:min|avg|max)-rtt)=([^\s]+)", details or ""))
    errors = []
    samples = []
    for line in lines:
        fields = line.casefold().split(maxsplit=1)
        if len(fields) != 2:
            continue
        sequence, response = fields
        parts = response.split()
        if (sequence in ("0", "1", "2") and len(parts) == 4 and parts[0] == target
                and parts[1].isdecimal() and parts[2].isdecimal()):
            elapsed = _duration_ms(parts[3])
            if elapsed is not None:
                samples.append((int(sequence), elapsed))
        for label in PING_ERRORS:
            if response == label or response.endswith(" " + label):
                error = _error_evidence(sequence, label, response.removesuffix(label).split())
                if error:
                    errors.append(error)
                break
    return _metrics({"sent": sent, "received": received, **stats}, errors, samples)


def _read_api_metrics(rows: list[dict[str, str]], target: str) -> dict | None:
    summary = next((row for row in reversed(rows) if "sent" in row or "received" in row), {})
    errors = []
    samples = []
    for row in rows:
        sequence, status = row.get("seq", ""), row.get("status", "").casefold()
        if sequence in ("0", "1", "2") and status in ("", "echo reply") and row.get("host") == target:
            elapsed = _duration_ms(row.get("time", ""))
            if elapsed is not None:
                samples.append((int(sequence), elapsed))
        error = _error_evidence(
            sequence, status,
            [row.get(key, "") for key in ("host", "size", "ttl", "time")],
        )
        if error:
            errors.append(error)
    return _metrics(summary, errors, samples)


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


def _observe_gateway_source(client: RouterOSApiClient, address: str, interface: str, deadline: float) -> dict:
    if client.sock is None or deadline <= monotonic():
        return {"status": "unavailable"}
    try:
        client.sock.settimeout(min(2.0, deadline - monotonic()))
        rows = client.call([
            "/ip/address/print", "=.proplist=address,interface,disabled,invalid", f"?interface={interface}",
        ])
    except (OSError, RuntimeError, ValueError):
        return {"status": "unavailable"}
    if any(
        row.get("interface") == interface and row.get("address", "").split("/", 1)[0] == address
        and row.get("disabled") == "false" and row.get("invalid") != "true"
        for row in rows
    ):
        return {"status": "assigned"}

    result = {"status": "missing"}
    timeout = min(2.0, deadline - monotonic())
    if timeout <= 0:
        return result
    try:
        client.sock.settimeout(timeout)
        rows = client.call([
            "/ip/dhcp-client/print", "=.proplist=interface,status,disabled", f"?interface={interface}",
        ])
    except (OSError, RuntimeError, ValueError):
        return result
    clients = [row for row in rows if row.get("interface") == interface and row.get("disabled") == "false"]
    if len(clients) == 1:
        status = clients[0].get("status", "").rstrip(".")
        if status in {"searching", "requesting", "bound", "renewing", "rebinding", "stopped", "error"}:
            result["dhcp"] = status
    return result


def _observe_gateway_link(client: RouterOSApiClient, interface: str, deadline: float) -> dict:
    timeout = min(2.0, deadline - monotonic())
    if client.sock is None or timeout <= 0:
        return {"status": "unavailable"}
    try:
        client.sock.settimeout(timeout)
        rows = client.call(["/interface/print", "=.proplist=name,running,disabled", f"?name={interface}"])
    except TimeoutError:
        return {"status": "timeout"}
    except (OSError, RuntimeError, ValueError):
        return {"status": "unavailable"}
    matches = [row for row in rows if row.get("name") == interface]
    if len(matches) != 1:
        return {"status": "unavailable"}
    row = matches[0]
    if row.get("disabled") == "true":
        return {"status": "observed", "state": "disabled"}
    running = row.get("running")
    if row.get("disabled") != "false" or running not in {"true", "false"}:
        return {"status": "unavailable"}
    return {"status": "observed", "state": "up" if running == "true" else "down"}


def _trace_reply(rows: list[dict[str, str]], target: str, ttl: int) -> dict:
    for row in rows:
        if row.get("seq", "0") != "0":
            continue
        status = row.get("status", "").casefold()
        host = row.get("host", "")
        if status == "ttl exceeded":
            try:
                address = str(_unicast_ipv4(host, "trace responder"))
            except ValueError:
                continue
            return {"ttl": ttl, "address": address, "status": "hop", "rtt_ms": _duration_ms(row.get("time", ""))}
        if status in ("", "echo reply") and host == target and row.get("received") == "1":
            return {"ttl": ttl, "address": target, "status": "destination", "rtt_ms": _duration_ms(row.get("time", ""))}
    return {"ttl": ttl, "address": None, "status": "no_reply", "rtt_ms": None}


def _trace_api(client: RouterOSApiClient, words: list[str], target: str, max_hops: int, deadline: float) -> dict:
    hops = []
    reason = "hop_limit"
    for ttl in range(1, max_hops + 1):
        timeout = min(2.0, deadline - monotonic())
        if timeout < 1:
            reason = "probe_budget_exhausted"
            break
        try:
            if client.sock is None:
                raise RuntimeError("RouterOS API connection unavailable")
            client.sock.settimeout(timeout)
            rows = client.call([*words, f"=ttl={ttl}"])
        except TimeoutError:
            reason = "router_api_timeout"
            break
        except (OSError, RuntimeError, ValueError):
            reason = "router_api_unavailable"
            break
        hop = _trace_reply(rows, target, ttl)
        hops.append(hop)
        if hop["status"] == "destination":
            return {"status": "reached", "reason": "echo_reply", "max_hops": max_hops, "hops": hops}
    return {"status": "partial" if hops else "unavailable", "reason": reason, "max_hops": max_hops, "hops": hops}


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
    trace_hops: int | None = None,
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
    if trace_hops is not None and (type(trace_hops) is not int or not 2 <= trace_hops <= MAX_TRACE_HOPS or not expected_hop):
        raise ValueError("router trace requires 2–8 hops and an expected first hop")

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
    if trace_hops is not None:
        evidence["trace"] = {"status": "unavailable", "reason": "router_api_trace_unavailable",
                             "max_hops": trace_hops, "hops": []}
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
            metrics = _read_ssh_metrics(output, str(destination))
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
                metrics = _read_api_metrics(client.call(words), str(destination))
                if observe_neighbor:
                    arp = _observe_gateway_arp(client, str(destination), interface, deadline)
                    evidence["gateway_arp"] = arp
                    if origin is not None and metrics is not None and not metrics["received"] and (
                        arp.get("resolved") is False or arp["status"] == "missing"
                    ):
                        evidence["gateway_source"] = _observe_gateway_source(client, str(origin), interface, deadline)
                if metrics is not None and first_hop is not None:
                    hop_words = ["/ping", *(f"={argument}" for argument in hop_arguments[:-1])]
                    if trace_hops is None:
                        hop_words.append("=ttl=1")
                    if mtu is not None:
                        hop_words.append("=do-not-fragment=")
                    if trace_hops is None:
                        observed_path = _measure_first_hop(
                            first_hop, lambda timeout: _first_hop_api(client, hop_words, timeout), deadline, transport,
                        )
                    else:
                        trace = _trace_api(client, hop_words, str(destination), trace_hops, deadline)
                        evidence["trace"] = trace
                        if trace["hops"] and trace["hops"][0]["status"] == "hop":
                            first = trace["hops"][0]
                            observed_path = first["address"]
                            first_hop.update(status="observed", reason="ttl_exceeded")
                            if first["rtt_ms"] is not None:
                                first_hop["rtt_ms"] = first["rtt_ms"]
                        else:
                            first_hop.update(status="unknown", reason="no_ttl_exceeded" if trace["hops"] else trace["reason"])
                if "gateway_source" in evidence:
                    evidence["gateway_link"] = _observe_gateway_link(client, interface, deadline)
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
