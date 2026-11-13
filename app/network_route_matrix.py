import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from subprocess import TimeoutExpired

from .network_probe_profiles import RouteProbe, RouteProfile
from .network_route_local import probe_local_route
from .netctl_client import NetctlError, run_netctl
from .vpnctl_client import VpnctlError, run_vpnctl

PROBE_STATUSES = {"reachable", "unreachable", "timeout", "unavailable", "failed", "not_connected"}


def _read_ipsec(source: str) -> dict:
    try:
        result = run_netctl(["ipsec", "status", "--allow-source-errors", f"--source={source}"], timeout=12)
    except NetctlError as exc:
        return {"reason": "collector_timeout" if isinstance(exc.__cause__, TimeoutExpired) else "collector_failed"}
    except (OSError, UnicodeError):
        return {"reason": "collector_failed"}
    row = next((row for row in result.get("sources", []) if row.get("source") == source), None)
    return {**row, "checked_at": datetime.now(UTC).isoformat()} if row else {"reason": "source_not_reported"}


def _ipsec_evidence(snapshot: dict, probe: RouteProbe) -> dict:
    observed = {"status": "unavailable", "checked_at": snapshot.get("checked_at")}
    if reason := snapshot.get("reason"):
        return {**observed, "reason": reason}
    if snapshot.get("status") == "error":
        return {**observed, "reason": "source_error"}
    matches = []
    for policy in snapshot.get("policies", []):
        if (policy.get("disabled") or policy.get("action") != "encrypt"
                or policy.get("protocol") not in {None, "", "all", "any", "icmp", "1", "255"}):
            continue
        try:
            source = ipaddress.IPv4Network(policy["src_address"], strict=False)
            target = ipaddress.IPv4Network(policy["dst_address"], strict=False)
        except (KeyError, ValueError):
            continue
        if ipaddress.IPv4Address(probe.source_address) in source and ipaddress.IPv4Address(probe.target) in target:
            matches.append((source, target, policy))
    if not matches:
        if snapshot.get("errors"):
            return {**observed, "reason": "source_report_incomplete"}
        return {**observed, "status": "no_matching_policy"}
    if len(matches) != 1:
        return {**observed, "status": "ambiguous_policy", "matching_policies": len(matches)}
    source, target, policy = matches[0]
    observed.update(status="established" if policy.get("established") else "inactive",
                    local_subnet=str(source), remote_subnet=str(target), phase2_count=policy.get("ph2_count"))
    if policy.get("local_sa_address_status") in {"assigned", "missing", "unavailable"}:
        observed["local_sa_address_status"] = policy["local_sa_address_status"]
    local_peer, remote_peer = policy.get("sa_src_address"), policy.get("sa_dst_address")
    if not local_peer or not remote_peer or local_peer == remote_peer or "0.0.0.0" in (local_peer, remote_peer):
        return observed
    counters = {}
    for name, pair in (("outgoing", (local_peer, remote_peer)), ("incoming", (remote_peer, local_peer))):
        readings = [row.get("current_bytes") for row in snapshot.get("installed_sas", [])
                    if (row.get("src_address"), row.get("dst_address")) == pair]
        if readings:
            counters[name] = {"associations": len(readings), "bytes": sum(readings) if all(
                type(value) is int and value >= 0 for value in readings) else None}
    if counters:
        observed["peer_sa_counters"] = counters
    return observed


def _read_openvpn_sessions() -> list[dict] | None:
    try:
        snapshot = run_vpnctl(["connected", "--source", "management"], timeout=5)
    except (VpnctlError, OSError, UnicodeError):
        return None
    sessions = snapshot.get("connected")
    if (
        snapshot.get("status") != "ok" or snapshot.get("source") != "management"
        or not isinstance(sessions, list)
        or any(not isinstance(row, dict) or not isinstance(row.get("common_name"), str)
               or not isinstance(row.get("virtual_address"), str) for row in sessions)
    ):
        return None
    return sessions


def _openvpn_session(probe: RouteProbe, sessions: list[dict] | None) -> str:
    if sessions is None:
        return "unavailable"
    matches = [row for row in sessions if row["virtual_address"] == probe.target]
    if len(matches) == 1 and matches[0]["common_name"] == probe.openvpn_client:
        return "connected"
    if matches or any(row["common_name"] == probe.openvpn_client for row in sessions):
        return "address_mismatch"
    return "not_connected"


def _run_probe(profile_id: str, probe: RouteProbe, sessions: list[dict] | None = None) -> dict:
    config_digest = probe.config_digest()
    session = _openvpn_session(probe, sessions) if probe.openvpn_client else None
    try:
        if session is not None and session != "connected":
            measurement = {"status": "unavailable" if session == "unavailable" else "not_connected"}
        elif probe.router_source:
            measurement = run_netctl(
                ["path", "probe", f"--profile={profile_id}", f"--probe={probe.id}",
                 f"--expected-config={config_digest}"], timeout=22,
            ).get("probe")
        elif probe.agent_origin:
            from .network_route_remote import probe_remote_route

            measurement = probe_remote_route(probe.agent_origin, profile_id, probe.id, probe.local_arguments())
        else:
            measurement = probe_local_route(**probe.local_arguments())
    except (NetctlError, OSError, UnicodeError, ValueError):
        measurement = None
    if not isinstance(measurement, dict) or measurement.get("status") not in PROBE_STATUSES:
        measurement = {"status": "unavailable", "evidence": {"reason": "probe_runner_unavailable"}}
    evidence = measurement.get("evidence", {})
    if session is not None:
        evidence = {**evidence, "openvpn_session": session}
    observed_path = measurement.get("observed_path")
    if not observed_path:
        path_status = "unconfirmed"
    elif not probe.expected_first_hop:
        path_status = "observed"
    else:
        path_status = "first_hop_matches" if observed_path == probe.expected_first_hop else "first_hop_mismatch"
    return {
        "id": probe.id,
        "config_digest": config_digest,
        "origin": probe.router_source or probe.agent_origin or "vpn-server",
        "target": probe.target,
        "protocol": probe.protocol,
        **({"dns_transport": probe.dns_transport} if probe.dns_transport is not None else {}),
        "expected_path": probe.expected_path,
        "expected_first_hop": probe.expected_first_hop,
        "observed_path": observed_path,
        "path_status": path_status,
        "source_address": probe.source_address,
        "interface": probe.interface,
        "routing_table": probe.routing_table,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": measurement["status"],
        "evidence": evidence,
        "reason": measurement.get("reason"),
        "kernel_route": measurement.get("kernel_route"),
        **({"openvpn_client": probe.openvpn_client} if probe.openvpn_client else {}),
    }


def run_route_matrix(profile_id: str, profile: RouteProfile) -> dict:
    sessions = _read_openvpn_sessions() if any(probe.openvpn_client for probe in profile.probes) else None
    with ThreadPoolExecutor(max_workers=4) as pool:
        sources = {probe.router_source for probe in profile.probes if probe.ipsec}
        ipsec = {source: pool.submit(_read_ipsec, source) for source in sources}
        probes = list(pool.map(lambda probe: _run_probe(profile_id, probe, sessions), profile.probes))
    for definition, row in zip(profile.probes, probes, strict=True):
        if definition.ipsec:
            row["ipsec"] = _ipsec_evidence(ipsec[definition.router_source].result(), definition)
    states = {row["status"] for row in probes}
    return {"status": states.pop() if len(states) == 1 else "partial", "result": {
        "profile": profile_id, "label": profile.label, "probes": probes,
    }}
