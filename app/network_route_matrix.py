import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from .network_probe_profiles import RouteProbe, RouteProfile
from .network_route_local import probe_local_route
from .netctl_client import NetctlError, run_netctl

PROBE_STATUSES = {"reachable", "unreachable", "timeout", "unavailable", "failed"}


def _read_ipsec(source: str) -> dict:
    try:
        result = run_netctl(["ipsec", "status", f"--source={source}"], timeout=12)
    except (NetctlError, OSError, UnicodeError):
        return {}
    row = next((row for row in result.get("sources", []) if row.get("source") == source), None)
    return {**row, "checked_at": datetime.now(UTC).isoformat()} if row else {}


def _ipsec_evidence(snapshot: dict, probe: RouteProbe) -> dict:
    observed = {"status": "unavailable", "checked_at": snapshot.get("checked_at")}
    if not snapshot or snapshot.get("status") == "error":
        return observed
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
        if not snapshot.get("errors"):
            observed["status"] = "no_matching_policy"
        return observed
    if len(matches) != 1:
        return {**observed, "status": "ambiguous_policy", "matching_policies": len(matches)}
    source, target, policy = matches[0]
    observed.update(status="established" if policy.get("established") else "inactive",
                    local_subnet=str(source), remote_subnet=str(target), phase2_count=policy.get("ph2_count"))
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


def _run_probe(profile_id: str, probe: RouteProbe) -> dict:
    try:
        if probe.router_source:
            measurement = run_netctl(
                ["path", "probe", f"--profile={profile_id}", f"--probe={probe.id}",
                 f"--expected-config={probe.config_digest()}"], timeout=22,
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
    observed_path = measurement.get("observed_path")
    if not observed_path:
        path_status = "unconfirmed"
    elif not probe.expected_first_hop:
        path_status = "observed"
    else:
        path_status = "first_hop_matches" if observed_path == probe.expected_first_hop else "first_hop_mismatch"
    return {
        "id": probe.id,
        "origin": probe.router_source or probe.agent_origin or "vpn-server",
        "target": probe.target,
        "protocol": probe.protocol,
        "expected_path": probe.expected_path,
        "expected_first_hop": probe.expected_first_hop,
        "observed_path": observed_path,
        "path_status": path_status,
        "source_address": probe.source_address,
        "interface": probe.interface,
        "routing_table": probe.routing_table,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": measurement["status"],
        "evidence": measurement.get("evidence", {}),
        "reason": measurement.get("reason"),
        "kernel_route": measurement.get("kernel_route"),
    }


def run_route_matrix(profile_id: str, profile: RouteProfile) -> dict:
    with ThreadPoolExecutor(max_workers=4) as pool:
        sources = {probe.router_source for probe in profile.probes if probe.ipsec}
        ipsec = {source: pool.submit(_read_ipsec, source) for source in sources}
        probes = list(pool.map(lambda probe: _run_probe(profile_id, probe), profile.probes))
    for definition, row in zip(profile.probes, probes, strict=True):
        if definition.ipsec:
            row["ipsec"] = _ipsec_evidence(ipsec[definition.router_source].result(), definition)
    states = {row["status"] for row in probes}
    return {"status": states.pop() if len(states) == 1 else "partial", "result": {
        "profile": profile_id, "label": profile.label, "probes": probes,
    }}
