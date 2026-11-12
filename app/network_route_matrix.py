from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from .network_probe_profiles import RouteProbe, RouteProfile
from .network_route_local import probe_local_route
from .netctl_client import NetctlError, run_netctl

PROBE_STATUSES = {"reachable", "unreachable", "timeout", "unavailable", "failed"}


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
        probes = list(pool.map(lambda probe: _run_probe(profile_id, probe), profile.probes))
    states = {row["status"] for row in probes}
    return {"status": states.pop() if len(states) == 1 else "partial", "result": {
        "profile": profile_id, "label": profile.label, "probes": probes,
    }}
