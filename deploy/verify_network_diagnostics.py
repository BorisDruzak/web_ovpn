"""Read the deployed diagnostics contract and verify scheduled route evidence."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
from math import isfinite
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlencode
from uuid import UUID

from app.network_capture import CAPTURE_MAX_KIB, CAPTURE_MAX_PACKETS, _pcap_packet_count
from mcp import openvpn_mcp_server as bridge


API = "/api/v1/network/diagnostics"
MCP_SCRIPT = Path(__file__).resolve().parents[1] / "mcp" / "openvpn_mcp_server.py"
CHECKS = {
    "route_availability", "linux_route", "asset_route", "trace_route",
    "source_test", "iperf3", "https_speed", "pcap_capture", "loop_check",
}
MCP_TOOLS = {
    "openvpn_network_diagnostic_checks", "openvpn_network_route_runs",
    "openvpn_network_interface_history", "openvpn_network_loop_diagnostics",
    "openvpn_network_check_runs", "openvpn_network_capture_list",
    "openvpn_network_run_check", "openvpn_network_download_pcap",
}
ROUTE_EVIDENCE_FIELDS = {
    "gateway_link": ("status", "state", "rate", "full_duplex", "auto_negotiation"),
    "gateway_source": ("status", "dhcp", "dhcp_address", "dhcp_gateway"),
    "gateway_arp": ("status", "state", "resolved"),
    "ipsec": ("status", "reason", "phase2_count", "local_sa_address_status"),
}
INTERFACE_COUNTERS = ("in_errors_delta", "out_errors_delta", "in_discards_delta", "out_discards_delta")
MCP_INTERFACE_LIMIT = 300


def route_report(
    runs: list[dict], now: datetime, max_age: timedelta, *,
    api_runs: list[dict], expected_hops: dict[str, str | None],
    expected_dns: dict[str, tuple[str, bool]] | None = None,
    expected_interfaces: dict[str, str] | None = None,
    expected_gateways: dict[str, str] | None = None,
    expected_ipsec: set[str] | None = None,
    expected_digests: dict[str, str] | None = None,
) -> dict:
    row = next((run for run in runs if run["trigger"] == "scheduled"), None)
    if row is None:
        return {"status": "missing", "fresh": False, "run_id": None, "api_matches": False,
                "profile_matches": False, "probes": []}
    checked_at = datetime.fromisoformat(row["checked_at"])
    expected_dns = expected_dns or {}
    probes = []
    for probe in row["result"]["probes"]:
        summary = {"id": probe["id"], "status": probe["status"]}
        if expected_digests is not None:
            expected_digest = expected_digests.get(probe["id"])
            summary["configuration_matches"] = bool(expected_digest and probe.get("config_digest") == expected_digest)
        evidence = probe.get("evidence", {})
        reason = evidence.get("reason") or probe.get("reason")
        if isinstance(reason, str) and reason:
            summary["reason"] = reason
        for name, fields in ROUTE_EVIDENCE_FIELDS.items():
            details = (probe if name == "ipsec" else evidence).get(name)
            if isinstance(details, dict):
                summary[name] = {field: details[field] for field in fields if details.get(field) is not None}
        if "ipsec" in summary:
            policy = summary["ipsec"]
            phase2 = policy.get("phase2_count")
            summary["ipsec_policy_confirmed"] = (
                policy.get("status") == "established" and type(phase2) is int and phase2 > 0
                and policy.get("local_sa_address_status") != "missing"
            )
        if probe.get("expected_first_hop"):
            summary.update(
                expected_first_hop=probe["expected_first_hop"],
                observed_path=probe.get("observed_path"),
                path_status=probe.get("path_status", "unconfirmed"),
            )
        if probe.get("dns_transport"):
            summary.update(
                dns_transport=probe["dns_transport"],
                observed_dns_transport=evidence.get("dns_transport"),
                dns_rcode=evidence.get("dns_rcode"),
                dns_answers_match=evidence.get("dns_answers_match"),
                dns_answers_required=expected_dns.get(probe["id"], (None, False))[1],
            )
        session = evidence.get("openvpn_session")
        if session is not None:
            summary["openvpn_session"] = session
        for field, route_key in (("interface", "dev"), ("gateway", "gateway")):
            expected_key = f"expected_kernel_{field}"
            expected = probe.get(expected_key)
            if not expected:
                continue
            route = probe.get("kernel_route") or {}
            observed = route.get("result", {}).get(route_key)
            summary[expected_key] = expected
            summary[f"observed_kernel_{field}"] = observed
            summary["kernel_route_status"] = route.get("status", "not_run")
            summary[f"kernel_{field}_matches"] = (
                route.get("status") == "route_found" and observed == expected
                and (not probe.get("openvpn_client") or session == "connected")
            )
        probes.append(summary)
    reported_hops = {probe["id"]: probe.get("expected_first_hop") for probe in probes}
    reported_transports = {probe["id"]: probe["dns_transport"] for probe in probes if "dns_transport" in probe}
    expected_transports = {probe_id: transport for probe_id, (transport, _) in expected_dns.items()}
    reported_interfaces = {
        probe["id"]: probe["expected_kernel_interface"] for probe in probes if "expected_kernel_interface" in probe
    }
    reported_gateways = {
        probe["id"]: probe["expected_kernel_gateway"] for probe in probes if "expected_kernel_gateway" in probe
    }
    return {
        "status": row["status"],
        "run_id": row["id"],
        "checked_at": row["checked_at"],
        "fresh": bool(probes) and timedelta(0) <= now - checked_at <= max_age,
        "api_matches": row in api_runs,
        "profile_matches": (
            reported_hops == expected_hops and len(probes) == len(expected_hops)
            and reported_transports == expected_transports
            and reported_interfaces == (expected_interfaces or {})
            and reported_gateways == (expected_gateways or {})
            and {probe["id"] for probe in probes if "ipsec" in probe} == (expected_ipsec or set())
            and (expected_digests is None or all(probe["configuration_matches"] for probe in probes))
        ),
        "probes": probes,
    }


def loop_report(result: dict) -> dict:
    sources = result["sources"]
    assessed = sum(
        not source["truncated"]
        and source["coverage"]["fdb"]["status"] == "recent"
        and source["coverage"]["stp"]["status"] == "recent"
        for source in sources
    )
    return {
        "status": result["status"],
        "since": result["since"],
        "until": result["until"],
        "truncated": result["truncated"],
        "sources": len(sources),
        "coverage": {
            "assessed": assessed,
            "total": len(sources),
            "complete": bool(sources) and assessed == len(sources) and not result["truncated"],
        },
        "source_coverage": [
            {field: source[field] for field in ("source", "status", "coverage", "truncated")}
            for source in sources
        ],
    }


def mcp_requests(script: Path, requests: list[tuple[str, dict]]) -> list[dict]:
    messages = [
        {"jsonrpc": "2.0", "id": number, "method": method, "params": params}
        for number, (method, params) in enumerate(requests, start=1)
    ]
    initialization = [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "network-diagnostics-verifier", "version": "1"},
        }},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    completed = subprocess.run(
        [sys.executable, str(script)],
        input="".join(json.dumps(message) + "\n" for message in [*initialization, *messages]),
        capture_output=True, encoding="utf-8", timeout=90, check=True,
    )
    replies = {reply["id"]: reply["result"] for reply in map(json.loads, completed.stdout.splitlines())}
    if replies[0]["protocolVersion"] != "2024-11-05":
        raise ValueError("Unexpected MCP protocol version")
    return [replies[message["id"]] for message in messages]


def mcp_call(name: str, arguments: dict | None = None) -> tuple[str, dict]:
    return "tools/call", {"name": name, "arguments": arguments or {}}


def mcp_data(reply: dict) -> dict:
    if reply.get("isError"):
        raise ValueError("MCP tool failed")
    return json.loads(reply["content"][0]["text"])["data"]


def capture_report(receipt: dict, download: dict, payload: bytes, directory: Path) -> dict:
    capture_id = str(UUID(receipt["capture_id"]))
    if (
        download["capture_id"] != capture_id
        or download["size_bytes"] != receipt["size_bytes"]
        or len(payload) != receipt["size_bytes"]
        or not 24 <= len(payload) <= CAPTURE_MAX_KIB * 1024
    ):
        raise ValueError("Capture receipt does not match downloads")
    path = directory / f"network-{capture_id}.pcap"
    if Path(download["path"]) != path or path.is_symlink() or not path.is_file():
        raise ValueError("Unexpected MCP download path")
    with path.open("rb") as file:
        if file.read(len(payload) + 1) != payload:
            raise ValueError("REST and MCP PCAP contents differ")
    packets = _pcap_packet_count(BytesIO(payload), len(payload), CAPTURE_MAX_PACKETS)
    if not packets or packets != receipt["packets"]:
        raise ValueError("PCAP is empty, invalid or has a different packet count")
    return {"capture_id": capture_id, "packets": packets, "size_bytes": len(payload), "sha256": sha256(payload).hexdigest()}


def verify_capture(script: Path, capture_id: UUID) -> dict:
    path = f"{API}/captures"
    catalog = bridge.api_request("GET", path)["data"]["captures"]
    listed = mcp_data(mcp_requests(script, [mcp_call("openvpn_network_capture_list")])[0])["captures"]
    receipt = next((row for row in catalog if row["capture_id"] == str(capture_id)), None)
    if receipt is None or receipt not in listed:
        raise ValueError("Capture is missing from REST or MCP list")
    media_type = "application/vnd.tcpdump.pcap"
    request = bridge._legacy_api_request("GET", f"{path}/{capture_id}", accept=media_type)
    with bridge._open_capture(request) as response:
        if response.headers.get_content_type() != media_type:
            raise ValueError("REST did not return PCAP")
        payload = response.read(CAPTURE_MAX_KIB * 1024 + 1)
    download = mcp_data(mcp_requests(script, [
        mcp_call("openvpn_network_download_pcap", {"capture_id": str(capture_id)}),
    ])[0])
    return capture_report(receipt, download, payload, Path.home() / ".codex" / "network-captures")


def interface_report(api: dict, mcp: dict, now: datetime, max_age: timedelta) -> dict:
    points = api["points"][-MCP_INTERFACE_LIMIT:]
    latest = points[-1]["observed_at"] if points else None
    counters = {}
    for field in INTERFACE_COUNTERS:
        values = [point[field] for point in points if type(point.get(field)) is int and point[field] >= 0]
        counters[field] = {"intervals": len(values), "total": sum(values) if values else None}
    return {
        "selected": api["selected"],
        "points": len(points),
        "available_points": len(api["points"]),
        "latest_observation": latest,
        "fresh": latest is not None and timedelta(0) <= now - datetime.fromisoformat(latest) <= max_age,
        "api_matches": (
            bool(api["source"] and api["selected"])
            and bool(mcp["source"]) and api["source"]["id"] == mcp["source"]["id"]
            and api["selected"] == mcp["selected"]
            and len(api["points"]) == mcp["available_points"] and points == mcp["points"]
        ),
        "counters": counters,
    }


def verify_interfaces(script: Path, selections: list[list[str]], max_age: timedelta) -> list[dict]:
    reports = []
    for source, interface in selections:
        args = {"source": source, "interface": interface}
        path = f"{API}/interfaces?{urlencode(args)}"
        for _ in range(2):
            mcp = mcp_data(mcp_requests(script, [
                mcp_call("openvpn_network_interface_history", {**args, "limit": MCP_INTERFACE_LIMIT}),
            ])[0])["diagnostics"]
            api = bridge.api_request("GET", path)["data"]["diagnostics"]
            report = interface_report(api, mcp, datetime.now(UTC), max_age)
            if report["api_matches"]:
                break
        reports.append({**args, **report})
    return reports


def speed_report(
    runs: list[dict], api_runs: list[dict], check: str, profile: str, expected_interface: str,
    now: datetime, max_age: timedelta,
) -> dict:
    directions = {}
    for direction in ("receive", "send"):
        target = f"{profile} · {direction}"
        row = next((run for run in runs if run["check"] == check and run["target"] == target
                    and run["status"] not in {"rate_limited", "busy"}), None)
        if row is None:
            directions[direction] = {"status": "missing", "confirmed": False}
            continue
        result = row.get("result") or {}
        if check == "https_speed":
            observation = result.get("wan_observation") or {}
            observed = observation.get("nat_interface") if observation.get("status") == "confirmed" else None
            speed_fields = ("mbps",)
        else:
            connection = result.get("connection") or {}
            observed = (result.get("kernel_route") or {}).get("dev") if connection.get("peer_address") else None
            speed_fields = ("sender_mbps", "receiver_mbps")
        speeds = {field: result.get(field) for field in speed_fields}
        checked_at = datetime.fromisoformat(row["checked_at"])
        fresh = timedelta(0) <= now - checked_at <= max_age
        api_matches = row in api_runs
        directions[direction] = {
            "status": row["status"], "checked_at": row["checked_at"], "fresh": fresh,
            "api_matches": api_matches, "observed_interface": observed, **speeds,
            "confirmed": (
                fresh and api_matches and row["status"] == "measured" and observed == expected_interface
                and all(type(value) in (int, float) and isfinite(value) and value > 0 for value in speeds.values())
            ),
        }
    return {"check": check, "profile": profile, "expected_interface": expected_interface, "directions": directions}


def verify_speed(script: Path, selections: list[list[str]], max_age: timedelta) -> list[dict]:
    history = mcp_data(mcp_requests(script, [mcp_call("openvpn_network_check_runs", {"limit": 100})])[0])
    api = bridge.api_request("GET", f"{API}/runs?limit=100")["data"]
    now = datetime.now(UTC)
    return [speed_report(history["runs"], api["runs"], *selection, now, max_age) for selection in selections]


def verify(script: Path, max_age: timedelta) -> dict:
    spec = bridge.api_request("GET", "/openapi.json")
    paths = spec["paths"]
    for suffix in ("checks", "route-runs", "interfaces", "runs", "loops", "captures", "captures/{capture_id}"):
        if "get" not in paths[f"{API}/{suffix}"]:
            raise ValueError("OpenAPI read path missing")
    schema = paths[f"{API}/checks"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    if CHECKS - schema["discriminator"]["mapping"].keys():
        raise ValueError("OpenAPI check types missing")

    direct = bridge.api_request("GET", API + "/checks")["data"]
    listed, catalog_reply = mcp_requests(script, [
        ("tools/list", {}),
        mcp_call("openvpn_network_diagnostic_checks"),
    ])
    tools = {entry["name"]: entry for entry in listed["tools"]}
    check_values = tools["openvpn_network_run_check"]["inputSchema"]["properties"]["check"]["enum"]
    catalog = mcp_data(catalog_reply)
    if catalog != direct or MCP_TOOLS - tools.keys() or CHECKS - set(check_values):
        raise ValueError("MCP and API contract mismatch")
    if CHECKS - {entry["check"] for entry in catalog["checks"]}:
        raise ValueError("Diagnostic checks missing")
    profiles = catalog["profiles"]
    scheduled = {profile["id"]: profile["probes"] for profile in profiles["routes"] if profile["scheduled"]}
    if not scheduled:
        raise ValueError("No scheduled route profiles")

    *history, loops = mcp_requests(script, [
        *(mcp_call("openvpn_network_route_runs", {"profile": profile, "limit": 20}) for profile in scheduled),
        mcp_call("openvpn_network_loop_diagnostics"),
    ])
    now = datetime.now(UTC)
    routes = {}
    for (profile, probes), reply in zip(scheduled.items(), history, strict=True):
        query = urlencode({"profile": profile, "limit": 100})
        api_runs = bridge.api_request("GET", f"{API}/route-runs?{query}")["data"]["runs"]
        routes[profile] = route_report(
            mcp_data(reply)["runs"], now, max_age, api_runs=api_runs,
            expected_hops={probe["id"]: probe.get("expected_first_hop") for probe in probes},
            expected_dns={
                probe["id"]: (probe["dns_transport"], bool(probe.get("expected_dns_answers")))
                for probe in probes if probe.get("dns_transport")
            },
            expected_interfaces={
                probe["id"]: probe["expected_kernel_interface"] for probe in probes if probe.get("expected_kernel_interface")
            },
            expected_gateways={
                probe["id"]: probe["expected_kernel_gateway"] for probe in probes if probe.get("expected_kernel_gateway")
            },
            expected_ipsec={probe["id"] for probe in probes if probe.get("ipsec")},
            expected_digests={probe["id"]: probe["config_digest"] for probe in probes},
        )
    return {
        "contracts": "ok",
        "routes": routes,
        "loop_diagnostics": loop_report(mcp_data(loops)["result"]),
        "profiles": {key: len(profiles[key]) for key in ("throughput", "https_speed", "capture")},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-script", type=Path, default=MCP_SCRIPT)
    parser.add_argument("--max-age-minutes", type=int, default=10)
    parser.add_argument("--require-reachable", action="store_true")
    parser.add_argument(
        "--require-ipsec", action="store_true",
        help="require an established IPsec policy with Phase 2 and a reachable target for each IPsec probe",
    )
    parser.add_argument(
        "--require-expected-first-hop", action="store_true",
        help="require confirmation for every configured first hop",
    )
    parser.add_argument(
        "--require-expected-kernel-interface", action="store_true",
        help="require the kernel to confirm the expected interface for every configured probe",
    )
    parser.add_argument(
        "--require-expected-kernel-gateway", action="store_true",
        help="require the kernel to confirm the expected IPv4 gateway for every configured probe",
    )
    parser.add_argument(
        "--require-dns-transport", action="store_true",
        help="require successful DNS responses on each explicitly configured transport",
    )
    parser.add_argument(
        "--require-loop-coverage", action="store_true",
        help="require recent VLAN-aware FDB and STP observations on every switch",
    )
    parser.add_argument("--capture-id", type=UUID, help="verify a nonempty PCAP owned by the current actor")
    parser.add_argument(
        "--speed", action="append", nargs=3, metavar=("CHECK", "PROFILE", "INTERFACE"),
        help="verify both directions of a saved iperf3 or https_speed measurement for the current actor",
    )
    parser.add_argument(
        "--interface", action="append", nargs=2, metavar=("SOURCE", "NAME"),
        help="verify recent interface telemetry in REST and MCP; repeat to check multiple interfaces",
    )
    args = parser.parse_args()
    if args.max_age_minutes < 1:
        parser.error("--max-age-minutes must be positive")
    if any(check not in {"iperf3", "https_speed"} for check, _, _ in args.speed or ()):
        parser.error("--speed CHECK must be iperf3 or https_speed")
    try:
        report = verify(args.mcp_script, timedelta(minutes=args.max_age_minutes))
    except (OSError, LookupError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"contracts": "failed", "error": "diagnostics_verification_failed"}))
        return 1
    routes = report["routes"].values()
    configured_hops = [
        probe for route in routes for probe in route["probes"] if probe.get("expected_first_hop")
    ]
    confirmed_hops = sum(
        probe["path_status"] == "first_hop_matches" and probe["observed_path"] == probe["expected_first_hop"]
        for probe in configured_hops
    )
    report["expected_first_hops"] = {"configured": len(configured_hops), "confirmed": confirmed_hops}
    interface_probes = [
        probe for route in routes for probe in route["probes"] if probe.get("expected_kernel_interface")
    ]
    confirmed_interfaces = sum(probe["kernel_interface_matches"] for probe in interface_probes)
    report["expected_kernel_interfaces"] = {"configured": len(interface_probes), "confirmed": confirmed_interfaces}
    gateway_probes = [
        probe for route in routes for probe in route["probes"] if probe.get("expected_kernel_gateway")
    ]
    confirmed_gateways = sum(probe["kernel_gateway_matches"] for probe in gateway_probes)
    report["expected_kernel_gateways"] = {"configured": len(gateway_probes), "confirmed": confirmed_gateways}
    ipsec_probes = [probe for route in routes for probe in route["probes"] if "ipsec_policy_confirmed" in probe]
    ipsec_confirmed = sum(probe["ipsec_policy_confirmed"] and probe["status"] == "reachable" for probe in ipsec_probes)
    report["ipsec_probes"] = {
        "configured": len(ipsec_probes),
        "policies_confirmed": sum(probe["ipsec_policy_confirmed"] for probe in ipsec_probes),
        "targets_reachable": sum(probe["status"] == "reachable" for probe in ipsec_probes),
        "confirmed": ipsec_confirmed,
    }
    dns_probes = [probe for route in routes for probe in route["probes"] if probe.get("dns_transport")]
    confirmed_dns = sum(
        probe["status"] == "reachable"
        and probe["observed_dns_transport"] == probe["dns_transport"].upper()
        and probe["dns_rcode"] == "NOERROR"
        and (not probe["dns_answers_required"] or probe["dns_answers_match"] is True)
        for probe in dns_probes
    )
    report["dns_transports"] = {"configured": len(dns_probes), "confirmed": confirmed_dns}
    if args.interface:
        try:
            report["interfaces"] = verify_interfaces(
                args.mcp_script, args.interface, timedelta(minutes=args.max_age_minutes),
            )
        except (OSError, LookupError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
            report["interfaces"] = []
            report["interface_error"] = "interface_verification_failed"
    if args.capture_id is not None:
        try:
            report["capture"] = verify_capture(args.mcp_script, args.capture_id)
        except (OSError, LookupError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
            report["capture"] = {"capture_id": str(args.capture_id), "error": "capture_verification_failed"}
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 1
    if args.speed:
        try:
            report["speed"] = verify_speed(args.mcp_script, args.speed, timedelta(minutes=args.max_age_minutes))
        except (OSError, LookupError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
            report["speed"] = []
            report["speed_error"] = "speed_verification_failed"
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.speed and (
        not report["speed"] or any(
            not row["confirmed"] for profile in report["speed"] for row in profile["directions"].values()
        )
    ):
        return 1
    if args.interface and (
        not report["interfaces"] or any(not (row["fresh"] and row["api_matches"]) for row in report["interfaces"])
    ):
        return 1
    if any(not (route["fresh"] and route["profile_matches"] and route["api_matches"]) for route in routes):
        return 1
    if (args.require_expected_first_hop and not configured_hops) or (args.require_dns_transport and not dns_probes):
        return 1
    if args.require_expected_kernel_interface and not interface_probes:
        return 1
    if args.require_expected_kernel_gateway and not gateway_probes:
        return 1
    if args.require_ipsec and not ipsec_probes:
        return 1
    if args.require_loop_coverage:
        coverage = report["loop_diagnostics"]["coverage"]
        if not coverage["total"]:
            return 1
        if not coverage["complete"]:
            return 2
    if args.require_expected_first_hop and confirmed_hops != len(configured_hops):
        return 2
    if args.require_expected_kernel_interface and confirmed_interfaces != len(interface_probes):
        return 2
    if args.require_expected_kernel_gateway and confirmed_gateways != len(gateway_probes):
        return 2
    if args.require_dns_transport and confirmed_dns != len(dns_probes):
        return 2
    if args.require_ipsec and ipsec_confirmed != len(ipsec_probes):
        return 2
    return 2 if args.require_reachable and any(route["status"] != "reachable" for route in routes) else 0


if __name__ == "__main__":
    sys.exit(main())
