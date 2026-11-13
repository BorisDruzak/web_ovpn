"""Read the deployed diagnostics contract and verify scheduled route evidence."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlencode

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


def route_report(
    runs: list[dict], now: datetime, max_age: timedelta, *,
    api_runs: list[dict], expected_hops: dict[str, str | None],
    expected_dns: dict[str, tuple[str, bool]] | None = None,
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
        if probe.get("expected_first_hop"):
            summary.update(
                expected_first_hop=probe["expected_first_hop"],
                observed_path=probe.get("observed_path"),
                path_status=probe.get("path_status", "unconfirmed"),
            )
        if probe.get("dns_transport"):
            evidence = probe.get("evidence", {})
            summary.update(
                dns_transport=probe["dns_transport"],
                observed_dns_transport=evidence.get("dns_transport"),
                dns_rcode=evidence.get("dns_rcode"),
                dns_answers_match=evidence.get("dns_answers_match"),
                dns_answers_required=expected_dns.get(probe["id"], (None, False))[1],
            )
        probes.append(summary)
    reported_hops = {probe["id"]: probe.get("expected_first_hop") for probe in probes}
    reported_transports = {probe["id"]: probe["dns_transport"] for probe in probes if "dns_transport" in probe}
    expected_transports = {probe_id: transport for probe_id, (transport, _) in expected_dns.items()}
    return {
        "status": row["status"],
        "run_id": row["id"],
        "checked_at": row["checked_at"],
        "fresh": bool(probes) and timedelta(0) <= now - checked_at <= max_age,
        "api_matches": row in api_runs,
        "profile_matches": (
            reported_hops == expected_hops and len(probes) == len(expected_hops)
            and reported_transports == expected_transports
        ),
        "probes": probes,
    }


def loop_report(result: dict) -> dict:
    sources = result["sources"]
    return {
        "status": result["status"],
        "since": result["since"],
        "until": result["until"],
        "truncated": result["truncated"],
        "sources": len(sources),
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
        "--require-expected-first-hop", action="store_true",
        help="require confirmation for every configured first hop",
    )
    parser.add_argument(
        "--require-dns-transport", action="store_true",
        help="require successful DNS responses on each explicitly configured transport",
    )
    args = parser.parse_args()
    if args.max_age_minutes < 1:
        parser.error("--max-age-minutes must be positive")
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
    dns_probes = [probe for route in routes for probe in route["probes"] if probe.get("dns_transport")]
    confirmed_dns = sum(
        probe["status"] == "reachable"
        and probe["observed_dns_transport"] == probe["dns_transport"].upper()
        and probe["dns_rcode"] == "NOERROR"
        and (not probe["dns_answers_required"] or probe["dns_answers_match"] is True)
        for probe in dns_probes
    )
    report["dns_transports"] = {"configured": len(dns_probes), "confirmed": confirmed_dns}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if any(not (route["fresh"] and route["profile_matches"] and route["api_matches"]) for route in routes):
        return 1
    if (args.require_expected_first_hop and not configured_hops) or (args.require_dns_transport and not dns_probes):
        return 1
    if args.require_expected_first_hop and confirmed_hops != len(configured_hops):
        return 2
    if args.require_dns_transport and confirmed_dns != len(dns_probes):
        return 2
    return 2 if args.require_reachable and any(route["status"] != "reachable" for route in routes) else 0


if __name__ == "__main__":
    sys.exit(main())
