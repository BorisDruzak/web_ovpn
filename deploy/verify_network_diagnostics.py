"""Read the deployed diagnostics contract and verify scheduled route evidence."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
import subprocess
import sys

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


def route_report(runs: list[dict], now: datetime, max_age: timedelta) -> dict:
    row = next((run for run in runs if run["trigger"] == "scheduled"), None)
    if row is None:
        return {"status": "missing", "fresh": False, "probes": []}
    checked_at = datetime.fromisoformat(row["checked_at"])
    probes = [{"id": probe["id"], "status": probe["status"]} for probe in row["result"]["probes"]]
    return {
        "status": row["status"],
        "checked_at": row["checked_at"],
        "fresh": bool(probes) and timedelta(0) <= now - checked_at <= max_age,
        "probes": probes,
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
    scheduled = {
        profile["id"]: {probe["id"] for probe in profile["probes"]}
        for profile in profiles["routes"] if profile["scheduled"]
    }
    if not scheduled:
        raise ValueError("No scheduled route profiles")

    *history, loops = mcp_requests(script, [
        *(mcp_call("openvpn_network_route_runs", {"profile": profile, "limit": 20}) for profile in scheduled),
        mcp_call("openvpn_network_loop_diagnostics"),
    ])
    now = datetime.now(UTC)
    routes = {
        profile: route_report(mcp_data(reply)["runs"], now, max_age)
        for profile, reply in zip(scheduled, history, strict=True)
    }
    for profile, expected in scheduled.items():
        routes[profile]["profile_matches"] = {probe["id"] for probe in routes[profile]["probes"]} == expected
    loop_data = mcp_data(loops)["result"]
    return {
        "contracts": "ok",
        "routes": routes,
        "loop_diagnostics": {
            "status": loop_data["status"], "sources": len(loop_data["sources"]),
        },
        "profiles": {key: len(profiles[key]) for key in ("throughput", "https_speed", "capture")},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-script", type=Path, default=MCP_SCRIPT)
    parser.add_argument("--max-age-minutes", type=int, default=10)
    parser.add_argument("--require-reachable", action="store_true")
    args = parser.parse_args()
    if args.max_age_minutes < 1:
        parser.error("--max-age-minutes must be positive")
    try:
        report = verify(args.mcp_script, timedelta(minutes=args.max_age_minutes))
    except (OSError, LookupError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"contracts": "failed", "error": "diagnostics_verification_failed"}))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    routes = report["routes"].values()
    if any(not (route["fresh"] and route["profile_matches"]) for route in routes):
        return 1
    return 2 if args.require_reachable and any(route["status"] != "reachable" for route in routes) else 0


if __name__ == "__main__":
    sys.exit(main())
