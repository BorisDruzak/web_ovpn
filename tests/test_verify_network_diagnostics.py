from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from deploy import verify_network_diagnostics as verifier
from deploy.verify_network_diagnostics import route_report


@pytest.mark.parametrize("selected,expected,status", [
    ([], ["archive", "vlan50"], 2),
    (["vlan50", "vlan50"], ["vlan50"], 0),
    (["archive", "vlan50"], ["archive", "vlan50"], 2),
    (["manual-only"], [], 1),
])
def test_verify_route_profile_selection(monkeypatch, capsys, selected, expected, status):
    argv = ["verifier", "--require-reachable"]
    for profile in selected:
        argv.extend(("--route-profile", profile))
    monkeypatch.setattr(sys, "argv", argv)
    now = datetime.now(UTC).isoformat()
    profiles = {
        "routes": [
            {"id": name, "scheduled": scheduled, "probes": [{"id": "ping", "config_digest": "digest"}]}
            for name, scheduled in (("archive", True), ("vlan50", True), ("manual-only", False))
        ],
        "throughput": [], "https_speed": [], "capture": [],
    }
    catalog = {"profiles": profiles, "checks": [{"check": name} for name in verifier.CHECKS]}
    histories = {}
    for name, reachability in (("archive", "unreachable"), ("vlan50", "reachable")):
        histories[name] = {"runs": [{
            "id": 1, "trigger": "scheduled", "checked_at": now, "status": reachability,
            "result": {"probes": [{"id": "ping", "status": reachability, "config_digest": "digest"}]},
        }]}
    loops = {"result": {"status": "insufficient_data", "since": now, "until": now, "sources": [], "truncated": False}}
    api_reads, mcp_reads = [], []

    def api_request(method, path):
        if path == "/openapi.json":
            paths = {f"{verifier.API}/{suffix}": {"get": {}} for suffix in (
                "checks", "route-runs", "interfaces", "runs", "loops", "captures", "captures/{capture_id}",
            )}
            paths[f"{verifier.API}/checks"]["post"] = {"requestBody": {"content": {"application/json": {
                "schema": {"discriminator": {"mapping": dict.fromkeys(verifier.CHECKS)}},
            }}}}
            return {"paths": paths}
        if path == f"{verifier.API}/checks":
            return {"data": catalog}
        if path == f"{verifier.API}/loops":
            return {"data": loops}
        profile = path.split("profile=", 1)[1].split("&", 1)[0]
        api_reads.append(profile)
        return {"data": histories[profile]}

    def mcp_requests(script: Path, requests):
        replies = []
        for method, params in requests:
            if method == "tools/list":
                replies.append({"tools": [{"name": name, "inputSchema": {"properties": {
                    "check": {"enum": list(verifier.CHECKS)},
                }}} for name in verifier.MCP_TOOLS]})
            elif params["name"] == "openvpn_network_diagnostic_checks":
                replies.append(catalog)
            elif params["name"] == "openvpn_network_loop_diagnostics":
                replies.append(loops)
            else:
                profile = params["arguments"]["profile"]
                mcp_reads.append(profile)
                replies.append(histories[profile])
        return replies

    monkeypatch.setattr(verifier.bridge, "api_request", api_request)
    monkeypatch.setattr(verifier, "mcp_requests", mcp_requests)
    monkeypatch.setattr(verifier, "mcp_data", lambda reply: reply)
    assert verifier.main() == status
    report = json.loads(capsys.readouterr().out)
    assert api_reads == mcp_reads == expected
    if status == 1:
        assert report["error"] == "unknown_scheduled_route_profiles"
        assert report["profiles"] == ["manual-only"]
    else:
        assert list(report["routes"]) == expected
        assert report["loop_diagnostics"]["api_matches"]


def test_route_report_uses_fresh_scheduled_run_and_preserves_failed_probe():
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    runs = [
        {"trigger": "manual", "checked_at": now.isoformat(), "status": "reachable"},
        {
            "id": 7, "trigger": "scheduled", "checked_at": (now - timedelta(minutes=2)).isoformat(),
            "status": "partial", "result": {"probes": [
                {"id": "rtk", "status": "reachable", "expected_first_hop": "192.0.2.1",
                 "observed_path": "192.0.2.1", "path_status": "first_hop_matches"},
                {"id": "is74", "status": "unreachable"},
            ]},
        },
    ]

    api_runs = [{**runs[1], "id": 8, "checked_at": now.isoformat()}, runs[1]]
    expected_hops = {"rtk": "192.0.2.1", "is74": None}
    report = route_report(runs, now, timedelta(minutes=10), api_runs=api_runs, expected_hops=expected_hops)
    assert report["fresh"]
    assert report["run_id"] == 7
    assert report["api_matches"]
    assert report["profile_matches"]
    assert report["status"] == "partial"
    assert report["probes"] == [
        {"id": "rtk", "status": "reachable", "expected_first_hop": "192.0.2.1",
         "observed_path": "192.0.2.1", "path_status": "first_hop_matches"},
        {"id": "is74", "status": "unreachable"},
    ]

    stale = route_report(
        runs, now + timedelta(minutes=10), timedelta(minutes=10), api_runs=api_runs, expected_hops=expected_hops,
    )
    assert not stale["fresh"]
    missing = route_report(runs[:1], now, timedelta(minutes=10), api_runs=api_runs, expected_hops=expected_hops)
    assert missing["status"] == "missing"
    changed = route_report(
        runs, now, timedelta(minutes=10), api_runs=api_runs, expected_hops={**expected_hops, "rtk": "192.0.2.2"},
    )
    assert changed["fresh"] and changed["api_matches"] and not changed["profile_matches"]


@pytest.mark.parametrize("trace", [
    {"status": "partial", "reason": "hop_limit", "max_hops": 3, "hops": [
        {"ttl": 1, "address": "192.0.2.1", "status": "hop", "rtt_ms": 0.5},
        {"ttl": 2, "address": None, "status": "no_reply", "rtt_ms": None},
        {"ttl": 3, "address": "192.0.2.2", "status": "hop", "rtt_ms": 1.2},
    ]},
    {"status": "unavailable", "reason": "router_api_trace_unavailable", "max_hops": 3, "hops": []},
])
def test_route_report_preserves_bounded_trace_evidence(trace):
    now = datetime.now(UTC)
    run = {
        "id": 1, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "reachable",
        "result": {"probes": [{"id": "wan", "status": "reachable", "evidence": {
            "trace": {**trace, "ignored": "raw output", "hops": [
                {**hop, "ignored": "raw row"} for hop in trace["hops"]
            ]},
        }}]},
    }
    report = route_report([run], now, timedelta(minutes=10), api_runs=[run], expected_hops={"wan": None})
    assert report["api_matches"]
    assert report["probes"][0]["trace"] == trace


def test_route_report_preserves_packet_loss_and_latency_measurements():
    now = datetime.now(UTC)
    metrics = {
        "sent": 3, "received": 3, "packet_loss_pct": 0.0,
        "rtt_ms": {"min": 2.5, "avg": 3.0, "max": 4.0},
        "rtt_variation": {"mean_abs_delta_ms": 0.5, "pairs": 2},
    }
    run = {
        "id": 1, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "partial",
        "result": {"probes": [
            {"id": "wan", "status": "reachable", "evidence": {**metrics, "rtt_ms": {
                **metrics["rtt_ms"], "ignored": "raw output",
            }}},
            {"id": "offline", "status": "unreachable", "evidence": {
                "sent": 3, "received": 0, "packet_loss_pct": 100.0,
            }},
            {"id": "unmeasured", "status": "unavailable", "evidence": {}},
        ]},
    }
    report = route_report(
        [run], now, timedelta(minutes=10), api_runs=[run],
        expected_hops={"wan": None, "offline": None, "unmeasured": None},
    )
    assert report["probes"] == [
        {"id": "wan", "status": "reachable", **metrics},
        {"id": "offline", "status": "unreachable", "sent": 3, "received": 0, "packet_loss_pct": 100.0},
        {"id": "unmeasured", "status": "unavailable"},
    ]


def test_route_report_rejects_previous_configuration_for_same_probe_id():
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    run = {
        "id": 7, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "reachable",
        "result": {"probes": [{"id": "wan", "status": "reachable", "config_digest": "a" * 64}]},
    }
    inputs = {"api_runs": [run], "expected_hops": {"wan": None}}
    current = route_report([run], now, timedelta(minutes=10), **inputs, expected_digests={"wan": "a" * 64})
    assert current["profile_matches"]
    assert current["probes"][0]["configuration_matches"]
    changed = route_report([run], now, timedelta(minutes=10), **inputs, expected_digests={"wan": "b" * 64})
    assert changed["api_matches"] and changed["fresh"] and not changed["profile_matches"]
    assert changed["probes"][0]["configuration_matches"] is False


def test_route_report_rejects_a_different_result_for_the_same_id():
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    run = {
        "id": 7, "trigger": "scheduled", "checked_at": now.isoformat(),
        "status": "reachable", "result": {"probes": [{"id": "rtk", "status": "reachable"}]},
    }
    different = {**run, "result": {"probes": [{"id": "rtk", "status": "timeout"}]}}
    for api_runs in ([], [different]):
        report = route_report([run], now, timedelta(minutes=10), api_runs=api_runs, expected_hops={"rtk": None})
        assert report["fresh"]
        assert not report["api_matches"]


def test_route_report_checks_configured_dns_transport_and_preserves_evidence():
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    run = {
        "id": 7, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "reachable",
        "result": {"probes": [{
            "id": "dns", "status": "reachable", "dns_transport": "tcp",
            "evidence": {"dns_transport": "UDP", "dns_rcode": "NOERROR", "dns_answers_match": True},
        }]},
    }
    report = route_report(
        [run], now, timedelta(minutes=10), api_runs=[run], expected_hops={"dns": None},
        expected_dns={"dns": ("tcp", True)},
    )
    assert report["profile_matches"]
    assert report["probes"][0] == {
        "id": "dns", "status": "reachable", "dns_transport": "tcp", "observed_dns_transport": "UDP",
        "dns_rcode": "NOERROR", "dns_answers_match": True, "dns_answers_required": True,
    }
    changed = route_report(
        [run], now, timedelta(minutes=10), api_runs=[run], expected_hops={"dns": None},
        expected_dns={"dns": ("udp", True)},
    )
    assert not changed["profile_matches"]
    removed = route_report([run], now, timedelta(minutes=10), api_runs=[run], expected_hops={"dns": None})
    assert not removed["profile_matches"]


def test_route_report_keeps_wan_and_ipsec_failure_evidence():
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    run = {
        "id": 7, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "unreachable",
        "result": {"probes": [{
            "id": "gateway", "status": "unreachable", "evidence": {
                "reason": "icmp_unreachable",
                "gateway_link": {"status": "observed", "state": "up"},
                "gateway_source": {"status": "missing", "dhcp": "searching"},
                "gateway_arp": {"status": "observed", "state": "failed", "resolved": False},
                "ignored": "raw probe output",
            },
        }, {
            "id": "alt-vlan", "status": "timeout", "evidence": {
                "reason": "icmp_no_echo_reply",
                "linux_neighbor": {"address": "192.0.2.1", "interface": "eth0.20",
                                   "state": "incomplete", "ignored": "raw probe output"},
            },
        }, {
            "id": "tunnel", "status": "unreachable", "ipsec": {
                "status": "inactive", "local_sa_address_status": "missing",
                "phase2_count": 0, "local_subnet": "192.0.2.0/24", "remote_subnet": "198.51.100.0/24",
                "peer_sa_counters": {
                    "outgoing": {"associations": 2, "bytes": 0, "ignored": "raw output"},
                    "incoming": {"associations": 1, "bytes": None},
                    "unexpected": {"associations": 3, "bytes": 99},
                },
            },
        }, {
            "id": "remote", "status": "timeout", "ipsec": {
                "status": "unavailable", "reason": "collector_timeout", "phase2_count": None,
            },
        }]},
    }
    report = route_report(
        [run], now, timedelta(minutes=10), api_runs=[run],
        expected_hops={"gateway": None, "alt-vlan": None, "tunnel": None, "remote": None},
        expected_ipsec={"tunnel", "remote"},
    )
    gateway, alt, tunnel, remote = report["probes"]
    assert gateway["reason"] == "icmp_unreachable"
    assert gateway["gateway_link"] == {"status": "observed", "state": "up"}
    assert gateway["gateway_source"] == {"status": "missing", "dhcp": "searching"}
    assert gateway["gateway_arp"] == {"status": "observed", "state": "failed", "resolved": False}
    assert "ignored" not in gateway
    assert alt["linux_neighbor"] == {
        "address": "192.0.2.1", "interface": "eth0.20", "state": "incomplete",
    }
    assert tunnel["ipsec"] == {
        "status": "inactive", "phase2_count": 0, "local_sa_address_status": "missing",
        "local_subnet": "192.0.2.0/24", "remote_subnet": "198.51.100.0/24",
        "peer_sa_counters": {
            "outgoing": {"associations": 2, "bytes": 0},
            "incoming": {"associations": 1, "bytes": None},
        },
    }
    assert remote["ipsec"] == {"status": "unavailable", "reason": "collector_timeout"}
    assert report["profile_matches"]
    assert tunnel["ipsec_policy_confirmed"] is False
    assert remote["ipsec_policy_confirmed"] is False
    changed = route_report(
        [run], now, timedelta(minutes=10), api_runs=[run],
        expected_hops={"gateway": None, "alt-vlan": None, "tunnel": None, "remote": None},
        expected_ipsec={"tunnel"},
    )
    assert not changed["profile_matches"]


@pytest.mark.parametrize("policy,status,expected", [
    (None, "reachable", 1),
    (True, "reachable", 0),
    (True, "timeout", 2),
    (False, "reachable", 2),
])
def test_require_ipsec_checks_policy_and_reachability(monkeypatch, policy, status, expected):
    monkeypatch.setattr(sys, "argv", ["verifier", "--require-ipsec"])
    probes = [] if policy is None else [{"status": status, "ipsec_policy_confirmed": policy}]
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {
        "ipsec": {"fresh": True, "profile_matches": True, "api_matches": True, "probes": probes},
    }})
    assert verifier.main() == expected


@pytest.mark.parametrize("phase2,address,confirmed", [
    (1, "assigned", True), (1, None, True), (0, "assigned", False),
    (True, "assigned", False), (1, "missing", False),
])
def test_ipsec_policy_confirmation_requires_positive_phase2(phase2, address, confirmed):
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    run = {
        "id": 7, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "timeout",
        "result": {"probes": [{"id": "tunnel", "status": "timeout", "ipsec": {
            "status": "established", "phase2_count": phase2, "local_sa_address_status": address,
        }}]},
    }
    report = route_report(
        [run], now, timedelta(minutes=10), api_runs=[run],
        expected_hops={"tunnel": None}, expected_ipsec={"tunnel"},
    )
    assert report["probes"][0]["ipsec_policy_confirmed"] is confirmed


@pytest.mark.parametrize("session,route,confirmed", [
    ("not_connected", None, False),
    ("connected", {"status": "route_found", "result": {"dev": "tun0"}}, True),
    ("connected", {"status": "route_found", "result": {"dev": "ens18"}}, False),
    ("connected", {"status": "failed", "result": {"dev": "tun0"}}, False),
    ("address_mismatch", {"status": "route_found", "result": {"dev": "tun0"}}, False),
])
def test_route_report_requires_kernel_evidence_for_expected_interface(session, route, confirmed):
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    run = {
        "id": 7, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "partial",
        "result": {"probes": [{
            "id": "tunnel", "status": "not_connected" if session == "not_connected" else "timeout",
            "expected_kernel_interface": "tun0", "openvpn_client": "router",
            "evidence": {"openvpn_session": session}, "kernel_route": route,
        }]},
    }
    inputs = {"api_runs": [run], "expected_hops": {"tunnel": None}}
    report = route_report(
        [run], now, timedelta(minutes=10), **inputs, expected_interfaces={"tunnel": "tun0"},
    )
    probe = report["probes"][0]
    assert report["profile_matches"]
    assert probe["openvpn_session"] == session
    assert probe["kernel_interface_matches"] is confirmed
    changed = route_report(
        [run], now, timedelta(minutes=10), **inputs, expected_interfaces={"tunnel": "tun1"},
    )
    assert not changed["profile_matches"]


@pytest.mark.parametrize("probes,code", [
    ([], 1),
    ([{"expected_kernel_interface": "tun0", "kernel_interface_matches": False}], 2),
    ([{"expected_kernel_interface": "tun0", "kernel_interface_matches": True}], 0),
])
def test_require_expected_kernel_interface(monkeypatch, probes, code):
    monkeypatch.setattr(sys, "argv", ["verifier", "--require-expected-kernel-interface"])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {
        "vpn": {"fresh": True, "profile_matches": True, "api_matches": True, "probes": probes},
    }})
    assert verifier.main() == code


@pytest.mark.parametrize("observed, confirmed", [("192.0.2.1", True), ("192.0.2.2", False), (None, False)])
def test_route_report_checks_configured_gateway(observed, confirmed):
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    run = {
        "id": 7, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "partial",
        "result": {"probes": [{
            "id": "lan", "status": "reachable" if confirmed else "unavailable",
            "expected_kernel_gateway": "192.0.2.1",
            "kernel_route": {"status": "route_found", "result": {"gateway": observed}},
        }]},
    }
    inputs = {"api_runs": [run], "expected_hops": {"lan": None}}
    report = route_report(
        [run], now, timedelta(minutes=10), **inputs, expected_gateways={"lan": "192.0.2.1"},
    )
    assert report["profile_matches"]
    assert report["probes"][0]["observed_kernel_gateway"] == observed
    assert report["probes"][0]["kernel_gateway_matches"] is confirmed
    assert not route_report([run], now, timedelta(minutes=10), **inputs)["profile_matches"]


@pytest.mark.parametrize("ages,confirmed", [
    ([30, 30], True), ([30, 31], False), ([181, 181], False), ([None, None], False), ([-31, -31], False),
])
def test_route_report_checks_shared_remote_measurement(ages, confirmed):
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    ids = ("dns", "http")
    probes = []
    for probe_id, age in zip(ids, ages, strict=True):
        stamp = (now - timedelta(seconds=age)).isoformat() if age is not None else None
        probes.append({"id": probe_id, "origin": "windows", "status": "reachable",
                       "checked_at": stamp, "evidence": {"origin_measured_at": stamp}})
    row = {"id": 7, "trigger": "scheduled", "checked_at": now.isoformat(), "status": "reachable",
           "result": {"probes": probes}}
    report = route_report(
        [row], now + timedelta(minutes=4), timedelta(minutes=10), api_runs=[row],
        expected_hops=dict.fromkeys(ids), expected_push_origins=dict.fromkeys(ids, "windows"),
    )
    assert report["fresh"] and report["api_matches"]
    assert report["push_origins"]["windows"]["confirmed"] is confirmed


@pytest.mark.parametrize("receipts,code", [({}, 1), ({"windows": {"confirmed": False}}, 2),
                                           ({"windows": {"confirmed": True}}, 0)])
def test_require_fresh_push_receipts(monkeypatch, receipts, code):
    monkeypatch.setattr(sys, "argv", ["verifier", "--require-fresh-push-receipts"])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {
        "vlan": {"fresh": True, "profile_matches": True, "api_matches": True,
                 "probes": [], "push_origins": receipts},
    }})
    assert verifier.main() == code


@pytest.mark.parametrize("changes,match", [
    ({"since": "later-start", "until": "later-end"}, True),
    ({"sources": [{"source": "switch-a", "coverage": {"fdb": {"status": "stale"}}}]}, False),
    ({"truncated": True}, False),
])
def test_loop_observations_match_ignores_only_window_boundaries(changes, match):
    result = {
        "status": "no_evidence", "since": "start", "until": "end", "truncated": False,
        "sources": [{"source": "switch-a", "coverage": {"fdb": {"status": "recent"}}}],
    }
    assert verifier.loop_observations_match(result, {**result, **changes}) is match


def test_loop_api_mismatch_fails_verification(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["verifier"])
    monkeypatch.setattr(verifier, "verify", lambda *_: {
        "routes": {}, "loop_diagnostics": {"api_matches": False},
    })
    assert verifier.main() == 1


def test_loop_report_preserves_per_source_coverage_without_copying_findings():
    coverage = {
        "fdb": {"status": "recent", "truncated": False},
        "stp": {"status": "unavailable", "last_observed_at": None},
        "broadcast": {"status": "recent", "sampled_ports": 4, "valid_intervals": 9, "truncated": False},
    }
    source = {"source": "switch-a", "status": "insufficient_data", "coverage": coverage, "truncated": False}
    result = {
        "status": "insufficient_data",
        "since": "2026-11-13T01:00:00Z",
        "until": "2026-11-13T02:00:00Z",
        "truncated": False,
        "sources": [{**source, "evidence": [{"mac": "02:00:00:00:00:01"}]}],
    }
    report = verifier.loop_report(result)
    assert report == {
        "status": result["status"], "since": result["since"], "until": result["until"],
        "truncated": False, "sources": 1, "source_coverage": [source],
        "coverage": {"assessed": 0, "total": 1, "complete": False},
        "broadcast_coverage": {"assessed": 1, "total": 1, "complete": True},
    }


@pytest.mark.parametrize("fdb,stp,truncated,assessed", [
    ("recent", "recent", False, 1),
    ("recent", "unavailable", False, 0),
    ("insufficient", "recent", False, 0),
    ("recent", "recent", True, 0),
])
def test_loop_coverage_requires_both_sources_and_an_untruncated_window(fdb, stp, truncated, assessed):
    result = verifier.loop_report({
        "status": "suspected_loop", "since": "start", "until": "end", "truncated": truncated,
        "sources": [{
            "source": "switch", "status": "suspected_loop", "truncated": truncated,
            "coverage": {"fdb": {"status": fdb}, "stp": {"status": stp}},
        }],
    })
    assert result["coverage"] == {"assessed": assessed, "total": 1, "complete": bool(assessed)}
    assert result["status"] == "suspected_loop"


@pytest.mark.parametrize("total,complete,expected", [(0, False, 1), (3, False, 2), (3, True, 0)])
def test_require_loop_coverage_distinguishes_missing_partial_and_complete(monkeypatch, total, complete, expected):
    monkeypatch.setattr(sys, "argv", ["verifier", "--require-loop-coverage"])
    monkeypatch.setattr(verifier, "verify", lambda *_: {
        "routes": {"lan": {"fresh": True, "profile_matches": True, "api_matches": True, "probes": []}},
        "loop_diagnostics": {"coverage": {"total": total, "complete": complete}},
    })
    assert verifier.main() == expected


@pytest.mark.parametrize("broadcast,truncated,expected", [
    (None, False, 1),
    ({"status": "recent", "valid_intervals": 0, "truncated": False}, False, 2),
    ({"status": "insufficient", "valid_intervals": 0, "truncated": False}, False, 2),
    ({"status": "recent", "valid_intervals": 3, "truncated": True}, False, 2),
    ({"status": "recent", "valid_intervals": 3, "truncated": False}, True, 2),
    ({"status": "recent", "valid_intervals": 3, "truncated": False}, False, 0),
])
def test_require_broadcast_coverage(monkeypatch, broadcast, truncated, expected):
    coverage = {"fdb": {"status": "insufficient"}, "stp": {"status": "recent"}}
    if broadcast is not None:
        coverage["broadcast"] = broadcast
    loops = verifier.loop_report({
        "status": "insufficient_data", "since": "start", "until": "end", "truncated": truncated,
        "sources": [{"source": "switch", "status": "insufficient_data", "coverage": coverage, "truncated": False}]
        if broadcast is not None else [],
    })
    monkeypatch.setattr(sys, "argv", ["verifier", "--require-broadcast-coverage"])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {}, "loop_diagnostics": loops})
    assert verifier.main() == expected


@pytest.mark.parametrize("change,passed", [
    ("none", True), ("bytes", False), ("count", False), ("empty", False),
    ("path", False), ("size", False),
])
def test_capture_verification_compares_download_and_receipt(tmp_path, change, passed):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1)
    payload = header + struct.pack("<IIII", 1, 0, 1, 1) + b"x"
    if change == "empty":
        payload = header
    path = tmp_path / "network-12345678-1234-1234-1234-123456789abc.pcap"
    path.write_bytes(payload if change != "bytes" else payload[:-1] + b"y")
    receipt = {"capture_id": path.stem.removeprefix("network-"), "size_bytes": len(payload),
               "packets": {"empty": 0, "count": 2}.get(change, 1)}
    download = {"capture_id": receipt["capture_id"], "size_bytes": len(payload), "path": str(path)}
    if change == "path":
        download["path"] = str(path.with_name("unexpected.pcap"))
    if change == "size":
        download["size_bytes"] += 1
    if not passed:
        with pytest.raises(ValueError):
            verifier.capture_report(receipt, download, payload, tmp_path)
        return
    report = verifier.capture_report(receipt, download, payload, tmp_path)
    assert report["packets"] == 1 and report["size_bytes"] == len(payload)
    assert len(report["sha256"]) == 64


@pytest.mark.parametrize("outside", [0, 1])
def test_capture_filter_checks_bidirectional_peer_and_port(monkeypatch, outside):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1)
    packet = struct.pack("<IIII", 1, 0, 1, 1) + b"x"
    payload = header + packet
    profile = {"interface": "ens18", "peer": "192.0.2.20", "protocol": "tcp", "port": 5201}

    def run(args, **kwargs):
        assert args == [
            "tcpdump", "-n", "-r", "-", "-w", "-",
            "tcp and ((src host 192.0.2.20 and src port 5201) or "
            "(dst host 192.0.2.20 and dst port 5201))",
        ]
        assert kwargs["input"] == payload
        return subprocess.CompletedProcess(args, 0, header + packet * (1 - outside))

    monkeypatch.setattr(verifier.subprocess, "run", run)
    if outside:
        with pytest.raises(ValueError, match="outside"):
            verifier.verify_capture_filter(profile, payload, 1)
    else:
        assert verifier.verify_capture_filter(profile, payload, 1) == {"filter": profile, "outside_filter_packets": 0}


def test_capture_cli_reports_failed_verification(monkeypatch, capsys):
    capture_id = "12345678-1234-1234-1234-123456789abc"
    monkeypatch.setattr(sys, "argv", [
        "verifier", "--capture-id", capture_id, "--speed", "iperf3", "lan-test", "ens18",
    ])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"contracts": "ok", "routes": {}})

    def unavailable(_script, selected, *, check_filter=False):
        assert str(selected) == capture_id
        assert not check_filter
        raise ValueError("receipt missing")

    monkeypatch.setattr(verifier, "verify_capture", unavailable)
    speed = [{"directions": {"receive": {"confirmed": True}, "send": {"confirmed": True}}}]
    monkeypatch.setattr(verifier, "verify_speed", lambda *_: speed)
    assert verifier.main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["capture"]["error"] == "capture_verification_failed"
    assert report["speed"] == speed


def test_interface_report_distinguishes_zero_from_missing_and_rejects_drift():
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    points = [
        {"observed_at": "2026-11-13T02:09:00Z", "in_errors_delta": 0, "out_discards_delta": 3},
        {"observed_at": "2026-11-13T02:14:00Z", "in_errors_delta": 0, "out_discards_delta": None},
    ]
    api = {"source": {"id": 1}, "selected": {"key": "wan"}, "points": points}
    mcp = {**api, "until": now.isoformat(), "available_points": 2}
    report = verifier.interface_report(api, mcp, now, timedelta(minutes=10))
    assert report["api_matches"] and report["fresh"]
    assert report["counters"]["in_errors_delta"] == {"intervals": 2, "total": 0}
    assert report["counters"]["out_errors_delta"] == {"intervals": 0, "total": None}
    assert report["counters"]["out_discards_delta"] == {"intervals": 1, "total": 3}
    drifted = {**mcp, "points": [{**points[0], "in_errors_delta": 5}, points[1]]}
    assert not verifier.interface_report(api, drifted, now, timedelta(minutes=10))["api_matches"]
    assert not verifier.interface_report(api, mcp, now + timedelta(minutes=12), timedelta(minutes=10))["fresh"]


@pytest.mark.parametrize("check,path,expected,confirmed", [
    ("https_speed", {"wan_observation": {"status": "confirmed", "nat_interface": "wan1"}}, "wan1", True),
    ("https_speed", {"wan_observation": {"status": "unconfirmed", "nat_interface": "wan1"}}, "wan1", False),
    ("https_speed", {"wan_observation": {"status": "confirmed", "nat_interface": "wan2"}}, "wan1", False),
    ("iperf3", {"kernel_route": {"dev": "ens18"}, "connection": {"peer_address": "192.0.2.1"}}, "ens18", True),
    ("iperf3", {"kernel_route": {"dev": "ens18"}}, "ens18", False),
    ("iperf3", {"kernel_route": {"dev": "ens18"}, "connection": {"peer_address": "192.0.2.1"},
                "wan_observation": {"status": "confirmed", "nat_interface": "wan1"}}, "wan1", True),
    ("iperf3", {"kernel_route": {"dev": "ens18"}, "connection": {"peer_address": "192.0.2.1"},
                "wan_observation": {"status": "unconfirmed"}}, "ens18", False),
])
def test_speed_report_requires_measured_directions_and_path(check, path, expected, confirmed):
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    data = {"mbps": 40} if check == "https_speed" else {"sender_mbps": 5, "receiver_mbps": 4.9}
    rows = [
        {"check": check, "status": "measured", "target": f"test · {direction}",
         "checked_at": now.isoformat(), "result": {**data, **path}}
        for direction in ("receive", "send")
    ]
    report = verifier.speed_report(rows, rows, check, "test", expected, now, timedelta(minutes=10))
    assert all(row["confirmed"] is confirmed for row in report["directions"].values())
    newer_failure = {**rows[0], "status": "failed"}
    limited = {**rows[0], "status": "rate_limited"}
    attempts = [limited, newer_failure, *rows]
    report = verifier.speed_report(attempts, rows, check, "test", expected, now, timedelta(minutes=10))
    assert report["directions"]["receive"]["status"] == "failed"
    assert not report["directions"]["receive"]["api_matches"]
    assert not report["directions"]["receive"]["confirmed"]


@pytest.mark.parametrize("check", ["https_speed", "iperf3"])
def test_speed_report_preserves_gateway_failure_evidence(check):
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    gateway = {
        "profile": "central-wan", "probe": "is74-gateway", "interface": "wan2",
        "status": "unreachable", "reason": "icmp_error",
        "gateway_source": {"status": "missing", "dhcp": "searching"},
        "gateway_link": {"state": "up"},
        "gateway_arp": {"state": "failed", "resolved": False},
    }
    wan = {"status": "unconfirmed", "reason": "no_unique_connection", "expected_interface": "wan2"}
    receive = {"check": check, "status": "wan_gateway_unavailable", "target": "test · receive",
               "checked_at": now.isoformat(), "result": {"gateway_check": gateway}}
    send = {**receive, "status": "wan_unconfirmed", "target": "test · send",
            "result": {"wan_observation": wan}}
    report = verifier.speed_report([receive, send], [receive, send], check, "test", "wan2", now, timedelta(minutes=10))
    assert report["directions"]["receive"]["gateway_check"] == gateway
    assert report["directions"]["send"]["wan_observation"] == wan
    assert all(row["api_matches"] and not row["confirmed"] for row in report["directions"].values())


def test_interface_report_uses_common_tail_when_mcp_limits_history(monkeypatch):
    now = datetime(2026, 11, 13, 2, 15, tzinfo=UTC)
    monkeypatch.setattr(verifier, "MCP_INTERFACE_LIMIT", 1)
    points = [
        {"observed_at": "2026-11-13T02:09:00Z", "in_errors_delta": 5},
        {"observed_at": "2026-11-13T02:14:00Z", "in_errors_delta": 0},
    ]
    api = {"source": {"id": 1}, "selected": {"key": "wan"}, "points": points}
    mcp = {**api, "points": points[-1:], "available_points": 2}
    report = verifier.interface_report(api, mcp, now, timedelta(minutes=10))
    assert report["api_matches"] and report["points"] == 1 and report["available_points"] == 2
    assert report["counters"]["in_errors_delta"] == {"intervals": 1, "total": 0}


@pytest.mark.parametrize("fresh,matches,api_matches,strict,expected", [
    (True, True, True, False, 0),
    (True, True, True, True, 2),
    (False, True, True, True, 1),
    (True, False, True, False, 1),
    (True, True, False, False, 1),
])
def test_exit_codes_distinguish_stale_contract_and_unreachable_path(
    monkeypatch, fresh, matches, api_matches, strict, expected
):
    monkeypatch.setattr(sys, "argv", ["verifier", *(["--require-reachable"] if strict else [])])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {
        "wan": {"fresh": fresh, "profile_matches": matches, "api_matches": api_matches,
                "status": "unreachable", "probes": []},
    }})
    assert verifier.main() == expected


@pytest.mark.parametrize("target_status, expected_hop, observed, path_status, flags, exit_code", [
    ("unreachable", "192.0.2.1", "192.0.2.1", "first_hop_matches", [], 0),
    ("unreachable", "192.0.2.1", "192.0.2.1", "first_hop_matches", ["--require-reachable"], 2),
    ("reachable", "192.0.2.1", "192.0.2.2", "first_hop_mismatch", [], 2),
    ("reachable", "192.0.2.1", None, "unconfirmed", [], 2),
    ("reachable", "192.0.2.1", "192.0.2.2", "first_hop_matches", [], 2),
    ("reachable", None, None, "unconfirmed", [], 1),
])
def test_expected_first_hop_is_verified_independently_of_target_status(
    monkeypatch, target_status, expected_hop, observed, path_status, flags, exit_code,
):
    monkeypatch.setattr(sys, "argv", ["verifier", "--require-expected-first-hop", *flags])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {
        "wan": {"fresh": True, "profile_matches": True, "api_matches": True, "status": target_status,
                "probes": [{"id": "rtk", "status": target_status, "expected_first_hop": expected_hop,
                            "observed_path": observed, "path_status": path_status}]},
    }})
    assert verifier.main() == exit_code


@pytest.mark.parametrize("transport,observed,status,rcode,required,answers,expected", [
    ("tcp", "TCP", "reachable", "NOERROR", True, True, 0),
    ("udp", "UDP", "reachable", "NOERROR", False, None, 0),
    ("tcp", "UDP", "reachable", "NOERROR", True, True, 2),
    ("tcp", None, "reachable", "NOERROR", True, True, 2),
    ("tcp", "TCP", "unreachable", "NOERROR", True, True, 2),
    ("tcp", "TCP", "reachable", "NXDOMAIN", True, True, 2),
    ("tcp", "TCP", "reachable", "NOERROR", True, False, 2),
    ("tcp", "TCP", "reachable", "NOERROR", True, None, 2),
    (None, "TCP", "reachable", "NOERROR", True, True, 1),
])
def test_strict_dns_transport_checks_the_response(
    monkeypatch, transport, observed, status, rcode, required, answers, expected,
):
    monkeypatch.setattr(sys, "argv", ["verifier", "--require-dns-transport"])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {
        "lan": {"fresh": True, "profile_matches": True, "api_matches": True, "status": status,
                "probes": [{"id": "dns", "status": status, "dns_transport": transport,
                            "observed_dns_transport": observed, "dns_rcode": rcode,
                            "dns_answers_required": required, "dns_answers_match": answers}]},
    }})
    assert verifier.main() == expected
