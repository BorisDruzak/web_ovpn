from datetime import UTC, datetime, timedelta
import sys

import pytest

from deploy import verify_network_diagnostics as verifier
from deploy.verify_network_diagnostics import route_report


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


def test_loop_report_preserves_per_source_coverage_without_copying_findings():
    coverage = {
        "fdb": {"status": "recent", "truncated": False},
        "stp": {"status": "unavailable", "last_observed_at": None},
        "broadcast": {"status": "recent", "sampled_ports": 4, "valid_intervals": 9},
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
    }


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
