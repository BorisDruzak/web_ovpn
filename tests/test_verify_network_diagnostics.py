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
            "trigger": "scheduled", "checked_at": (now - timedelta(minutes=2)).isoformat(),
            "status": "partial", "result": {"probes": [
                {"id": "rtk", "status": "reachable"}, {"id": "is74", "status": "unreachable"},
            ]},
        },
    ]

    report = route_report(runs, now, timedelta(minutes=10))
    assert report["fresh"]
    assert report["status"] == "partial"
    assert report["probes"] == [
        {"id": "rtk", "status": "reachable"}, {"id": "is74", "status": "unreachable"},
    ]

    stale = route_report(runs, now + timedelta(minutes=10), timedelta(minutes=10))
    assert not stale["fresh"]
    assert route_report(runs[:1], now, timedelta(minutes=10))["status"] == "missing"


@pytest.mark.parametrize("fresh,matches,strict,expected", [
    (True, True, False, 0),
    (True, True, True, 2),
    (False, True, True, 1),
    (True, False, False, 1),
])
def test_exit_codes_distinguish_stale_contract_and_unreachable_path(monkeypatch, fresh, matches, strict, expected):
    monkeypatch.setattr(sys, "argv", ["verifier", *(["--require-reachable"] if strict else [])])
    monkeypatch.setattr(verifier, "verify", lambda *_: {"routes": {
        "wan": {"fresh": fresh, "profile_matches": matches, "status": "unreachable"},
    }})
    assert verifier.main() == expected
