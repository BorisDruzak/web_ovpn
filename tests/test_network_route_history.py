from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db import Base


@pytest.fixture
def db(tmp_path):
    from app import models  # noqa: F401

    engine = create_engine(f"sqlite:///{tmp_path / 'history.sqlite'}")
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False) as session:
        yield session
    engine.dispose()


def _result(profile: str, checked_at: datetime) -> dict:
    return {
        "check": "route_availability",
        "target": profile,
        "status": "partial",
        "checked_at": checked_at.isoformat(),
        "result": {
            "profile": profile,
            "label": "Test route",
            "probes": [
                {"status": "reachable", "observed_path": "wan-a", "evidence": {"rtt_ms": 5}},
                {"status": "timeout", "observed_path": None, "evidence": {"reason": "timed_out"}},
            ],
        },
    }


def test_history_preserves_evidence_and_isolates_manual_owners(db):
    from app.network_route_history import list_route_runs, persist_route_run

    now = datetime.now(UTC)
    own = _result("wan-a", now - timedelta(seconds=1))
    scheduled = _result("wan-a", now)
    for owner, result in [
        ("user:reader", own),
        ("user:other", _result("wan-a", now)),
        ("service:reader", _result("wan-a", now)),
        ("schedule:", scheduled),
        ("schedule:another", _result("wan-a", now)),
        ("user:reader", _result("wan-b", now)),
    ]:
        persist_route_run(db, owner=owner, result=result)
    db.commit()

    rows = list_route_runs(db, owner="user:reader", profile="wan-a", limit=10)

    assert [row["trigger"] for row in rows] == ["scheduled", "manual"]
    assert [{key: row[key] for key in own} for row in rows] == [
        {**scheduled, "result": {**scheduled["result"], "path_changes": []}}, own,
    ]
    assert all("owner" not in row and datetime.fromisoformat(row["stored_at"]).tzinfo for row in rows)
    assert list_route_runs(db, owner="user:reader", profile="wan-a", limit=1) == rows[:1]


def test_persist_can_be_rolled_back_with_caller_transaction(db):
    from app.network_route_history import list_route_runs, persist_route_run

    persist_route_run(db, owner="user:reader", result=_result("wan-a", datetime.now(UTC)))
    db.rollback()

    assert list_route_runs(db, owner="user:reader", profile=None, limit=10) == []


def test_schedule_is_once_per_five_minute_slot_and_prunes_old_history(db, monkeypatch):
    from app import network_route_history as history
    from app.models import NetworkRouteRun

    now = datetime.now(UTC).replace(minute=10, second=1, microsecond=0)
    expired = _result("wan-a", now - timedelta(days=15))
    history.persist_route_run(db, owner="user:reader", result=expired)
    db.commit()
    assert history.list_route_runs(db, owner="user:reader", profile=None, limit=10) == []
    assert len(db.scalars(select(NetworkRouteRun)).all()) == 1
    monkeypatch.setattr(history, "load_probe_profiles", lambda: SimpleNamespace(routes={
        "wan-a": SimpleNamespace(scheduled=True),
        "wan-b": SimpleNamespace(scheduled=False),
    }))
    invoked = []

    def run(profile_id, profile):
        assert profile.scheduled
        invoked.append(profile_id)
        result = _result(profile_id, now)
        return {"status": result["status"], "result": result["result"]}

    monkeypatch.setattr(history, "run_route_matrix", run)

    assert history.run_scheduled_route_probes(db, now=now) == 1
    assert history.run_scheduled_route_probes(db, now=now + timedelta(minutes=3)) == 0
    assert history.run_scheduled_route_probes(db, now=now + timedelta(minutes=5)) == 1
    assert invoked == ["wan-a", "wan-a"]
    rows = history.list_route_runs(db, owner="service:reader", profile=None, limit=10)
    assert [(row["target"], row["trigger"]) for row in rows] == [
        ("wan-a", "scheduled"), ("wan-a", "scheduled"),
    ]
    assert len(db.scalars(select(NetworkRouteRun)).all()) == 2


def _first_hop_result(profile, checked_at, observed, **selectors):
    result = _result(profile, checked_at)
    result["result"]["probes"] = [{
        "id": "wan",
        "origin": "mikrotik-main",
        "target": "192.0.2.44",
        "protocol": "icmp",
        "source_address": "192.0.2.15",
        "interface": "ether9",
        "routing_table": "main",
        "expected_path": "primary WAN",
        "expected_first_hop": "192.0.2.1",
        "path_status": "observed" if observed else "unconfirmed",
        "observed_path": observed,
        **selectors,
    }]
    return result


def test_scheduled_history_records_transition_once_and_ignores_manual_or_other_profile_runs(db):
    from app.network_route_history import list_route_runs, persist_route_run

    now = datetime.now(UTC)
    for index, owner, profile, hop in [
        (0, "schedule:", "wan-a", "192.0.2.1"),
        (1, "user:reader", "wan-a", "192.0.2.3"),
        (2, "schedule:", "wan-b", "192.0.2.4"),
        (3, "schedule:", "wan-a", "192.0.2.2"),
        (4, "schedule:", "wan-a", "192.0.2.2"),
    ]:
        result = _first_hop_result(profile, now + timedelta(seconds=index), hop)
        persist_route_run(db, owner=owner, result=result)
    db.commit()

    rows = list_route_runs(db, owner="user:reader", profile="wan-a", limit=10)

    assert [row["result"].get("path_changes") for row in rows] == [
        [], [{"probe_id": "wan", "from": "192.0.2.1", "to": "192.0.2.2",
              "checked_at": (now + timedelta(seconds=3)).isoformat()}], None, [],
    ]


@pytest.mark.parametrize(
    ("previous_hop", "current_hop", "selectors"),
    [
        (None, "192.0.2.2", {}),
        ("192.0.2.1", None, {}),
        ("legacy-path-label", "192.0.2.2", {}),
        ("192.0.2.1", "192.0.2.2", {"id": "another"}),
        ("192.0.2.1", "192.0.2.2", {"origin": "mikrotik-hex"}),
        ("192.0.2.1", "192.0.2.2", {"target": "192.0.2.45"}),
        ("192.0.2.1", "192.0.2.2", {"protocol": "tcp"}),
        ("192.0.2.1", "192.0.2.2", {"source_address": "192.0.2.16"}),
        ("192.0.2.1", "192.0.2.2", {"interface": "ether10"}),
        ("192.0.2.1", "192.0.2.2", {"routing_table": "rtab-IS74"}),
        ("192.0.2.1", "192.0.2.2", {"expected_path": "secondary WAN"}),
        ("192.0.2.1", "192.0.2.2", {"expected_first_hop": "192.0.2.2"}),
    ],
)
def test_scheduled_history_does_not_skip_past_incomparable_readings(
    db, previous_hop, current_hop, selectors,
):
    from app.network_route_history import list_route_runs, persist_route_run

    now = datetime.now(UTC)
    for result in [
        _first_hop_result("wan-a", now, "192.0.2.1"),
        _first_hop_result("wan-a", now + timedelta(seconds=1), previous_hop),
        _first_hop_result("wan-a", now + timedelta(seconds=2), current_hop, **selectors),
    ]:
        persist_route_run(db, owner="schedule:", result=result)
    db.commit()

    [latest] = list_route_runs(db, owner="user:reader", profile="wan-a", limit=1)
    assert latest["result"]["path_changes"] == []
