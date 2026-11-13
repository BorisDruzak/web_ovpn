import json
from datetime import UTC, datetime, timedelta

import pytest

from app.network_probe_profiles import RouteProfile


ORIGIN = "test-windows"
PROFILE = "test-vlan"
NOW = datetime(2026, 11, 13, 1, tzinfo=UTC)


@pytest.fixture
def push_profile():
    return RouteProfile.model_validate({"label": "Windows", "probes": [{
        "id": "http", "push_origin": ORIGIN, "target": "192.0.2.80", "protocol": "http",
        "source_address": "192.0.2.20", "expected_path": "VLAN", "expected_kernel_interface": "ifindex-10",
        "expected_kernel_gateway": "192.0.2.1",
    }]})


def receipt(probe, *, measured=NOW, source="192.0.2.20", gateway="192.0.2.1"):
    return json.dumps({"measured_at": measured.isoformat(), "probes": {probe.id: {
        "digest": probe.config_digest(), "result": {
            "status": "reachable", "evidence": {"http_status": 200, "duration_ms": 5, "private": "discard"},
            "kernel_route": {"status": "route_found", "result": {
                "dst": probe.target, "from": source, "dev": "ifindex-10", "gateway": gateway,
            }},
        },
    }}}).encode()


def test_pushed_measurement_uses_original_time_and_current_config(tmp_path, monkeypatch, push_profile):
    from app import network_route_matrix, network_route_spool

    monkeypatch.setattr(network_route_spool, "SPOOL_PATH", tmp_path)
    (tmp_path / ORIGIN).mkdir()
    monkeypatch.setattr(network_route_spool, "utcnow", lambda: NOW)
    probe, = push_profile.probes
    network_route_spool.store_receipt(ORIGIN, PROFILE, push_profile, receipt(probe), now=NOW)
    row, = network_route_matrix.run_route_matrix(PROFILE, push_profile)["result"]["probes"]
    assert row["status"] == "reachable"
    assert row["origin"] == ORIGIN
    assert row["checked_at"] == NOW.isoformat()
    assert row["evidence"]["origin_measured_at"] == NOW.isoformat()
    assert row["evidence"]["http_status"] == 200
    assert "private" not in row["evidence"]
    changed = probe.model_copy(update={"http_path": "/health"})
    changed_profile = push_profile.model_copy(update={"probes": [changed]})
    assert network_route_spool.read_measurements(PROFILE, changed_profile)[probe.id]["evidence"]["reason"] == "profile_mismatch"
    monkeypatch.setattr(network_route_spool, "utcnow", lambda: NOW + timedelta(minutes=4))
    stale = network_route_spool.read_measurements(PROFILE, push_profile)[probe.id]
    assert stale["evidence"]["reason"] == "origin_receipt_stale"
    assert stale["evidence"]["origin_measured_at"] == NOW.isoformat()
    assert "measured_at" not in stale


def test_matrix_reads_one_receipt_for_all_probes_from_origin(tmp_path, monkeypatch, push_profile):
    from app import network_route_matrix, network_route_spool

    probe, = push_profile.probes
    second = probe.model_copy(update={"id": "http-second"})
    profile = push_profile.model_copy(update={"probes": [probe, second]})
    reads = []

    def read(path):
        reads.append(path)
        return NOW, {
            definition.id: json.loads(receipt(definition))["probes"][definition.id]
            for definition in profile.probes
        }

    monkeypatch.setattr(network_route_spool, "SPOOL_PATH", tmp_path)
    monkeypatch.setattr(network_route_spool, "utcnow", lambda: NOW)
    monkeypatch.setattr(network_route_spool, "_read", read)
    result = network_route_matrix.run_route_matrix(PROFILE, profile)
    assert result["status"] == "reachable"
    assert len(reads) == 1
    assert {row["evidence"]["origin_measured_at"] for row in result["result"]["probes"]} == {NOW.isoformat()}


def test_push_rejects_unapproved_replay_and_wrong_route(tmp_path, monkeypatch, push_profile):
    from app import network_route_spool

    monkeypatch.setattr(network_route_spool, "SPOOL_PATH", tmp_path)
    (tmp_path / ORIGIN).mkdir()
    probe, = push_profile.probes
    for origin, payload in (
        ("other", receipt(probe)), (ORIGIN, receipt(probe, source="192.0.2.2")),
        (ORIGIN, receipt(probe, gateway="192.0.2.2")),
        (ORIGIN, receipt(probe, measured=NOW + timedelta(minutes=1))),
    ):
        with pytest.raises(ValueError):
            network_route_spool.store_receipt(origin, PROFILE, push_profile, payload, now=NOW)
    network_route_spool.store_receipt(ORIGIN, PROFILE, push_profile, receipt(probe), now=NOW)
    network_route_spool.store_receipt(ORIGIN, PROFILE, push_profile, receipt(probe), now=NOW)
    with pytest.raises(ValueError):
        network_route_spool.store_receipt(
            ORIGIN, PROFILE, push_profile, receipt(probe, measured=NOW - timedelta(seconds=2)), now=NOW,
        )
