import json
from datetime import UTC, datetime, timedelta

import pytest

from app.network_probe_profiles import RouteProfile


ORIGIN = "test-windows"
PROFILE = "test-vlan"
NOW = datetime(2026, 11, 13, 1, tzinfo=UTC)


def test_receiver_loads_routes_even_with_newer_speed_fields(tmp_path, monkeypatch, push_profile):
    from app import network_probe_profiles

    config = tmp_path / "profiles.json"
    config.write_text(json.dumps({
        "routes": {PROFILE: push_profile.model_dump()},
        "https_speed": {"future": {"future_speed_field": True}},
    }), encoding="utf-8")
    monkeypatch.setattr(network_probe_profiles, "PROFILE_PATH", config)
    monkeypatch.setattr(network_probe_profiles, "_is_trusted_file", lambda info: True)
    assert network_probe_profiles.load_probe_profiles().routes == {}
    assert network_probe_profiles.load_probe_profiles(routes_only=True).routes[PROFILE] == push_profile


def test_map_uses_fresh_windows_dns_receipts_for_both_transports(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from app import infrastructure_endpoint_ports as ports, network_route_spool as spool
    from app.infrastructure_map import load_infrastructure_map

    probes = [{"id": transport, "push_origin": ORIGIN, "target": "192.0.2.1", "protocol": "dns",
               "source_address": "192.0.2.20", "expected_kernel_interface": "ifindex-10", "expected_path": "VLAN",
               "dns_name": "example.test.", "dns_transport": transport, "expected_dns_answers": ["192.0.2.80"]}
              for transport in ("udp", "tcp")]
    profile = RouteProfile.model_validate({"label": "Windows", "probes": probes})
    monkeypatch.setattr(ports, "load_probe_profiles", lambda **_: SimpleNamespace(routes={PROFILE: profile}))
    monkeypatch.setattr(spool, "SPOOL_PATH", tmp_path)
    monkeypatch.setattr(spool, "utcnow", lambda: NOW)
    (tmp_path / ORIGIN).mkdir()
    data = {}
    for probe in profile.probes:
        envelope = json.loads(receipt(probe))["probes"][probe.id]
        envelope["result"]["evidence"] = {"duration_ms": 5, "dns_rcode": "NOERROR", "dns_answers_match": True,
                                          "dns_transport": probe.id.upper()}
        data[probe.id] = envelope
    spool.store_receipt(ORIGIN, PROFILE, profile, json.dumps({"measured_at": NOW.isoformat(), "probes": data}).encode(), now=NOW)
    node = {"id": "dns", "name": "DNS", "kind": "Сервис", "probeTargetIP": "192.0.2.1"}
    station = {"id": "pc", "name": "Windows", "kind": "Рабочая станция"}
    graph = {"schema": 1, "snapshotAt": NOW.isoformat(), "nodes": [node, station], "links": []}
    ports.collect_endpoint_dns(graph, {"dns": {"origin": ORIGIN, "profile": PROFILE,
                                               "station": "pc", "probes": ["udp", "tcp"]}}, NOW)
    path = tmp_path / "map.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    public = load_infrastructure_map(path, NOW)
    dns = next(node for node in public["nodes"] if node["id"] == "dns")
    assert dns["mapStatus"] == "ok"
    assert {c["dns"]["transport"] for c in dns["serviceChecks"]} == {"UDP", "TCP"}
    assert all(c["checkedAt"] == NOW.isoformat() and c["dns"]["answersMatch"] is True for c in dns["serviceChecks"])
    assert any(link["kind"] == "Источник проверки" for link in public["links"])
    expired = next(node for node in load_infrastructure_map(path, NOW + timedelta(minutes=4))["nodes"] if node["id"] == "dns")
    assert expired["mapStatus"] == "unknown"
    for envelope in data.values():
        envelope["result"]["kernel_route"]["result"].pop("gateway")
    now = NOW + timedelta(seconds=1)
    adapter = {"name": "Ethernet", "mac": "02:00:00:00:00:10", "index": 10,
               "address": "192.0.2.20", "status": "Up", "neighbors": {"192.0.2.1": "02:00:00:00:00:01"}}
    spool.store_receipt(ORIGIN, PROFILE, profile, json.dumps({"measured_at": now.isoformat(), "probes": data,
                                                             "adapter": adapter}).encode(), now=now)
    monkeypatch.setattr(spool, "utcnow", lambda: now)
    bindings = {"endpoint_dns": {"dns": {"origin": ORIGIN, "profile": PROFILE, "probes": ["udp", "tcp"],
                                        "neighbor_address": "192.0.2.1"}}}
    assert ports.read_windows_dns_neighbors(bindings, now) == {"192.0.2.1": ("02:00:00:00:00:01", now.isoformat())}
    assert not ports.read_windows_dns_neighbors(bindings, now + timedelta(minutes=4))


@pytest.fixture
def push_profile():
    return RouteProfile.model_validate({"label": "Windows", "probes": [{
        "id": "http", "push_origin": ORIGIN, "target": "192.0.2.80", "protocol": "http",
        "source_address": "192.0.2.20", "expected_path": "VLAN", "expected_kernel_interface": "ifindex-10",
        "expected_kernel_gateway": "192.0.2.1",
    }]})


def test_map_exposes_windows_http_without_overriding_server_checks(tmp_path, monkeypatch, push_profile):
    from types import SimpleNamespace
    from app import infrastructure_endpoint_ports as ports, network_route_spool as spool
    from app.infrastructure_map import load_infrastructure_map

    monkeypatch.setattr(ports, "load_probe_profiles", lambda **_: SimpleNamespace(routes={PROFILE: push_profile}))
    monkeypatch.setattr(spool, "SPOOL_PATH", tmp_path)
    monkeypatch.setattr(spool, "utcnow", lambda: NOW)
    (tmp_path / ORIGIN).mkdir()
    probe, = push_profile.probes
    spool.store_receipt(ORIGIN, PROFILE, push_profile, receipt(probe), now=NOW)
    primary = {"source": "UI_VPN", "method": "HTTP", "required": True, "state": "unreachable",
               "target": probe.target, "path": "/", "port": 80, "checkedAt": NOW.isoformat()}
    service = {"id": "directum", "name": "Directum", "kind": "Сервис", "serviceChecks": [primary],
               "reachability": {**primary, "source": "Проверка сервиса"}}
    graph = {"schema": 1, "snapshotAt": NOW.isoformat(), "nodes": [service,
             {"id": "pc", "name": "Windows", "kind": "Рабочая станция"}], "links": []}
    ports.collect_endpoint_http(graph, {"directum": {"station": "pc", "origin": ORIGIN,
                                                     "profile": PROFILE, "probe": probe.id}}, NOW)
    path = tmp_path / "map.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    node = next(node for node in load_infrastructure_map(path, NOW)["nodes"] if node["id"] == "directum")
    assert node["mapStatus"] == "critical"
    check = next(check for check in node["serviceChecks"] if check.get("supplemental"))
    assert check["state"] == "reachable" and check["httpStatus"] == 200
    assert check["checkedAt"] == NOW.isoformat()
    expired = next(node for node in load_infrastructure_map(path, NOW + timedelta(minutes=4))["nodes"] if node["id"] == "directum")
    assert next(c for c in expired["serviceChecks"] if c.get("supplemental"))["state"] == "unknown"


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
        }, None

    monkeypatch.setattr(network_route_spool, "SPOOL_PATH", tmp_path)
    monkeypatch.setattr(network_route_spool, "utcnow", lambda: NOW)
    monkeypatch.setattr(network_route_spool, "_read", read)
    result = network_route_matrix.run_route_matrix(PROFILE, profile)
    assert result["status"] == "reachable"
    assert len(reads) == 1
    assert {row["evidence"]["origin_measured_at"] for row in result["result"]["probes"]} == {NOW.isoformat()}


def test_adapter_receipt_requires_matching_route_and_fresh_measurement(tmp_path, monkeypatch, push_profile):
    from app import network_route_spool as spool
    monkeypatch.setattr(spool, "SPOOL_PATH", tmp_path)
    (tmp_path / ORIGIN).mkdir()
    probe, = push_profile.probes
    data = json.loads(receipt(probe))
    adapter = {"name": "Ethernet", "mac": "02:00:00:00:00:10", "index": 10,
               "address": "192.0.2.20", "status": "Up"}
    data["adapter"] = adapter
    spool.store_receipt(ORIGIN, PROFILE, push_profile, json.dumps(data).encode(), now=NOW)
    assert spool.read_adapter_observation(ORIGIN, PROFILE, push_profile, NOW) == {**adapter, "checkedAt": NOW.isoformat()}
    assert spool.read_adapter_observation(ORIGIN, PROFILE, push_profile, NOW + timedelta(minutes=4)) == {}
    adapter["neighbors"] = {"192.0.2.1": "02:00:00:00:00:01", "192.0.2.99": "02:00:00:00:00:02"}
    adapter["speedBps"] = 10**9
    data["measured_at"] = (NOW + timedelta(milliseconds=500)).isoformat()
    now = NOW + timedelta(milliseconds=500)
    spool.store_receipt(ORIGIN, PROFILE, push_profile, json.dumps(data).encode(), now=now)
    assert spool.read_adapter_observation(ORIGIN, PROFILE, push_profile, now)["neighbors"] == {
        "192.0.2.1": "02:00:00:00:00:01",
    }
    assert spool.read_adapter_observation(ORIGIN, PROFILE, push_profile, now)["speedBps"] == 10**9
    adapter["speedBps"] = True
    now += timedelta(milliseconds=250)
    data["measured_at"] = now.isoformat()
    spool.store_receipt(ORIGIN, PROFILE, push_profile, json.dumps(data).encode(), now=now)
    assert "speedBps" not in spool.read_adapter_observation(ORIGIN, PROFILE, push_profile, now)
    data["measured_at"] = (NOW + timedelta(seconds=1)).isoformat()
    adapter["index"] = 11
    spool.store_receipt(ORIGIN, PROFILE, push_profile, json.dumps(data).encode(), now=NOW + timedelta(seconds=1))
    assert spool.read_adapter_observation(ORIGIN, PROFILE, push_profile, NOW + timedelta(seconds=1)) == {}


@pytest.mark.parametrize("learned_count", [1, 2])
def test_endpoint_pair_uses_fresh_switch_mac_and_physical_adapter(tmp_path, monkeypatch, push_profile, learned_count):
    from types import SimpleNamespace
    from app import infrastructure_endpoint_ports as ports
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    mac = "02:00:00:00:00:10"
    at = NOW.isoformat()
    monkeypatch.setattr(ports, "load_probe_profiles", lambda **_: SimpleNamespace(routes={PROFILE: push_profile}))
    monkeypatch.setattr(ports, "read_adapter_observation", lambda *_: {
        "name": "Ethernet", "mac": mac, "checkedAt": at, "index": 10, "speedBps": 10**9,
    })
    inventory = {"a": "Port7", "b": "Ethernet", "source": "GitHub", "confirmed": True}
    link = {"a": "switch", "b": "pc", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [inventory]}
    graph = {"nodes": [
        {"id": "pc", "kind": "Рабочая станция", "endpointKey": f"mac:{mac.upper()}"},
        {"id": "switch", "kind": "Коммутатор", "ports": [{
            "name": "Port7", "linkCheck": {"state": "up", "checkedAt": at, "endpointMac": {"deviceId": "pc", "mac": mac}},
            "fdbLearned": {"checkedAt": at, "partial": False, "learnedMacCount": learned_count},
        }]},
    ], "links": [link]}
    ports.confirm_endpoint_ports(graph, {"pc": {"origin": ORIGIN, "profile": PROFILE}}, NOW)
    assert link["portEvidence"] == [inventory] + (
        [{**inventory, "source": "SNMP + Windows", "at": at, "windowsAdapter": {
            "ifIndex": 10, "checkedAt": at, "switchCheckedAt": at,
        }}] if learned_count == 1 else []
    )
    for node in graph["nodes"]:
        node["name"] = node["id"]
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps({**graph, "schema": 1, "snapshotAt": at}), encoding="utf-8")
    public = load_infrastructure_map(path, NOW)
    audit = summarize_topology(public)["topologyAudit"]
    if learned_count == 1:
        assert audit["currentPairs"][0]["evidence"][0]["windowsAdapter"] == link["portEvidence"][-1]["windowsAdapter"]
        pair = audit["currentPairs"][0]
        side = "a" if pair["a"] == "pc" else "b"
        assert pair["portStates"][side] == {
            "state": "up", "checkedAt": at, "speedBps": 10**9, "source": "Windows · физический адаптер",
        }
    else:
        assert next(node for node in public["nodes"] if node["id"] == "pc")["ports"] == []
    stale = load_infrastructure_map(path, NOW + timedelta(minutes=4))
    expired = summarize_topology(stale)["topologyAudit"]
    assert expired["currentPairTotal"] == 0 and expired["inventoryOnlyPairTotal"] == 1
    assert all(port["state"] == "unknown" for node in stale["nodes"] if node["id"] == "pc" for port in node["ports"])


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
