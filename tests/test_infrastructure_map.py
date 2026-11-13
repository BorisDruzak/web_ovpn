import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from test_context_api import make_client


@pytest.mark.parametrize(("power", "age", "network"), [
    ("Off", 0, "unknown"),
    ("Off", 6, "unknown"),
    ("Off", 0, "reachable"),
    ("On", 0, "unknown"),
])
def test_pending_port_pair_reports_fresh_redfish_shutdown(tmp_path, power, age, network):
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(minutes=age)).isoformat()
    path = tmp_path / "map.json"
    path.write_text(json.dumps({"schema": 1, "snapshotAt": now.isoformat(), "nodes": [
        {"id": "sw", "name": "Switch", "kind": "Коммутатор"},
        {"id": "server", "name": "Server", "kind": "Сервер",
         "reachability": {"state": network, "source": "UI_VPN", "method": "ICMP", "checkedAt": now.isoformat()},
         "hardwarePower": {"state": power, "controllerId": "bmc", "checkedAt": stamp}},
        {"id": "bmc", "name": "BMC", "kind": "Контроллер управления"},
    ], "links": [
        {"a": "sw", "b": "server", "kind": "Сетевое соединение", "source": "GitHub", "confirmed": False,
         "portEvidence": [{"a": "ge14", "b": "eth2", "source": "GitHub", "confirmed": False}]},
    ]}), encoding="utf-8")
    graph = load_infrastructure_map(path, now, include_guest_attachments=True)
    audit = summarize_topology(graph)["topologyAudit"]
    pending, = audit["pending"]
    assert audit["currentPairTotal"] == 0
    assert "no_live_peer_identity" in pending["confirmationGaps"]
    if power == "Off" and age == 0 and network == "unknown":
        assert pending["stoppedEndpoints"] == {"b": {"controllerId": "bmc", "checkedAt": stamp}}
        assert audit["confirmationGapCounts"]["endpoint_powered_off"] == 1
    else:
        assert "stoppedEndpoints" not in pending
        assert "endpoint_powered_off" not in audit["confirmationGapCounts"]
    browser_pair, = graph["pendingPortPairs"]
    assert browser_pair.get("stoppedEndpoints") == pending.get("stoppedEndpoints")


@pytest.mark.parametrize(("placement", "other_host", "service_state", "age", "expected"), [
    (True, False, "unknown", 0, "stopped"),
    (False, False, "unknown", 0, "unknown"),
    (True, True, "unknown", 0, "unknown"),
    (True, False, "reachable", 0, "reachable"),
    (True, False, "unknown", 6, "unknown"),
])
def test_service_status_uses_fresh_redfish_power_of_its_only_host(placement, other_host, service_state, age, expected):
    from app.infrastructure_map import _map_statuses, _public_node, summarize_guest_attachment

    now = datetime.now(timezone.utc)
    rows = [
        {"id": "host", "kind": "Сервер", "hardwarePower": {
            "state": "Off", "controllerId": "bmc", "checkedAt": (now - timedelta(minutes=age)).isoformat()}},
        {"id": "other", "kind": "Сервер"},
        {"id": "web", "kind": "Сервис", "reachability": {
            "state": service_state, "source": "UI_VPN", "method": "HTTP", "checkedAt": now.isoformat()}},
    ]
    links = [{"a": "host", "b": "web", "kind": "Размещение", "confirmed": placement, "portEvidence": []}]
    if other_host:
        links.append({**links[0], "a": "other"})
    nodes = {row["id"]: _public_node(row, now) for row in rows}
    _map_statuses(nodes, links)
    service = nodes["web"]
    assert service["reachability"]["state"] == expected
    if expected == "stopped":
        assert service["mapStatus"] == "critical"
        assert service["reachability"] == {
            **nodes["host"]["reachability"], "stoppedBy": {"hostId": "host", "controllerId": "bmc"},
        }
        result = summarize_guest_attachment({"nodes": list(nodes.values()), "links": links}, "web")
        assert result["attachment"]["reachability"] == service["reachability"]
    else:
        assert "stoppedBy" not in service["reachability"]


@pytest.mark.parametrize(("power", "network", "expected"), [
    ("Off", "unknown", "stopped"),
    ("Off", "reachable", "reachable"),
    ("On", "unknown", "unknown"),
    ("On", "reachable", "reachable"),
    (None, "unknown", "unknown"),
])
def test_redfish_power_does_not_equate_power_on_with_os_availability(monkeypatch, power, network, expected):
    from app import infrastructure_redfish as redfish
    from app.infrastructure_map import _map_statuses, _public_node

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    host = {"id": "server", "kind": "Сервер", "reachability": {
        "state": network, "source": "UI_VPN", "method": "ICMP", "checkedAt": stamp}}
    bmc = {"id": "bmc", "kind": "Контроллер управления", "probeTargetIP": "192.0.2.31",
           "probeTargetIdentityAt": stamp}
    graph = {"nodes": [host, bmc], "links": [
        {"a": "bmc", "b": "server", "kind": "Управление оборудованием", "confirmed": True}]}
    spec = {"bmc": {"ip": "192.0.2.31", "tls_sha256": "a" * 64, "path": "/redfish/v1/Systems/system"}}
    reset = (now - timedelta(days=7)).isoformat()
    monkeypatch.setattr(redfish, "_read_resource", lambda *_: {
        "PowerState": power, "PowerRestorePolicy": "AlwaysOff", "LastResetTime": reset,
        "Status": {"Health": "OK", "HealthRollup": "Warning"},
        "MemorySummary": {"TotalSystemMemoryGiB": 64},
    })
    redfish.collect_redfish_power(graph, spec, None, now)
    node = _public_node(host, datetime.now(timezone.utc))
    assert node["reachability"]["state"] == expected
    assert node.get("hardwarePower", {}).get("state") == power
    if power:
        assert node["hardwarePower"]["restorePolicy"] == "AlwaysOff"
        assert node["hardwarePower"]["lastResetAt"] == reset
        assert node["hardwarePower"]["health"] == "OK"
        assert node["hardwarePower"]["healthRollup"] == "Warning"
        assert node["hardwarePower"]["totalSystemMemoryGiB"] == 64
        if power == "On" and network == "reachable":
            _map_statuses({node["id"]: node}, [])
            assert node["mapStatus"] == "warn"
        host["hardwarePower"].update(restorePolicy="invalid", lastResetAt=(now + timedelta(days=1)).isoformat(),
                                     health="invalid", healthRollup=None, totalSystemMemoryGiB=True)
        public = _public_node(host, datetime.now(timezone.utc))["hardwarePower"]
        assert "restorePolicy" not in public and "lastResetAt" not in public
        assert not {"health", "healthRollup", "totalSystemMemoryGiB"} & public.keys()
    expired = _public_node(host, now + timedelta(minutes=6))
    assert "hardwarePower" not in expired and expired["reachability"]["state"] != "stopped"
    graph["links"][0]["confirmed"] = False
    monkeypatch.setattr(redfish, "_read_resource", lambda *_: pytest.fail("unverified controller queried"))
    redfish.collect_redfish_power(graph, spec, None, now)


@pytest.mark.parametrize(("valid_system", "confirmed", "state"), [
    (True, True, "reachable"),
    (False, True, "unknown"),
    (True, False, None),
])
def test_redfish_service_reports_authenticated_system_read(monkeypatch, valid_system, confirmed, state):
    from app import infrastructure_redfish as redfish
    from app.infrastructure_map import _public_node

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path = "/redfish/v1/Systems/system"
    ip = "192.0.2.31"
    service = {"id": "redfish", "kind": "Сервис"}
    host = {"id": "server", "kind": "Сервер"}
    controller = {"id": "bmc", "kind": "Контроллер управления", "probeTargetIP": ip, "probeTargetIdentityAt": stamp}
    graph = {"nodes": [service, host, controller], "links": [
        {"a": "bmc", "b": "server", "kind": "Управление оборудованием", "confirmed": True},
        {"a": "bmc", "b": "redfish", "kind": "Размещение", "confirmed": confirmed},
    ]}
    monkeypatch.setattr(redfish, "_read_resource", lambda *_: {"PowerState": "Off"} if valid_system else None)
    redfish.collect_redfish_power(graph, {
        "bmc": {"ip": ip, "path": path, "service_id": "redfish"},
    }, None, now)
    checks = _public_node(service, datetime.now(timezone.utc))["serviceChecks"]
    if state is None:
        assert checks == []
    else:
        check, = checks
        assert check["method"] == "Redfish · ComputerSystem"
        assert check["component"] and check["required"]
        assert check["target"] == ip and check["path"] == path and check["identityCheckedAt"] == stamp
        assert check["state"] == state


@pytest.mark.parametrize("failure", [None, "mac", "stale", "shared", "speed", "down", "disabled", "address"])
def test_redfish_management_pair_requires_matching_current_switch_evidence(tmp_path, monkeypatch, failure):
    from app import infrastructure_redfish as redfish
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    observed = (now - timedelta(minutes=11)).isoformat() if failure == "stale" else stamp
    ip, mac = "192.0.2.31", "02:00:00:00:00:31"
    path = "/redfish/v1/Managers/bmc/EthernetInterfaces/eth0"
    interface = {"Id": "eth0", "InterfaceEnabled": failure != "disabled",
                 "LinkStatus": "LinkDown" if failure == "down" else "LinkUp", "MACAddress": mac,
                 "SpeedMbps": 100 if failure == "speed" else 1000,
                 "IPv4Addresses": [{"Address": "192.0.2.32" if failure == "address" else ip}]}
    monkeypatch.setattr(redfish, "_read_resource", lambda _, __, resource: interface if resource == path else {"PowerState": "Off"})
    graph = {"schema": 1, "snapshotAt": stamp, "nodes": [
        {"id": "bmc", "name": "BMC", "kind": "Контроллер управления", "probeTargetIP": ip, "probeTargetIdentityAt": stamp},
        {"id": "host", "name": "Host", "kind": "Сервер"},
        {"id": "sw", "name": "Switch", "kind": "Коммутатор", "ports": [
            {"name": "ge13", "state": "up", "checkedAt": observed, "speedBps": 10**9,
             "fdbLearned": {"checkedAt": observed, "partial": False, "learnedMacCount": 2 if failure == "shared" else 1}},
        ]},
    ], "links": [
        {"a": "bmc", "b": "host", "kind": "Управление оборудованием", "confirmed": True},
        {"a": "sw", "b": "bmc", "kind": "Путь по MAC-таблице", "source": "netctl FDB", "confirmed": True,
         "observedAt": observed, "portEvidence": [
             {"a": "ge13", "b": "", "source": "netctl FDB", "confirmed": True, "at": observed,
              "managementAddress": ip, "learnedEndpoint": {"switchId": "sw", "deviceId": "bmc",
                  "mac": "02:00:00:00:00:32" if failure == "mac" else mac}},
         ]},
        {"a": "sw", "b": "bmc", "kind": "Сетевое соединение", "source": "GitHub", "confirmed": True,
         "portEvidence": [{"a": "ge13", "b": "eth0", "source": "GitHub", "confirmed": True}]},
    ]}
    redfish.collect_redfish_power(graph, {"bmc": {"ip": ip, "interface_path": path}}, None, now)
    local_at = graph["nodes"][0].get("ports", [{}])[0].get("checkedAt")
    if local_at:
        assert now <= datetime.fromisoformat(local_at) <= datetime.now(timezone.utc)
    read_at = datetime.now(timezone.utc)
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps(graph), encoding="utf-8")
    for when, current in ((read_at, int(failure is None)), (read_at + timedelta(minutes=11), 0)):
        view = load_infrastructure_map(snapshot, when)
        controller = next(node for node in view["nodes"] if node["id"] == "bmc")
        audit = summarize_topology(view)["topologyAudit"]
        assert audit["currentPairTotal"] == current
        assert audit["inventoryOnlyPairTotal"] == 1 - current
        if current:
            assert audit["currentPairs"][0]["evidence"][0]["expiresAt"] == (now + timedelta(minutes=10)).isoformat()
            assert audit["currentPairs"][0]["portStates"]["b"] == {
                "state": "up", "speedBps": 10**9, "checkedAt": local_at, "source": "Redfish",
            }
        if failure == "address":
            assert controller["ports"] == []
        elif when == read_at:
            port, = controller["ports"]
            expected_state = failure if failure in ("down", "disabled") else "up"
            assert (port["name"], port["state"], port["source"], port["checkedAt"]) == (
                "eth0", expected_state, "Redfish", local_at,
            )
            assert port["speedBps"] == (interface["SpeedMbps"] * 10**6 if expected_state == "up" else None)
        else:
            port, = controller["ports"]
            assert port["state"] == "unknown" and port["speedBps"] is None


@pytest.mark.parametrize(("status", "headers", "state", "reason"), [
    (401, [("Server", "Microsoft-HTTPAPI/2.0"), ("WWW-Authenticate", "Kerberos")], "reachable", "winrm_auth_required"),
    (401, [("Server", "Microsoft-HTTPAPI/2.0"), ("WWW-Authenticate", "Basic")], "unknown", "unexpected_response"),
    (401, [("WWW-Authenticate", "Negotiate")], "unknown", "unexpected_response"),
    (200, [("Server", "Microsoft-HTTPAPI/2.0")], "unknown", "unexpected_response"),
    (503, [], "unreachable", "http_status"),
])
def test_winrm_probe_checks_the_authentication_challenge(monkeypatch, status, headers, state, reason):
    from types import SimpleNamespace
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("192.0.2.91", 5985, probes.TIMEOUT)

        def request(self, method, path, body, headers):
            assert (method, path) == ("POST", "/wsman")
            assert b"Identify" in body
            assert headers == {"Content-Type": "application/soap+xml; charset=UTF-8"}

        def getresponse(self):
            return SimpleNamespace(status=status, getheaders=lambda: headers)

        def close(self):
            pass

    monkeypatch.setattr(probes.http.client, "HTTPConnection", Connection)
    spec = {"type": "winrm", "ip": "192.0.2.91", "port": 5985}
    node = {"id": "winrm", "kind": "Сервис", "probeTargetIP": spec["ip"]}
    probes.apply_service_probes([node], {node["id"]: [spec]})
    check = _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))
    assert (check["method"], check["state"], check["target"], check["port"],
            check["path"], check["httpStatus"], check["reason"]) == (
        "WinRM HTTP", state, spec["ip"], 5985, "/wsman", status, reason,
    )


def test_tcp_connect_probe_reports_transport_without_sending_data(monkeypatch):
    from contextlib import nullcontext
    from app import infrastructure_service_probes as probes

    spec = {"type": "tcp_connect", "ip": "192.0.2.91", "port": 8000}
    sockets = []

    def connect(address, *, timeout):
        sockets.append(address)
        return nullcontext(object())

    monkeypatch.setattr(probes.socket, "create_connection", connect)
    node = {"id": "recorder-port", "kind": "Сервис", "probeTargetIP": spec["ip"]}
    probes.apply_service_probes([node], {node["id"]: [spec]})
    check, = node["serviceChecks"]
    assert (check["method"], check["state"], check["target"], check["port"]) == (
        "TCP", "reachable", "192.0.2.91", 8000)
    assert sockets == [("192.0.2.91", 8000)]
    node["probeTargetIP"] = None
    probes.apply_service_probes([node], {node["id"]: [spec]})
    assert node["serviceChecks"][-1]["reason"] == "probe_target_unconfirmed"
    assert len(sockets) == 1

    def reject(*args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr(probes.socket, "create_connection", reject)
    assert probes._tcp_connect(spec) == {"state": "unreachable", "reason": "tcp_connection_refused"}


@pytest.mark.parametrize(("reply", "state", "security"), [
    ("030000130ed000001234000200080001000000", "reachable", "TLS"),
    ("030000130ed000001234000200080002000000", "reachable", "CredSSP"),
    ("030000130ed000001234000300080005000000", "unreachable", None),
    ("030000130ed000001234000200080004000000", "unknown", None),
    ("030000130ee000001234000200080002000000", "unknown", None),
    ("030000130ed0000012340002000800", "unknown", None),
    ("0300ffff", "unknown", None),
])
def test_rdp_negotiation_requires_a_valid_connection_confirm(monkeypatch, reply, state, security):
    from contextlib import nullcontext
    from io import BytesIO
    from types import SimpleNamespace
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    requests = []
    connection = SimpleNamespace(sendall=requests.append, makefile=lambda mode: BytesIO(bytes.fromhex(reply)))
    monkeypatch.setattr(probes.socket, "create_connection", lambda address, timeout: nullcontext(connection))
    spec = {"type": "rdp_negotiation", "ip": "192.0.2.91", "port": 3389}
    node = {"id": "rdp", "kind": "Сервис", "probeTargetIP": spec["ip"]}
    probes.apply_service_probes([node], {"rdp": [spec]})
    check = _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))
    assert (check["method"], check["port"], check["state"], check.get("rdpSecurity")) == (
        "RDP Negotiation", 3389, state, security,
    )
    assert requests == [bytes.fromhex("030000130ee000000000000100080003000000")]


@pytest.mark.parametrize(("reply", "state", "reason"), [
    ("synchronized", "reachable", None),
    ("wrong_origin", "unknown", "unexpected_response"),
    ("short", "unknown", "unexpected_response"),
    ("wrong_mode", "unknown", "unexpected_response"),
    ("zero_time", "unknown", "unexpected_response"),
    ("unsynchronized", "unreachable", "ntp_unsynchronized"),
    ("stratum_zero", "unreachable", "ntp_unsynchronized"),
    ("rate_limited", "unreachable", "ntp_rate_limited"),
    ("access_denied", "unreachable", "ntp_access_denied"),
    ("timeout", "unknown", "timeout"),
])
def test_ntp_probe_requires_a_synchronized_reply_to_its_request(monkeypatch, reply, state, reason):
    from contextlib import nullcontext
    from app import infrastructure_service_probes as probes

    class Datagram:
        def bind(self, address):
            assert address == ("192.0.2.2", 0)
            self.bound = True

        def settimeout(self, value):
            assert value == probes.TIMEOUT

        def connect(self, address):
            assert address == ("192.0.2.91", 123)

        def send(self, request):
            assert len(request) == 48 and request[0] == 0x23
            assert any(request[40:48])
            self.request = request

        def recv(self, size):
            if reply == "timeout":
                raise TimeoutError
            packet = bytearray(48)
            packet[0] = {"unsynchronized": 0xE4, "wrong_mode": 0x23}.get(reply, 0x24)
            packet[1] = 0 if reply in ("stratum_zero", "rate_limited", "access_denied") else 2
            if reply in ("rate_limited", "access_denied"):
                packet[12:16] = b"RATE" if reply == "rate_limited" else b"DENY"
            if reply != "wrong_origin":
                packet[24:32] = self.request[40:48]
            if reply != "zero_time":
                packet[32:48] = self.request[40:48] * 2
            return bytes(packet[:10] if reply == "short" else packet)

    monkeypatch.setattr(probes.socket, "socket", lambda *args: nullcontext(Datagram()))
    spec = {"type": "ntp", "ip": "192.0.2.91", "port": 123}
    node = {"id": "time-service", "kind": "Сервис", "probeTargetIP": spec["ip"]}
    probes.apply_service_probes([node], {node["id"]: [spec]})
    check, = node["serviceChecks"]
    assert (check["method"], check["state"], check["target"], check["port"], check.get("reason")) == (
        "NTP (UDP)", state, spec["ip"], 123, reason)
    from app.infrastructure_map import _public_service_check

    public = _public_service_check(check, datetime.now(timezone.utc))
    assert (public["state"], public["port"], public.get("reason")) == (state, 123, reason)
    if reply in ("synchronized", "unsynchronized", "rate_limited", "access_denied", "stratum_zero"):
        assert public["ntp"] == {
            "version": 4, "stratum": 0 if reply in ("rate_limited", "access_denied", "stratum_zero") else 2,
            "leapIndicator": 3 if reply == "unsynchronized" else 0,
            **({"kissCode": {"rate_limited": "RATE", "access_denied": "DENY"}[reply]}
               if reply in ("rate_limited", "access_denied") else {}),
        }
        check["checkedAt"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert "ntp" not in _public_service_check(check, datetime.now(timezone.utc))
    else:
        assert "ntp" not in public
    if reply == "synchronized":
        datagram = Datagram()
        monkeypatch.setattr(probes.socket, "socket", lambda *args: nullcontext(datagram))
        assert probes._ntp(spec, source="192.0.2.2")["state"] == "reachable"
        assert datagram.bound
        route = {"state": "reachable", "sourceIP": "192.0.2.2", "gateway": "192.0.2.1",
                 "expectedGateway": "192.0.2.1", "interface": "eth0"}
        monkeypatch.setattr(probes, "_local_ipv4_route", lambda *_: route)
        spec["route_via"] = "192.0.2.1"
        node["serviceChecks"] = []
        probes.apply_service_probes([node], {node["id"]: [spec]})
        routed, = node["serviceChecks"]
        assert _public_service_check(routed, datetime.now(timezone.utc))["localRoute"] == route
        route["state"] = "unreachable"
        monkeypatch.setattr(probes.socket, "socket", lambda *_: pytest.fail("NTP sent over wrong route"))
        blocked = probes._ntp(spec)
        assert blocked == {"state": "unknown", "reason": "ntp_route_mismatch", "localRoute": route}


@pytest.mark.parametrize("windows", [False, True])
def test_service_probe_transition_tracks_confirmed_recovery(tmp_path, windows):
    from app.infrastructure_collect import _add_service_probe_transitions
    from app.infrastructure_map import WINDOWS_PROBE_SOURCE, load_infrastructure_map, summarize_guest_attachment, summarize_services

    now = datetime.now(timezone.utc)
    before = now - timedelta(minutes=2)

    def snapshot(at, state, target="192.0.2.30"):
        stamp = at.isoformat()
        check = {"source": "UI_VPN", "method": "HTTP", "state": state, "checkedAt": stamp,
                 "required": True, "target": target, "port": 3000, "path": "/health"}
        if windows:
            check.update(source=WINDOWS_PROBE_SOURCE, method="DNS", port=53, path="",
                         dns={"name": "example.test.", "record": "A", "transport": "UDP"})
        return {"schema": 1, "snapshotAt": stamp, "nodes": [
            {"id": "git", "name": "Git", "kind": "Сервис", "serviceChecks": [check],
             "reachability": {**check, "source": "Проверка сервиса"}},
        ], "links": []}

    previous = snapshot(before, "unreachable")
    current = snapshot(now, "reachable")
    _add_service_probe_transitions(current, previous)
    transition = {"from": "unreachable", "to": "reachable", "previousCheckedAt": before.isoformat(),
                  "checkedAt": now.isoformat()}
    assert current["nodes"][0]["probeTransition"] == transition
    repeated = snapshot(now, "reachable")
    _add_service_probe_transitions(repeated, current)
    assert repeated["nodes"][0]["probeTransition"] == transition
    after = now + timedelta(minutes=2)
    steady = snapshot(after, "reachable")
    _add_service_probe_transitions(steady, current)
    assert steady["nodes"][0]["probeTransition"] == transition
    path = tmp_path / "infra.json"
    path.write_text(json.dumps(steady), encoding="utf-8")
    public = load_infrastructure_map(path, after)
    assert public["nodes"][0]["probeTransition"] == transition
    assert summarize_services(public)["serviceAudit"]["services"][0]["probeTransition"] == transition
    assert summarize_guest_attachment(public, "git")["attachment"]["probeTransition"] == transition
    expired = load_infrastructure_map(path, after + timedelta(days=1))
    assert "probeTransition" not in expired["nodes"][0]
    assert "probeTransition" not in summarize_guest_attachment(expired, "git")["attachment"]
    public["nodes"].extend(
        {**public["nodes"][0], "id": f"earlier-{i}", "name": f"A service {i}", "probeTransition": None}
        for i in range(128)
    )
    audit = summarize_services(public)["serviceAudit"]
    assert all(row["id"] != "git" for row in audit["services"])
    assert audit["recentTransitionTotal"] == 1
    assert audit["recentTransitions"] == [
        {"id": "git", "name": "Git", "status": "ok", "hosts": [], **transition},
    ]
    assert summarize_services(public, host_id="another-host")["serviceAudit"]["recentTransitions"] == []
    assert summarize_services(expired)["serviceAudit"]["recentTransitionTotal"] == 0
    for old in (snapshot(before, "unknown"), snapshot(before, "unreachable", "192.0.2.31"),
                snapshot(before - timedelta(minutes=8), "unreachable")):
        changed = snapshot(now, "reachable")
        _add_service_probe_transitions(changed, old)
        assert "probeTransition" not in changed["nodes"][0]
    if windows:
        old = snapshot(before, "unreachable")
        old["nodes"][0]["serviceChecks"][0]["dns"]["transport"] = "TCP"
        changed = snapshot(now, "reachable")
        _add_service_probe_transitions(changed, old)
        assert "probeTransition" not in changed["nodes"][0]


def test_map_colors_use_node_and_confirmed_service_availability(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()

    def node(key, state, kind="Сервер", **extra):
        return {"id": key, "name": key, "kind": kind,
                "reachability": {"state": state, "checkedAt": stamp}, **extra}

    directum = node("role:directum", "unreachable", "Сервис",
                    sources=[{"name": "Server Observer", "at": stamp}],
                    checks=[{"name": "directumrx_active", "status": "critical"}])
    graph = {
        "schema": 1, "snapshotAt": stamp,
        "nodes": [node("green", "reachable"), node("yellow", "reachable"),
                  node("red", "unreachable"), node("grey", "reachable"),
                  node("off", "stopped"), node("unknown-host", "unknown"),
                  node("http", "reachable", "Сервис"), node("dns", "unknown", "Сервис"), directum],
        "links": [
            {"a": host, "b": service, "kind": "Цель проверки", "confirmed": confirmed}
            for host, service, confirmed in [
                ("green", "http", True), ("green", "dns", False),
                ("yellow", "role:directum", True), ("yellow", "dns", True),
                ("red", "http", True), ("grey", "dns", True), ("unknown-host", "role:directum", True),
            ]
        ],
    }
    path = tmp_path / "infrastructure.json"
    path.write_text(json.dumps(graph), encoding="utf-8")

    states = {item["id"]: item for item in load_infrastructure_map(path, now)["nodes"]}
    assert [states[key]["mapStatus"] for key in ("green", "yellow", "red", "grey", "off", "unknown-host")] == [
        "ok", "warn", "critical", "unknown", "critical", "unknown",
    ]
    assert states["yellow"]["reachability"]["state"] == "reachable"
    assert states["yellow"]["serviceAvailability"] == {
        "unavailable": ["role:directum"], "degraded": [], "unknown": ["dns"],
    }
    directum["reachability"]["state"] = "unknown"
    path.write_text(json.dumps(graph), encoding="utf-8")
    states = {item["id"]: item for item in load_infrastructure_map(path, now)["nodes"]}
    assert states["role:directum"]["reachability"]["state"] == "unknown"
    assert states["yellow"]["mapStatus"] == "unknown"


def test_service_color_includes_required_observer_checks_and_confirmed_dependencies(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path = tmp_path / "infrastructure.json"

    def read(component="ok", database="reachable", observer_at=stamp, confirmed=True, cycle=False, missing=False):
        checks = [] if component is None else [{"name": "redis_tcp_6379", "status": component}]
        checks.append({"name": "c_disk_free", "status": "critical"})
        if component == "error":
            checks[0]["message"] = "timeout"
        target = {"role": "directum", "status": "critical", "observed_at": observer_at, "checks": checks}
        report = {"freshness": "missing" if missing else "current", "targets": [] if missing else [target]}
        context = {"devices": [{"id": "vm", "name": "VM", "kind": "server"}]}
        graph = build_graph(context, {}, report, {}, {
            "roles": {"directum": {"asset": "vm", "required_observer_checks": ["redis_tcp_6379"]}},
        }, now)
        graph["nodes"].append({"id": "db", "name": "PostgreSQL", "kind": "Сервис"})
        for node in graph["nodes"]:
            state = database if node["id"] == "db" else "reachable"
            node["reachability"] = {"state": state, "checkedAt": stamp}
        graph["links"].append({"a": "role:directum", "b": "db", "kind": "Зависимость сервиса",
                               "confirmed": confirmed})
        if cycle:
            graph["links"].append({"a": "db", "b": "role:directum", "kind": "Зависимость сервиса",
                                   "confirmed": True})
        path.write_text(json.dumps(graph), encoding="utf-8")
        return {node["id"]: node for node in load_infrastructure_map(path, now)["nodes"]}

    assert read()["vm"]["mapStatus"] == "ok"
    for observed in (read(component="critical"), read(database="unreachable", cycle=True)):
        assert observed["role:directum"]["reachability"]["state"] == "reachable"
        assert observed["role:directum"]["mapStatus"] == "warn"
        assert observed["role:directum"]["status"] == "warn"
        assert observed["role:directum"]["sourceStatus"] == "critical"
        assert observed["vm"]["mapStatus"] == "warn"
        assert observed["vm"]["serviceAvailability"]["unavailable"] == []
        assert observed["vm"]["serviceAvailability"]["degraded"] == ["role:directum"]
    assert read(database="unreachable", confirmed=False)["vm"]["mapStatus"] == "ok"
    assert read(component=None)["vm"]["mapStatus"] == "unknown"
    timed_out = read(component="error")["role:directum"]
    assert timed_out["status"] == "unknown"
    assert timed_out["checks"][0]["error"] == "timeout"
    assert "error" not in read(component="error", observer_at=(now - timedelta(minutes=30)).isoformat())[
        "role:directum"]["checks"][0]
    assert read(missing=True)["vm"]["mapStatus"] == "unknown"
    assert read(database="unknown")["vm"]["mapStatus"] == "unknown"
    assert read(observer_at=(now - timedelta(minutes=30)).isoformat())["vm"]["mapStatus"] == "unknown"
    assert read(cycle=True)["vm"]["mapStatus"] == "ok"


def test_observer_disk_measurements_publish_units_and_reported_warning_threshold(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    snapshot = tmp_path / "infrastructure.json"
    report = {"freshness": "current", "targets": [
        {"role": "directum", "status": "critical", "observed_at": stamp, "checks": [
            {"name": "c_disk_free", "status": "critical", "observed": 5.32, "expected": 15,
             "disk_capacity": {"free_bytes": 5320, "total_bytes": 100000}},
            {"name": "rxdata_log_bytes", "status": "ok", "observed": 9 * 2**30, "expected": 20 * 2**30},
            {"name": "windows_memory_available_bytes", "status": "ok", "observed": 2**30},
            {"name": "windows_memory_available_percent", "status": "ok", "observed": 4.5},
            {"name": "data_disk_free", "status": "ok", "observed": 102, "expected": "unrelated"},
            {"name": "unrelated_metric", "status": "ok", "observed": 42, "expected": 45},
        ]},
    ]}
    graph = build_graph({}, {}, report, {}, {}, now)
    graph["serverObserverAt"] = stamp
    snapshot.write_text(json.dumps(graph), encoding="utf-8")

    def read(when=now):
        node, = load_infrastructure_map(snapshot, when)["nodes"]
        return {c["name"]: c for c in node["checks"]}

    checks = read()
    disk = checks["c_disk_free"]
    assert disk["label"] == "Свободно на диске C:"
    assert (disk["unit"], disk["observed"], disk["warningThreshold"]) == ("percent", 5.32, 15)
    assert disk["diskCapacity"] == {"freeBytes": 5320, "totalBytes": 100000}
    logs = checks["rxdata_log_bytes"]
    assert (logs["unit"], logs["observed"], logs["warningThreshold"]) == ("bytes", 9 * 2**30, 20 * 2**30)
    assert checks["windows_memory_available_bytes"]["unit"] == "bytes"
    assert checks["windows_memory_available_bytes"]["observed"] == 2**30
    assert checks["windows_memory_available_percent"]["unit"] == "percent"
    assert checks["windows_memory_available_percent"]["observed"] == 4.5
    assert "warningThreshold" not in checks["windows_memory_available_percent"]
    configured = {"roles": {"directum": {"windows_memory_warning_percent": 5}}}
    with_threshold = build_graph({}, {}, report, {}, configured, now)
    with_threshold["serverObserverAt"] = stamp
    snapshot.write_text(json.dumps(with_threshold), encoding="utf-8")
    memory = read()["windows_memory_available_percent"]
    assert (memory["status"], memory["required"], memory["warningThreshold"]) == ("warn", True, 5)
    linux_report = {"freshness": "current", "targets": [{
        "role": "nextcloud", "status": "ok", "observed_at": stamp, "checks": [
            {"name": "linux_memory_available_percent", "status": "ok", "observed": 4.5},
        ],
    }]}
    linux_config = {"roles": {"nextcloud": {"linux_memory_warning_percent": 5}}}
    linux_graph = build_graph({}, {}, linux_report, {}, linux_config, now)
    linux_graph["serverObserverAt"] = stamp
    snapshot.write_text(json.dumps(linux_graph), encoding="utf-8")
    memory = read()["linux_memory_available_percent"]
    assert (memory["status"], memory["required"], memory["warningThreshold"]) == ("warn", True, 5)
    snapshot.write_text(json.dumps(graph), encoding="utf-8")
    assert checks["data_disk_free"]["observed"] is None
    assert "warningThreshold" not in checks["data_disk_free"]
    assert "warningThreshold" not in checks["unrelated_metric"]
    old = read(now + timedelta(minutes=16))["c_disk_free"]
    assert old["stale"] and old["status"] == "unknown"
    assert old["observed"] == 5.32 and old["checkedAt"] == stamp
    public = load_infrastructure_map(snapshot, now + timedelta(minutes=16))
    assert public["availability"] == "ready" and public["collectionIssues"] == ["server_observer_stale"]


def test_qemu_prelaunch_reports_guest_state_backup_lock_and_configured_bridge(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment, summarize_guest_attachment_audit

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path = tmp_path / "infrastructure.json"
    guest = {"vmid": 104, "node": "pve1", "name": "Sirius", "type": "qemu",
             "status": "prelaunch", "lock": "backup"}
    pve = {"at": stamp, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [guest], "configs": {"104": {"net0": "virtio=02:00:00:00:00:04,bridge=vmbr1"}}}

    def read(when=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        graph = load_infrastructure_map(path, when)
        node = next(node for node in graph["nodes"] if node["id"] == "pve-guest:104")
        return node, graph

    node, graph = read()
    assert node["reachability"]["state"] == "unreachable"
    assert node["reachability"]["source"] == "Proxmox"
    assert node["mapStatus"] == "critical"
    assert node["properties"]["Состояние ВМ"] == "Гостевая ОС ещё не запущена"
    assert node["properties"]["Блокировка Proxmox"] == "Резервное копирование"
    placement = next(link for link in graph["links"] if link["b"] == "pve-guest:104")
    port, = placement["portEvidence"]
    assert (port["a"], port["b"]) == ("vmbr1", "net0")
    assert port["virtual"]["switchPorts"] == []
    for power in ("prelaunch", "paused"):
        guest.update(status=power)
        _, graph = read()
        audit = summarize_guest_attachment_audit(graph)["attachmentAudit"]
        assert audit["guestCounts"][power] == 1 and audit["guestCounts"]["unknown"] == 0
        assert audit["gapTotal"] == 0 and audit["interfaceCounts"]["inactive"] == 1
        attachment, = summarize_guest_attachment(graph, node["id"])["attachment"]["guests"]
        assert attachment["power"] == power and attachment["interfaces"][0]["bridge"] == "vmbr1"

    guest.update(status="prelaunch")
    node, graph = read(now + timedelta(minutes=26))
    assert node["mapStatus"] == "unknown"
    assert "Блокировка Proxmox" not in node["properties"]
    assert summarize_guest_attachment_audit(graph)["attachmentAudit"]["guestCounts"]["unknown"] == 1
    guest.update(status="running")
    node, graph = read()
    assert node["reachability"]["state"] == "unknown"
    assert node["properties"]["Блокировка Proxmox"] == "Резервное копирование"
    assert summarize_guest_attachment_audit(graph)["attachmentAudit"]["gapTotal"] == 1


def test_guest_network_reports_an_empty_configuration_only_after_a_successful_read(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment_audit

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [{"vmid": 127, "node": "pve1", "type": "lxc", "status": "running"}],
           "configs": {"127": {"networkConfigRead": True}}}
    path = tmp_path / "snapshot.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, when)["nodes"] if node.get("vmid") == 127)

    node = read()
    assert node["guestNetwork"] == {"checkedAt": at, "configured": 0, "enabled": 0, "disabled": 0}
    audit = summarize_guest_attachment_audit(load_infrastructure_map(path, now))["attachmentAudit"]
    assert audit["runningWithoutNetworkTotal"] == 1
    assert [(row["guest"]["vmid"], row["guestNetwork"]) for row in audit["runningWithoutNetwork"]] == [
        (127, node["guestNetwork"]),
    ]
    assert audit["runningNetworkCoverage"] == {"confirmed": 0, "incomplete": 0, "withoutNetwork": 1}
    assert audit["gapTotal"] == 0
    assert node["mapStatus"] == "unknown"
    assert node["reachability"]["method"] == "Адаптеры Proxmox не заданы"
    assert "guestNetwork" not in read(now + timedelta(hours=1))
    pve["configs"]["127"].update(
        net0="name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:00:01",
        net1="name=eth1,bridge=vmbr1,hwaddr=02:00:00:00:00:02,link_down=1",
        net2="name=eth2",
    )
    node = read()
    assert node["guestNetwork"] == {"checkedAt": at, "configured": 3, "enabled": 1, "disabled": 1}
    assert node["reachability"]["method"] == ""
    pve["configs"]["127"].pop("net0")
    assert read()["guestNetwork"]["enabled"] == 0
    audit = summarize_guest_attachment_audit(load_infrastructure_map(path, now))["attachmentAudit"]
    assert audit["runningWithoutNetworkTotal"] == 0
    pve["configs"]["127"].pop("net2")
    assert read()["guestNetwork"]["disabled"] == 1
    audit = summarize_guest_attachment_audit(load_infrastructure_map(path, now))["attachmentAudit"]
    assert audit["runningWithoutNetworkTotal"] == 1
    pve["configs"]["127"] = {}
    assert "guestNetwork" not in read()
    audit = summarize_guest_attachment_audit(load_infrastructure_map(path, now))["attachmentAudit"]
    assert audit["runningWithoutNetworkTotal"] == 0 and audit["gapTotal"] == 1
    assert audit["runningNetworkCoverage"] == {"confirmed": 0, "incomplete": 1, "withoutNetwork": 0}


def test_cluster_health_distinguishes_quorum_members_and_api(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment

    now = datetime.now(timezone.utc)
    path = tmp_path / "infrastructure.json"
    cluster = {"type": "cluster", "name": "example", "quorate": 1, "nodes": 2}
    members = [{"type": "node", "name": "pve1", "online": 1}, {"type": "node", "name": "pve2", "online": 1}]
    capacity = {}
    guest = {"node": "pve1", "vmid": 103, "status": "stopped", "type": "qemu"}

    def read(when=now):
        pve = {"at": now.isoformat(), "cluster": [cluster, *members],
               "guests": [guest], "configs": {"103": {"networkConfigRead": True}},
               "nodes": [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"}],
               **({"nodeStatus": capacity} if capacity else {})}
        graph = build_graph({}, {}, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, when)["nodes"] if node["id"] == "proxmox:cluster")

    healthy = read()
    assert healthy["mapStatus"] == "ok"
    assert [(c["method"], c["state"]) for c in healthy["serviceChecks"]] == [
        ("Кворум", "reachable"), ("Участники кластера", "reachable"),
    ]
    assert healthy["properties"]["Узлы"] == "2 из 2 в сети"
    graph = load_infrastructure_map(path, now)
    attachment = summarize_guest_attachment(graph, healthy["id"])["attachment"]
    assert attachment["guestTotal"] == 1
    assert attachment["guests"][0]["hypervisor"]["id"] == "pve1"
    assert [host["host"]["id"] for host in attachment["physicalHosts"]] == ["pve1", "pve2"]
    assert attachment["runningWithoutNetworkTotal"] == 0
    guest["status"] = "running"
    read()
    graph = load_infrastructure_map(path, now, include_guest_attachments=True)
    attachment = summarize_guest_attachment(graph, healthy["id"])["attachment"]
    assert graph["runningWithoutNetworkTotal"] == attachment["runningWithoutNetworkTotal"] == 1
    assert graph["runningWithoutNetwork"] == attachment["runningWithoutNetwork"]
    assert attachment["runningWithoutNetwork"][0]["guest"]["vmid"] == 103
    guest["status"] = "stopped"
    sample = {"checkedAt": now.isoformat(), "rootfs": {"avail": 500, "total": 1000},
              "swap": {"used": 0, "total": 0}, "memory": {"free": 100, "total": 1000}}
    capacity.update(pve1=sample, pve2={**sample, "endpointMemory": {"availableBytes": 50, "checkedAt": now.isoformat()}})
    degraded = read()
    assert degraded["mapStatus"] == "warn" and degraded["reachability"]["state"] == "reachable"
    assert degraded["clusterMemberHealth"]["warn"] == ["pve2"]
    assert all(check["state"] == "reachable" for check in degraded["serviceChecks"])
    capacity.clear()
    cluster["quorate"] = 0
    no_quorum = read()
    assert no_quorum["reachability"]["state"] == "reachable"
    assert no_quorum["mapStatus"] == "warn"
    cluster["quorate"] = 1
    members[1]["online"] = 0
    assert read()["mapStatus"] == "warn"
    assert read()["properties"]["Узлы"] == "1 из 2 в сети"
    members.pop()
    assert read()["mapStatus"] == "unknown"
    cluster["quorate"] = "1"
    assert read()["serviceChecks"][0]["state"] == "unknown"
    assert read(now + timedelta(hours=1))["reachability"]["state"] == "unknown"


def test_guest_disks_publish_storage_assignments_without_volume_paths(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    pve = {"at": now.isoformat(), "cluster": [],
           "nodes": [{"node": node, "status": "online"} for node in ("pve1", "pve2")],
           "guests": [{"vmid": 103, "node": "pve1", "type": "qemu", "status": "stopped"},
                      {"vmid": 105, "node": "pve1", "type": "lxc", "status": "running"},
                      {"vmid": 106, "node": "pve2", "type": "qemu", "status": "running"}],
           "configs": {"103": {"sata0": "zfs-vm-storage:private-volume-name,size=450G",
                                "scsi1": "file=main-zfs:private-volume-name,size=1.5T",
                                "ide2": "local:iso/private-image.iso,media=cdrom,size=9G",
                                "ide3": "local:vm-103-cloudinit,size=4M",
                                "unused0": "zfs-vm-storage:detached,size=10G",
                                "virtio0": "/dev/disk/by-id/private-device,size=2G"},
                       "105": {"rootfs": "volume=local-lvm:private-volume-name,size=8G",
                               "mp0": "/srv/private-path,mp=/private-directory",
                               "mp1": "local-lvm:private-volume-name,mp=/private-directory,size=bad"},
                       "106": {"scsi0": "zfs-vm-storage:private-volume-name,size=8G"}}}
    path = tmp_path / "infrastructure.json"
    graph = build_graph({}, {}, {}, pve, {}, now)
    raw = json.dumps(graph)
    assert "private-" not in raw
    path.write_text(raw, encoding="utf-8")

    def read(vmid, when=now):
        return next(node for node in load_infrastructure_map(path, when)["nodes"] if node["vmid"] == vmid)

    assert read(103)["guestStorage"] == {"checkedAt": now.isoformat(), "disks": [
        {"device": "sata0", "storage": "zfs-vm-storage", "sizeBytes": 450 * 2**30},
        {"device": "scsi1", "storage": "main-zfs", "sizeBytes": 1536 * 2**30},
    ]}
    assert read(105)["guestStorage"]["disks"] == [
        {"device": "rootfs", "storage": "local-lvm", "sizeBytes": 8 * 2**30},
        {"device": "mp1", "storage": "local-lvm"},
    ]
    public = load_infrastructure_map(path, now)
    cluster = next(node for node in public["nodes"] if node["id"] == public["clusterId"])
    assert cluster["storageAssignments"] == {"checkedAt": now.isoformat(), "hosts": [
        {"id": "pve1", "storages": [
            {"id": "local-lvm", "guestCount": 1, "diskCount": 2},
            {"id": "main-zfs", "guestCount": 1, "diskCount": 1},
            {"id": "zfs-vm-storage", "guestCount": 1, "diskCount": 1},
        ]},
        {"id": "pve2", "storages": [{"id": "zfs-vm-storage", "guestCount": 1, "diskCount": 1}]},
    ]}
    expired = load_infrastructure_map(path, now + timedelta(hours=1))
    assert "storageAssignments" not in next(node for node in expired["nodes"] if node["id"] == expired["clusterId"])
    assert "guestStorage" not in read(103, now + timedelta(hours=1))


def test_hypervisor_smart_checks_report_fresh_disk_health(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "disks": {"pve1": {"checkedAt": at, "disks": [
               {"device": "/dev/sda", "kind": "ssd", "smartState": "ok", "endurancePercent": 95,
                "sizeBytes": 2**40, "serial": "private serial"},
               {"device": "/dev/sdb", "kind": "hdd", "smartState": "critical", "endurancePercent": "N/A"},
           ]}}}
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
    assert "private serial" not in snapshot.read_text(encoding="utf-8")

    def node(when):
        return next(n for n in load_infrastructure_map(snapshot, when)["nodes"] if n["id"] == "pve1")

    current = node(now)
    assert current["reachability"]["state"] == "reachable" and current["mapStatus"] == "warn"
    assert current["hardwareDisks"]["disks"] == [
        {"device": "/dev/sda", "kind": "ssd", "smartState": "ok", "endurancePercent": 95, "sizeBytes": 2**40},
        {"device": "/dev/sdb", "kind": "hdd", "smartState": "critical"},
    ]
    assert "hardwareDisks" not in node(now + timedelta(hours=1))


def test_hypervisor_zfs_health_is_current_and_warns_on_degraded_pool(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pool = {"name": "pool", "health": "DEGRADED", "sizeBytes": 100, "freeBytes": 30}
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "zfs": {"pve1": {"checkedAt": at, "pools": [pool, {"name": "../private", "health": "ONLINE"}]}}}
    snapshot = tmp_path / "map.json"

    def node(when=now):
        snapshot.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        assert "../private" not in snapshot.read_text(encoding="utf-8")
        return next(n for n in load_infrastructure_map(snapshot, when)["nodes"] if n["id"] == "pve1")

    current = node()
    assert current["reachability"]["state"] == "reachable" and current["mapStatus"] == "warn"
    assert current["zfsPools"] == {"checkedAt": at, "pools": [pool]}
    assert "zfsPools" not in node(now + timedelta(hours=1))
    pool["health"] = "ONLINE"
    assert node()["mapStatus"] == "ok"
    pool["freeBytes"] = 101
    assert "freeBytes" not in node()["zfsPools"]["pools"][0]


def test_lvm_thin_capacity_warns_for_either_dimension(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pool = {"volumeGroup": "pve", "name": "data", "sizeBytes": 100, "usedBytes": 30,
            "metadataSizeBytes": 100, "metadataUsedBytes": 90}
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "lvmThin": {"pve1": {"checkedAt": at, "pools": [pool]}}}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        return next(n for n in load_infrastructure_map(path, when)["nodes"] if n["id"] == "pve1")

    assert read()["mapStatus"] == "warn"
    assert read()["lvmThinPools"]["pools"][0] == {**pool, "capacityStatus": "warn"}
    pool.update(usedBytes=100, metadataUsedBytes=1)
    assert read()["mapStatus"] == "warn"
    pool["usedBytes"] = 5
    assert read()["lvmThinPools"]["pools"][0]["capacityStatus"] == "ok"
    pool["metadataUsedBytes"] = 101
    assert read()["lvmThinPools"]["pools"][0]["capacityStatus"] == "unknown"
    assert "lvmThinPools" not in read(now + timedelta(hours=1))


def test_guest_resources_require_unique_running_guest_with_fresh_proxmox_data(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    guest = {"vmid": 103, "node": "pve1", "name": "Directum", "type": "qemu", "status": "running",
             "cpu": 0.0, "maxcpu": 8, "mem": 3 * 2**30, "maxmem": 8 * 2**30, "uptime": 3600}
    pve = {"at": now.isoformat(), "cluster": [], "nodes": [], "guests": [guest], "configs": {}}
    path = tmp_path / "snapshot.json"

    def read(when=now):
        graph = build_graph({}, {}, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, when)["nodes"] if node["id"] == "pve-guest:103")

    assert read()["resources"] == {"checkedAt": now.isoformat(), "cpuRatio": 0.0, "logicalCpus": 8,
                                  "memoryUsedBytes": 3 * 2**30, "memoryTotalBytes": 8 * 2**30, "uptimeSeconds": 3600}
    assert "resources" not in read(now + timedelta(minutes=26))
    guest["status"] = "stopped"
    assert "resources" not in read()
    guest["status"] = "running"
    pve["guests"].append({**guest, "node": "pve2"})
    assert "resources" not in read()


def test_guest_io_requires_continuous_counter_samples_on_the_same_host(tmp_path):
    from app.infrastructure_collect import build_graph, _add_guest_io_rates
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=2)
    guest = {"vmid": 103, "node": "pve1", "name": "Directum", "type": "qemu", "status": "running",
             "uptime": 600, "netin": 24000, "netout": 12000, "diskread": 500, "diskwrite": 500}
    pve = {"at": start.isoformat(), "cluster": [], "nodes": [], "guests": [guest], "configs": {}}
    previous = build_graph({}, {}, {}, pve, {}, start)
    assert next(n for n in previous["nodes"] if n.get("guest"))["guestIoCounters"]["netin"] == 24000
    pve["at"] = now.isoformat()
    guest.update(uptime=720, netin=48000, diskread=1100, diskwrite=2900)
    path = tmp_path / "snapshot.json"

    def read(when=now):
        graph = build_graph({}, {}, {}, pve, {}, now)
        _add_guest_io_rates(graph, previous)
        path.write_text(json.dumps(graph), encoding="utf-8")
        node = next(n for n in load_infrastructure_map(path, when)["nodes"] if n.get("guest"))
        assert "guestIoCounters" not in node
        return node.get("guestIo")

    assert read() == {"checkedAt": now.isoformat(), "intervalSeconds": 120,
                      "networkInBytesPerSecond": 200, "networkOutBytesPerSecond": 0,
                      "diskReadBytesPerSecond": 5, "diskWriteBytesPerSecond": 20}
    assert read(now + timedelta(minutes=6)) is None
    guest["diskread"] = 499
    assert "diskReadBytesPerSecond" not in read() and "diskWriteBytesPerSecond" not in read()
    guest["node"] = "pve2"
    assert read() is None
    guest.update(node="pve1", uptime=30)
    assert read() is None


def test_hypervisor_resources_require_current_online_node_data(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    path = tmp_path / "infrastructure.json"
    node = {"node": "pve1", "status": "online", "cpu": 0.0, "maxcpu": 72, "mem": 512,
            "maxmem": 1024, "disk": 0, "maxdisk": 4096, "uptime": 30}

    def read(when=now):
        graph = build_graph({}, {}, {}, {"at": now.isoformat(), "cluster": [], "nodes": [node], "guests": []}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(n for n in load_infrastructure_map(path, when)["nodes"] if n["id"] == "pve1")

    assert read()["resources"] == {"checkedAt": now.isoformat(), "cpuRatio": 0.0, "logicalCpus": 72,
                                    "memoryUsedBytes": 512, "memoryTotalBytes": 1024,
                                    "rootUsedBytes": 0, "rootTotalBytes": 4096, "uptimeSeconds": 30}
    assert "resources" not in read(now + timedelta(hours=1))
    node.update(status="offline")
    assert "resources" not in read()
    node.update(status="online", cpu=True, mem=1025, disk=-1, maxcpu="72", uptime=None)
    assert "resources" not in read()
    node["cpu"] = 0.42
    assert read()["resources"] == {"checkedAt": now.isoformat(), "cpuRatio": 0.42}


def test_proxmox_capacity_uses_available_root_space_and_reports_missing_data(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    status = {"checkedAt": stamp, "rootfs": {"avail": 100, "free": 400, "total": 1000},
              "swap": {"used": 0, "total": 0}, "memory": {"free": 22, "total": 1000}}
    pve = {"at": stamp, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "nodeStatus": {"pve1": status}}
    path = tmp_path / "infrastructure.json"

    def read(at=now):
        path.write_text(json.dumps(build_graph({}, {}, {}, pve, {}, now)), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, at)["nodes"] if node["id"] == "pve1")

    node = read()
    assert node["resourceCapacity"]["root"] == {"availableBytes": 100, "totalBytes": 1000, "status": "warn"}
    assert node["resourceCapacity"]["swap"]["status"] == "not_configured"
    assert node["resourceCapacity"]["memory"]["freeBytes"] == 22
    assert node["mapStatus"] == "warn" and node["reachability"]["state"] == "reachable"
    status["rootfs"]["avail"] = 101
    assert read()["mapStatus"] == "ok"
    status["endpointMemory"] = {"availableBytes": 60, "checkedAt": stamp}
    node = read()
    assert node["mapStatus"] == "warn"
    assert node["resourceCapacity"]["memoryHeadroom"]["availablePercent"] == 6
    assert node["resourceCapacity"]["memoryHeadroom"]["source"] == "Endpoint Agent"
    status["endpointMemory"]["checkedAt"] = (now - timedelta(minutes=7)).isoformat()
    assert read()["mapStatus"] == "ok"
    status["swap"] = {"used": 90, "total": 100}
    assert read()["mapStatus"] == "warn"
    status["swap"]["used"] = True
    assert read()["mapStatus"] == "unknown"
    assert read(now + timedelta(minutes=6))["resourceCapacity"]["root"] == {"status": "unknown"}
    pve["nodeStatus"].clear()
    assert read()["mapStatus"] == "unknown"


def test_backup_state_requires_a_valid_watchdog_report(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_services

    now = datetime.now(timezone.utc)
    target = {"role": "acti_backup", "status": "critical", "observed_at": now.isoformat(), "checks": []}
    path = tmp_path / "infrastructure.json"

    def read(watchdog, snapshot, capacity="ok", freshness="current", *, duplicate=False):
        target["checks"] = [{"name": name, "status": status} for name, status in (
            ("watchdog_fresh", watchdog), ("backup_snapshot_fresh", snapshot), ("repository_capacity", capacity),
        ) if status is not None]
        if snapshot is not None:
            check = next(check for check in target["checks"] if check["name"] == "backup_snapshot_fresh")
            check.update(observed=48 if snapshot == "critical" else 4, expected=30)
        if duplicate:
            target["checks"].append({"name": "backup_snapshot_fresh", "status": "critical", "observed": 72})
        graph = build_graph({}, {}, {"freshness": freshness, "targets": [target]}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        public = load_infrastructure_map(path, now)
        node, = public["nodes"]
        audit, = summarize_services(public)["serviceAudit"]["services"]
        return node, audit

    node, audit = read("critical", "critical", "critical")
    assert node["mapStatus"] == "unknown"
    assert [(check["label"], check["status"]) for check in node["checks"]] == [
        ("Свежесть отчёта watchdog", "critical"), ("Свежесть резервной копии", "unknown"),
        ("Ёмкость хранилища копий", "unknown"),
    ]
    assert audit["requiredChecks"] == {"passed": 0, "failed": 0, "unconfirmed": 2}
    assert node["checks"][1]["observed"] is None
    assert read(None, "critical")[0]["mapStatus"] == "unknown"
    node, audit = read("ok", "critical")
    assert node["mapStatus"] == "critical"
    assert audit["requiredChecks"] == {"passed": 1, "failed": 1, "unconfirmed": 0}
    issue, = audit["issues"]
    assert (issue["check"], issue["required"], issue["observed"], issue["warningThreshold"]) == (
        "backup_snapshot_fresh", True, 48, 30,
    )
    assert read("ok", "ok", capacity="critical")[0]["mapStatus"] == "warn"
    assert read("ok", "ok", capacity=None)[0]["mapStatus"] == "unknown"
    node, audit = read("ok", "ok", duplicate=True)
    assert node["mapStatus"] == "unknown"
    assert audit["requiredChecks"] == {"passed": 1, "failed": 0, "unconfirmed": 1}
    duplicate, = [check for check in node["checks"] if check["name"] == "backup_snapshot_fresh"]
    assert duplicate["observed"] is None
    assert read("ok", "critical", freshness="stale")[0]["mapStatus"] == "unknown"


def test_acti_service_reflects_backup_dependency_on_inventory_host(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_services

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    report = {"freshness": "current", "targets": [
        {"role": "acti_backup", "status": "critical", "observed_at": stamp,
         "checks": [{"name": "watchdog_fresh", "status": "ok"},
                    {"name": "backup_snapshot_fresh", "status": "critical", "observed": 48, "expected": 30,
                     "backup_snapshot_at": int((now - timedelta(hours=48)).timestamp())},
                    {"name": "repository_capacity", "status": "ok", "backup_repository": {
                        "checked_at": int((now - timedelta(hours=1)).timestamp()), "used_bytes": 2**30, "free_gib": 200,
                    }}]},
        {"role": "acti", "status": "ok", "observed_at": stamp,
         "checks": [{"name": "https_ready", "status": "ok"},
                    {"name": "backup_job", "status": "critical", "backup_job": {
                        "state": "failed", "completed_at": 1794435967, "exit_code": 1, "timer_active": True,
                    }}]},
    ]}
    context = {"devices": [{"id": "fileserver", "name": "File server", "kind": "server"},
                           {"id": "acti-vm", "name": "ACTI VM", "kind": "server",
                            "management_ip": "192.0.2.45"}]}
    network = {"hosts": [{"ip": "192.0.2.45", "availability": {
        "checked_at": stamp, "run_status": "success", "state": "online",
        "reason": "active_probe", "active_method": "icmp",
    }}]}
    bindings = {"roles": {"acti": {"asset": "acti-vm"},
                          "acti_backup": {"asset": "fileserver", "used_by": ["role:acti"]}}}
    path = tmp_path / "infrastructure.json"

    def read():
        graph = build_graph(context, network, report, {}, bindings, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        public = load_infrastructure_map(path, now)
        return {n["id"]: n for n in public["nodes"]}, public["links"]

    nodes, links = read()
    assert any(l["a"] == "role:acti" and l["b"] == "role:acti_backup"
               and l["kind"] == "Зависимость сервиса" and l["confirmed"] for l in links)
    assert nodes["role:acti"]["reachability"]["state"] == "reachable"
    assert any(check["name"] == "https_ready" and check["required"] for check in nodes["role:acti"]["checks"])
    job, = [check for check in nodes["role:acti"]["checks"] if check["name"] == "backup_job"]
    assert job["status"] == "critical"
    assert job["backupJob"] == {"state": "failed", "completedAt": "2026-11-11T22:26:07+00:00",
                                "exitCode": 1, "timerActive": True}
    backup_job, = [check for check in nodes["role:acti_backup"]["checks"] if check["name"] == "backup_job"]
    assert backup_job == {**job, "required": False, "sourceNodeId": "role:acti"}
    capacity, = [check for check in nodes["role:acti_backup"]["checks"] if check["name"] == "repository_capacity"]
    assert capacity["backupRepository"] == {
        "checkedAt": (now - timedelta(hours=1)).replace(microsecond=0).isoformat(), "usedBytes": 2**30,
        "freeGiB": 200, "maximumBytes": 300 * 2**30, "minimumFreeGiB": 100,
    }
    audit = summarize_services(load_infrastructure_map(path, now))["serviceAudit"]["services"]
    acti, = [service for service in audit if service["id"] == "role:acti"]
    issue, = [issue for issue in acti["issues"] if issue["check"] == "backup_job"]
    assert issue["backupJob"] == job["backupJob"]
    backup = next(service for service in audit if service["id"] == "role:acti_backup")
    freshness = next(issue for issue in backup["issues"] if issue["check"] == "backup_snapshot_fresh")
    assert freshness["backupSnapshotAt"] == (now - timedelta(hours=48)).replace(microsecond=0).isoformat()
    assert next(issue for issue in backup["issues"] if issue["check"] == "backup_job")["sourceNodeId"] == "role:acti"
    assert nodes["role:acti"]["mapStatus"] == nodes["acti-vm"]["mapStatus"] == "warn"
    assert nodes["role:acti"]["serviceAvailability"]["unavailable"] == ["role:acti_backup"]
    report["targets"][0]["checks"][1]["status"] = "ok"
    assert read()[0]["acti-vm"]["mapStatus"] == "ok"
    report["targets"][0]["checks"][0]["status"] = "critical"
    report["targets"][0]["observed_at"] = (now - timedelta(minutes=25)).isoformat()
    nodes, _ = read()
    assert nodes["acti-vm"]["mapStatus"] == "unknown"
    assert all("backupSnapshotAt" not in check for check in nodes["role:acti_backup"]["checks"])
    backup_job, = [check for check in nodes["role:acti_backup"]["checks"] if check["name"] == "backup_job"]
    assert backup_job["checkedAt"] == stamp and backup_job["stale"] is False
    context["devices"].pop(0)
    nodes, _ = read()
    assert nodes["acti-vm"]["mapStatus"] == "ok"
    assert not any(check["name"] == "backup_job" for check in nodes["role:acti_backup"]["checks"])


def test_service_distinguishes_partial_failure_and_unconfirmed_http_responses(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.infrastructure_map import _map_statuses, _public_node, _public_service_check
    from app.infrastructure_service_probes import apply_service_probes
    from app import infrastructure_service_probes as probes

    original_request = probes.http.client.HTTPConnection.request

    def request(connection, method, path, **kwargs):
        if path == "/timeout":
            raise TimeoutError
        return original_request(connection, method, path, **kwargs)

    monkeypatch.setattr(probes.http.client.HTTPConnection, "request", request)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            code, payload = {
                "/client": (200, b"<script src='client.js'></script>"),
                "/healthy": (200, b"Healthy"),
                "/unexpected": (200, b"Sign in"),
                "/unavailable": (503, b"Unavailable"),
                "/redirect": (302, b"Redirect"),
                "/named": (200, b"Healthy") if self.headers["Host"] == f"directum.example:{self.server.server_port}"
                else (404, b"Wrong host"),
            }[self.path]
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            if code == 302:
                self.send_header("Location", "/login?session=private")
            self.end_headers()
            self.wfile.write(payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            base = {"ip": "127.0.0.1", "port": server.server_port, "type": "http"}
            client = {**base, "path": "/client", "body_contains": "client.js"}
            paths = ("/healthy", "/unexpected", "/unavailable", "/redirect", "/primary-down",
                     "/partial", "/all-down", "/incomplete", "/timeout", "/named", "/bad-host")
            nodes = [{"id": path, "kind": "Сервис"} for path in paths]
            specs = {
                node["id"]: [client, {**base, "path": node["id"], "body": "Healthy"}] for node in nodes[:4]
            }
            failed = {**base, "path": "/unavailable", "body": "Healthy"}
            specs["/primary-down"] = [{**client, "component": True}, failed]
            specs["/partial"] = [client, {**failed, "component": True}]
            specs["/all-down"] = [failed, failed]
            timeout = {**base, "path": "/timeout", "body": "Healthy"}
            specs["/incomplete"] = [failed, timeout]
            specs["/timeout"] = [timeout]
            specs["/named"] = [{**base, "path": "/named", "body": "Healthy", "http_host": "directum.example",
                               "report_target": True}]
            specs["/bad-host"] = [{**specs["/named"][0], "http_host": "directum.example\r\nX-Injected: value"}]
            apply_service_probes(nodes, specs)
        finally:
            server.shutdown()
            worker.join()
    assert [node["reachability"]["state"] for node in nodes] == [
        "reachable", "reachable", "reachable", "reachable", "unreachable", "reachable", "unreachable", "unknown", "unknown",
        "reachable", "unknown",
    ]
    assert [[check["state"] for check in node["serviceChecks"]] for node in nodes[:4]] == [
        ["reachable", "reachable"], ["reachable", "unknown"], ["reachable", "unreachable"], ["reachable", "unknown"],
    ]
    assert nodes[1]["serviceChecks"][1]["path"] == "/unexpected"
    now = datetime.now(timezone.utc)
    public = {node["id"]: _public_node(node, now) for node in nodes}
    _map_statuses(public, [])
    assert [node["mapStatus"] for node in public.values()] == [
        "ok", "unknown", "warn", "unknown", "critical", "warn", "critical", "unknown", "unknown", "ok", "unknown",
    ]
    assert [node["status"] for node in public.values()] == [node["mapStatus"] for node in public.values()]
    assert public["/named"]["serviceChecks"][0]["httpHost"] == "directum.example"
    assert public["/named"]["serviceChecks"][0]["target"] == "127.0.0.1"
    assert public["/healthy"]["serviceChecks"][0]["target"] == ""
    assert public["/bad-host"]["serviceChecks"][0]["reason"] == "http_configuration"
    assert "httpHost" not in public["/bad-host"]["serviceChecks"][0]
    assert public["/bad-host"]["serviceChecks"][0]["target"] == ""
    assert public["/timeout"]["serviceChecks"][0]["reason"] == "timeout"
    assert public["/primary-down"]["serviceChecks"][0]["component"] is True
    assert public["/partial"]["serviceChecks"][1]["required"] is True
    checks = [_public_service_check(node["serviceChecks"][1], now) for node in nodes[:4]]
    assert [(check["httpStatus"], check.get("reason")) for check in checks] == [
        (200, None), (200, "http_payload_mismatch"), (503, "http_status"), (302, "http_status"),
    ]
    assert "private" not in json.dumps(checks)
    foreign = {**nodes[0]["serviceChecks"][1], "method": "DNS", "reason": "http_status"}
    assert "httpStatus" not in _public_service_check(foreign, now)
    assert "reason" not in _public_service_check(foreign, now)


def test_http_probe_matches_json_health_fields_without_fixing_the_version():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.infrastructure_service_probes import _probe

    responses = {
        "/ready": (200, b'{"version": "2", "database": "ok", "service": "example", "status": "ok"}'),
        "/wrong": (200, b'{"status":"ok","service":"example","database":"down"}'),
        "/reported-down": (200, b'{"status":"DOWN","service":"example"}'),
        "/invalid": (200, b"not json"),
        "/large": (200, b'{"status":"ok","service":"example","database":"ok"}' + b" " * 32768),
        "/down": (503, b'{"status":"unavailable"}'),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = responses[self.path]
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            base = {"type": "http", "ip": "127.0.0.1", "port": server.server_port,
                    "json_fields": {"status": "ok", "database": "ok", "service": "example"},
                    "json_unavailable": {"status": "DOWN", "service": "example"}}
            results = [_probe({**base, "path": path}) for path in responses]
        finally:
            server.shutdown()
            worker.join()
    assert results == ["reachable", "unknown", "unreachable", "unknown", "unknown", "unreachable"]


def test_http_script_probe_follows_only_the_unique_relative_build_asset(monkeypatch):
    from app.infrastructure_service_probes import _http_probe

    page = b'<script src="app_2.0_a1.js"></script>'
    requests = []
    asset_status = 200

    class Response:
        def __init__(self, path):
            self.page = path == "/Client/"
            self.status = 200 if self.page else asset_status

        def getheader(self, name, default):
            if name == "Content-Type":
                return "text/html" if self.page else "text/javascript"
            return default

        def read(self, limit):
            return (page if self.page else b"(() => {})();")[:limit]

    class Connection:
        def __init__(self, host, port, **kwargs):
            assert (host, port) == ("192.0.2.1", 80)

        def request(self, method, path, headers):
            assert method == "GET" and headers["Host"] == "directum.example.test"
            self.path = path
            requests.append(path)

        def getresponse(self):
            return Response(self.path)

        def close(self):
            pass

    monkeypatch.setattr("app.infrastructure_service_probes.http.client.HTTPConnection", Connection)
    spec = {"type": "http", "ip": "192.0.2.1", "port": 80, "path": "/Client/",
            "http_host": "directum.example.test", "script_src_prefix": "app_"}
    assert _http_probe(spec)["state"] == "reachable"
    assert requests == ["/Client/", "/Client/app_2.0_a1.js"]
    page = b'<script src="app_3_b2.js"></script>'
    asset_status = 404
    result = _http_probe(spec)
    assert result["state"] == "unreachable"
    assert result["httpStatus"] == 404
    assert result["path"] == "/Client/app_3_b2.js"

    for unsafe in (
        b'<script src="//other.test/app_x.js"></script>',
        b'<script src="../app_x.js"></script>',
        b'<script src="app_%2e%2e.js"></script>',
        b'<base href="/other/"><script src="app_x.js"></script>',
        b'<script src="app_x.js"></script><script src="app_y.js"></script>',
    ):
        page = unsafe
        requests.clear()
        assert _http_probe(spec)["state"] != "reachable"
        assert requests == ["/Client/"]

    asset_status = 200
    page = b'<script type="module" src="/assets/index-CDo-W9To.js"></script>'
    absolute_spec = {**spec, "script_src_prefix": "index-", "script_src_directory": "/assets/"}
    requests.clear()
    assert _http_probe(absolute_spec)["path"] == "/assets/index-CDo-W9To.js"
    assert requests == ["/Client/", "/assets/index-CDo-W9To.js"]
    for ref in ("//assets/index-ab.js", "/other/index-ab.js", "/assets/../index-ab.js",
                "/assets/index-ab.js?x=1", "/assets/index-ab.js#x"):
        page = f'<script src="{ref}"></script>'.encode()
        requests.clear()
        assert _http_probe(absolute_spec)["state"] == "unreachable"
        assert requests == ["/Client/"]
    assert _http_probe({**absolute_spec, "script_src_directory": "/assets/../"})["reason"] == "http_configuration"


def test_redfish_root_probe_reports_only_validated_api_version(monkeypatch):
    from app.infrastructure_service_probes import _http_probe

    document = {"Id": "RootService", "RedfishVersion": "1.9.0",
                "Managers": {"@odata.id": "/redfish/v1/Managers"},
                "Systems": {"@odata.id": "/redfish/v1/Systems"}}
    status = 200

    class Response:
        def __init__(self):
            self.status = status

        def getheader(self, name, default):
            return "application/json" if name == "Content-Type" else default

        def read(self, limit):
            return json.dumps(document).encode()[:limit]

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, headers):
            assert method == "GET" and path == "/redfish/v1/"
            assert "Authorization" not in headers

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr("app.infrastructure_service_probes.http.client.HTTPSConnection", Connection)
    spec = {"type": "https", "ip": "192.0.2.1", "port": 443, "path": "/redfish/v1/",
            "redfish_service_root": True}
    assert _http_probe(spec) == {"state": "reachable", "httpStatus": 200, "redfishVersion": "1.9.0"}
    document["RedfishVersion"] = "not a version"
    assert _http_probe(spec) == {"state": "unknown", "httpStatus": 200, "reason": "http_payload_mismatch"}
    document["RedfishVersion"] = "1.10.2"
    document["Managers"]["@odata.id"] = "https://elsewhere.test/redfish/v1/Managers"
    assert _http_probe(spec)["state"] == "unknown"
    status = 401
    assert _http_probe(spec) == {"state": "unknown", "httpStatus": 401, "reason": "http_status"}
    assert _http_probe({**spec, "type": "http"})["reason"] == "http_configuration"


def test_oidc_jwks_probe_requires_a_usable_public_rs256_signing_key(monkeypatch):
    import base64

    from cryptography.hazmat.primitives.asymmetric import rsa

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()

    def encode(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    signing = {"kid": "signing", "kty": "RSA", "use": "sig", "alg": "RS256",
               "n": encode(public.n), "e": encode(public.e)}
    encryption = {**signing, "kid": "encryption", "use": "enc", "alg": "RSA-OAEP"}
    document = {"keys": [encryption, signing]}
    path = "/idp/realms/example/protocol/openid-connect/certs"

    class Response:
        status = 200

        def getheader(self, name, default):
            return "application/json" if name == "Content-Type" else default

        def read(self, limit):
            return json.dumps(document).encode()[:limit]

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, target, headers):
            assert (method, target) == ("GET", path)
            assert "Authorization" not in headers

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(probes.http.client, "HTTPSConnection", Connection)
    spec = {"type": "https", "ip": "192.0.2.1", "port": 443, "path": path, "oidc_rs256_jwks": True}
    assert probes._http_probe(spec) == {"state": "reachable", "httpStatus": 200}
    for keys in ([encryption], [{**signing, "n": "AA"}], [{**signing, "d": "private"}], []):
        document["keys"] = keys
        result = probes._http_probe(spec)
        assert result == {"state": "unreachable", "httpStatus": 200, "reason": "oidc_rs256_key_missing"}
        public_result = _public_service_check(
            {**result, "method": "HTTPS", "source": "UI_VPN", "path": path,
             "checkedAt": datetime.now(timezone.utc).isoformat()},
            datetime.now(timezone.utc),
        )
        assert public_result["reason"] == "oidc_rs256_key_missing"
        assert "private" not in json.dumps(public_result)
    document["keys"] = {"signing": signing}
    assert probes._http_probe(spec)["reason"] == "http_payload_mismatch"
    assert probes._http_probe({**spec, "type": "http"})["reason"] == "http_configuration"


def test_http_probe_retries_one_connection_refusal_when_enabled(monkeypatch):
    from app import infrastructure_service_probes as probes

    refused = {"state": "unreachable", "reason": "http_connection_refused"}
    ready = {"state": "reachable", "httpStatus": 200}
    error = {"state": "unreachable", "reason": "http_status", "httpStatus": 503}
    spec = {"type": "http", "ip": "192.0.2.1", "port": 8088, "path": "/login"}
    waiting = []
    monkeypatch.setattr(probes, "sleep", waiting.append)

    for enabled, responses, expected, waits in (
        (True, [refused, ready], {**ready, "attempts": 2}, [2]),
        (True, [refused, refused], {**refused, "attempts": 2}, [2]),
        (True, [error], error, []),
        (False, [refused], refused, []),
    ):
        pending = iter(responses)
        waiting.clear()
        monkeypatch.setattr(probes, "_http", lambda *args: next(pending))
        assert probes._http_probe({**spec, "retry_connection_refused": enabled}) == expected
        assert list(pending) == [] and waiting == waits


def test_http_probe_accepts_only_bounded_complete_gzip_when_configured(monkeypatch):
    import gzip
    from io import BytesIO

    from app import infrastructure_service_probes as probes

    marker = b"<title>MikroTik SwOS</title>"
    body = gzip.compress(marker)

    class Response(BytesIO):
        status = 200

        def getheader(self, name, default):
            return {"Content-Type": "text/html", "Content-Encoding": "gzip"}.get(name, default)

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response(body)

        def close(self):
            pass

    monkeypatch.setattr(probes.http.client, "HTTPConnection", Connection)
    spec = {"type": "http", "ip": "192.0.2.10", "port": 80, "path": "/index.html",
            "content_type": "text/html", "body_contains": marker.decode()}
    assert probes._http_probe(spec)["state"] == "unknown"
    spec["allow_gzip"] = True
    assert probes._http_probe(spec)["state"] == "reachable"
    body = gzip.compress(b"<title>Other</title>")
    assert probes._http_probe(spec)["reason"] == "http_payload_mismatch"
    body = gzip.compress(marker)[:-4]
    assert probes._http_probe(spec)["reason"] == "http_content_encoding"
    body = gzip.compress(marker + b" " * probes.HTTP_BODY_LIMIT)
    assert probes._http_probe(spec)["reason"] == "http_body_limit"


def test_http_probe_checks_nested_boolean_health_fields(monkeypatch):
    from app.infrastructure_service_probes import _http_probe

    class Response:
        status = 200
        payload = {}

        def getheader(self, name, default):
            return "application/json"

        def read(self, limit):
            return json.dumps(self.payload).encode()

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return response

        def close(self):
            pass

    response = Response()
    monkeypatch.setattr("app.infrastructure_service_probes.http.client.HTTPConnection", Connection)
    spec = {"type": "http", "ip": "192.0.2.10", "port": 80, "path": "/ready",
            "json_fields": {"ProductName": "Directum RX", "MaintenanceModeState.IsEnabled": False},
            "json_unavailable": {"ProductName": "Directum RX", "MaintenanceModeState.IsEnabled": True}}
    for value, expected in [(False, "reachable"), (True, "unreachable"), (0, "unknown"),
                            ("false", "unknown"), (None, "unknown")]:
        response.payload = {"ProductName": "Directum RX", "MaintenanceModeState": {"IsEnabled": value}}
        assert _http_probe(spec)["state"] == expected
    response.payload = {"ProductName": "Directum RX", "MaintenanceModeState.IsEnabled": False}
    assert _http_probe(spec)["state"] == "unknown"


def test_malformed_service_probe_config_cannot_leave_observer_green():
    from app.infrastructure_map import _map_statuses, _public_node
    from app.infrastructure_service_probes import apply_service_probes

    for invalid in ([], {}, [None], [{"type": "dns"}] * 9, [{"type": "typo"}]):
        node = {"id": "service", "kind": "Сервис", "reachability": {
            "state": "reachable", "source": "Server Observer", "method": "HTTPS",
            "checkedAt": datetime.now(timezone.utc).isoformat(),
        }}
        apply_service_probes([node], {"service": invalid})
        public = _public_node(node, datetime.now(timezone.utc))
        _map_statuses({"service": public}, [])
        assert public["mapStatus"] == "unknown"
        assert public["serviceChecks"][0]["reason"] == "probe_configuration"


def test_service_probe_list_keeps_all_dns_components(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _map_statuses, _public_node

    node = {"id": "dns", "kind": "Сервис"}
    specs = [
        {"type": "dns", "ip": "192.0.2.53", "port": 53, "record": "A", "name": name,
         "transport": transport, "component": name != "primary.example."}
        for name in ("primary.example.", "secondary.example.", "replica.example.")
        for transport in ("udp", "tcp")
    ]
    calls = []

    def read(spec):
        calls.append((spec["name"], spec["transport"]))
        state = "unreachable" if spec is specs[-1] else "reachable"
        return {"state": state}

    monkeypatch.setattr(probes, "_dns", read)
    probes.apply_service_probes([node], {"dns": specs})
    assert calls == [(spec["name"], spec["transport"]) for spec in specs]
    public = _public_node(node, datetime.now(timezone.utc))
    _map_statuses({"dns": public}, [])
    assert len(public["serviceChecks"]) == 6
    assert all(check["required"] for check in public["serviceChecks"])
    assert public["mapStatus"] == "warn"


@pytest.mark.parametrize("correct_reply", [False, True])
def test_dns_probe_requires_udp_reply_from_the_queried_endpoint(monkeypatch, correct_reply):
    import dns.message
    import dns.rrset
    import socket
    from concurrent.futures import ThreadPoolExecutor

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _map_statuses, _public_node

    ip = "127.0.0.1"

    def tcp(query, target, **kwargs):
        assert target == ip and kwargs["port"] == port
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text("service.example.", 60, "IN", "A", "192.0.2.10"))
        return dns.message.from_wire(response.to_wire())

    monkeypatch.setattr(probes.dns.query, "tcp", tcp)
    monkeypatch.setattr(probes, "TIMEOUT", 0.5)
    node = {"id": "dns", "kind": "Сервис", "probeTargetIP": ip}
    with (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as expected,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unexpected,
          ThreadPoolExecutor(max_workers=1) as executor):
        expected.bind((ip, 0))
        unexpected.bind((ip, 0))
        expected.settimeout(2)
        port = expected.getsockname()[1]
        unexpected_port = unexpected.getsockname()[1]
        spec = {"type": "dns", "ip": ip, "port": port, "name": "service.example.", "record": "A",
                "expected_addresses": ["192.0.2.10"]}

        def reply():
            request, client = expected.recvfrom(4096)
            query = dns.message.from_wire(request)
            response = tcp(query, ip, port=port)
            expected.sendto(b"invalid DNS", client)
            unexpected.sendto(response.to_wire(), client)
            if correct_reply:
                expected.sendto(response.to_wire(), client)

        exchange = executor.submit(reply)
        probes.apply_service_probes([node], {"dns": [{**spec, "transport": mode} for mode in ("tcp", "udp")]})
        exchange.result()

    public = _public_node(node, datetime.now(timezone.utc))
    _map_statuses({"dns": public}, [])
    good, udp = public["serviceChecks"]
    assert (good["state"], good["dns"]["transport"]) == ("reachable", "TCP")
    assert udp["dns"]["transport"] == "UDP"
    if correct_reply:
        assert udp["state"] == "reachable" and public["mapStatus"] == "ok"
        assert "unexpectedResponder" not in udp["dns"]
    else:
        assert (udp["state"], udp["reason"], public["mapStatus"]) == (
            "unreachable", "dns_unexpected_source", "warn",
        )
        assert udp["dns"]["unexpectedResponder"] == {
            "address": ip, "port": unexpected_port, "rcode": "NOERROR",
            "addresses": ["192.0.2.10"], "matchesExpectedAddresses": True,
        }
        assert "addresses" not in udp["dns"]


def test_routed_dns_binds_checked_source_and_skips_wrong_route(monkeypatch):
    import dns.message
    import dns.rrset

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    ip, gateway, source = "198.51.100.53", "192.0.2.1", "192.0.2.10"
    route = {"dst": ip, "gateway": gateway, "dev": "eth0", "prefsrc": source}
    monkeypatch.setattr(probes.subprocess, "check_output", lambda *args, **kwargs: json.dumps([route]).encode())
    calls = []

    def query_udp(query, target, port, source):
        calls.append((target, source))
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", "192.0.2.53"))
        return dns.message.from_wire(response.to_wire()), None

    monkeypatch.setattr(probes, "_explicit_dns_udp", query_udp, raising=False)
    spec = {"type": "dns", "ip": ip, "port": 53, "name": "example.test.", "record": "A",
            "transport": "udp", "route_via": gateway}

    def check():
        node = {"id": "dns", "kind": "Сервис", "probeTargetIP": ip}
        probes.apply_service_probes([node], {"dns": [spec]})
        result, = node["serviceChecks"]
        return _public_service_check(result, datetime.now(timezone.utc))

    result = check()
    assert result["localRoute"] == {"state": "reachable", "expectedGateway": gateway, "gateway": gateway,
                                    "interface": "eth0", "sourceIP": source}
    assert result["state"] == "reachable"
    route["gateway"] = "192.0.2.2"
    result = check()
    assert (result["state"], result["reason"], result["localRoute"]["gateway"]) == (
        "unknown", "dns_route_mismatch", "192.0.2.2",
    )
    assert calls == [(ip, source)]


def test_gateway_segment_service_binds_only_to_its_canonical_gateway():
    from app.infrastructure_collect import build_graph

    context = {"devices": [{"id": "firewall", "name": "Firewall", "kind": "router", "management_ip": "192.0.2.1"}],
               "segments": [{"id": "lan", "gateway_device": "firewall", "gateway": "198.51.100.1", "cidr": "198.51.100.0/24"}]}
    bindings = {"asset_services": {
        "dns": {"asset": "firewall", "label": "DNS", "gateway_segment": "lan"},
        "other": {"asset": "firewall", "label": "Other", "gateway_segment": "missing"},
    }}
    graph = build_graph(context, {}, {}, {}, bindings, datetime.now(timezone.utc))
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert nodes["dns"]["probeTargetIP"] == "198.51.100.1"
    assert nodes["other"]["probeTargetIP"] is None


def test_dns_probe_requires_an_answer_to_the_actual_query(monkeypatch):
    import dns.message
    import dns.rrset

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    spec = {"type": "dns", "ip": "192.0.2.53", "port": 53, "name": "service.example.", "record": "A"}

    def check(*answers):
        def reply(query, *args, **kwargs):
            response = dns.message.make_response(query)
            response.answer.extend(dns.rrset.from_text(owner, 60, "IN", kind, *records)
                                   for owner, kind, records in answers)
            return dns.message.from_wire(response.to_wire()), False

        monkeypatch.setattr(probes.dns.query, "udp_with_fallback", reply)
        return probes._probe(spec)

    assert check(("unrelated.example.", "A", ["192.0.2.10"])) == "unreachable"
    alias = ("service.example.", "CNAME", ["host.example."])
    assert check(alias, ("host.example.", "A", ["192.0.2.11"])) == "reachable"

    spec["expected_addresses"] = ["192.0.2.10", "192.0.2.11"]
    assert check(alias, ("host.example.", "A", ["192.0.2.11"])) == "unreachable"
    assert check(alias, ("host.example.", "A", ["192.0.2.11", "192.0.2.10"])) == "reachable"
    assert check(alias, ("host.example.", "A", ["192.0.2.11", "192.0.2.10", "192.0.2.12"])) == "unreachable"
    node = {"id": "dns", "kind": "Сервис"}
    probes.apply_service_probes([node], {"dns": [spec]})
    detail = _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))
    assert detail["state"] == "unreachable" and detail["reason"] == "dns_address_mismatch"
    assert detail["dns"] == {"name": "service.example.", "record": "A", "rcode": "NOERROR",
                             "transport": "UDP", "addresses": ["192.0.2.10", "192.0.2.11", "192.0.2.12"]}
    spec["expected_addresses"] = ["2001:db8::10"]
    assert check(alias, ("host.example.", "A", ["192.0.2.10"])) == "unknown"


def test_dns_srv_probe_matches_controller_targets_and_ports(monkeypatch):
    import dns.message
    import dns.rrset
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    name = "_ldap._tcp.dc._msdcs.example.test."
    spec = {"name": name, "record": "SRV", "ip": "192.0.2.53", "port": 53,
            "expected_srv_records": [{"target": "DC1.example.test.", "port": 389},
                                     {"target": "dc2.example.test.", "port": 389}]}
    records = ["0 100 389 DC2.example.test.", "0 100 389 dc1.example.test."]

    def respond(query, *_args, **_kwargs):
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_text(name, 60, "IN", "SRV", *records))
        return dns.message.from_wire(reply.to_wire()), False

    monkeypatch.setattr(probes.dns.query, "udp_with_fallback", respond)
    result = probes._dns(spec)
    assert result["state"] == "reachable"
    now = datetime.now(timezone.utc)
    public = _public_service_check({**result, "method": "DNS", "source": "UI_VPN", "checkedAt": now.isoformat()}, now)
    assert public["dns"]["srvRecords"] == [{"target": "dc1.example.test.", "port": 389},
                                           {"target": "dc2.example.test.", "port": 389}]
    records[0] = "0 100 3268 dc2.example.test."
    assert probes._dns(spec)["reason"] == "dns_srv_mismatch"
    records[:] = ["0 0 0 ."]
    assert probes._dns(spec)["reason"] == "dns_no_answer"


def test_https_probe_checks_dns_name_against_ca_while_connecting_to_verified_ip(monkeypatch, tmp_path):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    name = "service.example.test"
    ip = "192.0.2.15"
    ca = str(tmp_path / "ca.pem")
    raw = object()
    secured = SimpleNamespace(getpeercert=lambda: {"notAfter": "Jan  1 00:00:00 2031 GMT"}, version=lambda: "TLSv1.3")
    events = []

    class Context:
        def wrap_socket(self, transport, *, server_hostname):
            assert transport is raw
            events.append(("tls", server_hostname))
            if server_hostname != name:
                raise probes.ssl.SSLCertVerificationError("hostname mismatch")
            return secured

    class Connection:
        def __init__(self, host, port, *, timeout, context):
            self.host = host
            assert port == 443
            assert isinstance(context, Context)

        def request(self, method, path, headers):
            assert self.sock is secured
            events.append((self.host, method, path))

        def getresponse(self):
            return reply

        def close(self):
            pass

    def connect(address, *, timeout):
        events.append(("tcp", address))
        return nullcontext(raw)

    def trust(*, cafile):
        assert cafile == ca
        return Context()

    monkeypatch.setattr(probes.socket, "create_connection", connect)
    monkeypatch.setattr(probes.ssl, "create_default_context", trust)
    monkeypatch.setattr(probes.http.client, "HTTPSConnection", Connection)
    reply = SimpleNamespace(status=200, getheader=lambda *_: "text/plain", read=lambda _: b"ready")
    spec = {"type": "https", "ip": ip, "port": 443, "path": "/ready", "body": "ready",
            "tls_server_name": name, "tls_ca_file": ca}
    assert probes._probe(spec) == "reachable"
    assert events == [("tcp", (ip, 443)), ("tls", name), (name, "GET", "/ready")]
    events.clear()
    assert probes._probe({**spec, "tls_server_name": "wrong.example.test"}) == "unknown"
    assert events == [("tcp", (ip, 443)), ("tls", "wrong.example.test")]
    events.clear()
    assert probes._probe({**spec, "tls_sha256": "0" * 64}) == "unknown"
    assert not events
    result = probes._http_probe({**spec, "report_tls_expiry": True})
    checked_at = datetime.now(timezone.utc)
    public = _public_service_check({**result, "method": "HTTPS", "source": "UI_VPN", "checkedAt": checked_at.isoformat()}, checked_at)
    assert (public["state"], public["tlsExpiresAt"], public["tlsVersion"]) == ("reachable", "2031-01-01T00:00:00+00:00", "TLSv1.3")
    failed = probes._http_probe({**spec, "tls_server_name": "wrong.example.test", "report_tls_expiry": True})
    assert "tlsExpiresAt" not in failed

    protected = {key: value for key, value in spec.items() if key != "body"}
    protected.update(path="/mcp", basic_auth_realm="GitNexus")
    assert probes._http_probe(protected) == {"state": "unknown", "httpStatus": 200, "reason": "http_status"}
    reply.status = 401
    reply.getheaders = lambda: [("WWW-Authenticate", 'Basic realm="GitNexus"')]
    assert probes._http_probe(protected) == {"state": "reachable", "httpStatus": 401}
    reply.getheaders = lambda: [("WWW-Authenticate", 'Basic realm="Other"')]
    assert probes._http_probe(protected) == {"state": "unknown", "httpStatus": 401, "reason": "http_payload_mismatch"}
    reply.getheaders = lambda: [("WWW-Authenticate", 'Basic realm="GitNexus"')]
    assert probes._http_probe(spec) == {"state": "unknown", "httpStatus": 401, "reason": "http_status"}
    assert probes._http_probe({**protected, "type": "http"}) == {"state": "unknown", "reason": "http_configuration"}


def test_asset_https_probe_validates_certificate_before_sending_request(monkeypatch):
    from hashlib import sha256
    from types import SimpleNamespace
    from app.infrastructure_collect import build_graph
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    events = []
    cert = b"peer-certificate"

    class Connection:
        def __init__(self, ip, port, *, timeout, context):
            assert (ip, port) == ("192.0.2.14", 8007)
            assert context.verify_mode == probes.ssl.CERT_NONE
            self.sock = SimpleNamespace(getpeercert=lambda **_: cert)

        def connect(self):
            events.append("connect")

        def request(self, method, path, headers):
            events.append((method, path))

        def getresponse(self):
            return SimpleNamespace(status=200, getheader=lambda *_: "text/html",
                                   read=lambda _: b'<script src="/js/proxmox-backup-gui.js">')

        def close(self):
            events.append("close")

    monkeypatch.setattr(probes.http.client, "HTTPSConnection", Connection)
    context = {"devices": [{"id": "pbs", "name": "PBS", "kind": "backup_server",
                            "management_ip": "192.0.2.14"}]}
    bindings = {"asset_services": {"pbs-web": {"asset": "pbs", "label": "PBS Web"}}}
    graph = build_graph(context, {}, {}, {}, bindings, now)
    node = next(node for node in graph["nodes"] if node["id"] == "pbs-web")
    assert any(link["a"] == "pbs" and link["b"] == "pbs-web" and link["confirmed"] for link in graph["links"])
    spec = {"type": "https", "ip": "192.0.2.15", "port": 8007, "path": "/",
            "content_type": "text/html", "body_contains": "/js/proxmox-backup-gui.js",
            "tls_sha256": "0" * 64}
    configured = {"pbs-web": [spec]}
    probes.apply_service_probes(graph["nodes"], configured)
    assert not events
    spec["ip"] = "192.0.2.14"
    probes.apply_service_probes(graph["nodes"], configured)
    assert events == ["connect", "close"]
    assert node["reachability"]["state"] == "unknown"
    assert node["serviceChecks"][-1]["reason"] == "http_certificate_pin"
    assert "httpStatus" not in node["serviceChecks"][-1]
    events.clear()
    spec["tls_sha256"] = sha256(cert).hexdigest()
    probes.apply_service_probes(graph["nodes"], configured)
    assert events == ["connect", ("GET", "/"), "close"]
    assert node["reachability"]["state"] == "reachable"
    assert node["serviceChecks"][-1]["httpStatus"] == 200


def test_pinned_https_probe_checks_redfish_authentication_challenge(monkeypatch):
    from hashlib import sha256
    from types import SimpleNamespace

    from app.infrastructure_service_probes import _http_probe

    cert = b"redfish-certificate"
    challenge = 'Basic realm="AMI_Redfish_Server", X-Auth-Token realm="AMI_Redfish_Server"'
    requests = []

    class Connection:
        sock = SimpleNamespace(getpeercert=lambda **_: cert)

        def __init__(self, *args, **kwargs):
            pass

        def connect(self):
            pass

        def request(self, method, path, headers):
            assert "Authorization" not in headers
            requests.append((method, path))

        def getresponse(self):
            return SimpleNamespace(status=401, getheaders=lambda: [("WWW-Authenticate", challenge)])

        def close(self):
            pass

    monkeypatch.setattr("app.infrastructure_service_probes.http.client.HTTPSConnection", Connection)
    spec = {"type": "https", "ip": "192.0.2.5", "port": 443, "path": "/redfish/v1/Systems",
            "tls_sha256": sha256(cert).hexdigest(), "basic_auth_realm": "AMI_Redfish_Server"}
    assert _http_probe({**spec, "tls_sha256": "0" * 64})["reason"] == "http_certificate_pin"
    assert requests == []
    assert _http_probe(spec) == {"state": "reachable", "httpStatus": 401}
    assert requests == [("GET", "/redfish/v1/Systems")]
    challenge = "Basic"
    assert _http_probe({**spec, "basic_auth_realm": ""}) == {"state": "reachable", "httpStatus": 401}
    assert _http_probe(spec)["reason"] == "http_payload_mismatch"
    challenge = 'Digest realm="AMI_Redfish_Server"'
    assert _http_probe(spec)["reason"] == "http_payload_mismatch"
    assert _http_probe({**spec, "basic_auth_realm": ""})["reason"] == "http_payload_mismatch"
    assert _http_probe({**spec, "tls_sha256": None})["reason"] == "http_configuration"


def test_http_digest_challenge_requires_401_realm_and_nonce(monkeypatch):
    from types import SimpleNamespace

    from app.infrastructure_service_probes import _http_probe
    from app.infrastructure_map import _public_service_check

    response = SimpleNamespace(status=401)
    response.getheaders = lambda: [("WWW-Authenticate", challenge)]
    challenge = 'Digest realm="Device, API", qop="auth,auth-int", nonce="token"'

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, headers):
            assert (method, path) == ("GET", "/ISAPI/System/deviceInfo")
            assert "Authorization" not in headers

        def getresponse(self):
            return response

        def close(self):
            pass

    monkeypatch.setattr("app.infrastructure_service_probes.http.client.HTTPConnection", Connection)
    spec = {"type": "http", "ip": "192.0.2.5", "port": 80, "path": "/ISAPI/System/deviceInfo",
            "digest_auth_challenge": True}
    result = _http_probe(spec)
    assert result == {"state": "reachable", "httpStatus": 401, "httpAuthChallenge": "Digest"}
    now = datetime.now(timezone.utc)
    check = {**result, "source": "UI_VPN", "method": "HTTP", "required": True, "checkedAt": now.isoformat()}
    assert _public_service_check(check, now)["httpAuthChallenge"] == "Digest"
    assert "httpAuthChallenge" not in _public_service_check({**check, "httpStatus": 200}, now)
    assert "httpAuthChallenge" not in _public_service_check(check, now + timedelta(minutes=6))
    for challenge in ('Basic realm="Device"', 'Digest realm="Device"', 'Digest nonce="token"',
                      'Digest realm="Device", nonce=""', 'Digest realm="Device", nonce="one", nonce="two"'):
        assert _http_probe(spec) == {"state": "unknown", "httpStatus": 401, "reason": "http_payload_mismatch"}
    response.status = 200
    assert _http_probe(spec) == {"state": "unknown", "httpStatus": 200, "reason": "http_status"}
    assert _http_probe({**spec, "body": "hello"})["reason"] == "http_configuration"


def test_zabbix_version_checks_matching_json_rpc_response():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from app.infrastructure_service_probes import apply_service_probes

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert request == {"jsonrpc": "2.0", "method": "apiinfo.version", "params": [], "id": 1}
            code = 503 if self.path == "/failed" else 200
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"jsonrpc": "2.0", "id": 2 if self.path == "/wrong-id" else 1, "result": "7.0.21"}
            self.wfile.write(json.dumps(response).encode())

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            paths = ("/zabbix/api_jsonrpc.php", "/wrong-id", "/failed")
            nodes = [{"id": path, "kind": "Сервис"} for path in paths]
            specs = {path: [{"type": "zabbix_api", "ip": "127.0.0.1", "port": server.server_port, "path": path}]
                     for path in paths}
            apply_service_probes(nodes, specs)
        finally:
            server.shutdown()
            worker.join()
    assert [n["reachability"]["state"] for n in nodes] == ["reachable", "unknown", "unreachable"]
    assert nodes[0]["serviceChecks"][0]["path"] == paths[0]
    from app.infrastructure_map import _public_service_check

    checks = [_public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc)) for node in nodes]
    assert [(check.get("zabbixVersion"), check.get("httpStatus")) for check in checks] == [
        ("7.0.21", 200), (None, 200), (None, 503),
    ]


def test_smb_requires_complete_negotiate_reply_and_reports_dialect(monkeypatch):
    from io import BytesIO
    import struct
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    response = bytearray(128)
    response[:4] = b"\xfeSMB"
    struct.pack_into("<H", response, 4, 64)
    struct.pack_into("<I", response, 16, 1)
    struct.pack_into("<HHH", response, 64, 65, 3, 0x0302)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def sendall(self, request):
            assert request[4:8] == b"\xfeSMB"
            self.wire = BytesIO(len(self.payload).to_bytes(4, "big") + self.payload)

        def recv(self, size):
            return self.wire.read(min(size, 11))

        def settimeout(self, timeout):
            assert 0 < timeout <= probes.TIMEOUT

    connection = Connection()
    monkeypatch.setattr(probes.socket, "create_connection", lambda *_args, **_kwargs: connection)
    spec = {"type": "smb", "ip": "192.0.2.20", "port": 445}

    def check(payload):
        connection.payload = payload
        node = {"id": "share", "kind": "Сервис"}
        probes.apply_service_probes([node], {"share": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    assert check(response[:70])["state"] == "unknown"
    check_result = check(response)
    assert check_result["state"] == "reachable"
    assert check_result["smbDialect"] == "3.0.2"
    assert check_result["smbSigningRequired"] is True
    struct.pack_into("<Q", response, 24, 1)
    assert check(response)["state"] == "unknown"
    struct.pack_into("<Q", response, 24, 0)
    struct.pack_into("<HH", response, 120, 128, 12)
    assert check(response)["state"] == "unknown"


@pytest.mark.parametrize("protocol", ["mongodb_ping", "amqp_start", "redis_ping"])
def test_directum_dependencies_require_the_matching_application_protocol(monkeypatch, protocol):
    import struct

    from app import infrastructure_service_probes as probes

    sent = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            assert 0 < value <= probes.TIMEOUT

        def sendall(self, data):
            sent.append(data)
            if protocol == "mongodb_ping":
                assert data.endswith(b"\x02$db\x00\x06\x00\x00\x00admin\x00\x00")
                request_id = struct.unpack_from("<i", data, 4)[0]
                self.response = struct.pack("<4i", 38, 1, request_id, 2013) + bytes.fromhex(
                    "000000000011000000016f6b00000000000000f03f00")
            elif protocol == "amqp_start":
                assert data == b"AMQP\x00\x00\x09\x01"
                body = bytes.fromhex("000a000a00090000000000000005504c41494e00000005656e5f5553")
                self.response = struct.pack("!BHI", 1, 0, len(body)) + body + b"\xce"
            else:
                assert data == b"*1\r\n$4\r\nPING\r\n"
                self.response = b"+PONG\r\n"
            if corrupt:
                self.response = self.response[:-1] + b"X"

        def recv(self, size):
            size = min(size, 3)
            data, self.response = self.response[:size], self.response[size:]
            return data

    monkeypatch.setattr(probes.socket, "create_connection", lambda *args, **kwargs: Connection())
    spec = {"type": protocol, "ip": "192.0.2.10", "port": 1234}
    node = {"id": "svc", "kind": "Сервис", "probeTargetIP": None}
    probes.apply_service_probes([node], {"svc": [spec]})
    assert node["serviceChecks"][0]["reason"] == "probe_target_unconfirmed"
    assert not sent

    for corrupt, state in ((False, "reachable"), (True, "unknown")):
        node = {"id": "svc", "kind": "Сервис", "probeTargetIP": spec["ip"]}
        probes.apply_service_probes([node], {"svc": [spec]})
        check, = node["serviceChecks"]
        assert check["state"] == state and check["required"]
        assert check["target"] == spec["ip"] and check["port"] == spec["port"]


def test_postgresql_probe_requires_protocol_response(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    class Connection:
        response = b"S"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def sendall(self, payload):
            assert payload.hex() == "0000000804d2162f"

        def recv(self, size):
            assert size == 1
            return self.response

    connection = Connection()
    monkeypatch.setattr(probes.socket, "create_connection", lambda *_args, **_kwargs: connection)

    class TLS:
        fails = False

        def wrap_socket(self, socket):
            assert socket is connection and not self.check_hostname
            assert self.verify_mode == probes.ssl.CERT_NONE
            if self.fails:
                raise probes.ssl.SSLError("internal TLS details")
            return self

        def version(self):
            return "TLSv1.3"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    tls = TLS()
    monkeypatch.setattr(probes.ssl, "SSLContext", lambda *_: tls)
    spec = {"type": "postgresql", "ip": "192.0.2.27", "port": 5432}
    assert probes._probe(spec) == "reachable"

    def public():
        node = {"id": "db", "kind": "Сервис"}
        probes.apply_service_probes([node], {"db": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    check = public()
    assert (check["state"], check["postgresqlTls"], check["tlsVersion"]) == ("reachable", "negotiated", "TLSv1.3")
    tls.fails = True
    check = public()
    assert (check["state"], check["postgresqlTls"], check["reason"]) == ("unknown", "failed", "postgresql_tls_handshake")
    assert "internal TLS details" not in json.dumps(check)
    connection.response = b"N"
    assert probes._probe(spec) == "reachable"
    assert public()["postgresqlTls"] == "declined"
    connection.response = b"H"
    assert probes._probe(spec) == "unreachable"
    assert public()["reason"] == "unexpected_response"


def test_inventory_observer_service_probes_only_the_confirmed_vm(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    mac, address = "02:00:00:00:00:03", "192.0.2.10"
    context = {"devices": [{"id": "directumrx", "name": "DirectumServer", "kind": "server"}],
               "services": [{"id": "gateway-dns", "name": "DNS"}]}
    bindings = {"roles": {"directum": {"asset": "directumrx", "vmid": 103, "mac": mac}},
                "guests": {"103": {"asset": "directumrx", "mac": mac}},
                "guest_probe_ips": {"103": address},
                "asset_services": {"gateway-dns": {"asset": "gateway", "used_by": ["role:directum"]}}}
    pve = {"cluster": [], "nodes": [],
           "guests": [{"vmid": 103, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"103": {"net0": f"virtio={mac},bridge=vmbr1"}}}
    arp = {"ip": address, "mac": mac, "last_seen_at": now.isoformat()}
    calls = []
    monkeypatch.setattr(probes, "_http_probe", lambda spec: calls.append(spec["ip"]) or {"state": "reachable"})

    def check(network):
        graph = build_graph(context, network, {}, pve, bindings, now)
        item = next(node for node in graph["nodes"] if node["id"] == "role:directum")
        assert any(edge["a"] == item["id"] and edge["b"] == "gateway-dns"
                   and edge["kind"] == "Зависимость сервиса" for edge in graph["links"])
        probes.apply_service_probes([item], {item["id"]: [{"type": "http", "ip": address, "port": 80}]})
        return item["serviceChecks"][0]

    assert check({})["reason"] == "probe_target_unconfirmed"
    assert check({"arp": [arp]})["identityCheckedAt"] == now.isoformat()
    bindings["guests"] = {}
    assert check({"arp": [arp]})["reason"] == "probe_target_unconfirmed"
    assert calls == [address]


def test_observer_service_attaches_to_the_vm_with_the_expected_mac(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _map_statuses, _public_node
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    mac = "02:00:00:00:00:03"
    pve = {"at": now.isoformat(), "cluster": [], "nodes": [],
           "guests": [{"vmid": 211, "node": "pve2", "type": "qemu", "status": "running"}],
           "configs": {"211": {"net0": f"virtio={mac},bridge=vmbr1"}}}
    bindings = {"roles": {"nextcloud": {"label": "Nextcloud", "vmid": 211, "mac": mac}}}
    server = {"freshness": "current", "targets": [{"role": "nextcloud", "status": "ok",
              "observed_at": now.isoformat(), "checks": [{"name": "nextcloud_status", "status": "ok"}]}]}

    def load(at=now):
        graph = build_graph({}, {}, server, pve, bindings, at)
        item, = [n for n in graph["nodes"] if n["id"] == "role:nextcloud"]
        links = [e for e in graph["links"] if e["b"] == item["id"]]
        return item, links

    item, links = load()
    assert item["reachability"]["source"] == "Server Observer"
    assert [(e["a"], e["source"], e["confirmed"]) for e in links] == [("pve-guest:211", "Proxmox", True)]
    pve["guests"][0]["status"] = "stopped"
    stopped, _ = load()
    assert stopped["reachability"]["state"] == "stopped"
    assert stopped["reachability"]["source"] == "Proxmox"
    def unexpected_probe(spec):
        raise AssertionError("probe ran")

    monkeypatch.setattr(probes, "_http_probe", unexpected_probe)
    probes.apply_service_probes([stopped], {stopped["id"]: [{"type": "https", "port": 443}]})
    public = _public_node(stopped, datetime.now(timezone.utc))
    _map_statuses({public["id"]: public}, [])
    assert public["status"] == "critical"
    assert public["serviceChecks"][0]["reason"] == "probe_host_stopped"
    pve["guests"][0]["status"] = "running"
    assert load(now + timedelta(hours=1))[1] == []
    pve["configs"]["211"]["net0"] = "virtio=02:00:00:00:00:04,bridge=vmbr1"
    assert load()[1] == []


@pytest.mark.parametrize("inventory_service", [False, True])
def test_guest_service_requires_matching_mac_and_arp_to_enable_probe(monkeypatch, inventory_service):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _public_service_check
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    mac, address = "02:00:00:00:00:03", "192.0.2.21"
    pve = {
        "cluster": [], "nodes": [],
        "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}},
    }
    arp = {"ip": address, "mac": mac, "last_seen_at": now.isoformat()}
    network = {"arp": [arp]}
    binding = {"guest_probe_ips": {"108": address},
               "guest_services": {"zabbix-api": {"label": "Zabbix API", "vmid": 108, "mac": mac,
                                                "used_by": ["consumer"]}}}
    context = {"services": [{"id": "consumer", "name": "Consumer"}]}
    host_id = "pve-guest:108"
    if inventory_service:
        host_id = "zabbix"
        context["devices"] = [{"id": host_id, "name": "Zabbix", "kind": "server", "management_ip": address}]
        context["services"].append({"id": "zabbix-api", "name": "Zabbix API", "device": host_id})
        binding["guests"] = {"108": {"asset": host_id, "mac": mac}}
    configured = {"zabbix-api": [{"ip": address, "port": 80, "type": "zabbix_api"}]}
    calls = []
    monkeypatch.setattr(probes, "_zabbix_api", lambda spec: calls.append(spec["ip"]) or {"state": "reachable"})

    def build():
        graph = build_graph(context, network, {}, pve, binding, now)
        probes.apply_service_probes(graph["nodes"], configured)
        return graph, next(n for n in graph["nodes"] if n["id"] == "zabbix-api")

    graph, service = build()
    assert service["reachability"]["state"] == "reachable"
    assert service["serviceChecks"][0]["identityCheckedAt"] == now.isoformat()
    assert any(e["a"] == host_id and e["b"] == "zabbix-api" and e["confirmed"] for e in graph["links"])
    assert any(e["a"] == "consumer" and e["b"] == "zabbix-api" and e["confirmed"]
               and e["kind"] == "Зависимость сервиса" for e in graph["links"])
    configured["zabbix-api"][0]["ip"] = "192.0.2.22"
    mismatch = build()[1]
    assert "reachability" not in mismatch
    assert mismatch["serviceChecks"][0]["reason"] == "probe_target_mismatch"
    assert mismatch["serviceChecks"][0]["skipped"] is True
    configured["zabbix-api"][0]["ip"] = address
    network["arp"] = []
    unconfirmed = build()[1]
    assert "reachability" not in unconfirmed
    check = _public_service_check(unconfirmed["serviceChecks"][0], datetime.now(timezone.utc))
    assert check["state"] == "unknown" and check["skipped"] is True and check["reason"] == "probe_target_unconfirmed"
    assert check["target"] == "" and check["method"] == "Zabbix API"
    assert calls == [address]
    network["arp"] = [arp]
    pve["configs"]["108"]["net0"] = "virtio=02:00:00:00:00:99,bridge=vmbr0"
    graph, service = build()
    assert "reachability" not in service
    dependency, = [e for e in graph["links"] if e["b"] == "zabbix-api" and e["kind"] == "Зависимость сервиса"]
    assert (dependency["a"], dependency["kind"], dependency["confirmed"]) == (
        "consumer", "Зависимость сервиса", True,
    )
    pve["configs"]["108"]["net0"] = f"virtio={mac},bridge=vmbr0"
    pve["at"] = (now - timedelta(hours=1)).isoformat()
    graph, service = build()
    assert service["serviceChecks"][0]["reason"] == "probe_target_unconfirmed"
    assert not any(e["source"] == "Proxmox" and e["b"] == "zabbix-api" for e in graph["links"])
    if inventory_service:
        pve["at"] = now.isoformat()
        binding["guests"] = {}
        graph, service = build()
        assert service["serviceChecks"][0]["reason"] == "probe_target_unconfirmed"
        assert not any(e["a"] == "pve-guest:108" and e["b"] == "zabbix-api" for e in graph["links"])


def test_guest_service_uses_fresh_explicit_local_arp_without_router_entry(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    mac, address = "02:00:00:00:00:03", "192.0.2.21"
    pve = {
        "at": now.isoformat(), "cluster": [], "nodes": [],
        "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}},
    }
    bindings = {
        "guest_probe_ips": {"108": address},
        "guest_local_arp_macs": {"108": mac},
        "guest_services": {"panel": {"label": "Панель", "vmid": 108, "mac": mac}},
    }
    calls = []
    answers = ["matched"]

    def probe(ip, expected_mac):
        calls.append((ip, expected_mac))
        return {"state": answers[-1]}

    monkeypatch.setattr(collector, "_local_arp_diagnostic", probe, raising=False)
    network = {"arp": []}

    def collect():
        network["guest_arp_probes"] = collector._collect_guest_arp_probes(
            pve, network, bindings["guest_probe_ips"], now, local_macs=bindings["guest_local_arp_macs"],
        )
        graph = collector.build_graph({}, network, {}, pve, bindings, datetime.now(timezone.utc))
        return next(n for n in graph["nodes"] if n["id"] == "panel")

    service = collect()
    assert service["probeTargetIP"] == address
    assert service["probeTargetIdentityAt"] == now.isoformat()
    assert calls == [(address, mac)]

    network["arp"] = [{"ip": address, "mac": mac, "last_seen_at": now.isoformat()}]
    monkeypatch.setattr(collector, "_probe_on_link_mac", lambda *_: False)
    assert collect()["probeTargetIP"] == address
    assert calls == [(address, mac), (address, mac)]
    network["arp"] = []

    answers.append("no_reply")
    assert collect()["probeTargetIP"] is None

    calls.clear()
    answers.append("matched")
    network["arp"] = [{"ip": address, "mac": "02:00:00:00:00:09", "last_seen_at": now.isoformat()}]
    assert collect()["probeTargetIP"] is None
    assert calls == []

    network["arp"] = []
    pve["configs"]["108"]["net0"] += ",link_down=1"
    assert collect()["probeTargetIP"] is None
    assert calls == []


def test_collector_vm_uses_its_local_interface_address_only_for_matching_adapter(tmp_path, monkeypatch):
    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment

    now = datetime.now(timezone.utc)
    address, mac = "192.0.2.30", "02:00:00:00:00:03"
    bindings = {"guest_probe_ips": {"109": address}, "guest_local_interfaces": {"109": "ens18"},
                "guest_services": {"local-ssh": {"vmid": 109, "mac": mac, "label": "SSH"}}}
    rows = [{"ifname": "ens18", "link_type": "ether", "address": mac, "flags": ["UP", "LOWER_UP"],
             "addr_info": [{"family": "inet", "local": address, "scope": "global"}]}]
    monkeypatch.setattr(collector.subprocess, "check_output", lambda *args, **kwargs: json.dumps(rows))
    pve = {"at": now.isoformat(), "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [{"vmid": 109, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"109": {"net0": f"virtio={mac},bridge=vmbr0"}}}
    path = tmp_path / "infrastructure.json"

    def build():
        network = {"guest_local_ipv4": collector._collect_local_guest_ipv4(bindings)}
        raw = collector.build_graph({}, network, {}, pve, bindings, datetime.now(timezone.utc))
        service = next(row for row in raw["nodes"] if row["id"] == "local-ssh")
        path.write_text(json.dumps(raw), encoding="utf-8")
        graph = load_infrastructure_map(path)
        guest, = summarize_guest_attachment(graph, "pve-guest:109")["attachment"]["guests"]
        node = next(row for row in graph["nodes"] if row["id"] == "pve-guest:109")
        return guest["interfaces"][0], node["reachability"], service["probeTargetIP"]

    interface, reachability, target = build()
    observed, = interface["ipv4Observations"]
    assert (observed["address"], observed["method"]) == (address, "Локальный интерфейс ens18")
    assert reachability["state"] == "unknown"
    assert target == address
    rows[0]["address"] = "02:00:00:00:00:04"
    interface, _, target = build()
    assert "ipv4Observations" not in interface and target is None
    rows[0]["address"] = mac
    rows[0]["flags"].remove("LOWER_UP")
    interface, _, target = build()
    assert "ipv4Observations" not in interface and target is None


@pytest.mark.parametrize(("protocol", "port"), [("dns", 53), ("ntp", 123)])
def test_service_requires_verified_vlan_peer_and_uses_local_address(monkeypatch, protocol, port):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _public_service_check
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    address = "192.0.2.1"
    transit = {"ip": address, "peerAsset": "gateway", "localAsset": "observer", "peerMac": "02:00:00:00:00:01",
               "interface": "eth0.50", "vlan": 50, "address": "192.0.2.2/30"}
    context = {"devices": [{"id": "gateway", "name": "Gateway", "kind": "firewall_dns_host",
                            "management_ip": "198.51.100.1"}]}
    bindings = {"asset_services": {"dns50": {"asset": "gateway", "label": "DNS", "local_vlan_transit": "link"}}}
    config = {"dns50": [{"type": protocol, "ip": address, "port": port, "transport": "udp"}]}
    vlan = {"interface": "eth0.50", "id": 50, "localAddress": "192.0.2.2/30",
            "peer": {"asset": "gateway", "guestPort": "net2", "state": "matched"}}
    calls = []

    def service_probe(spec, *, source=None):
        calls.append((spec["ip"], source))
        return {"state": "reachable"}

    monkeypatch.setattr(probes, "_local_vlan_transit", lambda spec: {"state": "reachable", "vlanTransit": vlan})
    monkeypatch.setattr(probes, "_" + protocol, service_probe)

    def check(transits):
        graph = build_graph(context, {}, {}, {}, bindings, now, local_vlan_probes=transits)
        probes.apply_service_probes(graph["nodes"], config)
        service = next(row for row in graph["nodes"] if row["id"] == "dns50")
        return _public_service_check(service["serviceChecks"][0], datetime.now(timezone.utc))

    result = check({"transit:link": transit})
    assert result["state"] == "reachable" and result["vlanTransit"] == vlan
    assert calls == [(address, "192.0.2.2")]
    vlan["peer"]["state"] = "unconfirmed"
    assert check({"transit:link": transit})["reason"] == "vlan_peer_identity_unconfirmed"
    assert check({})["skipped"]
    assert calls == [(address, "192.0.2.2")]


def test_port_evidence_keeps_direction_and_parallel_links(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    observed = (now - timedelta(minutes=1)).isoformat()
    devices = [{"id": key, "name": key, "kind": "switch", "management_ip": ip}
               for key, ip in (("west", "192.0.2.1"), ("east", "192.0.2.2"))]
    declared = {"endpoint_a": {"device": "west", "interface": "west-1"},
                "endpoint_b": {"device": "east", "interface": "east-1"}}
    network = {
        "sources": [{"id": index, "name": d["id"], "host": d["management_ip"]}
                    for index, d in enumerate(devices, 1)],
        "ports": [{"source": "east", "port_key": "index:2", "name": "east-2"}],
        "links": [{"source_a_id": 2, "source_b_id": 1, "port_a_key": "index:2",
                   "port_b_key": "west-2", "last_seen_at": now.isoformat(), "state": "confirmed",
                   "evidence": [
                       {"endpoint_a": {"source_id": 2, "port_key": "index:2"},
                        "endpoint_b": {"source_id": 1, "port_key": "west-2"},
                        "evidence_type": "lldp_chassis_mac", "observed_at": observed},
                   ]}],
        "lldp": [{"source": "west", "system_name": "east", "local_port_key": "west-3",
                  "port_id_subtype": 3, "port_id": "00:01:02:03:04:05", "observed_at": observed}],
    }
    graph = build_graph({"devices": devices, "links": [declared]}, network, {}, {}, {}, now)
    path = tmp_path / "infrastructure.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    link, = load_infrastructure_map(path, now)["links"]
    assert (link["a"], link["b"]) == ("west", "east")
    assert [(row["a"], row["b"], row["confirmed"]) for row in link["portEvidence"]] == [
        ("west-1", "east-1", False), ("west-2", "east-2", True), ("west-3", "", True),
    ]
    stale_link, = load_infrastructure_map(path, now + timedelta(hours=1))["links"]
    assert not stale_link["confirmed"]
    assert all(not row["confirmed"] for row in stale_link["portEvidence"])
    assert link["portEvidence"][1]["at"] == observed

    network.pop("lldp")
    network["links"][0]["evidence"][0]["observed_at"] = (now - timedelta(hours=1)).isoformat()
    graph = build_graph({"devices": devices, "links": [declared]}, network, {}, {}, {}, now)
    assert not graph["links"][0]["confirmed"]


def test_fdb_only_topology_does_not_create_or_confirm_physical_links():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    context = {"devices": [{"id": key, "name": key, "kind": "switch"} for key in ("core", "access", "remote")],
               "links": [{"relation": "connected_to", "state": {"verified": False},
                          "endpoint_a": {"device": "core", "interface": "ge5"},
                          "endpoint_b": {"device": "access", "interface": "Port1"}}]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access", "remote"), 1)]
    network = {"sources": sources, "links": [{"source_a_id": 1, "source_b_id": peer, "state": "confirmed",
                "evidence": [{"evidence_type": "fdb_management_mac", "observed_at": now.isoformat(),
                              "endpoint_a": {"source_id": 1, "port_key": "ge5"},
                              "endpoint_b": {"source_id": peer}}]} for peer in (2, 3)]}
    links = {edge["b"]: edge for edge in build_graph(context, network, {}, {}, {}, now)["links"]}
    assert links["access"]["kind"] == "Сетевое соединение" and not links["access"]["confirmed"]
    assert all(not p["confirmed"] for p in links["access"]["portEvidence"])
    assert links["remote"]["kind"] == "Путь по MAC-таблице" and not links["remote"]["confirmed"]
    assert links["remote"]["portEvidence"][0]["a"] == "ge5"


def test_lldp_direct_neighbor_overrides_conflicting_fdb_ports():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": key, "name": name, "kind": kind}
                            for key, name, kind in (("core", "SNR", "switch"), ("ito", "ITO", "switch"),
                                                    ("router", "RB3011", "router"), ("other", "Other", "router"))]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "ito", "router", "other"), 1)]
    inferred = [{"source_a_id": 1, "source_b_id": peer, "state": "confirmed", "evidence": [
        {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1, "port_key": "ge23"},
         "endpoint_b": {"source_id": peer}, "observed_at": at},
    ]} for peer in (3, 4)]
    lldp = [{"source": "core", "local_port_key": port, "system_name": name, "chassis_id": mac,
             "port_id": "ether1", "port_id_subtype": "interface_name", "observed_at": at}
            for port, name, mac in (("ge23", "ITO", "02:00:00:00:00:02"),
                                    ("ge24", "RB3011", "02:00:00:00:00:03"))]
    graph = build_graph(context, {"sources": sources, "links": inferred, "lldp": lldp}, {}, {}, {}, now)
    links = {e["b"]: e for e in graph["links"] if e["a"] == "core"}
    assert links["ito"]["confirmed"]
    assert links["router"]["confirmed"]
    assert [(p["a"], p["confirmed"]) for p in links["router"]["portEvidence"]] == [("ge24", True), ("ge23", False)]
    assert links["other"]["kind"] == "Путь по MAC-таблице"
    assert not links["other"]["confirmed"]
    assert not links["other"]["portEvidence"][0]["confirmed"]


def test_map_reports_port_state_for_declared_pair_without_confirming_cable(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": key, "name": key, "kind": "switch"} for key in ("core", "access")],
               "links": [{"relation": "connected_to", "state": {"verified": False},
                          "endpoint_a": {"device": "core", "interface": "Gi1/0/18"},
                          "endpoint_b": {"device": "access", "interface": "Port5"}}]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access"), 1)]
    ports = [
        {"source": "core", "port_key": "ifindex:49170", "name": "gigabitEthernet 1/0/18",
         "oper_status": "up", "last_seen_at": at},
        {"source": "access", "port_key": "physical:5", "name": "p5_uplink_IT_TP",
         "oper_status": "down", "last_seen_at": at},
    ]
    path = tmp_path / "graph.json"

    def load(when=now):
        graph = build_graph(context, {"sources": sources, "ports": ports}, {}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        link, = load_infrastructure_map(path, when)["links"]
        report, = link["portEvidence"]
        assert not link["confirmed"] and not report["confirmed"]
        return report.get("portStates", {})

    assert load() == {
        "a": {"name": "gigabitEthernet 1/0/18", "state": "up", "checkedAt": at, "speedBps": None, "stale": False},
        "b": {"name": "p5_uplink_IT_TP", "state": "down", "checkedAt": at, "speedBps": None, "stale": False},
    }
    assert not load(now + timedelta(hours=1))
    ports.append({**ports[0], "port_key": "ifindex:42", "name": "Gi1/0/18"})
    assert set(load()) == {"b"}


def test_lldp_neighbor_count_on_ports_and_declared_links_uses_current_poll(tmp_path):
    from app.infrastructure_collect import build_graph, publish_snapshot
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    devices = [{"id": key, "name": key, "kind": "switch", "management_ip": f"192.0.2.{index}"}
               for index, key in enumerate(("a", "b"), 1)]
    devices[0]["mac_addresses"] = ["00:11:22:33:44:66"]
    devices[1]["mac_addresses"] = ["00:11:22:33:44:55"]
    devices.append({"id": "c", "name": "C", "kind": "server", "mac_addresses": ["00:11:22:33:44:66"]})
    context = {"devices": devices, "links": [{
        "endpoint_a": {"device": "a", "interface": "ge1"}, "endpoint_b": {"device": "b", "interface": "ge1"},
        "relation": "connected_to",
    }]}
    sources = [{"id": index, "name": key, "driver": "snmp_switch", "host": f"192.0.2.{index}", "enabled": 1}
               for index, key in enumerate(("a", "b"), 1)]
    ports = [{"source": key, "name": "ge1", "port_key": "ifindex:1", "if_index": 1,
              "oper_status": "up", "last_seen_at": stamp, "collector_run_id": 7} for key in ("a", "b")]
    ports[0]["rxErrorCounters"] = {"checkedAt": stamp, "ifInErrors": 44, "fcsErrors": 0}
    modes = {"a": {"checkedAt": stamp, "ports": {1: {"port": "ge1", "duplex": "full", "autoNegotiation": True}}}}
    modules = {"a": {"checkedAt": stamp, "ports": {1: {"port": "ge1", "formFactor": "SFP+",
                                                       "opticalPower": {"state": "unavailable"}}}}}
    sample = {"source": "a", "port_key": "ifindex:1", "collector_run_id": 7, "observed_at": stamp,
              "sample_interval_seconds": 300, "in_errors_delta": 2}
    neighbor = {"source": "a", "local_port_key": "ifindex:1", "observed_at": stamp, "collector_run_id": 7,
                "chassis_id": "00:11:22:33:44:55", "port_id": "eth0", "system_name": "Phone",
                "port_id_subtype": "interface_name",
                "management_addresses": ["192.0.2.90"], "system_description": "private"}
    lldp = [neighbor, neighbor.copy(), {**neighbor, "port_id": "eth1"},
            {**neighbor, "chassis_id": "00:11:22:33:44:66", "port_id_subtype": "private"},
            {**neighbor, "port_id": "eth2", "collector_run_id": 6},
            {**neighbor, "port_id": "eth3", "observed_at": (now - timedelta(minutes=1)).isoformat()}]
    hosts = [{"ip": "192.0.2.66", "mac": "00:11:22:33:44:66", "hostname": "workstation", "last_seen_at": stamp},
             {"ip": "192.0.2.66", "mac": "00:11:22:33:44:66", "hostname": "old-name",
              "last_seen_at": (now - timedelta(hours=1)).isoformat()}]
    lldp_status = {"a": {"checkedAt": stamp, "ports": {"ge1": {"admin": "tx_rx", "rxFrames": 0, "txFrames": 21}}},
                   "b": {"checkedAt": (now - timedelta(minutes=6)).isoformat(),
                         "ports": {"ge1": {"admin": "rx_only", "rxFrames": 3}}}}
    graph = build_graph(context, {"sources": sources, "ports": ports, "lldp": lldp, "hosts": hosts,
                                  "lldp_port_status": lldp_status, "port_telemetry": [sample],
                                  "link_modes": modes, "transceivers": modules}, {}, {}, {}, now)
    path = tmp_path / "map.json"
    publish_snapshot(path, graph)
    public = load_infrastructure_map(path, now)
    nodes = {node["id"]: node for node in public["nodes"]}
    assert nodes["a"]["ports"][0]["lldpNeighborCount"] == 3
    assert nodes["a"]["ports"][0]["lldpChassisCount"] == 2
    expected_status = {"checkedAt": stamp, "admin": "tx_rx", "rxFrames": 0, "txFrames": 21}
    assert nodes["a"]["ports"][0]["lldpPort"] == expected_status
    assert "lldpPort" not in nodes["b"]["ports"][0]
    assert "lldpNeighborCount" not in nodes["b"]["ports"][0]
    direct = next(edge for edge in public["links"] if edge["kind"] == "Сетевое соединение")
    assert not direct["confirmed"]
    report = direct["portEvidence"][0]
    assert report["portStates"]["a"]["lldpNeighborCount"] == 3
    assert report["portStates"]["a"]["lldpChassisCount"] == 2
    assert "lldpNeighborCount" not in report["portStates"]["b"]
    details = nodes["a"]["ports"][0]["lldpNeighbors"]
    assert [row["portId"] for row in details] == ["eth0", "eth1", "eth0"]
    assert details[0] == {"chassisId": "00:11:22:33:44:55", "portId": "eth0", "systemName": "Phone",
                          "inventoryDeviceId": "b", "portIdSubtype": "interface_name"}
    assert details[2]["hostName"] == "workstation"
    assert "inventoryDeviceId" not in details[2]
    assert "private" not in json.dumps(details) and "192.0.2.90" not in json.dumps(details)
    pending, = summarize_topology(public)["topologyAudit"]["pending"]
    assert pending["portObservations"]["a"]["lldpPort"] == expected_status
    browser_pair, = load_infrastructure_map(path, now, include_guest_attachments=True)["pendingPortPairs"]
    assert browser_pair["portObservations"]["a"]["lldpPort"] == expected_status
    for key in ("telemetry", "rxErrorCounters", "linkMode", "transceiver"):
        assert browser_pair["portObservations"]["a"][key] == pending["portObservations"]["a"][key]
        assert key not in browser_pair["portObservations"]["b"]
    assert browser_pair["portObservations"]["a"]["telemetry"]["rxErrors"] == 2
    assert "lldpPort" not in browser_pair["portObservations"]["b"]
    assert pending["lldpObservations"] == {"a": {"checkedAt": stamp, "neighbors": details}}
    assert pending["missingPortSides"] == [] and pending["identifiedPeerSides"] == ["a"]
    aged = load_infrastructure_map(path, now + timedelta(hours=1))
    assert all(not {"lldpNeighborCount", "lldpChassisCount", "lldpNeighbors", "lldpPort"} & port.keys()
               for node in aged["nodes"] for port in node["ports"])


def test_direct_link_compares_contemporaneous_port_samples(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    nodes = [{"id": key, "name": key, "kind": "Коммутатор",
              "ports": [{"name": "ge1", "state": "up", "speedBps": 10**9, "checkedAt": stamp}]}
             for key in ("a", "b")]
    report = {"a": "ge1", "b": "ge1", "source": "LLDP · двустороннее", "confirmed": True, "at": stamp}
    link = {"a": "a", "b": "b", "kind": "Сетевое соединение", "source": report["source"],
            "confirmed": True, "observedAt": stamp, "portEvidence": [report]}
    path = tmp_path / "map.json"

    def comparison():
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": nodes, "links": [link]}),
                        encoding="utf-8")
        return load_infrastructure_map(path, now)["links"][0]["portEvidence"][0].get("portComparison")

    assert comparison() == {"state": "both_up", "checkedAt": stamp}
    nodes[1]["ports"][0]["speedBps"] = 100_000_000
    assert comparison()["state"] == "speed_mismatch"
    nodes[1]["ports"][0]["state"] = "down"
    assert comparison()["state"] == "one_down"
    nodes[0]["ports"][0]["state"] = "disabled"
    assert comparison()["state"] == "both_down"
    nodes[1]["ports"][0]["checkedAt"] = (now - timedelta(minutes=3)).isoformat()
    assert comparison() is None
    nodes[1]["ports"][0]["checkedAt"] = stamp
    nodes[1]["ports"][0].update(source="Proxmox", proxmoxActive=True, state="up")
    assert comparison() is None
    nodes[1]["ports"][0].pop("source")
    link["kind"] = "Путь по MAC-таблице"
    assert comparison() is None


def test_live_snmp_sample_compares_ports_without_redating_inventory(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    previous = (now - timedelta(minutes=4)).isoformat()
    switch = {"id": "switch", "name": "Switch", "kind": "Коммутатор", "ports": [
        {"name": "xe1", "state": "up", "speedBps": 10**9, "checkedAt": previous,
         "fdbLearned": {"checkedAt": previous, "learnedMacCount": 3, "partial": False},
         "telemetry": {"checkedAt": previous, "intervalSeconds": 300, "rxBps": 100},
         "linkCheck": {"state": "up", "speedBps": 10**10, "checkedAt": stamp}},
    ]}
    host = {"id": "host", "name": "Host", "kind": "Гипервизор", "ports": [
        {"name": "eth0", "source": "Proxmox · sysfs", "state": "up", "speedBps": 10**10, "checkedAt": stamp},
    ]}
    evidence = {"a": "xe1", "b": "eth0", "source": "GitHub", "confirmed": True}
    edge = {"a": "switch", "b": "host", "kind": "Сетевое соединение", "confirmed": True,
            "portEvidence": [evidence]}
    path = tmp_path / "map.json"

    def read(at):
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": [switch, host], "links": [edge]}),
                        encoding="utf-8")
        graph = load_infrastructure_map(path, at)
        return graph["nodes"][0]["ports"][0], graph["links"][0]["portEvidence"][0]

    port, pair = read(now)
    assert (port["checkedAt"], port["speedBps"]) == (stamp, 10**10)
    assert port["fdbLearned"]["checkedAt"] == previous
    assert port["telemetry"]["checkedAt"] == previous
    assert pair["portComparison"] == {"state": "both_up", "checkedAt": stamp}
    switch["ports"][0]["linkCheck"]["state"] = "down"
    port, pair = read(now)
    assert port["state"] == "down" and port["speedBps"] is None and "telemetry" not in port
    assert pair["portComparison"]["state"] == "one_down"
    port, pair = read(now + timedelta(minutes=6))
    assert port["checkedAt"] == previous and "portComparison" not in pair


def test_live_snmp_poll_rechecks_ifindex_name_for_declared_ports(monkeypatch):
    import asyncio

    from app import infrastructure_collect as collector
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.oids import IF_ADMIN_STATUS, IF_HIGH_SPEED, IF_NAME, IF_OPER_STATUS
    from netctl.snmp.outcomes import SnmpOutcome

    now = datetime.now(timezone.utc)
    names = {5: b"xe1", 6: b"reused-index", 7: b"xe3"}
    calls = []

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, oid):
            calls.append(oid)
            column, index = oid[:-1], oid[-1]
            kind, value = {
                IF_NAME: ("octet_string", names[index]), IF_ADMIN_STATUS: ("integer", 1),
                IF_OPER_STATUS: ("integer", 1), IF_HIGH_SPEED: ("gauge32", 10_000),
            }[column]
            return CapabilityResult("", SnmpOutcome.SUCCESS_WITH_ROWS, (SnmpVarBind(oid, kind, value),))

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda _: Transport())
    links = [
        {"endpoint_a": {"device": "switch", "interface": f"xe{i}"},
         "endpoint_b": {"device": "host", "interface": f"eth{i}"},
         "relation": "connected_to", "state": {"verified": i < 3}}
        for i in (1, 2, 3)
    ]
    context = {"devices": [{"id": "switch", "kind": "switch", "management_ip": "192.0.2.1"}], "links": links}
    network = {
        "sources": [{"name": "observer", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}],
        "ports": [{"source": "observer", "name": f"xe{i}", "if_index": i + 4, "collector_run_id": 1,
                   "last_seen_at": now.isoformat()} for i in (1, 2, 3)],
    }
    pve = {"physicalPorts": {"host": [{"name": f"eth{i}", "source": "Proxmox · sysfs"}
                                    for i in (1, 2, 3)]}}
    asyncio.run(collector._check_declared_switch_ports(context, network, pve, now))
    first, second, third = network["ports"]
    assert first["linkCheck"]["state"] == "up" and first["linkCheck"]["speedBps"] == 10**10
    assert "linkCheck" not in second and third["linkCheck"]["state"] == "up"
    assert calls == [(*column, index) for index in (5, 6, 7)
                     for column in ((IF_NAME,) if index == 6 else (IF_NAME, IF_ADMIN_STATUS, IF_OPER_STATUS, IF_HIGH_SPEED))]


def test_declared_switch_port_checks_cover_unverified_sides_and_exclude_retired_paths(monkeypatch):
    import asyncio

    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    calls = []

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def read(transport, index, name):
        calls.append((index, name))
        return {"state": "up", "speedBps": 10**9}

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda _: Transport())
    monkeypatch.setattr(collector, "read_interface_link", read)
    context = {
        "devices": [
            *({"id": f"s{i}", "kind": "switch", "management_ip": f"192.0.2.{i}"} for i in (1, 2, 3)),
            {"id": "bmc", "kind": "management_controller"},
        ],
        "links": [
            {"relation": "connected_to", "state": {"verified": True},
             "endpoint_a": {"device": "s1", "interface": "Slot0/16"},
             "endpoint_b": {"device": "bmc", "interface": "eth0"}},
            {"relation": "connected_to", "state": {"verified": True},
             "endpoint_a": {"device": "s1", "interface": "Slot0/17"},
             "endpoint_b": {"device": "bmc"}},
            {"relation": "connected_to", "state": {"verified": True},
             "endpoint_a": {"device": "s1", "interface": "Port52"},
             "endpoint_b": {"device": "s2", "interface": "ge21"}},
            {"relation": "connected_to", "state": {"verified": True},
             "endpoint_a": {"device": "s1", "interface": "Slot0/51"},
             "endpoint_b": {"device": "s3", "interface": "ge1"}},
            {"relation": "connected_to", "state": {"verified": False},
             "endpoint_a": {"device": "s1", "interface": "Slot0/15"},
             "endpoint_b": {"device": "s2", "interface": "ge22"}},
            {"relation": "connected_to", "state": {"intent": "absent"},
             "endpoint_a": {"device": "s1", "interface": "Slot0/13"},
             "endpoint_b": {"device": "s2"}},
            {"relation": "connected_to", "state": {}, "vlan": {"mode": "tagged_transit"},
             "endpoint_a": {"device": "s1", "interface": "Slot0/14"},
             "endpoint_b": {"device": "s2"}},
        ],
    }
    network = {
        "sources": [{"name": f"s{i}", "host": f"192.0.2.{i}", "driver": "snmp_switch", "enabled": True}
                    for i in (1, 2, 3)],
        "ports": [{"source": source, "name": name, "port_key": f"ifindex:{index}", "if_index": index,
                   "collector_run_id": 1, "last_seen_at": now.isoformat()}
                  for source, name, index in (("s1", "Slot0/52", 52), ("s2", "ge21", 5021),
                                              ("s1", "Slot0/51", 51), ("s1", "Slot0/15", 15), ("s2", "ge22", 5022),
                                              ("s1", "Slot0/13", 13), ("s1", "Slot0/14", 14),
                                              ("s1", "Slot0/16", 16), ("s1", "Slot0/17", 17))],
    }
    asyncio.run(collector._check_declared_switch_ports(context, network, {}, now))
    assert set(calls) == {(52, "Slot0/52"), (5021, "ge21"), (51, "Slot0/51"),
                          (15, "Slot0/15"), (5022, "ge22"), (16, "Slot0/16")}
    assert sum("linkCheck" in row for row in network["ports"]) == 6


@pytest.mark.parametrize("learned_port", [7, 8])
def test_css_access_link_reports_live_mac_only_on_declared_port(monkeypatch, tmp_path, learned_port):
    import asyncio

    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment, summarize_topology

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    mac, address = "c0:9b:f4:61:4b:cd", "192.0.2.8"

    async def read_link(_, index, name):
        assert (index, name) == (7, "Port7")
        return {"state": "up", "speedBps": 10**9}

    async def read_fdb(_, address):
        assert address == mac
        return learned_port

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda _: Transport())
    monkeypatch.setattr(collector, "read_interface_link", read_link)
    monkeypatch.setattr(collector, "read_learned_fdb_port", read_fdb)
    context = {
        "devices": [{"id": "css", "name": "CSS", "kind": "switch", "management_ip": address},
                    {"id": "pc", "name": "Workstation", "kind": "endpoint", "mac_addresses": [mac.upper()]}],
        "links": [{"relation": "connected_to", "state": {"verified": True}, "vlan": {"id": 20, "mode": "access"},
                   "endpoint_a": {"device": "css", "interface": "Port7"},
                   "endpoint_b": {"device": "pc", "interface": "Ethernet"}}],
    }
    network = {
        "sources": [{"name": "css", "host": address, "driver": "snmp_switch", "enabled": True}],
        "switches": [{"source": "css", "profile_id": "css326", "last_success_at": stamp}],
        "ports": [{"source": "css", "name": "Port7", "port_key": "physical:7", "bridge_port": 7,
                   "if_index": 7, "collector_run_id": 1, "last_seen_at": stamp, "oper_status": "up"}],
    }
    asyncio.run(collector._check_declared_switch_ports(context, network, {}, now))
    collected = datetime.now(timezone.utc)
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(collector.build_graph(context, network, {}, {}, {}, collected)), encoding="utf-8")
    graph = load_infrastructure_map(path, collected)
    edge, = graph["links"]
    assert edge["confirmed"] and edge["portEvidence"][0]["pairEvidence"] == "verified_inventory"
    port = edge["portEvidence"][0]["portStates"]["a"]
    assert port["state"] == "up" and port["speedBps"] == 10**9
    audit = summarize_topology(graph, node_id="css", port_name="port7")["topologyAudit"]
    pair, = audit["inventoryPairs"]
    assert audit["currentPairTotal"] == 0
    browser = load_infrastructure_map(path, collected, include_guest_attachments=True)
    assert browser["inventoryPairs"] == [pair]
    attachment = summarize_guest_attachment(graph, "pc")["attachment"]["physicalHosts"][0]
    peer_port = attachment["connections"][0]["ports"][0]["portStates"]["peer"]
    if learned_port == 7:
        assert port["endpointMac"] == {"deviceId": "pc", "mac": mac, "checkedAt": port["checkedAt"]}
        assert pair["endpointMacObservations"] == {"a": port["endpointMac"]}
        assert peer_port["endpointMac"] == port["endpointMac"]
    else:
        assert "endpointMac" not in port
        assert "endpointMacObservations" not in pair
        assert "endpointMac" not in peer_port
    expired = load_infrastructure_map(path, collected + timedelta(minutes=6))
    assert all("endpointMac" not in port for node in expired["nodes"] for port in node["ports"])
    assert "endpointMacObservations" not in summarize_topology(expired)["topologyAudit"]["inventoryPairs"][0]


def test_proxmox_backup_checks_match_storage_and_guest_and_expire():
    from app.infrastructure_collect import build_graph
    from app.infrastructure_backup import backup_service_checks, read_proxmox_backup
    from app.infrastructure_map import _map_statuses, _public_node, _public_service_check

    now = datetime.now(timezone.utc)
    ended = int((now - timedelta(hours=26)).timestamp())
    recent = int((now - timedelta(hours=2)).timestamp())

    def task(upid, endtime, status="OK"):
        return {"upid": upid, "node": "pve1", "type": "vzdump", "starttime": endtime - 30,
                "endtime": endtime, "status": status}

    backup = task("UPID:pve1:backup", ended)
    other_storage = task("UPID:pve1:other", recent)
    failed = task("UPID:pve1:failed", recent, "job errors")
    tasks = [backup, other_storage, failed]
    logs = {
        "backup": ["INFO: starting new backup job: vzdump 102 --storage pbs",
                   "INFO: Finished Backup of VM 102 (00:00:30)", "TASK OK"],
        "other": ["INFO: starting new backup job: vzdump 102 --storage local",
                  "INFO: Finished Backup of VM 102 (00:00:30)", "TASK OK"],
        "failed": ["INFO: starting new backup job: vzdump 104 --storage pbs",
                   "ERROR: Backup of VM 104 failed - private details", "TASK ERROR: job errors"],
    }

    def get(path):
        if path == "cluster/backup":
            return [{"type": "vzdump", "enabled": 1, "storage": "pbs", "vmid": "102,104,106"}]
        if "?typefilter=vzdump" in path:
            return tasks
        for name, lines in logs.items():
            if f"%3A{name}/log?" in path:
                return [{"t": line} for line in lines]
        raise AssertionError(path)

    def check():
        observation = read_proxmox_backup(get, ["pve1"], "pbs", now)
        return {row["backupVmid"]: row for row in backup_service_checks(observation, {102: 24, 104: 30, 106: 192}, now)}

    results = check()
    assert [results[vm]["reason"] for vm in (102, 104, 106)] == [
        "backup_overdue", "backup_task_failed", "backup_no_result",
    ]
    assert results[102]["backupCompletedAt"] == datetime.fromtimestamp(ended, timezone.utc).isoformat()
    assert "private details" not in json.dumps(results)
    stale = _public_service_check(results[104], now + timedelta(minutes=6))
    assert stale["stale"] and stale["state"] == "unknown"
    graph = build_graph({"devices": [{"id": "pbs", "name": "PBS", "kind": "backup_server"}]}, {}, {},
                        {"cluster": [], "nodes": [], "guests": [], "at": now.isoformat(),
                         "backup": read_proxmox_backup(get, ["pve1"], "pbs", now)},
                        {"proxmox_backup_monitor": {"asset": "pbs", "storage": "pbs",
                                                    "max_age_hours": {"102": 30, "104": 30, "106": 192}}}, now)
    nodes = {node["id"]: _public_node(node, now) for node in graph["nodes"]}
    nodes["pbs"]["reachability"]["state"] = "reachable"
    _map_statuses(nodes, graph["links"])
    assert nodes["proxmox-pbs-backups"]["mapStatus"] == nodes["pbs"]["mapStatus"] == "warn"
    logs["other"].pop()
    assert check()[102]["reason"] == "backup_no_result"
    logs["other"] = ["INFO: starting new backup job: vzdump 102 --storage pbs", "TASK ERROR: setup failed"]
    assert check()[102]["reason"] == "backup_no_result"


def test_guest_backup_coverage_is_scoped_and_failures_apply_to_the_right_guest(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import (
        _map_statuses, _public_node, load_infrastructure_map, summarize_guest_attachment, summarize_services,
    )

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    pve = {"cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "at": stamp,
           "guests": [{"vmid": vmid, "node": "pve1", "name": f"vm-{vmid}", "type": "qemu", "status": "running"}
                      for vmid in (102, 103, 104)],
           "backup": {"guests": {102, 104}, "checkedAt": stamp,
                      "results": {102: {"successful": False, "completedAt": now},
                                  104: {"successful": True, "completedAt": now}}}}
    bindings = {"proxmox_backup_monitor": {"asset": "pbs", "storage": "pbs",
                                           "max_age_hours": {"102": 30, "104": 30}}}
    context = {"devices": [{"id": "pbs", "name": "PBS", "kind": "backup_server"}]}

    def read(at=now):
        graph = build_graph(context, {}, {}, pve, bindings, now)
        nodes = {row["id"]: _public_node(row, at) for row in graph["nodes"]}
        for vmid in (102, 103, 104):
            nodes[f"pve-guest:{vmid}"]["reachability"]["state"] = "reachable"
        _map_statuses(nodes, graph["links"])
        return [nodes[f"pve-guest:{vmid}"] for vmid in (102, 103, 104)]

    failed, outside, healthy = read()
    assert failed["backupCoverage"] == {"storage": "pbs", "serviceId": "proxmox-pbs-backups",
                                        "state": "scheduled", "checkedAt": stamp, "stale": False}
    assert failed["mapStatus"] == "warn"
    assert failed["serviceChecks"][0]["reason"] == "backup_task_failed"
    assert outside["backupCoverage"]["state"] == "not_scheduled" and outside["serviceChecks"] == []
    assert outside["mapStatus"] == healthy["mapStatus"] == "ok"
    pve["backup"]["incomplete"] = True
    assert read()[1]["backupCoverage"]["state"] == "unknown"
    expired = read(now + timedelta(minutes=6))[0]
    assert expired["backupCoverage"]["stale"] and expired["backupCoverage"]["state"] == "unknown"
    assert expired["mapStatus"] == "unknown"

    path = tmp_path / "infrastructure.json"

    def read_scope():
        snapshot = build_graph(context, {}, {}, pve, bindings, now)
        path.write_text(json.dumps(snapshot), encoding="utf-8")
        graph = load_infrastructure_map(path)
        node = next(node for node in graph["nodes"] if node["id"] == "proxmox-pbs-backups")
        audit = next(row for row in summarize_services(graph)["serviceAudit"]["services"] if row["id"] == node["id"])
        assert audit["backupScope"] == node["backupScope"]
        assert audit["status"] == node["mapStatus"]
        service = summarize_guest_attachment(graph, node["id"])["attachment"]
        assert service["backupScope"] == node["backupScope"]
        guest = summarize_guest_attachment(graph, "pve-guest:103")["attachment"]
        assert guest["backupCoverage"]["state"] == next(
            row["backupCoverage"]["state"] for row in graph["nodes"] if row["id"] == "pve-guest:103"
        )
        graph["links"].append({"a": "pve-guest:103", "b": node["id"], "kind": "Размещение",
                               "confirmed": True, "portEvidence": []})
        hosted = summarize_guest_attachment(graph, node["id"])["attachment"]["guests"]
        assert hosted[0]["backupCoverage"] == guest["backupCoverage"]
        graph["links"].pop()
        pbs = summarize_guest_attachment(graph, "pbs")["attachment"]
        backup = next(row for row in pbs["services"] if row["node"]["id"] == node["id"])
        assert backup["backupScope"] == node["backupScope"]
        return node["backupScope"], node["mapStatus"]

    pve["backup"]["results"][102]["successful"] = True
    pve["backup"].pop("incomplete")
    scope, status = read_scope()
    assert status == "warn"
    assert scope["running"] == {"total": 3, "scheduled": 2, "notScheduled": 1, "unknown": 0}
    assert scope["runningGaps"] == [{"id": "pve-guest:103", "name": "vm-103", "vmid": 103,
                                     "state": "not_scheduled"}]
    pve["guests"][1]["status"] = "stopped"
    scope, status = read_scope()
    assert status == "ok"
    assert scope["notScheduled"] == 1 and scope["running"]["notScheduled"] == 0
    assert scope["runningGaps"] == []
    pve["guests"][1]["status"] = "running"
    pve["backup"]["incomplete"] = True
    scope, status = read_scope()
    assert status == "unknown"
    assert scope["running"] == {"total": 3, "scheduled": 2, "notScheduled": 0, "unknown": 1}
    assert scope["runningGaps"][0]["state"] == "unknown"
    pve["backup"]["checkedAt"] = (now - timedelta(minutes=6)).isoformat()
    assert read_scope()[0]["unknown"] == 3


def test_proxmox_port_observer_verifies_target_and_only_updates_inventory_ports(tmp_path, monkeypatch):
    from app import infrastructure_port_ssh as observer
    from app.infrastructure_map import _public_port

    now = datetime.now(timezone.utc)
    nodes = [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "offline"}]
    ports = [{"name": "eth0", "state": "unknown", "source": "Proxmox", "proxmoxActive": True,
              "checkedAt": now.isoformat()}, {"name": "eth1", "state": "unknown", "source": "Proxmox"}]
    pve = {"nodes": nodes, "physicalPorts": {"pve1": ports}}
    context = {"devices": [
        {"id": "pve1", "kind": "hypervisor", "management_ip": "192.0.2.1"},
        {"id": "pve2", "kind": "hypervisor", "management_ip": "192.0.2.2"},
    ], "links": [{"relation": "connected_to", "state": {"verified": True},
                   "endpoint_a": {"device": "switch", "interface": "xe3"},
                   "endpoint_b": {"device": "pve1", "interface": "eth0"},
                   "vlans": {"untagged": [1], "tagged": [20]}}]}
    for name in ("pve-port-ssh-key", "pve-port-known-hosts"):
        (tmp_path / name).touch()
    calls = []
    payload = {"hostname": "pve2", "ports": {"eth0": {"state": "up", "speedMbps": 1000,
                                                  "vlanRanges": [[1, 1, "untagged", True], [2, 4094, "tagged", False]]},
                                         "extra0": {"state": "disabled"}}}

    def run(args, **options):
        calls.append(args)
        return observer.subprocess.CompletedProcess(args, 0, stdout=json.dumps(payload).encode())

    monkeypatch.setattr(observer.subprocess, "run", run)
    observer.collect_proxmox_port_states(context, pve, tmp_path)
    assert ports[0]["state"] == "unknown"
    payload["hostname"] = "pve1"
    observer.collect_proxmox_port_states(context, pve, tmp_path)
    assert len(calls) == 2 and all(args[-1] == "ui-vpn-ports@192.0.2.1" for args in calls)
    assert all("StrictHostKeyChecking=yes" in args for args in calls)
    assert [row["name"] for row in ports] == ["eth0", "eth1"]
    public = _public_port(ports[0], datetime.now(timezone.utc))
    assert (public["source"], public["state"], public["speedBps"], public["proxmoxActive"]) == (
        "Proxmox · sysfs", "up", 10**9, True,
    )
    assert public["vlanMemberships"] == {"checkedAt": public["checkedAt"], "vlans": [
        {"id": 1, "egress": "untagged", "pvid": True}, {"id": 20, "egress": "tagged", "pvid": False},
    ]}
    assert ports[1]["state"] == "unknown"
    payload["ports"]["eth0"]["vlanRanges"].append([20, 20, "untagged", False])
    observer.collect_proxmox_port_states(context, pve, tmp_path)
    assert "vlanMemberships" not in _public_port(ports[0], datetime.now(timezone.utc))


def test_snr_root_bridge_uses_fresh_port_mapping_without_confirming_a_pair(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    root = {"id": "router", "kind": "router", "name": "Root router",
            "observed_state": {"rstp": {"bridge_id": "32768.2C:C8:1B:9C:31:EA"}}}
    port = {"source": "snr", "name": "ge23", "bridge_port": 23, "port_key": "ifindex:5023",
            "collector_run_id": 1, "last_seen_at": stamp, "oper_status": "up"}
    state = {"source": "snr", "root_port_key": "physical:23", "root_bridge_mac": "2C:C8:1B:9C:31:EA",
             "observed_at": stamp}
    network = {"sources": [{"name": "snr", "driver": "snmp_switch", "enabled": True}],
               "switches": [{"source": "snr", "profile_id": "snr"}], "ports": [port], "stp": [state]}
    path = tmp_path / "infrastructure.json"

    def read():
        graph = build_graph({"devices": [root]}, network, {}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        public = load_infrastructure_map(path, now)
        assert public["links"] == []
        return summarize_topology(public)["topologyAudit"]["stpRoots"]

    assert read() == [{"id": "observer:snr", "name": "snr", "localPort": "ge23",
                       "rootBridgeMac": "2c:c8:1b:9c:31:ea", "rootDeviceId": "router", "checkedAt": stamp}]
    network["ports"].append({**port, "name": "ge24", "port_key": "ifindex:5024"})
    assert read() == []
    network["ports"].pop()
    port["last_seen_at"] = (now - timedelta(seconds=1)).isoformat()
    assert read() == []
    port["last_seen_at"] = stamp
    state["observed_at"] = (now - timedelta(minutes=6)).isoformat()
    assert read() == []


def test_css_root_port_stp_projects_only_fresh_unambiguous_observations():
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _public_node

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    network = {
        "sources": [{"name": "css", "driver": "snmp_switch", "host": "192.0.2.2", "enabled": True}],
        "ports": [{"source": "css", "name": "Port13", "bridge_port": 13, "port_key": "physical:13",
                   "collector_run_id": 1, "last_seen_at": stamp, "oper_status": "up"}],
        "stp_root_paths": {"css": {"rootPortNumber": 13, "designatedBridgeMac": "2c:c8:1b:9c:31:ea",
                                    "designatedPortId": "80:03", "checkedAt": stamp}},
    }

    def read(devices=()):
        graph = build_graph({"devices": devices}, network, {}, {}, {}, now)
        assert graph["links"] == []
        return _public_node(next(node for node in graph["nodes"] if node["name"] == "css"), now)

    assert read()["stpRootPath"] == {
        "localPort": "Port13", "designatedBridgeMac": "2c:c8:1b:9c:31:ea",
        "designatedPortId": "80:03", "checkedAt": stamp,
    }
    bridge = {"id": "root", "kind": "switch", "name": "Root",
              "management_ip": "192.0.2.3",
              "observed_state": {"rstp": {"bridge_id": "32768.2C:C8:1B:9C:31:EA"}}}
    assert read([bridge])["stpRootPath"]["bridgeDeviceId"] == "root"
    assert "bridgeDeviceId" not in read([bridge, {**bridge, "id": "duplicate"}])["stpRootPath"]
    network["ports"].append({**network["ports"][0], "name": "Port14"})
    assert "stpRootPath" not in read()
    network["ports"].pop()
    bridge_id = "80:00:2c:c8:1b:9c:31:ea"
    network["stp_root_paths"]["css"]["designatedBridgeId"] = bridge_id
    network["sources"].append({"name": "snr", "driver": "snmp_switch", "host": "192.0.2.3", "enabled": True})
    network["ports"].append({"source": "snr", "name": "ge21", "if_index": 5021, "port_key": "ifindex:5021",
                             "collector_run_id": 1, "last_seen_at": stamp, "oper_status": "up"})
    network["stp_designated_ports"] = {"snr": {"ports": {(bridge_id, "80:03"): 5021}, "checkedAt": stamp}}
    assert read([bridge])["stpRootPath"]["designatedPortName"] == "ge21"
    assert read([bridge])["stpRootPath"]["designatedPortCheckedAt"] == stamp
    network["stp_root_paths"]["css"]["designatedBridgeId"] = "90:00:2c:c8:1b:9c:31:ea"
    assert "designatedPortName" not in read([bridge])["stpRootPath"]
    network["stp_root_paths"]["css"]["checkedAt"] = (now - timedelta(minutes=6)).isoformat()
    assert "stpRootPath" not in read()


def test_css_root_port_stp_rejects_root_port_change_during_poll():
    import asyncio

    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome
    from netctl.snmp.stp import read_stp_root_path

    class Transport:
        def __init__(self, last_port):
            self.values = iter([13, bytes.fromhex("80002cc81b9c31ea"), bytes.fromhex("8003"), last_port])

        async def get(self, oid):
            value = next(self.values)
            kind = "octet_string" if isinstance(value, bytes) else "integer"
            return CapabilityResult("", SnmpOutcome.SUCCESS_WITH_ROWS, (SnmpVarBind(oid, kind, value),))

    assert asyncio.run(read_stp_root_path(Transport(13))) == {
        "rootPortNumber": 13, "designatedBridgeMac": "2c:c8:1b:9c:31:ea", "designatedPortId": "80:03",
        "designatedBridgeId": "80:00:2c:c8:1b:9c:31:ea",
    }
    assert asyncio.run(read_stp_root_path(Transport(5))) == {}


def test_switch_link_mode_uses_negotiated_duplex_and_current_interface_identity(tmp_path):
    import asyncio

    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map
    from netctl.snmp.interfaces import read_switch_link_modes
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome

    class Transport:
        async def walk(self, oid, *, capability):
            samples = {
                "link_mode_names": ("octet_string", {5014: b"ge14", 5025: b"xe1", 5028: b"xe4"}),
                "link_mode_duplex": ("integer", {5014: 3, 5025: 3, 5028: 2}),
                "link_mode_snr": ("integer", {5014: 0, 5025: 25, 5028: 6}),
            }
            kind, rows = samples[capability]
            return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS,
                                    tuple(SnmpVarBind((*oid, index), kind, value) for index, value in rows.items()))

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    modes = asyncio.run(read_switch_link_modes(Transport(), snr=True))
    assert modes[5014] == {"port": "ge14", "duplex": "full", "autoNegotiation": True}
    assert modes[5025]["autoNegotiation"] is False
    assert modes[5028]["duplex"] == "half"
    context = {"devices": [{"id": "switch", "name": "Switch", "kind": "switch", "management_ip": "192.0.2.1"}]}
    network = {
        "sources": [{"name": "snr", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}],
        "ports": [{"source": "snr", "collector_run_id": 1, "if_index": index, "port_key": label,
                   "name": label, "oper_status": state, "last_seen_at": stamp}
                  for index, label, state in [(5014, "ge14", "up"), (5025, "renamed", "up"), (5028, "xe4", "down")]],
        "link_modes": {"snr": {"checkedAt": stamp, "ports": modes}},
    }
    path = tmp_path / "map.json"
    path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
    node, = load_infrastructure_map(path, now)["nodes"]
    ports = {p["name"]: p for p in node["ports"]}
    assert ports["ge14"]["linkMode"] == {"checkedAt": stamp, "duplex": "full", "autoNegotiation": True}
    assert "linkMode" not in ports["renamed"]
    assert "linkMode" not in ports["xe4"]
    expired, = load_infrastructure_map(path, now + timedelta(minutes=6))["nodes"]
    assert all("linkMode" not in p for p in expired["ports"])


def test_bridge_stp_state_is_fresh_and_independent_of_physical_link(tmp_path):
    import asyncio

    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology
    from netctl.snmp import interfaces, oids
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome

    class Transport:
        async def walk(self, oid, *, capability):
            kind, samples = {
                oids.DOT1D_BASE_PORT_IFINDEX: ("integer", {15: 5015, 22: 5022}),
                oids.DOT1D_STP_PORT_STATE: ("integer", {15: 1, 22: 5, 5015: 6}),
                oids.DOT1D_STP_PORT_ENABLE: ("integer", {15: 1, 22: 2}),
                oids.IF_NAME: ("octet_string", {5015: b"Slot0/15", 5022: b"previous"}),
            }[oid]
            return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS,
                                    tuple(SnmpVarBind((*oid, index), kind, value) for index, value in samples.items()))

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    samples = asyncio.run(interfaces.read_bridge_stp_ports(Transport()))
    assert samples[5015] == {"port": "Slot0/15", "state": "disabled", "enabled": True}
    assert 15 not in samples
    context = {"devices": [{"id": key, "name": key, "kind": "switch", "management_ip": ip}
                           for key, ip in (("dgs", "192.0.2.1"), ("peer", "192.0.2.2"))],
               "links": [{"relation": "connected_to", "endpoint_a": {"device": "dgs", "interface": "Slot0/15"},
                          "endpoint_b": {"device": "peer", "interface": "Port1"}, "state": {"verified": False}}]}
    network = {"sources": [{"name": "dgs", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}],
               "ports": [{"source": "dgs", "collector_run_id": 1, "if_index": index, "port_key": label,
                          "name": label, "oper_status": "up", "last_seen_at": stamp}
                         for index, label in [(5015, "Slot0/15"), (5022, "Slot0/22")]],
               "stp_ports": {"dgs": {"checkedAt": stamp, "ports": samples}}}
    path = tmp_path / "map.json"
    path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")

    graph = load_infrastructure_map(path, now)
    switch = next(node for node in graph["nodes"] if node["id"] == "dgs")
    ports = {port["name"]: port for port in switch["ports"]}
    observed = {"checkedAt": stamp, "state": "disabled", "enabled": True}
    assert ports["Slot0/15"]["state"] == "up" and ports["Slot0/15"]["stpPort"] == observed
    assert "stpPort" not in ports["Slot0/22"]
    audit = summarize_topology(graph)["topologyAudit"]
    assert audit["pending"][0]["portObservations"]["a"]["stpPort"] == observed
    expired = load_infrastructure_map(path, now + timedelta(minutes=6))
    assert all("stpPort" not in port for node in expired["nodes"] for port in node["ports"])


def test_snr_transceiver_inventory_uses_the_current_interface_identity(tmp_path):
    import asyncio

    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome
    from netctl.snmp.interfaces import read_snr_transceivers

    class Transport:
        async def walk(self, oid, *, capability):
            assert oid[:-1] == (1, 3, 6, 1, 4, 1, 57206, 7, 100, 30, 3, 1)
            readings = {
                2: [b"xe1", b"xe2", b"xe3"],
                4: [b"OEM", b"OEM", b"NULL"],
                5: [b"SFP+", b"SFP+", b"NULL"],
                6: [b"UNKNOWN", b"10GBASE-SR", b"NULL"],
                7: [b"10300Mbit/s", b"10300Mbit/s", b"NULL"],
            }
            rows = tuple(SnmpVarBind((*oid, index), "octet_string", value)
                         for index, value in enumerate(readings[oid[-1]], 5025))
            return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS, rows)

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    modules = asyncio.run(read_snr_transceivers(Transport()))
    assert set(modules) == {5025, 5026}
    assert modules[5026]["media"] == "10GBASE-SR"
    modules[5025]["opticalPower"] = {"state": "unavailable", "rxDbm": 8.16}
    context = {"devices": [{"id": "switch", "name": "Switch", "kind": "switch", "management_ip": "192.0.2.1"}]}
    network = {
        "sources": [{"name": "snr", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}],
        "ports": [{"source": "snr", "collector_run_id": 1, "if_index": index, "port_key": label,
                   "name": label, "oper_status": "up", "last_seen_at": stamp}
                  for index, label in [(5025, "xe1"), (5026, "xe4")]],
        "transceivers": {"snr": {"checkedAt": stamp, "ports": modules}},
    }
    path = tmp_path / "map.json"
    path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
    node, = load_infrastructure_map(path, now)["nodes"]
    first, second = node["ports"]
    assert first["transceiver"] == {"checkedAt": stamp, "vendor": "OEM", "formFactor": "SFP+",
                                    "nominalBps": 10300000000, "opticalPower": {"state": "unavailable"}}
    assert "transceiver" not in second
    expired, = load_infrastructure_map(path, now + timedelta(minutes=6))["nodes"]
    assert "transceiver" not in expired["ports"][0]


def test_switch_lldp_port_state_checks_local_port_identity_and_preserves_zero():
    import asyncio

    from netctl.snmp.interfaces import read_switch_lldp_port_state
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome

    class Transport:
        async def walk(self, oid, *, capability):
            readings = {
                (1, 6, 1, 2): [("integer", 3), ("integer", 2), ("integer", 4), ("integer", 1)],
                (3, 7, 1, 2): [("integer", 5), ("integer", 1), ("integer", 1), ("integer", 7)],
                (3, 7, 1, 3): [("octet_string", b"xe1"), ("octet_string", b"2"),
                               ("octet_string", b"99"), ("octet_string", b"unbound")],
                (2, 7, 1, 4): [("integer", 0), ("counter32", 104), ("integer", 5), ("integer", 1)],
                (2, 6, 1, 2): [("integer", 450), ("counter32", 2**32), ("integer", 5), ("integer", 1)],
            }
            assert oid[:7] == (1, 0, 8802, 1, 1, 2, 1)
            rows = tuple(SnmpVarBind((*oid, i), value_type, value)
                         for i, (value_type, value) in enumerate(readings[oid[7:]], 1))
            return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS, rows)

    assert asyncio.run(read_switch_lldp_port_state(Transport())) == {
        "xe1": {"admin": "tx_rx", "rxFrames": 0, "txFrames": 450},
    }
    assert asyncio.run(read_switch_lldp_port_state(Transport(), dgs=True)) == {
        "xe1": {"admin": "tx_rx", "rxFrames": 0, "txFrames": 450},
        "slot0/2": {"admin": "rx_only", "rxFrames": 104},
    }


def test_lldp_port_deltas_require_continuous_samples_from_the_same_port(tmp_path):
    from copy import deepcopy

    from app.infrastructure_collect import _add_lldp_port_deltas
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    earlier = (now - timedelta(seconds=120)).isoformat()
    stamp = now.isoformat()
    base = {"id": "snr", "name": "SNR", "kind": "Коммутатор", "ports": [
        {"name": "xe1", "key": "ifindex:5025", "state": "up", "checkedAt": earlier,
         "lldpPort": {"admin": "tx_rx", "checkedAt": earlier, "sourceId": 1,
                      "sysUptimeTicks": 100000, "rxFrames": 0, "txFrames": 190}},
    ]}
    previous = {"nodes": [base]}
    graph = {"schema": 1, "snapshotAt": stamp, "nodes": [deepcopy(base)]}
    port = graph["nodes"][0]["ports"][0]
    port["checkedAt"] = stamp
    port["lldpPort"].update(checkedAt=stamp, sysUptimeTicks=112000, txFrames=194)
    expected = {"startedAt": earlier, "intervalSeconds": 120, "rxFrames": 0, "txFrames": 4}

    def read(change=None):
        current = deepcopy(graph)
        sample = current["nodes"][0]["ports"][0]["lldpPort"]
        if change:
            sample.update(change)
        _add_lldp_port_deltas(current, previous)
        path = tmp_path / "map.json"
        path.write_text(json.dumps(current), encoding="utf-8")
        return load_infrastructure_map(path, now)["nodes"][0]["ports"][0]["lldpPort"]

    assert read() == {"checkedAt": stamp, "admin": "tx_rx", "rxFrames": 0, "txFrames": 194, "delta": expected}
    for change in ({"sysUptimeTicks": 4000}, {"sysUptimeTicks": 100000}, {"txFrames": 189},
                   {"admin": "tx_only"}, {"sourceId": 2}):
        assert "delta" not in read(change)
    port["state"] = "down"
    assert "delta" not in read()


def test_snr_transceiver_power_requires_ordered_alarm_limits():
    import asyncio

    from netctl.snmp.interfaces import read_snr_transceiver_power
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.outcomes import SnmpOutcome

    root = (1, 3, 6, 1, 4, 1, 57206, 7, 100, 30, 1, 1)

    class Transport:
        async def walk(self, oid, *, capability):
            assert oid == root
            readings = {
                5025: (5025, b"8.16", b"8.16", b"8.16", b"8.16", b"8.16", b"8.16"),
                5026: (5026, b"-17.25", b"0.5", b"-16", b"-2.75", b"0.5", b"-8"),
                5027: (5027, b"-", b"0.5", b"-16", b"-2.75", b"0.5", b"-8"),
                5028: (5030, b"-17", b"0.5", b"-16", b"-2.75", b"0.5", b"-8"),
            }
            rows = tuple(SnmpVarBind((*root, column, index), "integer" if column == 1 else "octet_string", value)
                         for index, sample in readings.items()
                         for column, value in zip((1, 17, 18, 19, 22, 23, 24), sample))
            return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS, rows)

    assert asyncio.run(read_snr_transceiver_power(Transport(), {5025, 5026, 5027, 5028})) == {
        5025: {"state": "unavailable"},
        5026: {"state": "available", "rxDbm": -17.25, "txDbm": -2.75},
        5027: {"state": "available", "txDbm": -2.75},
    }


def test_stp_designated_ports_match_the_local_bridge_and_reject_ambiguous_ids():
    import asyncio

    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.oids import DOT1D_BASE_BRIDGE_ADDRESS, DOT1D_STP_PORT_DESIGNATED_BRIDGE, DOT1D_STP_PORT_DESIGNATED_PORT
    from netctl.snmp.outcomes import SnmpOutcome
    from netctl.snmp.stp import read_stp_designated_ports

    mac = bytes.fromhex("f8f082d65929")
    local_bridge = bytes.fromhex("8000") + mac

    class Transport:
        async def get(self, oid):
            assert oid == DOT1D_BASE_BRIDGE_ADDRESS
            return CapabilityResult("", SnmpOutcome.SUCCESS_WITH_ROWS, (SnmpVarBind(oid, "octet_string", mac),))

        async def walk(self, oid, *, capability):
            samples = {
                DOT1D_STP_PORT_DESIGNATED_BRIDGE: {
                    5021: local_bridge, 5022: b"\x80\x00" + bytes.fromhex("2cc81b9c31ea"),
                    5023: local_bridge, 5024: local_bridge,
                },
                DOT1D_STP_PORT_DESIGNATED_PORT: {
                    5021: bytes.fromhex("839d"), 5022: bytes.fromhex("839d"),
                    5023: bytes.fromhex("839f"), 5024: bytes.fromhex("839f"),
                },
            }
            rows = tuple(SnmpVarBind((*oid, idx), "octet_string", value) for idx, value in samples[oid].items())
            return CapabilityResult(capability, SnmpOutcome.SUCCESS_WITH_ROWS, rows)

    assert asyncio.run(read_stp_designated_ports(Transport())) == {("80:00:f8:f0:82:d6:59:29", "83:9d"): 5021}


def test_stp_observer_uses_recent_detected_snr_profile_without_a_hint(monkeypatch):
    import asyncio

    from app import infrastructure_collect as collector

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def read(_):
        return {("80:00:f8:f0:82:d6:59:29", "83:9d"): 5021}

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda source: Transport())
    monkeypatch.setattr(collector, "read_stp_designated_ports", read)
    now = datetime.now(timezone.utc)
    source = {"name": "snr", "driver": "snmp_switch", "enabled": True}
    status = {"source": "snr", "profile_id": "snr", "last_success_at": now.isoformat()}
    roots, designated = asyncio.run(collector._collect_stp_observations([source], [status], now))
    assert not roots and designated["snr"]["ports"] == {("80:00:f8:f0:82:d6:59:29", "83:9d"): 5021}
    status["last_success_at"] = (now - timedelta(hours=1)).isoformat()
    assert asyncio.run(collector._collect_stp_observations([source], [status], now)) == ({}, {})


def test_vlan_audit_keeps_port_configuration_and_learned_mac_evidence_distinct(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    expected = {"tagged": [20], "untagged": [1]}
    configured = [{"id": 1, "egress": "untagged", "pvid": True}, {"id": 20, "egress": "tagged", "pvid": False}]
    port_a = {"name": "ge23", "state": "up", "checkedAt": stamp,
              "vlanMemberships": {"checkedAt": stamp, "vlans": configured}}
    port_b = {"name": "Gi1/0/47", "state": "up", "checkedAt": stamp,
              "vlanCollection": {"state": "empty", "checkedAt": stamp},
              "fdbVlans": {"checkedAt": stamp, "vlans": [{"id": 20, "learnedMacCount": 2}]}}
    snapshot = {"schema": 1, "snapshotAt": stamp, "nodes": [
        {"id": "a", "name": "A", "kind": "Коммутатор", "ports": [port_a]},
        {"id": "b", "name": "B", "kind": "Коммутатор", "ports": [port_b]},
    ], "links": [{"a": "a", "b": "b", "kind": "Сетевое соединение", "source": "GitHub", "confirmed": True,
                  "portEvidence": [{"a": "ge23", "b": "Gi1/0/47", "source": "GitHub", "confirmed": True,
                                    "expectedVlans": expected}]}]}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(snapshot), encoding="utf-8")
        graph = load_infrastructure_map(path, when)
        audit, = summarize_topology(graph)["topologyAudit"]["vlanAudits"]
        for node_id, port_name in (("a", "GE23"), ("b", "gigabitEthernet 1/0/47"), ("b", None)):
            scoped = summarize_topology(graph, node_id=node_id, port_name=port_name)["topologyAudit"]
            assert scoped["vlanAudits"] == [audit]
        assert summarize_topology(graph, node_id="a", port_name="ge24")["topologyAudit"]["vlanAudits"] == []
        return audit["vlans"]

    native, tagged = read()
    assert native["state"] == tagged["state"] == "unconfirmed"
    assert tagged["ports"] == {
        "a": {"egress": "tagged", "membershipCheckedAt": stamp},
        "b": {"learnedMacCount": 2, "fdbCheckedAt": stamp,
              "vlanCollection": {"state": "empty", "checkedAt": stamp}},
    }
    assert "b" not in read(now + timedelta(minutes=11))[1]["ports"]
    port_b["vlanMemberships"] = {"checkedAt": stamp, "vlans": configured}
    assert all(vlan["state"] == "confirmed" for vlan in read())
    port_b["vlanMemberships"]["vlans"] = [{"id": 20, "egress": "untagged", "pvid": False}]
    assert read()[1]["state"] == "mismatch"


def test_topology_port_alerts_require_confirmed_pairs_and_fresh_states(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    old = (now - timedelta(minutes=26)).isoformat()
    a = {"id": "a", "name": "Switch A", "kind": "Коммутатор", "ports": [
        {"name": "ge1", "key": "ifindex:5001", "state": "up", "speedBps": 10**9, "checkedAt": stamp},
    ], "properties": {"Источник сбора": "snr-test"}}
    b = {"id": "b", "name": "Switch B", "kind": "Коммутатор", "ports": [
        {"name": "ge2", "key": "physical:2", "state": "up", "speedBps": 10**8, "checkedAt": stamp},
    ], "properties": {"Источник сбора": "peer-test"}}
    inventory = {"a": "ge1", "b": "ge2", "source": "GitHub", "confirmed": True}
    observed = {**inventory, "source": "LLDP · двустороннее", "at": stamp}
    edge = {"a": "a", "b": "b", "kind": "Сетевое соединение", "confirmed": True,
            "portEvidence": [inventory, observed]}
    path = tmp_path / "map.json"

    def read():
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": [a, b], "links": [edge]}),
                        encoding="utf-8")
        graph = load_infrastructure_map(path, now)
        audit = summarize_topology(graph)["topologyAudit"]
        alerts = graph["links"][0].get("portAlerts", [])
        assert audit["portAlertTotal"] == len(alerts)
        assert audit["portAlerts"] == [
            {"a": "a", "b": "b", "nameA": "Switch A", "nameB": "Switch B", **alert} for alert in alerts
        ]
        scoped = summarize_topology(graph, node_id="a", port_name="GE1")["topologyAudit"]
        assert scoped["portAlertTotal"] == len(alerts)
        assert scoped["portAlerts"] == audit["portAlerts"]
        if edge["kind"] == "Сетевое соединение" and observed["confirmed"] and b["ports"][0]["checkedAt"] == stamp:
            pair, = scoped["currentPairs"]
            assert pair["portHistory"] == {
                side: {"source": source, "interface": key}
                for side, node, source, key in (
                    ("a", a, "snr-test", "ifindex:5001"),
                    ("b", b, "peer-test", "physical:2"),
                ) if node["ports"][0]["checkedAt"] == stamp
            }
            browser = load_infrastructure_map(path, now, include_guest_attachments=True)
            assert browser["currentPortPairs"] == scoped["currentPairs"]
            expected_state = alerts[0]["state"] if alerts else "both_up"
            assert pair["linkHealth"]["state"] == expected_state
            assert pair["linkHealth"]["checkedAt"] == stamp
            assert audit["currentPairLinkCounts"][expected_state] == 1
            assert scoped["currentPairMeasurementGaps"] == ([
                {"a": "a", "b": "b", "portA": "ge1", "portB": "ge2", "missingSides": ["a"]},
            ] if expected_state == "port_down" else [])
            assert pair["portStates"]["b"]["state"] == b["ports"][0]["state"]
            expected_speed = b["ports"][0]["speedBps"] if b["ports"][0]["state"] == "up" else None
            assert pair["portStates"]["b"]["speedBps"] == expected_speed
            assert ("a" in pair["portStates"]) == (a["ports"][0]["checkedAt"] == stamp)
        elif scoped["currentPairs"]:
            assert "portStates" not in scoped["currentPairs"][0]
            assert scoped["currentPairs"][0]["linkHealth"] == {"state": "unconfirmed"}
            assert audit["currentPairMeasurementGaps"] == [
                {"a": "a", "b": "b", "portA": "ge1", "portB": "ge2", "missingSides": ["a", "b"]},
            ]
        browser = load_infrastructure_map(path, now, include_guest_attachments=True)
        assert browser["currentPairMeasurementGapTotal"] == audit["currentPairMeasurementGapTotal"]
        assert summarize_topology(graph, node_id="a", port_name="ge99")["topologyAudit"]["portAlerts"] == []
        return alerts

    assert read() == [{"portA": "ge1", "portB": "ge2", "state": "speed_mismatch", "checkedAt": stamp}]
    b["ports"][0]["speedBps"] = 10**9
    assert read() == []
    b["ports"][0].update(state="down")
    assert read() == [{"portA": "ge1", "portB": "ge2", "state": "one_down", "checkedAt": stamp}]
    a["ports"][0].update(checkedAt=old)
    assert read() == [{"portA": "ge1", "portB": "ge2", "state": "port_down",
                       "downSides": ["b"], "checkedAt": stamp}]
    b["ports"][0].update(checkedAt=old)
    assert read() == []
    b["ports"][0].update(checkedAt=stamp)
    edge["kind"] = "Путь по MAC-таблице"
    assert read() == []
    edge["kind"] = "Сетевое соединение"
    inventory["confirmed"] = observed["confirmed"] = False
    assert read() == []


def test_slot_port_alias_requires_matching_snmp_ifindex():
    from app.infrastructure_map import _public_node, index_port_states

    now = datetime.now(timezone.utc)
    port = {"name": "Slot0/52", "key": "ifindex:52", "state": "up",
            "speedBps": 10**9, "checkedAt": now.isoformat()}
    node = _public_node({"ports": [port]}, now)
    assert node["ports"][0]["aliases"] == ["Port52"]
    assert index_port_states([port], now)["port52"]["speedBps"] == 10**9
    for changed in ({**port, "key": "ifindex:51"}, {**port, "name": "Slot1/52"}):
        assert "port52" not in index_port_states([changed], now)


def test_reciprocal_switch_management_macs_verify_path_without_proving_direct_link(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": key, "name": key, "kind": "switch", "management_ip": f"192.0.2.{i}"}
                           for i, key in enumerate(("core", "access"), 1)],
               "links": [{"id": "core-to-access", "relation": "connected_to", "state": {"verified": False},
                          "endpoint_a": {"device": "core", "interface": "Gi1/0/18"},
                          "endpoint_b": {"device": "access", "interface": "Port5"}}]}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access"), 1)]
    ports = [
        {"source": "core", "port_key": "ifindex:49170", "name": "gigabitEthernet 1/0/18",
         "oper_status": "up", "last_seen_at": at},
        {"source": "access", "port_key": "physical:5", "name": "p5_uplink_IT_TP",
         "oper_status": "up", "last_seen_at": at},
        {"source": "access", "port_key": "physical:7", "name": "Port7",
         "oper_status": "up", "last_seen_at": at},
    ]
    sightings = [
        {"source_id": 1, "peer_source_id": 2, "port_key": "ifindex:49170", "observed_at": at},
        {"source_id": 2, "peer_source_id": 1, "port_key": "physical:5", "observed_at": at},
    ]

    mac = "02:00:00:00:00:07"
    sample = {"source": "core", "at": at, "macs": [mac],
              "remote": {"source": "access", "readings": [{"mac": mac, "name": "Port7", "at": at}]}}

    def paths(when=now):
        graph = build_graph(context, {"sources": sources, "ports": ports, "switch_management_fdb": sightings,
                                     "downstream_fdb": {"core-to-access": sample}},
                            {}, {}, {"downstream_mac_links": ["core-to-access"]}, now)
        path = tmp_path / "snapshot.json"
        path.write_text(json.dumps(graph), encoding="utf-8")
        graph = load_infrastructure_map(path, when)
        assert not next(e for e in graph["links"] if e["kind"] == "Сетевое соединение")["confirmed"]
        access = next(node for node in graph["nodes"] if node["id"] == "access")
        assert access["ports"][0]["aliases"] == ["Port5"]
        paths = [e for e in graph["links"] if e["kind"] == "Путь по MAC-таблице"]
        if any(path["confirmed"] for path in paths):
            assert access["downstream"]["basis"] == "reciprocal_mac"
            device, = access["downstream"]["devices"]
            assert device["switchPort"]["name"] == "Port7"
        else:
            assert "downstream" not in access
        return paths

    path, = paths()
    assert path["confirmed"]
    assert [(p["a"], p["b"], p["at"]) for p in path["portEvidence"]] == [
        ("gigabitEthernet 1/0/18", "p5_uplink_IT_TP", at),
    ]
    expired, = paths(now + timedelta(hours=1))
    assert not expired["confirmed"] and not expired["portEvidence"][0]["confirmed"]
    sightings.append({**sightings[0], "port_key": "ifindex:999"})
    assert not paths()
    sightings.pop()
    sightings[1]["observed_at"] = (now - timedelta(hours=1)).isoformat()
    assert not paths()
    sightings[1]["observed_at"] = at
    ports[1]["oper_status"] = "down"
    assert not paths()


def test_verified_switch_ports_require_fresh_bidirectional_fdb_and_live_ports(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    earlier = (now - timedelta(minutes=1)).isoformat()
    devices = [{"id": key, "name": key, "kind": "switch"} for key in ("core", "access", "other")]
    declared = {"relation": "connected_to", "state": {"verified": True},
                "endpoint_a": {"device": "core", "interface": "ge22"},
                "endpoint_b": {"device": "access", "interface": "Port24"}}
    sources = [{"id": i, "name": key, "driver": "snmp_switch", "driver_options": {"intent_stable_id": key}}
               for i, key in enumerate(("core", "access"), 1)]
    ports = [{"source": source, "port_key": name, "name": name, "oper_status": "up", "last_seen_at": at}
             for source, name in (("core", "ge22"), ("access", "Port24"))]
    ports[1].update(port_key="physical:24", name="uplink-to-core")
    one_way = {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1, "port_key": "ge22"},
               "endpoint_b": {"source_id": 2}, "observed_at": at}
    reverse = {"evidence_type": "fdb_management_mac", "endpoint_a": {"source_id": 1},
               "endpoint_b": {"source_id": 2, "port_key": "physical:24"}, "observed_at": earlier}
    evidence = [one_way, reverse]
    network = {"sources": sources, "ports": ports, "links": [
        {"source_a_id": 1, "source_b_id": 2, "state": "confirmed", "evidence": evidence},
    ]}
    path = tmp_path / "graph.json"

    def paired(when=now):
        graph = build_graph({"devices": devices, "links": [declared]}, network, {}, {}, {}, when)
        path.write_text(json.dumps(graph), encoding="utf-8")
        link = next(edge for edge in load_infrastructure_map(path, when)["links"] if {edge["a"], edge["b"]} == {"core", "access"})
        configured = next(p for p in link["portEvidence"] if p["source"] == "GitHub")
        assert configured["pairEvidence"] == "verified_inventory"
        return [p for p in link["portEvidence"] if p["source"] == "SNMP · двусторонний FDB"]

    report, = paired()
    assert {key: report[key] for key in ("a", "b", "at", "confirmed")} == {
        "a": "ge22", "b": "uplink-to-core", "at": earlier, "confirmed": True,
    }
    assert report["pairEvidence"] == "current"
    assert {side: port["state"] for side, port in report["portStates"].items()} == {"a": "up", "b": "up"}
    assert not paired(now + timedelta(hours=1))
    evidence.pop()
    assert not paired()
    evidence.append(reverse)
    evidence.append({**one_way, "endpoint_a": {"source_id": 1, "port_key": "ge23"}})
    assert not paired()
    evidence.pop()
    ports[1]["oper_status"] = "down"
    assert not paired()
    ports[1]["oper_status"] = "up"
    network["lldp"] = [{"source": "core", "local_port_key": "ge22", "system_name": "other",
                        "port_id": "ether1", "port_id_subtype": "interface_name", "observed_at": at}]
    assert not paired()


def test_reciprocal_lldp_confirms_numeric_alias_and_unnamed_peer():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    a_mac, b_mac = "02:00:00:00:00:01", "02:00:00:00:00:02"
    sources = [{"id": i, "name": name, "host": ip, "enabled": 1, "driver": "snmp_switch"}
               for i, name, ip in ((1, "dgs", "192.0.2.16"), (2, "snr", "192.0.2.254"))]
    ports = [{"source": source, "port_key": f"ifindex:{index}", "if_index": index, "name": label,
              "mac": mac, "oper_status": "up", "last_seen_at": at}
             for source, index, label, mac in (("dgs", 52, "Slot0/52", None), ("snr", 5021, "ge21", b_mac))]
    lldp = [
        {"source": "dgs", "local_port_key": "ifindex:52", "chassis_id": b_mac, "chassis_id_subtype": "mac_address", "port_id": "ge21",
         "port_id_subtype": "interface_name", "observed_at": at},
        {"source": "snr", "local_port_key": "ifindex:5021", "chassis_id": a_mac, "chassis_id_subtype": "mac_address", "port_id": "52",
         "port_id_subtype": "interface_alias", "observed_at": at},
    ]
    network = {"sources": sources, "ports": ports, "lldp": lldp,
               "arp": [{"ip": "192.0.2.16", "mac": a_mac, "last_seen_at": at}]}

    def pairs():
        graph = build_graph({}, network, {}, {}, {}, now)
        return [(p["a"], p["b"]) for e in graph["links"] for p in e.get("portEvidence", [])
                if p["confirmed"] and p["source"] == "LLDP · двустороннее"]

    assert pairs() == [("Slot0/52", "ge21")]
    lldp[1]["port_id"] = "53"
    assert pairs() == []
    lldp[1]["port_id"] = "52"
    lldp.append({**lldp[0], "chassis_id": "02:00:00:00:00:99"})
    assert pairs() == []
    lldp.pop()
    lldp[1]["observed_at"] = (now - timedelta(hours=1)).isoformat()
    assert pairs() == []


def test_lldp_multiple_neighbors_on_one_port_do_not_confirm_direct_links():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    devices = [{"id": name, "name": name, "kind": "router"} for name in ("one", "two")]
    network = {"sources": [{"id": 1, "name": "switch", "driver": "snmp_switch"}], "lldp": [
        {"source": "switch", "system_name": name, "local_port_key": "48",
         "chassis_id": f"02:00:00:00:00:0{index}", "observed_at": now.isoformat()}
        for index, name in enumerate(("one", "two"), 1)
    ]}
    graph = build_graph({"devices": devices}, network, {}, {}, {}, now)
    assert len(graph["links"]) == 2
    assert all(not link["confirmed"] and not link["portEvidence"][0]["confirmed"] for link in graph["links"])


def test_shared_lldp_ports_publish_paths_and_require_live_port_and_unique_chassis(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    first, second, unexpected = (f"02:00:00:00:00:0{i}" for i in (1, 2, 3))
    context = {"devices": [{"id": "switch", "name": "switch", "kind": "switch"},
                           {"id": "one", "name": "one", "kind": "switch", "mac_addresses": [first]},
                           {"id": "two", "name": "two", "kind": "router", "mac_addresses": [second]}],
               "links": [{"relation": "connected_to", "state": {"verified": False,
                          "observed": "lldp_neighbor_on_shared_or_intermediate_l2_path"},
                          "endpoint_a": {"device": "switch", "interface": "Gi1/0/48"},
                          "endpoint_b": {"device": "one", "interface": "bridge/ether3"},
                          "evidence": [{"source": "docs/shared-ports.yaml", "observed_at": "2026-08-13"}]}]}
    port = {"source": "switch", "port_key": "ifindex:48", "name": "gigabitEthernet 1/0/48",
            "oper_status": "up", "last_seen_at": at, "collector_run_id": 1}
    rows = [{"source": "switch", "system_name": name, "local_port_key": "ifindex:48",
             "chassis_id": chassis, "port_id": "bridge/ether3", "port_id_subtype": "interface_name",
             "observed_at": at, "collector_run_id": 1} for name, chassis in (("one", first), ("two", unexpected))]
    network = {"sources": [{"id": 1, "name": "switch", "driver": "snmp_switch",
                            "driver_options": {"intent_stable_id": "switch"}}], "ports": [port], "lldp": rows}
    path = tmp_path / "snapshot.json"
    rows[0]["system_description"] = "SWT-1318P Software Version V1.2.3 build 210419"
    rows[1]["system_description"] = "MikroTik RouterOS 7.19.6 (stable) cAPGi-5HaxD2HaxD"

    def snapshot(when=now, **options):
        graph = build_graph(context, network, {}, {}, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return load_infrastructure_map(path, when, **options)

    def read(when=now):
        return {e["b"]: e for e in snapshot(when)["links"] if e["a"] == "switch"}

    def firmware(when=now):
        return {n["id"]: n["firmware"] for n in snapshot(when)["nodes"] if "firmware" in n}

    links = read()
    assert all(e["kind"] == "Путь через общий порт" for e in links.values())
    assert links["one"]["confirmed"] and not links["two"]["confirmed"]
    proof = next(p for p in links["one"]["portEvidence"] if p["confirmed"])
    assert (proof["a"], proof["b"], proof["portStates"]["a"]["state"]) == ("gigabitEthernet 1/0/48", "", "up")
    assert proof["lldpPeers"] == {"a": [{
        "localPort": proof["a"], "checkedAt": at, "chassisId": first,
        "portId": "bridge/ether3", "portIdSubtype": "interface_name",
    }]}
    assert "pairEvidence" not in proof
    audit = summarize_topology(snapshot())["topologyAudit"]
    row, = audit["pending"]
    assert row["sharedPort"] is True
    assert "shared_switch_port" in row["confirmationGaps"]
    assert (row["basis"], row["a"], row["portA"], row["b"], row["portB"]) == (
        "shared_lldp", "switch", proof["a"], "one", "",
    )
    assert row["lldpPeers"] == proof["lldpPeers"]
    inventory_peer_ports = [{
        "port": "bridge/ether3",
        "inventorySources": [{"path": "docs/shared-ports.yaml", "observedOn": "2026-08-13"}],
    }]
    assert row["inventoryPeerPorts"] == inventory_peer_ports
    card, = snapshot(include_guest_attachments=True)["pendingPortPairs"]
    assert card["portB"] == "" and card["inventoryPeerPorts"] == inventory_peer_ports
    assert not any(audit["directLinks"].values())
    provenance = {"checkedAt": at, "observerId": "switch", "observerPort": "gigabitEthernet 1/0/48", "source": "LLDP"}
    swt_firmware = {**provenance, "product": "SWT-1318P", "version": "1.2.3", "build": "210419"}
    assert firmware() == {"one": swt_firmware}
    assert firmware(now + timedelta(minutes=11)) == {}
    rows.append({**rows[0], "system_description": "SWT-1318P Software Version V1.2.4 build 210420"})
    assert firmware() == {}
    rows.pop()
    assert not read(now + timedelta(hours=1))["one"]["confirmed"]
    address = "192.0.2.22"
    rows[1]["management_addresses"] = [address]
    network["arp"] = [{"ip": address, "mac": unexpected, "last_seen_at": at}]
    network["hosts"] = [{"ip": address, "mac": unexpected, "last_seen_at": at}]
    neighbors = [{"identity": "two", "address": address, "mac": unexpected, "last_seen_at": at}]
    network["router_neighbors"] = neighbors
    assert read()["two"]["confirmed"]
    rows_by_peer = {row["b"]: row for row in summarize_topology(snapshot())["topologyAudit"]["pending"]}
    assert set(rows_by_peer) == {"one", "two"}
    assert rows_by_peer["two"]["lldpPeers"]["a"][0]["chassisId"] == unexpected
    assert rows_by_peer["two"]["portB"] == ""
    assert "inventoryPeerPorts" not in rows_by_peer["two"]
    combined = snapshot()
    declaration = next(link for link in combined["links"] if link["b"] == "one")
    declaration["confirmed"] = False
    declaration["portEvidence"] = [report for report in declaration["portEvidence"] if report["source"] == "GitHub"]
    combined["links"].append({"a": "switch", "b": "one", "kind": "Путь по MAC-таблице", "confirmed": True,
                              "portEvidence": [{"a": proof["a"], "b": "", "source": "netctl FDB", "at": at,
                                                "confirmed": True, "learnedEndpoint": {
                                                    "switchId": "switch", "deviceId": "one", "mac": first}}]})
    combined["links"].append({"a": "switch", "b": "two", "kind": "Путь по MAC-таблице", "confirmed": True,
                              "portEvidence": [{"a": proof["a"], "b": "", "source": "netctl FDB", "at": at,
                                                "confirmed": True, "learnedEndpoint": {
                                                    "switchId": "switch", "deviceId": "two", "mac": unexpected}}]})
    combined_audit = summarize_topology(combined, node_id="switch", port_name="Gi1/0/48")["topologyAudit"]
    fdb_only = next(row for row in combined_audit["pending"] if row["b"] == "one")
    assert [reading["source"] for reading in fdb_only["observedPaths"]] == ["netctl FDB"]
    assert fdb_only["portB"] == "" and fdb_only["inventoryPeerPorts"] == inventory_peer_ports
    candidate, = fdb_only["unconfirmedLldpCandidates"]
    assert (candidate["portId"], candidate["chassisId"], candidate["checkedAt"]) == ("bridge/ether3", first, at)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_declaration = next(link for link in raw["links"] if link["b"] == "one")
    raw_declaration["confirmed"] = False
    raw_declaration["portEvidence"] = [report for report in raw_declaration["portEvidence"] if report["source"] == "GitHub"]
    raw["links"].extend(combined["links"][-2:])
    path.write_text(json.dumps(raw), encoding="utf-8")
    browser = load_infrastructure_map(path, now, include_guest_attachments=True)
    browser_row = next(row for row in browser["pendingPortPairs"] if row["b"] == "one")
    assert browser_row["unconfirmedLldpCandidates"] == [candidate]
    assert browser_row["portB"] == "" and browser["currentPortPairTotal"] == 0
    combined_row = next(row for row in combined_audit["pending"] if row["b"] == "two")
    assert [reading["source"] for reading in combined_row["observedPaths"]] == ["netctl FDB", "LLDP · общий порт"]
    assert combined_row["lldpPeers"] == rows_by_peer["two"]["lldpPeers"]
    assert combined_row["portB"] == "" and combined_audit["currentPairTotal"] == 0
    assert "unconfirmedLldpCandidates" not in combined_row
    shared_port, = combined_audit["sharedPorts"]
    assert shared_port == {"switchId": "switch", "port": proof["a"], "peerTotal": 2,
                           "peerIds": ["one", "two"], "liveLldpPeerIds": ["two"],
                           "liveFdbPeerIds": ["one", "two"], "peerObservations": [
                               {"id": "one", "name": "one", "fdbCheckedAt": at, "lldpCandidateCheckedAt": at},
                               {"id": "two", "name": "two", "fdbCheckedAt": at, "lldpCheckedAt": at},
                           ]}
    assert firmware()["two"] == {**provenance, "product": "RouterOS", "version": "7.19.6"}
    neighbors[0]["last_seen_at"] = (now - timedelta(hours=1)).isoformat()
    assert not read()["two"]["confirmed"]
    assert [row["b"] for row in summarize_topology(snapshot())["topologyAudit"]["pending"]] == ["one"]
    assert "two" not in firmware()
    neighbors[0]["last_seen_at"] = at
    neighbors.append({**neighbors[0], "mac": first})
    assert not read()["two"]["confirmed"]
    neighbors.pop()
    context["devices"][1]["management_ip"] = address
    assert not read()["two"]["confirmed"]
    context["devices"][1].pop("management_ip")
    rows.append({**rows[0], "local_port_key": "ifindex:47"})
    assert not read()["one"]["confirmed"]
    assert "one" not in firmware()
    rows.pop()
    rows.pop()
    assert read()["one"]["kind"] == "Путь через общий порт"
    port["oper_status"] = "down"
    assert not read()["one"]["confirmed"]
    assert firmware() == {}
    port["oper_status"] = "up"
    context["links"].clear()
    assert read()["one"]["kind"] == "Сетевое соединение"
    assert firmware() == {"one": swt_firmware}


def test_fdb_ports_require_fresh_unambiguous_device_identity(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    fresh = (now - timedelta(minutes=1)).isoformat()
    old = (now - timedelta(hours=1)).isoformat()
    first, duplicate, stale, virtual = [f"02:00:00:00:00:0{n}" for n in range(1, 5)]
    devices = [{"id": name, "name": name, "kind": "server", **identity} for name, identity in [
        ("server", {"management_ip": "192.0.2.4"}),
        ("duplicate-a", {"mac_addresses": [duplicate]}),
        ("duplicate-b", {"mac_addresses": [duplicate]}),
        ("stale", {"mac_addresses": [stale]}),
        ("guest", {"mac_addresses": [virtual]}),
        ("hypervisor", {}),
    ]]
    network = {
        "sources": [{"id": 5, "name": "switch", "driver": "snmp_switch"}],
        "ports": [{"source": "switch", "port_key": "1/1", "name": "Gi1/1"}],
        "hosts": [{"ip": "192.0.2.4", "mac": first, "last_seen_at": fresh}],
        "attachments": [{"source_id": 5, "port_key": "1/1", "mac": mac,
                         "observed_at": observed, "vlan_id": 100}
                        for mac, observed in [(first, fresh), (duplicate, fresh), (stale, old), (virtual, fresh)]],
    }
    placement = {"endpoint_a": {"device": "guest"}, "endpoint_b": {"device": "hypervisor"},
                 "relation": "virtualized_on"}
    graph = build_graph({"devices": devices, "links": [placement]}, network, {}, {}, {}, now)
    path = tmp_path / "infrastructure.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    link, = (link for link in load_infrastructure_map(path, now)["links"] if link["source"] == "netctl FDB")
    assert (link["a"], link["b"], link["confirmed"]) == ("observer:switch", "server", True)
    assert link["portEvidence"] == [{"a": "Gi1/1", "b": "", "source": "netctl FDB",
                                     "at": fresh, "confirmed": True, "vlan": 100}]
    assert first not in path.read_text(encoding="utf-8")


def test_matching_fdb_attachment_adds_evidence_and_supplemental_ip_check(monkeypatch, tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map
    from app import infrastructure_service_probes as probes

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, address = "02:00:00:00:00:14", "192.0.2.14"
    context = {"devices": [
        {"id": "pc", "name": "PC", "kind": "endpoint", "mac_addresses": [mac],
         "observed_ipv4_addresses": [address]},
        {"id": "sw", "name": "CSS", "kind": "switch", "management_ip": "192.0.2.254"},
    ], "links": [{"endpoint_a": {"device": "pc", "interface": "Ethernet"},
                  "endpoint_b": {"device": "sw", "interface": "Port7"},
                  "relation": "connected_to", "state": {"verified": True}}]}
    network = {"sources": [{"id": 1, "name": "css", "host": "192.0.2.254", "driver": "snmp_switch"}],
               "ports": [{"source": "css", "port_key": "Port7", "name": "Port7",
                          "oper_status": "up", "last_seen_at": at}],
               "attachments": [{"source_id": 1, "port_key": "Port7", "mac": mac, "observed_at": at, "vlan_id": 20}]}
    bindings = {"asset_ip_checks": {"pc": address}}
    configured = {"pc": [{"type": "icmp", "ip": address}]}
    monkeypatch.setattr(probes, "_icmp_check", lambda ip: {"state": "reachable"})

    def build():
        graph = build_graph(context, network, {}, {}, bindings, now)
        probes.apply_service_probes(graph["nodes"], configured)
        return graph, next(n for n in graph["nodes"] if n["id"] == "pc")

    graph, node = build()
    link, = graph["links"]
    assert link["confirmed"] and link["source"] == "GitHub"
    assert [(p["a"], p["b"]) for p in link["portEvidence"]] == [("Ethernet", "Port7"), ("", "Port7")]
    assert node["serviceChecks"][0]["state"] == "reachable"
    assert "reachability" not in node
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps(graph), encoding="utf-8")
    public = load_infrastructure_map(snapshot, datetime.now(timezone.utc))
    assert public["links"][0]["portEvidence"][-1]["portStates"]["b"]["state"] == "up"
    endpoint = next(node for node in public["nodes"] if node["id"] == "pc")
    assert endpoint["mapStatus"] == "unknown"
    assert endpoint["serviceChecks"][0]["reason"] == "icmp_identity_unconfirmed"
    network["attachments"][0]["port_key"] = "Port8"
    graph, node = build()
    assert len(graph["links"]) == 2
    skipped, = node["serviceChecks"]
    assert skipped["skipped"] and skipped["supplemental"] and skipped["reason"] == "probe_target_unconfirmed"


def test_lacp_confirms_only_ports_whose_partner_matches_fresh_arp(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, address = "02:00:00:00:00:14", "192.0.2.14"
    context = {"devices": [
        {"id": "pbs", "name": "PBS", "kind": "backup_server", "management_ip": address},
        {"id": "sw", "name": "SNR", "kind": "switch", "management_ip": "192.0.2.254"},
    ], "links": [
        {"endpoint_a": {"device": "sw", "interface": port}, "endpoint_b": {"device": "pbs", "interface": alias},
         "relation": "connected_to"} for port, alias in (("po1", "data_lag"), ("xe1", "backup_10g"))
    ]}
    network = {
        "sources": [{"id": 1, "name": "snr", "host": "192.0.2.254", "driver": "snmp_switch"}],
        "arp": [{"ip": address, "mac": mac, "last_seen_at": at}],
        "ports": [{"source": "snr", "port_key": name, "name": name, "oper_status": "up",
                   "speed_bps": speed, "last_seen_at": at} for name, speed in (("po1", 2*10**9), ("ge6", 10**9))],
        "lacp": [{"source": "snr", "asset": "pbs", "aggregate": "po1", "expected": 2, "at": at,
                  "members": [{"port": "ge6", "partner_port": 1, "mac": mac},
                              {"port": "ge7", "partner_port": 2, "mac": "02:00:00:00:00:99"}]}],
    }
    path = tmp_path / "map.json"

    def link(stamp=now):
        graph = build_graph(context, network, {}, {}, {
            "asset_services": {"pbs-ssh": {"asset": "pbs", "label": "PBS SSH", "require_network_identity": True}},
            "lacp_links": [{"source": "snr", "asset": "pbs", "aggregate": "po1", "members": ["ge6", "ge7"]}],
        }, now)
        ssh = next(node for node in graph["nodes"] if node["id"] == "pbs-ssh")
        verified = len(network["arp"]) == 1
        assert ssh["probeTargetIP"] == (address if verified else None)
        assert ssh.get("probeTargetIdentityAt") == (at if verified else None)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(e for e in load_infrastructure_map(path, stamp)["links"] if {e["a"], e["b"]} == {"sw", "pbs"})

    result = link()
    assert result["confirmed"] and result["source"] == "SNMP LACP + ARP"
    assert [(p["a"], p["b"]) for p in result["portEvidence"] if p["confirmed"]] == [("po1 / ge6", "LACP 1")]
    member = next(p for p in result["portEvidence"] if p["confirmed"])
    assert "pairEvidence" not in member
    assert member["portStates"]["a"]["name"] == "ge6"
    assert member["portStates"]["a"]["speedBps"] == 10**9
    assert "b" not in member["portStates"] and "portComparison" not in member
    assert {key: member["lacp"][key] for key in ("side", "aggregate", "member", "partnerPort")} == {
        "side": "a", "aggregate": "po1", "member": "ge6", "partnerPort": 1,
    }
    assert member["lacp"]["aggregateState"]["speedBps"] == 2*10**9
    expired = link(now + timedelta(hours=1))
    assert not expired["confirmed"] and all("lacp" not in p for p in expired["portEvidence"])
    network["arp"].append({**network["arp"][0], "mac": "02:00:00:00:00:98"})
    assert not link()["confirmed"]
    assert mac not in path.read_text(encoding="utf-8")


def test_lacp_health_warns_on_explicit_link_failure_and_expires_port_evidence(tmp_path, monkeypatch):
    from app.infrastructure_collect import build_graph, _refresh_lacp_peer_arp
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment, summarize_topology

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:14"
    devices = [{"id": "pbs", "name": "PBS", "kind": "backup_server", "management_ip": "192.0.2.14"},
               {"id": "snr", "name": "SNR", "kind": "switch", "management_ip": "192.0.2.254"}]
    bindings = {"lacp_links": [{"source": "switch", "asset": "pbs", "aggregate": "po1", "members": ["ge6", "ge7"]}]}
    sources = [{"id": 1, "name": "switch", "enabled": True, "driver": "snmp_switch", "host": "192.0.2.254"}]
    ports = [{"source": "switch", "port_key": name, "name": name, "oper_status": "up", "last_seen_at": at,
              "speed_bps": 10**9 if name != "po1" else 2 * 10**9}
             for name in ("ge6", "ge7", "po1")]
    report = {**bindings["lacp_links"][0], "expected": 2, "at": at, "members": [
        {"port": "ge6", "partner_port": 1, "mac": mac}, {"port": "ge7", "partner_port": 2, "mac": mac}]}
    network = {"sources": sources, "ports": ports, "lacp": [report],
               "arp": [{"ip": "192.0.2.14", "mac": mac, "last_seen_at": at}]}
    path = tmp_path / "map.json"

    def read(stamp=now):
        context = {"devices": devices, "links": [{"endpoint_a": {"device": "snr", "interface": "po1"},
                    "endpoint_b": {"device": "pbs", "interface": "bond0"}, "relation": "connected_to"}],
                   "services": [{"id": "pbs-web", "name": "PBS Web", "device": "pbs"}]}
        graph = build_graph(context, network, {}, {}, bindings, now)
        next(node for node in graph["nodes"] if node["id"] == "pbs")["reachability"] = {
            "state": "reachable", "source": "netctl", "method": "ICMP", "checkedAt": at}
        next(node for node in graph["nodes"] if node["id"] == "pbs-web")["reachability"] = {
            "state": "reachable", "source": "UI_VPN", "method": "HTTPS", "checkedAt": at}
        next(node for node in graph["nodes"] if node["id"] == "pbs-web")["serviceChecks"] = [
            {"state": "reachable", "source": "UI_VPN", "method": "HTTPS", "checkedAt": at,
             "target": address, "port": 8007} for address in ("192.0.2.14", "192.0.2.15")
        ]
        path.write_text(json.dumps(graph), encoding="utf-8")
        node = next(node for node in load_infrastructure_map(path, stamp)["nodes"] if node["id"] == "pbs")
        return node["mapStatus"], node["lacpHealth"][0]

    color, health = read()
    assert (color, health["status"]) == ("ok", "ok")
    assert [member["partnerPort"] for member in health["members"]] == [1, 2]
    assert [member["partnerInterfaceState"] for member in health["members"]] == ["unconfirmed"] * 2
    assert [member["speedBps"] for member in health["members"]] == [10**9] * 2
    assert [member["linkCheckedAt"] for member in health["members"]] == [at] * 2
    assert health["aggregateLink"] == {"state": "up", "checkedAt": at, "speedBps": 2 * 10**9}

    def service_paths(stamp=now):
        snapshot = load_infrastructure_map(path, stamp, include_guest_attachments=True)
        paths = summarize_guest_attachment(snapshot, "pbs-web")["attachment"]["servicePaths"]
        assert snapshot["servicePaths"].get("pbs-web", []) == paths
        return paths

    probe, = service_paths()
    assert probe["target"] == "192.0.2.14" and probe["port"] == 8007
    switch = next(node for node in load_infrastructure_map(path, now)["nodes"] if node["id"] == "snr")
    aggregate_state = next(port for port in switch["ports"] if port["name"] == "po1")
    assert probe["lacpAttachment"] == {
        "switchId": "snr", "aggregate": "po1", "checkedAt": at, "source": "SNMP LACP + ARP",
        "members": health["members"], "aggregateState": aggregate_state,
    }
    assert "physicalPair" not in probe

    def service_host(stamp=now):
        snapshot = load_infrastructure_map(path, stamp)
        host, = summarize_guest_attachment(snapshot, "pbs-web")["attachment"]["physicalHosts"]
        return host

    host = service_host()
    assert host["lacpHealth"] == [health]
    assert all("pairEvidence" not in row for connection in host["connections"] for row in connection["ports"]
               if "lacp" in row)
    members = [row["lacp"] for connection in host["connections"] for row in connection["ports"] if "lacp" in row]
    assert len(members) == 2
    assert all(member["aggregateState"] == probe["lacpAttachment"]["aggregateState"] for member in members)

    def lacp_gaps(stamp=now):
        audit = summarize_topology(load_infrastructure_map(path, stamp))["topologyAudit"]
        assert audit["lacpPartnerInterfaceGapTotal"] == len(audit["lacpPartnerInterfaceGaps"])
        browser = load_infrastructure_map(path, stamp, include_guest_attachments=True)
        assert browser["lacpPartnerInterfaceGapTotal"] == audit["lacpPartnerInterfaceGapTotal"]
        assert browser["lacpPartnerInterfaceGaps"] == audit["lacpPartnerInterfaceGaps"]
        port_graph = load_infrastructure_map(path, stamp, include_port_pairs=True)
        assert port_graph["lacpPartnerInterfaceGaps"] == audit["lacpPartnerInterfaceGaps"]
        selected = summarize_topology(port_graph, node_id="snr", port_name="GE6")["topologyAudit"]
        assert selected["lacpPartnerInterfaceGaps"] == [
            row for row in audit["lacpPartnerInterfaceGaps"] if row["switchPort"] == "ge6"
        ]
        assert selected["lacpPartnerInterfaceGapTotal"] == len(selected["lacpPartnerInterfaceGaps"])
        aggregate = summarize_topology(port_graph, node_id="snr", port_name="po1")["topologyAudit"]
        assert aggregate["lacpPartnerInterfaceGaps"] == audit["lacpPartnerInterfaceGaps"]
        assert aggregate["lacpHealth"] == selected["lacpHealth"] == audit["lacpHealth"]
        assert summarize_topology(port_graph, node_id="pbs")["topologyAudit"]["lacpHealth"] == audit["lacpHealth"]
        assert summarize_topology(port_graph, node_id="snr", port_name="ge99")["topologyAudit"]["lacpHealth"] == []
        return audit["lacpPartnerInterfaceGaps"]

    assert lacp_gaps() == [{"id": "pbs", "name": "PBS", "switchId": "snr", "aggregate": "po1",
                           "switchPort": port, "partnerPort": partner, "checkedAt": at}
                          for port, partner in (("ge6", 1), ("ge7", 2))]
    assert lacp_gaps(now + timedelta(minutes=6)) == []
    expired_graph = load_infrastructure_map(path, now + timedelta(minutes=6))
    expired_link, = [edge for edge in expired_graph["links"] if edge["source"] == "SNMP LACP + ARP"]
    assert not expired_link["confirmed"]
    assert all(not port["confirmed"] and "lacp" not in port for port in expired_link["portEvidence"])

    def service_ports():
        graph = load_infrastructure_map(path, now, include_guest_attachments=True)
        return [(row["port"], row["services"][0]["basis"]) for row in graph["servicePorts"].get("snr", [])]

    assert service_ports() == [("ge6", ["host_lacp"]), ("ge7", ["host_lacp"]), ("po1", ["host_lacp"])]
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    snapshot["nodes"].append({"id": "proxmox-pbs-backups", "name": "Backups", "kind": "Сервис", "serviceChecks": [
        {"method": "Копия Proxmox", "source": "Proxmox", "checkedAt": stamp, "state": state,
         "required": True, "backupVmid": vmid, "backupMaxAgeHours": 30}
        for vmid, stamp, state in ((100, at, "reachable"), (101, at, "unreachable"),
                                  (102, (now - timedelta(hours=1)).isoformat(), "reachable"))
    ]})
    snapshot["links"].append({"a": "pbs", "b": "proxmox-pbs-backups", "kind": "Размещение", "confirmed": True})
    for vmid, state in ((100, "scheduled"), (101, "not_scheduled"), (102, "unknown")):
        snapshot["nodes"].append({"id": f"vm-{vmid}", "name": f"VM {vmid}", "kind": "Виртуальная машина",
                                  "guest": True, "vmid": vmid, "backupCoverage": {
                                      "storage": "pbs", "state": state, "checkedAt": at,
                                  }})
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    projected = load_infrastructure_map(path, now, include_service_ports=True)["servicePorts"]["snr"]
    for port in projected:
        backup = next(service for service in port["services"] if service["id"] == "proxmox-pbs-backups")
        assert backup["backupChecks"] == {"passed": 1, "failed": 1, "unconfirmed": 1}
        assert backup["backupScope"] == {"storage": "pbs", "total": 3, "scheduled": 1,
                                         "notScheduled": 1, "unknown": 1,
                                         "running": {"total": 0, "scheduled": 0, "notScheduled": 0, "unknown": 0},
                                         "runningGaps": []}
        assert "probeEndpoints" not in backup
    network["arp"][0]["last_seen_at"] = (now - timedelta(minutes=6)).isoformat()
    assert read()[0] == "ok"
    network["arp"][0]["last_seen_at"] = (now - timedelta(minutes=9)).isoformat()
    assert read()[0] == "unknown"
    network["arp"][0].update(source="router", interface="bridge-lan")
    calls = []

    def probe(sources, source, interface, expected_mac, *, address):
        calls.append((source, interface, expected_mac, address))
        return {"state": "reachable", "checkedAt": at}

    monkeypatch.setattr("app.infrastructure_collect._router_layer2_observation", probe)
    _refresh_lacp_peer_arp({"devices": devices}, network, now)
    assert calls == [("router", "bridge-lan", mac, "192.0.2.14")]
    assert read()[0] == "ok" and service_ports() == [
        ("ge6", ["host_lacp"]), ("ge7", ["host_lacp"]), ("po1", ["host_lacp"]),
    ]
    assert network["arp"][0]["last_seen_at"] == (now - timedelta(minutes=9)).isoformat()
    report.pop("partnerArp")
    network["arp"].append({**network["arp"][0], "mac": "02:00:00:00:00:13"})
    _refresh_lacp_peer_arp({"devices": devices}, network, now)
    assert len(calls) == 1 and read()[0] == "unknown"
    network["arp"].pop()
    network["arp"][0]["last_seen_at"] = at
    report["members"].pop()
    assert read()[0] == "unknown"
    ports[1]["oper_status"] = "down"
    color, health = read()
    assert (color, health["status"]) == ("warn", "warn")
    assert health["members"][1] == {"name": "ge7", "status": "down", "checkedAt": at}
    assert service_paths()[0]["lacpAttachment"]["members"] == [health["members"][0]]
    assert service_host()["lacpHealth"] == [health]
    assert [gap["switchPort"] for gap in lacp_gaps()] == ["ge6"]
    assert service_ports() == [("ge6", ["host_lacp"]), ("po1", ["host_lacp"])]
    ports[1]["oper_status"] = "up"
    report["members"].append({"port": "ge7", "partner_port": 2, "mac": mac})
    ports[2]["oper_status"] = "down"
    color, health = read()
    assert all(member["status"] == "forwarding" for member in health["members"])
    assert (color, health["status"]) == ("warn", "warn")
    assert health["aggregateLinkFault"] == {"state": "down", "checkedAt": at}
    assert service_host()["lacpHealth"] == [health]
    audit = summarize_topology(load_infrastructure_map(path, now), node_id="snr", port_name="po1")["topologyAudit"]
    assert audit["servicePorts"] == []
    assert audit["lacpHealth"][0]["hostedServices"] == [
        {"id": "pbs-web", "name": "PBS Web", "kind": "Сервис", "mapStatus": "ok"},
    ]
    assert service_paths() == []
    assert service_ports() == [("ge6", ["host_lacp"]), ("ge7", ["host_lacp"])]
    ports[2]["oper_status"] = "up"
    color, health = read()
    assert (color, health["status"]) == ("ok", "ok")
    assert "aggregateLinkFault" not in health
    ports[2]["last_seen_at"] = (now - timedelta(minutes=6)).isoformat()
    color, health = read()
    assert all(member["status"] == "forwarding" for member in health["members"])
    assert (color, health["status"]) == ("unknown", "unknown")
    assert health["aggregateLink"] == {"state": "unknown"}
    ports[2]["last_seen_at"] = at
    assert read(now + timedelta(minutes=6))[0] == "unknown"
    assert all(member["status"] == "unknown" for member in service_host(now + timedelta(minutes=6))["lacpHealth"][0]["members"])
    network.clear()
    assert read()[0] == "unknown"


def test_collection_keeps_network_fresh_during_proxmox_api_failure(tmp_path, monkeypatch):
    import hashlib
    import sys
    from urllib.error import URLError
    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map

    context = tmp_path / "context.yaml"
    context.write_text("devices: []\n", encoding="utf-8")
    path = tmp_path / "graph.json"
    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(minutes=2)).isoformat()
    guest = {"id": "vm", "name": "Directum VM", "kind": "Виртуальная машина", "vmid": 103, "guest": True,
             "pveHost": "pve1", "reachability": {"state": "stopped", "checkedAt": stamp, "source": "Proxmox"}}
    collector.publish_snapshot(path, {
        "schema": 1, "snapshotAt": stamp, "contextSha256": hashlib.sha256(context.read_bytes()).hexdigest(),
        "clusterId": "proxmox:cluster", "nodeOrder": ["pve1"], "nodes": [
            {"id": "proxmox:cluster", "name": "Proxmox", "kind": "Кластер Proxmox"},
            {"id": "pve1", "name": "pve1", "kind": "Гипервизор"}, guest,
        ], "links": [{"a": "pve1", "b": "vm", "kind": "Размещение ВМ", "confirmed": True, "source": "Proxmox"}],
    })

    def unavailable(*args):
        raise URLError("internal exception detail")

    monkeypatch.setattr(collector, "read_proxmox", unavailable)
    monkeypatch.setattr(collector, "load_schema", lambda _: {})
    monkeypatch.setattr(collector, "validate_context", lambda *_: [])
    monkeypatch.setattr(collector, "read_network", lambda *args, **kwargs: {"sources": [
        {"name": "switch", "driver": "snmp_switch", "enabled": 1, "last_status": "success",
         "last_collect_at": now.isoformat()},
    ]})
    monkeypatch.setattr(collector, "build_server_health_view", lambda *_: {})
    monkeypatch.setattr(sys, "argv", ["infrastructure_collect", "--context", str(context), "--schema", str(context),
                                     "--server-health", str(context), "--output", str(path),
                                     "--proxmox-url", "https://pve.example", "--proxmox-token-file", str(context)])
    assert collector.main() == 0
    result = load_infrastructure_map(path)
    nodes = {n["id"]: n for n in result["nodes"]}
    assert result["snapshotAt"] > stamp and result["collectionIssues"] == ["proxmox"]
    assert nodes["observer:switch"]["mapStatus"] == "ok"
    assert nodes["vm"]["vmid"] == 103 and nodes["vm"]["mapStatus"] == "unknown"
    assert not nodes["vm"]["pveHost"]
    assert result["nodeOrder"] == ["pve1"] and result["clusterId"] == "proxmox:cluster"
    assert len(result["links"]) == 1 and not result["links"][0]["confirmed"]
    assert "internal exception detail" not in path.read_text(encoding="utf-8")
    assert collector.main() == 0
    assert any(n["id"] == "vm" for n in load_infrastructure_map(path)["nodes"])
    monkeypatch.setattr(collector, "read_proxmox", lambda *args: {"cluster": [], "nodes": [], "guests": []})
    assert collector.main() == 0
    recovered = load_infrastructure_map(path)
    assert "collectionIssues" not in recovered
    assert all(n["id"] != "vm" for n in recovered["nodes"])


def test_network_observer_failure_keeps_proxmox_and_independent_checks(tmp_path, monkeypatch, capsys):
    import sys
    from threading import Barrier
    from app import infrastructure_collect as collector
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import load_infrastructure_map

    context = tmp_path / "context.yaml"
    context.write_text(
        "devices:\n- id: switch\n  kind: switch\n  name: Switch\nservices:\n- id: web\n  name: Web\n",
        encoding="utf-8",
    )
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps({"service_probes": {"web": [{"type": "http", "ip": "192.0.2.20",
                         "port": 80, "path": "/ready", "body": "ready"}]}}), encoding="utf-8")
    path = tmp_path / "graph.json"
    monkeypatch.setattr(collector, "load_schema", lambda _: {})
    monkeypatch.setattr(collector, "validate_context", lambda *_: [])
    monkeypatch.setattr(collector, "read_proxmox", lambda *args: {
        "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 103, "name": "Guest", "node": "pve1", "type": "qemu", "status": "stopped"}],
    })

    def unavailable(*args, **kwargs):
        raise collector.NetctlError("internal netctl details")

    monkeypatch.setattr(collector, "read_network", unavailable)
    monkeypatch.setattr(collector, "build_server_health_view", lambda *_: {})
    monkeypatch.setattr(probes, "_http_probe", lambda _: {"state": "reachable", "httpStatus": 200})
    monkeypatch.setattr(sys, "argv", ["infrastructure_collect", "--context", str(context), "--schema", str(context),
                                     "--server-health", str(context), "--bindings", str(bindings), "--output", str(path),
                                     "--proxmox-url", "https://pve.example", "--proxmox-token-file", str(context)])
    concurrent_probes = Barrier(2, timeout=3)
    apply_service_probes = collector.apply_service_probes

    def downstream(*_):
        concurrent_probes.wait()

    def service_checks(*args):
        concurrent_probes.wait()
        apply_service_probes(*args)

    with monkeypatch.context() as concurrent:
        concurrent.setattr(collector, "_check_downstream_addresses", downstream)
        concurrent.setattr(collector, "apply_service_probes", service_checks)
        assert collector.main() == 0
    journal = capsys.readouterr().err
    stages = ["Proxmox", "Network Observer database", "build graph", "downstream address and service probes", "publish snapshot"]
    positions = [journal.index(f"starting {stage}") for stage in stages]
    assert positions == sorted(positions)
    assert "infrastructure collection: published snapshot in " in journal
    assert "internal netctl details" not in journal
    graph = load_infrastructure_map(path)
    assert graph["availability"] == "ready" and graph["collectionIssues"] == ["network_observer"]
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert nodes["switch"]["mapStatus"] == "unknown" and nodes["switch"]["ports"] == []
    assert nodes["pve1"]["mapStatus"] == "ok"
    assert nodes["pve-guest:103"]["reachability"]["state"] == "stopped"
    assert nodes["web"]["serviceChecks"][0]["httpStatus"] == 200
    assert "internal netctl details" not in path.read_text(encoding="utf-8")
    monkeypatch.setattr(collector, "read_network", lambda *args, **kwargs: {"sources": []})
    assert collector.main() == 0
    assert "collectionIssues" not in load_infrastructure_map(path)
    monkeypatch.setattr(collector, "build_server_health_view", lambda *_: {"freshness": "missing", "targets": []})
    assert collector.main() == 0
    incomplete = load_infrastructure_map(path)
    assert incomplete["collectionIssues"] == ["server_observer_unavailable"]
    assert next(n for n in incomplete["nodes"] if n["id"] == "web")["serviceChecks"][0]["httpStatus"] == 200


def test_proxmox_physical_port_inventory_preserves_admin_state_without_carrier(tmp_path, monkeypatch):
    from io import BytesIO
    from urllib.error import HTTPError
    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map

    token = tmp_path / "pve-token"
    token.write_text("PVEAPIToken=test@pve!monitor=test", encoding="utf-8")
    responses = {
        "cluster/status": [],
        "cluster/resources?type=node": [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"}],
        "cluster/resources?type=vm": [],
        "nodes/pve1/network/vmbr0": {"type": "bridge", "active": 1, "bridge_ports": "eno1",
                                      "bridge_vlan_aware": 1, "bridge_vids": "2-4094"},
        "nodes/pve2/network/vmbr1": {"type": "bridge", "active": 1, "bridge_ports": "eno3"},
        "nodes/pve1/status": {"rootfs": {"avail": 900, "total": 1000}, "swap": {"used": 0, "total": 100},
                              "memory": {"free": 70, "available": 200, "total": 1000}, "private": "ignore"},
        "nodes/pve1/network?type=eth": [
            {"iface": "eno1", "type": "eth", "exists": 1, "active": 1},
            {"iface": "eno2", "type": "eth", "exists": 1},
            {"iface": "eno3", "type": "eth"},
            {"iface": "vmbr0", "type": "bridge", "exists": 1, "active": 1},
        ],
    }

    class Opener:
        def open(self, request, timeout):
            path = request.full_url.split("/api2/json/", 1)[1]
            if path in {"nodes/pve2/network?type=eth", "nodes/pve2/status"}:
                raise HTTPError(request.full_url, 403, "Forbidden", {}, None)
            return BytesIO(json.dumps({"data": responses.get(path, [])}).encode())

    monkeypatch.setattr(collector, "build_opener", lambda *args: Opener())
    pve = collector.read_proxmox("https://pve.example", token, None, set(),
                                 {"pve1": "vmbr0", "pve2": "vmbr1"})
    assert pve["bridges"]["pve1"]["vmbr0"]["bridgeVlanMode"] == "enabled"
    assert pve["bridges"]["pve2"]["vmbr1"]["bridgeVlanMode"] == "not_reported"
    assert "bridge_vids" not in json.dumps(pve["bridges"])
    context = {"devices": [{"id": "switch", "name": "Switch", "kind": "switch"},
                           {"id": "pve1", "name": "pve1", "kind": "hypervisor"}], "links": [{
        "endpoint_a": {"device": "switch", "interface": "ge1"},
        "endpoint_b": {"device": "pve1", "interface": "eno1"},
        "relation": "connected_to",
    }]}
    now = datetime.now(timezone.utc)
    path = tmp_path / "graph.json"
    collector.publish_snapshot(path, collector.build_graph(context, {}, {}, pve, {}, now))
    graph = load_infrastructure_map(path, now)
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert [(p["name"], p["proxmoxActive"], p["state"]) for p in nodes["pve1"]["ports"]] == [
        ("eno1", True, "unknown"), ("eno2", False, "unknown"),
    ]
    assert not nodes["pve2"]["ports"]
    assert nodes["pve1"]["resourceCapacity"]["memory"]["availableBytes"] == 200
    assert nodes["pve1"]["mapStatus"] == "ok" and nodes["pve2"]["mapStatus"] == "unknown"
    assert "private" not in json.dumps(pve["nodeStatus"])
    link = next(e for e in graph["links"] if e["kind"] == "Сетевое соединение")
    assert not link["confirmed"]
    report, = link["portEvidence"]
    assert report["portStates"]["b"]["proxmoxActive"] is True
    assert "portComparison" not in report
    aged = load_infrastructure_map(path, now + timedelta(hours=1))
    assert all("proxmoxActive" not in port for node in aged["nodes"] for port in node["ports"])


def test_proxmox_management_port_joins_unique_fdb_and_active_bridge(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, address = "02:00:00:00:00:13", "192.0.2.13"
    context = {"devices": [
        {"id": "pve3", "name": "pve3", "kind": "hypervisor", "management_ip": address},
        {"id": "sw", "name": "SNR", "kind": "switch", "management_ip": "192.0.2.254"},
    ], "links": [{"endpoint_a": {"device": "sw", "interface": "ge11"},
                  "endpoint_b": {"device": "pve3", "interface": "enp2s0f0"}, "relation": "connected_to",
                  "state": {"verified": True}, "vlans": {"untagged": [1], "tagged": [20]}}]}
    source = {"id": 1, "name": "snr", "host": "192.0.2.254", "driver": "snmp_switch"}
    attachment = {"mac": mac, "source_id": 1, "port_key": "ge11", "vlan_id": 1, "observed_at": at}
    network = {"sources": [source], "attachments": [attachment],
               "hosts": [{"ip": address, "mac": mac, "last_seen_at": at}],
               "arp": [{"ip": address, "mac": mac, "last_seen_at": at}]}
    pve = {"at": at, "nodes": [{"node": "pve3", "status": "online"}], "cluster": [], "guests": [],
           "management": {"pve3": {"address": address, "port": "enp2s0f0"}}}
    path = tmp_path / "map.json"

    def load(stamp=now):
        graph = build_graph(context, network, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return [link for link in load_infrastructure_map(path, stamp)["links"]
                if {link["a"], link["b"]} == {"sw", "pve3"}]

    link, = load()
    assert link["confirmed"]
    assert any(p["confirmed"] and p["a"] == "ge11" and p["b"] == "enp2s0f0" for p in link["portEvidence"])
    assert [row["managementAddress"] for row in link["portEvidence"] if "managementAddress" in row] == [address]
    audit, = [row["vlanAudit"] for row in link["portEvidence"] if "vlanAudit" in row]
    assert audit[0]["managementObservation"] == {"address": address, "switchSide": "a", "checkedAt": at}
    assert audit[0]["state"] == "unconfirmed" and "managementObservation" not in audit[1]
    aged, = load(now + timedelta(minutes=11))
    assert all("managementObservation" not in vlan for row in aged["portEvidence"] for vlan in row.get("vlanAudit", []))
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    direct = next(link for link in snapshot["links"] if {link["a"], link["b"]} == {"pve3", "sw"})
    management_report = next(row for row in direct["portEvidence"] if "managementAddress" in row)
    direct["portEvidence"].remove(management_report)
    direct["portEvidence"].append({key: value for key, value in management_report.items()
                                   if key not in {"managementAddress", "vlan"}})
    snapshot["links"].append({**direct, "kind": "Путь по MAC-таблице", "portEvidence": [management_report]})
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    split = next(link for link in load_infrastructure_map(path, now)["links"]
                 if link["kind"] == "Сетевое соединение")
    assert next(row["vlanAudit"] for row in split["portEvidence"] if "vlanAudit" in row) == audit
    snapshot["links"].pop()
    direct["portEvidence"][-1] = management_report
    snapshot["nodes"].append({"id": "management", "name": "Management", "kind": "Сервис", "serviceChecks": [
        {"source": "UI_VPN", "method": "HTTPS", "target": address, "port": 8006, "checkedAt": at, "state": "reachable"},
        {"source": "UI_VPN", "method": "HTTPS", "target": "192.0.2.99", "port": 8006, "checkedAt": at, "state": "reachable"},
    ]})
    snapshot["links"].append({"a": "pve3", "b": "management", "kind": "Размещение", "confirmed": True})
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    from app.infrastructure_map import summarize_guest_attachment
    graph = load_infrastructure_map(path, now, include_guest_attachments=True)
    management, = graph["servicePaths"]["management"]
    assert management["management"] is True and management["target"] == address
    assert management["physicalPair"]["switchPort"] == "ge11"
    assert summarize_guest_attachment(graph, "management")["attachment"]["servicePaths"] == [management]
    assert graph["servicePorts"]["sw"][0]["services"][0]["basis"] == ["host_management"]
    next(link for link in snapshot["links"] if {link["a"], link["b"]} == {"pve3", "sw"})["kind"] = "Путь по MAC-таблице"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    graph = load_infrastructure_map(path, now, include_guest_attachments=True)
    assert "management" not in graph["servicePaths"]
    assert not load(now + timedelta(hours=1))[0]["confirmed"]
    network["attachments"].append({**attachment, "port_key": "ge12"})
    assert not any("managementAddress" in p for link in load() for p in link["portEvidence"])
    network["attachments"].pop()
    network["arp"].clear()
    assert not any("managementAddress" in p for link in load() for p in link["portEvidence"])


def test_lldp_management_address_requires_matching_inventory_and_host_mac(monkeypatch):
    from app.infrastructure_collect import build_graph
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:03"
    address = "192.0.2.13"
    context = {"devices": [{"id": "remote", "name": "Remote", "kind": "switch", "mac_addresses": [mac]}]}
    host = {"ip": address, "mac": mac, "last_seen_at": at, "availability": {
        "checked_at": at, "run_status": "success", "state": "online", "reason": "active_probe", "active_method": "icmp",
    }}
    network = {"sources": [{"id": 1, "name": "local", "driver": "snmp_switch"}], "hosts": [host], "lldp": [
        {"source": "local", "local_port_key": "51", "system_name": "Remote", "chassis_id": mac,
         "port_id": "Ge1", "port_id_subtype": "interface_name", "management_addresses": [address], "observed_at": at},
    ]}
    network["arp"] = [{"ip": address, "mac": mac, "last_seen_at": at}]
    bindings = {"asset_ip_checks": {"remote": address}}
    graph = build_graph(context, network, {}, {}, bindings, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["reachability"]["state"] == "reachable"
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["probeTargetIP"] == address
    monkeypatch.setattr(probes, "_icmp_check", lambda ip: {"state": "reachable", "roundTripMs": 0.8})
    probes.apply_service_probes([remote], {"remote": [{"type": "icmp", "ip": address}]})
    assert remote["reachability"]["method"] == "ICMP · LLDP + ARP"
    check = _public_service_check(remote["serviceChecks"][0], datetime.now(timezone.utc))
    assert check["identityCheckedAt"] == at and check["roundTripMs"] == 0.8
    raw_check = remote["serviceChecks"][0]
    stale = _public_service_check({**raw_check, "identityCheckedAt": (now - timedelta(hours=1)).isoformat()},
                                  datetime.now(timezone.utc))
    assert stale["state"] == "unknown" and stale["stale"] and "identityCheckedAt" not in stale
    without_arp = build_graph(context, {**network, "arp": []}, {}, {}, bindings, now)
    assert "probeTargetIP" not in next(node for node in without_arp["nodes"] if node["id"] == "remote")
    context["devices"][0]["management_ip"] = address
    registered = build_graph(context, network, {}, {}, bindings, now)
    target = next(node for node in registered["nodes"] if node["id"] == "remote")
    assert target["reachability"]["state"] == "reachable"
    assert target["probeTargetIP"] == address and target["probeTargetIdentityAt"] == at
    host["mac"] = "02:00:00:00:00:04"
    registered = build_graph(context, network, {}, {}, bindings, now)
    target = next(node for node in registered["nodes"] if node["id"] == "remote")
    assert "reachability" not in target and "probeTargetIP" not in target
    context["devices"][0].pop("management_ip")
    link, = graph["links"]
    assert link["portEvidence"][0]["b"] == "Ge1"
    host["mac"] = "02:00:00:00:00:04"
    graph = build_graph(context, network, {}, {}, bindings, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert "reachability" not in remote
    assert "probeTargetIP" not in remote

    network["router_neighbors"] = [{"identity": "Remote", "address": address, "mac": host["mac"], "last_seen_at": at}]
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["reachability"]["state"] == "reachable"
    assert remote["properties"]["Адрес управления по LLDP"] == address

    available = host["availability"]
    host["availability"] = {}
    alternate = {**host, "ip": "192.0.2.14", "mac": mac, "availability": available}
    network["hosts"].append(alternate)
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["reachability"]["state"] == "reachable"
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["properties"]["IP по MAC"] == alternate["ip"]
    host["availability"] = available
    network["hosts"].pop()

    layer2 = {"state": "reachable", "source": "router", "method": "MAC ping · L2", "checkedAt": at}
    network["asset_mac_checks"] = {"remote": layer2}
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["reachability"]["method"] == "ICMP"
    assert remote["serviceChecks"] == [layer2]
    host["availability"] = {}
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert remote["properties"]["Адрес управления по LLDP"] == address
    assert remote["reachability"] == layer2
    host["availability"] = available
    del network["asset_mac_checks"]

    network["lldp"][0]["chassis_id"] = host["mac"]
    graph = build_graph(context, network, {}, {}, {}, now)
    remote = next(node for node in graph["nodes"] if node["id"] == "remote")
    assert "reachability" not in remote
    assert remote["properties"]["IP заявлен в LLDP"] == address
    assert "MAC шасси" in remote["properties"]["Сопоставление LLDP"]
    assert not graph["links"][0]["confirmed"]


def test_downstream_devices_require_the_expected_live_lldp_pair(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    switch_mac, endpoint_mac = "02:00:00:00:00:03", "02:00:00:00:00:04"
    address = "192.0.2.111"
    context = {"devices": [{"id": "core", "name": "Core", "kind": "switch", "management_ip": "192.0.2.1"},
                           {"id": "poe", "name": "PoE", "kind": "switch", "mac_addresses": [switch_mac]}],
               "links": [{"id": "core-to-poe", "relation": "connected_to", "state": {"verified": True},
                          "endpoint_a": {"device": "core", "interface": "Slot0/51"},
                          "endpoint_b": {"device": "poe", "interface": "Ge1"}}]}
    lldp = {"source": "main", "local_port_key": "ifindex:51", "system_name": "PoE", "chassis_id": switch_mac,
            "port_id": "Ge1", "port_id_subtype": "interface_name", "observed_at": at}
    network = {"sources": [{"id": 1, "name": "main", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}],
               "ports": [{"source": "main", "port_key": "ifindex:51", "name": "Slot0/51", "oper_status": "up",
                          "last_seen_at": at, "collector_run_id": 2}],
               "lldp": [lldp], "downstream_fdb": {"core-to-poe": {"source": "main", "at": at,
                                                                    "macs": [switch_mac, endpoint_mac]}},
               "arp": [{"ip": address, "mac": endpoint_mac, "last_seen_at": at}],
               "hosts": [{"ip": address, "mac": endpoint_mac, "last_seen_at": at, "availability": {
                   "checked_at": at, "run_status": "success", "state": "online", "reason": "active_probe",
                   "active_method": "icmp"}}]}
    snapshot = tmp_path / "map.json"

    def read(when=now):
        graph = build_graph(context, network, {}, {}, {"downstream_mac_links": ["core-to-poe"]}, now)
        snapshot.write_text(json.dumps(graph), encoding="utf-8")
        result = load_infrastructure_map(snapshot, when)
        return result, next(n for n in result["nodes"] if n["id"] == "poe")

    graph, node = read()
    downstream = node["downstream"]
    assert downstream["upstreamId"] == "core" and downstream["port"] == "Slot0/51"
    endpoint, = downstream["devices"]
    assert endpoint["mac"] == endpoint_mac and endpoint["ip"] == address
    assert endpoint["reachability"]["state"] == "reachable"
    assert len(graph["nodes"]) == 2 and len(graph["links"]) == 1
    assert summarize_topology(graph)["topologyAudit"]["downstreamSwitches"][0]["devices"] == downstream["devices"]
    context["devices"][1]["management_ip"] = "192.0.2.2"
    network["sources"].append({"id": 2, "name": "remote", "host": "192.0.2.2", "driver": "snmp_switch", "enabled": True})
    network["ports"].append({"source": "remote", "port_key": "ifindex:2", "name": "Ge2", "oper_status": "up",
                             "last_seen_at": at, "collector_run_id": 2})
    sample = network["downstream_fdb"]["core-to-poe"]
    sample["remote"] = {"source": "remote", "readings": [
        {"mac": endpoint_mac, "name": "Ge2", "at": at.replace("+00:00", "Z")},
    ]}
    endpoint, = read()[1]["downstream"]["devices"]
    assert endpoint["switchPort"] == {"name": "Ge2", "checkedAt": at}
    sample["remote"]["readings"].append({"mac": endpoint_mac, "name": "Ge1", "at": at})
    endpoint, = read()[1]["downstream"]["devices"]
    assert "switchPort" not in endpoint
    sample["remote"]["readings"].pop()
    context["devices"][1]["mac_addresses"] = []
    endpoint, = read()[1]["downstream"]["devices"]
    assert endpoint["switchPort"]["name"] == "Ge2"
    context["devices"][1]["mac_addresses"] = [switch_mac]
    del sample["remote"]
    network["arp"].clear()
    endpoint, = read()[1]["downstream"]["devices"]
    assert "ip" not in endpoint and endpoint["reachability"]["state"] == "unknown"
    assert "downstream" not in read(now + timedelta(minutes=26))[1]
    lldp["port_id"] = "Ge2"
    assert "downstream" not in read()[1]


def test_downstream_inventory_pair_requires_matching_live_stp_and_fdb(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    core_mac, endpoint_mac = "02:00:00:00:00:01", "02:00:00:00:00:07"
    context = {
        "devices": [
            {"id": "core", "name": "Core", "kind": "switch", "management_ip": "192.0.2.1",
             "mac_addresses": [core_mac]},
            {"id": "access", "name": "Access", "kind": "switch", "management_ip": "192.0.2.2"},
        ],
        "links": [{"id": "inventory", "relation": "connected_to", "state": {"verified": True},
                   "endpoint_a": {"device": "core", "interface": "Ge19"},
                   "endpoint_b": {"device": "access", "interface": "Port1"}}],
    }
    def port(source, name, index):
        return {"source": source, "name": name, "port_key": f"physical:{index}", "bridge_port": index,
                "oper_status": "up", "last_seen_at": at, "collector_run_id": 2}

    stp = {"rootPortNumber": 1, "designatedBridgeMac": core_mac, "designatedPortId": "83:9b", "checkedAt": at}
    network = {
        "sources": [{"id": i, "name": name, "host": f"192.0.2.{i}", "enabled": True, "driver": "snmp_switch"}
                    for i, name in enumerate(("core", "access"), 1)],
        "ports": [port("core", "Ge19", 19), port("access", "Port1", 1), port("access", "Port7", 7)],
        "stp_root_paths": {"access": stp},
        "downstream_fdb": {"inventory": {
            "source": "core", "at": at, "macs": [endpoint_mac],
            "remote": {"source": "access", "readings": [{"mac": endpoint_mac, "name": "Port7", "at": at}]},
        }},
    }
    path = tmp_path / "graph.json"
    def read(when=now):
        graph = build_graph(context, network, {}, {}, {"downstream_mac_links": ["inventory"]}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return load_infrastructure_map(path, when)

    graph = read()
    access = next(node for node in graph["nodes"] if node["id"] == "access")
    assert access["downstream"]["basis"] == "inventory_stp"
    assert access["downstream"]["stpCheckedAt"] == at
    assert access["downstream"]["devices"][0]["switchPort"]["name"] == "Port7"
    assert all(p.get("pairEvidence") != "current" for edge in graph["links"] for p in edge["portEvidence"])
    assert all("downstream" not in node for node in read(now + timedelta(minutes=6))["nodes"])
    network["ports"][2]["oper_status"] = "down"
    assert all("downstream" not in node for node in read()["nodes"])
    network["ports"][2]["oper_status"] = "up"
    stp["designatedBridgeMac"] = "02:00:00:00:00:09"
    assert all("downstream" not in node for node in read()["nodes"])
    stp["designatedBridgeMac"] = core_mac
    context["links"][0]["state"]["verified"] = False
    assert all("downstream" not in node for node in read()["nodes"])


def test_inventory_pair_corroborated_by_exact_stp_ports(tmp_path):
    from app.infrastructure_collect import _corroborate_stp_ports
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    link = {"kind": "Сетевое соединение", "confirmed": True, "a": "access", "b": "core"}
    inventory = {"a": "Port24", "b": "ge22", "source": "GitHub", "confirmed": True, "at": None}
    path = {"localPort": "Port24", "bridgeDeviceId": "core", "designatedPortName": "ge22",
            "checkedAt": stamp, "designatedPortCheckedAt": stamp}
    nodes = {
        "access": {"kind": "Коммутатор", "stpRootPath": path,
                   "ports": [{"name": "Port24", "state": "up", "checkedAt": stamp}]},
        "core": {"kind": "Коммутатор", "ports": [{"name": "ge22", "state": "up", "checkedAt": stamp}]},
    }

    def reports(*other):
        link["portEvidence"] = [inventory, *other]
        _corroborate_stp_ports([link], nodes, set(), now)
        return [row for row in link["portEvidence"] if row["source"] == "SNMP · порты STP"]

    assert reports() == [{"a": "Port24", "b": "ge22", "source": "SNMP · порты STP", "at": stamp, "confirmed": True}]
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "links": [link], "nodes": [
        {**node, "id": key, "name": key} for key, node in nodes.items()
    ]}), encoding="utf-8")
    def current_pairs(when):
        return summarize_topology(load_infrastructure_map(snapshot, when))["topologyAudit"]["currentPairs"]

    assert current_pairs(now)[0]["evidence"] == [{"source": "SNMP · порты STP", "checkedAt": stamp,
                                                 "expiresAt": (now + timedelta(minutes=5)).isoformat()}]
    assert not current_pairs(now + timedelta(minutes=6))
    path["designatedPortName"] = "ge19"
    assert not reports()
    path["designatedPortName"] = "ge22"
    path["checkedAt"] = (now - timedelta(minutes=6)).isoformat()
    assert not reports()
    path["checkedAt"] = stamp
    nodes["core"]["ports"][0]["state"] = "down"
    assert not reports()
    nodes["core"]["ports"][0]["state"] = "up"
    assert not reports({"a": "Port24", "b": "ge23", "source": "LLDP UI_VPN", "at": stamp, "confirmed": True})
    link["portEvidence"] = [inventory]
    _corroborate_stp_ports([link], nodes, {("core", "ge22")}, now)
    assert link["portEvidence"] == [inventory]
    inventory["confirmed"] = False
    assert not reports()


def test_downstream_local_probe_requires_unique_observed_address_and_mac(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    ip, mac = "192.0.2.113", "02:00:00:00:00:04"
    device = {"mac": mac}
    nodes = [{"downstream": {"devices": [device]}}]
    host = {"ip": ip, "mac": mac, "last_seen_at": now.isoformat()}
    network = {"hosts": [host]}
    probes = []

    def check(address, identity, *, fresh_only=False):
        probes.append((address, identity, fresh_only))
        return True

    monkeypatch.setattr(collector, "_probe_on_link_mac", check)
    collector._check_downstream_addresses(nodes, network, now)
    assert probes == [(ip, mac, True)]
    assert device["ip"] == ip and device["reachability"]["state"] == "reachable"
    assert device["identityCheckedAt"] == device["reachability"]["checkedAt"]
    probes.clear()
    device.clear()
    device["mac"] = mac
    network["arp"] = [{**host, "mac": "02:00:00:00:00:09"}]
    collector._check_downstream_addresses(nodes, network, now)
    assert not probes and device == {"mac": mac}


def test_downstream_rtsp_checks_only_configured_fresh_identity(monkeypatch):
    from app import infrastructure_collect as collector
    from app.infrastructure_map import _public_downstream

    now = datetime.now(timezone.utc)
    ip, mac = "192.0.2.113", "02:00:00:00:00:04"
    device = {"ip": ip, "mac": mac, "identityCheckedAt": now.isoformat()}
    other = {"ip": "192.0.2.114", "mac": "02:00:00:00:00:06", "identityCheckedAt": now.isoformat()}
    downstream = {"upstreamId": "upstream", "port": "ge1", "checkedAt": now.isoformat(),
                  "devices": [device, other]}
    nodes = [{"id": "poe", "downstream": downstream}]
    probes = []

    def rtsp(spec):
        probes.append(spec)
        return {"state": "reachable", "rtspStatus": 200}

    monkeypatch.setattr(collector, "_rtsp_options", rtsp)
    collector._check_downstream_rtsp(nodes, {"poe": {ip: mac, other["ip"]: "02:00:00:00:00:05"}}, now)
    assert probes == [{"ip": ip, "port": 554, "path": "/"}]
    published_at = datetime.now(timezone.utc)
    devices = _public_downstream(downstream, [], {}, published_at)["devices"]
    assert devices[0]["rtsp"]["rtspStatus"] == 200
    assert devices[0]["rtsp"]["state"] == "reachable"
    assert "rtsp" not in devices[1]
    assert "rtsp" not in _public_downstream(downstream, [], {}, published_at + timedelta(minutes=6))["devices"][0]


def test_direct_probe_waits_for_neighbor_revalidation_when_required(monkeypatch):
    from app import infrastructure_collect as collector

    ip, mac = "192.0.2.113", "02:00:00:00:00:04"
    responses = iter(([{"dev": "eth0"}], [{"dst": ip, "lladdr": mac, "state": ["DELAY"]}],
                      [{"dst": ip, "lladdr": mac, "state": ["REACHABLE"]}]))
    waits = []
    monkeypatch.setattr(collector, "probe_icmp", lambda address: address == ip)
    monkeypatch.setattr(collector, "sleep", waits.append)
    monkeypatch.setattr(collector.subprocess, "check_output", lambda *args, **kwargs: json.dumps(next(responses)))
    assert collector._probe_on_link_mac(ip, mac, fresh_only=True)
    assert waits == [6]


def test_openvpn_requires_connected_daemon_and_active_session(monkeypatch):
    from io import BytesIO
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    class Management:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            assert timeout > 0

        def connect(self, path):
            assert path == "/run/openvpn/server.sock"

        def sendall(self, command):
            assert command == b"state\nstatus 3\n"

        def makefile(self, mode):
            return BytesIO(self.response)

    connection = Management()
    monkeypatch.setattr(probes.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(probes.socket, "socket", lambda family: connection)
    ready = b"123,CONNECTED,SUCCESS,,\nEND\r\n"
    header = b"HEADER\tCLIENT_LIST\tCommon Name\n"
    client = b"CLIENT_LIST\tsample\n"
    spec = {"type": "openvpn_management", "port": 1194}
    socket_listing = b"UNCONN 0 0 192.0.2.30:1194 0.0.0.0:*\nUNCONN 0 0 [::]:1194 [::]:*\n"

    def read_socket(args, **kwargs):
        assert args == ["/usr/bin/ss", "-H", "-lun", "sport = :1194"]
        return socket_listing

    monkeypatch.setattr(probes.subprocess, "check_output", read_socket)
    connection.response = ready + header + client + b"END\n"
    assert probes._probe(spec) == "reachable"
    for response in (ready + header + b"END\n", header + client + b"END\n", ready + header + client):
        connection.response = response
        assert probes._probe(spec) == "unknown"

    def check(response, expected_socket):
        connection.response = response
        node = {"id": "vpn", "kind": "Сервис"}
        probes.apply_service_probes([node], {"vpn": [spec]})
        raw, listener = node["serviceChecks"]
        now = datetime.now(timezone.utc)
        listener = _public_service_check(listener, now)
        assert listener["method"] == "OpenVPN UDP-сокет"
        assert listener["required"] and listener["component"]
        assert listener["state"] == expected_socket
        assert listener["configuredPort"] == 1194
        assert listener["localUdpSocket"] == raw["localUdpSocket"]
        assert node["reachability"]["state"] == raw["state"]
        return _public_service_check(raw, now)

    observed = check(ready + header + client + b"CLIENT_LIST\tprivate-second\nEND\n", "reachable")
    assert observed["method"] == "OpenVPN Management"
    assert observed["port"] is None and observed["configuredPort"] == 1194
    assert observed["localUdpSocket"] == {"state": "bound", "addresses": ["192.0.2.30", "::"]}
    assert observed["sessionCount"] == 2 and observed["daemonReady"] is True
    assert "sample" not in json.dumps(observed) and "private-second" not in json.dumps(observed)
    empty = check(ready + header + b"END\n", "reachable")
    assert empty["state"] == "unknown" and empty["sessionCount"] == 0 and empty["daemonReady"] is True
    assert empty["reason"] == "openvpn_no_active_sessions"
    daemon = check(header + client + b"END\n", "reachable")
    assert daemon["state"] == "unknown" and daemon["reason"] == "openvpn_daemon_unconfirmed"
    incomplete = check(ready + header + client, "reachable")
    assert incomplete["reason"] == "openvpn_management_incomplete"
    assert "sessionCount" not in incomplete
    socket_listing = b""
    assert check(ready + header + b"END\n", "unreachable")["localUdpSocket"] == {"state": "unbound"}
    socket_listing = b"UNCONN 0 0 192.0.2.30:1195 0.0.0.0:*\n"
    assert check(ready + header + b"END\n", "unknown")["localUdpSocket"] == {"state": "unknown"}

    def unavailable(path):
        raise PermissionError("private socket details")

    monkeypatch.setattr(connection, "connect", unavailable)
    blocked = check(b"", "unknown")
    assert blocked["state"] == "unknown" and blocked["reason"] == "openvpn_management_unavailable"
    assert "sessionCount" not in blocked and "private socket details" not in json.dumps(blocked)


def test_smb_mount_checks_the_configured_live_share_without_local_fallback(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _map_statuses, _public_node

    spec = {"type": "smb_mount", "ip": "192.0.2.4", "share": "Soft",
            "mount": "/mnt/share", "component": True}
    mounts = [{"id": 41, "source": "//192.0.2.4/Soft", "target": "/mnt/share", "fstype": "cifs"}]
    reads = []
    replace_mount = False

    def command(args, **kwargs):
        if args[0] == "/usr/bin/findmnt":
            return json.dumps({"filesystems": mounts}).encode()
        assert args == ["/usr/bin/stat", "--cached=never", "--format=%F", "--", "/mnt/share"]
        reads.append(args)
        if replace_mount:
            mounts[0]["id"] += 1
        return b"directory\n"

    monkeypatch.setattr(probes.subprocess, "check_output", command)
    monkeypatch.setattr(probes, "_smb", lambda spec: {"state": "reachable"})

    def check():
        node = {"id": "files", "kind": "Сервис"}
        probes.apply_service_probes([node], {"files": [{"type": "smb", "ip": spec["ip"], "port": 445}, spec]})
        public = _public_node(node, datetime.now(timezone.utc))
        _map_statuses({"files": public}, [])
        return public["mapStatus"], public["serviceChecks"][1]

    status, result = check()
    assert status == "ok" and result["state"] == "reachable" and result["component"]
    assert result["smbShare"] == "//192.0.2.4/Soft"
    replace_mount = True
    status, result = check()
    assert (status, result["reason"]) == ("unknown", "smb_mount_changed")
    mounts[0]["source"] = "//192.0.2.4/Other"
    status, result = check()
    assert (status, result["reason"]) == ("warn", "smb_mount_source")
    mounts[0].update(source="systemd-1", fstype="autofs")
    assert check()[0] == "unknown"
    mounts.clear()
    assert check()[1]["reason"] == "smb_mount_missing"
    assert len(reads) == 2


def test_openvpn_tunnel_checks_kernel_link_and_address_as_required_component(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _map_statuses, _public_node

    spec = {"type": "openvpn_tunnel", "interface": "tun0", "address": "192.0.2.1/24", "component": True}
    kernel = [{"ifname": "tun0", "flags": ["UP", "LOWER_UP"],
               "linkinfo": {"info_kind": "tun", "info_data": {"type": "tun"}},
               "addr_info": [{"family": "inet", "local": "192.0.2.1", "prefixlen": 24}]}]

    def output(command, *, timeout):
        if command[0] == "/usr/bin/ss":
            return b"UNCONN 0 0 192.0.2.30:1194 0.0.0.0:*\n"
        assert command == ["/usr/sbin/ip", "-j", "-d", "address", "show"]
        assert timeout == probes.TIMEOUT
        return json.dumps(kernel).encode()

    monkeypatch.setattr(probes.subprocess, "check_output", output)
    monkeypatch.setattr(probes, "_openvpn_management",
                        lambda: {"state": "reachable", "daemonReady": True, "sessionCount": 1})

    def check():
        node = {"id": "vpn", "kind": "Сервис"}
        probes.apply_service_probes([node], {"vpn": [{"type": "openvpn_management", "port": 1194}, spec]})
        public = _public_node(node, datetime.now(timezone.utc))
        _map_statuses({"vpn": public}, [])
        tunnel = next(check for check in public["serviceChecks"] if check["method"] == "OpenVPN TUN")
        return public["mapStatus"], tunnel

    status, result = check()
    assert status == "ok" and result["state"] == "reachable" and result["component"]
    assert (result["tunnelInterface"], result["tunnelAddress"]) == ("tun0", "192.0.2.1/24")
    kernel[0]["flags"] = ["UP"]
    status, result = check()
    assert (status, result["state"], result["reason"]) == ("warn", "unreachable", "openvpn_tunnel_down")
    kernel[0]["flags"] = ["UP", "LOWER_UP"]
    kernel[0]["addr_info"][0]["prefixlen"] = 25
    assert check()[1]["reason"] == "openvpn_tunnel_address"
    kernel[0]["linkinfo"]["info_data"]["type"] = "tap"
    assert check()[1]["reason"] == "openvpn_tunnel_kind"
    kernel.clear()
    assert check()[1]["reason"] == "openvpn_tunnel_missing"
    kernel.append("invalid kernel data")
    assert check()[0] == "unknown"


def test_network_device_without_management_ip_uses_unique_current_mac_binding():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:03"
    address = "192.0.2.15"
    device = {"id": "router", "name": "Router", "kind": "router", "mac_addresses": [mac]}
    host = {"ip": address, "mac": mac, "last_seen_at": at, "availability": {
        "checked_at": at, "run_status": "success", "state": "online", "reason": "active_probe", "active_method": "icmp",
    }}

    def build(devices, hosts):
        return build_graph({"devices": devices}, {"hosts": hosts}, {}, {}, {}, now)["nodes"][0]

    node = build([device], [host])
    assert node["reachability"]["state"] == "reachable"
    assert node["properties"]["IP по MAC"] == address
    assert "reachability" not in build([device, {**device, "id": "other"}], [host])
    assert "reachability" not in build([device], [host, {**host, "ip": "192.0.2.17"}])
    assert "reachability" not in build([device], [{**host, "last_seen_at": (now - timedelta(hours=1)).isoformat()}])


def test_router_management_address_uses_only_fresh_matching_mac():
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import _public_node

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    address, mac = "192.0.2.15", "02:00:00:00:00:03"
    device = {"id": "router", "name": "Router", "kind": "router",
              "management_ip": address, "mac_addresses": [mac]}
    host = {"ip": address, "mac": mac, "last_seen_at": at, "availability": {
        "checked_at": at, "run_status": "success", "state": "online", "reason": "active_probe", "active_method": "icmp",
    }}
    other = {**host, "mac": "02:00:00:00:00:09"}
    stale = {**host, "last_seen_at": (now - timedelta(hours=1)).isoformat()}

    def build(hosts):
        node, = build_graph({"devices": [device]}, {"hosts": hosts}, {}, {}, {}, now)["nodes"]
        return _public_node(node, now)

    assert build([other])["reachability"]["state"] == "unknown"
    assert build([other, host])["reachability"]["state"] == "unknown"
    assert build([stale])["reachability"]["state"] == "unknown"
    public = build([host])
    assert public["reachability"]["state"] == "reachable"
    assert public["properties"]["Адрес управления"] == address


def test_switch_ports_expose_fresh_link_state_and_age(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    recent = (now - timedelta(minutes=2)).isoformat()
    old = (now - timedelta(hours=1)).isoformat()
    network = {
        "sources": [{"id": 1, "name": "sw", "driver": "snmp_switch"}],
        "ports": [
            {"source": "sw", "name": "ge1", "oper_status": "up", "admin_status": "up",
             "speed_bps": 1_000_000_000, "last_seen_at": recent, "mac": "hidden", "collector_run_id": 2},
            {"source": "sw", "name": "ge2", "oper_status": "up", "last_seen_at": old, "collector_run_id": 2},
            {"source": "sw", "name": "ge3", "oper_status": "down", "admin_status": "down",
             "last_seen_at": recent, "collector_run_id": 2},
            {"source": "sw", "name": "ge1", "oper_status": "up", "last_seen_at": old, "collector_run_id": 1},
        ],
    }
    graph = build_graph({}, network, {}, {}, {}, now)
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    node, = load_infrastructure_map(path, now)["nodes"]
    assert "hidden" not in path.read_text(encoding="utf-8")
    assert node["ports"] == [
        {"name": "ge1", "state": "up", "speedBps": 1_000_000_000, "checkedAt": recent, "stale": False},
        {"name": "ge2", "state": "unknown", "speedBps": None, "checkedAt": old, "stale": True},
        {"name": "ge3", "state": "disabled", "speedBps": None, "checkedAt": recent, "stale": False},
    ]


def test_switch_collection_check_keeps_failed_fdb_separate_from_host_reachability(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    finished = (now - timedelta(minutes=1)).isoformat()
    address = "192.0.2.9"
    report = {"finished_at": finished, "status": "failed", "error_class": "fdb_unavailable"}
    network = {"sources": [{"name": "sw", "host": address, "driver": "snmp_switch", "enabled": True}],
               "switch_collection": {"sw": report}, "hosts": [{"ip": address, "last_seen_at": finished,
                   "availability": {"checked_at": finished, "run_status": "success", "state": "online",
                                    "reason": "active_probe", "active_method": "icmp"}}]}
    path = tmp_path / "graph.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph({}, network, {}, {}, {}, now)), encoding="utf-8")
        graph = load_infrastructure_map(path, when)
        node, = graph["nodes"]
        check, = node["serviceChecks"]
        return node, check, summarize_topology(graph)["topologyAudit"]["switchCollectionIssues"]

    node, check, issues = read()
    assert node["reachability"]["state"] == "reachable" and node["mapStatus"] == "warn"
    assert check["method"] == "Сбор данных SNMP" and check["state"] == "unreachable" and check["required"]
    assert check["reason"] == "snmp_fdb_unavailable" and check["checkedAt"] == finished
    assert issues == [{"id": node["id"], "name": node["name"], "state": "unreachable", "checkedAt": finished,
                       "stale": False, "reason": "snmp_fdb_unavailable"}]

    _, check, _ = read(now + timedelta(minutes=26))
    assert check["stale"] and check["state"] == "unknown" and "reason" not in check
    report.update(status="partial", error_class="", outcomes_json=json.dumps({
        "fdb": "success_with_rows", "lldp_remote": "success_with_rows",
        "lldp_remote_management_address": "timeout", "pvid": "unsupported_no_such_object",
        "unrecognized": "auth_or_view_failure",
    }))
    _, check, issues = read()
    assert check["reason"] == "snmp_collection_partial"
    failures = [{"capability": "lldp_remote_management_address", "outcome": "timeout"}]
    assert check["snmpFailures"] == issues[0]["snmpFailures"] == failures
    assert "snmpFailures" not in read(now + timedelta(minutes=26))[1]
    report.update(status="success")
    node, check, issues = read()
    assert node["mapStatus"] == "ok" and check["state"] == "reachable" and issues == []


def test_guest_placement_includes_current_bridge_and_configured_members(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    pve = {
        "at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 103, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"103": {"net0": "virtio=02:00:00:00:00:03,bridge=vmbr1,tag=100,link_down=1",
                            "net1": "virtio=02:00:00:00:00:04", "net2": "bridge=bad/path"}},
        "bridges": {"pve1": {"vmbr1": {"type": "bridge", "bridge_ports": "bond0 eno2", "active": 1,
                                       "bridgeVlanMode": "enabled"}}},
    }
    graph = build_graph({}, {}, {}, pve, {}, now)
    path = tmp_path / "graph.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    assert "02:00:00:00:00:03" not in path.read_text(encoding="utf-8")
    link = next(link for link in load_infrastructure_map(path, now)["links"] if link["b"] == "pve-guest:103")
    assert link["portEvidence"] == [{
        "a": "vmbr1", "b": "net0", "source": "Proxmox · конфигурация ВМ", "at": at,
        "confirmed": True, "vlan": 100,
        "virtual": {"linkDisabled": True, "bridgeActive": True, "bridgeVlanMode": "enabled",
                    "uplinks": ["bond0", "eno2"], "switchPorts": []},
    }]
    stale_link = next(link for link in load_infrastructure_map(path, now + timedelta(hours=1))["links"]
                      if link["b"] == "pve-guest:103")
    assert not stale_link["confirmed"]
    assert not stale_link["portEvidence"][0]["confirmed"]
    assert "bridgeVlanMode" not in stale_link["portEvidence"][0]["virtual"]


def test_running_vm_is_unreachable_when_every_configured_adapter_is_disconnected(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    mac = "02:00:00:00:00:03"
    disconnected = f"virtio={mac},bridge=vmbr1,link_down=1"
    pve = {
        "at": now.isoformat(), "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 122, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"122": {"net0": disconnected, "directNetworkOnly": True}},
    }
    network = {"hosts": [{"mac": mac, "availability": {
        "checked_at": now.isoformat(), "run_status": "success", "state": "online",
        "reason": "active_probe", "active_method": "icmp",
    }}]}
    path = tmp_path / "graph.json"

    def load(at=now):
        graph = build_graph({}, network, {}, pve, {}, at)
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(node for node in load_infrastructure_map(path, at)["nodes"] if node["vmid"] == 122)

    node = load()
    assert node["properties"]["Состояние ВМ"] == "Запущена"
    assert node["mapStatus"] == "critical"
    assert node["reachability"]["source"] == "Proxmox"
    assert node["reachability"]["method"] == "Все адаптеры ВМ отключены"
    config = pve["configs"]["122"]
    config["net1"] = "virtio=02:00:00:00:00:04"
    assert load()["mapStatus"] == "unknown"
    del config["net1"]
    del config["directNetworkOnly"]
    assert load()["reachability"]["source"] == ""
    config["networkConfigRead"] = True
    node = load()
    assert node["mapStatus"] == "unknown"
    assert node["reachability"] == {
        "state": "unknown", "source": "Proxmox", "method": "Адаптеры Proxmox отключены",
        "checkedAt": now.isoformat(), "stale": False,
    }
    config["directNetworkOnly"] = True
    assert load(now + timedelta(hours=1))["mapStatus"] == "unknown"
    config.clear()
    assert load()["mapStatus"] == "unknown"


def test_vm_switch_observation_requires_current_mac_and_declared_host_port(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:03"
    context = {
        "devices": [{"id": name, "name": name, "kind": kind}
                    for name, kind in [("pve1", "hypervisor"), ("sw", "switch")]],
        "links": [{"relation": "connected_to", "state": {"verified": True},
                   "endpoint_a": {"device": "sw", "interface": "XE3"},
                   "endpoint_b": {"device": "pve1", "interface": "vm_net_10g"}}],
    }
    pve = {
        "at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 103, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"103": {"net0": f"virtio={mac},bridge=vmbr1"}},
        "bridges": {"pve1": {"vmbr1": {"active": 1, "bridge_ports": "ens7f1np1"}}},
        "activePorts": {"pve1": ["ens7f1np1"]},
    }
    network = {
        "sources": [{"id": 1, "name": "switch-source", "driver": "snmp_switch",
                     "driver_options": {"intent_stable_id": "sw"}}],
        "ports": [{"source": "switch-source", "port_key": "index:3", "name": "xe3"}],
        "guest_fdb": [{"mac": mac, "source_id": 1, "port_key": port, "vlan_id": 1, "observed_at": at}
                      for port in ("index:3", "unrelated")],
    }
    path = tmp_path / "graph.json"

    def switch_ports(rendered_at):
        graph = build_graph(context, network, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        assert mac not in path.read_text(encoding="utf-8")
        link = next(edge for edge in load_infrastructure_map(path, rendered_at)["links"] if edge["b"] == "pve-guest:103")
        return link["portEvidence"][0]["virtual"]["switchPorts"]

    def physical_ports():
        graph = build_graph(context, network, {}, pve, {}, now)
        link = next(e for e in graph["links"] if {e["a"], e["b"]} == {"sw", "pve1"})
        return [(p["a"], p["b"]) for p in link["portEvidence"] if p["source"] == "netctl FDB + Proxmox"]

    def guest_uplink(vmid, rendered_at=now):
        graph = build_graph(context, network, {}, pve, {}, now)
        path.write_text(json.dumps(graph), encoding="utf-8")
        link = next(edge for edge in load_infrastructure_map(path, rendered_at)["links"]
                    if edge["b"] == f"pve-guest:{vmid}")
        return link["portEvidence"][0]["virtual"].get("switchUplink")

    assert switch_ports(now) == [{"id": "sw", "port": "xe3", "vlan": 1, "at": at}]
    assert physical_ports() == [("xe3", "ens7f1np1")]
    pve["guests"].append({**pve["guests"][0], "vmid": 104})
    pve["configs"]["104"] = {"net0": "virtio=02:00:00:00:00:04,bridge=vmbr1"}
    assert guest_uplink(103) is None
    assert guest_uplink(104) == {"id": "sw", "port": "xe3", "at": at}
    pve["guests"][1]["status"] = "stopped"
    assert guest_uplink(104) == {"id": "sw", "port": "xe3", "at": at, "configuredOnly": True}
    pve["guests"][1]["status"] = "running"
    assert guest_uplink(104, now + timedelta(hours=1)) is None
    context["devices"].append({"id": "other", "name": "Other", "kind": "router"})
    network["lldp"] = [{"source": "switch-source", "local_port_key": "index:3",
                        "system_name": "Other", "observed_at": at}]
    assert guest_uplink(104) is None
    del network["lldp"]
    pve["configs"]["104"]["net0"] += ",link_down=1"
    assert guest_uplink(104) == {"id": "sw", "port": "xe3", "at": at, "configuredOnly": True}
    pve["configs"]["104"]["net0"] = pve["configs"]["104"]["net0"].removesuffix(",link_down=1")
    pve["activePorts"]["pve1"] = []
    assert physical_ports() == []
    assert guest_uplink(104) is None
    pve["activePorts"]["pve1"] = ["ens7f1np1"]
    pve["bridges"]["pve1"]["vmbr1"]["bridge_ports"] += " ens7f0np0"
    assert physical_ports() == []
    assert guest_uplink(104) is None
    pve["bridges"]["pve1"]["vmbr1"]["bridge_ports"] = "ens7f1np1"
    assert switch_ports(now + timedelta(hours=1)) == []
    pve["configs"]["103"]["net0"] += ",link_down=1"
    assert switch_ports(now) == []
    assert physical_ports() == []


def test_switch_vlans_join_current_port_by_unique_ifindex(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": "sw", "name": "Switch", "kind": "switch"}]}
    base = {"source": "core", "collector_run_id": 11, "if_index": 5012}
    membership = {**base, "port_key": "physical:12", "observed_at": at, "vlan_id": 20,
                  "egress": 1, "untagged": 0, "pvid": 0}
    network = {"sources": [{"id": 1, "name": "core", "driver": "snmp_switch",
                            "driver_options": {"intent_stable_id": "sw"}}],
               "ports": [{**base, "port_key": "ifindex:5012", "name": "ge12",
                          "oper_status": "up", "last_seen_at": at}],
               "port_vlans": [membership, {**membership, "vlan_id": 1, "untagged": 1, "pvid": 1},
                              {**membership, "vlan_id": 99, "collector_run_id": 10}],
               "port_fdb_learned": [{**base, "port_key": "ifindex:5012", "observed_at": at,
                                     "learned_mac_count": 2, "partial": 0},
                                    {**base, "port_key": "alternate", "observed_at": at,
                                     "learned_mac_count": 0, "partial": 1}],
               "port_fdb_vlans": [{**base, "port_key": "ifindex:5012", "observed_at": at,
                                   "vlan_id": 30, "learned_mac_count": 2},
                                  {**base, "port_key": "ifindex:5012", "observed_at": at,
                                   "vlan_id": 99, "learned_mac_count": 4, "collector_run_id": 10}]}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
        return load_infrastructure_map(path, when)["nodes"][0]["ports"]

    assert read()[0]["vlanMemberships"] == {"checkedAt": at, "vlans": [
        {"id": 1, "egress": "untagged", "pvid": True}, {"id": 20, "egress": "tagged", "pvid": False},
    ]}
    assert read()[0]["fdbVlans"] == {"checkedAt": at, "vlans": [{"id": 30, "learnedMacCount": 2}]}
    assert read()[0]["fdbLearned"] == {"checkedAt": at, "learnedMacCount": 2, "partial": False}
    assert "vlanMemberships" not in read(now + timedelta(hours=1))[0]
    assert "fdbVlans" not in read(now + timedelta(hours=1))[0]
    assert "fdbLearned" not in read(now + timedelta(hours=1))[0]
    network["ports"].append({**network["ports"][0], "port_key": "alternate", "name": "ge13"})
    assert all("vlanMemberships" not in port for port in read())
    assert read()[1]["fdbLearned"] == {"checkedAt": at, "learnedMacCount": 0, "partial": True}
    network["port_fdb_learned"][1]["collector_run_id"] = 10
    assert "fdbLearned" not in read()[1]


def test_port_counter_audit_includes_peer_evidence_in_map_and_mcp(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    nodes = [{"id": "core", "name": "Core", "kind": "Коммутатор", "ports": [
        {"name": f"ge{index}", "state": "up", "checkedAt": at,
         "telemetry": {"checkedAt": at, "intervalSeconds": 60, "rxErrors": 2}}
        for index in range(1, 5)
    ]}]
    nodes.extend({"id": name, "name": name.title(), "kind": "Коммутатор"}
                 for name in ("live", "recorded", "pending"))
    nodes[1]["ports"] = [{"name": "eth1", "key": "physical:1", "state": "up", "checkedAt": at}]
    links = []
    for index, peer, confirmed, source in ((1, "live", True, "LLDP UI_VPN"),
                                           (2, "recorded", True, "GitHub"),
                                           (3, "pending", False, "GitHub")):
        links.append({"a": "core", "b": peer, "kind": "Сетевое соединение", "confirmed": confirmed,
                      "portEvidence": [{"a": f"ge{index}", "b": "eth1", "source": source,
                                        "confirmed": confirmed, "at": at if index == 1 else None,
                                        **({"pairEvidence": "verified_inventory",
                                            "inventorySources": [{"path": "evidence/manual/verified.md",
                                                                  "observedOn": now.date().isoformat()}]}
                                           if index == 2 else {})}]})
    links[0]["portEvidence"].append({**links[1]["portEvidence"][0], "a": "ge1", "b": "Port1"})
    path = tmp_path / "map.json"
    path.write_text(json.dumps({"schema": 1, "snapshotAt": at, "nodes": nodes, "links": links}), encoding="utf-8")
    graph = load_infrastructure_map(path, now)
    audit = graph["portCounterAudit"]
    assert summarize_topology(graph)["topologyAudit"]["portCounterAudit"] == audit
    assert audit["affectedPorts"] == 4
    for index, (peer, evidence) in enumerate((("live", "current"), ("recorded", "verified_inventory"),
                                              ("pending", "unconfirmed")), start=1):
        scoped = summarize_topology(graph, node_id="core", port_name=f"ge{index}")["topologyAudit"]
        row = audit["ports"][index - 1]
        assert scoped["portCounterAudit"]["ports"] == [row]
        assert row["peers"] == [{"id": peer, "name": peer.title(), "port": "eth1", "evidence": evidence}]
    assert "peers" not in audit["ports"][3]


def test_switch_port_telemetry_requires_matching_current_collection(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": "sw", "name": "Switch", "kind": "switch"}]}
    sample = {"source": "core", "port_key": "physical:7", "collector_run_id": 11, "observed_at": at,
              "sample_interval_seconds": 300, "rx_bps": 250000, "tx_bps": 0, "in_errors_delta": 2}
    network = {"sources": [{"id": 1, "name": "core", "driver": "snmp_switch", "enabled": True,
                            "driver_options": {"intent_stable_id": "sw"}}],
               "ports": [{"source": "core", "port_key": "physical:7", "name": "Port7",
                          "collector_run_id": 11, "oper_status": "up", "last_seen_at": at,
                          "rxErrorCounters": {"checkedAt": at, "ifInErrors": 44, "fcsErrors": 0,
                                              "pauseOperMode": "disabled", "rxPauseFrames": 0, "txPauseFrames": 17,
                                              "alignmentErrors": -1, "unrecognized": 1}}],
               "port_telemetry": [sample], "empty_vlan_collections": {"core": at}}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
        graph = load_infrastructure_map(path, when)
        audit = summarize_topology(graph)["topologyAudit"]["portCounterAudit"]
        assert graph["portCounterAudit"] == audit
        assert summarize_topology(graph, node_id="sw", port_name="port7")["topologyAudit"]["portCounterAudit"] == audit
        assert summarize_topology(graph, node_id="sw", port_name="port8")["topologyAudit"]["portCounterAudit"] == {
            "measuredPorts": 0, "affectedPorts": 0, "ports": [],
        }
        return graph["nodes"][0]["ports"][0], audit

    port, audit = read()
    assert port["vlanCollection"] == {"state": "empty", "checkedAt": at}
    network["empty_vlan_collections"]["core"] = (now - timedelta(seconds=1)).isoformat()
    assert "vlanCollection" not in read()[0]
    assert port["telemetry"] == {"checkedAt": at, "intervalSeconds": 300,
                                 "rxBps": 250000, "txBps": 0, "rxErrors": 2}
    assert port["rxErrorCounters"] == {"checkedAt": at, "ifInErrors": 44, "fcsErrors": 0,
                                       "pauseOperMode": "disabled", "rxPauseFrames": 0, "txPauseFrames": 17}
    assert audit == {"measuredPorts": 1, "affectedPorts": 1, "ports": [
        {"deviceId": "sw", "deviceName": "Switch", "port": "Port7", "telemetry": port["telemetry"],
         "rxErrorCounters": port["rxErrorCounters"]},
    ]}
    assert read(now + timedelta(minutes=21))[1] == {"measuredPorts": 0, "affectedPorts": 0, "ports": []}
    assert "rxErrorCounters" not in read(now + timedelta(minutes=6))[0]
    assert "rxErrorCounters" not in read(now + timedelta(minutes=6))[1]["ports"][0]
    raw_port = network["ports"][0]
    raw_port["rxErrorCounters"]["checkedAt"] = (now - timedelta(seconds=1)).isoformat()
    assert "rxErrorCounters" not in read()[0]
    raw_port["rxErrorCounters"]["checkedAt"] = at
    raw_port["linkCheck"] = {"state": "down", "checkedAt": (now + timedelta(seconds=1)).isoformat()}
    assert "rxErrorCounters" not in read(now + timedelta(seconds=1))[0]
    raw_port.pop("linkCheck")
    sample["in_errors_delta"] = 0
    assert read()[1] == {"measuredPorts": 1, "affectedPorts": 0, "ports": []}
    sample["in_errors_delta"] = 2
    sample["collector_run_id"] = 10
    assert "telemetry" not in read()[0]
    assert read()[1]["measuredPorts"] == 0


def test_switch_rx_silence_requires_continuous_64_bit_samples_on_the_current_port(tmp_path):
    import sqlite3
    from app.infrastructure_collect import _read_rx_silence_windows
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment, summarize_topology

    now = datetime.now(timezone.utc)
    stamps = [(now - timedelta(seconds=offset)).isoformat() for offset in (600, 300, 0)]
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE switch_port_counter_samples (
        id INTEGER PRIMARY KEY, source_id INTEGER, port_key TEXT, collector_run_id INTEGER,
        if_index INTEGER, observed_at TEXT, octet_counter_bits INTEGER, sys_uptime_ticks INTEGER,
        in_octets TEXT, out_octets TEXT
    )""")
    for index, stamp in enumerate(stamps):
        conn.execute("INSERT INTO switch_port_counter_samples VALUES (?,1,'p1',?,7,?,64,?,'20',?)",
                     (index, index + 1, stamp, 60000 + index * 30000, str(1000 + index * 500)))
    telemetry = {"source_id": 1, "port_key": "p1", "collector_run_id": 3, "observed_at": stamps[-1],
                 "rx_bps": 0, "tx_bps": 500 * 8 / 300}

    def read(**changes):
        sample = {**telemetry, **changes}
        _read_rx_silence_windows(conn, [sample], now)
        return sample.get("rxSilence")

    silence = read()
    assert silence == {"startedAt": stamps[0], "checkedAt": stamps[-1],
                       "intervalCount": 2, "txBytes": 1000}
    assert read(collector_run_id=4) is None
    assert read(rx_bps=1) is None
    assert read(tx_bps=0) is None
    for column, value, restored in (("if_index", 8, 7), ("sys_uptime_ticks", 1, 90000),
                                     ("octet_counter_bits", 32, 64), ("in_octets", "19", "20")):
        conn.execute(f"UPDATE switch_port_counter_samples SET {column}=? WHERE id=1", (value,))
        assert read() is None
        conn.execute(f"UPDATE switch_port_counter_samples SET {column}=? WHERE id=1", (restored,))

    path = tmp_path / "map.json"
    raw_port = {"name": "xe1", "state": "up", "checkedAt": stamps[-1],
                "telemetry": {"checkedAt": stamps[-1], "intervalSeconds": 300, "rxBps": 0, "txBps": 10},
                "rxSilence": silence}
    raw = {"schema": 1, "snapshotAt": stamps[-1], "nodes": [
        {"id": "sw", "name": "SNR", "kind": "Коммутатор", "ports": [raw_port]},
        {"id": "pbs", "name": "PBS", "kind": "Сервер"},
    ], "links": [{"a": "sw", "b": "pbs", "kind": "Сетевое соединение", "portEvidence": [
        {"a": "xe1", "b": "", "source": "GitHub", "confirmed": False},
    ]}]}

    def graph(when=now):
        path.write_text(json.dumps(raw), encoding="utf-8")
        return load_infrastructure_map(path, when)

    assert graph()["nodes"][0]["ports"][0]["rxSilence"] == silence
    pending, = summarize_topology(graph())["topologyAudit"]["pending"]
    assert pending["portObservations"]["a"]["rxSilence"] == silence
    host, = summarize_guest_attachment(graph(), "pbs")["attachment"]["physicalHosts"]
    connection, = host["connections"]
    report, = connection["ports"]
    assert report["portStates"]["peer"]["telemetry"] == raw_port["telemetry"]
    assert report["portStates"]["peer"]["rxSilence"] == silence
    audit = graph()["portRxSilenceAudit"]
    assert audit == {"total": 1, "ports": [{"deviceId": "sw", "deviceName": "SNR", "port": "xe1", "rxSilence": silence,
                                          "pendingPeers": [{"id": "pbs", "name": "PBS", "port": ""}]}]}
    assert summarize_topology(graph())["topologyAudit"]["portRxSilenceAudit"] == audit
    assert summarize_topology(graph(), node_id="sw")["topologyAudit"]["portRxSilenceAudit"] == audit
    assert summarize_topology(graph(), node_id="sw", port_name="XE1")["topologyAudit"]["portRxSilenceAudit"] == audit
    assert summarize_topology(graph(), node_id="pbs")["topologyAudit"]["portRxSilenceAudit"] == {"total": 0, "ports": []}
    raw["links"][0]["portEvidence"][0]["a"] = "xe2"
    assert "pendingPeers" not in graph()["portRxSilenceAudit"]["ports"][0]
    later = now + timedelta(seconds=1)
    raw_port["linkCheck"] = {"state": "down", "checkedAt": later.isoformat()}
    port = graph(later)["nodes"][0]["ports"][0]
    assert port["state"] == "down" and "rxSilence" not in port
    assert graph(later)["portRxSilenceAudit"] == {"total": 0, "ports": []}


def test_rx_error_diagnostics_poll_only_matching_affected_ports(monkeypatch):
    import asyncio
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    ports = [{"source": "core", "port_key": name, "name": name, "if_index": index,
              "last_seen_at": at, "collector_run_id": 11, "oper_status": "up"}
             for index, name in enumerate(("ge1", "ge2", "ge3"), 1)]
    ports.append({**ports[0], "port_key": "physical:1", "collector_run_id": 10})
    telemetry = [{"source": "core", "port_key": port["port_key"], "collector_run_id": run,
                  "observed_at": at, "in_errors_delta": count}
                 for port, run, count in zip(ports, (11, 10, 11), (2, 9, 0))]
    network = {"sources": [{"name": "core", "enabled": True, "driver": "snmp_switch"}],
               "ports": ports, "port_telemetry": telemetry}

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def read(transport, index, name):
        assert (index, name) == (1, "ge1")
        return {"ifInErrors": 44, "fcsErrors": 0}

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda source: Transport())
    monkeypatch.setattr(collector, "read_interface_rx_error_counters", read)
    asyncio.run(collector._collect_switch_rx_errors(network, now))
    assert ports[0]["rxErrorCounters"]["fcsErrors"] == 0
    assert all("rxErrorCounters" not in port for port in ports[1:])


def test_collection_reads_source_registry_without_syncing_config(monkeypatch):
    from app import infrastructure_collect as collector
    from contextlib import contextmanager

    calls = []

    class ReadConnection:
        def execute(self, statement):
            assert statement.lstrip().startswith("SELECT")
            return []

        def close(self):
            calls.append("closed")

    connection = ReadConnection()

    @contextmanager
    def snapshot(url):
        calls.append("snapshot")
        yield connection
        connection.close()

    def switch_page(kind, conn, *, limit, offset):
        assert conn is connection and calls[0] == "snapshot" and "closed" not in calls
        calls.append((kind, offset))
        return {"items": [], "pagination": {"next_offset": 500 if kind == "ports" and offset == 0 else None}}

    def netctl(args, **kwargs):
        payloads = {
            ("switches", "status"): {"switches": []},
            ("topology", "links"): {"links": []},
            ("hosts", "export"): {"hosts": []},
        }
        return payloads[tuple(args[:2])]

    monkeypatch.setattr(collector, "read_context_snapshot", snapshot)
    monkeypatch.setattr(collector, "query_switch_ports", lambda conn, **kw: switch_page("ports", conn, **kw))
    monkeypatch.setattr(collector, "query_switch_lldp_neighbors", lambda conn, **kw: switch_page("lldp", conn, **kw))
    monkeypatch.setattr(collector, "query_switch_stp", lambda conn, **kw: switch_page("stp", conn, **kw))
    monkeypatch.setattr(collector, "list_sources", lambda conn: [{"id": 1, "name": "test"}])
    monkeypatch.setattr(collector, "query_confirmed_attachment_ports", lambda conn: [])
    monkeypatch.setattr(collector, "run_netctl", netctl)
    assert collector.read_network()["sources"] == [{"id": 1, "name": "test"}]
    assert calls == ["snapshot", ("ports", 0), ("ports", 500), ("lldp", 0), ("stp", 0), "closed"]


def test_ipsec_phase_two_requires_expected_peers_and_both_policy_directions(tmp_path):
    from app.infrastructure_collect import build_graph, publish_snapshot
    from app.infrastructure_map import load_infrastructure_map, summarize_services

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    local, remote = "192.0.2.0/24", "198.51.100.0/24"
    feature = {"id": "office-tunnel", "kind": "policy_based_ipsec", "local_device": "left", "remote_device": "right",
               "central_peer": {"name": "office"}, "remote_peer": {"name": "main"}, "policy_destinations": [local]}
    context = {"devices": [{"id": name, "name": name, "kind": "router"} for name in ("left", "right")],
               "features": [feature], "segments": [{"id": "office-lan", "cidr": remote}]}
    binding = {"ipsec_links": {"office-tunnel": {"label": "IPsec", "local_source": "local-router",
               "remote_source": "remote-router", "remote_segment": "office-lan"}}}
    policy = {"action": "encrypt", "tunnel": True, "established": True}
    reply = {**policy, "peer": "main", "src_address": remote, "dst_address": local}
    network = {"sources": [
        {"name": "local-router", "driver": "mikrotik_api", "driver_options": {"intent_stable_id": "left"}},
        {"name": "remote-router", "driver": "mikrotik_api", "driver_options": {"intent_stable_id": "right"}},
    ], "ipsec": {
        "local-router": {"at": at, "policies": [{**policy, "peer": "office", "src_address": local, "dst_address": remote}]},
        "remote-router": {"at": at, "policies": [reply]},
    }}

    def build():
        graph = build_graph(context, network, {}, {}, binding, now)
        node = next(n for n in graph["nodes"] if n["id"] == "ipsec:office-tunnel")
        return graph, node["reachability"]["state"]

    graph, state = build()
    assert state == "reachable"
    assert {e["a"] for e in graph["links"] if e["b"] == "ipsec:office-tunnel" and e["confirmed"]} == {"left", "right"}
    reply["peer"] = "another-peer"
    graph, state = build()
    assert state == "unreachable"
    path = tmp_path / "infrastructure.json"
    publish_snapshot(path, graph)
    issue, = summarize_services(load_infrastructure_map(path, now))["serviceAudit"]["services"][0]["issues"]
    assert issue["required"] is True and issue["target"] == local
    assert issue["ipsecPolicy"] == {"remoteNetwork": remote, "directions": [
        {"source": "local-router", "state": "reachable", "checkedAt": at},
        {"source": "remote-router", "state": "unreachable", "checkedAt": at, "reason": "ipsec_policy_missing"},
    ]}
    reply.update(peer="main", established=False)
    graph, state = build()
    assert state == "unreachable"
    service = next(n for n in graph["nodes"] if n["id"] == "ipsec:office-tunnel")
    assert service["serviceChecks"][0]["ipsecPolicy"]["directions"][1]["reason"] == "ipsec_phase2_not_established"
    network["ipsec"].pop("remote-router")
    assert build()[1] == "unknown"


def test_ipsec_path_checks_explicit_sources_in_both_directions(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    context = {"devices": [
        {"id": "ui", "name": "UI", "kind": "server", "management_ip": "192.0.2.30"},
        {"id": "left", "name": "Central", "kind": "router"},
        {"id": "right", "name": "Branch", "kind": "router", "management_ip": "198.51.100.1"},
    ], "features": [
        {"id": "office", "kind": "policy_based_ipsec", "local_device": "left", "remote_device": "right",
         "policy_destinations": ["192.0.2.0/24"], "central_peer": {"name": "branch"}, "remote_peer": {"name": "central"}},
    ], "segments": [{"id": "branch-lan", "cidr": "198.51.100.0/24"}]}
    configured = {"office": {"label": "IPsec phase 2", "local_source": "center", "remote_source": "branch",
                              "remote_segment": "branch-lan", "connectivity": {"asset": "ui", "label": "ICMP link"}}}
    sources = [
        {"name": "center", "driver": "mikrotik_api", "enabled": True, "driver_options": {"intent_stable_id": "left"}},
        {"name": "branch", "driver": "mikrotik_ssh", "enabled": True, "host": "198.51.100.1",
         "driver_options": {"intent_stable_id": "right"}},
    ]
    calls = []
    class Remote:
        def ping_ipv4(self, address, source):
            calls.append(("branch", address, source))
            return True

    monkeypatch.setattr(collector, "legacy_driver_for", lambda *_: Remote())
    monkeypatch.setattr(collector, "load_secrets", lambda: {})
    monkeypatch.setattr(collector, "probe_icmp", lambda address, *, source_ip: calls.append(("ui", address, source_ip)) or True)
    observations = collector._collect_ipsec_connectivity(context, sources, configured)
    assert calls == [("ui", "198.51.100.1", "192.0.2.30"), ("branch", "192.0.2.30", "198.51.100.1")]
    graph = collector.build_graph(context, {"sources": sources, "ipsec_connectivity": observations},
                                  {}, {}, {"ipsec_links": configured}, datetime.now(timezone.utc))
    path = next(n for n in graph["nodes"] if n["id"] == "ipsec:office:connectivity")
    assert path["reachability"]["state"] == "reachable"
    assert [c["target"] for c in path["serviceChecks"]] == ["198.51.100.1", "192.0.2.30"]
    phase = next(n for n in graph["nodes"] if n["id"] == "ipsec:office")
    assert phase["reachability"]["state"] == "unknown"
    context["devices"][0]["management_ip"] = "203.0.113.30"
    assert collector._collect_ipsec_connectivity(context, sources, configured) == {}
    assert len(calls) == 2
    context["devices"][0]["management_ip"] = "192.0.2.30"
    failed = {"branch": {"reason": "ipsec_ssh_unavailable", "failedAt": datetime.now(timezone.utc).isoformat()}}
    forward, reverse = collector._collect_ipsec_connectivity(context, sources, configured, failed)["office"]
    assert forward["state"] == "reachable"
    assert reverse["state"] == "unknown" and reverse["reason"] == "icmp_source_ssh_unavailable"
    assert calls[2:] == [("ui", "198.51.100.1", "192.0.2.30")]


def test_routeros_ipsec_policy_read_requires_recognizable_rows(monkeypatch):
    import pytest
    from netctl.drivers.mikrotik_ssh import MikroTikSshDriver

    driver = MikroTikSshDriver({"host": "198.51.100.1", "username": "observer"}, {})
    template = '0 T * src-address=::/0 dst-address=::/0 template=yes'
    policy = ('1 A peer=central src-address=198.51.100.0/24 dst-address=192.0.2.0/24 '
              'tunnel=yes action=encrypt ph2-count=1')
    for output in ("", "Flags: T - template", template + "\n1 A peer=central", policy.replace("peer=central ", "")):
        monkeypatch.setattr(driver, "_run_read", lambda _, output=output: output)
        with pytest.raises(ValueError, match="policy table"):
            driver.read_ipsec_policies()
    monkeypatch.setattr(driver, "_run_read", lambda _: template)
    assert driver.read_ipsec_policies() == []
    monkeypatch.setattr(driver, "_run_read", lambda _: template + "\n" + policy)
    row, = driver.read_ipsec_policies()
    assert row["peer"] == "central" and row["established"]


def test_routeros_ping_uses_one_packet_and_rejects_injected_addresses(monkeypatch):
    from types import SimpleNamespace
    import pytest
    from netctl.drivers import mikrotik_ssh

    calls = []
    def run(args, **kwargs):
        calls.append(args[-1])
        return SimpleNamespace(returncode=0, stdout="sent=1 received=1 packet-loss=0%")

    monkeypatch.setattr(mikrotik_ssh.subprocess, "run", run)
    driver = mikrotik_ssh.MikroTikSshDriver({"host": "198.51.100.1", "username": "observer"}, {})
    assert driver.ping_ipv4("192.0.2.30", "198.51.100.1")
    with pytest.raises(ValueError):
        driver.ping_ipv4("192.0.2.30 count=100", "198.51.100.1")
    assert calls == ["/ping address=192.0.2.30 src-address=198.51.100.1 count=1"]


def test_port_comparison_uses_speed_measurement_times():
    from app.infrastructure_map import _compare_link_ports

    now = datetime.now(timezone.utc)
    older = (now - timedelta(minutes=3)).isoformat()
    recent = (now - timedelta(seconds=20)).isoformat()
    ports = {
        "a": {"state": "up", "speedBps": 10**9, "checkedAt": older, "speedCheckedAt": recent},
        "b": {"state": "up", "speedBps": 10**8, "checkedAt": now.isoformat()},
    }
    assert _compare_link_ports(ports) == {"state": "speed_mismatch", "checkedAt": recent}
    ports["a"]["speedCheckedAt"] = older
    assert _compare_link_ports(ports) == {}
    ports["a"]["checkedAt"] = recent
    assert _compare_link_ports(ports) == {"state": "both_up", "checkedAt": recent}
    ports["a"].update(state="down", speedCheckedAt=older)
    assert _compare_link_ports(ports) == {"state": "one_down", "checkedAt": recent}


def test_routeros_speed_has_its_own_freshness_and_preserves_telemetry():
    from app.infrastructure_map import _public_port

    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(minutes=4)).isoformat()
    row = {
        "name": "ether6", "source": "RouterOS", "state": "up", "checkedAt": stamp,
        "routerLink": {"checkedAt": now.isoformat(), "speedBps": 10**9},
        "telemetry": {"checkedAt": stamp, "intervalSeconds": 60, "rxBps": 1200},
    }
    port = _public_port(row, now)
    assert port["speedBps"] == 10**9 and port["speedCheckedAt"] == now.isoformat()
    assert port["telemetry"]["checkedAt"] == stamp
    stale = _public_port(row, now + timedelta(minutes=6))
    assert stale["speedBps"] is None and "speedCheckedAt" not in stale
    assert _public_port({**row, "state": "down"}, now)["speedBps"] is None
    assert _public_port({**row, "checkedAt": now.isoformat()}, now)["speedBps"] == 10**9


def test_routeros_link_modes_poll_only_configured_active_ethernet(monkeypatch):
    from types import SimpleNamespace

    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    network = {
        "sources": [{"name": "main", "driver": "mikrotik_api", "enabled": 1}],
        "router_interfaces": [
            {"source": "main", "name": name, "type": kind, "running": running,
             "disabled": 0, "last_seen_at": now.isoformat()}
            for name, kind, running in (
                ("ether6", "ether", 1), ("ether7", "ether", 1), ("ether8", "ether", 0), ("bridge", "bridge", 1)
            )
        ],
    }

    def read(names):
        assert names == ["ether6"]
        return {"ether6": {"rate": "2.5Gbps", "full-duplex": "true", "auto-negotiation": "done"}}

    monkeypatch.setattr(collector, "load_secrets", lambda: {})
    monkeypatch.setattr(collector, "legacy_driver_for", lambda *_: SimpleNamespace(read_ethernet_link_modes=read))
    modes = collector._collect_router_link_modes(network, {"main": ["ether6", "ether8", "bridge"]})
    sample = modes.pop(("main", "ether6"))
    assert not modes and datetime.fromisoformat(sample.pop("checkedAt")) >= now
    assert sample == {"speedBps": 2_500_000_000, "duplex": "full", "autoNegotiation": True}


def test_transit_port_requires_direct_route_running_ethernet_and_neighbor_arp(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": name, "name": name, "kind": "router"} for name in ("rb", "coordinator")],
               "segments": [{"id": "transit", "cidr": "192.0.2.0/30", "local_address": "192.0.2.1", "gateway_device": "rb"}]}
    inventory_stamp = (now - timedelta(days=30)).isoformat()
    context["devices"][1]["observed_state"] = {"ipv4_interfaces": [
        {"name": "eth2", "address": "192.0.2.2/30", "observed_at": inventory_stamp,
         "source": "docs/coordinator.yaml"},
        {"name": "eth0", "address": "198.51.100.20/24", "observed_at": inventory_stamp},
    ]}
    binding = {"transit_links": {"transit": {"asset": "coordinator", "source": "main",
                                              "peer": "192.0.2.2", "label": "Transit"}}}
    network = {
        "sources": [{"id": 1, "name": "main", "driver": "mikrotik_api", "enabled": 1,
                     "driver_options": {"intent_stable_id": "rb"}}],
        "routes": [{"source": "main", "dst_address": "192.0.2.0/30", "gateway": "ether8", "immediate_gateway": "ether8",
                    "routing_table": "main", "active": 1, "disabled": 0, "dynamic": 1, "route_type": "unicast", "last_seen_at": at}],
        "router_interfaces": [{"source": "main", "name": "ether8", "type": "ether", "running": 1, "disabled": 0, "last_seen_at": at}],
        "router_port_telemetry": {("main", "ether8"): {"checkedAt": at, "intervalSeconds": 60,
                                                        "rxBps": 1200, "txBps": 2400}},
        "router_link_modes": {("main", "ether8"): {"checkedAt": at, "speedBps": 10**9, "duplex": "full"}},
        "arp": [{"ip": "192.0.2.2", "mac": "02:00:00:00:00:08", "source": "main", "interface": "ether8", "last_seen_at": at}],
    }

    def build():
        graph = build_graph(context, network, {}, {}, binding, now)
        service = next(n for n in graph["nodes"] if n["id"] == "transit:transit")
        edges = [e for e in graph["links"] if {e["a"], e["b"]} == {"rb", "coordinator"}]
        return service, edges

    service, (link,) = build()
    assert service["probeTargetIP"] == "192.0.2.2"
    assert link["confirmed"] and link["portEvidence"][0]["a"] == "ether8"
    assert link["portEvidence"][0]["b"] == ""
    sources = [{"path": "docs/coordinator.yaml", "observedOn": inventory_stamp[:10]}]
    assert link["portEvidence"][1] == {"a": "", "b": "eth2", "source": "GitHub", "at": inventory_stamp,
                                      "confirmed": False, "inventorySources": sources}

    def attachment(node_id, at=now):
        graph = build_graph(context, network, {}, {}, binding, now)
        transit = next(n for n in graph["nodes"] if n["id"] == "transit:transit")
        transit["serviceChecks"] = [{"source": "UI_VPN", "method": "ICMP", "state": "reachable",
                                     "target": "192.0.2.2", "checkedAt": now.isoformat()}]
        snapshot = tmp_path / "transit.json"
        snapshot.write_text(json.dumps(graph), encoding="utf-8")
        public = load_infrastructure_map(snapshot, at, include_guest_attachments=True)
        return summarize_guest_attachment(public, node_id)["attachment"]

    detail = attachment("transit:transit")
    path, = detail["servicePaths"]
    assert path["routerAttachment"] == {
        "routerId": "rb", "port": "ether8", "source": "MikroTik · ARP", "checkedAt": at,
        "portLink": {"state": "up", "speedBps": 10**9, "checkedAt": at, "speedCheckedAt": at,
                     "source": "RouterOS", "linkMode": {"checkedAt": at, "duplex": "full"}},
        "telemetry": {"checkedAt": at, "intervalSeconds": 60, "rxBps": 1200, "txBps": 2400},
        "archivedPeer": {"nodeId": "coordinator", "port": "eth2", "checkedAt": inventory_stamp,
                         "inventorySources": sources},
    }
    for host in detail["physicalHosts"]:
        connection, = host["connections"]
        assert connection["kind"] == "Транзитный сегмент"
        assert all("pairEvidence" not in report for report in connection["ports"])
    port, = attachment("rb")["servicePorts"]
    row, = port["services"]
    assert port["port"] == "ether8" and row["basis"] == ["router_arp"]
    assert row["probeEndpoints"] == [{"target": "192.0.2.2", "port": None, "method": "ICMP",
                                      "passed": 1, "failed": 0, "unconfirmed": 0, "lastCheckedByOutcome": {"passed": at}}]
    assert not attachment("transit:transit", now + timedelta(hours=1))["servicePaths"]
    network["arp"][0]["interface"] = "bridge1"
    assert build()[0]["probeTargetIP"] is None and build()[1] == []
    network["arp"][0]["interface"] = "ether8"
    network["routes"][0]["immediate_gateway"] = "192.0.2.1%ether8"
    assert build()[0]["probeTargetIP"] is None
    network["routes"][0]["immediate_gateway"] = "ether8"
    network["router_interfaces"][0]["running"] = 0
    assert build()[0]["probeTargetIP"] is None


def test_observed_fdb_resolves_ifindex_only_with_matching_live_port_collection():
    import sqlite3
    from contextlib import closing
    from app.infrastructure_collect import _read_downstream_fdb
    from netctl.switch_queries import query_observed_mac_ports

    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE network_sources (id INTEGER, enabled INTEGER);
            CREATE TABLE switch_ports (source_id INTEGER, port_key TEXT, collector_run_id INTEGER, oper_status TEXT);
            CREATE TABLE current_switch_fdb (source_id INTEGER, port_key TEXT, if_index INTEGER,
                collector_run_id INTEGER, mac TEXT, vlan_id INTEGER, last_seen_at TEXT, status TEXT);
            INSERT INTO network_sources VALUES (1, 1);
            INSERT INTO switch_ports VALUES (1, 'ifindex:49175', 5, 'up');
            INSERT INTO current_switch_fdb VALUES (1, 'physical:23', 49175, 5,
                '02:00:00:00:00:23', 1, '2026-11-11T18:36:04Z', 'learned');
        """)
        macs = {"02:00:00:00:00:23"}
        report, = query_observed_mac_ports(conn, macs)
        assert report["port_key"] == "ifindex:49175"
        assert query_observed_mac_ports(conn, macs, learned_only=True) == [report]
        conn.executescript("""
            ALTER TABLE switch_ports ADD name TEXT DEFAULT 'Ge23';
            ALTER TABLE switch_ports ADD last_seen_at TEXT DEFAULT '2026-11-11T18:36:04Z';
            ALTER TABLE switch_ports ADD admin_status TEXT DEFAULT 'up';
        """)
        sources = [{"id": 1, "name": "core", "host": "192.0.2.1", "driver": "snmp_switch", "enabled": True}]
        scopes = {"link": ("192.0.2.1", {"interface": "ge23"}, {})}
        assert _read_downstream_fdb(conn, sources, scopes) == {"link": {
            "source": "core", "at": "2026-11-11T18:36:04Z", "macs": ["02:00:00:00:00:23"],
        }}
        conn.execute("UPDATE switch_ports SET name='gigabitEthernet 1/0/23'")
        alias_scope = {"link": ("192.0.2.1", {"interface": "Gi1/0/23"}, {})}
        assert _read_downstream_fdb(conn, sources, alias_scope)["link"]["macs"] == list(macs)
        conn.execute("""INSERT INTO switch_ports VALUES
            (1, 'ifindex:49176', 5, 'up', 'Gi1/0/23', '2026-11-11T18:36:04Z', 'up')""")
        assert _read_downstream_fdb(conn, sources, alias_scope) == {}
        conn.execute("DELETE FROM switch_ports WHERE port_key='ifindex:49176'")
        conn.execute("UPDATE switch_ports SET name='Ge23'")
        conn.executescript("""
            INSERT INTO network_sources VALUES (2, 1);
            INSERT INTO switch_ports VALUES (2, 'ifindex:7', 8, 'up', 'Ge7', '2026-11-11T18:36:04Z', 'up');
            INSERT INTO current_switch_fdb VALUES (2, 'ifindex:7', 7, 8,
                '02:00:00:00:00:23', 1, '2026-11-11T18:36:04Z', 'learned');
        """)
        remote_source = {"id": 2, "name": "peer", "host": "192.0.2.2", "driver": "snmp_switch", "enabled": True}
        remote_scope = {"link": ("192.0.2.1", {"interface": "ge23"}, {"address": "192.0.2.2"})}
        assert _read_downstream_fdb(conn, [*sources, remote_source], remote_scope)["link"]["remote"] == {
            "source": "peer", "readings": [{"mac": "02:00:00:00:00:23", "name": "Ge7", "at": "2026-11-11T18:36:04Z"}],
        }
        conn.executescript("DELETE FROM current_switch_fdb WHERE source_id=2; DELETE FROM switch_ports WHERE source_id=2;")
        conn.execute("UPDATE switch_ports SET last_seen_at='2026-11-11T18:36:05Z'")
        assert _read_downstream_fdb(conn, sources, scopes) == {}
        conn.execute("UPDATE current_switch_fdb SET status='static'")
        assert query_observed_mac_ports(conn, macs, learned_only=True) == []
        assert query_observed_mac_ports(conn, macs) == [report]
        conn.execute("UPDATE switch_ports SET collector_run_id=6")
        assert query_observed_mac_ports(conn, macs) == []
        conn.execute("UPDATE switch_ports SET collector_run_id=5")
        conn.execute("INSERT INTO switch_ports(source_id, port_key, collector_run_id, oper_status) VALUES (1, 'physical:23', 4, 'up')")
        assert query_observed_mac_ports(conn, macs) == [report]
        conn.execute("UPDATE switch_ports SET collector_run_id=5, oper_status='down' WHERE port_key='physical:23'")
        assert query_observed_mac_ports(conn, macs) == []
        conn.execute("UPDATE current_switch_fdb SET port_key='lag:po1', if_index=100001, status='learned'")
        conn.execute("INSERT INTO switch_ports(source_id, port_key, collector_run_id, oper_status) VALUES (1, 'ifindex:100001', 5, 'up')")
        lag, = query_observed_mac_ports(conn, macs, learned_only=True)
        assert lag["port_key"] == "ifindex:100001"


def test_confirmed_attachment_requires_fdb_and_port_from_same_collection():
    import sqlite3
    from contextlib import closing
    from netctl.switch_queries import query_confirmed_attachment_ports

    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE network_sources (id INTEGER, enabled INTEGER);
            CREATE TABLE asset_interfaces (id INTEGER, mac TEXT, lifecycle TEXT);
            CREATE TABLE asset_attachment_resolutions (asset_interface_id INTEGER, selected_source_id INTEGER,
                selected_port_key TEXT, selected_vlan_key TEXT, correlation_run_id INTEGER, status TEXT);
            CREATE TABLE asset_attachment_candidates (asset_interface_id INTEGER, switch_source_id INTEGER,
                port_key TEXT, vlan_key TEXT, vlan_id INTEGER, correlation_run_id INTEGER,
                candidate_class TEXT, observed_at TEXT);
            CREATE TABLE switch_ports (source_id INTEGER, port_key TEXT, collector_run_id INTEGER, oper_status TEXT);
            CREATE TABLE current_switch_fdb (source_id INTEGER, port_key TEXT, if_index INTEGER,
                collector_run_id INTEGER, mac TEXT, vlan_key TEXT, status TEXT);
            INSERT INTO network_sources VALUES (1, 1);
            INSERT INTO asset_interfaces VALUES (2, '02:00:00:00:00:17', 'active');
            INSERT INTO asset_attachment_resolutions VALUES (2, 1, 'physical:17', '1', 50, 'confirmed');
            INSERT INTO asset_attachment_candidates VALUES (2, 1, 'physical:17', '1', 1, 50,
                'direct', '2026-11-11T20:40:00Z');
            INSERT INTO switch_ports VALUES (1, 'physical:17', 4, 'up');
            INSERT INTO current_switch_fdb VALUES (1, 'physical:17', 5017, 5,
                '02:00:00:00:00:17', '1', 'learned');
        """)
        assert query_confirmed_attachment_ports(conn) == []
        conn.execute("INSERT INTO switch_ports VALUES (1, 'ifindex:5017', 5, 'up')")
        report, = query_confirmed_attachment_ports(conn)
        assert report["port_key"] == "ifindex:5017"
        assert report["observed_at"] == "2026-11-11T20:40:00Z"
        conn.execute("UPDATE switch_ports SET collector_run_id=5, oper_status='down' WHERE port_key='physical:17'")
        assert query_confirmed_attachment_ports(conn) == []
        conn.execute("UPDATE switch_ports SET oper_status='up' WHERE port_key='physical:17'")
        report, = query_confirmed_attachment_ports(conn)
        assert report["port_key"] == "physical:17"
        conn.execute("UPDATE current_switch_fdb SET mac='02:00:00:00:00:18'")
        assert query_confirmed_attachment_ports(conn) == []


def test_local_asset_arp_requires_inventory_mac_and_a_configured_fdb_source(monkeypatch):
    from app import infrastructure_collect as collector

    mac = "02:00:00:00:00:01"
    router = {"id": "router", "management_ip": "192.0.2.10", "mac_addresses": [mac.upper()]}
    context = {"devices": [router, {**router, "id": "other", "management_ip": "192.0.2.11"}]}
    bindings = {"asset_local_arp": {"router": mac, "other": mac}, "asset_fdb_paths": {"router": "switch"}}
    observed = "matched"
    calls = []

    def probe(address, expected_mac):
        calls.append((address, expected_mac))
        return {"state": observed, "interface": "eth0"}

    monkeypatch.setattr(collector, "_local_arp_diagnostic", probe)
    rows = collector._collect_local_asset_arp(context, bindings)
    assert calls == [("192.0.2.10", mac)]
    assert rows[0]["source"] == "UI_VPN · локальный ARP" and rows[0]["interface"] == "eth0"
    fresh = datetime.now(timezone.utc)
    assert collector._arp_mappings(rows, fresh)["192.0.2.10"][0] == mac
    assert collector._arp_mappings([*rows, {**rows[0], "mac": "02:00:00:00:00:02"}], fresh) == {}
    observed = "different_mac"
    assert collector._collect_local_asset_arp(context, bindings) == []
    router["mac_addresses"] = []
    calls.clear()
    assert collector._collect_local_asset_arp(context, bindings) == []
    assert calls == []


def test_local_asset_arp_checks_independent_targets_concurrently(monkeypatch):
    from threading import Barrier

    from app import infrastructure_collect as collector

    devices = [
        {"id": f"switch-{index}", "management_ip": f"192.0.2.{index}",
         "mac_addresses": [f"02:00:00:00:00:{index:02d}"]}
        for index in (1, 2)
    ]
    bindings = {"asset_local_arp": {d["id"]: d["mac_addresses"][0] for d in devices},
                "asset_fdb_paths": {d["id"]: "upstream" for d in devices}}
    both_started = Barrier(2)

    def probe(_address, _mac):
        both_started.wait(timeout=3)
        return {"state": "matched", "interface": "eth0"}

    monkeypatch.setattr(collector, "_local_arp_diagnostic", probe)
    rows = collector._collect_local_asset_arp({"devices": devices}, bindings)
    assert [row["ip"] for row in rows] == [d["management_ip"] for d in devices]


def test_active_router_arp_supersedes_only_its_own_conflicting_cache(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    address, expected = "192.0.2.22", "02:00:00:00:00:05"
    context = {"devices": [{"id": "host", "management_ip": address, "mac_addresses": [expected]}]}
    bindings = {"asset_local_arp": {"host": expected},
                "asset_router_arp_refresh": {"host": {"source": "router", "interface": "bridge-lan"}}}
    local = {"ip": address, "mac": expected, "last_seen_at": at, "source": "UI_VPN · локальный ARP"}
    cache = {**local, "mac": "02:00:00:00:00:04", "source": "router", "interface": "bridge-lan"}
    other = {**cache, "interface": "bridge-other"}
    called = []
    reply = None

    def refresh(sources, source, interface, mac, *, address):
        called.append((source, interface, mac, address))
        return reply

    monkeypatch.setattr(collector, "_router_layer2_observation", refresh)
    network = {"sources": [], "arp": [cache.copy()]}
    collector._refresh_conflicting_asset_arp(context, network, bindings, now)
    assert called == []
    network["arp"].append(local.copy())
    collector._refresh_conflicting_asset_arp(context, network, bindings, now)
    assert collector._arp_mappings(network["arp"], now) == {}
    reply = {"checkedAt": at}
    network["arp"].append(other.copy())
    collector._refresh_conflicting_asset_arp(context, network, bindings, now)
    assert called == [("router", "bridge-lan", expected, address)] * 2
    assert network["arp"] == [{**cache, "mac": expected}, local, other]
    assert collector._arp_mappings(network["arp"], now) == {}
    assert collector._arp_mappings(network["arp"][:2], now)[address][0] == expected


def test_configured_asset_fdb_path_is_scoped_and_requires_a_unique_live_port(monkeypatch, tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment
    from app.infrastructure_service_probes import apply_service_probes

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    address, mac = "192.0.2.22", "02:00:00:00:00:23"
    context = {"devices": [{"id": "gateway", "name": "Gateway", "kind": "fxs_gateway",
                            "management_ip": address, "mac_addresses": [mac]}]}
    network = {
        "sources": [{"id": 1, "name": "access", "driver": "snmp_switch", "enabled": True},
                    {"id": 2, "name": "core", "driver": "snmp_switch", "enabled": True}],
        "arp": [{"ip": address, "mac": mac, "last_seen_at": at}],
        "ports": [{"source": "access", "port_key": "physical:23", "name": "Gi1/0/23",
                   "oper_status": "up", "last_seen_at": at, "collector_run_id": 1}],
        "port_telemetry": [{"source": "access", "port_key": "physical:23", "collector_run_id": 1,
                            "observed_at": at, "sample_interval_seconds": 300, "in_errors_delta": 3}],
        "asset_fdb": [{"source_id": 1, "mac": mac, "port_key": "physical:23", "vlan_id": 1, "observed_at": at},
                      {"source_id": 2, "mac": mac, "port_key": "physical:47", "vlan_id": 1, "observed_at": at}],
    }
    bindings = {"asset_fdb_paths": {"gateway": "access"}, "asset_ip_checks": {"gateway": address}}

    def links(at=now):
        return build_graph(context, network, {}, {}, bindings, at)["links"]

    path, = links()
    assert path["a"] == "observer:access" and path["b"] == "gateway"
    assert path["kind"] == "Путь по MAC-таблице" and path["confirmed"]
    learned = {"switchId": "observer:access", "deviceId": "gateway", "mac": mac}
    assert path["portEvidence"] == [{"a": "Gi1/0/23", "b": "", "source": "netctl FDB",
                                     "at": at, "confirmed": True, "vlan": 1, "learnedEndpoint": learned,
                                     "managementAddress": address}]
    monkeypatch.setattr("app.infrastructure_service_probes._icmp_check", lambda ip: {"state": "reachable", "roundTripMs": 0.5})
    graph = build_graph(context, network, {}, {}, bindings, now)
    gateway = next(node for node in graph["nodes"] if node["id"] == "gateway")
    apply_service_probes([gateway], {"gateway": [{"type": "icmp", "ip": address}]})
    assert gateway["reachability"]["method"] == "ICMP · ARP + FDB"
    assert gateway["serviceChecks"][0]["identityCheckedAt"] == at
    snapshot = tmp_path / "map.json"
    snapshot.write_text(json.dumps(graph), encoding="utf-8")
    public = load_infrastructure_map(snapshot)
    observed, = public["links"]
    evidence, = observed["portEvidence"]
    assert evidence["portStates"]["a"]["telemetry"]["rxErrors"] == 3
    assert evidence["learnedEndpoint"] == learned
    assert "pairEvidence" not in evidence
    host = summarize_guest_attachment(public, "gateway")["attachment"]
    observation, = host["servicePaths"]
    assert observation["switchAttachment"]["port"] == "Gi1/0/23"
    assert observation["state"] == "reachable" and observation["roundTripMs"] == 0.5
    gateway["serviceChecks"][0].update(state="unknown", reason="icmp_no_echo_reply")
    gateway["serviceChecks"][0].pop("roundTripMs")
    snapshot.write_text(json.dumps(graph), encoding="utf-8")
    timeout, = summarize_guest_attachment(load_infrastructure_map(snapshot), "gateway")["attachment"]["servicePaths"]
    assert timeout["state"] == "unknown" and timeout["reason"] == "icmp_no_echo_reply"
    assert "roundTripMs" not in timeout
    switch = summarize_guest_attachment(public, "observer:access")["attachment"]
    port, = switch["servicePorts"]
    check, = port["services"]
    assert check["id"] == "gateway" and check["basis"] == ["switch_mac"]
    assert check["probeEndpoints"] == [{"target": address, "port": None, "method": "ICMP · ARP + FDB",
                                       "passed": 1, "failed": 0, "unconfirmed": 0,
                                       "lastCheckedByOutcome": {"passed": observation["checkedAt"]}}]
    expired = load_infrastructure_map(snapshot, now + timedelta(hours=1))
    assert not summarize_guest_attachment(expired, "gateway")["attachment"].get("servicePaths")
    stale, = load_infrastructure_map(snapshot, now + timedelta(hours=1))["links"]
    assert "learnedEndpoint" not in stale["portEvidence"][0]
    assert links(now + timedelta(hours=1)) == []
    network["asset_fdb"].append({**network["asset_fdb"][0], "port_key": "physical:24"})
    assert links() == []
    network["asset_fdb"].pop()
    network["ports"][0]["oper_status"] = "down"
    assert links() == []
    network["ports"][0]["oper_status"] = "up"
    network["arp"][0]["mac"] = "02:00:00:00:00:24"
    assert links() == []
    graph = build_graph(context, network, {}, {}, bindings, now)
    assert "probeTargetIP" not in next(node for node in graph["nodes"] if node["id"] == "gateway")


def test_switch_management_interface_requires_matching_arp_and_snmp(tmp_path, monkeypatch):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map
    from app.infrastructure_service_probes import apply_service_probes

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    ip, mac = "192.0.2.22", "02:00:00:00:00:22"
    context = {"devices": [{"id": "core", "name": "Core", "kind": "switch", "management_ip": ip}]}
    source = {"id": 1, "name": "core-snmp", "host": ip, "driver": "snmp_switch", "enabled": True}
    port = {"source": "core-snmp", "port_key": "ifindex:15", "name": "vlan1", "oper_status": "up",
            "mac": mac, "last_seen_at": stamp}
    network = {"sources": [source], "ports": [port], "arp": [{"ip": ip, "mac": mac, "last_seen_at": stamp}]}
    bindings = {"switch_management_interfaces": {"core": "vlan1"},
                "asset_services": {"ssh": {"asset": "core", "label": "SSH", "require_network_identity": True}}}
    monkeypatch.setattr("app.infrastructure_service_probes._ssh_identification", lambda _: {"state": "reachable"})
    path = tmp_path / "map.json"

    def check():
        graph = build_graph(context, network, {}, {}, bindings, now)
        apply_service_probes(graph["nodes"], {"ssh": [{"type": "ssh_identification", "ip": ip, "port": 22}]})
        path.write_text(json.dumps(graph), encoding="utf-8")
        return next(n for n in load_infrastructure_map(path)["nodes"] if n["id"] == "ssh")["serviceChecks"][0]

    assert check()["managementInterface"] == {"name": "vlan1", "source": "SNMP · ARP"}
    port["mac"] = "02:00:00:00:00:23"
    assert check()["reason"] == "probe_target_unconfirmed"


@pytest.mark.parametrize("canonical", (False, True))
def test_asset_service_can_require_current_fdb_and_arp_identity(monkeypatch, tmp_path, canonical):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment
    from app.infrastructure_service_probes import apply_service_probes

    now = datetime.now(timezone.utc)
    observed = (now - timedelta(minutes=24)).isoformat()
    ip, mac = "192.0.2.22", "02:00:00:00:00:22"
    context = {"devices": [{"id": "recorder", "name": "Recorder", "kind": "video_recorder",
                            "management_ip": ip, "mac_addresses": [mac]}]}
    if canonical:
        context["services"] = [{"id": "recorder-web", "name": "Inventory Web", "device": "recorder"}]
    network = {"sources": [{"id": 1, "name": "switch", "driver": "snmp_switch", "enabled": True}],
               "ports": [{"source": "switch", "port_key": "ifindex:15", "name": "ge15", "oper_status": "up",
                          "last_seen_at": observed}],
               "arp": [{"ip": ip, "mac": mac, "last_seen_at": observed}],
               "asset_fdb": [{"source_id": 1, "mac": mac, "port_key": "ifindex:15", "vlan_id": 1,
                              "observed_at": observed}]}
    bindings = {"asset_fdb_paths": {"recorder": "switch"},
                "asset_services": {"recorder-web": {"asset": "recorder", "label": "Web", "require_network_identity": True}}}
    spec = {"type": "http", "ip": ip, "port": 80, "path": "/login", "body_contains": "login"}
    calls = []

    def probe(probe_spec):
        calls.append(probe_spec)
        return {"state": "reachable", "httpStatus": 200}

    monkeypatch.setattr("app.infrastructure_service_probes._http_probe", probe)
    snapshot = tmp_path / "map.json"

    def read(when=None):
        graph = build_graph(context, network, {}, {}, bindings, now)
        apply_service_probes(graph["nodes"], {"recorder-web": [spec]})
        service = next(node for node in graph["nodes"] if node["id"] == "recorder-web")
        service["serviceChecks"].append({**service["serviceChecks"][0], "target": "192.0.2.99",
                                         "supplemental": True, "required": False})
        snapshot.write_text(json.dumps(graph), encoding="utf-8")
        return next(node for node in load_infrastructure_map(snapshot, when)["nodes"] if node["id"] == "recorder-web")

    node = read()
    assert node["mapStatus"] == "ok" and node["serviceChecks"][0]["identityCheckedAt"] == observed
    assert node["name"] == ("Inventory Web" if canonical else "Web")
    graph = load_infrastructure_map(snapshot, include_guest_attachments=True)
    path, = summarize_guest_attachment(graph, "recorder-web")["attachment"]["servicePaths"]
    assert path["target"] == ip and path["port"] == 80
    assert path["path"] == "/login"
    switch = next(node for node in graph["nodes"] if node["id"] == "observer:switch")
    local_port, = [port for port in switch["ports"] if port["name"] == "ge15"]
    assert path["switchAttachment"] == {
        "switchId": "observer:switch", "port": "ge15", "source": "netctl FDB", "checkedAt": observed,
        "portLink": {key: local_port[key] for key in ("state", "speedBps", "checkedAt")},
    }
    assert "physicalPair" not in path and graph["servicePaths"]["recorder-web"] == [path]
    group, = summarize_guest_attachment(graph, "observer:switch")["attachment"]["servicePorts"]
    endpoint, = group["services"][0]["probeEndpoints"]
    assert group["port"] == "ge15" and endpoint["target"] == ip and endpoint["path"] == "/login"
    assert endpoint["responseCodes"] == [200]
    assert read(now + timedelta(minutes=2))["mapStatus"] == "unknown"
    stale = load_infrastructure_map(snapshot, now + timedelta(minutes=2), include_guest_attachments=True)
    assert "recorder-web" not in stale["servicePaths"]
    calls.clear()
    if canonical:
        bindings["asset_services"]["recorder-web"]["asset"] = "different-device"
        assert read()["serviceChecks"][0]["reason"] == "probe_target_unconfirmed"
        assert calls == []
        bindings["asset_services"]["recorder-web"]["asset"] = "recorder"
    network["asset_fdb"].clear()
    node = read()
    assert calls == []
    assert node["mapStatus"] == "unknown" and node["serviceChecks"][0]["reason"] == "probe_target_unconfirmed"


def test_management_path_includes_both_ports_only_for_unique_current_cable(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    address = "192.0.2.14"
    nodes = [
        {"id": "upstream", "name": "Upstream", "kind": "Коммутатор",
         "ports": [{"name": "gigabitEthernet 1/0/31", "state": "up", "checkedAt": at, "lldpNeighborCount": 2,
                    "lldpNeighbors": [
                        {"chassisId": "02:00:00:00:00:14", "inventoryDeviceId": "host",
                         "portId": "bond0", "portIdSubtype": "interface_name"},
                        {"chassisId": "02:00:00:00:00:15", "inventoryDeviceId": "other",
                         "portId": "eth1", "portIdSubtype": "interface_name"},
                    ]}]},
        {"id": "host", "name": "Host", "kind": "Коммутатор"},
        {"id": "other", "name": "Other switch", "kind": "Коммутатор"},
        {"id": "web", "name": "Web", "kind": "Сервис", "serviceChecks": [
            {"method": "HTTP", "state": "reachable", "source": "UI_VPN", "required": True,
             "checkedAt": at, "target": address, "port": 80},
        ]},
    ]
    observed = {"a": "upstream", "b": "host", "kind": "Путь по MAC-таблице", "confirmed": True,
                "portEvidence": [{"a": "gigabitEthernet 1/0/31", "b": "", "source": "netctl FDB",
                    "at": at, "confirmed": True, "managementAddress": address,
                    "learnedEndpoint": {"switchId": "upstream", "deviceId": "host", "mac": "02:00:00:00:00:14"}}]}
    hosted = {"a": "host", "b": "web", "kind": "Размещение", "confirmed": True}

    def cable(remote, source, **fields):
        return {"a": remote, "b": "upstream", "kind": "Сетевое соединение", "confirmed": True,
                "portEvidence": [{"a": "Gi1/0/47", "b": "Gi1/0/31", "source": source, "at": at,
                                  "confirmed": True, **fields}]}

    snapshot = tmp_path / "map.json"

    def read(*cables):
        raw = {"schema": 1, "snapshotAt": at, "nodes": nodes, "links": [observed, hosted, *cables]}
        snapshot.write_text(json.dumps(raw), encoding="utf-8")
        graph = load_infrastructure_map(snapshot, now, include_guest_attachments=True)
        service, = summarize_guest_attachment(graph, "web")["attachment"]["servicePaths"]
        assert graph["servicePaths"]["web"] == [service]
        return service["switchAttachment"]

    direct = cable("host", "LLDP · двустороннее")
    telemetry = {"checkedAt": at, "intervalSeconds": 300, "rxBps": 0, "txBps": 1250, "rxErrors": 12}
    switch_port = nodes[0]["ports"][0]
    counters = {"checkedAt": at, "ifInErrors": 120, "fcsErrors": 5}
    switch_port.update(telemetry=telemetry, rxErrorCounters=counters)
    path = read()
    assert path["telemetry"] == telemetry
    assert path["rxErrorCounters"] == counters
    switch_port["telemetry"] = {**telemetry, "checkedAt": (now - timedelta(minutes=20)).isoformat()}
    assert not {"telemetry", "rxErrorCounters"} & read().keys()
    assert path["lldpPeers"] == [{"localPort": "gigabitEthernet 1/0/31", "checkedAt": at,
                                  "chassisId": "02:00:00:00:00:14", "portId": "bond0",
                                  "portIdSubtype": "interface_name"}]
    assert "physicalPair" not in path
    assert read(direct)["physicalPair"] == {"hostId": "host", "hostPort": "Gi1/0/47", "switchPort": "Gi1/0/31",
                                            "source": "LLDP · двустороннее", "checkedAt": at}
    assert "physicalPair" not in read(cable("host", "GitHub"))
    assert "physicalPair" not in read(direct, cable("other", "LLDP · двустороннее"))
    assert "physicalPair" not in read(cable("host", "LLDP · двустороннее", at=(now - timedelta(hours=1)).isoformat()))
    nodes[1]["ports"] = [{"name": "Gi1/0/47", "state": "down", "checkedAt": at}]
    assert "physicalPair" not in read(direct)
    nodes[0]["ports"][0]["lldpNeighbors"][0]["chassisId"] = "02:00:00:00:00:16"
    assert "lldpPeers" not in read()


def test_controller_warns_for_errors_on_its_unambiguous_management_switch_port(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    telemetry = {"checkedAt": at, "intervalSeconds": 300, "rxErrors": 12}
    port = {"name": "ge4", "state": "up", "checkedAt": at, "telemetry": telemetry,
            "fdbLearned": {"learnedMacCount": 1, "partial": False, "checkedAt": at}}
    controller = {"id": "bmc", "name": "BMC", "kind": "Контроллер управления",
                  "reachability": {"state": "reachable", "source": "UI_VPN", "method": "ICMP · ARP + FDB", "checkedAt": at}}
    switch = {"id": "sw", "name": "Switch", "kind": "Коммутатор", "ports": [port]}
    evidence = {"a": "ge4", "b": "", "source": "netctl FDB", "at": at, "confirmed": True,
                "managementAddress": "192.0.2.14",
                "learnedEndpoint": {"switchId": "sw", "deviceId": "bmc", "mac": "02:00:00:00:00:14"}}
    link = {"a": "sw", "b": "bmc", "kind": "Путь по MAC-таблице", "source": "netctl FDB", "confirmed": True,
            "observedAt": at, "portEvidence": [evidence]}
    snapshot = tmp_path / "map.json"

    def read():
        raw = {"schema": 1, "snapshotAt": at, "nodes": [switch, controller], "links": [link]}
        snapshot.write_text(json.dumps(raw), encoding="utf-8")
        graph = load_infrastructure_map(snapshot, now)
        return next(node for node in graph["nodes"] if node["id"] == "bmc")

    node = read()
    assert node["mapStatus"] == "warn"
    assert node["reachability"]["state"] == "reachable"
    location = node["managementSwitchPort"]
    assert (location["switchId"], location["port"], location["source"], location["checkedAt"]) == ("sw", "ge4", "netctl FDB", at)
    assert "physicalPair" not in location and location["portLink"]["state"] == "up"
    assert node["managementPortErrors"] == {"switchId": "sw", "port": "ge4", "source": "netctl FDB",
                                            "checkedAt": at, "telemetry": telemetry}
    counters = {"checkedAt": at, "ifInErrors": 3145919, "fcsErrors": 0}
    port["rxErrorCounters"] = counters
    assert read()["managementPortErrors"]["rxErrorCounters"] == counters
    switch["properties"] = {"Источник сбора": "snr-s5210g-254"}
    port["key"] = "ifindex:5004"
    assert read()["managementPortErrors"]["history"] == {
        "source": "snr-s5210g-254", "interface": "ifindex:5004",
    }
    port["key"] = "invalid&interface=other"
    assert "history" not in read()["managementPortErrors"]
    port["fdbLearned"]["learnedMacCount"] = 2
    node = read()
    assert node["mapStatus"] == "ok" and node["managementSwitchPort"]["port"] == "ge4"
    port["fdbLearned"]["learnedMacCount"] = 1
    telemetry["rxErrors"] = 0
    telemetry["rxDiscards"] = 5
    assert "managementPortErrors" not in read()
    telemetry["rxErrors"] = 12
    controller["kind"] = "Видеорегистратор"
    node = read()
    assert node["mapStatus"] == "ok" and node["managementSwitchPort"]["port"] == "ge4"
    evidence["at"] = (now - timedelta(hours=1)).isoformat()
    assert "managementSwitchPort" not in read()


def test_hypervisor_fdb_path_reports_management_interface_without_claiming_direct_cable(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    earlier = (now - timedelta(minutes=1)).isoformat()
    address, mac = "192.0.2.11", "02:00:00:00:00:11"
    context = {"devices": [{"id": "pve1", "name": "pve1", "kind": "hypervisor",
                            "management_ip": address, "mac_addresses": [mac]}]}
    network = {"sources": [{"id": 1, "name": "core", "driver": "snmp_switch", "enabled": True}],
               "arp": [{"ip": address, "mac": mac, "last_seen_at": at}],
               "ports": [{"source": "core", "port_key": "physical:12", "name": "ge12",
                          "oper_status": "up", "last_seen_at": at}],
               "asset_fdb": [{"source_id": 1, "mac": mac, "port_key": "physical:12", "vlan_id": 1, "observed_at": at}]}
    pve = {"at": earlier, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"108": {"net0": "virtio=02:00:00:00:00:08,bridge=vmbr0"}},
           "bridges": {"pve1": {"vmbr0": {"active": 1, "bridge_ports": "enp134s0"}}},
           "activePorts": {"pve1": ["enp134s0"]},
           "management": {"pve1": {"address": address, "port": "enp134s0"}}}
    bindings = {"asset_fdb_paths": {"pve1": "core"}, "asset_services": {
        "pve1-management": {"asset": "pve1", "label": "PVE1", "require_network_identity": True},
    }}

    def proof(identity_at=earlier):
        graph = build_graph(context, network, {}, pve, bindings, now)
        service = next(node for node in graph["nodes"] if node["id"] == "pve1-management")
        assert service["probeTargetIP"] == (address if identity_at else None)
        assert service.get("probeTargetIdentityAt") == identity_at
        path, = [edge for edge in graph["links"] if edge["a"] == "observer:core"]
        assert path["kind"] == "Путь по MAC-таблице" and path["confirmed"]
        report, = path["portEvidence"]
        return report

    def guest_uplink(rendered_at=now):
        raw = build_graph(context, network, {}, pve, bindings, now)
        path = tmp_path / "infrastructure.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        graph = load_infrastructure_map(path, rendered_at)
        placement = next(link for link in graph["links"] if link["b"] == "pve-guest:108")
        virtual = placement["portEvidence"][0]["virtual"]
        assert virtual["switchPorts"] == []
        return virtual.get("switchUplink")

    assert proof() == {"a": "ge12", "b": "enp134s0", "source": "netctl FDB + Proxmox",
                       "at": earlier, "confirmed": True, "vlan": 1, "managementAddress": address,
                       "learnedEndpoint": {"switchId": "observer:core", "deviceId": "pve1", "mac": mac}}
    assert guest_uplink() == {"id": "observer:core", "port": "ge12", "at": earlier, "viaMacTable": True}
    assert guest_uplink(now + timedelta(minutes=25)) is None
    context["devices"][0].pop("mac_addresses")
    network["hosts"] = [{"ip": address, "mac": mac, "last_seen_at": at}]
    assert proof()["b"] == "enp134s0"
    context["devices"][0]["mac_addresses"] = [mac]
    pve["activePorts"]["pve1"] = []
    assert guest_uplink() is None
    pve["activePorts"]["pve1"] = ["enp134s0"]
    context["devices"].append({"id": "router", "name": "Other router", "kind": "router"})
    network["lldp"] = [{"source": "core", "local_port_key": "physical:12",
                        "system_name": "Other router", "observed_at": at}]
    assert guest_uplink() is None
    del network["lldp"]
    pve["management"]["pve1"]["address"] = "192.0.2.12"
    fallback = proof(None)
    assert fallback["b"] == "" and fallback["source"] == "netctl FDB"
    assert guest_uplink() is None
    pve["management"]["pve1"]["address"] = address
    pve["at"] = (now - timedelta(hours=1)).isoformat()
    assert proof(None)["b"] == ""


def test_transit_peer_management_port_requires_fresh_arp_fdb_and_active_ethernet(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment, summarize_services, summarize_topology

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    address, mac = "198.51.100.20", "02:00:00:00:00:07"
    inventory_stamp = (now - timedelta(days=30)).isoformat()
    context = {"devices": [{"id": "rb", "name": "RB", "kind": "router"},
                           {"id": "coordinator", "name": "Coordinator", "kind": "security_gateway",
                            "management_ip": address, "observed_state": {"ipv4_interfaces": [
                                {"name": "eth0", "address": address + "/24", "observed_at": inventory_stamp,
                                 "source": "docs/coordinator.yaml"},
                                {"name": "eth2", "address": "192.0.2.2/30", "observed_at": inventory_stamp},
                            ]}}],
               "services": [{"id": "coordinator-web", "name": "Coordinator web", "device": "coordinator"}],
               "segments": [{"id": "transit", "cidr": "192.0.2.0/30",
                             "local_address": "192.0.2.1", "gateway_device": "rb"}]}
    bindings = {"transit_links": {"transit": {"asset": "coordinator", "source": "main",
                                            "peer": "192.0.2.2", "label": "Transit", "lan_bridge": "bridge-lan",
                                            "lan_port": "ether7"}},
                "asset_services": {"coordinator-web": {"asset": "coordinator", "require_network_identity": True}}}
    learned = {"source": "main", "mac": mac, "bridge": "bridge-lan", "interface": "ether7", "last_seen_at": at}
    network = {
        "sources": [{"name": "main", "driver": "mikrotik_api", "enabled": 1,
                     "driver_options": {"intent_stable_id": "rb"}}],
        "arp": [{"source": "main", "ip": address, "mac": mac, "interface": "bridge-lan", "last_seen_at": at}],
        "router_bridge_hosts": [learned],
        "router_interfaces": [{"source": "main", "name": "ether7", "type": "ether",
                               "running": 1, "disabled": 0, "last_seen_at": at},
                              {"source": "main", "name": "ether9", "type": "ether",
                               "running": 0, "disabled": 1, "last_seen_at": at},
                              {"source": "main", "name": "bridge-lan", "type": "bridge",
                               "running": 1, "disabled": 0, "last_seen_at": at}],
    }
    path = tmp_path / "graph.json"

    def lan(at=now, public_at=now):
        graph = build_graph(context, network, {}, {}, bindings, at)
        service = next(node for node in graph["nodes"] if node["id"] == "coordinator-web")
        service["serviceChecks"] = [{"source": "UI_VPN", "method": "HTTPS", "port": 8080,
                                     "state": "reachable", "checkedAt": at.isoformat(), "target": ip}
                                    for ip in (address, "192.0.2.2")]
        path.write_text(json.dumps(graph), encoding="utf-8")
        return [e for e in load_infrastructure_map(path, public_at)["links"] if e["a"] == "rb" and e["b"] == "coordinator"]

    def target_identity():
        graph = build_graph(context, network, {}, {}, bindings, now)
        service = next(node for node in graph["nodes"] if node["id"] == "coordinator-web")
        return service["probeTargetIP"], service.get("probeTargetIdentityAt")

    assert target_identity() == (address, at)
    bindings["transit_links"]["transit"]["lan_port"] = "ether9"
    assert target_identity() == (None, None)
    bindings["transit_links"]["transit"]["lan_port"] = "ether7"
    network["router_bridge_hosts"].append({**learned, "interface": "ether9"})
    assert target_identity() == (None, None)
    network["router_bridge_hosts"].pop()
    link, = lan()
    assert link["kind"] == "Путь по MAC-таблице" and link["confirmed"]
    expected = {"name": "ether7", "source": "RouterOS", "state": "up",
                "speedBps": None, "checkedAt": at, "stale": False}
    live, inventory = link["portEvidence"]
    assert live == {"a": "ether7", "b": "", "source": "MikroTik · ARP + FDB", "at": at,
                    "confirmed": True, "managementAddress": address, "portStates": {"a": expected}}
    sources = [{"path": "docs/coordinator.yaml", "observedOn": inventory_stamp[:10]}]
    assert inventory == {"a": "", "b": "eth0", "source": "GitHub", "at": inventory_stamp, "confirmed": False,
                         "inventorySources": sources}
    public = load_infrastructure_map(path, now, include_guest_attachments=True)
    audit = summarize_topology(public)["topologyAudit"]
    row, = audit["pending"]
    assert (row["a"], row["portA"], row["b"], row["portB"]) == ("rb", "ether7", "coordinator", "eth0")
    assert row["archivedPortSides"] == ["b"]
    assert row["inventorySources"] == sources
    assert row["observedPaths"] == [{"portA": "ether7", "portB": "", "source": "MikroTik · ARP + FDB", "checkedAt": at}]
    assert not any(audit["directLinks"].values())
    assert public["pendingPortPairs"][0]["archivedPortSides"] == ["b"]
    assert public["pendingPortPairs"][0]["archivedPortAt"] == {"b": inventory_stamp}
    assert public["pendingPortPairs"][0]["inventorySources"] == sources
    service_path, = summarize_guest_attachment(public, "coordinator-web")["attachment"]["servicePaths"]
    assert service_path == {"target": address, "port": 8080, "method": "HTTPS", "checkedAt": at,
                            "state": "reachable",
                            "addressCheckedAt": at, "routerAttachment": {"routerId": "rb", "port": "ether7",
                            "source": "MikroTik · ARP + FDB", "checkedAt": at,
                            "portLink": {"state": "up", "speedBps": None, "checkedAt": at, "source": "RouterOS"},
                            "archivedPeer": {"nodeId": "coordinator", "port": "eth0", "checkedAt": inventory_stamp,
                                             "inventorySources": sources}}}
    web = next(node for node in public["nodes"] if node["id"] == "coordinator-web")
    for check in web["serviceChecks"]:
        check.update(state="unreachable", required=True)
    issues = summarize_services(public, service_ids={"coordinator-web"})["serviceAudit"]["services"][0]["issues"]
    assert issues[0]["portObservation"] == {
        "nodeId": "rb", "port": "ether7", "source": "MikroTik · ARP + FDB", "checkedAt": at,
    }
    assert "portObservation" not in issues[1]
    reverse, = summarize_guest_attachment(public, "rb")["attachment"]["servicePorts"]
    coordinator = next(node for node in public["nodes"] if node["id"] == "coordinator")
    assert coordinator["managementRouterPaths"] == [{"address": address, **service_path["routerAttachment"]}]
    attachment = summarize_guest_attachment(public, "coordinator")["attachment"]
    assert attachment["managementRouterPaths"] == coordinator["managementRouterPaths"]
    endpoint, = reverse["services"][0]["probeEndpoints"]
    assert reverse["port"] == "ether7" and endpoint["target"] == address
    raw = json.loads(path.read_text(encoding="utf-8"))
    route = {"method": "Маршрут", "source": "Network Observer", "state": "reachable",
             "checkedAt": at, "target": "203.0.113.0/24", "via": address, "routeSource": "main",
             "required": True, "component": True}
    raw["nodes"].append({"id": "routing", "name": "Routing", "kind": "Сервис", "serviceChecks": [
        route, {**route, "target": "203.0.114.0/24", "routeSource": "other"},
        {**route, "target": "203.0.115.0/24", "state": "unreachable", "reason": "route_inactive"},
    ]})
    raw["links"].append({"a": "coordinator", "b": "routing", "kind": "Размещение", "confirmed": True})
    path.write_text(json.dumps(raw), encoding="utf-8")
    routed = load_infrastructure_map(path, now, include_guest_attachments=True)
    route_path, = summarize_guest_attachment(routed, "routing")["attachment"]["servicePaths"]
    assert route_path["target"] == route["target"] and route_path["via"] == address
    assert route_path["routerAttachment"] == service_path["routerAttachment"]
    ports = summarize_guest_attachment(routed, "rb")["attachment"]["servicePorts"]
    routing = next(item for item in ports[0]["services"] if item["id"] == "routing")
    assert [probe["target"] for probe in routing["probeEndpoints"]] == [route["target"]]
    path.write_text(json.dumps({**raw, "nodes": raw["nodes"][:-1], "links": raw["links"][:-1]}), encoding="utf-8")
    expired_audit = summarize_topology(load_infrastructure_map(path, now + timedelta(hours=1)))["topologyAudit"]
    assert expired_audit["pendingTotal"] == 0
    ports = next(node["ports"] for node in load_infrastructure_map(path, now)["nodes"] if node["id"] == "rb")
    assert ports == [expected, {**expected, "name": "ether9", "state": "disabled"}]
    expired = lan(public_at=now + timedelta(hours=1))[0]
    assert not expired["confirmed"]
    assert "portStates" not in expired["portEvidence"][0]
    assert lan(at=now + timedelta(hours=1), public_at=now + timedelta(hours=1)) == []
    speed_at = (now - timedelta(seconds=1)).isoformat()
    network["router_interfaces"][0]["last_seen_at"] = (now - timedelta(minutes=3)).isoformat()
    network["router_link_modes"] = {("main", "ether7"): {"checkedAt": speed_at, "speedBps": 10**9}}
    lan()
    public = load_infrastructure_map(path, now, include_guest_attachments=True)
    pending, = summarize_topology(public)["topologyAudit"]["pending"]
    for item in (pending, public["pendingPortPairs"][0]):
        port = item["portObservations"]["a"]
        assert port["speedBps"] == 10**9 and port["speedCheckedAt"] == speed_at
        assert port["checkedAt"] == network["router_interfaces"][0]["last_seen_at"]
        assert item["archivedPortSides"] == ["b"]
    network.pop("router_link_modes")
    network["router_interfaces"][0]["last_seen_at"] = at
    declared = context["devices"][1]["observed_state"]["ipv4_interfaces"]
    declared.append({**declared[0], "name": "eth3"})
    assert lan()[0]["portEvidence"] == [live]
    row, = summarize_topology(load_infrastructure_map(path, now))["topologyAudit"]["pending"]
    assert row["portB"] == "" and row["missingPortSides"] == ["b"]
    declared.pop()
    network["router_bridge_hosts"].append({**learned, "interface": "ether6"})
    assert lan() == []
    network["router_bridge_hosts"].pop()
    network["router_interfaces"][0]["running"] = 0
    assert lan() == []


def test_router_neighbor_table_is_scoped_to_one_live_port_and_never_confirms_a_pair(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": "rb", "name": "Router", "kind": "router"}]}
    network = {
        "sources": [{"name": "router", "driver": "mikrotik_ssh", "enabled": True,
                     "driver_options": {"intent_stable_id": "rb"}}],
        "router_interfaces": [
            {"source": "router", "name": name, "type": "ether", "running": running,
             "disabled": 0, "last_seen_at": at}
            for name, running in (("ether2", 1), ("ether3", 1), ("ether4", 0))
        ],
        "router_neighbors": [
            {"source": source, "interface": interfaces, "identity": "test-neighbor", "platform": "MikroTik",
             "address": "192.0.2.18", "mac": f"02:00:00:00:00:{index:02x}", "last_seen_at": checked}
            for index, (source, interfaces, checked) in enumerate((
                ("router", "ether2,bridge-lan", at),
                ("router", "ether2,ether3,bridge-lan", at),
                ("router", "ether4,bridge-lan", at),
                ("other", "ether2,bridge-lan", at),
                ("router", "ether2", (now - timedelta(minutes=1)).isoformat()),
            ), 1)
        ],
    }
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
    graph = load_infrastructure_map(path, now)
    assert graph["links"] == []
    ports = graph["nodes"][0]["ports"]
    assert ports[0]["routerNeighbors"] == {
        "checkedAt": at, "total": 1, "devices": [
            {"name": "test-neighbor", "platform": "MikroTik", "mac": "02:00:00:00:00:01", "address": "192.0.2.18"},
        ],
    }
    assert all("routerNeighbors" not in port for port in ports[1:])
    expired = load_infrastructure_map(path, now + timedelta(minutes=11))
    assert "routerNeighbors" not in expired["nodes"][0]["ports"][0]


def test_pppoe_internet_probe_requires_configured_public_targets_and_active_session(monkeypatch):
    from app import infrastructure_collect as collector

    calls = []
    session = {"name": "pppoe-out1", "parent": "ether1-wan", "running": True, "disabled": False}

    class Driver:
        def pppoe_interfaces(self):
            return [session]

        def ping_ipv4_via_interface(self, address, interface):
            calls.append((address, interface))
            return True

    monkeypatch.setattr(collector, "load_secrets", lambda: {})
    monkeypatch.setattr(collector, "legacy_driver_for", lambda *_: Driver())
    context = {"wan": [{"id": "uplink", "device": "rb", "interface": "pppoe-out1", "gateway": "pppoe_peer"}]}
    sources = [{"name": "router", "driver": "mikrotik_ssh", "enabled": True,
                "driver_options": {"intent_stable_id": "rb"}}]
    assert collector._collect_pppoe(context, sources, {"uplink": ["10.0.0.1"]})["router"]["internet"] == []
    sample = collector._collect_pppoe(context, sources, {"uplink": ["1.1.1.1"]})["router"]
    assert calls == [("1.1.1.1", "pppoe-out1")]
    assert sample["internet"][0]["received"] is True
    session["running"] = False
    assert collector._collect_pppoe(context, sources, {"uplink": ["1.1.1.1"]})["router"]["internet"] == []
    assert len(calls) == 1


def test_pppoe_wan_uses_live_session_and_keeps_physical_confirmation_separate(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {"devices": [{"id": "rb", "name": "Router", "kind": "router"}],
               "wan": [{"id": "uplink", "device": "rb", "interface": "pppoe-out1", "gateway": "pppoe_peer"}]}
    session = {"name": "pppoe-out1", "parent": "ether1-wan", "running": True, "disabled": False}
    network = {"sources": [{"name": "router", "driver": "mikrotik_ssh", "enabled": True,
                           "driver_options": {"intent_stable_id": "rb"}}],
               "pppoe": {"router": {"checkedAt": at, "interfaces": [session], "internet": [
                   {"session": "pppoe-out1", "target": "1.1.1.1", "received": True, "checkedAt": at},
                   {"session": "pppoe-out1", "target": "8.8.8.8", "received": False, "checkedAt": at},
               ]}},
               "router_interfaces": [{"source": "router", "name": "ether1-wan", "type": "ether",
                                      "running": 1, "disabled": 0, "last_seen_at": at}]}
    path = tmp_path / "map.json"

    def read(public_at=now):
        path.write_text(json.dumps(build_graph(context, network, {}, {}, {}, now)), encoding="utf-8")
        result = load_infrastructure_map(path, public_at)
        return next(n for n in result["nodes"] if n["id"] == "wan:uplink"), result["links"]

    service, links = read()
    assert service["mapStatus"] == "ok"
    check, positive, silent = service["serviceChecks"]
    assert check["required"] and check["pppoe"] == {
        "session": "pppoe-out1", "parent": "ether1-wan", "state": "connected",
        "parentLink": {"state": "up", "source": "RouterOS", "checkedAt": at},
    }
    assert (positive["method"], positive["target"], positive["state"]) == ("ICMP через PPPoE", "1.1.1.1", "reachable")
    assert (silent["target"], silent["state"], silent["reason"]) == ("8.8.8.8", "unknown", "icmp_no_echo_reply")
    assert any(r["a"] == "ether1-wan" and r["b"] == "pppoe-out1" for e in links for r in e["portEvidence"])
    assert not any("pairEvidence" in r for e in links for r in e["portEvidence"])
    network["router_interfaces"][0]["last_seen_at"] = (now - timedelta(minutes=11)).isoformat()
    assert "parentLink" not in read()[0]["serviceChecks"][0]["pppoe"]
    network["router_interfaces"][0].update(running=0, last_seen_at=at)
    session["running"] = False
    service, _ = read()
    assert service["mapStatus"] == "critical"
    assert service["serviceChecks"][0]["pppoe"]["parentLink"]["state"] == "down"
    assert len(service["serviceChecks"]) == 1
    session["disabled"] = True
    service, _ = read()
    assert service["mapStatus"] == "critical"
    assert service["serviceChecks"][0]["pppoe"]["state"] == "disabled"
    service, links = read(now + timedelta(minutes=6))
    assert service["mapStatus"] == "unknown"
    assert not next(e for e in links if e["source"] == "RouterOS · PPPoE")["confirmed"]
    network["pppoe"].clear()
    assert read()[0]["mapStatus"] == "unknown"


def test_route_evidence_is_scoped_and_does_not_mark_service_available():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    context = {
        "services": [{"id": "vpn", "name": "VPN"}],
        "routing_intent": [{"id": "vpn-routes", "next_hop": "192.0.2.1", "routing_table": "main",
                            "destinations": ["198.51.100.0/24", "203.0.113.0/24"]}],
    }
    network = {"routes": [
        {"source": source, "gateway": "192.0.2.1", "routing_table": table,
         "dst_address": dest, "active": 1, "disabled": 0, "last_seen_at": at}
        for source, table, dest in [("router", "main", "198.51.100.0/24"),
                                    ("router", "other", "203.0.113.0/24"),
                                    ("other", "main", "203.0.113.0/24")]
    ]}
    bindings = {"route_evidence": {"vpn": {"source": "router", "intent": "vpn-routes"}}}
    node, = build_graph(context, network, {}, {}, bindings, now)["nodes"]
    assert "reachability" not in node
    assert [(check["target"], check["state"]) for check in node["serviceChecks"]] == [
        ("198.51.100.0/24", "reachable"), ("203.0.113.0/24", "unknown"),
    ]
    assert node["serviceChecks"][0]["routeSource"] == "router"
    from app.infrastructure_map import _map_statuses, _public_node

    node["reachability"] = {"state": "reachable", "source": "ICMP", "checkedAt": at}
    public = _public_node(node, now)
    _map_statuses({"vpn": public}, [])
    assert public["mapStatus"] == "unknown"
    node["serviceChecks"][1].update(state="unreachable", checkedAt=at)
    public = _public_node(node, now)
    _map_statuses({"vpn": public}, [])
    assert public["mapStatus"] == "warn"


def test_service_availability_expires_using_its_own_probe_evidence():
    from app.infrastructure_map import _map_statuses, _public_node

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    stale = (now - timedelta(minutes=6)).isoformat()
    current = (now - timedelta(minutes=1)).isoformat()

    def check(state, at, **extra):
        return {"state": state, "method": "HTTP", "source": "UI_VPN", "checkedAt": at, "required": True, **extra}

    def read(*checks):
        raw = {"id": "app", "kind": "Сервис", "serviceChecks": list(checks),
               "reachability": {"state": "reachable", "source": "Проверка сервиса", "checkedAt": stamp}}
        public = _public_node(raw, now)
        _map_statuses({"app": public}, [])
        return public["reachability"], public["mapStatus"]

    health, color = read(check("reachable", stale), check("unreachable", stamp), check("reachable", stamp, component=True))
    assert health["state"] == "unknown" and color == "unknown"
    health, color = read(check("reachable", current), check("unknown", stamp))
    assert health["state"] == "reachable" and health["checkedAt"] == current and color == "unknown"
    health, color = read(check("unreachable", current), check("unreachable", stamp))
    assert health["state"] == "unreachable" and health["checkedAt"] == current and color == "critical"


def test_route_checks_report_mismatch_inactive_and_missing_observation():
    from app.infrastructure_collect import _route_checks
    from app.infrastructure_map import _public_service_check

    now = datetime.now(timezone.utc)
    current = now.isoformat()
    stale = (now - timedelta(minutes=26)).isoformat()
    destination, gateway = "198.51.100.0/24", "192.0.2.1"
    intent = {"destinations": [destination], "next_hop": gateway}
    route = {"source": "router", "routing_table": "main", "dst_address": destination,
             "gateway": gateway, "active": 1, "disabled": 0, "last_seen_at": current}

    def read(*routes):
        check, = _route_checks(intent, "router", list(routes), now)
        return _public_service_check(check, now)

    other = read({**route, "gateway": "192.0.2.2"})
    assert (other["state"], other["reason"], other["via"], other["observedVia"]) == (
        "unreachable", "route_other_gateway", gateway, "192.0.2.2",
    )
    assert read({**route, "active": 0})["reason"] == "route_inactive"
    assert read({**route, "disabled": 1})["state"] == "unreachable"
    assert read({**route, "route_type": "blackhole"})["reason"] == "route_rejecting"
    mixed = read(route, {**route, "gateway": "192.0.2.2"})
    assert mixed["state"] == "unknown" and mixed["reason"] == "route_multiple_gateways"
    assert read({**route, "gateway": "192.0.2.2"}, {**route, "gateway": "192.0.2.3"})["state"] == "unknown"
    old = read({**route, "active": 0, "last_seen_at": stale})
    assert old["state"] == "unknown" and old["stale"] and old["checkedAt"] == stale
    assert "reason" not in old
    missing = read({**route, "routing_table": "other"})
    assert missing["state"] == "unknown" and missing["method"] == "Маршрут"
    assert missing["checkedAt"] is None

    host = "198.51.100.12/32"
    checks = _route_checks(intent, "router", [route, {**route, "dst_address": host}], now,
                           host_routes=[host, host, "203.0.113.10/32", "198.51.100.0/28", "invalid"])
    assert [(check["target"], check["state"]) for check in checks] == [
        (destination, "reachable"), (host, "reachable"),
    ]


def test_asset_icmp_probes_resolve_expected_gateway_from_inventory():
    from app.infrastructure_collect import _asset_icmp_probes

    context = {"devices": [{"id": "firewall", "management_ip": "192.0.2.1"}]}
    bindings = {"asset_ip_checks": {"endpoint": "198.51.100.10", "local": "192.0.2.20", "unresolved": "198.51.100.11"},
                "asset_ip_check_gateways": {"endpoint": "firewall", "unresolved": "unknown-gateway"}}
    assert _asset_icmp_probes(context, bindings) == {
        "endpoint": [{"type": "icmp", "ip": "198.51.100.10", "route_via": "192.0.2.1"}],
        "local": [{"type": "icmp", "ip": "192.0.2.20"}],
        "unresolved": [{"type": "icmp", "ip": "198.51.100.11", "route_via": None}],
    }


def test_skipped_host_probe_reports_failed_local_arp_without_promoting_availability(monkeypatch):
    from app.infrastructure_collect import _asset_icmp_probes
    from app.infrastructure_map import _public_service_check
    from app import infrastructure_service_probes as probes

    address, source = "192.0.2.120", "192.0.2.30"
    device = {"id": "server", "management_ip": address, "mac_addresses": ["02:00:00:00:00:20"]}
    context = {"devices": [device]}
    bindings = {"asset_ip_checks": {"server": address}, "asset_arp_diagnostics": ["server"]}
    specs = _asset_icmp_probes(context, bindings)
    route = {"dst": address, "dev": "ens18", "prefsrc": source}
    calls = []

    def kernel(args, **kwargs):
        if "route" in args:
            return json.dumps([route])
        return json.dumps([{"dst": address, "state": ["FAILED"]}])

    def ping(ip, **kwargs):
        calls.append((ip, kwargs))
        return probes.subprocess.CompletedProcess([], 1)

    monkeypatch.setattr(probes.subprocess, "check_output", kernel)
    monkeypatch.setattr(probes, "_ping", ping)
    node = {"id": "server", "kind": "Сервер", "probeTargetIP": None}
    probes.apply_service_probes([node], specs)
    check = _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))
    assert calls == [(address, {"source_ip": source, "interface": "ens18"})]
    assert check["state"] == "unknown" and check["skipped"] and not check["target"]
    assert check["arpDiagnostic"] == {"state": "no_reply", "address": address,
                                     "sourceIP": source, "interface": "ens18"}
    assert "reachability" not in node
    route["gateway"] = "192.0.2.1"
    calls.clear()
    node["serviceChecks"].clear()
    probes.apply_service_probes([node], specs)
    assert calls == [] and "arpDiagnostic" not in node["serviceChecks"][0]


def test_skipped_service_shows_arp_from_its_host_and_same_address(tmp_path, monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_collect import _asset_icmp_probes, build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment, summarize_services

    address = "192.0.2.120"
    arp = {"state": "no_reply", "address": address, "sourceIP": "192.0.2.30", "interface": "ens18"}
    now = datetime.now(timezone.utc)
    context = {"devices": [{"id": "server", "name": "Server", "kind": "server", "management_ip": address,
                             "mac_addresses": ["02:00:00:00:00:20"]}]}
    bindings = {"asset_ip_checks": {"server": address}, "asset_arp_diagnostics": ["server"],
                "asset_services": {"web": {"asset": "server", "label": "Web", "require_network_identity": True}}}
    calls = []

    def local_arp(ip, _mac):
        calls.append(ip)
        return arp

    monkeypatch.setattr(probes, "_local_arp_diagnostic", local_arp)
    monkeypatch.setattr(probes, "_http_probe", lambda spec: pytest.fail("unverified target was contacted"))
    graph = build_graph(context, {}, {}, {}, bindings, now)
    probes.apply_service_probes(graph["nodes"], {**_asset_icmp_probes(context, bindings), "web": [
        {"type": "http", "ip": address, "port": 30080}, {"type": "http", "ip": "192.0.2.121", "port": 8080},
    ]})
    path = tmp_path / "map.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    loaded = load_infrastructure_map(path)
    web = next(node for node in loaded["nodes"] if node["id"] == "web")
    matching, other = web["serviceChecks"]
    assert calls == [address]
    assert web["mapStatus"] == "unknown" and matching["skipped"] and matching["target"] == ""
    assert matching["arpDiagnostic"] == arp and "arpDiagnostic" not in other
    issues = summarize_services(loaded)["serviceAudit"]["services"][0]["issues"]
    assert issues[0]["arpDiagnostic"] == arp
    attachment = summarize_guest_attachment(loaded, "web")["attachment"]
    assert attachment["serviceChecks"] == [matching, other]
    assert attachment["servicePaths"] == []
    assert attachment["physicalHosts"][0]["host"]["id"] == "server"
    server = summarize_guest_attachment(loaded, "server")["attachment"]
    assert server["serviceChecks"] == next(node["serviceChecks"] for node in loaded["nodes"] if node["id"] == "server")
    assert server["serviceTotal"] == 1
    assert server["services"] == [{"node": attachment["node"], "checks": attachment["checks"],
                                    "serviceChecks": [matching, other], "servicePaths": []}]


def test_icmp_via_expected_router_keeps_route_evidence_separate_from_echo(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    target, gateway = "192.0.2.19", "192.0.2.1"
    route = {"dst": target, "gateway": gateway, "dev": "ens18", "prefsrc": "192.0.2.30"}
    calls = []

    def route_output(command, **kwargs):
        assert command == ["/usr/sbin/ip", "-j", "-4", "route", "get", target]
        return json.dumps([route]).encode()

    def ping(address, *, source_ip, interface):
        calls.append((address, source_ip, interface))
        return {"state": "unknown", "reason": "icmp_no_echo_reply"}

    monkeypatch.setattr(probes.subprocess, "check_output", route_output)
    monkeypatch.setattr(probes, "_icmp_check", ping)

    def check():
        node = {"id": "vpn", "kind": "Сервис"}
        probes.apply_service_probes([node], {"vpn": [
            {"type": "icmp", "ip": target, "route_via": gateway, "supplemental": True},
        ]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    observed = check()
    assert observed["state"] == "unknown" and observed["reason"] == "icmp_no_echo_reply"
    assert observed["localRoute"] == {"state": "reachable", "gateway": gateway, "expectedGateway": gateway,
                                      "interface": "ens18", "sourceIP": "192.0.2.30"}
    route["gateway"] = "192.0.2.254"
    different = check()
    assert different["state"] == "unknown" and different["reason"] == "icmp_route_mismatch"
    assert different["localRoute"]["state"] == "unreachable"
    assert calls == [(target, "192.0.2.30", "ens18")]


def test_wireguard_policy_needs_fresh_kernel_route_mark_and_handshake(tmp_path, monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    now = datetime.now(timezone.utc)
    report = tmp_path / "policy.json"
    facts = {"checkedAt": now.isoformat(), "markers": {"ens18.50": 1},
             "wireguard": {"wg0": {"peerCount": 1, "latestHandshake": int(now.timestamp()) - 15}}}
    route = {"dst": "192.0.2.1", "from": "172.16.50.1", "iif": "ens18.50",
             "dev": "wg0", "table": "123", "mark": 1, "flags": []}
    monkeypatch.setattr(probes.subprocess, "check_output", lambda *args, **kwargs: json.dumps([route]).encode())
    spec = {"type": "wireguard_policy", "interface": "wg0", "ingress": "ens18.50", "mark": 1, "table": 123,
            "peer": "172.16.50.1", "report": str(report)}

    def read():
        report.write_text(json.dumps(facts), encoding="utf-8")
        node = {"id": "policy", "kind": "Сервис"}
        probes.apply_service_probes([node], {"policy": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    check = read()
    assert check["state"] == "reachable" and check["wireguardPolicy"]["markerConfirmed"]
    assert check["wireguardPolicy"]["routeConfirmed"] and check["wireguardPolicy"]["peerCount"] == 1
    facts["wireguard"]["wg0"]["latestHandshake"] = int(now.timestamp()) - 310
    assert read()["reason"] == "wireguard_handshake_unconfirmed"
    facts["markers"]["ens18.50"] = 2
    assert read()["reason"] == "wireguard_mark_mismatch"
    route["dev"] = "ens18"
    assert read()["reason"] == "wireguard_route_mismatch"


def test_wireguard_report_rejects_ambiguous_marking_and_exports_only_handshake_metadata():
    import runpy
    from pathlib import Path

    report = runpy.run_path(str(Path(__file__).resolve().parents[1] / "deploy" / "openvpn-policy-report.py"))
    prerouting = ["-P PREROUTING ACCEPT", "-A PREROUTING -j VPN_POLICY_MARK"]
    rules = ["-N VPN_POLICY_MARK", "-A VPN_POLICY_MARK -i ens18.50 -j MARK --set-xmark 0x1/0xffffffff",
             "-A VPN_POLICY_MARK -s 192.0.2.9/32 -i tun0 -j QUEST_WG"]
    assert report["markers"](prerouting, rules) == {"ens18.50": 1}
    assert report["markers"](prerouting, [*rules, "-A VPN_POLICY_MARK -i ens+ -j DROP"]) is None
    assert report["markers"](prerouting, [*rules, "-A VPN_POLICY_MARK -i ens18.50 -j RETURN"]) == {}
    assert report["handshakes"](["wg0\tprivate-output-placeholder\t123"]) == {
        "wg0": {"peerCount": 1, "latestHandshake": 123},
    }


def test_local_vlan_probe_requires_expected_link_address_and_route(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    address = [{"ifname": "ens18.50", "flags": ["UP", "LOWER_UP"],
                "linkinfo": {"info_kind": "vlan", "info_data": {"id": 50}},
                "addr_info": [{"family": "inet", "local": "192.0.2.2", "prefixlen": 30}]}]
    route = [{"dst": "192.0.2.1", "from": "192.0.2.2", "dev": "ens18.50"}]
    neighbors = [{"dst": "192.0.2.1", "lladdr": "02:00:00:00:00:11", "state": ["REACHABLE"]}]
    pings = []
    def ip_output(args, **kwargs):
        return json.dumps(address if "address" in args else neighbors if "neigh" in args else route).encode()
    monkeypatch.setattr(probes.subprocess, "check_output", ip_output)

    def ping(ip, *, source_ip=None, interface=None):
        pings.append((ip, source_ip, interface))
        return probes.subprocess.CompletedProcess([], 0, stdout=b"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.3 ms")

    monkeypatch.setattr(probes, "_ping", ping)
    spec = {"type": "vlan_transit", "interface": "ens18.50", "vlan": 50, "address": "192.0.2.2/30", "ip": "192.0.2.1"}

    def read():
        node = {"id": "transit", "kind": "Сервис"}
        probes.apply_service_probes([node], {"transit": [spec]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    check = read()
    assert (check["state"], check["roundTripMs"], check["vlanTransit"]) == (
        "reachable", 0.3, {"interface": "ens18.50", "id": 50, "localAddress": "192.0.2.2/30"},
    )
    assert pings == [("192.0.2.1", "192.0.2.2", "ens18.50")]
    spec.update(peerAsset="peer", peerGuestPort="net2", peerMac="02:00:00:00:00:11")
    check = read()
    assert check["vlanTransit"]["peer"] == {"asset": "peer", "guestPort": "net2", "state": "matched"}
    assert spec["peerMac"] not in json.dumps(check)
    neighbors[0]["lladdr"] = "02:00:00:00:00:99"
    check = read()
    assert (check["state"], check["reason"], check["vlanTransit"]["peer"]["state"]) == (
        "unknown", "vlan_peer_identity_mismatch", "mismatch",
    )
    route[0]["dev"] = "ens18"
    assert read()["reason"] == "vlan_route_mismatch"
    address[0]["linkinfo"]["info_data"]["id"] = 51
    assert read()["reason"] == "vlan_id_mismatch"
    assert len(pings) == 3


def test_tagged_transit_is_excluded_from_physical_topology_and_uses_canonical_endpoints(tmp_path):
    from app.infrastructure_collect import _bind_vlan_probe_peers, _local_vlan_probe_specs, build_graph
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    transit = {"id": "policy", "relation": "connected_to", "state": {"verified": True},
               "endpoint_a": {"device": "remote", "interface": "vlan02", "address": "192.0.2.1/30"},
               "endpoint_b": {"device": "local", "interface": "ens18.50", "address": "192.0.2.2/30"},
               "vlan": {"id": 50, "mode": "tagged_transit"}}
    context = {"devices": [{"id": key, "name": key, "kind": "server"} for key in ("local", "remote")],
               "links": [transit]}
    specs = _local_vlan_probe_specs(context, {"policy": "local"})
    assert specs["transit:policy"]["ip"] == "192.0.2.1"
    bindings = {"local_vlan_peer_adapters": {"policy": "net2"},
                "guests": {"110": {"asset": "remote", "mac": "02:00:00:00:00:10"}}}
    pve = {"at": now.isoformat(), "guests": [{"vmid": 110, "status": "running"}],
           "configs": {"110": {"net0": "virtio=02:00:00:00:00:10,bridge=vmbr0",
                               "net2": "virtio=02:00:00:00:00:11,bridge=vmbr1"}}}
    _bind_vlan_probe_peers(specs, pve, bindings, now)
    assert (specs["transit:policy"]["peerGuestPort"], specs["transit:policy"]["peerMac"]) == ("net2", "02:00:00:00:00:11")
    pve["configs"]["110"]["net2"] += ",link_down=1"
    disabled = _local_vlan_probe_specs(context, {"policy": "local"})
    _bind_vlan_probe_peers(disabled, pve, bindings, now)
    assert "peerMac" not in disabled["transit:policy"]
    graph = build_graph(context, {}, {}, {}, {}, now, local_vlan_probes=specs)
    path = tmp_path / "map.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    public = load_infrastructure_map(path, now)
    audit = summarize_topology(public)["topologyAudit"]
    assert not any(audit["directLinks"].values())
    link = next(edge for edge in public["links"] if edge["kind"] == "Транзитный сегмент")
    proof, = link["portEvidence"]
    assert (proof["a"], proof["b"], proof["vlan"]) == ("vlan02", "ens18.50", 50)
    assert "pairEvidence" not in proof
    transit["endpoint_b"]["address"] = "192.0.2.2/24"
    assert _local_vlan_probe_specs(context, {"policy": "local"}) == {}


def test_icmp_diagnostics_distinguish_echo_silence_and_probe_error(monkeypatch):
    from subprocess import CompletedProcess, TimeoutExpired
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    readings = {
        "192.0.2.1": (0, b"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.401 ms\n"),
        "192.0.2.2": (1, b""),
        "192.0.2.3": (1, b"From 192.0.2.254 icmp_seq=1 Destination Host Unreachable\n"),
        "192.0.2.4": (2, b"raw output must not be public"),
    }

    def run(command, **kwargs):
        assert kwargs["env"]["LC_ALL"] == "C"
        if command[-1] == "192.0.2.5":
            raise TimeoutExpired(command, 3)
        code, output = readings[command[-1]]
        return CompletedProcess(command, code, stdout=output)

    monkeypatch.setattr(probes.subprocess, "run", run)
    nodes = [{"id": key, "kind": "Сервис"} for key in (*readings, "192.0.2.5")]
    probes.apply_service_probes(nodes, {
        node["id"]: [{"type": "icmp", "ip": node["id"], "supplemental": True}] for node in nodes
    })
    now = datetime.now(timezone.utc)
    checks = [_public_service_check(node["serviceChecks"][0], now) for node in nodes]
    assert all("reachability" not in node for node in nodes)
    assert all(check["supplemental"] is True for check in checks)
    assert [(c["state"], c.get("reason")) for c in checks] == [
        ("reachable", None), ("unknown", "icmp_no_echo_reply"), ("unknown", "icmp_unreachable"),
        ("unknown", "icmp_probe_error"), ("unknown", "icmp_probe_error"),
    ]
    assert checks[0]["roundTripMs"] == 0.401
    assert checks[2]["errorSource"] == "192.0.2.254"
    assert "raw output" not in json.dumps(checks)


def test_pinned_tls_certificate_distinguishes_expiry_from_changed_identity(monkeypatch):
    import hashlib
    from unittest.mock import MagicMock

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    now = datetime.now(timezone.utc).replace(microsecond=0)
    expired = now - timedelta(days=1)
    key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now - timedelta(days=2)).not_valid_after(expired)
                   .sign(key, None).public_bytes(Encoding.DER))
    context, tcp = MagicMock(), MagicMock()
    tls = context.wrap_socket.return_value.__enter__.return_value
    tls.getpeercert.return_value = certificate
    tls.version.return_value = "TLSv1.2"
    monkeypatch.setattr(probes.ssl, "SSLContext", lambda _: context)
    monkeypatch.setattr(probes.socket, "create_connection", lambda *args, **kwargs: tcp)

    def check(pin):
        node = {"id": "certificate", "kind": "Сервис", "probeTargetIP": "192.0.2.4"}
        probes.apply_service_probes([node], {"certificate": [{"type": "tls_certificate", "ip": "192.0.2.4",
                                                                 "port": 5061, "tls_sha256": pin}]})
        result, = node["serviceChecks"]
        return _public_service_check(result, datetime.now(timezone.utc))

    result = check(hashlib.sha256(certificate).hexdigest())
    assert (result["state"], result["reason"], result["tlsExpiresAt"], result["tlsVersion"]) == (
        "unreachable", "tls_certificate_expired", expired.isoformat(), "TLSv1.2",
    )
    changed = check("0" * 64)
    assert (changed["state"], changed["reason"]) == ("unknown", "tls_certificate_pin")
    assert "tlsExpiresAt" not in changed


@pytest.mark.parametrize(("days", "required", "age_minutes", "expected"), [
    (30, True, 0, "warn"), (31, True, 0, "ok"),
    (1, False, 0, "ok"), (1, True, 10, "unknown"),
])
def test_service_warns_before_required_tls_certificate_expires(days, required, age_minutes, expected):
    from app.infrastructure_map import _map_statuses, _public_node, summarize_services

    now = datetime.now(timezone.utc)
    check = {"method": "Сертификат TLS", "source": "UI_VPN", "state": "reachable", "required": required,
             "checkedAt": (now - timedelta(minutes=age_minutes)).isoformat(),
             "tlsExpiresAt": (now + timedelta(days=days)).isoformat(), "port": 443}
    raw = {"id": "https", "name": "HTTPS", "kind": "Сервис", "serviceChecks": [check],
           "reachability": {"method": "HTTPS", "source": "Network Observer", "state": "reachable",
                            "checkedAt": now.isoformat()}}
    node = _public_node(raw, now)
    _map_statuses({node["id"]: node}, [])
    service, = summarize_services({"nodes": [node], "links": []})["serviceAudit"]["services"]
    assert service["status"] == node["mapStatus"] == expected
    assert node["reachability"]["state"] == "reachable"
    if expected == "warn":
        assert node["serviceChecks"][0]["state"] == "reachable"
        assert service["issues"][0]["reason"] == "tls_certificate_expiring"
        assert service["issues"][0]["tlsExpiresAt"] == check["tlsExpiresAt"]


def test_tls_certificate_verifies_name_and_chain_for_configured_address(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=30)
    context, tcp = MagicMock(), MagicMock()
    create_context = MagicMock(return_value=context)
    connect = MagicMock(return_value=tcp)
    tls = context.wrap_socket.return_value.__enter__.return_value
    tls.getpeercert.return_value = b"peer certificate"
    tls.version.return_value = "TLSv1.3"
    peer = MagicMock(not_valid_before_utc=now - timedelta(days=1), not_valid_after_utc=expires)
    monkeypatch.setattr(probes.ssl, "create_default_context", create_context)
    monkeypatch.setattr(probes.socket, "create_connection", connect)
    monkeypatch.setattr(probes.x509, "load_der_x509_certificate", MagicMock(return_value=peer))
    ca_file = str(tmp_path / "domain-ca.pem")
    spec = {"type": "tls_certificate", "ip": "192.0.2.4", "port": 636, "component": True,
            "tls_server_name": "ad.example.test", "tls_ca_file": ca_file}

    def check(probe):
        node = {"id": "certificate", "kind": "Сервис", "probeTargetIP": "192.0.2.4"}
        probes.apply_service_probes([node], {"certificate": [probe]})
        result, = node["serviceChecks"]
        return _public_service_check(result, datetime.now(timezone.utc))

    result = check(spec)
    assert (result["state"], result["tlsExpiresAt"], result["tlsVersion"]) == (
        "reachable", expires.isoformat(), "TLSv1.3",
    )
    assert (result["port"], result["target"], result["component"]) == (636, "192.0.2.4", True)
    create_context.assert_called_once_with(cafile=ca_file)
    connect.assert_called_once_with(("192.0.2.4", 636), timeout=probes.TIMEOUT)
    context.wrap_socket.assert_called_once_with(tcp.__enter__.return_value, server_hostname="ad.example.test")

    context.wrap_socket.side_effect = probes.ssl.SSLCertVerificationError("certificate mismatch")
    result = check(spec)
    assert (result["state"], result["reason"]) == ("unreachable", "tls_certificate_verification_failed")
    assert "tlsExpiresAt" not in result

    connect.reset_mock()
    result = check({**spec, "tls_sha256": "0" * 64})
    assert (result["state"], result["reason"]) == ("unknown", "probe_configuration")
    create_context.side_effect = OSError("CA cannot be read")
    result = check(spec)
    assert (result["state"], result["reason"]) == ("unknown", "probe_configuration")
    connect.assert_not_called()


def test_ldaps_requires_complete_root_dse_response_on_verified_peer(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    import ldap3

    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    context = MagicMock()
    create_context = MagicMock(return_value=context)
    monkeypatch.setattr(probes.ssl, "create_default_context", create_context)
    server, create_connection = MagicMock(), MagicMock()
    monkeypatch.setattr(ldap3, "Server", server)
    monkeypatch.setattr(ldap3, "Connection", create_connection)
    connection = create_connection.return_value
    connection.closed = False
    connection.result = {"result": 0}
    connection.search.return_value = True
    context_name = "DC=example,DC=test"
    entry = {"type": "searchResEntry", "dn": "", "attributes": {"defaultNamingContext": [context_name]}}
    connection.response = [entry]
    ca_file = str(tmp_path / "domain-ca.pem")
    spec = {"type": "ldaps", "ip": "192.0.2.4", "port": 3269, "component": True,
            "naming_context": context_name, "tls_server_name": "ad.example.test", "tls_ca_file": ca_file}

    def probe():
        node = {"id": "catalog", "kind": "Сервис", "probeTargetIP": "192.0.2.4"}
        probes.apply_service_probes([node], {"catalog": [spec]})
        raw, = node["serviceChecks"]
        return _public_service_check(raw, datetime.now(timezone.utc))

    result = probe()
    assert (result["state"], result["method"], result["port"], result["target"], result["component"]) == (
        "reachable", "LDAPS RootDSE", 3269, "192.0.2.4", True,
    )
    create_context.assert_called_once_with(cafile=ca_file)
    assert server.call_args.args == ("192.0.2.4",)
    tls = server.call_args.kwargs["tls"]
    tls.wrap_socket(connection, do_handshake=True)
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "ad.example.test"
    assert create_connection.call_args.kwargs["auto_referrals"] is False
    connection.open.assert_called_once_with(read_server_info=False)
    assert connection.search.call_args.kwargs["search_scope"] == ldap3.BASE
    assert connection.search.call_args.kwargs["attributes"] == ["defaultNamingContext"]
    connection.unbind.assert_called_once()

    connection.response = [{**entry, "attributes": {"defaultNamingContext": ["DC=other,DC=test"]}}]
    result = probe()
    assert (result["state"], result["reason"]) == ("unreachable", "ldaps_naming_context_mismatch")
    connection.response = [entry]
    connection.result = {"result": 4}
    result = probe()
    assert (result["state"], result["reason"]) == ("unknown", "ldaps_response_unconfirmed")
    connection.search.reset_mock()
    connection.open.side_effect = probes.ssl.SSLCertVerificationError("wrong server name")
    connection.closed = True
    result = probe()
    assert (result["state"], result["reason"]) == ("unreachable", "ldaps_tls_certificate")
    connection.search.assert_not_called()


def test_ftp_probe_requires_complete_feature_reply(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    class Connection:
        def __init__(self, *chunks):
            self.chunks = iter(chunks)
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            assert timeout > 0

        def recv(self, size):
            return next(self.chunks, b"")[:size]

        def sendall(self, data):
            self.sent.append(data)

    def check(*chunks):
        connection = Connection(*chunks)
        monkeypatch.setattr(probes.socket, "create_connection", lambda *args, **kwargs: connection)
        node = {"id": "ftp", "kind": "Сервис", "probeTargetIP": "192.0.2.4"}
        probes.apply_service_probes([node], {"ftp": [{"type": "ftp_features", "ip": "192.0.2.4", "port": 21}]})
        result, = node["serviceChecks"]
        return _public_service_check(result, datetime.now(timezone.utc)), connection.sent

    result, sent = check(b"220 FTP Service\r\n", b"211-Extended features\r\n UTF8\r\n", b"211 END\r\n")
    assert (result["state"], result["ftpReply"], sent) == ("reachable", 211, [b"FEAT\r\n"])
    result, sent = check(b"421 Service unavailable\r\n")
    assert (result["state"], result["ftpReply"], sent) == ("unreachable", 421, [])
    result, _ = check(b"220 FTP Service\r\n", b"211-Extended features\r\n UTF8\r\n")
    assert (result["state"], result["reason"]) == ("unknown", "ftp_invalid_reply")
    result, sent = check(b"HTTP/1.1 200 OK\r\n")
    assert result["state"] == "unknown" and not sent


def test_ssh_identification_confirms_only_a_bounded_protocol_response(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_service_check

    ip = "192.0.2.20"
    chunks = []
    connections = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            assert 0 < timeout <= probes.TIMEOUT

        def recv(self, size):
            if not chunks:
                return b""
            chunk = chunks.pop(0)
            if isinstance(chunk, OSError):
                raise chunk
            return chunk[:size]

    def connect(destination, *, timeout):
        assert destination == (ip, 22) and 0 < timeout <= probes.TIMEOUT
        connections.append(destination)
        if chunks and isinstance(chunks[0], OSError):
            raise chunks.pop(0)
        return Connection()

    monkeypatch.setattr(probes.socket, "create_connection", connect)

    def check(*response, target=ip, confirm_early_close=False):
        chunks[:] = response
        node = {"id": "ssh", "kind": "Сервис", "probeTargetIP": target}
        probes.apply_service_probes([node], {"ssh": [{"type": "ssh_identification", "ip": ip, "port": 22,
                                                       "confirm_early_close": confirm_early_close}]})
        return _public_service_check(node["serviceChecks"][0], datetime.now(timezone.utc))

    success = check(b"NOTICE\r\nSSH-", b"2.0-example private-text\r\n\x00\x01")
    assert (success["method"], success["state"], success["target"], success["port"]) == ("SSH", "reachable", ip, 22)
    assert "private-text" not in json.dumps(success)
    assert success["sshTcpConnected"] is True
    assert check(b"SSH-1.99-example\n")["state"] == "reachable"
    assert check(b"SSH-2.0-example\n")["state"] == "reachable"
    closed = check(b"")
    assert (closed["state"], closed["reason"]) == ("unknown", "ssh_closed_before_identification")
    assert closed["sshTcpConnected"] is True
    repeated = check(b"", b"", confirm_early_close=True)
    assert (repeated["state"], repeated["reason"], repeated["attempts"]) == (
        "unreachable", "ssh_closed_before_identification", 2,
    )
    assert check(b"", b"SSH-2.0-example\r\n", confirm_early_close=True)["state"] == "reachable"
    assert check(b"", TimeoutError(), confirm_early_close=True)["state"] == "unknown"
    ipssh = check(b"SSH-2.0-IPSSH-6.6.0\r\n")
    assert ipssh["state"] == "reachable" and "IPSSH" not in json.dumps(ipssh)
    for banner in (b"HTTP/1.1 200 OK\r\n", b"SSH-2.0-" + b"x" * 250 + b"\r\n", b"SSH-2.0-example", b"x" * 1024,
                   b"SSH-2.0-IPSSH-not-a-version\r\n", b"SSH-2.0-other-6.6.0\r\n"):
        failed = check(banner)
        assert (failed["state"], failed["reason"]) == ("unknown", "ssh_identification_invalid")
    refused = check(ConnectionRefusedError())
    assert (refused["state"], refused["reason"]) == ("unreachable", "ssh_connection_refused")
    expired = check(TimeoutError())
    assert (expired["state"], expired["reason"]) == ("unknown", "timeout")
    assert "sshTcpConnected" not in expired
    banner_timeout = check(b"NOTICE\r\n", TimeoutError())
    assert (banner_timeout["state"], banner_timeout["reason"]) == ("unknown", "timeout")
    assert banner_timeout["sshTcpConnected"] is True
    previous = len(connections)
    assert check(target="192.0.2.21")["reason"] == "probe_target_mismatch"
    assert len(connections) == previous


def test_rtsp_options_confirms_the_authenticated_service_without_opening_a_stream(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_node

    address = "192.0.2.8"
    status, sequence, challenge = b"401 Unauthorized", b"matching", b"Digest realm=\"redacted\""
    requests = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            assert timeout > 0

        def sendall(self, request):
            requests.append(request)
            cseq = next(line.split(b": ", 1)[1] for line in request.split(b"\r\n") if line.startswith(b"CSeq: "))
            self.chunks = [b"RTSP/1.0 " + status + b"\r\nCSeq: " + (cseq if sequence == b"matching" else sequence),
                           b"\r\n" + (b"WWW-Authenticate: " + challenge + b"\r\n" if challenge else b"") + b"\r\n"]

        def recv(self, size):
            return self.chunks.pop(0)

    def connect(destination, *, timeout):
        assert destination == (address, 554)
        return Connection()

    monkeypatch.setattr(probes.socket, "create_connection", connect)
    spec = {"type": "rtsp_options", "ip": address, "port": 554, "path": "/Streaming/channels/101"}

    def check(confirmed=True):
        node = {"id": "video", "kind": "Сервис", "probeTargetIP": address if confirmed else None}
        probes.apply_service_probes([node], {"video": [spec]})
        return _public_node(node, datetime.now(timezone.utc))["serviceChecks"][0]

    result = check()
    assert (result["method"], result["state"], result["rtspStatus"], result["reason"]) == (
        "RTSP OPTIONS", "reachable", 401, "rtsp_auth_required",
    )
    assert "redacted" not in json.dumps(result)
    assert requests[-1].startswith(b"OPTIONS rtsp://192.0.2.8:554/Streaming/channels/101 RTSP/1.0\r\n")
    assert check(confirmed=False)["reason"] == "probe_target_unconfirmed"
    assert len(requests) == 1
    challenge = b""
    assert check()["state"] == "unknown"
    status = b"200 OK"
    assert check()["state"] == "reachable"
    sequence = b"0"
    assert check()["reason"] == "unexpected_response"


def test_ipmi_lan_requires_a_matching_rmcp_pong_with_ipmi_support(monkeypatch):
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _public_node

    address = "192.0.2.8"
    responses = []
    destinations = []

    class Datagram:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def connect(self, destination):
            destinations.append(destination)

        def sendall(self, request):
            assert request[:9] == bytes.fromhex("0600ff06000011be80")
            assert request[10:] == b"\x00\x00"
            self.tag = request[9]

        def recv(self, size):
            if not responses:
                raise TimeoutError
            tag_delta, supported_entities = responses.pop(0)
            return (bytes.fromhex("0600ff06000011be40")
                    + bytes(((self.tag + tag_delta) % 256, 0, 16))
                    + bytes(8) + bytes((supported_entities,)) + bytes(7))

    monkeypatch.setattr(probes.socket, "socket", lambda *args: Datagram())

    def check(port=623, *, confirmed=True):
        node = {"id": "bmc-ipmi", "kind": "Сервис", "probeTargetIP": address if confirmed else None}
        probes.apply_service_probes([node], {node["id"]: [{"type": "ipmi_lan", "ip": address, "port": port}]})
        return _public_node(node, datetime.now(timezone.utc))["serviceChecks"][0]

    responses.extend([(1, 0x81), (0, 0x81)])
    result = check()
    assert (result["method"], result["state"], result["target"], result["port"]) == (
        "IPMI LAN (UDP)", "reachable", address, 623,
    )
    assert 0 <= result["roundTripMs"] <= 3000
    timed_out = check()
    assert timed_out["reason"] == "timeout" and "roundTripMs" not in timed_out
    responses.extend([(1, 0x81), (0, 0x01)])
    assert check()["reason"] == "unexpected_response"
    assert check(port=443)["state"] == "unknown"
    assert check(confirmed=False)["reason"] == "probe_target_unconfirmed"
    assert destinations == [(address, 623)] * 3


@pytest.mark.parametrize("truncated", [False, True])
def test_sip_tcp_waits_for_a_complete_transaction_reply(monkeypatch, truncated):
    from app import infrastructure_service_probes as probes

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def getsockname(self):
            return "192.0.2.14", 12345

        def settimeout(self, timeout):
            assert timeout > 0

        def sendall(self, request):
            assert b"Via: SIP/2.0/TCP" in request
            headers = [line for line in request.split(b"\r\n") if line.startswith((b"Via:", b"Call-ID:", b"CSeq:"))]
            head = b"\r\n".join([b"SIP/2.0 200 OK", *headers, b"l: 4", b"", b""])
            self.chunks = iter((head[:25], head[25:] + (b"no" if truncated else b"body"), b""))

        def recv(self, _):
            return next(self.chunks)

    monkeypatch.setattr(probes.socket, "create_connection", lambda *args, **kwargs: Stream())
    result = probes._sip_options({"ip": "192.0.2.13", "port": 5060, "transport": "tcp"})
    assert result == ({"state": "unknown", "reason": "unexpected_response"} if truncated else
                      {"state": "reachable", "reason": "sip_response", "responseCode": 200})


def test_sip_options_validates_transaction_and_treats_silence_as_unknown(monkeypatch):
    import ipaddress
    import struct
    from app import infrastructure_service_probes as probes
    from app.infrastructure_map import _map_statuses, _public_node, summarize_services

    class Datagram:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def setsockopt(self, level, option, value):
            self.option = (level, option)

        def setblocking(self, blocking):
            assert not blocking

        def connect(self, address):
            assert address == ("192.0.2.13", 5060)

        def bind(self, address):
            assert address == ("192.0.2.14", 0)
            self.bound = True

        def getsockname(self):
            return ("192.0.2.14", 12345)

        def sendall(self, request):
            assert request.startswith(b"OPTIONS sip:192.0.2.13:5060 SIP/2.0")
            self.requests.append(request)
            self.headers = [line for line in request.split(b"\r\n") if line.startswith((b"Via:", b"Call-ID:", b"CSeq:"))]
            self.sent_final = False

        def recv(self, size):
            if len(self.requests) <= self.drop_count:
                raise TimeoutError
            if self.code == b"refused":
                raise ConnectionRefusedError
            if self.before_final:
                code, headers = self.before_final.pop(0)
                return b"\r\n".join([b"SIP/2.0 " + code, *headers(self.headers), b"", b""])
            if self.code is None or self.sent_final:
                raise TimeoutError
            self.sent_final = True
            headers = self.headers if self.match else [b"Call-ID: unrelated", b"CSeq: 1 OPTIONS"]
            return b"\r\n".join([b"SIP/2.0 " + self.code, *headers, b"", b""])

        def recvmsg(self, size, ancillary_size, flags):
            if not self.offender:
                raise BlockingIOError
            extended = struct.pack("=IBBBBII", 111, 2, 3, 3, 0, 0, 0)
            address = struct.pack("=HH", probes.socket.AF_INET, 0) + ipaddress.ip_address(self.offender).packed
            return b"", [(*self.option, extended + address)], 0, ("192.0.2.13", 5060)

    wire = Datagram()
    wire.drop_count = 0
    wire.before_final = []
    monkeypatch.setattr(probes.socket, "socket", lambda *args: wire)
    monkeypatch.setattr(probes.socket, "MSG_ERRQUEUE", 8192, raising=False)
    spec = {"type": "sip_options", "ip": "192.0.2.13", "port": 5060}
    node = {"id": "pbx", "kind": "Сервис"}
    for code, match, offender, state, reason, response_code in [
        (b"200 OK", True, None, "reachable", "sip_response", 200),
        (b"503 Busy", True, None, "unreachable", "sip_response", 503),
        (b"200 OK", False, None, "unknown", "unexpected_response", None),
        (None, True, None, "unknown", "timeout", None),
        (b"refused", True, None, "unknown", "connection_refused", None),
        (b"refused", True, "192.0.2.13", "unreachable", "icmp_port_unreachable", None),
        (b"refused", True, "192.0.2.1", "unknown", "icmp_rejected", None),
    ]:
        wire.code, wire.match, wire.offender = code, match, offender
        wire.requests = []
        probes.apply_service_probes([node], {"pbx": [spec]})
        check = node["serviceChecks"][-1]
        assert node["reachability"]["state"] == check["state"] == state
        public = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
        assert (public["source"], public["reason"], public.get("responseCode")) == ("UI_VPN", reason, response_code)
        assert public.get("errorSource") == offender
        assert public["attempts"] == len(wire.requests) == (3 if code is None or not match else 1)
    node["serviceChecks"][-1].update(reason="arbitrary output", responseCode=900, attempts=4)
    public = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert "reason" not in public and "responseCode" not in public and "attempts" not in public
    wire.requests, wire.drop_count = [], 1
    wire.code, wire.match, wire.offender = b"200 OK", True, None
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert result["state"] == "reachable" and result["attempts"] == 2
    assert len(wire.requests) == 2 and wire.requests[0] == wire.requests[1]

    wire.requests, wire.drop_count = [], 0
    wire.before_final = [
        (b"200 OK", lambda headers: [b"v: SIP/2.0/UDP 192.0.2.14;branch=z9hG4bKunrelated", *headers[1:]]),
        (b"100 Trying", lambda headers: headers),
    ]
    wire.code = b"503 Service Unavailable"
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert (result["state"], result["responseCode"], result["attempts"]) == ("unreachable", 503, 1)

    wire.requests = []
    wire.before_final = [(b"100 Trying", lambda headers: headers)]
    wire.code = None
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][-1]
    assert (result["state"], result["responseCode"], result["attempts"]) == ("unknown", 100, 3)

    gateway = "192.0.2.1"
    spec["route_via"] = gateway
    route = {"state": "unreachable", "expectedGateway": gateway, "gateway": "192.0.2.254",
             "sourceIP": "192.0.2.14", "interface": "eth0"}
    monkeypatch.setattr(probes, "_local_ipv4_route", lambda address, via: route)
    node["serviceChecks"].clear()
    wire.requests = []
    probes.apply_service_probes([node], {"pbx": [spec]})
    result = _public_node(node, datetime.now(timezone.utc))["serviceChecks"][0]
    assert result["state"] == "unknown" and result["reason"] == "sip_route_mismatch"
    assert result["localRoute"] == route and wire.requests == []

    route.update(state="reachable", gateway=gateway)
    node["serviceChecks"].clear()
    wire.code, wire.offender = b"refused", spec["ip"]
    probes.apply_service_probes([node], {"pbx": [spec]})
    assert wire.bound
    public = _public_node(node, datetime.now(timezone.utc))
    _map_statuses({"pbx": public}, [])
    issue, = summarize_services({"nodes": [public], "links": []})["serviceAudit"]["services"][0]["issues"]
    assert (issue["status"], issue["errorSource"], issue["attempts"], issue["localRoute"]) == (
        "critical", spec["ip"], 1, route,
    )


def test_infrastructure_map_serves_only_public_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    now = datetime.now(timezone.utc)
    path.write_text(json.dumps({
        "schema": 1, "snapshotAt": now.isoformat(),
        "nodes": [
            {"id": "vm:103", "name": "Directum VM", "kind": "Виртуальная машина",
             "properties": {"Состояние ВМ": "Запущена"}, "status": "ok", "guest": True, "vmid": 103,
             "sources": [{"name": "Proxmox", "status": "ok", "at": (now - timedelta(hours=1)).isoformat()}],
             "credential": "must-not-leave-the-source"},
        ],
        "links": [{"a": "vm:103", "b": "missing", "kind": "placement", "confirmed": True}],
    }), encoding="utf-8")
    client, headers, _ = make_client(tmp_path, monkeypatch)

    assert client.get("/network/infrastructure", follow_redirects=False).status_code == 303
    assert client.get("/api/v1/network/infrastructure").status_code == 401
    response = client.get("/api/v1/network/infrastructure", headers=headers)
    assert response.status_code == 200
    graph = response.json()["infrastructure"]
    assert graph["nodes"][0]["status"] == "unknown"
    assert graph["nodes"][0]["reachability"]["state"] == "unknown"
    assert graph["nodes"][0]["sources"][0]["stale"]
    assert graph["links"] == []
    assert "must-not-leave-the-source" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_port_includes_fresh_layer2_check_for_current_lldp_neighbor(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    check = {"source": "mikrotik-main", "method": "MAC ping · L2", "state": "reachable", "checkedAt": stamp}
    evidence = {"a": "ge3", "b": "ether1", "source": "LLDP UI_VPN", "at": stamp, "confirmed": True}
    raw = {"schema": 1, "snapshotAt": stamp, "nodes": [
        {"id": "sw", "name": "Switch", "kind": "Коммутатор"},
        {"id": "ap", "name": "AP", "kind": "Точка доступа", "serviceChecks": [check]},
    ], "links": [{"a": "sw", "b": "ap", "kind": "Сетевое соединение", "confirmed": True,
                  "portEvidence": [evidence]}]}
    path = tmp_path / "map.json"

    def read_graph():
        path.write_text(json.dumps(raw), encoding="utf-8")
        return load_infrastructure_map(path, now, include_service_ports=True)

    def read_ports():
        return read_graph()["servicePorts"]

    def read_connection_ports(node_id):
        attachment = summarize_guest_attachment(read_graph(), node_id)["attachment"]
        return attachment["physicalHosts"][0]["connections"][0]["ports"]

    port, = read_ports()["sw"]
    neighbor, = port["services"]
    assert port["port"] == "ge3" and neighbor["id"] == "ap"
    assert neighbor["basis"] == ["lldp_peer"] and neighbor["linkChecks"] == [check]
    ap_port, = read_connection_ports("ap")
    switch_port, = read_connection_ports("sw")
    expected = [{"nodeId": "ap", **check}]
    assert ap_port["linkChecks"] == switch_port["linkChecks"] == expected
    evidence["b"] = ""
    assert read_ports() == {}
    evidence["b"] = "ether1"
    check["checkedAt"] = (now - timedelta(hours=1)).isoformat()
    assert read_ports() == {}
    assert "linkChecks" not in read_connection_ports("ap")[0]
    evidence["at"], check["checkedAt"] = check["checkedAt"], stamp
    assert read_ports() == {}
    assert "linkChecks" not in read_connection_ports("ap")[0]


def test_attachment_includes_controller_path_without_attributing_it_to_the_server(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment

    stamp = datetime.now(timezone.utc).isoformat()
    telemetry = {"checkedAt": stamp, "intervalSeconds": 300, "rxErrors": 12}
    path = tmp_path / "map.json"
    links = [
        {"a": "bmc", "b": "server", "kind": "Управление оборудованием", "confirmed": True},
        {"a": "bmc", "b": "redfish", "kind": "Размещение", "confirmed": True},
        {"a": "sw", "b": "bmc", "kind": "Сетевое соединение", "confirmed": False, "portEvidence": [
            {"a": "ge13", "b": "eth0", "source": "GitHub", "confirmed": False}]},
        {"a": "sw", "b": "bmc", "kind": "Путь по MAC-таблице", "confirmed": True, "portEvidence": [
            {"a": "ge13", "b": "", "source": "netctl FDB", "confirmed": True, "at": stamp,
             "learnedEndpoint": {"switchId": "sw", "deviceId": "bmc", "mac": "02:00:00:00:00:13"},
             "managementAddress": "192.0.2.31"}]},
    ]

    def read():
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "links": links, "nodes": [
            {"id": "server", "name": "Server", "kind": "Сервер", "reachability": {
                "state": "reachable", "source": "UI_VPN", "method": "ICMP", "checkedAt": stamp}},
            {"id": "bmc", "name": "BMC", "kind": "Контроллер управления", "serviceChecks": [
                {"method": "ICMP · ARP + FDB", "source": "UI_VPN", "state": "reachable", "checkedAt": stamp,
                 "identityCheckedAt": stamp, "target": "192.0.2.31"}]},
            {"id": "sw", "name": "Switch", "kind": "Коммутатор", "ports": [
                {"name": "ge13", "state": "up", "checkedAt": stamp, "telemetry": telemetry,
                 "fdbLearned": {"checkedAt": stamp, "partial": False, "learnedMacCount": 1}}]},
            {"id": "redfish", "name": "Redfish", "kind": "Сервис", "serviceChecks": [
                {"method": "HTTPS", "source": "UI_VPN", "state": "reachable", "checkedAt": stamp,
                 "required": True, "port": 443, "target": "192.0.2.31", "httpStatus": 200}]},
        ]}), encoding="utf-8")
        return summarize_guest_attachment(load_infrastructure_map(path), "server")["attachment"]

    attachment = read()
    host, = attachment["physicalHosts"]
    controller, = host["managementControllers"]
    assert controller["node"]["id"] == "bmc"
    assert controller["confirmed"] is True
    assert host["host"]["mapStatus"] == "warn"
    assert controller["managementPortErrors"] == {
        "switchId": "sw", "port": "ge13", "source": "netctl FDB",
        "checkedAt": stamp, "telemetry": telemetry,
    }
    service, = controller["services"]
    assert service["node"]["id"] == "redfish"
    check, = service["serviceChecks"]
    assert (check["port"], check["httpStatus"], check["state"]) == (443, 200, "reachable")
    probe, = controller["servicePaths"]
    assert probe["switchAttachment"]["port"] == "ge13"
    assert "physicalPair" not in probe["switchAttachment"]
    assert host["connections"] == [] and "servicePaths" not in attachment
    assert host["pendingPortPairTotal"] == 0
    assert controller["pendingPortPairTotal"] == 1
    pending, = controller["pendingPortPairs"]
    assert (pending["a"], pending["portA"], pending["b"], pending["portB"]) == ("sw", "ge13", "bmc", "eth0")
    assert pending["identifiedPeerSides"] == ["a"]
    links[0]["confirmed"] = False
    uncertain_host, = read()["physicalHosts"]
    assert uncertain_host["host"]["mapStatus"] == "ok"
    candidate, = uncertain_host["managementControllers"]
    assert candidate == {**controller, "confirmed": False}
    links[2]["confirmed"] = True
    links[2]["portEvidence"][0]["confirmed"] = True
    host, = read()["physicalHosts"]
    controller, = host["managementControllers"]
    pair, = controller["inventoryPairs"]
    assert (pair["a"], pair["portA"], pair["b"], pair["portB"]) == ("sw", "ge13", "bmc", "eth0")
    assert controller["pendingPortPairTotal"] == 0
    assert host["connections"] == []


def test_attachment_view_includes_physical_service_hosts_and_distinguishes_port_evidence(tmp_path, monkeypatch):
    stamp = datetime.now(timezone.utc).isoformat()
    earlier = (datetime.fromisoformat(stamp) - timedelta(seconds=10)).isoformat()
    expired = (datetime.fromisoformat(stamp) - timedelta(minutes=8)).isoformat()
    checks = [
        {"method": "TCP", "source": "UI_VPN", "state": state, "target": "192.0.2.10",
         "port": port, "checkedAt": checked, "required": True}
        for state, port, checked in (("reachable", 8000, stamp), ("unreachable", 8000, earlier), ("reachable", 22, expired))
    ]
    path = tmp_path / "map.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    raw = {"schema": 1, "snapshotAt": stamp, "nodes": [
        {"id": "web", "name": "Web", "kind": "Сервис", "serviceChecks": checks},
        {"id": "server", "name": "Server", "kind": "Сервер"},
        {"id": "sw", "name": "Switch", "kind": "Коммутатор", "ports": [
            {"name": "xe1", "state": "up", "checkedAt": stamp, "speedBps": 10**10,
             "lldpNeighborCount": 1,
             "lldpNeighbors": [{"chassisId": "02:00:00:00:00:01", "inventoryDeviceId": "server",
                                "portId": "bond0", "portIdSubtype": "interface_name"}]},
        ]},
        {"id": "unbound", "name": "Unbound", "kind": "Сервер"},
    ], "links": [
        {"a": "server", "b": "web", "kind": "Размещение", "confirmed": True},
        {"a": "unbound", "b": "web", "kind": "Размещение", "confirmed": False},
        {"a": "sw", "b": "server", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [
            {"a": "ge1", "b": "eth0", "source": "LLDP UI_VPN", "at": stamp, "confirmed": True},
            {"a": "xe1", "b": "", "source": "GitHub", "confirmed": False},
        ]},
        {"a": "server", "b": "sw", "kind": "Путь по MAC-таблице", "source": "netctl FDB",
         "observedAt": stamp, "confirmed": True, "portEvidence": [
            {"a": "", "b": "ge1", "source": "netctl FDB", "at": stamp, "confirmed": True,
             "learnedEndpoint": {"switchId": "sw", "deviceId": "server", "mac": "02:00:00:00:00:01"}},
         ]},
    ]}
    path.write_text(json.dumps(raw), encoding="utf-8")
    client, headers, _ = make_client(tmp_path, monkeypatch)

    def read(node):
        response = client.get("/api/v1/network/infrastructure?view=attachment&node_id=" + node, headers=headers)
        assert response.status_code == 200
        return response.json()["infrastructure"]["attachment"]

    report = read("web")
    assert report["guestTotal"] == 0 and report["physicalHostTotal"] == 1
    host, = report["physicalHosts"]
    assert host["host"]["id"] == "server" and host["connectionTotal"] == 2
    direct, learned = host["connections"]
    assert direct["peer"]["id"] == "sw" and direct["kind"] == "Сетевое соединение"
    logical_peer = {"localPort": "xe1", "chassisId": "02:00:00:00:00:01", "portId": "bond0",
                    "portIdSubtype": "interface_name", "checkedAt": stamp}
    assert direct["ports"] == [
        {"hostPort": "eth0", "peerPort": "ge1", "source": "LLDP UI_VPN", "checkedAt": stamp,
         "confirmed": True, "pairEvidence": "current"},
        {"hostPort": "", "peerPort": "xe1", "source": "GitHub", "checkedAt": None, "confirmed": False,
         "portStates": {"peer": {"name": "xe1", "state": "up", "checkedAt": stamp,
                                 "speedBps": 10**10, "stale": False}},
         "lldpPeers": {"peer": [logical_peer]}},
    ]
    reading, = learned["ports"]
    assert learned["kind"] == "Путь по MAC-таблице" and reading["peerPort"] == "ge1"
    assert reading["hostPort"] == "" and "pairEvidence" not in reading
    assert reading["learnedEndpoint"]["deviceId"] == "server"
    assert host["pendingPortPairTotal"] == 1
    pending, = host["pendingPortPairs"]
    assert (pending["a"], pending["portA"], pending["b"], pending["portB"]) == ("sw", "xe1", "server", "")
    assert pending["identifiedPeerSides"] == ["a"] and pending["missingPortSides"] == ["b"]
    assert pending["observedPaths"] == []
    assert pending["lldpPeers"] == {"a": [logical_peer]}
    assert pending["portObservations"]["a"]["speedBps"] == 10**10
    pairs = client.get("/api/v1/network/infrastructure?include_port_pairs=true", headers=headers)
    assert pairs.status_code == 200
    pair_graph = pairs.json()["infrastructure"]
    assert pair_graph["pendingPortPairs"] == [pending]
    assert any(row["portA"] == "ge1" and row["portB"] == "eth0" for row in pair_graph["currentPortPairs"])
    assert host["currentPortPairTotal"] == 1
    assert host["currentPortPairs"] == pair_graph["currentPortPairs"]
    assert host["inventoryPairTotal"] == 0 and host["inventoryPairs"] == []
    assert read("server")["physicalHosts"] == [host]
    switch_attachment = read("sw")
    switch, = switch_attachment["physicalHosts"]
    service_port, = switch_attachment["servicePorts"]
    assert service_port["port"] == "ge1" and service_port["total"] == 1
    scope = "/api/v1/network/infrastructure?view=topology&node_id=sw"
    for suffix, expected in (("", [service_port]), ("&port_name=GE1", [service_port]), ("&port_name=xe1", [])):
        result = client.get(scope + suffix, headers=headers)
        assert result.status_code == 200
        assert result.json()["infrastructure"]["topologyAudit"]["servicePorts"] == expected
    assert [(service["id"], service["basis"]) for service in service_port["services"]] == [("web", ["host_mac"])]
    assert service_port["services"][0]["probeEndpoints"] == [{
        "method": "TCP", "target": "192.0.2.10", "port": 8000,
        "passed": 1, "failed": 1, "unconfirmed": 0,
        "lastCheckedByOutcome": {"passed": stamp, "failed": earlier},
    }]
    extra_ids = [f"web-{index:02d}" for index in range(69)]
    extra_nodes = [{**raw["nodes"][0], "id": key} for key in extra_ids]
    extra_links = [{**raw["links"][0], "b": key} for key in extra_ids]
    expanded = {**raw, "nodes": raw["nodes"] + extra_nodes, "links": raw["links"] + extra_links}
    path.write_text(json.dumps(expanded), encoding="utf-8")
    expanded_port, = read("sw")["servicePorts"]
    assert expanded_port["total"] == 70
    assert [service["id"] for service in expanded_port["services"]] == ["web", *extra_ids]
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert switch["pendingPortPairs"] == [pending]
    inverse = switch["connections"][0]["ports"][0]
    assert (inverse["hostPort"], inverse["peerPort"]) == ("ge1", "eth0")
    assert read("unbound")["physicalHosts"][0]["pendingPortPairs"] == []
    cable = raw["links"][2]["portEvidence"].pop(0)
    raw["nodes"][2]["ports"].append({
        "name": "ge1", "state": "up", "checkedAt": stamp, "speedBps": 10**9, "lldpNeighborCount": 1,
        "lldpNeighbors": [{"chassisId": "02:00:00:00:00:01", "inventoryDeviceId": "server",
                           "portId": "bridgeLocal/ether2", "portIdSubtype": "interface_name"}],
    })
    path.write_text(json.dumps(raw), encoding="utf-8")
    pending_without_cable = read("server")["physicalHosts"][0]["pendingPortPairs"]
    learned_gap, configured_gap = pending_without_cable
    assert configured_gap == pending
    assert learned_gap["basis"] == "learned_endpoint"
    assert (learned_gap["a"], learned_gap["portA"], learned_gap["b"], learned_gap["portB"]) == (
        "sw", "ge1", "server", "",
    )
    assert learned_gap["missingPortSides"] == ["b"] and learned_gap["identifiedPeerSides"] == ["a"]
    assert learned_gap["observedPaths"][0]["learnedEndpoint"]["deviceId"] == "server"
    assert learned_gap["lldpPeers"] == {"a": [{
        "localPort": "ge1", "chassisId": "02:00:00:00:00:01", "portId": "bridgeLocal/ether2",
        "portIdSubtype": "interface_name", "checkedAt": stamp,
    }]}
    audit = client.get("/api/v1/network/infrastructure?view=topology", headers=headers).json()["infrastructure"]["topologyAudit"]
    assert audit["pendingTotal"] == 2
    assert audit["pending"] == pending_without_cable
    from app.infrastructure_map import load_infrastructure_map

    browser_graph = load_infrastructure_map(path, include_guest_attachments=True)
    assert browser_graph["pendingPortPairTotal"] == 2
    assert [tuple(row[key] for key in ("a", "b", "nameA", "nameB", "portA", "portB"))
            for row in browser_graph["pendingPortPairs"]] == [
        tuple(row[key] for key in ("a", "b", "nameA", "nameB", "portA", "portB")) for row in pending_without_cable
    ]
    learned_row = browser_graph["pendingPortPairs"][0]
    assert learned_row["observedSources"] == ["netctl FDB"]
    assert learned_row["identifiedPeerSides"] == ["a"]
    assert learned_row["observedSourceTimes"] == {"netctl FDB": stamp}
    assert learned_row["lldpPortIds"] == ["bridgeLocal/ether2"]
    assert learned_row["lldpPeers"] == learned_gap["lldpPeers"]
    configured_row = browser_graph["pendingPortPairs"][1]
    assert configured_row["portObservations"]["a"] == {
        "name": "xe1", "state": "up", "speedBps": 10**10, "checkedAt": stamp,
    }
    assert "b" not in configured_row["portObservations"]
    assert "pendingPortPairs" not in load_infrastructure_map(path)
    raw["nodes"][2]["ports"].pop()
    raw["links"][2]["portEvidence"].insert(0, cable)
    raw["links"][1]["confirmed"] = True
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert read("sw")["servicePorts"] == []
    raw["links"][1]["confirmed"] = False
    raw["links"][3]["observedAt"] = (datetime.fromisoformat(stamp) - timedelta(minutes=26)).isoformat()
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert read("sw")["servicePorts"] == []
    raw["links"][2]["portEvidence"][-1]["b"] = "eth2"
    path.write_text(json.dumps(raw), encoding="utf-8")
    browser_graph = load_infrastructure_map(path, include_guest_attachments=True)
    row, = browser_graph["pendingPortPairs"]
    assert row["inventoryPortSides"] == ["b"]


def test_node_search_aliases_follow_fresh_address_evidence(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    old = (now - timedelta(hours=1)).isoformat()
    nodes = [
        {"id": "pve", "name": "Proxmox", "kind": "Гипервизор"},
        {"id": "vm", "name": "VM", "guest": True, "kind": "Виртуальная машина", "aliases": ["VM alias"]},
        {"id": "router", "name": "Router", "kind": "Маршрутизатор",
         "properties": {"Адрес управления": "192.0.2.1"}},
    ]

    def interface(port, address, checked_at, **config):
        return {"a": "vmbr1", "b": port, "source": "Proxmox · конфигурация ВМ", "at": stamp,
                "confirmed": True, "virtual": {**config, "ipv4Observations": [{"address": address,
                    "checkedAt": checked_at, "source": "UI_VPN", "method": "ICMP · ARP"}]}}

    placement = {"a": "pve", "b": "vm", "kind": "Размещение ВМ", "source": "Proxmox", "confirmed": True,
                 "observedAt": stamp, "portEvidence": [
                     interface("net0", "192.0.2.10", stamp),
                     interface("net1", "192.0.2.11", old),
                     interface("net2", "192.0.2.12", stamp, linkDisabled=True),
                 ]}
    path = tmp_path / "infrastructure.json"

    def read(at=now):
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": nodes, "links": [placement]}),
                        encoding="utf-8")
        return {node["id"]: node["aliases"] for node in load_infrastructure_map(path, at)["nodes"]}

    assert read() == {"pve": [], "vm": ["VM alias", "192.0.2.10"], "router": ["192.0.2.1"]}
    assert read(now + timedelta(hours=1))["vm"] == ["VM alias"]
    placement["confirmed"] = False
    assert read()["vm"] == ["VM alias"]


def test_attachment_view_matches_guest_mac_to_the_correct_physical_pair(tmp_path, monkeypatch):
    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    stamp = datetime.now(timezone.utc).isoformat()
    vlan_ports = {
        "host": {"name": "ens7", "state": "up", "source": "Proxmox · sysfs", "checkedAt": stamp, "speedBps": 10**10},
        "switch": {"name": "xe3", "state": "up", "checkedAt": stamp, "speedBps": 10**10},
    }
    for port in vlan_ports.values():
        port["vlanMemberships"] = {"checkedAt": stamp, "vlans": [
            {"id": 1, "egress": "untagged", "pvid": True},
            {"id": 20, "egress": "tagged", "pvid": False},
            {"id": 50, "egress": "tagged", "pvid": False},
        ]}
    raw = {"schema": 1, "snapshotAt": stamp, "nodes": [
        {"id": key, "name": key, "kind": kind, **extra} for key, kind, extra in (
            ("directum", "Сервис", {}),
            ("vm", "Виртуальная машина", {"guest": True, "vmid": 103,
             "resources": {"uptimeSeconds": 300, "checkedAt": stamp},
             "guestIo": {"networkInBytesPerSecond": 2.3, "networkOutBytesPerSecond": 0,
                         "diskReadBytesPerSecond": 800, "diskWriteBytesPerSecond": 10,
                         "checkedAt": stamp, "intervalSeconds": 120},
             "sources": [{"name": "Proxmox", "status": "ok", "label": "Запущена", "at": stamp}]}),
            ("pve", "Гипервизор", {"ports": [vlan_ports["host"]]}),
            ("snr", "Коммутатор", {"ports": [vlan_ports["switch"]]}),
        )],
        "links": [
            {"a": "vm", "b": "directum", "kind": "Цель проверки", "confirmed": True},
            {"a": "pve", "b": "vm", "kind": "Размещение ВМ", "source": "Proxmox", "confirmed": True,
             "observedAt": stamp, "portEvidence": [{"a": "vmbr1", "b": "net0", "source": "Proxmox · конфигурация ВМ",
                 "confirmed": True, "at": stamp, "virtual": {"bridgeActive": True, "bridgeVlanMode": "enabled",
                                                              "uplinks": ["ens7"],
                     "switchPorts": [{"id": "snr", "port": "xe3", "at": stamp, "vlan": 1}]}}]},
            {"a": "snr", "b": "pve", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [
                {"a": "xe3", "b": "ens7", "source": "netctl FDB + Proxmox", "confirmed": True, "at": stamp},
                {"a": "ge12", "b": "eno1", "source": "netctl FDB + Proxmox", "confirmed": True, "at": stamp},
            ]},
        ]}
    client, headers, _ = make_client(tmp_path, monkeypatch)
    url = "/api/v1/network/infrastructure?view=attachment"

    def read():
        path.write_text(json.dumps(raw), encoding="utf-8")
        response = client.get(url + "&node_id=directum", headers=headers)
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        report = response.json()["infrastructure"]
        assert "nodes" not in report and "links" not in report
        return report["attachment"]

    report = read()
    assert report["node"]["id"] == "directum"
    guest, = report["guests"]
    assert guest["guest"]["vmid"] == 103 and guest["hypervisor"]["id"] == "pve"
    traffic = {"networkInBytesPerSecond": 2.3, "networkOutBytesPerSecond": 0,
               "source": "Proxmox", "checkedAt": stamp, "intervalSeconds": 120}
    assert guest["networkTraffic"] == traffic
    interface, = guest["interfaces"]
    assert (interface["guestPort"], interface["bridge"]) == ("net0", "vmbr1")
    assert interface["bridgeVlanConfig"] == {"mode": "enabled", "source": "Proxmox API", "checkedAt": stamp}
    match, = interface["switchObservations"]
    assert match["basis"] == "guest_mac" and match["switchPort"] == "xe3"
    assert match["physicalPair"] == {"hostPort": "ens7", "switchPort": "xe3",
                                      "source": "netctl FDB + Proxmox", "checkedAt": stamp}
    port_links = {
        "host": {"state": "up", "speedBps": 10**10, "checkedAt": stamp, "source": "Proxmox · sysfs"},
        "switch": {"state": "up", "speedBps": 10**10, "checkedAt": stamp},
    }
    assert match["uplinkPortLinks"] == port_links
    assert match["uplinkLinkHealth"] == {"state": "both_up", "checkedAt": stamp}
    cable_reports = raw["links"][2]["portEvidence"]
    for conflict in ({"b": "eno1"}, {"a": "xe4"}):
        cable_reports.append({**cable_reports[0], **conflict})
        observation, = read()["guests"][0]["interfaces"][0]["switchObservations"]
        assert observation["basis"] == "guest_mac"
        assert "physicalPair" not in observation and "vlanMemberships" not in observation
        assert "uplinkPortLinks" not in observation
        assert "uplinkLinkHealth" not in observation
        cable_reports.pop()
    assert read()["guests"] == [guest]

    def guests_on_port(port):
        response = client.get("/api/v1/network/infrastructure", params={
            "view": "topology", "node_id": "snr", "port_name": port,
        }, headers=headers)
        assert response.status_code == 200
        audit = response.json()["infrastructure"]["topologyAudit"]
        assert audit["guestAttachmentTotal"] == len(audit["guestAttachments"])
        return audit["guestAttachments"]

    row, = guests_on_port("XE3")
    assert row == {"guest": guest["guest"], "hypervisor": guest["hypervisor"],
                   "guestPort": "net0", "bridge": "vmbr1", **match}
    legacy = client.get("/api/v1/network/infrastructure?include_service_ports=true&include_port_pairs=true",
                        headers=headers).json()["infrastructure"]
    assert legacy["guestSwitchAttachments"]["snr"] == [row]
    assert guests_on_port("ge12") == []
    def guests_on_host_port(port):
        response = client.get("/api/v1/network/infrastructure", params={
            "view": "topology", "node_id": "pve", "port_name": port,
        }, headers=headers)
        assert response.status_code == 200
        return response.json()["infrastructure"]["topologyAudit"]

    host_audit = guests_on_host_port("ENS7")
    assert host_audit["guestAttachmentTotal"] == 1
    assert host_audit["guestAttachments"] == [row]
    assert host_audit["confirmedUplinks"][0]["switchPort"] == "xe3"
    unrelated = guests_on_host_port("eno1")
    assert unrelated["guestAttachmentTotal"] == unrelated["confirmedUplinkTotal"] == 0
    vlan_evidence = match["vlanMemberships"]
    assert vlan_evidence == {"id": 1, "basis": "guest_mac", "ports": {
        "host": {"egress": "untagged", "pvid": True, "source": "Proxmox · sysfs", "checkedAt": stamp},
        "switch": {"egress": "untagged", "pvid": True, "source": "SNMP", "checkedAt": stamp},
    }}
    old = (datetime.fromisoformat(stamp) - timedelta(minutes=11)).isoformat()
    from app import infrastructure_service_probes as probes

    monkeypatch.setattr(probes, "_ldap", lambda ip, port, spec: "reachable")
    service = {"id": "directum", "kind": "Сервис"}
    probes.apply_service_probes([service], {"directum": [{"type": "ldap", "ip": "192.0.2.11", "port": 389}]})
    check, = service["serviceChecks"]
    check["checkedAt"] = stamp
    address = {"address": "192.0.2.11", "source": "UI_VPN", "method": "ICMP · ARP", "checkedAt": stamp}
    adapter, = raw["links"][1]["portEvidence"]
    adapter["virtual"]["ipv4Observations"] = [address]
    raw["nodes"][0]["serviceChecks"] = [check, {**check, "target": "192.0.2.12"}]
    service_path, = read()["servicePaths"]
    assert service_path == {"target": "192.0.2.11", "port": 389, "method": "LDAP", "checkedAt": stamp,
                            "state": "reachable",
                            "guestId": "vm", "guestPort": "net0", "bridge": "vmbr1", "hypervisorId": "pve",
                            "switchId": "snr", "physicalPair": match["physicalPair"], "addressCheckedAt": stamp,
                            "destinationVlan": vlan_evidence, "uplinkPortLinks": port_links,
                            "uplinkLinkHealth": match["uplinkLinkHealth"]}
    switch_port = vlan_ports["switch"]
    speed = switch_port["speedBps"]
    switch_port["speedBps"] = 10**9
    assert read()["servicePaths"][0]["uplinkLinkHealth"] == {"state": "speed_mismatch", "checkedAt": stamp}
    switch_port["speedBps"] = speed
    switch_port["checkedAt"] = (datetime.fromisoformat(stamp) - timedelta(minutes=3)).isoformat()
    assert read()["servicePaths"][0]["uplinkLinkHealth"] == {"state": "unconfirmed"}
    switch_port["checkedAt"] = stamp
    telemetry = {"checkedAt": stamp, "intervalSeconds": 300, "rxBps": 1024, "txBps": 2048, "rxDiscards": 3}
    vlan_ports["switch"]["telemetry"] = telemetry
    measured = read()["servicePaths"][0]
    assert measured["switchPortTelemetry"] == telemetry
    raw["nodes"][-1]["ports"].append({**vlan_ports["switch"], "name": "ge12"})
    service_checks = raw["nodes"][0]["serviceChecks"]
    raw["nodes"][0]["serviceChecks"] = [{**service_checks[0], "state": "unreachable", "required": True}]
    raw["nodes"][0]["reachability"] = {"state": "unreachable", "source": "Проверка сервиса",
                                        "method": "LDAP", "checkedAt": stamp}
    read()
    url_topology = "/api/v1/network/infrastructure?view=topology"
    audit = client.get(url_topology, headers=headers).json()["infrastructure"]["topologyAudit"]["portCounterAudit"]
    rows = {row["port"]: row for row in audit["ports"]}
    assert rows["xe3"]["linkedStatusCounts"] == {"critical": 1, "warn": 0, "unknown": 0, "ok": 0}
    assert "linkedStatusCounts" not in rows["ge12"]
    scoped = client.get(url_topology + "&node_id=snr&port_name=XE3", headers=headers).json()["infrastructure"]
    assert scoped["topologyAudit"]["portCounterAudit"]["ports"] == [rows["xe3"]]
    from app.infrastructure_map import load_infrastructure_map

    assert load_infrastructure_map(path, include_guest_attachments=True)["portCounterAudit"] == audit
    raw["nodes"][-1]["ports"].pop()
    raw["nodes"][0]["serviceChecks"] = service_checks
    raw["nodes"][0].pop("reachability")
    vlan_ports["switch"]["telemetry"] = {**telemetry, "checkedAt": old}
    assert "switchPortTelemetry" not in read()["servicePaths"][0]
    from app.infrastructure_map import WINDOWS_PROBE_SOURCE

    raw["nodes"][0]["serviceChecks"].append({**check, "source": WINDOWS_PROBE_SOURCE, "method": "HTTP",
                                            "port": 80, "supplemental": True, "via": "192.0.2.1"})
    raw["nodes"].append({"id": "pc", "name": "Windows", "kind": "Рабочая станция"})
    raw["links"].extend([
        {"a": "pc", "b": "directum", "kind": "Источник проверки", "confirmed": True},
        {"a": "snr", "b": "pc", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [
            {"a": "ge20", "b": "Ethernet", "source": "SNMP + Windows", "at": stamp, "confirmed": True,
             "windowsAdapter": {"ifIndex": 10, "checkedAt": stamp, "switchCheckedAt": stamp}},
        ]},
    ])
    windows = next((path for path in read()["servicePaths"] if path.get("source") == WINDOWS_PROBE_SOURCE), None)
    assert windows and windows["physicalPair"] == match["physicalPair"] and windows["via"] == "192.0.2.1"
    assert windows["destinationVlan"] == match["vlanMemberships"]
    assert windows["clientAttachment"] == {"stationId": "pc", "stationPort": "Ethernet", "switchId": "snr",
                                            "switchPort": "ge20", "source": "SNMP + Windows", "checkedAt": stamp}
    raw["nodes"][0]["serviceChecks"].append({**check, "source": WINDOWS_PROBE_SOURCE, "method": "DNS",
                                            "target": "192.0.2.53", "port": 53, "required": True})
    dns = next(path for path in read()["servicePaths"] if path["method"] == "DNS")
    assert dns["clientAttachment"] == windows["clientAttachment"]
    assert "physicalPair" not in dns and "destinationVlan" not in dns
    raw["nodes"][0]["serviceChecks"].pop()
    evidence = raw["links"].pop()["portEvidence"][0]
    older = (datetime.fromisoformat(stamp) - timedelta(seconds=1)).isoformat()
    evidence.update(at=older, windowsAdapter={"ifIndex": 10, "checkedAt": older, "switchCheckedAt": stamp})
    raw["links"].append({"a": "snr", "b": "pc", "kind": "Сетевое соединение", "confirmed": True,
                         "portEvidence": [evidence]})
    assert not any("clientAttachment" in path for path in read()["servicePaths"])
    del raw["links"][-2:]
    raw["nodes"].pop()
    raw["nodes"][0]["serviceChecks"].pop()
    adapter["virtual"]["switchPorts"].append({"id": "snr", "port": "ge12", "at": stamp, "vlan": 1})
    ambiguous = read()
    assert ambiguous["guests"][0]["interfaces"][0]["ambiguousSwitchPorts"]
    assert ambiguous.get("servicePaths", []) == []
    adapter["virtual"]["switchPorts"].pop()
    raw["links"][1]["portEvidence"].append({**adapter, "b": "net1"})
    assert read()["servicePaths"] == []
    raw["links"][1]["portEvidence"].pop()
    expired = (datetime.fromisoformat(stamp) - timedelta(minutes=26)).isoformat()
    address["checkedAt"] = expired
    assert read()["servicePaths"] == []
    address["checkedAt"] = stamp
    check["checkedAt"] = expired
    assert read()["servicePaths"] == []
    check["checkedAt"] = stamp
    adapter["virtual"]["uplinks"] = ["eno1"]
    assert read()["servicePaths"] == []
    adapter["virtual"]["uplinks"] = ["ens7"]
    raw["nodes"][0].pop("serviceChecks")
    adapter["virtual"].pop("ipv4Observations")
    host = vlan_ports["host"]
    host["checkedAt"] = host["vlanMemberships"]["checkedAt"] = old
    observation, = read()["guests"][0]["interfaces"][0]["switchObservations"]
    assert observation["physicalPair"] == match["physicalPair"]
    assert observation["vlanMemberships"]["ports"] == {"switch": vlan_evidence["ports"]["switch"]}
    host["checkedAt"] = host["vlanMemberships"]["checkedAt"] = stamp
    assert read()["guests"] == [guest]

    def read_audit():
        response = client.get(url, headers=headers)
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        report = response.json()["infrastructure"]
        assert "nodes" not in report and "links" not in report
        return report["attachmentAudit"]

    audit = read_audit()
    assert audit["guestCounts"] == {"running": 1, "stopped": 0, "prelaunch": 0, "paused": 0, "unknown": 0}
    assert audit["interfaceCounts"]["guest_mac_with_physical_pair"] == 1
    assert audit["gapTotal"] == 0
    assert audit["confirmedUplinkTotal"] == 1
    uplink, = audit["confirmedUplinks"]
    assert uplink["switch"]["id"] == "snr" and uplink["switchPort"] == "xe3"
    assert uplink["hypervisor"] == guest["hypervisor"] and uplink["hostPort"] == "ens7"
    assert uplink["guestTotal"] == uplink["interfaceTotal"] == 1
    assert uplink["uplinkPortLinks"] == port_links
    assert uplink["uplinkLinkHealth"] == match["uplinkLinkHealth"]
    assert uplink["interfaces"] == [
        {"guest": guest["guest"], "guestPort": "net0", "bridge": "vmbr1", "basis": "guest_mac"},
    ]
    switch = client.get(url + "&node_id=snr", headers=headers).json()["infrastructure"]["attachment"]
    assert switch["confirmedUplinkTotal"] == 1
    assert switch["confirmedUplinks"] == [uplink]
    topology = client.get("/api/v1/network/infrastructure?view=topology&node_id=snr&port_name=ge12",
                          headers=headers).json()["infrastructure"]["topologyAudit"]
    assert topology["confirmedUplinkTotal"] == 0

    def read_hypervisor():
        response = client.get(url + "&node_id=pve", headers=headers)
        assert response.status_code == 200
        return response.json()["infrastructure"]["attachment"]

    hypervisor = read_hypervisor()
    assert hypervisor["guestTotal"] == hypervisor["physicalHostTotal"] == 1
    assert hypervisor["guests"] == [guest]
    assert hypervisor["confirmedUplinkTotal"] == 1
    assert hypervisor["confirmedUplinks"] == [uplink]
    hypervisor_node = next(node for node in raw["nodes"] if node["id"] == "pve")
    hypervisor_node["sources"] = [{"name": "Proxmox", "status": "ok", "label": "В сети", "at": stamp}]
    hypervisor_node["resourceCapacity"] = {"checkedAt": stamp, "memory": {"free": 40, "total": 1000},
                                           "endpointMemory": {"availableBytes": 50, "checkedAt": stamp}}
    read()
    capacity = read_hypervisor()["resourceCapacity"]
    assert capacity["memoryHeadroom"]["availablePercent"] == 5
    assert capacity["memoryHeadroom"]["source"] == "Endpoint Agent"
    assert read_hypervisor()["confirmedUplinks"] == [uplink]
    raw["nodes"].append({"id": "pve2", "name": "pve2", "kind": "Гипервизор"})
    raw["links"].append({**raw["links"][1], "a": "pve2", "portEvidence": []})
    read()
    hypervisor = read_hypervisor()
    assert hypervisor["guestTotal"] == hypervisor["confirmedUplinkTotal"] == 0
    raw["links"].pop()
    raw["nodes"].pop()
    virtual = raw["links"][1]["portEvidence"][0]["virtual"]
    virtual["switchPorts"].append({"id": "snr", "port": "ge12", "at": stamp, "vlan": 1})
    read()
    ambiguous = read_audit()
    assert ambiguous["interfaceCounts"]["ambiguous_switch_port"] == 1
    assert ambiguous["confirmedUplinkTotal"] == 0 and ambiguous["confirmedUplinks"] == []
    gap, = ambiguous["gaps"]
    assert gap["interfaces"] == [{"guestPort": "net0", "bridge": "vmbr1", "state": "ambiguous_switch_port",
                                  "switchPorts": [{"switchId": "snr", "port": "ge12"},
                                                  {"switchId": "snr", "port": "xe3"}]}]
    virtual["switchPorts"].pop()
    read()
    browser_endpoint = "/network/infrastructure/snapshot"
    assert client.get(browser_endpoint, follow_redirects=False).status_code == 303
    login = client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": "admin-pass"},
                follow_redirects=False)
    browser = client.get(browser_endpoint).json()["infrastructure"]
    assert browser["guestAttachments"] == {"vm": guest}
    assert browser["servicePaths"] == {}
    raw["nodes"][0]["serviceChecks"] = [check]
    adapter["virtual"]["ipv4Observations"] = [address]
    assert read()["servicePaths"] == [service_path]
    raw["nodes"][0]["serviceChecks"].extend([{**check, "port": 3268}, {**check, "target": "192.0.2.90"}])
    raw["nodes"][0].update(
        sources=[{"name": "Server Observer", "status": "critical", "at": stamp}],
        requiredObserverChecks=["c_disk_free", "iis_active"],
        checks=[{"name": "c_disk_free", "status": "critical", "observed": 4.53, "expected": 15},
                {"name": "iis_active", "status": "ok"}],
    )
    raw["nodes"].append({"id": "backup", "name": "Backup", "kind": "Сервис",
                         "reachability": {"state": "unreachable", "source": "UI_VPN", "checkedAt": stamp}})
    raw["links"].append({"a": "directum", "b": "backup", "kind": "Зависимость сервиса", "confirmed": True})
    assert len(read()["servicePaths"]) == 2
    services_url = "/api/v1/network/infrastructure?view=services"
    def service_audit_row():
        audit = client.get(services_url, headers=headers).json()["infrastructure"]["serviceAudit"]
        return next(row for row in audit["services"] if row["id"] == "directum")

    audit_row = service_audit_row()
    assert audit_row["guestUplinks"] == [{
        "guestId": "vm", "guestPort": "net0", "bridge": "vmbr1", "hypervisorId": "pve",
        "switchId": "snr", "basis": "guest_mac", **match["physicalPair"],
    }]
    assert "portObservation" not in next(issue for issue in audit_row["issues"] if issue["check"] == "c_disk_free")
    adapter["virtual"]["linkDisabled"] = True
    read()
    assert "guestUplinks" not in service_audit_row()
    adapter["virtual"]["linkDisabled"] = False
    read()
    vm_url = url + "&node_id=vm"
    vm = client.get(vm_url, headers=headers).json()["infrastructure"]["attachment"]
    disk, = vm["checks"]
    assert (disk["name"], disk["observed"], disk["sourceNodeId"], disk["required"]) == (
        "c_disk_free", 4.53, "directum", False,
    )
    raw["nodes"].append({"id": "other-vm", "name": "Other", "kind": "Виртуальная машина", "guest": True})
    raw["links"].append({"a": "other-vm", "b": "directum", "kind": "Цель проверки", "confirmed": True})
    read()
    assert client.get(vm_url, headers=headers).json()["infrastructure"]["attachment"]["checks"] == []
    raw["links"].pop()
    raw["nodes"].pop()
    read()
    browser = client.get(browser_endpoint).json()["infrastructure"]
    assert browser["servicePaths"] == {"directum": [service_path, {**service_path, "port": 3268}]}
    switch_ports = browser["servicePorts"]["snr"]
    assert len(switch_ports) == 1 and switch_ports[0]["port"] == "xe3" and switch_ports[0]["total"] == 1
    assert switch_ports[0]["statusCounts"] == {"critical": 0, "warn": 0, "unknown": 1, "ok": 0}
    assert [service["id"] for service in switch_ports[0]["services"]] == ["directum"]
    issue, = switch_ports[0]["services"][0]["observerIssues"]
    assert (issue["name"], issue["status"], issue["observed"], issue["unit"]) == (
        "c_disk_free", "critical", 4.53, "percent",
    )
    assert switch_ports[0]["services"][0]["dependencies"] == {
        "unavailable": ["backup"], "degraded": [], "unknown": [],
    }
    assert [(probe["target"], probe["port"]) for probe in switch_ports[0]["services"][0]["probeEndpoints"]] == [
        ("192.0.2.11", 389), ("192.0.2.11", 3268),
    ]
    switch = client.get(url + "&node_id=snr", headers=headers).json()["infrastructure"]["attachment"]
    assert switch["servicePorts"] == switch_ports
    port_api = client.get("/api/v1/network/infrastructure?include_service_ports=true", headers=headers)
    assert port_api.status_code == 200
    port_graph = port_api.json()["infrastructure"]
    assert port_graph["servicePorts"]["snr"] == switch_ports
    assert "guestAttachments" not in port_graph and "pendingPortPairs" not in port_graph
    http = {**check, "method": "HTTP", "port": 8787}
    raw["nodes"][0]["serviceChecks"] = [
        {**http, "path": "/api/session", "httpStatus": 200},
        {**http, "path": "/app.js", "state": "unreachable", "httpStatus": 503},
        {**http, "path": "/style.css", "state": "unknown"},
    ]
    assert [(path["path"], path["state"], path.get("httpStatus")) for path in read()["servicePaths"]] == [
        ("/api/session", "reachable", 200), ("/app.js", "unreachable", 503), ("/style.css", "unknown", None),
    ]
    browser = client.get(browser_endpoint).json()["infrastructure"]
    probes = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert [(probe["path"], probe["passed"], probe["failed"], probe["unconfirmed"]) for probe in probes] == [
        ("/api/session", 1, 0, 0), ("/app.js", 0, 1, 0), ("/style.css", 0, 0, 1),
    ]
    assert [probe.get("responseCodes") for probe in probes] == [[200], [503], None]
    expires = (datetime.fromisoformat(stamp) - timedelta(days=1)).isoformat()
    raw["nodes"][0]["serviceChecks"] = [
        {**check, "method": "Сертификат TLS", "port": 443, "tlsVersion": "TLSv1.3",
         "tlsExpiresAt": expires, "state": "unreachable", "reason": "tls_certificate_expired"},
    ]
    certificate_path, = read()["servicePaths"]
    assert certificate_path["tlsExpiresAt"] == expires and certificate_path["tlsVersion"] == "TLSv1.3"
    raw["nodes"][0]["serviceChecks"].append({**raw["nodes"][0]["serviceChecks"][0], "target": "192.0.2.90"})
    read()
    issues = {issue.get("target"): issue for issue in service_audit_row()["issues"]}
    assert issues["192.0.2.11"]["portObservation"] == {
        "nodeId": "snr", "port": "xe3", "source": "netctl FDB + Proxmox",
        "checkedAt": certificate_path["physicalPair"]["checkedAt"],
    }
    assert "portObservation" not in issues["192.0.2.90"]
    raw["nodes"][0]["serviceChecks"].pop()
    read()
    browser = client.get(browser_endpoint).json()["infrastructure"]
    certificate, = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert certificate["tlsCertificates"] == [{"expiresAt": expires, "version": "TLSv1.3"}]
    smb = {**check, "method": "SMB2", "port": 445, "smbDialect": "2.1", "smbSigningRequired": False}
    raw["nodes"][0]["serviceChecks"] = [smb, {**smb, "smbSigningRequired": True},
                                       {**smb, "smbSigningRequired": "invalid"}]
    smb_paths = read()["servicePaths"]
    assert [path.get("smbSigningRequired") for path in smb_paths] == [False, True, None]
    assert [path.get("smbDialect") for path in smb_paths] == ["2.1", "2.1", None]
    browser = client.get(browser_endpoint).json()["infrastructure"]
    smb_endpoint, = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert smb_endpoint["smbNegotiations"] == [{"dialect": "2.1", "signingRequired": False},
                                               {"dialect": "2.1", "signingRequired": True}]
    postgres = {**check, "method": "PostgreSQL SSLRequest", "port": 5432}
    raw["nodes"][0]["serviceChecks"] = [
        {**postgres, "postgresqlTls": "negotiated", "tlsVersion": "TLSv1.3"},
        {**postgres, "postgresqlTls": "declined"},
    ]
    assert [(path["postgresqlTls"], path.get("tlsVersion")) for path in read()["servicePaths"]] == [
        ("negotiated", "TLSv1.3"), ("declined", None),
    ]
    browser = client.get(browser_endpoint).json()["infrastructure"]
    endpoint, = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert endpoint["postgresqlTlsResults"] == [
        {"state": "negotiated", "version": "TLSv1.3"}, {"state": "declined"},
    ]
    raw["nodes"][0]["serviceChecks"] = [
        {**check, "method": "SIP OPTIONS (UDP)", "port": 5060, "reason": "sip_response", "responseCode": 200},
        {**check, "method": "RTSP OPTIONS", "port": 554, "reason": "rtsp_auth_required", "rtspStatus": 401},
    ]
    sip, rtsp = read()["servicePaths"]
    assert sip["responseCode"] == 200 and rtsp["rtspStatus"] == 401
    browser = client.get(browser_endpoint).json()["infrastructure"]
    probes = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert [(probe["port"], probe["responseCodes"]) for probe in probes] == [(554, [401]), (5060, [200])]
    raw["nodes"][0]["serviceChecks"] = [
        {**check, "method": "HTTPS", "port": 443, "path": "/redfish/v1/", "httpStatus": 200, "redfishVersion": "1.5.0"},
        {**check, "method": "FTP FEAT", "port": 21, "ftpReply": 211},
    ]
    redfish, ftp = read()["servicePaths"]
    assert redfish["redfishVersion"] == "1.5.0" and ftp["ftpReply"] == 211
    browser = client.get(browser_endpoint).json()["infrastructure"]
    ftp, redfish = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert ftp["responseCodes"] == [211]
    assert redfish["responseCodes"] == [200] and redfish["redfishVersions"] == ["1.5.0"]
    raw["nodes"][0]["serviceChecks"] = [
        {**check, "method": "SIP OPTIONS (UDP)", "port": 5060, "state": "unreachable",
         "reason": "icmp_port_unreachable", "errorSource": address["address"]},
        {**check, "method": "TCP", "port": 5060},
    ]
    udp_path = read()["servicePaths"][0]
    assert udp_path["errorSource"] == address["address"]
    browser = client.get(browser_endpoint).json()["infrastructure"]
    udp, tcp = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert udp["issues"] == [{"state": "unreachable", "reason": "icmp_port_unreachable",
                              "errorSource": address["address"]}]
    assert tcp["passed"] == 1 and "issues" not in tcp
    route = {"state": "reachable", "gateway": address["address"], "expectedGateway": address["address"],
             "sourceIP": "192.0.2.20", "interface": "ens18"}
    routed = {**check, "method": "DNS", "port": 53, "target": "198.51.100.1", "localRoute": route}
    raw["nodes"][0]["serviceChecks"] = [routed]
    routed_path = {**service_path, "target": routed["target"], "port": 53, "method": "DNS",
                   "gateway": route["gateway"], "localRoute": route}
    del routed_path["destinationVlan"]
    assert read()["servicePaths"] == [routed_path]
    browser = client.get(browser_endpoint).json()["infrastructure"]
    assert browser["servicePaths"] == {"directum": [routed_path]}
    assert browser["servicePorts"]["snr"][0]["services"][0]["basis"] == ["guest_gateway"]
    adapter["virtual"]["ipv4Observations"].append({**address, "address": routed["target"]})
    assert read()["servicePaths"] == [routed_path]
    adapter["virtual"]["ipv4Observations"].pop()
    dns_checks = [
        {**routed, "state": state, "dns": {"name": name, "record": record, "transport": transport}}
        for name, record, transport, state in (
            ("example.test.", "A", "TCP", "reachable"),
            ("example.test.", "A", "UDP", "unreachable"),
            ("_ldap._tcp.example.test.", "SRV", "TCP", "unknown"),
        )
    ]
    raw["nodes"][0]["serviceChecks"] = dns_checks
    assert [path["dns"] for path in read()["servicePaths"]] == [check["dns"] for check in dns_checks]
    browser = client.get(browser_endpoint).json()["infrastructure"]
    probes = browser["servicePorts"]["snr"][0]["services"][0]["probeEndpoints"]
    assert [(probe["transport"], probe["dns"]["name"], probe["dns"]["record"],
             probe["passed"], probe["failed"], probe["unconfirmed"]) for probe in probes] == [
        ("TCP", "_ldap._tcp.example.test.", "SRV", 0, 0, 1),
        ("TCP", "example.test.", "A", 1, 0, 0),
        ("UDP", "example.test.", "A", 0, 1, 0),
    ]
    raw["nodes"][0]["serviceChecks"] = [routed]
    route["state"] = "unreachable"
    assert read()["servicePaths"] == []
    route["state"] = "reachable"
    route["expectedGateway"] = "192.0.2.99"
    assert read()["servicePaths"] == []
    route["expectedGateway"] = route["gateway"]
    raw["links"][1]["portEvidence"].append({**adapter, "b": "net1"})
    assert read()["servicePaths"] == []
    raw["links"][1]["portEvidence"].pop()
    socket_check = {"method": "OpenVPN Management", "source": "UI_VPN", "state": "unknown", "configuredPort": 1194,
                    "localUdpSocket": {"state": "bound", "addresses": ["0.0.0.0", address["address"]]},
                    "checkedAt": stamp, "reason": "openvpn_no_active_sessions"}
    listener_check = {**socket_check, "method": "OpenVPN UDP-сокет", "state": "reachable",
                      "reason": "", "required": True}
    raw["nodes"][0]["serviceChecks"] = [socket_check, listener_check]
    assert read()["servicePaths"] == []  # An ARP match alone cannot establish which guest owns the local socket.
    adapter["virtual"]["ipv4Observations"] = [{**address, "method": "Локальный интерфейс ens18"}]
    listener, = read()["servicePaths"]
    assert listener == {**service_path, "method": "Локальный UDP-сокет", "port": 1194, "localListener": True}
    browser = client.get(browser_endpoint).json()["infrastructure"]
    service, = browser["servicePorts"]["snr"][0]["services"]
    assert service["basis"] == ["guest_local_udp"]
    endpoint, = service["probeEndpoints"]
    assert (endpoint["target"], endpoint["port"], endpoint["localListener"]) == (address["address"], 1194, True)
    listener_check["state"] = "unknown"
    assert read()["servicePaths"] == []
    raw["nodes"][0]["serviceChecks"] = [socket_check]
    legacy_listener, = read()["servicePaths"]
    assert legacy_listener == listener
    socket_check["localUdpSocket"]["addresses"] = ["0.0.0.0", "::", "*"]
    assert read()["servicePaths"] == []
    raw["nodes"][0].pop("serviceChecks")
    adapter["virtual"].pop("ipv4Observations")
    raw["links"][1]["portEvidence"][0]["virtual"]["uplinks"] = ["eno1"]
    match, = read()["guests"][0]["interfaces"][0]["switchObservations"]
    assert "physicalPair" not in match and "vlanMemberships" not in match
    audit = read_audit()
    assert audit["interfaceCounts"]["guest_mac"] == 1 and audit["gapTotal"] == 1
    gap, = audit["gaps"]
    assert gap["guest"]["id"] == "vm"
    assert gap["networkTraffic"] == traffic
    assert gap["interfaces"] == [{"guestPort": "net0", "bridge": "vmbr1", "state": "guest_mac"}]
    raw["links"][1]["portEvidence"][0]["virtual"]["uplinks"] = ["ens7"]
    guest_port = raw["links"][1]["portEvidence"][0]
    virtual = guest_port["virtual"]
    virtual["switchUplink"], = virtual.pop("switchPorts")
    guest_port["vlan"] = 20
    configured, = read()["guests"][0]["interfaces"][0]["switchObservations"]
    assert configured["vlanMemberships"]["basis"] == "configured_tag"
    assert configured["vlanMemberships"]["id"] == 20
    assert {r["egress"] for r in configured["vlanMemberships"]["ports"].values()} == {"tagged"}
    guest_port.pop("vlan")
    assert read_audit()["interfaceCounts"]["bridge_with_physical_pair"] == 1
    raw["nodes"][0]["serviceChecks"] = [{
        "method": "ICMP · VLAN", "state": "reachable", "source": "UI_VPN", "checkedAt": stamp,
        "required": True, "target": "192.0.2.1",
        "vlanTransit": {"interface": "ens18.50", "id": 50, "localAddress": "192.0.2.2/30",
                        "peer": {"asset": "vm", "guestPort": "net0", "state": "matched"}},
    }]
    interface, = read()["guests"][0]["interfaces"]
    assert interface["localNeighbor"] == {
        "vlan": 50, "interface": "ens18.50", "peerAddress": "192.0.2.1", "checkedAt": stamp,
    }
    assert interface["switchObservations"][0]["basis"] == "bridge_uplink"
    assert interface["switchObservations"][0]["vlanMemberships"]["basis"] == "local_neighbor"
    assert interface["switchObservations"][0]["vlanMemberships"]["id"] == 50
    transit_path, = read()["servicePaths"]
    assert transit_path == {"target": "192.0.2.1", "port": None, "method": "ICMP · VLAN", "checkedAt": stamp,
                            "state": "reachable",
                            "guestId": "vm", "guestPort": "net0", "bridge": "vmbr1", "hypervisorId": "pve",
                            "switchId": "snr", "physicalPair": interface["switchObservations"][0]["physicalPair"],
                            "addressCheckedAt": stamp, "localNeighbor": interface["localNeighbor"],
                            "uplinkPortLinks": port_links, "uplinkLinkHealth": {"state": "both_up", "checkedAt": stamp}}
    audit = read_audit()
    assert audit["interfaceCounts"]["local_neighbor_with_physical_pair"] == 1 and audit["gapTotal"] == 0
    assert audit["runningNetworkCoverage"] == {"confirmed": 1, "incomplete": 0, "withoutNetwork": 0}
    raw["nodes"][0]["serviceChecks"][0]["vlanTransit"]["peer"]["state"] = "mismatch"
    assert "localNeighbor" not in read()["guests"][0]["interfaces"][0]
    assert read()["servicePaths"] == []
    raw["nodes"][0].pop("serviceChecks")
    virtual["switchPorts"] = [virtual.pop("switchUplink")]
    raw["links"][2]["portEvidence"][0]["source"] = "GitHub"
    match, = read()["guests"][0]["interfaces"][0]["switchObservations"]
    assert match["basis"] == "guest_mac" and "physicalPair" not in match
    raw["links"][1]["portEvidence"][0]["virtual"]["linkDisabled"] = True
    assert read()["guests"][0]["interfaces"][0]["switchObservations"] == []
    assert guests_on_port("xe3") == []
    audit = read_audit()
    assert audit["interfaceCounts"]["inactive"] == 1 and audit["gapTotal"] == 1
    assert audit["runningNetworkCoverage"] == {"confirmed": 0, "incomplete": 1, "withoutNetwork": 0}
    raw["links"][1]["confirmed"] = False
    guest, = read()["guests"]
    assert guest["placement"] == "unconfirmed" and guest["interfaces"] == []
    gap, = read_audit()["gaps"]
    assert gap["placement"] == "unconfirmed" and gap["interfaces"] == []
    raw["nodes"][1]["reachability"] = {"state": "stopped", "checkedAt": stamp, "source": "Proxmox"}
    read()
    assert read_audit()["guestCounts"] == {"running": 0, "stopped": 1, "prelaunch": 0, "paused": 0, "unknown": 0}
    assert read_audit()["gapTotal"] == 0


def test_service_audit_shares_map_status_and_reports_required_check_gaps(tmp_path, monkeypatch):
    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path.write_text(json.dumps({
        "schema": 1, "snapshotAt": stamp,
        "nodes": [
            {"id": "vm", "name": "VM", "kind": "Сервер"},
            {"id": "svc", "name": "Directum", "kind": "Сервис",
             "reachability": {"state": "reachable", "checkedAt": stamp},
             "sources": [{"name": "Server Observer", "at": stamp}],
             "requiredObserverChecks": ["c_disk_free", "iis_active"],
             "checks": [{"name": "c_disk_free", "status": "critical"}],
             "serviceChecks": [
                 {"method": "HTTP", "source": "UI_VPN", "state": "reachable", "required": True, "checkedAt": stamp},
                 {"method": "DNS", "source": "UI_VPN", "state": "unknown", "supplemental": True, "checkedAt": stamp},
                 {"method": "HTTPS", "source": "UI_VPN", "state": "reachable", "required": True,
                  "checkedAt": (now - timedelta(minutes=10)).isoformat()},
             ]},
            {"id": "vipnet", "name": "ViPNet", "kind": "Сервис",
             "serviceChecks": [
                 {"method": "Маршрут", "source": "UI_VPN", "state": "reachable", "required": True,
                  "component": True, "checkedAt": stamp},
                 {"method": "ICMP", "source": "UI_VPN", "state": "unknown", "supplemental": True,
                  "checkedAt": stamp, "reason": "icmp_no_echo_reply"},
             ]},
        ],
        "links": [{"a": "vm", "b": "svc", "kind": "Цель проверки", "confirmed": True}],
    }), encoding="utf-8")
    client, headers, _ = make_client(tmp_path, monkeypatch)
    url = "/api/v1/network/infrastructure"
    response = client.get(url + "?view=services", headers=headers)
    assert response.status_code == 200
    graph = response.json()["infrastructure"]
    assert "nodes" not in graph and "links" not in graph
    audit = graph["serviceAudit"]
    assert audit["total"] == 2 and audit["counts"] == {"critical": 0, "warn": 1, "unknown": 1, "ok": 0}
    row, vipnet = audit["services"]
    full = client.get(url, headers=headers).json()["infrastructure"]
    assert row["id"] == "svc" and row["status"] == full["nodes"][1]["mapStatus"] == "warn"
    assert row["hosts"] == ["vm"]
    attachment = client.get(url + "?view=attachment&node_id=svc", headers=headers).json()["infrastructure"]["attachment"]
    assert attachment["checks"] == full["nodes"][1]["checks"]
    assert attachment["serviceChecks"] == full["nodes"][1]["serviceChecks"]
    assert attachment["physicalHosts"][0]["host"]["id"] == "vm"
    snapshot_with_dependency = json.loads(path.read_text(encoding="utf-8"))
    snapshot_with_dependency["links"].extend([
        {"a": "svc", "b": "vipnet", "kind": "Зависимость сервиса", "confirmed": True},
        {"a": "vipnet", "b": "svc", "kind": "Зависимость сервиса", "confirmed": False},
    ])
    path.write_text(json.dumps(snapshot_with_dependency), encoding="utf-8")
    with_dependency = client.get(url + "?view=attachment&node_id=svc", headers=headers).json()["infrastructure"]["attachment"]
    assert with_dependency["serviceAvailability"] == {"unavailable": [], "degraded": [], "unknown": ["vipnet"]}
    assert with_dependency["dependencyTotal"] == 1
    assert with_dependency["dependencies"] == [
        {"id": "vipnet", "name": "ViPNet", "kind": "Сервис", "mapStatus": "unknown"},
    ]
    from app.infrastructure_map import summarize_services

    dependency_graph = client.get(url, headers=headers).json()["infrastructure"]
    filtered, = summarize_services(dependency_graph, service_ids={"svc"})["serviceAudit"]["services"]
    assert filtered["dependencyIssueTotal"] == 1
    dependency, = filtered["dependencyIssues"]
    assert (dependency["id"], dependency["name"], dependency["status"], dependency["issueTotal"]) == (
        "vipnet", "ViPNet", "unknown", 1,
    )
    assert dependency["issue"]["reason"] == "icmp_no_echo_reply"
    reverse = client.get(url + "?view=attachment&node_id=vipnet", headers=headers).json()["infrastructure"]["attachment"]
    assert reverse["dependencies"] == []
    snapshot_with_dependency["links"] = snapshot_with_dependency["links"][:1]
    path.write_text(json.dumps(snapshot_with_dependency), encoding="utf-8")
    assert row["requiredChecks"] == {"passed": 1, "failed": 1, "unconfirmed": 2}
    assert {(c["check"], c["status"], c["stale"]) for c in row["issues"]} == {
        ("c_disk_free", "critical", False), ("iis_active", "unknown", False), ("HTTPS", "unknown", True),
    }
    assert vipnet["requiredChecks"] == {"passed": 1, "failed": 0, "unconfirmed": 0}
    hint, = vipnet["issues"]
    assert hint["check"] == "ICMP" and hint["required"] is False and hint["reason"] == "icmp_no_echo_reply"
    assert response.headers["cache-control"] == "no-store"
    paged = client.get(url + "?view=services&service_offset=1", headers=headers).json()["infrastructure"]["serviceAudit"]
    assert paged["offset"] == 1 and paged["nextOffset"] is None
    assert paged["counts"] == audit["counts"] and paged["services"] == [vipnet]
    assert client.get(url + "?view=topology&service_offset=1", headers=headers).status_code == 422
    assert client.get(url + "?view=services&service_offset=-1", headers=headers).status_code == 422

    snapshot = json.loads(path.read_text(encoding="utf-8"))
    snapshot["nodes"].extend({"id": f"service-{i}", "name": f"Service {i:03}", "kind": "Сервис"} for i in range(130))
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    first = client.get(url + "?view=services", headers=headers).json()["infrastructure"]["serviceAudit"]
    last = client.get(url + f"?view=services&service_offset={first['nextOffset']}", headers=headers)
    last = last.json()["infrastructure"]["serviceAudit"]
    assert first["nextOffset"] == 128 and last["nextOffset"] is None
    assert first["total"] == last["total"] == 132
    assert len({row["id"] for page in (first, last) for row in page["services"]}) == 132


def test_inventory_port_sources_are_dated_and_kept_separate_from_live_checks(tmp_path):
    from datetime import date

    from app.infrastructure_collect import build_graph, publish_snapshot
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    observed = date(2026, 8, 7)
    reference = {"source": "evidence/manual/port-check.yaml", "observed_at": observed, "value": "omit detail"}
    links = [{"relation": "connected_to", "endpoint_a": {"device": "a", "interface": f"ge{index}"},
              "endpoint_b": {"device": key, "interface": "eth0"}, "state": {"verified": key == "b"},
              "evidence": [reference, reference, {**reference, "source": "docs/../private.yml"},
                           {**reference, "source": "https://example.test/private"},
                           {**reference, "observed_at": "2026-02-30"}]}
             for index, key in enumerate(("b", "c"), 1)]
    context = {"devices": [{"id": key, "name": key, "kind": "switch"} for key in "abc"], "links": links}
    path = tmp_path / "map.json"
    publish_snapshot(path, build_graph(context, {}, {}, {}, {}, now))
    graph = load_infrastructure_map(path, now)
    expected = [{"path": "evidence/manual/port-check.yaml", "observedOn": "2026-08-07"}]
    verified, pending = [edge["portEvidence"][0] for edge in graph["links"]]
    assert verified["inventorySources"] == pending["inventorySources"] == expected
    assert verified["at"] is pending["at"] is None
    assert verified["pairEvidence"] == "verified_inventory" and not pending["confirmed"]
    assert "omit detail" not in path.read_text(encoding="utf-8")
    audit = summarize_topology(graph)["topologyAudit"]
    assert audit["pending"][0]["inventorySources"] == expected
    assert audit["inventoryPairs"] == [{"a": "a", "b": "b", "portA": "ge1", "portB": "eth0",
                                         "inventorySources": expected}]
    assert audit["inventoryOnlyPairTotal"] == 1
    assert audit["inventoryOnlyPairs"] == audit["inventoryPairs"]
    current_graph = {**graph, "links": [*graph["links"], {
        "a": "b", "b": "a", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [
            {"a": "ETH0", "b": "GE1", "source": "LLDP UI_VPN", "confirmed": True,
             "at": now.isoformat(), "pairEvidence": "current"},
        ],
    }]}
    scoped = summarize_topology(current_graph, node_id="a", port_name="ge1")["topologyAudit"]
    assert scoped["currentPairTotal"] == 1
    assert scoped["inventoryOnlyPairTotal"] == 0 and scoped["inventoryOnlyPairs"] == []
    next(node for node in graph["nodes"] if node["id"] == "a")["ports"] = [
        {"name": "Slot0/1", "aliases": ["ge1"]},
    ]
    current_graph["links"][-1]["portEvidence"][0]["b"] = "Slot0/1"
    scoped = summarize_topology(current_graph, node_id="a", port_name="Slot0/1")["topologyAudit"]
    assert len(scoped["inventoryPairs"]) == scoped["currentPairTotal"] == 1
    assert scoped["inventoryOnlyPairTotal"] == 0
    port_graph = load_infrastructure_map(path, now, include_port_pairs=True)
    assert port_graph["inventoryPairs"] == audit["inventoryPairs"]
    assert port_graph["currentPortPairs"] == []
    browser = load_infrastructure_map(path, now, include_guest_attachments=True)
    assert browser["inventoryPairs"] == audit["inventoryPairs"]
    assert browser["currentPortPairs"] == []


def test_topology_withholds_conflicting_live_pairs_even_without_inventory(tmp_path):
    from app.infrastructure_map import load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    raw = {"schema": 1, "snapshotAt": stamp, "nodes": [
        {"id": name, "name": name, "kind": "Коммутатор"} for name in ("core", "one", "two", "three")
    ], "links": [
        {"a": "core", "b": peer, "kind": "Сетевое соединение", "confirmed": True,
         "portEvidence": [{"a": port, "b": "Port1", "source": source, "confirmed": True, "at": stamp}]}
        for peer, port, source in (
            ("one", "Gi1/0/1", "LLDP UI_VPN"), ("two", "gigabitEthernet 1/0/1", "LLDP · двустороннее"),
            ("three", "Gi1/0/2", "LLDP UI_VPN"),
        )
    ]}
    path = tmp_path / "map.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    graph = load_infrastructure_map(path, now, include_guest_attachments=True)
    audit = summarize_topology(graph, node_id="core", port_name="Gi1/0/1")["topologyAudit"]
    assert audit["currentPairTotal"] == 0 and audit["pendingTotal"] == 2
    assert audit["confirmationGapCounts"] == {"conflicting_port_pairs": 2}
    assert {row["b"] for row in audit["pending"]} == {"one", "two"}
    assert all(row["observedPaths"][0]["source"].startswith("LLDP") for row in audit["pending"])
    assert graph["currentPortPairTotal"] == 1 and graph["pendingPortPairTotal"] == 2
    assert graph["currentPortPairs"][0]["b"] == "three"
    assert all(not edge["confirmed"] for edge in graph["links"] if edge["b"] in ("one", "two"))


def test_topology_audit_surfaces_pending_declared_ports_without_promoting_mac_paths(tmp_path, monkeypatch):
    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    now = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps({
        "schema": 1, "snapshotAt": now,
        "nodes": [{"id": "snr", "name": "SNR", "kind": "Коммутатор",
                   "properties": {"Источник сбора": "snr-test"},
                   "ports": [{"name": "ge12", "state": "down", "checkedAt": now, "ifAlias": "PVE1 IPMI"},
                             {"name": "ge15", "key": "ifindex:5015", "state": "up", "speedBps": 10**9, "checkedAt": now,
                              "ifAlias": "<invalid>\npassword=value",
                              "lldpNeighborCount": 2,
                              "lldpNeighbors": [
                                  {"chassisId": "02:00:00:00:00:15", "inventoryDeviceId": "recorder",
                                   "portId": "bond0", "portIdSubtype": "interface_name"},
                                  {"chassisId": "02:00:00:00:00:16", "inventoryDeviceId": "other",
                                   "portId": "eth1", "portIdSubtype": "interface_name"},
                              ],
                              "fdbLearned": {"checkedAt": now, "learnedMacCount": 3, "partial": False},
                              "telemetry": {"checkedAt": now, "intervalSeconds": 60, "rxBps": 0,
                                            "txBps": 400_000, "rxErrors": 5, "private": "excluded"},
                              "rxErrorCounters": {"checkedAt": now, "ifInErrors": 44, "fcsErrors": 0},
                              "transceiver": {"checkedAt": now, "formFactor": "SFP+",
                                              "nominalBps": 10**10, "serialNumber": "excluded"}},
                             {"name": "xe3", "key": "physical:3", "state": "up", "checkedAt": "2026-01-01T00:00:00Z",
                              "ifAlias": "Expired"}]},
                  {"id": "recorder", "name": "Recorder", "kind": "Сервер", "serviceChecks": [
                      {"method": "ICMP адреса из инвентаря", "source": "UI_VPN", "state": "unknown", "checkedAt": now,
                       "supplemental": True, "skipped": True, "reason": "probe_target_unconfirmed",
                       "arpDiagnostic": {"state": "no_reply", "address": "192.0.2.15", "sourceIP": "192.0.2.30",
                                         "interface": "ens18", "private": "excluded"}}]},
                  {"id": "pve", "name": "pve1", "kind": "Гипервизор", "ports": [{"name": "enp2s0"}]}],
        "links": [
            {"a": "snr", "b": "pve", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [
                {"a": "xe3", "b": "vm_net_10g", "source": "GitHub", "confirmed": True},
                {"a": "xe3", "b": "ens7f1", "source": "netctl FDB + Proxmox", "confirmed": True, "at": now},
                {"a": "Port3", "b": "ens7f1", "source": "LLDP · двустороннее", "confirmed": True, "at": now},
                {"a": "ge99", "b": "eno99", "source": "LLDP · двустороннее", "confirmed": True,
                 "at": (datetime.fromisoformat(now) - timedelta(hours=1)).isoformat()},
                {"a": "po1 / ge6", "b": "LACP 1", "source": "SNMP LACP + ARP", "confirmed": True, "at": now},
                {"a": "ge12", "b": "management_1g", "source": "GitHub", "confirmed": False},
                {"a": "xe3", "b": "enp2s0", "source": "GitHub", "confirmed": False},
            ]},
            {"a": "pve", "b": "snr", "kind": "Путь по MAC-таблице", "confirmed": True, "portEvidence": [
                {"a": "enp134s0", "b": "ge12", "source": "netctl FDB + Proxmox", "confirmed": True, "at": now},
            ]},
            {"a": "snr", "b": "recorder", "kind": "Сетевое соединение", "portEvidence": [
                {"a": "ge15", "b": "", "source": "GitHub", "confirmed": False},
            ]},
            {"a": "recorder", "b": "snr", "kind": "Путь по MAC-таблице", "source": "netctl FDB",
             "confirmed": True, "observedAt": now, "portEvidence": [
                {"a": "", "b": "ge15", "source": "netctl FDB", "confirmed": True, "at": now,
                 "learnedEndpoint": {"switchId": "snr", "deviceId": "recorder", "mac": "02:00:00:00:00:15"}},
            ]},
        ],
    }), encoding="utf-8")
    client, headers, _ = make_client(tmp_path, monkeypatch)
    response = client.get("/api/v1/network/infrastructure?view=topology", headers=headers)
    assert response.status_code == 200
    graph = response.json()["infrastructure"]
    assert "nodes" not in graph and "links" not in graph
    audit = graph["topologyAudit"]
    assert audit["directLinks"] == {"current": 1, "verifiedInventory": 0, "unconfirmed": 1}
    assert audit["currentPairTotal"] == 1
    assert audit["currentPairLinkCounts"] == {"unconfirmed": 1}
    assert audit["currentPairs"] == [{"a": "snr", "b": "pve", "nameA": "SNR", "nameB": "pve1",
                                     "linkHealth": {"state": "unconfirmed"},
                                     "portA": "xe3", "portB": "ens7f1", "evidence": [
                                         {"source": "LLDP · двустороннее", "checkedAt": now,
                                          "expiresAt": (datetime.fromisoformat(now) + timedelta(minutes=25)).isoformat()},
                                         {"source": "netctl FDB + Proxmox", "checkedAt": now,
                                          "expiresAt": (datetime.fromisoformat(now) + timedelta(minutes=25)).isoformat()},
                                     ]}]
    from app.infrastructure_map import load_infrastructure_map

    browser_graph = load_infrastructure_map(path, include_guest_attachments=True)
    assert browser_graph["currentPortPairTotal"] == audit["currentPairTotal"]
    assert browser_graph["currentPortPairs"] == audit["currentPairs"]
    assert audit["pendingTotal"] == 3
    pending, mismatch, recorder = audit["pending"]
    assert "missing_port_name" in recorder["confirmationGaps"]
    assert "no_live_peer_identity" not in recorder["confirmationGaps"]
    browser_recorder = next(pair for pair in browser_graph["pendingPortPairs"] if pair["b"] == "recorder")
    assert recorder["portHistory"] == {"a": {"source": "snr-test", "interface": "ifindex:5015"}}
    assert browser_recorder["portHistory"] == recorder["portHistory"]
    assert "portHistory" not in mismatch
    assert browser_recorder["confirmationGaps"] == recorder["confirmationGaps"]
    scoped = client.get("/api/v1/network/infrastructure?view=topology&node_id=snr&port_name=GE15", headers=headers)
    assert scoped.status_code == 200
    port_audit = scoped.json()["infrastructure"]["topologyAudit"]
    assert port_audit["pending"] == [recorder]
    assert port_audit["pendingTotal"] == 1 and port_audit["currentPairTotal"] == 0
    assert port_audit["ports"][0]["name"] == "ge15"
    scope = "/api/v1/network/infrastructure?view=topology&node_id="
    assert client.get(scope + "missing", headers=headers).json()["infrastructure"]["topologyAudit"]["node"] is None
    assert client.get(scope + "pve&port_name=ens7f1", headers=headers).json()["infrastructure"]["topologyAudit"]["currentPairs"] == audit["currentPairs"]
    assert client.get("/api/v1/network/infrastructure?view=topology&port_name=ge15", headers=headers).status_code == 422
    assert (pending["a"], pending["b"], pending["portA"], pending["portB"]) == ("snr", "pve", "ge12", "management_1g")
    observed, = pending["observedPaths"]
    assert (observed["portA"], observed["portB"]) == ("ge12", "enp134s0")
    projected = next(row for row in browser_graph["pendingPortPairs"] if row["portA"] == "ge12")
    assert projected["observedPaths"] == [{key: observed[key] for key in ("portA", "portB", "source", "checkedAt")}]
    assert pending["portObservations"] == {
        "a": {"name": "ge12", "state": "down", "checkedAt": now, "speedBps": None,
              "configuredLabel": {"text": "PVE1 IPMI", "checkedAt": now}},
    }
    assert mismatch["portB"] == "enp2s0" and mismatch["observedPaths"] == []
    assert "portObservations" not in mismatch
    assert recorder["portB"] == "" and recorder["portObservations"] == {
        "a": {"name": "ge15", "state": "up", "checkedAt": now, "speedBps": 10**9,
              "fdbLearned": {"checkedAt": now, "learnedMacCount": 3, "partial": False},
              "telemetry": {"checkedAt": now, "intervalSeconds": 60, "rxBps": 0, "txBps": 400_000, "rxErrors": 5},
              "rxErrorCounters": {"checkedAt": now, "ifInErrors": 44, "fcsErrors": 0},
              "transceiver": {"checkedAt": now, "formFactor": "SFP+", "nominalBps": 10**10}},
    }
    assert recorder["missingPortSides"] == ["b"] and recorder["identifiedPeerSides"] == ["a"]
    assert recorder["multiMacPortSides"] == ["a"]
    projected_recorder = next(row for row in browser_graph["pendingPortPairs"] if row["portA"] == "ge15")
    assert projected_recorder["multiMacPortSides"] == ["a"]
    assert "multiMacPortSides" not in pending
    assert recorder["arpDiagnostics"] == {"b": [{"state": "no_reply", "address": "192.0.2.15",
                                                 "sourceIP": "192.0.2.30", "interface": "ens18", "checkedAt": now}]}
    expected_peer = {"localPort": "ge15", "chassisId": "02:00:00:00:00:15", "portId": "bond0",
                     "portIdSubtype": "interface_name", "checkedAt": now}
    assert recorder["lldpPeers"] == {"a": [expected_peer]}
    assert recorder["logicalPeerInterfaces"] == {"b": [{"name": "bond0", "checkedAt": now}]}
    assert browser_recorder["logicalPeerInterfaces"] == recorder["logicalPeerInterfaces"]
    assert port_audit["confirmationGapCounts"]["logical_lldp_interface"] == 1
    assert len(recorder["lldpObservations"]["a"]["neighbors"]) == 2
    snapshot = client.get("/api/v1/network/infrastructure", headers=headers).json()["infrastructure"]
    edge = next(edge for edge in snapshot["links"] if edge["a"] == "snr" and edge["b"] == "recorder")
    report, = edge["portEvidence"]
    assert report["lldpPeers"] == {"a": [expected_peer]}
    assert report["b"] == "" and not report["confirmed"] and "pairEvidence" not in report
    assert recorder["observedPaths"] == [{
        "portA": "ge15", "portB": "", "source": "netctl FDB", "checkedAt": now,
        "learnedEndpoint": {"switchId": "snr", "deviceId": "recorder", "mac": "02:00:00:00:00:15"},
    }]
    raw = json.loads(path.read_text(encoding="utf-8"))
    port = raw["nodes"][0]["ports"][1]
    port.pop("lldpNeighbors")
    port.pop("lldpNeighborCount")
    port["lldpPort"] = {"admin": "tx_rx", "checkedAt": now, "rxFrames": 0, "txFrames": 21,
                        "delta": {"startedAt": (datetime.fromisoformat(now) - timedelta(seconds=90)).isoformat(),
                                  "rxFrames": 0, "txFrames": 3}}
    path.write_text(json.dumps(raw), encoding="utf-8")
    result = client.get(scope + "snr&port_name=ge15", headers=headers).json()["infrastructure"]["topologyAudit"]
    assert result["confirmationGapCounts"]["no_lldp_rx"] == 1
    assert result["pending"][0]["lldpNoRxSides"] == ["a"]
    port["lldpPort"]["admin"] = "tx_only"
    path.write_text(json.dumps(raw), encoding="utf-8")
    result = client.get(scope + "snr&port_name=ge15", headers=headers).json()["infrastructure"]["topologyAudit"]
    assert "no_lldp_rx" not in result["confirmationGapCounts"]


def test_reciprocal_mac_path_shows_fresh_stp_evidence_without_confirming_cable(tmp_path):
    from app.infrastructure_map import RECIPROCAL_MAC_SOURCE, load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    path = tmp_path / "infrastructure.json"
    stp = {"localPort": "Port13", "designatedBridgeMac": "2c:c8:1b:9c:31:ea",
           "designatedPortId": "80:03", "checkedAt": stamp, "bridgeDeviceId": "root",
           "designatedPortName": "ge21", "designatedPortCheckedAt": stamp}
    switch = {"id": "css", "name": "CSS", "kind": "Коммутатор", "stpRootPath": stp,
              "ports": [{"name": "Port13", "state": "up", "checkedAt": stamp}]}
    declared = {"a": "Port13", "b": "Gi1/22", "source": "GitHub", "confirmed": False}
    observed = {**declared, "source": RECIPROCAL_MAC_SOURCE, "confirmed": True, "at": stamp}
    edges = [{"a": "css", "b": "tp", "kind": "Сетевое соединение", "portEvidence": [declared]},
             {"a": "css", "b": "tp", "kind": "Путь по MAC-таблице", "confirmed": True,
              "portEvidence": [observed]},
             {"a": "tp", "b": "root", "kind": "Сетевое соединение", "confirmed": True,
              "portEvidence": [{"a": "Gi1/52", "b": "ge21", "source": "LLDP · двустороннее",
                                "confirmed": True, "at": stamp}]}]

    def read(at=now):
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "links": edges, "nodes": [switch,
                                    {"id": "tp", "name": "TP", "kind": "Коммутатор"},
                                    {"id": "root", "name": "Root", "kind": "Коммутатор",
                                     "ports": [{"name": "ge21", "state": "up", "checkedAt": stamp}]}]}), encoding="utf-8")
        return load_infrastructure_map(path, at, include_guest_attachments=True)

    graph = read()
    direct, learned, _ = graph["links"]
    assert direct["confirmed"] is False
    proof, = learned["portEvidence"]
    assert "pairEvidence" not in proof
    assert proof["stpPaths"] == [{**stp, "deviceId": "css"}]
    pending, = summarize_topology(graph)["topologyAudit"]["pending"]
    assert pending["observedPaths"][0]["stpPaths"] == proof["stpPaths"]
    assert pending["identifiedPeerSides"] == ["a", "b"]
    assert graph["pendingPortPairs"][0]["identifiedPeerSides"] == ["a", "b"]
    assert graph["pendingPortPairs"][0]["stpPaths"] == proof["stpPaths"]
    confirmed, = summarize_topology(graph)["topologyAudit"]["currentPairs"]
    assert pending["stpBridgeConnections"] == [confirmed]
    switch["ports"][0]["telemetry"] = {"checkedAt": stamp, "intervalSeconds": 300, "rxBps": 1900, "txBps": 1000}
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["nodes"][0] = switch
    raw["nodes"][1]["ports"] = [{"name": "Gi1/22", "state": "up", "checkedAt": stamp,
                                    "telemetry": {"checkedAt": stamp, "intervalSeconds": 300,
                                                  "rxBps": 1000, "txBps": 2000}}]
    path.write_text(json.dumps(raw), encoding="utf-8")
    comparison_graph = load_infrastructure_map(path, now, include_guest_attachments=True)
    comparison, = summarize_topology(comparison_graph)["topologyAudit"]["pending"]
    assert comparison["trafficComparison"]["overlapSeconds"] == 300
    assert comparison["linkHealth"] == {"state": "both_up", "checkedAt": stamp}
    assert comparison_graph["pendingPortPairs"][0]["linkHealth"] == comparison["linkHealth"]
    assert summarize_topology(comparison_graph)["topologyAudit"]["pendingPairLinkCounts"] == {"both_up": 1}
    scoped = summarize_topology(comparison_graph, node_id=comparison["a"],
                                port_name=comparison["portA"])["topologyAudit"]
    assert scoped["pendingPairLinkCounts"] == {"both_up": 1}
    assert comparison_graph["pendingPortPairLinkCounts"] == {"both_up": 1}
    assert comparison["trafficComparison"]["aToB"] == {"txBps": 1000, "rxBps": 1000, "differencePercent": 0}
    assert comparison["trafficComparison"]["bToA"]["differencePercent"] == 5
    assert comparison_graph["pendingPortPairs"][0]["trafficComparison"] == comparison["trafficComparison"]
    upstream = summarize_topology(graph, node_id="root", port_name="GE21")["topologyAudit"]
    assert upstream["currentPairs"] == [confirmed] and upstream["pendingTotal"] == 0
    assert upstream["pendingPairLinkCounts"] == {}
    assert upstream["stpRelatedPending"] == [pending]
    assert summarize_topology(graph, node_id="root", port_name="ge22")["topologyAudit"]["stpRelatedPending"] == []
    assert graph["pendingPortPairs"][0]["stpBridgeConnections"] == [confirmed]
    assert read(now + timedelta(minutes=6))["pendingPortPairs"][0]["stpPaths"] == []
    assert "stpPaths" not in read(now + timedelta(minutes=6))["links"][1]["portEvidence"][0]
    observed["a"] = "Port14"
    assert "stpPaths" not in read()["links"][1]["portEvidence"][0]
    assert "stpBridgeConnections" not in read()["pendingPortPairs"][0]
    assert read()["pendingPortPairs"][0]["identifiedPeerSides"] == ["b"]


def test_pending_switch_pair_links_stp_bridge_to_observed_fdb_port(tmp_path):
    from app.infrastructure_map import RECIPROCAL_MAC_SOURCE, load_infrastructure_map, summarize_topology

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    mac = "02:00:00:00:00:03"
    stp = {"localPort": "Port13", "designatedBridgeMac": mac, "designatedPortId": "80:03",
           "checkedAt": stamp, "bridgeDeviceId": "router"}
    observed = {"a": "ge48", "b": "", "source": "netctl FDB", "confirmed": True, "at": stamp,
                "learnedEndpoint": {"switchId": "school", "deviceId": "router", "mac": mac}}
    path = tmp_path / "infrastructure.json"

    def read():
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": [
            {"id": "css", "name": "CSS", "kind": "Коммутатор", "stpRootPath": stp,
             "ports": [{"name": "Port13", "state": "up", "checkedAt": stamp}]},
            {"id": "ito", "name": "ITO", "kind": "Коммутатор"},
            {"id": "school", "name": "School", "kind": "Коммутатор",
             "ports": [{"name": "ge48", "state": "up", "checkedAt": stamp}]},
            {"id": "router", "name": "Router", "kind": "Маршрутизатор"},
        ], "links": [
            {"a": "css", "b": "ito", "kind": "Сетевое соединение", "portEvidence": [
                {"a": "Port13", "b": "ge22", "source": "GitHub", "confirmed": False}]},
            {"a": "css", "b": "ito", "kind": "Путь по MAC-таблице", "confirmed": True, "portEvidence": [
                {"a": "Port13", "b": "ge22", "source": RECIPROCAL_MAC_SOURCE, "confirmed": True, "at": stamp}]},
            {"a": "school", "b": "router", "kind": "Путь по MAC-таблице", "confirmed": True,
             "portEvidence": [observed]},
        ]}), encoding="utf-8")
        graph = load_infrastructure_map(path, now, include_guest_attachments=True)
        topology = summarize_topology(graph)["topologyAudit"]
        assert topology["currentPairTotal"] == 0
        return [next(row for row in rows if row["a"] == "css")
                for rows in (graph["pendingPortPairs"], topology["pending"])]

    expected = [{"bridgeDeviceId": "router", "switchId": "school", "port": "ge48", "checkedAt": stamp}]
    assert all(row["stpBridgeMacObservations"] == expected for row in read())
    observed["learnedEndpoint"]["mac"] = "02:00:00:00:00:04"
    assert all("stpBridgeMacObservations" not in row for row in read())
    observed["learnedEndpoint"]["mac"] = mac
    observed["at"] = (now - timedelta(minutes=26)).isoformat()
    assert all("stpBridgeMacObservations" not in row for row in read())


def test_agent_audit_keeps_unbound_mac_matches_diagnostic_and_redacts_identity(tmp_path, monkeypatch):
    from app import infrastructure_map
    from app.endpoint_platform_client import EndpointPlatformServiceError

    path = tmp_path / "infrastructure.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    at = datetime.now(timezone.utc).isoformat()
    keys = ("mac-020000000001", "mac-020000000002", "mac-020000000003")
    guests = [
        {"id": f"vm:{index}", "name": f"VM {index}", "guest": True, "vmid": index,
         "kind": "Виртуальная машина", "agentMatchKeys": [key],
         "sources": [{"name": "Proxmox", "status": "ok", "at": at, "label": "Запущена"}]}
        for index, key in enumerate(keys, 1)
    ]
    guests.extend([
        {"id": "vm:4", "name": "VM 4", "guest": True, "vmid": 4, "kind": "Виртуальная машина",
         "sources": [{"name": "Proxmox", "status": "warn", "at": at, "label": "Выключена"}]},
        {"id": "vm:5", "name": "VM 5", "guest": True, "vmid": 5, "kind": "Виртуальная машина",
         "sources": [{"name": "Proxmox", "status": "ok", "at": at, "label": "Запущена"}],
         "guestNetwork": {"checkedAt": at, "configured": 1, "enabled": 0, "disabled": 1}},
        {"id": "vm:6", "name": "VM 6", "guest": True, "vmid": 6, "kind": "Виртуальная машина",
         "sources": [{"name": "Proxmox", "status": "ok", "at": at, "label": "Запущена"}]},
    ])
    host = {"id": "pve", "name": "Proxmox", "kind": "Гипервизор"}
    switch = {"id": "switch", "name": "Switch", "kind": "Коммутатор"}
    service = {"id": "web", "name": "Web", "kind": "Сервис",
               "serviceChecks": [{"method": "HTTP", "source": "UI_VPN", "state": "reachable",
                                  "required": True, "checkedAt": at, "port": 443}]}
    ssh_service = {"id": "ssh", "name": "SSH", "kind": "Сервис", "serviceChecks": [
        {"method": "SSH", "source": "UI_VPN", "state": "reachable", "required": True,
         "checkedAt": at, "port": 22, "target": "192.0.2.10"},
        {"method": "SSH", "source": "UI_VPN", "state": "unknown", "required": True,
         "checkedAt": at, "port": 22, "target": "192.0.2.99"},
    ]}
    placement = {"a": "pve", "b": "vm:1", "kind": "Размещение ВМ", "confirmed": True,
                 "portEvidence": [{"a": "vmbr0", "b": "net0", "source": "Proxmox · конфигурация ВМ",
                                   "at": at, "confirmed": True,
                                   "virtual": {"bridgeActive": True, "linkDisabled": False, "uplinks": ["eth0"],
                                               "switchPorts": [{"id": "switch", "port": "ge3", "at": at}],
                                               "ipv4Observations": [
                                                   {"address": ip, "source": "UI_VPN", "method": "ARP", "checkedAt": at}
                                                   for ip in ("192.0.2.10", "192.0.2.11")
                                               ]}}]}
    links = [placement, {"a": "vm:1", "b": "web", "kind": "Цель проверки", "confirmed": True},
             {"a": "pve", "b": "switch", "kind": "Сетевое соединение", "confirmed": True, "portEvidence": [
                 {"a": "eth0", "b": "ge3", "source": "LLDP UI_VPN", "at": at, "confirmed": True}]}]
    path.write_text(json.dumps({"schema": 1, "snapshotAt": at, "nodes": [*guests, host, switch, service],
                                "links": links}), encoding="utf-8")

    class Adapter:
        unavailable = False
        reads = []
        health_at = at
        network_at = at
        network_observed_at = None
        network_interfaces_empty = False
        platform = "linux"
        health_warnings = []

        def list_agent_network_identities(self):
            if self.unavailable:
                raise EndpointPlatformServiceError("test")
            profiles = [{"profile": "health_v1", "collected_at": at},
                        {"profile": "network_v1", "collected_at": at},
                        {"profile": "session_v1", "collected_at": at},
                        {"profile": "inventory_v1", "collected_at": at}]
            return [{"id": f"00000000-0000-4000-8000-{index:012d}", "baseline_mac_keys": [key], "online": True,
                     "last_seen_at": at, "baseline_collected_at": at, "profiles": profiles}
                    for index, key in enumerate([keys[0], keys[1], keys[1]])]

        def read_observed_profiles(self, device_id, profiles):
            self.reads.append((str(device_id), tuple(profiles)))
            snapshots = {
                "network_v1": {"profile": "network_v1", "collected_at": self.network_at,
                               "observed_at": self.network_observed_at, "sections": {"interfaces": [] if self.network_interfaces_empty else [
                                   {"name": "Ethernet 2", "addresses": ["192.0.2.10/24", "192.0.2.10", "192.0.2.12",
                                                                       "127.0.0.1", "169.254.1.2", "invalid"]},
                                   {"name": "lo", "addresses": ["127.0.0.1/8", "::1"]},
                               ]}},
                "inventory_v1": {"profile": "inventory_v1", "collected_at": at,
                                 "sections": {"system": {"platform": self.platform, "os_name": "Ubuntu",
                                                         "os_version": "24.04", "architecture": "x86_64",
                                                         "hostname": "private-hostname"},
                                              "hardware": {"serial_number": "private-serial"}}},
                "health_v1": {"profile": "health_v1", "collected_at": self.health_at, "warnings": self.health_warnings,
                              "sections": {"resources": {"uptime_seconds": 7200, "free_bytes": 2**31,
                                                         "load_1m": 0.0, "private": "excluded"},
                                           "services": [
                                               {"name": "sshd", "status": "active", "private": "excluded"},
                                               {"name": "NetworkManager", "status": "inactive"},
                                               {"name": "private-service", "status": "failed"},
                                           ]}},
            }
            return {profile: snapshots[profile] for profile in profiles}

        def close(self):
            pass

    monkeypatch.setattr(infrastructure_map, "get_endpoint_context_adapter", Adapter)
    client, headers, _ = make_client(tmp_path, monkeypatch)
    regular = client.get("/api/v1/network/infrastructure", headers=headers).json()["infrastructure"]
    assert all("agentMatchKeys" not in n for n in regular["nodes"])
    assert all(n["mapStatus"] == "unknown" for n in regular["nodes"] if n["guest"] and n["id"] != "vm:1")
    response = client.get("/api/v1/network/infrastructure?view=agents", headers=headers)
    assert response.status_code == 200
    assert {"attachment", "serviceAudit"}.isdisjoint(response.json()["infrastructure"])
    assert all(key not in response.text for key in keys)
    result = response.json()["infrastructure"]["agentAudit"]
    assert (result["eligible"], result["matched"], result["ambiguous"]) == (3, 1, 1)
    assert (result["total"], result["unmatched"], result["notEligible"]) == (6, 1, 3)
    assert result["healthProfileCoverage"] == {
        "guests": {"fresh": 1, "stale": 0, "unconfirmed": 0},
        "hypervisors": {"fresh": 0, "stale": 0, "unconfirmed": 0},
    }
    matched, ambiguous, unmatched, stopped, disabled, unknown_network = result["guests"]
    assert matched == {"id": "vm:1", "name": "VM 1", "vmid": 1, "state": "matched",
                       "registrations": 1, "presence": "online", "lastSeenAt": at, "healthProfileState": "fresh",
                       "contextProfiles": [{"profile": "health_v1", "collectedAt": at},
                                           {"profile": "network_v1", "collectedAt": at},
                                           {"profile": "inventory_v1", "collectedAt": at}]}
    assert ambiguous["state"] == "ambiguous" and "lastSeenAt" not in ambiguous
    assert ambiguous["reason"] == "multiple_registrations"
    assert (unmatched["state"], unmatched["reason"], unmatched["registrations"]) == (
        "unmatched", "no_matching_registration", 0,
    )
    assert (stopped["state"], stopped["reason"]) == ("not_eligible", "guest_stopped")
    assert disabled["reason"] == "no_enabled_network_adapter"
    assert unknown_network["reason"] == "network_config_unconfirmed"
    assert all("presence" not in row for row in [unmatched, stopped, disabled, unknown_network])
    assert all("contextProfiles" not in row for row in [ambiguous, unmatched, stopped, disabled, unknown_network])
    assert Adapter.reads == []
    selected = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers)
    assert selected.status_code == 200
    context = selected.json()["infrastructure"]
    detail, = context["agentAudit"]["guests"]
    attachment = client.get("/api/v1/network/infrastructure?view=attachment&node_id=vm:1", headers=headers)
    assert context["attachment"] == attachment.json()["infrastructure"]["attachment"]
    guest, = context["attachment"]["guests"]
    assert guest["placement"] == "confirmed"
    interface, = guest["interfaces"]
    assert (interface["guestPort"], interface["bridge"], interface["uplinks"]) == ("net0", "vmbr0", ["eth0"])
    web, = context["serviceAudit"]["services"]
    assert web["id"] == "web" and web["requiredChecks"] == {"passed": 1, "failed": 0, "unconfirmed": 0}
    assert context["attachment"]["serviceTotal"] == 1
    hosted, = context["attachment"]["services"]
    assert hosted["node"]["id"] == "web"
    service_attachment = client.get("/api/v1/network/infrastructure?view=attachment&node_id=web",
                                    headers=headers).json()["infrastructure"]["attachment"]
    for field in ("checks", "serviceChecks", "servicePaths"):
        assert hosted[field] == service_attachment[field]
    system = {"collectedAt": at, "platform": "linux", "name": "Ubuntu", "version": "24.04",
              "architecture": "x86_64"}
    network = {"checkedAt": at, "stale": False, "interfaces": [{"name": "Ethernet 2", "ipv4": ["192.0.2.10", "192.0.2.12"]}]}
    assert context["agentAudit"]["guests"][0].pop("ipv4Comparison") == {
        "matched": ["192.0.2.10"], "endpointOnly": ["192.0.2.12"], "observedOnly": ["192.0.2.11"],
        "matchedPaths": [{"address": "192.0.2.10", "guestPort": "net0", "bridge": "vmbr0", "hypervisorId": "pve",
                          "endpointInterface": "Ethernet 2",
                          "addressCheckedAt": at, "switchId": "switch", "switchCheckedAt": at,
                          "physicalPair": {"hostPort": "eth0", "switchPort": "ge3", "source": "LLDP UI_VPN", "checkedAt": at}}],
    }
    assert detail == {**matched, "operatingSystem": system, "network": network, "health": {"checkedAt": at, "uptimeSeconds": 7200,
                                             "memoryAvailableBytes": 2**31, "loadAverage1m": 0.0, "services": [
                                                 {"name": "sshd", "status": "active"},
                                                 {"name": "NetworkManager", "status": "inactive"},
                                             ]}}
    service_agents_url = "/api/v1/network/infrastructure?view=agents&node_id=web"
    service_context = client.get(service_agents_url, headers=headers).json()["infrastructure"]
    assert service_context["attachment"] == service_attachment
    assert service_context["serviceAudit"]["services"] == [web]
    service_agent, = service_context["agentAudit"]["guests"]
    assert service_agent["ipv4Comparison"]["matchedPaths"][0]["physicalPair"]["switchPort"] == "ge3"
    assert service_agent["health"] == detail["health"]
    assert len(Adapter.reads) == 2 and Adapter.reads.pop() == Adapter.reads[0]
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    snapshot["links"].append({"a": "vm:2", "b": "web", "kind": "Цель проверки", "confirmed": True})
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    shared = client.get("/api/v1/network/infrastructure?view=attachment&node_id=vm:1",
                        headers=headers).json()["infrastructure"]["attachment"]
    assert shared["serviceTotal"] == 1
    assert shared["services"] == [{**hosted, "servicePaths": []}]
    shared_context = client.get(service_agents_url, headers=headers).json()["infrastructure"]
    assert shared_context["attachment"]["guestTotal"] == 2
    assert shared_context["agentAudit"]["guests"] == []
    assert shared_context["serviceAudit"]["services"][0]["hosts"] == ["vm:1", "vm:2"]
    snapshot["links"].pop()
    snapshot["nodes"].append(ssh_service)
    snapshot["links"].append({"a": "vm:1", "b": "ssh", "kind": "Цель проверки", "confirmed": True})
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    paired = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers).json()
    assert paired["infrastructure"]["agentAudit"]["guests"][0]["networkServiceChecks"] == [{
        "serviceId": "ssh", "localService": "sshd", "method": "SSH", "target": "192.0.2.10",
        "port": 22, "state": "reachable", "checkedAt": at,
    }]
    snapshot["links"].append({"a": "web", "b": "ssh", "kind": "Зависимость сервиса", "confirmed": True})
    snapshot["nodes"][-1]["reachability"] = {
        "state": "unreachable", "source": "Проверка сервиса", "method": "SSH", "checkedAt": at,
    }
    for check in snapshot["nodes"][-1]["serviceChecks"]:
        check.update(state="unreachable", reason="ssh_connection_refused")
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    dependent = client.get(service_agents_url, headers=headers).json()["infrastructure"]
    dependency, = dependent["dependencyAudit"]["services"]
    assert dependent["dependencyAudit"]["total"] == 1
    assert dependent["serviceAudit"]["services"][0]["dependencies"]["unavailable"] == ["ssh"]
    assert dependency["id"] == "ssh" and dependency["status"] == "critical"
    assert dependency["issues"][0]["reason"] == "ssh_connection_refused"
    assert len(Adapter.reads) == 3 and Adapter.reads.pop() == Adapter.reads[0]
    snapshot["links"].pop()
    snapshot["nodes"].pop()
    snapshot["links"].pop()
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    Adapter.reads.pop()
    assert "private-service" not in selected.text
    assert "private-hostname" not in selected.text and "private-serial" not in selected.text
    assert Adapter.reads == [("00000000-0000-4000-8000-000000000000", ("health_v1", "inventory_v1", "network_v1"))]
    selected = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:2", headers=headers)
    assert selected.json()["infrastructure"]["agentAudit"]["guests"] == [ambiguous]
    assert len(Adapter.reads) == 1
    Adapter.health_at = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    Adapter.network_at = (datetime.now(timezone.utc) - timedelta(minutes=21)).isoformat()
    stale = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers)
    assert stale.json()["infrastructure"]["agentAudit"]["guests"] == [{
        **matched, "operatingSystem": system, "network": {**network, "checkedAt": Adapter.network_at, "stale": True},
    }]
    Adapter.network_observed_at = at
    reobserved = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers)
    reobserved_guest, = reobserved.json()["infrastructure"]["agentAudit"]["guests"]
    assert reobserved_guest["network"] == {**network, "snapshotAt": Adapter.network_at}
    assert reobserved_guest["ipv4Comparison"]["matched"] == ["192.0.2.10"]
    Adapter.network_interfaces_empty = True
    empty = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers)
    empty_guest, = empty.json()["infrastructure"]["agentAudit"]["guests"]
    assert empty_guest["network"] == {
        "checkedAt": at, "snapshotAt": Adapter.network_at, "stale": False, "interfaces": [],
        "reason": "no_reported_ipv4",
    }
    assert "ipv4Comparison" not in empty_guest
    Adapter.network_interfaces_empty = False
    Adapter.network_observed_at = None
    Adapter.health_at = at
    Adapter.network_at = at
    Adapter.platform = "windows"
    windows = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers).json()
    assert "loadAverage1m" not in windows["infrastructure"]["agentAudit"]["guests"][0]["health"]
    Adapter.platform = "linux"
    Adapter.health_warnings = ["source_unavailable"]
    partial = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers).json()
    assert "loadAverage1m" not in partial["infrastructure"]["agentAudit"]["guests"][0]["health"]
    Adapter.health_warnings = []

    browser_url = "/network/infrastructure/agents"
    assert client.get(browser_url, follow_redirects=False).status_code == 303
    login = client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": "admin-pass"},
                follow_redirects=False)
    response = client.get(browser_url)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["infrastructure"]["agentAudit"] == result
    assert all(key not in response.text for key in keys)
    assert "nodes" not in response.json()["infrastructure"]
    response = client.get(browser_url + "?node_id=vm:1")
    browser_detail, = response.json()["infrastructure"]["agentAudit"]["guests"]
    assert browser_detail.pop("ipv4Comparison")["matched"] == ["192.0.2.10"]
    assert browser_detail == detail
    Adapter.unavailable = True
    assert client.get(browser_url).json()["infrastructure"]["agentAudit"] == {"sourceState": "unavailable"}
    selected = client.get("/api/v1/network/infrastructure?view=agents&node_id=vm:1", headers=headers)
    unavailable = selected.json()["infrastructure"]
    assert unavailable["agentAudit"] == {"sourceState": "unavailable"}
    assert unavailable["attachment"] == context["attachment"]
    assert unavailable["serviceAudit"] == context["serviceAudit"]
    unavailable_service = client.get(service_agents_url, headers=headers).json()["infrastructure"]
    assert unavailable_service["agentAudit"] == {"sourceState": "unavailable"}
    assert unavailable_service["attachment"] == service_attachment
    assert unavailable_service["serviceAudit"]["services"] == [web]


def test_agent_address_comparison_omits_path_for_ambiguous_network_observations():
    from app.infrastructure_map import _agent_ipv4_comparison

    address = "192.0.2.10"
    network = {"interfaces": [{"ipv4": [address]}]}
    interface = {"guestPort": "net0", "bridge": "vmbr0", "linkDisabled": False,
                 "ipv4Observations": [{"address": address}], "switchObservations": [
                     {"basis": "guest_mac", "physicalPair": {"switchPort": "ge3"}},
                     {"basis": "guest_mac"},
                 ]}
    interfaces = [interface]
    attachment = {"guests": [{"placement": "confirmed", "interfaces": interfaces}]}
    expected = {"matched": [address], "endpointOnly": [], "observedOnly": []}
    assert _agent_ipv4_comparison(network, attachment) == expected
    interface["switchObservations"].pop()
    interfaces.append({**interface, "guestPort": "net1"})
    assert _agent_ipv4_comparison(network, attachment) == expected
    interfaces.pop()
    attachment["guests"][0]["hypervisor"] = {"id": "pve"}
    interface["ipv4Observations"][0]["checkedAt"] = "2026-11-13T14:39:00+00:00"
    interface["switchObservations"][0].update(switch={"id": "switch"}, checkedAt="2026-11-13T14:39:00+00:00")
    network["interfaces"] = [{"name": "ens18", "ipv4": [address]}]
    assert _agent_ipv4_comparison(network, attachment)["matchedPaths"][0]["endpointInterface"] == "ens18"
    network["interfaces"].append({"name": "bond0", "ipv4": [address]})
    path, = _agent_ipv4_comparison(network, attachment)["matchedPaths"]
    assert "endpointInterface" not in path


def test_agent_audit_selects_only_current_registration_among_long_offline_duplicates(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    key = "mac-020000000001"
    second_key = "mac-020000000002"
    guest = {"id": "vm:1", "name": "VM 1", "guest": True, "vmid": 1,
             "kind": "Виртуальная машина", "agentMatchKeys": [key],
             "sources": [{"name": "Proxmox", "status": "ok", "at": stamp, "label": "Запущена"}]}
    path = tmp_path / "infrastructure.json"

    def audit(active_changes=None, offline_changes=None, *, extra_guest=False, two_adapters=False):
        guest_keys = [key, second_key] if two_adapters else [key]
        nodes = [{**guest, "agentMatchKeys": guest_keys}]
        if extra_guest:
            nodes.append({**guest, "id": "vm:2", "vmid": 2, "agentMatchKeys": [second_key]})
        path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": nodes}), encoding="utf-8")
        old = (now - timedelta(days=2)).isoformat()
        active = {"id": "current", "baseline_mac_keys": [key, second_key], "online": True,
                  "last_seen_at": stamp, "baseline_collected_at": stamp, **(active_changes or {})}
        offline = {"id": "previous", "baseline_mac_keys": [key], "online": False,
                   "last_seen_at": old, "baseline_collected_at": old, **(offline_changes or {})}
        return load_infrastructure_map(path, now, agent_identities=[active, offline])["agentAudit"]["guests"][0]

    assert audit() == {
        "id": "vm:1", "name": "VM 1", "vmid": 1, "state": "matched", "registrations": 2,
        "identitySource": "active_mac_registration", "presence": "online", "lastSeenAt": stamp,
        "healthProfileState": "unconfirmed",
    }
    older_health = {"profile": "health_v1", "collected_at": (now - timedelta(minutes=7)).isoformat()}
    assert audit(active_changes={"profiles": [older_health]})["healthProfileState"] == "stale"
    assert audit(active_changes={"profiles": [older_health, {**older_health, "collected_at": stamp}]})[
        "healthProfileState"] == "unconfirmed"
    for changes in ({"online": True}, {"online": None}, {"last_seen_at": stamp}, {"last_seen_at": None}):
        assert audit(offline_changes=changes)["reason"] == "multiple_registrations"
    stale = (now - timedelta(days=2)).isoformat()
    for changes in ({"last_seen_at": stale}, {"baseline_collected_at": stale}, {"online": False}):
        assert audit(active_changes=changes)["reason"] == "multiple_registrations"
    assert audit(active_changes={"baseline_mac_keys": [second_key]}, two_adapters=True)["reason"] == "multiple_registrations"
    assert audit(extra_guest=True)["reason"] == "registration_matches_multiple_guests"


def test_guest_enrollment_fallback_requires_fresh_matching_proxmox_mac(tmp_path, monkeypatch):
    from app import infrastructure_map
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    mac = "02:00:00:00:00:16"
    endpoint_id = "946afddb-83b3-4416-830b-e0d3ec63e001"
    path = tmp_path / "map.json"
    pve = {"at": stamp, "cluster": [], "nodes": [],
           "guests": [{"vmid": 116, "node": "pve1", "name": "FILESERVER", "type": "qemu", "status": "running"}],
           "configs": {"116": {"net0": f"virtio={mac},bridge=vmbr1"}}}
    context = {"devices": [{"id": "fileserver", "name": "FILESERVER", "kind": "server"}]}
    bindings = {"guests": {"116": {"asset": "fileserver", "mac": mac, "endpoint_device_id": endpoint_id}}}
    calls = []

    class Adapter:
        identities = []

        def list_agent_network_identities(self):
            return self.identities

        def list_device_presences(self):
            calls.append(True)
            return [{"id": endpoint_id, "online": True, "retired_at": None, "last_seen_at": stamp}]

        def read_observed_profiles(self, device_id, profiles):
            assert str(device_id) == endpoint_id
            assert set(profiles) == {"health_v1", "network_v1", "inventory_v1"}
            calls.append("profiles")
            return {"health_v1": {"collected_at": stamp, "sections": {"resources": {"private": 1}}}}

        def close(self):
            pass

    monkeypatch.setattr(infrastructure_map, "get_endpoint_context_adapter", Adapter)

    def audit():
        raw = build_graph(context, {}, {}, pve, bindings, now)
        path.write_text(json.dumps(raw), encoding="utf-8")
        result = infrastructure_map.load_infrastructure_agent_audit(path)["agentAudit"]
        assert endpoint_id not in json.dumps(result)
        return result["guests"][0]

    entry = audit()
    assert (entry["state"], entry["presence"], entry["identitySource"]) == ("matched", "online", "verified_enrollment")
    assert entry["contextProfiles"] == [{"profile": "health_v1", "collectedAt": stamp}]
    Adapter.identities = [{"id": "other", "baseline_mac_keys": ["mac-020000000016"]}]
    assert audit()["reason"] == "enrollment_registration_conflict"
    pve["configs"]["116"]["net0"] = "virtio=02:00:00:00:00:17,bridge=vmbr1"
    assert audit()["state"] == "unmatched"
    assert calls == [True, "profiles", True]


def test_verified_enrollment_for_unbound_vm_ignores_only_old_same_mac_registrations(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    old = (now - timedelta(days=3)).isoformat()
    mac = "02:00:00:00:00:10"
    key = "mac-020000000010"
    endpoint_id = "946afddb-83b3-4416-830b-e0d3ec63e001"
    pve = {"at": stamp, "cluster": [], "nodes": [],
           "guests": [{"vmid": 100, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"100": {"net0": f"virtio={mac},bridge=vmbr1"}}}
    bindings = {"guests": {"100": {"mac": mac, "endpoint_device_id": endpoint_id}}}
    current = {"id": endpoint_id, "baseline_mac_keys": [key], "online": True,
               "last_seen_at": stamp, "baseline_collected_at": old}
    historical = {"id": "historical", "baseline_mac_keys": [key], "online": False, "last_seen_at": old}
    path = tmp_path / "map.json"

    def audit():
        raw = build_graph({}, {}, {}, pve, bindings, now)
        path.write_text(json.dumps(raw), encoding="utf-8")
        graph = load_infrastructure_map(path, now, agent_identities=[current, historical],
                                        load_agent_presence=lambda: [current])
        result, = graph["agentAudit"]["guests"]
        assert endpoint_id not in json.dumps(graph)
        return result

    entry = audit()
    assert (entry["id"], entry["state"], entry["presence"], entry["identitySource"], entry["registrations"]) == (
        "pve-guest:100", "matched", "online", "verified_enrollment", 2,
    )
    historical.update(online=True, last_seen_at=stamp)
    assert audit()["reason"] == "enrollment_registration_conflict"
    historical.update(online=False, last_seen_at=old, baseline_mac_keys=["mac-020000000011"])
    pve["configs"]["100"]["net1"] = "virtio=02:00:00:00:00:11,bridge=vmbr1"
    assert audit()["reason"] == "enrollment_registration_conflict"
    pve["configs"]["100"]["net0"] = f"virtio={mac},bridge=vmbr1,link_down=1"
    remaining = audit()
    assert remaining["state"] == "matched" and "identitySource" not in remaining


def test_agent_audit_reports_duplicate_guest_macs_without_using_them_for_presence(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac = "02:00:00:00:00:01"
    pve = {
        "at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": vmid, "node": "pve1", "status": "running", "type": "qemu"} for vmid in (100, 101)],
        "configs": {str(vmid): {"net0": f"virtio={mac},bridge=vmbr0"} for vmid in (100, 101)},
    }
    raw = build_graph({}, {}, {}, pve, {}, now)
    path = tmp_path / "map.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    identities = [{"id": "registration", "baseline_mac_keys": ["mac-020000000001"], "online": True,
                   "baseline_collected_at": at, "last_seen_at": at}]
    graph = load_infrastructure_map(path, now, agent_identities=identities)
    audit = graph["agentAudit"]
    assert (audit["eligible"], audit["matched"], audit["ambiguous"]) == (2, 0, 2)
    assert [(entry["vmid"], entry["reason"]) for entry in audit["guests"]] == [
        (100, "duplicate_guest_mac"), (101, "duplicate_guest_mac"),
    ]
    assert all("presence" not in entry and "lastSeenAt" not in entry for entry in audit["guests"])
    assert mac not in json.dumps(graph) and "agentMatchConflict" not in json.dumps(graph)
    stale = load_infrastructure_map(path, now + timedelta(hours=1), agent_identities=identities)
    assert stale["agentAudit"]["eligible"] == 0
    assert [row["reason"] for row in stale["agentAudit"]["guests"]] == ["proxmox_stale", "proxmox_stale"]

    pve["configs"]["101"]["net0"] = "virtio=02:00:00:00:00:02,bridge=vmbr0"
    raw = build_graph({}, {}, {}, pve, {}, now)
    path.write_text(json.dumps(raw), encoding="utf-8")
    identities[0]["baseline_mac_keys"].append("mac-020000000002")
    guests = load_infrastructure_map(path, now, agent_identities=identities)["agentAudit"]["guests"]
    assert [(entry["vmid"], entry["reason"]) for entry in guests] == [
        (100, "registration_matches_multiple_guests"), (101, "registration_matches_multiple_guests"),
    ]


def test_hypervisor_agent_memory_uses_available_bytes_and_fresh_capacity():
    from app.infrastructure_map import _guest_agent_health

    now = datetime.now(timezone.utc)
    snapshot = {"profile": "health_v1", "collected_at": now.isoformat(),
                "sections": {"resources": {"free_bytes": 3 * 2**30}}}
    capacity = {"memory": {"totalBytes": 64 * 2**30}, "checkedAt": now.isoformat()}
    report = _guest_agent_health(snapshot, now, capacity=capacity)
    assert report["memoryHeadroom"] == {"availablePercent": 4.69, "warningThreshold": 10, "status": "warn",
                                        "totalBytes": 64 * 2**30, "capacityCheckedAt": now.isoformat()}
    snapshot["sections"]["resources"]["free_bytes"] = 0
    snapshot["warnings"] = ["source_unavailable"]
    assert "memoryHeadroom" not in _guest_agent_health(snapshot, now, capacity=capacity)
    snapshot["sections"]["resources"]["free_bytes"] = 3 * 2**30
    capacity["checkedAt"] = (now - timedelta(minutes=6)).isoformat()
    assert "memoryHeadroom" not in _guest_agent_health(snapshot, now, capacity=capacity)


def test_agent_audit_matches_hypervisor_using_verified_management_mac(tmp_path, monkeypatch):
    from app import infrastructure_map
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    arp_at = (now - timedelta(minutes=2)).isoformat()
    address, mac = "192.0.2.11", "02:00:00:00:00:01"
    context = {"devices": [{"id": "pve1", "name": "pve1", "kind": "hypervisor", "management_ip": address}]}
    network = {
        "hosts": [{"ip": address, "mac": mac, "last_seen_at": arp_at}],
        "arp": [{"ip": address, "mac": mac, "last_seen_at": arp_at}],
    }
    pve = {"at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}], "guests": [],
           "management": {"pve1": {"address": address, "port": "eno1"}}}
    identity = {"id": "hidden-registration", "baseline_mac_keys": ["mac-020000000001"], "online": True,
                "baseline_collected_at": at, "last_seen_at": at}
    path = tmp_path / "map.json"

    def read(when=now):
        path.write_text(json.dumps(build_graph(context, network, {}, pve, {}, now)), encoding="utf-8")
        return load_infrastructure_map(path, when, agent_identities=[identity], agent_node_id="pve1")["agentAudit"]

    audit = read()
    assert (audit["total"], audit["eligible"], audit["matched"], audit["guests"]) == (0, 0, 0, [])
    entry, = audit["hypervisors"]
    assert entry == {"id": "pve1", "name": "pve1", "state": "matched", "registrations": 1, "presence": "online",
                     "lastSeenAt": at, "identityCheckedAt": arp_at, "identitySource": "proxmox_management_mac",
                     "healthProfileState": "unconfirmed"}
    assert identity["id"] not in json.dumps(audit) and mac not in json.dumps(audit)

    class Adapter:
        def list_agent_network_identities(self):
            return [identity]

        def close(self):
            pass

    monkeypatch.setattr(infrastructure_map, "get_endpoint_context_adapter", Adapter)
    result = infrastructure_map.load_infrastructure_agent_audit(path, node_id="pve1")
    assert result["attachment"]["node"]["id"] == "pve1"
    assert result["attachment"]["physicalHosts"][0]["host"]["id"] == "pve1"
    assert result["serviceAudit"]["total"] == 0
    assert result["agentAudit"]["hypervisors"][0]["identitySource"] == "proxmox_management_mac"

    stale, = read(now + timedelta(minutes=24))["hypervisors"]
    assert stale["state"] == "not_eligible" and stale["reason"] == "management_mac_unconfirmed"
    network["arp"].append({**network["arp"][0], "mac": "02:00:00:00:00:02"})
    conflict, = read()["hypervisors"]
    assert conflict["state"] == "not_eligible" and "presence" not in conflict
    network["arp"].pop()
    pve["management"]["pve1"]["address"] = "192.0.2.12"
    different, = read()["hypervisors"]
    assert different["state"] == "not_eligible" and "presence" not in different


def test_shared_port_summary_includes_distinct_fdb_peers_without_lldp():
    from app.infrastructure_map import _summarize_shared_ports

    at = "2026-11-13T21:25:00+00:00"
    rows = [
        {"a": "switch", "b": peer, "nameB": peer, "portA": "Gi1/0/23",
         "observedPaths": [{"source": "netctl FDB", "checkedAt": at, "portA": "gigabitEthernet 1/0/23",
                            "learnedEndpoint": {"switchId": "switch", "deviceId": peer}}]}
        for peer in ("router", "phone")
    ]
    rows[0]["basis"] = "learned_endpoint"
    assert _summarize_shared_ports(rows[:1]) == []
    assert _summarize_shared_ports([rows[0], rows[0]]) == []
    port, = _summarize_shared_ports(rows)
    assert port["peerIds"] == port["liveFdbPeerIds"] == ["phone", "router"]
    assert port["liveLldpPeerIds"] == []
    assert all(not row.get("sharedPort") for row in rows)
    rows[1]["observedPaths"][0]["portA"] = "Gi1/0/24"
    assert _summarize_shared_ports(rows) == []


def test_missing_infrastructure_snapshot_has_explicit_empty_state(tmp_path, monkeypatch):
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(tmp_path / "missing.json"))
    client, headers, _ = make_client(tmp_path, monkeypatch)

    response = client.get("/api/v1/network/infrastructure", headers=headers)
    assert response.status_code == 200
    assert response.json()["infrastructure"]["availability"] == "missing"


def test_agent_audit_explains_unconfirmed_presence_even_with_recent_health(tmp_path):
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    path = tmp_path / "map.json"
    key = "mac-020000000001"
    path.write_text(json.dumps({"schema": 1, "snapshotAt": at, "nodes": [
        {"id": "vm:1", "name": "VM 1", "guest": True, "vmid": 1, "kind": "Виртуальная машина",
         "agentMatchKeys": [key], "sources": [{"name": "Proxmox", "status": "ok", "at": at, "label": "Запущена"}]}
    ]}), encoding="utf-8")
    identity = {"id": "registered", "baseline_mac_keys": [key], "online": True,
                "last_seen_at": at, "baseline_collected_at": at,
                "profiles": [{"profile": "health_v1", "collected_at": at}]}
    stale = (now - timedelta(days=2)).isoformat()
    for changes, reason in (
        ({"online": False}, "endpoint_reports_offline"),
        ({"online": None}, "endpoint_presence_missing"),
        ({"last_seen_at": stale}, "endpoint_last_seen_stale"),
        ({"last_seen_at": None}, "endpoint_last_seen_missing"),
        ({"baseline_collected_at": stale}, "endpoint_network_baseline_stale"),
        ({"baseline_collected_at": None}, "endpoint_network_baseline_missing"),
    ):
        audit = load_infrastructure_map(path, now, agent_identities=[{**identity, **changes}])["agentAudit"]
        entry, = audit["guests"]
        assert (entry["state"], entry["presence"], entry["presenceReason"], entry["healthProfileState"]) == (
            "matched", "unconfirmed", reason, "fresh",
        )
        assert "lastSeenAt" not in entry and "health" not in entry

    identity["id"] = "3218eb22-423b-43a4-8f97-a0a00f21a4bd"
    identity["baseline_collected_at"] = stale

    def read_baseline(device, profiles):
        assert str(device) == identity["id"]
        assert profiles == ("baseline_v1",)
        return {"baseline_v1": {"profile": "baseline_v1", "observed_at": at, "collected_at": stale,
                                "sections": {"interfaces": [{"stable_key": key}]}}}

    audit = load_infrastructure_map(path, now, agent_identities=[identity], load_agent_profiles=read_baseline)["agentAudit"]
    entry, = audit["guests"]
    assert entry["presence"] == "online" and entry["lastSeenAt"] == at
    assert entry["baselineObservedAt"] == at
    assert "presenceReason" not in entry

    def conflicting_baseline(device, profiles):
        result = read_baseline(device, profiles)
        result["baseline_v1"]["sections"]["interfaces"][0]["stable_key"] = "mac-020000000002"
        return result

    audit = load_infrastructure_map(path, now, agent_identities=[identity], load_agent_profiles=conflicting_baseline)["agentAudit"]
    assert audit["guests"][0]["presenceReason"] == "endpoint_network_baseline_stale"


def test_browser_can_refresh_snapshot_only_with_a_web_session(tmp_path, monkeypatch):
    path = tmp_path / "map.json"
    monkeypatch.setenv("INFRASTRUCTURE_MAP_SNAPSHOT_PATH", str(path))
    client, _, _ = make_client(tmp_path, monkeypatch)
    endpoint = "/network/infrastructure/snapshot"
    assert client.get(endpoint, follow_redirects=False).status_code == 303
    login = client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    response = client.post("/login", data={"csrf_token": csrf, "username": "admin", "password": "admin-pass"},
                           follow_redirects=False)
    assert response.headers["location"] == "/"
    assert client.get(endpoint).json()["infrastructure"]["availability"] == "missing"
    stamp = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps({"schema": 1, "snapshotAt": stamp, "nodes": [], "links": []}), encoding="utf-8")
    updated = client.get(endpoint)
    assert updated.headers["cache-control"] == "no-store"
    assert updated.json()["infrastructure"]["snapshotAt"] == stamp
    assert 'data-snapshot-url="/network/infrastructure/snapshot"' in client.get("/network/infrastructure").text


def test_guest_reachability_accepts_current_arp_with_newer_successful_probe():
    from app.infrastructure_collect import build_graph

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, other = "02:00:00:00:00:03", "02:00:00:00:00:04"
    address = "192.0.2.21"
    pve = {
        "at": at, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
        "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
        "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}},
    }
    seen = (now - timedelta(minutes=1)).isoformat()
    host = {"ip": address, "mac": other, "availability": {"state": "online", "reason": "active_probe",
            "active_method": "icmp", "checked_at": at, "run_status": "success"}}
    arp = {"ip": address, "mac": mac, "last_seen_at": seen}
    network = {"hosts": [host], "arp": [arp]}

    def guest():
        graph = build_graph({}, network, {}, pve, {}, now)
        return next(node for node in graph["nodes"] if node.get("vmid") == 108)

    node = guest()
    assert node["reachability"]["state"] == "reachable"
    assert node["properties"]["IP проверки по ARP"] == address
    network["arp"].append({**arp, "mac": other})
    assert "reachability" not in guest()
    network["arp"].pop()
    host["availability"]["checked_at"] = (now - timedelta(minutes=2)).isoformat()
    assert "reachability" not in guest()
    host["availability"]["checked_at"] = at
    pve["configs"]["108"]["net0"] += ",link_down=1"
    assert "reachability" not in guest()


def test_guest_arp_probe_requires_on_link_identity_and_current_proxmox_interface(monkeypatch, tmp_path):
    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment

    now = datetime.now(timezone.utc)
    ip, mac = "192.0.2.21", "02:00:00:00:00:03"
    guest = {"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}
    config = {"net0": f"virtio={mac},bridge=vmbr0"}
    config["net1"] = "virtio=02:00:00:00:00:04,bridge=vmbr1"
    pve = {"cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [guest], "configs": {"108": config}}
    arp = {"ip": ip, "mac": mac, "last_seen_at": now.isoformat()}
    network = {"arp": [arp]}
    route = {"dev": "ens18"}
    neighbor = {"dst": ip, "lladdr": mac, "state": ["DELAY"]}
    pings = []
    monkeypatch.setattr(collector, "probe_icmp", lambda address: pings.append(address) or True)
    monkeypatch.setattr(collector.subprocess, "check_output",
                        lambda args, **_: json.dumps([route if args[2] == "route" else neighbor]).encode())

    def collect():
        return collector._collect_guest_arp_probes(pve, network, {"108": ip}, now)

    network["guest_arp_probes"] = collect()
    graph = collector.build_graph({}, network, {}, pve, {}, datetime.now(timezone.utc))
    node = next(node for node in graph["nodes"] if node.get("vmid") == 108)
    assert node["reachability"]["source"] == "UI_VPN"
    assert node["properties"]["IP проверки по ARP"] == ip
    path = tmp_path / "infrastructure.json"

    def interfaces():
        path.write_text(json.dumps(collector.build_graph({}, network, {}, pve, {}, datetime.now(timezone.utc))),
                        encoding="utf-8")
        guest, = summarize_guest_attachment(load_infrastructure_map(path), "pve-guest:108")["attachment"]["guests"]
        return {row["guestPort"]: row for row in guest["interfaces"]}

    addresses = interfaces()
    assert addresses["net0"]["ipv4Observations"] == [
        {"address": ip, "checkedAt": node["reachability"]["checkedAt"], "source": "UI_VPN", "method": "ICMP · ARP"},
    ]
    assert "ipv4Observations" not in addresses["net1"]
    assert pings == [ip]
    route["gateway"] = "192.0.2.1"
    assert collect() == {}
    assert pings == [ip]
    del route["gateway"]
    neighbor["lladdr"] = "02:00:00:00:00:05"
    assert collect() == {}
    assert pings == [ip, ip]
    network["arp"].append({**arp, "mac": neighbor["lladdr"]})
    assert collect() == {}
    network["arp"].pop()
    config["net0"] += ",link_down=1"
    assert collect() == {}
    assert "ipv4Observations" not in interfaces()["net0"]
    assert pings == [ip, ip]


def test_auto_guest_arp_checks_use_unique_local_ip_and_prefer_the_newer_result(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    earlier = (now - timedelta(minutes=1)).isoformat()
    ip, mac = "192.0.2.21", "02:00:00:00:00:03"
    pve = {"at": earlier, "cluster": [], "nodes": [],
           "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}}}
    arp = {"ip": ip, "mac": mac, "last_seen_at": earlier}
    host = {"ip": ip, "mac": mac, "availability": {"state": "online", "reason": "active_probe",
            "active_method": "icmp", "checked_at": earlier, "run_status": "success"}}
    network = {"arp": [arp], "hosts": [host]}
    calls = []
    monkeypatch.setattr(collector, "_probe_on_link_mac", lambda address, mac: calls.append((address, mac)) or True)

    def collect(configured=None):
        return collector._collect_guest_arp_probes(pve, network, configured or {}, now, auto_on_link=True)

    assert collector._collect_guest_arp_probes(pve, network, {}, now) == {}
    network["guest_arp_probes"] = collect()
    graph = collector.build_graph({}, network, {}, pve, {}, datetime.now(timezone.utc))
    node = next(row for row in graph["nodes"] if row.get("vmid") == 108)
    assert node["reachability"]["source"] == "UI_VPN"
    assert node["properties"]["IP проверки по ARP"] == ip
    assert calls == [(ip, mac)]
    assert collect({"108": "192.0.2.99"}) == {}
    network["arp"].append({**arp, "ip": "192.0.2.22"})
    assert collect() == {}
    network["arp"].pop()
    pve["at"] = (now - timedelta(hours=1)).isoformat()
    assert collect() == {}
    assert calls == [(ip, mac)]


def test_unanswered_guest_arp_is_visible_without_confirming_ip_or_reachability(tmp_path, monkeypatch):
    from app import infrastructure_collect as collector
    from app.infrastructure_map import load_infrastructure_map, summarize_guest_attachment_audit

    now = datetime.now(timezone.utc)
    stamp = now.isoformat()
    ip, mac = "192.0.2.21", "02:00:00:00:00:03"
    pve = {"at": stamp, "cluster": [], "nodes": [{"node": "pve1", "status": "online"}],
           "guests": [{"vmid": 108, "node": "pve1", "type": "qemu", "status": "running"}],
           "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}}}
    network = {"arp": [{"ip": ip, "mac": mac, "last_seen_at": stamp}]}
    monkeypatch.setattr(collector, "_probe_on_link_mac", lambda *_: False)
    calls = []

    def read_arp(address, expected_mac):
        calls.append((address, expected_mac))
        return {"state": "no_reply", "address": address, "sourceIP": "192.0.2.2", "interface": "ens18"}

    monkeypatch.setattr(collector, "_local_arp_diagnostic", read_arp)
    diagnostics = {}
    assert collector._collect_guest_arp_probes(pve, network, {}, now, auto_on_link=True,
                                               arp_diagnostics=diagnostics) == {}
    assert calls == [(ip, mac)]
    network["guest_arp_diagnostics"] = diagnostics
    path = tmp_path / "graph.json"
    collected = datetime.now(timezone.utc)
    collector.publish_snapshot(path, collector.build_graph({}, network, {}, pve, {}, collected))
    graph = load_infrastructure_map(path, collected, include_guest_attachments=True)
    node = next(n for n in graph["nodes"] if n["vmid"] == 108)
    interface, = graph["guestAttachments"][node["id"]]["interfaces"]
    assert interface["arpDiagnostic"] == {"state": "no_reply", "address": ip, "sourceIP": "192.0.2.2",
                                          "interface": "ens18", "identityCheckedAt": stamp,
                                          "checkedAt": diagnostics[mac]["checkedAt"]}
    assert node["reachability"]["state"] == "unknown" and "ipv4Observations" not in interface
    assert mac not in json.dumps(graph)
    gap, = summarize_guest_attachment_audit(graph)["attachmentAudit"]["gaps"]
    assert gap["interfaces"][0]["arpDiagnostic"] == interface["arpDiagnostic"]
    old = load_infrastructure_map(path, collected + timedelta(minutes=6), include_guest_attachments=True)
    assert "arpDiagnostic" not in old["guestAttachments"][node["id"]]["interfaces"][0]


def test_router_layer2_probe_requires_a_reply_from_the_expected_mac(monkeypatch):
    from contextlib import nullcontext

    from netctl.drivers.mikrotik_api import MikroTikApiDriver

    mac = "02:00:00:00:00:03"
    calls = []
    rows = [{"host": mac, "sent": "1", "received": "1"}]

    class Api:
        def call(self, words):
            calls.append(words)
            return rows

    monkeypatch.setattr(MikroTikApiDriver, "_client", lambda self: nullcontext(Api()))
    driver = MikroTikApiDriver({}, {})
    assert driver.probe_layer2("bridge-lan", mac)
    assert driver.probe_layer2("bridge-lan", mac, address="192.0.2.21")
    assert calls == [
        ["/ping", f"=address={mac}", "=interface=bridge-lan", "=count=1"],
        ["/ping", "=address=192.0.2.21", "=interface=bridge-lan", "=count=1", "=arp-ping=yes"],
    ]
    rows[0]["host"] = "02:00:00:00:00:07"
    assert not driver.probe_layer2("bridge-lan", mac, address="192.0.2.21")
    rows[0].update(host=mac, received="0")
    assert not driver.probe_layer2("bridge-lan", mac)


def test_router_layer2_checks_follow_inventory_and_guest_arp_identity(monkeypatch):
    from app import infrastructure_collect as collector

    now = datetime.now(timezone.utc)
    ip, mac = "192.0.2.21", "02:00:00:00:00:03"
    ap_mac = "02:00:00:00:00:04"
    pve = {"cluster": [], "nodes": [], "guests": [{"vmid": 108, "node": "pve1", "status": "running"}],
           "configs": {"108": {"net0": f"virtio={mac},bridge=vmbr0"}}}
    source = {"name": "router", "enabled": True, "driver": "mikrotik_api"}
    arp = {"ip": ip, "mac": mac, "source": "router", "interface": "bridge-lan", "last_seen_at": now.isoformat()}
    network = {"arp": [arp], "sources": [source]}
    context = {"devices": [{"id": "ap", "name": "AP", "kind": "wireless_access_point", "mac_addresses": [ap_mac]}]}
    bindings = {"asset_mac_probes": {"ap": {"source": "router", "interface": "bridge-lan", "mac": ap_mac}},
                "guest_router_arp_sources": {"108": "router"}}
    calls = []

    class Driver:
        def probe_layer2(self, interface, target, *, address=None):
            calls.append((interface, target, address))
            return True

    monkeypatch.setattr(collector, "load_secrets", lambda: {})
    monkeypatch.setattr(collector, "legacy_driver_for", lambda *_: Driver())
    monkeypatch.setattr(collector, "_probe_on_link_mac", lambda *_: False)
    network["asset_mac_checks"] = collector._collect_asset_mac_probes(context, [source], bindings["asset_mac_probes"])
    network["guest_arp_probes"] = collector._collect_guest_arp_probes(
        pve, network, {"108": ip}, now, bindings["guest_router_arp_sources"],
    )
    graph = collector.build_graph(context, network, {}, pve, bindings, datetime.now(timezone.utc))
    nodes = {row["id"]: row for row in graph["nodes"]}
    assert nodes["ap"]["reachability"]["method"] == "MAC ping · L2"
    assert nodes["pve-guest:108"]["reachability"]["method"] == "ARP · L2"
    assert calls == [("bridge-lan", ap_mac, None), ("bridge-lan", mac, ip)]
    arp["source"] = "other-router"
    assert collector._collect_guest_arp_probes(pve, network, {"108": ip}, now, bindings["guest_router_arp_sources"]) == {}
    context["devices"][0]["mac_addresses"] = [mac]
    assert collector._collect_asset_mac_probes(context, [source], bindings["asset_mac_probes"]) == {}
    assert len(calls) == 2
    context["devices"][0].update(mac_addresses=[ap_mac], management_ip="192.0.2.24")
    spec = bindings["asset_mac_probes"]["ap"]
    spec["address"] = "192.0.2.24"
    checked = collector._collect_asset_mac_probes(context, [source], bindings["asset_mac_probes"])
    assert checked["ap"]["method"] == "ARP · L2"
    assert checked["ap"]["target"] == "192.0.2.24"
    assert calls[-1] == ("bridge-lan", ap_mac, "192.0.2.24")
    spec["address"] = ip
    assert collector._collect_asset_mac_probes(context, [source], bindings["asset_mac_probes"]) == {}
    spec["address"] = "192.0.2.24"
    context["devices"].append({"id": "other", "management_ip": spec["address"]})
    assert collector._collect_asset_mac_probes(context, [source], bindings["asset_mac_probes"]) == {}
    assert len(calls) == 3


def test_guest_attachment_probe_requires_router_arp_and_a_live_learned_switch_port(monkeypatch):
    import asyncio

    from app import infrastructure_collect as collector
    from netctl.snmp.models import CapabilityResult, SnmpVarBind
    from netctl.snmp.oids import DOT1D_FDB_PORT, DOT1D_FDB_STATUS
    from netctl.snmp.outcomes import SnmpOutcome

    now = datetime.now(timezone.utc)
    at = now.isoformat()
    mac, ip = "02:00:00:00:00:03", "192.0.2.21"
    pve = {"at": at, "guests": [{"vmid": 111, "status": "running"}],
           "configs": {"111": {"net0": f"virtio={mac},bridge=vmbr1"}}}
    arp = {"ip": ip, "mac": mac, "source": "router", "interface": "bridge-lan", "last_seen_at": at}
    network = {"arp": [arp], "sources": [
        {"name": "switch", "id": 7, "driver": "snmp_switch", "enabled": True},
    ], "switches": [{"source": "switch", "profile_id": "snr", "last_success_at": at}],
        "ports": [{"source": "switch", "collector_run_id": 9, "port_key": "xe3", "name": "xe3",
                   "if_index": 5027, "oper_status": "up", "last_seen_at": at}]}
    bindings = {"guest_probe_ips": {"111": ip}, "guest_router_arp_sources": {"111": "router"},
                "guest_attachment_fdb": {"111": "switch"}}
    calls = []
    learned = True

    class Transport:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, oid):
            column, index = oid[:-6], oid[-6:]
            assert index == tuple(bytes.fromhex(mac.replace(":", "")))
            assert calls[-1] == ("router", "bridge-lan", mac, ip)
            value = {DOT1D_FDB_STATUS: 3 if learned else 4, DOT1D_FDB_PORT: 5027}[column]
            return CapabilityResult("", SnmpOutcome.SUCCESS_WITH_ROWS, (SnmpVarBind(oid, "integer", value),))

    def probe(sources, name, interface, target, *, address):
        calls.append((name, interface, target, address))
        return {"state": "reachable"}

    async def link(transport, index, name):
        assert (index, name) == (5027, "xe3")
        return {"state": "up"}

    monkeypatch.setattr(collector.SnmpTransport, "from_source", lambda _: Transport())
    monkeypatch.setattr(collector, "_router_layer2_observation", probe)
    monkeypatch.setattr(collector, "read_interface_link", link)

    def collect():
        return asyncio.run(collector._collect_guest_attachment_fdb(pve, network, bindings, now))

    row, = collect()
    assert {k: row[k] for k in ("source_id", "port_key", "mac", "vlan_id")} == {
        "source_id": 7, "port_key": "xe3", "mac": mac, "vlan_id": None,
    }
    network["guest_fdb"] = [{**row, "observed_at": at, "vlan_id": 1}]
    assert collect() == []
    network["guest_fdb"].clear()
    learned = False
    assert collect() == []
    arp["source"] = "other-router"
    assert collect() == [] and len(calls) == 3


def test_inventory_binding_needs_matching_guest_mac():
    from app.infrastructure_collect import build_graph

    context = {"devices": [{"id": "document-server", "name": "Document server", "kind": "server"}]}
    pve = {
        "cluster": [{"type": "cluster", "name": "example", "quorate": 1}],
        "nodes": [{"node": "pve-a", "status": "online"}],
        "guests": [{"vmid": 103, "node": "pve-a", "type": "qemu", "name": "guest", "status": "running"}],
        "configs": {"103": {"net0": "virtio=02:00:00:00:00:03,bridge=vmbr0"}},
    }
    binding = {"103": {"asset": "document-server", "mac": "02:00:00:00:00:03"}}
    graph = build_graph(context, {}, {}, pve, {"guests": binding}, datetime.now(timezone.utc))
    assert graph["overviewGuests"] == ["document-server"]
    assert any(edge["a"] == "pve-a" and edge["b"] == "document-server" for edge in graph["links"])

    pve["configs"]["103"]["net0"] = "virtio=02:00:00:00:00:99,bridge=vmbr0"
    graph = build_graph(context, {}, {}, pve, {"guests": binding}, datetime.now(timezone.utc))
    assert graph["overviewGuests"] == []
    assert any(node["id"] == "pve-guest:103" for node in graph["nodes"])


def test_reachability_uses_active_network_evidence_not_vm_power(tmp_path):
    from app.infrastructure_collect import build_graph
    from app.infrastructure_map import load_infrastructure_map

    now = datetime.now(timezone.utc)
    active = {"state": "online", "run_status": "success", "reason": "active_probe",
              "active_method": "icmp", "checked_at": now.isoformat()}
    negative = {**active, "state": "offline", "reason": "active_negative_no_passive_evidence"}
    network = {"hosts": [
        {"ip": "192.0.2.10", "mac": "02:00:00:00:00:10", "availability": active},
        {"ip": "192.0.2.20", "mac": "02:00:00:00:00:20", "availability": negative},
        {"ip": "192.0.2.30", "mac": "02:00:00:00:00:30",
         "availability": {**active, "state": "seen", "reason": "passive_evidence"}},
    ]}
    pve = {
        "cluster": [], "nodes": [{"node": "pve-a", "status": "online"}],
        "guests": [
            {"vmid": i, "node": "pve-a", "type": "qemu", "status": status}
            for i, status in [(10, "running"), (20, "running"), (30, "running"), (40, "stopped"), (50, "running")]
        ],
        "configs": {
            str(i): {"net0": f"virtio=02:00:00:00:00:{i},bridge=vmbr0"} for i in (10, 20, 30)
        },
    }
    graph = build_graph({}, network, {}, pve, {}, now)
    path = tmp_path / "map.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    published = load_infrastructure_map(path, now)
    states = {node["vmid"]: node["reachability"]["state"] for node in published["nodes"] if node["guest"]}
    assert states == {10: "reachable", 20: "unreachable", 30: "unknown", 40: "stopped", 50: "unknown"}
    expired = load_infrastructure_map(path, now + timedelta(minutes=26))
    assert all(node["reachability"]["state"] == "unknown" for node in expired["nodes"])
