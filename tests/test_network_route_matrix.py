import hashlib

import pytest
from pydantic import ValidationError

from app import network_probe_profiles


def matrix_config():
    return {
        "routes": {"comparison": {"label": "Compare WAN paths", "probes": [
            {"id": "main", "expected_path": "WAN 1", "target": "192.0.2.20", "protocol": "icmp",
             "router_source": "mikrotik-main", "interface": "wan1", "routing_table": "isp1"},
            {"id": "backup", "expected_path": "WAN 2", "target": "192.0.2.20", "protocol": "icmp",
             "router_source": "mikrotik-main", "interface": "wan2", "routing_table": "isp2"},
            {"id": "web", "expected_path": "VPN service", "target": "192.0.2.30", "protocol": "https",
             "server_name": "status.example.test"},
        ]}},
    }


def test_schedule_accepts_six_profiles_with_at_most_four_remote_origins():
    local = {"id": "gateway", "expected_path": "local", "target": "192.0.2.1", "protocol": "icmp"}
    remote = {**local, "router_source": "router"}
    profiles = {
        f"path-{i}": {"label": f"Path {i}", "scheduled": True, "probes": [remote if i < 4 else local]}
        for i in range(6)
    }
    assert len(network_probe_profiles.ProbeProfiles.model_validate({"routes": profiles}).routes) == 6
    with pytest.raises(ValidationError):
        network_probe_profiles.ProbeProfiles.model_validate({
            "routes": {**profiles, "path-6": {"label": "Extra", "scheduled": True, "probes": [local]}},
        })
    profiles["path-4"]["probes"] = [{**local, "agent_origin": "probe-host"}]
    with pytest.raises(ValidationError):
        network_probe_profiles.ProbeProfiles.model_validate({"routes": profiles})


@pytest.mark.parametrize("changes", [
    {"target": "239.1.1.1"}, {"target": "192.0.2.20;command"}, {"interface": "wan1 extra"},
    {"router_source": None}, {"protocol": "tcp", "port": 443}, {"id": "backup"},
])
def test_route_profiles_reject_invalid_parameters(changes):
    config = matrix_config()
    config["routes"]["comparison"]["probes"][0].update(changes)
    with pytest.raises(ValidationError):
        network_probe_profiles.ProbeProfiles.model_validate(config)


def test_dns_transport_is_explicit_without_changing_existing_probe_digests():
    common = {
        "id": "dns", "expected_path": "LAN", "target": "192.0.2.20",
        "protocol": "dns", "dns_name": "service.test",
    }
    original = network_probe_profiles.RouteProbe.model_validate(common)
    expected = original.model_dump_json(exclude={
        "openvpn_client", "dns_transport", "expected_kernel_interface", "expected_kernel_gateway", "push_origin",
    })
    assert original.config_digest() == hashlib.sha256(expected.encode()).hexdigest()
    assert "dns_transport" not in original.local_arguments()
    tcp = network_probe_profiles.RouteProbe.model_validate({**common, "dns_transport": "tcp"})
    assert tcp.local_arguments()["dns_transport"] == "tcp"
    assert tcp.config_digest() != original.config_digest()
    with pytest.raises(ValidationError):
        network_probe_profiles.RouteProbe.model_validate({**common, "dns_transport": "tls"})


def test_route_matrix_keeps_requested_and_observed_paths_distinct(monkeypatch):
    from app import network_route_matrix

    config = matrix_config()
    config["routes"]["comparison"]["probes"][2]["expected_kernel_gateway"] = "192.0.2.1"
    profiles = network_probe_profiles.ProbeProfiles.model_validate(config)
    calls = []

    def run_netctl(args, **kwargs):
        calls.append(args)
        if args[-2] == "--probe=backup":
            return {"probe": {"status": "timeout", "evidence": {}}}
        return {"probe": {"status": "reachable", "evidence": {"received": 3}}}

    def run_local(**kwargs):
        assert kwargs["port"] == 443
        assert kwargs["expected_http_status"] == 200
        assert kwargs["expected_kernel_gateway"] == "192.0.2.1"
        return {"status": "reachable", "evidence": {"http_status": 200},
                "kernel_route": {"status": "route_found", "result": {"dev": "tun0"}}}

    monkeypatch.setattr(network_route_matrix, "run_netctl", run_netctl)
    monkeypatch.setattr(network_route_matrix, "probe_local_route", run_local)
    result = network_route_matrix.run_route_matrix("comparison", profiles.routes["comparison"])
    assert result["status"] == "partial"
    main, backup, web = result["result"]["probes"]
    assert main["expected_path"] == "WAN 1" and main["path_status"] == "unconfirmed"
    assert main["observed_path"] is None and backup["status"] == "timeout"
    assert web["kernel_route"]["result"]["dev"] == "tun0" and web["observed_path"] is None
    assert web["expected_kernel_gateway"] == "192.0.2.1"
    assert sorted(call[:-1] for call in calls) == [
        ["path", "probe", "--profile=comparison", "--probe=backup"],
        ["path", "probe", "--profile=comparison", "--probe=main"],
    ]


@pytest.mark.parametrize("connections,expected,session", [
    ([], "not_connected", "not_connected"),
    ([{"common_name": "other", "virtual_address": "192.0.2.20"}], "not_connected", "address_mismatch"),
    ([{"common_name": "router", "virtual_address": "192.0.2.30"}], "not_connected", "address_mismatch"),
    ([{"common_name": "router", "virtual_address": "192.0.2.20"}], "reachable", "connected"),
    (None, "unavailable", "unavailable"),
])
def test_openvpn_probe_requires_the_expected_live_session(monkeypatch, connections, expected, session):
    from app import network_route_matrix

    profile = network_probe_profiles.RouteProfile.model_validate({"label": "Tunnel", "probes": [{
        "id": "router", "expected_path": "OpenVPN", "target": "192.0.2.20",
        "protocol": "icmp", "openvpn_client": "router",
    }]})
    calls = []

    def read_sessions(args, **kwargs):
        assert args == ["connected", "--source", "management"]
        return {"status": "ok", "source": "management" if connections is not None else "status_file",
                "connected": connections or []}

    def probe(**kwargs):
        calls.append(kwargs)
        return {"status": "reachable", "evidence": {}}

    monkeypatch.setattr(network_route_matrix, "run_vpnctl", read_sessions)
    monkeypatch.setattr(network_route_matrix, "probe_local_route", probe)
    result = network_route_matrix.run_route_matrix("tunnel", profile)
    assert result["status"] == expected
    assert len(calls) == int(expected == "reachable")
    assert result["result"]["probes"][0]["openvpn_client"] == "router"
    assert result["result"]["probes"][0]["evidence"]["openvpn_session"] == session


def test_cli_reads_router_from_sqlite_and_rejects_changed_profile(tmp_path, monkeypatch):
    from netctl import cli, db, route_availability

    profiles = network_probe_profiles.ProbeProfiles.model_validate(matrix_config())
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    monkeypatch.setattr(cli, "load_secrets", lambda: {})
    path = f"sqlite:///{tmp_path / 'netctl.sqlite'}"
    with db.connect(path) as conn:
        db.upsert_source(conn, {
            "name": "mikrotik-main", "driver": "mikrotik_api", "host": "192.0.2.1", "port": 8729,
            "username": "reader", "secret_ref": "test_router", "tls": True, "verify_tls": True,
            "site": "main", "role": "router", "enabled": True,
        })
    calls = []

    def ping(driver, command):
        calls.append(command)
        return [{"sent": "3", "received": "3", "host": "192.0.2.20"}]

    class RouterClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        call = ping

    monkeypatch.setattr(route_availability.MikroTikApiDriver, "_client", lambda self: RouterClient())
    args = ["--db", path, "path", "probe", "--profile=comparison", "--probe=main"]
    parser = cli.build_parser()
    code, payload = cli.dispatch(parser.parse_args([*args, "--expected-config=changed"]))
    assert code == 0 and payload["probe"]["reason"] == "profile_mismatch" and calls == []
    digest = profiles.routes["comparison"].probes[0].config_digest()
    code, payload = cli.dispatch(parser.parse_args([*args, f"--expected-config={digest}"]))
    assert code == 0 and payload["probe"]["status"] == "reachable"
    assert calls == [["/ping", "=address=192.0.2.20", "=count=3", "=interval=1s", "=interface=wan1", "=routing-table=isp1"]]


def test_ipsec_policy_and_peer_sa_bytes_are_independent_of_echo_reply(monkeypatch):
    from app import network_route_matrix

    profile = network_probe_profiles.RouteProfile.model_validate({"label": "Archive", "probes": [{
        "id": "to-archive", "expected_path": "Tunnel", "target": "192.0.2.20", "protocol": "icmp",
        "router_source": "mikrotik-main", "source_address": "198.51.100.10", "ipsec": True,
    }]})

    def netctl(args, **kwargs):
        if args[:2] == ["path", "probe"]:
            return {"probe": {"status": "unreachable", "evidence": {"received": 0}}}
        assert args == ["ipsec", "status", "--allow-source-errors", "--source=mikrotik-main"]
        return {"sources": [{"source": "mikrotik-main", "status": "ok", "errors": [], "policies": [{
            "src_address": "198.51.100.0/24", "dst_address": "192.0.2.0/24", "action": "encrypt",
            "disabled": False, "established": True, "ph2_count": 1,
            "sa_src_address": "203.0.113.1", "sa_dst_address": "203.0.113.2",
            "local_sa_address_status": "assigned",
        }], "installed_sas": [
            {"src_address": "203.0.113.1", "dst_address": "203.0.113.2", "state": "mature", "current_bytes": 42},
            {"src_address": "203.0.113.2", "dst_address": "203.0.113.1", "state": "mature", "current_bytes": 10},
            {"src_address": "203.0.113.3", "dst_address": "203.0.113.1", "state": "mature", "current_bytes": 70},
        ]}]}

    monkeypatch.setattr(network_route_matrix, "run_netctl", netctl)
    row = network_route_matrix.run_route_matrix("archive", profile)["result"]["probes"][0]
    assert row["status"] == "unreachable" and row["observed_path"] is None
    assert row["ipsec"]["status"] == "established"
    assert row["ipsec"]["local_sa_address_status"] == "assigned"
    assert row["ipsec"]["peer_sa_counters"] == {
        "outgoing": {"associations": 1, "bytes": 42}, "incoming": {"associations": 1, "bytes": 10},
    }


@pytest.mark.parametrize("failure", ["collector_timeout", "source_error"])
def test_ipsec_observation_failure_is_separate_from_ping_status(monkeypatch, failure):
    from subprocess import TimeoutExpired

    from app import network_route_matrix
    from app.netctl_client import NetctlError

    profile = network_probe_profiles.RouteProfile.model_validate({"label": "Archive", "probes": [{
        "id": "from-archive", "expected_path": "Tunnel", "target": "192.0.2.20", "protocol": "icmp",
        "router_source": "archive-router", "source_address": "198.51.100.10", "ipsec": True,
    }]})

    def netctl(args, **kwargs):
        if args[:2] == ["path", "probe"]:
            return {"probe": {"status": "timeout"}}
        if failure == "collector_timeout":
            raise NetctlError("netctl timeout", stdout="internal output") from TimeoutExpired(args, 12)
        return {"sources": [{"source": "archive-router", "status": "error", "errors": [{"message": "internal output"}]}]}

    monkeypatch.setattr(network_route_matrix, "run_netctl", netctl)
    row = network_route_matrix.run_route_matrix("archive", profile)["result"]["probes"][0]

    assert row["status"] == "timeout"
    assert row["ipsec"]["status"] == "unavailable"
    assert row["ipsec"]["reason"] == failure
    assert "internal output" not in repr(row)
