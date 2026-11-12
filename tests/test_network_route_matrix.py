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


@pytest.mark.parametrize("changes", [
    {"target": "239.1.1.1"}, {"target": "192.0.2.20;command"}, {"interface": "wan1 extra"},
    {"router_source": None}, {"protocol": "tcp", "port": 443}, {"id": "backup"},
])
def test_route_profiles_reject_invalid_parameters(changes):
    config = matrix_config()
    config["routes"]["comparison"]["probes"][0].update(changes)
    with pytest.raises(ValidationError):
        network_probe_profiles.ProbeProfiles.model_validate(config)


def test_route_matrix_keeps_requested_and_observed_paths_distinct(monkeypatch):
    from app import network_route_matrix

    profiles = network_probe_profiles.ProbeProfiles.model_validate(matrix_config())
    calls = []

    def run_netctl(args, **kwargs):
        calls.append(args)
        if args[-2] == "--probe=backup":
            return {"probe": {"status": "timeout", "evidence": {}}}
        return {"probe": {"status": "reachable", "evidence": {"received": 3}}}

    def run_local(**kwargs):
        assert kwargs["port"] == 443
        assert kwargs["expected_http_status"] == 200
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
    assert sorted(call[:-1] for call in calls) == [
        ["path", "probe", "--profile=comparison", "--probe=backup"],
        ["path", "probe", "--profile=comparison", "--probe=main"],
    ]


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
