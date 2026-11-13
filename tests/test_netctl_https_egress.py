from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from app import network_probe_profiles
from netctl import cli, https_egress
from netctl.https_egress import observe_https_egress


@pytest.mark.parametrize("combined", [True, False])
@pytest.mark.parametrize("peer_port", [443, 5201])
def test_egress_requires_exact_tuple_and_unique_nat_interface(combined, peer_port):
    local, peer, port = "192.0.2.10", "162.159.140.220", 42013
    nat = "198.51.100.5"
    row = {
        "protocol": "tcp", "srcnat": "true", "seen-reply": "true",
        "reply-dst-address": f"{nat}:62013" if combined else nat,
        "src-address": f"{local}:{port}" if combined else local,
        "dst-address": f"{peer}:{peer_port}" if combined else peer,
    }
    if not combined:
        row.update({"src-port": str(port), "dst-port": str(peer_port)})
    calls = []

    def call(args):
        calls.append(args)
        if args[0] == "/ip/address/print":
            return [{"address": f"{nat}/24", "interface": "wan1", "disabled": "false"}]
        if ("?src-address=" + row["src-address"]) in args:
            return [row]
        return []

    driver = SimpleNamespace(_client=lambda: nullcontext(SimpleNamespace(call=call)))
    assert observe_https_egress(driver, local, port, peer, peer_port) == {
        "status": "confirmed", "nat_interface": "wan1",
    }
    row["dst-address"] = f"{peer}:1234" if combined else peer
    if not combined:
        row["dst-port"] = "1234"
    calls.clear()
    assert observe_https_egress(driver, local, port, peer, peer_port)["status"] == "unconfirmed"
    assert all(args[0] == "/ip/firewall/connection/print" for args in calls)


@pytest.mark.parametrize("command,catalog,peer,peer_port", [
    ("https-egress", "https_speed", "162.159.140.220", 443),
    ("iperf-egress", "throughput", "192.0.2.20", 5201),
])
def test_cli_binds_observation_to_root_profile_and_checks_digest(monkeypatch, command, catalog, peer, peer_port):
    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "https_speed": {"wan": {
            "label": "WAN", "peer": "162.159.140.220", "download_bytes": 100_000,
            "upload_bytes": 100_000, "router_source": "router", "source_address": "192.0.2.10",
        }},
        "throughput": {"wan": {
            "label": "WAN", "peer": "192.0.2.20", "port": 5201, "duration_seconds": 5,
            "bitrate_mbps": 5, "router_source": "router", "source_address": "192.0.2.10",
        }},
    })
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    conn = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(cli, "connect_read_only", lambda db: conn)
    source = {"enabled": True, "driver": "mikrotik_api"}
    monkeypatch.setattr(cli, "get_source", lambda db, name: source if name == "router" else None)
    monkeypatch.setattr(cli, "load_secrets", dict)
    calls = []

    def observe(driver, local, port, peer, peer_port=443):
        calls.append((driver.source, local, port, peer, peer_port))
        return {"status": "confirmed", "nat_interface": "wan1"}

    monkeypatch.setattr(https_egress, "observe_https_egress", observe)
    argv = ["path", command, "--profile=wan", "--source-port=42013"]
    parser = cli.build_parser()
    assert cli.dispatch(parser.parse_args([*argv, "--expected-config=wrong"]))[0] == 1
    digest = getattr(profiles, catalog)["wan"].config_digest()
    rc, response = cli.dispatch(parser.parse_args([*argv, f"--expected-config={digest}"]))
    assert rc == 0 and response["egress"]["nat_interface"] == "wan1"
    assert calls == [(source, "192.0.2.10", 42013, peer, peer_port)]
