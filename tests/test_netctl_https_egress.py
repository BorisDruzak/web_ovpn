from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from app import network_probe_profiles
from netctl import cli, https_egress
from netctl.https_egress import observe_https_egress


@pytest.mark.parametrize("combined", [True, False])
def test_egress_requires_exact_tuple_and_unique_nat_interface(combined):
    local, peer, port = "192.0.2.10", "162.159.140.220", 42013
    nat = "198.51.100.5"
    row = {
        "protocol": "tcp", "srcnat": "true", "seen-reply": "true",
        "reply-dst-address": f"{nat}:62013" if combined else nat,
        "src-address": f"{local}:{port}" if combined else local,
        "dst-address": f"{peer}:443" if combined else peer,
    }
    if not combined:
        row.update({"src-port": str(port), "dst-port": "443"})
    calls = []

    def call(args):
        calls.append(args)
        if args[0] == "/ip/address/print":
            return [{"address": f"{nat}/24", "interface": "wan1", "disabled": "false"}]
        if ("?src-address=" + row["src-address"]) in args:
            return [row]
        return []

    driver = SimpleNamespace(_client=lambda: nullcontext(SimpleNamespace(call=call)))
    assert observe_https_egress(driver, local, port, peer) == {
        "status": "confirmed", "nat_interface": "wan1",
    }
    row["dst-address"] = "198.51.100.9"
    calls.clear()
    assert observe_https_egress(driver, local, port, peer)["status"] == "unconfirmed"
    assert all(args[0] == "/ip/firewall/connection/print" for args in calls)


def test_cli_binds_observation_to_root_profile_and_checks_digest(monkeypatch):
    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "https_speed": {"wan": {
            "label": "WAN", "peer": "162.159.140.220", "download_bytes": 100_000,
            "upload_bytes": 100_000, "router_source": "router", "source_address": "192.0.2.10",
        }},
    })
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    conn = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(cli, "connect_read_only", lambda db: conn)
    source = {"enabled": True, "driver": "mikrotik_api"}
    monkeypatch.setattr(cli, "get_source", lambda db, name: source if name == "router" else None)
    monkeypatch.setattr(cli, "load_secrets", dict)
    calls = []

    def observe(driver, local, port, peer):
        calls.append((driver.source, local, port, peer))
        return {"status": "confirmed", "nat_interface": "wan1"}

    monkeypatch.setattr(https_egress, "observe_https_egress", observe)
    argv = ["path", "https-egress", "--profile=wan", "--source-port=42013"]
    parser = cli.build_parser()
    assert cli.dispatch(parser.parse_args([*argv, "--expected-config=wrong"]))[0] == 1
    digest = profiles.https_speed["wan"].config_digest()
    rc, response = cli.dispatch(parser.parse_args([*argv, f"--expected-config={digest}"]))
    assert rc == 0 and response["egress"]["nat_interface"] == "wan1"
    assert calls == [(source, "192.0.2.10", 42013, "162.159.140.220")]
