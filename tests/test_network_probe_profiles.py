import ipaddress
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app import network_capture_store, network_probe_profiles


def test_throughput_profile_uses_kernel_route_and_pinned_stream(monkeypatch):
    from app import network_checks

    profiles = network_probe_profiles.ProbeProfiles.model_validate({"throughput": {"site": {
        "label": "Site", "peer": "192.0.2.12", "port": 5201, "duration_seconds": 5,
        "bitrate_mbps": 10, "source_address": "192.0.2.4", "bind_interface": "tun0",
    }}})
    monkeypatch.setattr(network_checks, "load_probe_profiles", lambda: profiles)
    planned = {"status": "route_found", "result": {"dev": "ens18"}}
    calls = []

    def route(destination, *, source, interface, tcp_port):
        assert destination == ipaddress.ip_address("192.0.2.12")
        assert (str(source), interface, tcp_port) == ("192.0.2.4", "tun0", 5201)
        return planned

    def measure(peer, port, direction, **kwargs):
        calls.append((peer, port, direction, kwargs))
        return {"status": "ok", "result": {"sender_mbps": 10, "receiver_mbps": 9.8},
                "connection": {"source_address": "192.0.2.4", "peer_address": peer, "peer_port": port}}

    monkeypatch.setattr(network_checks, "lookup_linux_route", route)
    monkeypatch.setattr(network_checks, "run_throughput", measure)
    check = network_checks.IperfCheck(check="iperf3", profile="site", direction="receive")
    blocked = network_checks.execute_network_check(check)
    assert blocked["status"] == "route_mismatch" and calls == []
    assert blocked["result"]["kernel_route"]["result"]["dev"] == "ens18"
    planned = {"status": "route_found", "result": {"dev": "tun0"}}
    result = network_checks.execute_network_check(check)
    assert calls == [("192.0.2.12", 5201, "receive", {
        "duration_seconds": 5, "bitrate_mbps": 10, "source_address": "192.0.2.4", "bind_interface": "tun0",
    })]
    assert result["status"] == "measured"
    assert result["result"]["kernel_route"]["result"]["dev"] == "tun0"
    assert result["result"]["connection"]["source_address"] == "192.0.2.4"


def test_profile_catalog_exposes_ids_and_limits(tmp_path, monkeypatch):
    config = tmp_path / "network-probes.json"
    config.write_text(json.dumps({
        "throughput": {"lan": {"label": "LAN", "peer": "192.0.2.12", "port": 5201,
                               "duration_seconds": 5, "bitrate_mbps": 10}},
        "capture": {},
    }), encoding="utf-8")
    monkeypatch.setattr(network_probe_profiles, "PROFILE_PATH", config)
    monkeypatch.setattr(network_probe_profiles, "_is_trusted_file", lambda info: True)
    catalog = network_probe_profiles.probe_catalog()
    assert catalog["throughput"] == [{
        "id": "lan", "label": "LAN", "peer": "192.0.2.12", "port": 5201,
        "duration_seconds": 5, "bitrate_mbps": 10,
    }]
    assert catalog["capture"] == []


def test_route_catalog_exposes_probe_digest_without_private_ca_path(monkeypatch):
    profiles = network_probe_profiles.ProbeProfiles.model_validate({
        "routes": {"services": {"label": "Services", "probes": [{
            "id": "api", "expected_path": "LAN", "target": "192.0.2.20",
            "protocol": "https", "server_name": "api.test", "tls_ca_file": "/etc/test/ca.pem",
        }]}},
    })
    monkeypatch.setattr(network_probe_profiles, "load_probe_profiles", lambda: profiles)
    row = network_probe_profiles.probe_catalog()["routes"][0]["probes"][0]
    assert row["config_digest"] == profiles.routes["services"].probes[0].config_digest()
    assert "tls_ca_file" not in row


def test_capture_receipt_owner_expiry_and_purge(tmp_path, monkeypatch):
    directory = tmp_path / "captures"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(network_capture_store, "CAPTURE_DIRECTORY", directory)
    now = datetime(2026, 11, 12, 17, tzinfo=UTC)
    monkeypatch.setattr(network_capture_store, "capture_packets", lambda output, **kwargs: (
        output.write_bytes(b"capture data" * 3), {"status": "ok", "size_bytes": 36, "packets": 1}
    )[1])
    profile = network_probe_profiles.CaptureProfile(
        label="PCAP", interface="ens18", peer="192.0.2.12", port=5201, protocol="tcp",
        duration_seconds=5, max_packets=40, max_kib=64,
    )
    result = network_capture_store.create_capture("service:reader", profile, now=now)
    capture_id = UUID(result["result"]["capture_id"])
    assert result["status"] == "captured"
    assert network_capture_store.read_capture(capture_id, "service:reader", now=now) == b"capture data" * 3
    assert network_capture_store.read_capture(capture_id, "user:reader", now=now) is None
    assert network_capture_store.list_captures("service:other", now=now) == []
    expired = now + timedelta(hours=1)
    assert network_capture_store.read_capture(capture_id, "service:reader", now=expired) is None
    network_capture_store.purge_captures(now=expired)
    assert list(directory.glob("*.pcap")) == [] and list(directory.glob("*.json")) == []
