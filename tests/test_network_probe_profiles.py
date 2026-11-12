import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app import network_capture_store, network_probe_profiles


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
