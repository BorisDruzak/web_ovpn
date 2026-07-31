from __future__ import annotations

from copy import deepcopy

from app.endpoint_agent_network import correlate_endpoint_agents


def _identity(device_id: str, mac_keys: list[str]) -> dict[str, object]:
    return {
        "id": device_id,
        "display_name": "Office workstation",
        "last_seen_at": "2026-07-31T10:00:00Z",
        "baseline_collected_at": "2026-07-31T09:00:00Z",
        "profiles": [{"profile": "baseline_v1", "collected_at": "2026-07-31T09:00:00Z"}],
        "baseline_mac_keys": mac_keys,
    }


def test_correlation_confirms_only_one_exact_mac_pair_and_discards_matching_material() -> None:
    inventory = [
        {
            "device_key": "mac:AA:BB:CC:DD:EE:01",
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.168.100.55",
            "hostname": "pc-buh-01",
        }
    ]
    identities = [_identity("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", ["mac-aabbccddee01"])]

    result = correlate_endpoint_agents(inventory, identities)

    assert result == {
        "mac:AA:BB:CC:DD:EE:01": {
            "state": "confirmed",
            "device_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_display_name": "Office workstation",
            "gateway_last_seen_at": "2026-07-31T10:00:00Z",
            "baseline_collected_at": "2026-07-31T09:00:00Z",
            "profiles": ["baseline_v1"],
            "evidence_kind": "baseline_interface_mac",
        }
    }
    assert "mac" not in result["mac:AA:BB:CC:DD:EE:01"]
    assert "ip" not in result["mac:AA:BB:CC:DD:EE:01"]

    changed_ip = deepcopy(inventory)
    changed_ip[0]["ip"] = "192.168.101.77"
    assert correlate_endpoint_agents(changed_ip, identities) == result


def test_correlation_marks_duplicate_asset_or_agent_mac_as_ambiguous() -> None:
    duplicate_assets = [
        {"device_key": "asset-a", "mac": "AA:BB:CC:DD:EE:01"},
        {"device_key": "asset-b", "mac": "aa-bb-cc-dd-ee-01"},
    ]
    duplicate_agents = [
        _identity("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", ["mac-aabbccddee01"]),
        _identity("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", ["mac-aabbccddee01"]),
    ]

    assert correlate_endpoint_agents(duplicate_assets, duplicate_agents[:1]) == {
        "asset-a": {
            "state": "ambiguous",
            "device_id": None,
            "device_display_name": None,
            "gateway_last_seen_at": None,
            "baseline_collected_at": None,
            "profiles": [],
            "evidence_kind": "baseline_interface_mac",
        },
        "asset-b": {
            "state": "ambiguous",
            "device_id": None,
            "device_display_name": None,
            "gateway_last_seen_at": None,
            "baseline_collected_at": None,
            "profiles": [],
            "evidence_kind": "baseline_interface_mac",
        },
    }
    assert correlate_endpoint_agents(
        [{"device_key": "asset-a", "mac": "AA:BB:CC:DD:EE:01"}], duplicate_agents
    ) == {
        "asset-a": {
            "state": "ambiguous",
            "device_id": None,
            "device_display_name": None,
            "gateway_last_seen_at": None,
            "baseline_collected_at": None,
            "profiles": [],
            "evidence_kind": "baseline_interface_mac",
        }
    }
