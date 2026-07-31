from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.endpoint_agent_network import correlate_endpoint_agents
from app.endpoint_context_adapter import EndpointContextAdapter
from app.db import Base
from app.models import EndpointAgentNetworkLink, EndpointAgentNetworkRefresh


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


def test_endpoint_agent_cache_schema_keeps_only_safe_rendering_metadata() -> None:
    link_columns = set(EndpointAgentNetworkLink.__table__.columns.keys())
    refresh_columns = set(EndpointAgentNetworkRefresh.__table__.columns.keys())

    assert {
        "asset_key", "state", "device_id", "device_display_name",
        "gateway_last_seen_at", "baseline_collected_at", "profile_summary",
        "evidence_kind", "calculated_at",
    } <= link_columns
    assert {"id", "last_success_at", "lease_expires_at", "last_error_code"} <= refresh_columns
    assert not ({"mac", "ip", "raw_payload", "token", "error_body"} & link_columns)


def test_endpoint_adapter_projects_only_network_identity_fields_needed_for_correlation() -> None:
    class Client:
        def close(self) -> None:
            return None

        def list_agent_network_identities(self) -> list[dict[str, object]]:
            return [
                {
                    "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    "device_identifier": "agent-001",
                    "display_name": "Office workstation",
                    "last_seen_at": "2026-07-31T10:00:00Z",
                    "baseline_collected_at": "2026-07-31T09:00:00Z",
                    "profiles": [{"profile": "baseline_v1", "collected_at": "2026-07-31T09:00:00Z"}],
                    "baseline_mac_keys": ["mac-aabbccddeeff"],
                    "raw_payload": {"token": "must-not-cross"},
                }
            ]

    identities = EndpointContextAdapter(Client()).list_agent_network_identities()  # type: ignore[arg-type]

    assert identities == [
        {
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "display_name": "Office workstation",
            "last_seen_at": "2026-07-31T10:00:00Z",
            "baseline_collected_at": "2026-07-31T09:00:00Z",
            "profiles": [{"profile": "baseline_v1", "collected_at": "2026-07-31T09:00:00Z"}],
            "baseline_mac_keys": ["mac-aabbccddeeff"],
        }
    ]


def test_safe_cache_persists_confirmed_result_without_mac_or_ip() -> None:
    from app.endpoint_agent_network import cached_endpoint_agent_statuses, store_endpoint_agent_statuses

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    result = {
        "asset-a": {
            "state": "confirmed",
            "device_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "device_display_name": "Office workstation",
            "gateway_last_seen_at": "2026-07-31T10:00:00Z",
            "baseline_collected_at": "2026-07-31T09:00:00Z",
            "profiles": ["baseline_v1", "health_v1"],
            "evidence_kind": "baseline_interface_mac",
        }
    }
    with Session(engine) as db:
        store_endpoint_agent_statuses(db, result, now)
        db.commit()
        status = cached_endpoint_agent_statuses(db, now)
        link = db.get(EndpointAgentNetworkLink, "asset-a")
        refresh = db.get(EndpointAgentNetworkRefresh, 1)

    assert status == result
    assert refresh is not None
    assert refresh.last_success_at is not None
    assert refresh.last_success_at.replace(tzinfo=timezone.utc) == now
    assert link is not None
    assert "mac" not in link.__dict__
    assert "ip" not in link.__dict__


def test_refresh_lease_allows_one_refresh_and_preserves_cache_on_failure() -> None:
    from app.endpoint_agent_network import acquire_refresh_lease, mark_endpoint_agent_refresh_failed

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    with Session(engine) as db:
        assert acquire_refresh_lease(db, now) is True
        assert acquire_refresh_lease(db, now + timedelta(seconds=1)) is False
        mark_endpoint_agent_refresh_failed(db, "endpoint_platform_unavailable")
        db.commit()
        refresh = db.get(EndpointAgentNetworkRefresh, 1)

    assert refresh is not None
    assert refresh.lease_expires_at is None
    assert refresh.last_error_code == "endpoint_platform_unavailable"
