from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy import select

from app.inventory.endpoint import InventoryEndpointService
from app.inventory.models import (
    InventoryAssetType,
    InventoryEndpointState,
    InventoryEndpointSyncControl,
    InventoryExternalBinding,
    InventoryObservation,
    InventoryObservationSource,
)
from app.inventory.service import InventoryService
from app.models import EndpointAgentNetworkLink
from app.endpoint_platform_client import (
    EndpointPlatformServiceDisabled,
    EndpointPlatformServiceScopeDenied,
    EndpointPlatformServiceUnavailable,
)

NOW = datetime(2026, 9, 18, 8, tzinfo=timezone.utc)
DEVICE = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'worker.sqlite'}")
    from app.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db()
    with get_sessionmaker()() as db:
        yield db


def pc(db):
    service = InventoryService()
    asset = service.create_asset(db, InventoryAssetType.PC)
    service.sync_identifiers(db, asset, [{"identifier_type": "mac", "value": MAC}])
    return asset


class Adapter:
    def __init__(self):
        self.hash = "a" * 64
        self.reads = 0
        self.absent = False
        self.error = None

    def list_agent_network_identities(self):
        if self.error:
            raise self.error
        return [
            {
                "id": DEVICE,
                "baseline_mac_keys": ["mac-aabbccddee01"],
                "baseline_collected_at": NOW.isoformat(),
                "last_seen_at": NOW.isoformat(),
                "profiles": [
                    {"profile": "baseline_v1", "collected_at": NOW.isoformat()}
                ],
            }
        ]

    def read_profiles(self, device_id):
        assert device_id == UUID(DEVICE)
        self.reads += 1
        if self.error:
            raise self.error
        return {
            "baseline_v1": None
            if self.absent
            else {
                "id": "snapshot-1",
                "profile": "baseline_v1",
                "semantic_hash": self.hash,
                "collected_at": NOW.isoformat(),
                "sections": {
                    "system": {"platform": "windows", "distribution": "Windows 11"},
                    "hardware": {"cpu_model": "CPU", "memory_bytes": 17179869184},
                    "storage": [{"size_bytes": 536870912000}],
                    "token": "DO-NOT-PERSIST",
                },
            },
            "health_v1": None,
            "network_v1": None,
        }

    def close(self):
        pass


def observations(db):
    return db.scalars(
        select(InventoryObservation).where(
            InventoryObservation.source == InventoryObservationSource.ENDPOINT
        )
    ).all()


def test_same_hash_updates_freshness_without_second_observation(session):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    asset = pc(session)
    adapter = Adapter()
    sync_confirmed_bindings(session, adapter, NOW)
    sync_confirmed_bindings(session, adapter, NOW + timedelta(minutes=5))
    binding = session.scalar(select(InventoryExternalBinding))
    state = session.get(InventoryEndpointState, binding.id)
    assert len(observations(session)) == 1
    assert state.last_checked_at == NOW + timedelta(minutes=5)
    assert state.safe_context_json["ram_gb"] == 16
    assert state.safe_context_json["storage_gb"] == 500
    assert "DO-NOT-PERSIST" not in str(state.safe_context_json)
    assert InventoryService().details_for(session, asset)["ram_gb"] is None
    adapter.hash = "b" * 64
    sync_confirmed_bindings(session, adapter, NOW + timedelta(minutes=10))
    assert len(observations(session)) == 2


def test_presence_pass_is_minutely_and_profiles_are_five_minutely(session):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    pc(session)
    adapter = Adapter()
    sync_confirmed_bindings(session, adapter, NOW)
    sync_confirmed_bindings(session, adapter, NOW + timedelta(minutes=1))
    assert adapter.reads == 1
    control = session.get(InventoryEndpointSyncControl, 1)
    assert control.last_presence_sync_at == NOW + timedelta(minutes=1)
    assert control.last_full_sync_at == NOW
    sync_confirmed_bindings(session, adapter, NOW + timedelta(minutes=5))
    assert adapter.reads == 2


def test_missing_profile_preserves_previous_state_and_reports_absence(session):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    pc(session)
    adapter = Adapter()
    sync_confirmed_bindings(session, adapter, NOW)
    adapter.absent = True
    sync_confirmed_bindings(session, adapter, NOW + timedelta(minutes=5))
    state = session.scalar(select(InventoryEndpointState))
    assert state.safe_context_json["ram_gb"] == 16
    assert state.safe_context_json["profile_status"]["baseline_v1"] == "unavailable"
    assert len(observations(session)) == 1


def test_atomic_lease_excludes_other_sessions_and_recent_success(session):
    from app.db import get_sessionmaker
    from app.inventory.endpoint_sync import acquire_endpoint_sync_lease

    assert acquire_endpoint_sync_lease(session, NOW)
    session.commit()
    with get_sessionmaker()() as other:
        assert not acquire_endpoint_sync_lease(other, NOW + timedelta(seconds=1))
    control = session.get(InventoryEndpointSyncControl, 1)
    control.lease_expires_at = None
    control.last_presence_sync_at = NOW
    session.commit()
    assert not acquire_endpoint_sync_lease(session, NOW + timedelta(seconds=59))
    assert acquire_endpoint_sync_lease(session, NOW + timedelta(minutes=1))


@pytest.mark.parametrize(
    "error,code",
    [
        (EndpointPlatformServiceDisabled(), "endpoint_platform_disabled"),
        (EndpointPlatformServiceScopeDenied(), "endpoint_platform_scope_denied"),
        (EndpointPlatformServiceUnavailable(), "endpoint_platform_unavailable"),
    ],
)
def test_worker_failure_preserves_binding_state_and_cache(
    session, monkeypatch, error, code
):
    from app.inventory import endpoint_sync as worker

    pc(session)
    adapter = Adapter()
    worker.sync_confirmed_bindings(session, adapter, NOW)
    worker.rebuild_endpoint_agent_network_cache(session, NOW)
    session.commit()
    original = dict(session.scalar(select(InventoryEndpointState)).safe_context_json)
    adapter.error = error
    monkeypatch.setattr(worker, "get_endpoint_context_adapter", lambda: adapter)
    assert worker.run_inventory_endpoint_sync(NOW + timedelta(minutes=5)) == 1
    session.expire_all()
    state = session.scalar(select(InventoryEndpointState))
    assert state.safe_context_json == original
    assert state.unavailable_since == NOW + timedelta(minutes=5)
    assert session.scalar(select(InventoryExternalBinding)).ended_at is None
    assert session.get(EndpointAgentNetworkLink, "mac:" + MAC).device_id == DEVICE
    control = session.get(InventoryEndpointSyncControl, 1)
    assert control.last_safe_error_code == code
    assert control.lease_expires_at is None


def test_worker_only_sends_bounded_fingerprint_evidence(session, monkeypatch):
    import json
    from app.inventory import endpoint_sync as worker

    asset = pc(session)
    asset.assigned_person_name = "PRIVATE"
    session.commit()
    calls = []
    monkeypatch.setattr(worker, "get_endpoint_context_adapter", Adapter)
    monkeypatch.setattr(
        worker, "run_netctl", lambda args, timeout: calls.append(args) or {}
    )
    assert worker.run_inventory_endpoint_sync(NOW) == 0
    assert json.loads(calls[0][3]) == [
        {
            "asset_key": "mac:" + MAC,
            "state": "confirmed",
            "os_family": "windows",
            "device_type": "pc",
        }
    ]


def test_cache_is_derived_from_confirmed_bindings_and_duplicate_mac_is_excluded(
    session,
):
    from app.inventory.endpoint_sync import (
        sync_confirmed_bindings,
        rebuild_endpoint_agent_network_cache,
    )

    asset = pc(session)
    sync_confirmed_bindings(session, Adapter(), NOW)
    rebuild_endpoint_agent_network_cache(session, NOW)
    assert session.get(EndpointAgentNetworkLink, "mac:" + MAC).device_id == DEVICE
    pc(session)
    rebuild_endpoint_agent_network_cache(session, NOW)
    assert session.scalar(select(EndpointAgentNetworkLink)) is None
    assert (
        InventoryEndpointService().lookup_confirmed_endpoint(session, DEVICE).id
        == asset.id
    )


def test_render_context_and_legacy_refresh_do_not_use_remote_adapter(
    session, monkeypatch
):
    import app.endpoint_agent_network as network
    import app.endpoint_context_adapter as boundary

    asset = pc(session)
    monkeypatch.setattr(
        boundary, "get_endpoint_context_adapter", lambda: pytest.fail("remote render")
    )
    network.refresh_endpoint_agent_network([])
    assert (
        InventoryEndpointService().asset_context(session, asset.id, NOW)["binding"]
        is None
    )


def test_network_projection_only_persists_valid_card_safe_ipv4(session):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    pc(session)

    class NetworkAdapter(Adapter):
        def read_profiles(self, device_id):
            profiles = super().read_profiles(device_id)
            profiles["network_v1"] = {
                "id": "network-1",
                "profile": "network_v1",
                "semantic_hash": "c" * 64,
                "collected_at": NOW.isoformat(),
                "sections": {
                    "interfaces": [
                        {"name": "loopback", "addresses": ["127.0.0.1/8"]},
                        {"name": "Ethernet", "addresses": ["TOKEN", "192.0.2.5/24"]},
                    ],
                    "default_route": {"gateway": "PRIVATE-ROUTE"},
                },
            }
            return profiles

    sync_confirmed_bindings(session, NetworkAdapter(), NOW)
    state = session.scalar(select(InventoryEndpointState))
    assert state.safe_context_json["ip"] == "192.0.2.5"
    assert "TOKEN" not in str(state.safe_context_json)
    assert "PRIVATE-ROUTE" not in str(state.safe_context_json)


def test_hashless_optional_snapshot_is_unavailable_without_losing_baseline(session):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    pc(session)

    class HashlessAdapter(Adapter):
        def read_profiles(self, device_id):
            profiles = super().read_profiles(device_id)
            profiles["health_v1"] = {
                "id": "health-1",
                "profile": "health_v1",
                "semantic_hash": None,
                "collected_at": NOW.isoformat(),
                "sections": {},
            }
            return profiles

    sync_confirmed_bindings(session, HashlessAdapter(), NOW)
    state = session.scalar(select(InventoryEndpointState))
    assert state.safe_context_json["ram_gb"] == 16
    assert state.safe_context_json["profile_status"]["health_v1"] == "unavailable"


def test_midpass_scope_denial_rolls_back_discovery_and_observations(
    session, monkeypatch
):
    from app.inventory import endpoint_sync as worker

    pc(session)
    session.commit()

    class DeniedAdapter(Adapter):
        def read_profiles(self, device_id):
            raise EndpointPlatformServiceScopeDenied()

    monkeypatch.setattr(worker, "get_endpoint_context_adapter", DeniedAdapter)
    assert worker.run_inventory_endpoint_sync(NOW) == 1
    session.expire_all()
    assert session.scalar(select(InventoryExternalBinding)) is None
    assert observations(session) == []


def test_leased_worker_exits_without_upstream_or_netctl_calls(session, monkeypatch):
    from app.inventory import endpoint_sync as worker

    assert worker.acquire_endpoint_sync_lease(session, NOW)
    session.commit()
    monkeypatch.setattr(
        worker, "get_endpoint_context_adapter", lambda: pytest.fail("lease ignored")
    )
    assert worker.run_inventory_endpoint_sync(NOW + timedelta(seconds=1)) == 0


def test_remote_wait_does_not_hold_database_write_lock(session, monkeypatch):
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryAsset
    from app.inventory import endpoint_sync as worker

    asset = pc(session)
    asset_id = asset.id
    session.commit()

    class ConcurrentAdapter(Adapter):
        def read_profiles(self, device_id):
            with get_sessionmaker()() as manual:
                manual.get(
                    InventoryAsset, asset_id
                ).custom_name = "Manual edit during remote wait"
                manual.commit()
            return super().read_profiles(device_id)

    monkeypatch.setattr(worker, "get_endpoint_context_adapter", ConcurrentAdapter)
    monkeypatch.setattr(worker, "run_netctl", lambda *args, **kwargs: {})
    assert worker.run_inventory_endpoint_sync(NOW) == 0
    session.expire_all()
    assert (
        session.get(InventoryAsset, asset_id).custom_name
        == "Manual edit during remote wait"
    )
