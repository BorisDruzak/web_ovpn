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


def test_inventory_and_session_profiles_update_typed_endpoint_state(session):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    class InventoryAdapter(Adapter):
        def read_profiles(self, device_id):
            profiles = super().read_profiles(device_id)
            profiles["inventory_v1"] = {
                "id": "inventory-1",
                "profile": "inventory_v1",
                "semantic_hash": "i" * 64,
                "collected_at": NOW.isoformat(),
                "sections": {
                    "system": {
                        "hostname": "pc-1",
                        "platform": "windows",
                        "os_name": "Windows 11 Pro",
                        "os_version": "24H2",
                        "os_build": "26100",
                    },
                    "hardware": {
                        "manufacturer": "Contoso",
                        "model": "Workstation",
                        "serial_number": "ABC123",
                        "product_uuid": "11111111-1111-4111-8111-111111111111",
                        "cpu_model": "CPU",
                    },
                    "memory": {
                        "total_bytes": 17179869184,
                        "memory_type": "DDR5",
                        "module_count": 2,
                        "modules": [],
                    },
                    "storage": {
                        "physical_devices": [
                            {
                                "stable_key": "disk-1",
                                "model": "SSD",
                                "size_bytes": 536870912000,
                                "media_type": "SSD",
                                "bus_type": "NVME",
                            }
                        ]
                    },
                    "interfaces": [],
                    "raw": "DO-NOT-PERSIST",
                },
            }
            profiles["session_v1"] = {
                "id": "session-1",
                "profile": "session_v1",
                "semantic_hash": "s" * 64,
                "collected_at": NOW.isoformat(),
                "sections": {
                    "current_user_login": "operator",
                    "interactive_session_present": True,
                    "token": "DO-NOT-PERSIST",
                },
            }
            return profiles

    pc(session)
    sync_confirmed_bindings(session, InventoryAdapter(), NOW)

    state = session.scalar(select(InventoryEndpointState))
    assert state.inventory_snapshot_id == "inventory-1"
    assert state.inventory_semantic_hash == "i" * 64
    assert state.session_snapshot_id == "session-1"
    assert state.session_semantic_hash == "s" * 64
    assert state.safe_context_json["hostname"] == "pc-1"
    assert state.safe_context_json["ram_type"] == "DDR5"
    assert state.safe_context_json["current_user"] == "operator"
    assert state.safe_context_json["storage_gb"] == 500
    assert "DO-NOT-PERSIST" not in str(state.safe_context_json)
    assert {row.profile for row in observations(session)} == {
        "baseline_v1", "inventory_v1", "session_v1"
    }


def test_inventory_profile_wins_effective_freshness_over_stale_baseline(session):
    from app.inventory.endpoint import InventoryEndpointService
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    class InventoryAdapter(Adapter):
        def read_profiles(self, device_id):
            profiles = super().read_profiles(device_id)
            profiles["baseline_v1"]["collected_at"] = (
                NOW - timedelta(minutes=11)
            ).isoformat()
            profiles["inventory_v1"] = {
                "id": "inventory-1",
                "profile": "inventory_v1",
                "semantic_hash": "i" * 64,
                "collected_at": NOW.isoformat(),
                "sections": {
                    "system": {"platform": "windows"},
                    "hardware": {"cpu_model": "Fresh CPU"},
                    "memory": {"total_bytes": 17179869184, "module_count": 0, "modules": []},
                    "storage": {"physical_devices": []},
                    "interfaces": [],
                },
            }
            profiles["session_v1"] = None
            return profiles

    asset = pc(session)
    sync_confirmed_bindings(session, InventoryAdapter(), NOW)

    context = InventoryEndpointService().asset_context(session, asset.id, NOW)
    assert context["effective"]["cpu_model"] == {
        "value": "Fresh CPU",
        "source": "endpoint",
        "observed_at": NOW.isoformat(),
        "freshness": "fresh",
    }


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


def test_stopped_worker_cache_ages_without_another_write(session):
    from app.endpoint_agent_network import endpoint_agent_refresh_status, cached_endpoint_agent_statuses
    from app.inventory.endpoint_sync import sync_confirmed_bindings, rebuild_endpoint_agent_network_cache

    pc(session)
    sync_confirmed_bindings(session, Adapter(), NOW)
    rebuild_endpoint_agent_network_cache(session, NOW)
    assert endpoint_agent_refresh_status(session, NOW)["state"] == "ready"
    later = NOW + timedelta(minutes=11)
    assert endpoint_agent_refresh_status(session, later)["state"] == "stale"
    assert cached_endpoint_agent_statuses(session, later)["mac:" + MAC]["state"] == "stale"
    assert session.get(EndpointAgentNetworkLink, "mac:" + MAC).state == "confirmed"


@pytest.mark.parametrize("action", ["detach", "replace"])
def test_ended_binding_masks_cached_device_link_without_worker_rebuild(session, action):
    from app.endpoint_agent_network import cached_endpoint_agent_statuses
    from app.inventory.endpoint_sync import sync_confirmed_bindings, rebuild_endpoint_agent_network_cache

    asset = pc(session)
    sync_confirmed_bindings(session, Adapter(), NOW)
    rebuild_endpoint_agent_network_cache(session, NOW)
    binding = session.scalar(select(InventoryExternalBinding))
    service = InventoryEndpointService()
    if action == "detach":
        service.detach_binding(session, asset.id, binding.id, "operator", NOW)
    else:
        service.replace_binding(session, asset.id, binding.id, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "operator", NOW)
    assert "mac:" + MAC not in cached_endpoint_agent_statuses(session, NOW)
    assert session.get(EndpointAgentNetworkLink, "mac:" + MAC).device_id == DEVICE
    assert session.get(InventoryEndpointState, binding.id) is not None


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


@pytest.mark.parametrize("missing", ["absent", "hashless"])
def test_context_exposes_retained_profile_as_unavailable_without_new_success(
    session, missing
):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    asset = pc(session)
    adapter = Adapter()
    sync_confirmed_bindings(session, adapter, NOW)
    if missing == "absent":
        adapter.absent = True
    else:
        adapter.hash = None
    later = NOW + timedelta(minutes=5)
    sync_confirmed_bindings(session, adapter, later)
    context = InventoryEndpointService().asset_context(session, asset.id, later)
    assert context["effective"]["ram_gb"]["value"] == 16
    assert context["effective"]["ram_gb"]["observed_at"] == NOW.isoformat()
    assert context["effective"]["ram_gb"]["freshness"] == "unavailable"
    fresh = context["freshness"]["endpoint"]
    assert fresh["status"] == "unavailable"
    assert fresh["last_success_at"] == NOW.isoformat()
    assert fresh["profiles"]["baseline_v1"] == {
        "status": "unavailable",
        "collected_at": NOW.isoformat(),
        "last_checked_at": later.isoformat(),
        "last_success_at": NOW.isoformat(),
    }


def test_presence_does_not_advance_technical_success_and_old_collections_stay_stale(
    session,
):
    from app.inventory.endpoint_sync import sync_confirmed_bindings

    asset = pc(session)
    sync_confirmed_bindings(session, Adapter(), NOW)
    sync_confirmed_bindings(session, Adapter(), NOW + timedelta(minutes=1))
    context = InventoryEndpointService().asset_context(
        session, asset.id, NOW + timedelta(minutes=1)
    )
    assert context["freshness"]["endpoint"]["last_success_at"] == NOW.isoformat()
    later = NOW + timedelta(hours=1)
    sync_confirmed_bindings(session, Adapter(), later)
    context = InventoryEndpointService().asset_context(session, asset.id, later)
    assert context["freshness"]["endpoint"]["status"] == "stale"
    assert (
        context["freshness"]["endpoint"]["profiles"]["baseline_v1"]["status"] == "stale"
    )
    assert context["effective"]["ram_gb"]["freshness"] == "stale"


@pytest.mark.parametrize("missing", ["identity", "profile", "old_collection"])
def test_worker_keeps_stale_binding_cache_but_withholds_netctl_classification(
    session, monkeypatch, missing
):
    import json
    from app.inventory import endpoint_sync as worker

    pc(session)
    worker.sync_confirmed_bindings(session, Adapter(), NOW)
    session.commit()

    class DegradedAdapter(Adapter):
        def list_agent_network_identities(self):
            return (
                [] if missing == "identity" else super().list_agent_network_identities()
            )

        def read_profiles(self, device_id):
            self.absent = missing == "profile"
            return super().read_profiles(device_id)

    adapter = DegradedAdapter()
    calls = []
    monkeypatch.setattr(worker, "get_endpoint_context_adapter", lambda: adapter)
    monkeypatch.setattr(
        worker, "run_netctl", lambda args, timeout: calls.append(args) or {}
    )
    later = NOW + (
        timedelta(hours=1) if missing == "old_collection" else timedelta(minutes=5)
    )
    assert worker.run_inventory_endpoint_sync(later) == 0
    session.expire_all()
    cache = session.get(EndpointAgentNetworkLink, "mac:" + MAC)
    assert cache.device_id == DEVICE
    assert cache.state == "stale"
    assert json.loads(calls[0][3]) == [{"asset_key": "mac:" + MAC, "state": "no_agent"}]
    assert session.scalar(select(InventoryExternalBinding)).ended_at is None


def test_valid_snapshot_completed_during_remote_reads_uses_completion_clock(
    session, monkeypatch
):
    from app.inventory import endpoint_sync as worker

    asset = pc(session)
    asset_id = asset.id
    session.commit()
    clock_time = [NOW]

    class CompletingAdapter(Adapter):
        def read_profiles(self, device_id):
            profiles = super().read_profiles(device_id)
            profiles["baseline_v1"]["collected_at"] = (
                NOW + timedelta(seconds=2)
            ).isoformat()
            clock_time[0] = NOW + timedelta(seconds=3)
            return profiles

    monkeypatch.setattr(worker, "get_endpoint_context_adapter", CompletingAdapter)
    monkeypatch.setattr(worker, "run_netctl", lambda *args, **kwargs: {})
    assert worker.run_inventory_endpoint_sync(NOW, clock=lambda: clock_time[0]) == 0
    session.expire_all()
    context = InventoryEndpointService().asset_context(session, asset_id, clock_time[0])
    assert (
        context["effective"]["ram_gb"]["observed_at"]
        == (NOW + timedelta(seconds=2)).isoformat()
    )
    assert (
        context["freshness"]["endpoint"]["last_success_at"] == clock_time[0].isoformat()
    )


def test_advancing_clock_keeps_healthy_cache_and_netctl_classification(
    session, monkeypatch
):
    import json
    from app.inventory import endpoint_sync as worker

    pc(session)
    session.commit()
    ticks = [0]

    def advancing_clock():
        ticks[0] += 1
        return NOW + timedelta(milliseconds=ticks[0])

    calls = []
    monkeypatch.setattr(worker, "get_endpoint_context_adapter", Adapter)
    monkeypatch.setattr(
        worker, "run_netctl", lambda args, timeout: calls.append(args) or {}
    )
    assert worker.run_inventory_endpoint_sync(NOW, clock=advancing_clock) == 0
    session.expire_all()
    assert session.get(EndpointAgentNetworkLink, "mac:" + MAC).state == "confirmed"
    assert json.loads(calls[0][3]) == [
        {
            "asset_key": "mac:" + MAC,
            "state": "confirmed",
            "device_type": "pc",
            "os_family": "windows",
        }
    ]


@pytest.mark.parametrize(
    "sections", [{}, {"hardware": {"cpu_model": "Replacement CPU"}}]
)
def test_partial_baseline_does_not_retimestamp_omitted_fields_or_republish_old_os(
    session, monkeypatch, sections
):
    import json
    from app.inventory import endpoint_sync as worker

    asset = pc(session)
    asset_id = asset.id
    InventoryService().update_details(session, asset, {"ram_gb": 8})
    worker.sync_confirmed_bindings(session, Adapter(), NOW)
    session.commit()
    later = NOW + timedelta(minutes=5)

    class PartialAdapter(Adapter):
        def read_profiles(self, device_id):
            profiles = super().read_profiles(device_id)
            profiles["baseline_v1"].update(
                sections=sections,
                semantic_hash="d" * 64,
                collected_at=later.isoformat(),
                id="partial-baseline",
            )
            return profiles

    calls = []
    monkeypatch.setattr(worker, "get_endpoint_context_adapter", PartialAdapter)
    monkeypatch.setattr(
        worker, "run_netctl", lambda args, timeout: calls.append(args) or {}
    )
    assert worker.run_inventory_endpoint_sync(later) == 0
    session.expire_all()
    context = InventoryEndpointService().asset_context(session, asset_id, later)
    assert context["effective"]["ram_gb"]["value"] == 8
    assert context["effective"]["ram_gb"]["source"] == "manual"
    assert "ram_gb" not in context["sources"]["endpoint"]
    assert "os_name" not in context["sources"]["endpoint"]
    assert "storage_gb" not in context["sources"]["endpoint"]
    if sections:
        assert context["effective"]["cpu_model"]["value"] == "Replacement CPU"
        assert context["effective"]["cpu_model"]["observed_at"] == later.isoformat()
    assert session.get(EndpointAgentNetworkLink, "mac:" + MAC).device_id == DEVICE
    assert json.loads(calls[0][3]) == [
        {"asset_key": "mac:" + MAC, "state": "confirmed", "device_type": "pc"}
    ]
    assert any(row.data_json.get("ram_gb") == 16 for row in observations(session))
