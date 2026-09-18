from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError


DEVICE_A = "11111111-1111-1111-1111-111111111111"
DEVICE_B = "22222222-2222-2222-2222-222222222222"
NOW = datetime(2026, 9, 18, 8, 0, tzinfo=timezone.utc)


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite:///{tmp_path / 'inventory-endpoint.sqlite'}"
    )

    from app.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db()
    with get_sessionmaker()() as db:
        yield db


def _asset(session, asset_id: str, asset_type):
    from app.inventory.models import InventoryAsset

    asset = InventoryAsset(id=asset_id, asset_type=asset_type)
    session.add(asset)
    session.commit()
    return asset


def _binding(*, asset_id: str, external_id: str, status, ended_at=None):
    from app.inventory.models import InventoryExternalBinding

    return InventoryExternalBinding(
        asset_id=asset_id,
        source="endpoint_platform",
        external_id=external_id,
        status=status,
        binding_method="manual",
        confidence=100,
        first_seen_at=NOW,
        last_verified_at=NOW,
        ended_at=ended_at,
        created_by="test",
    )


def test_confirmed_endpoint_binding_is_unique_per_pc_and_device(session) -> None:
    from app.inventory.models import InventoryAssetType, InventoryExternalBindingStatus

    _asset(session, "pc-1", InventoryAssetType.PC)
    _asset(session, "pc-2", InventoryAssetType.PC)
    session.add(
        _binding(
            asset_id="pc-1",
            external_id=DEVICE_A,
            status=InventoryExternalBindingStatus.CONFIRMED,
        )
    )
    session.commit()

    session.add(
        _binding(
            asset_id="pc-1",
            external_id=DEVICE_B,
            status=InventoryExternalBindingStatus.CONFIRMED,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()

    session.add(
        _binding(
            asset_id="pc-2",
            external_id=DEVICE_A,
            status=InventoryExternalBindingStatus.CONFIRMED,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()


def test_endpoint_binding_rejects_non_pc_assets(session) -> None:
    from app.inventory.models import InventoryAssetType, InventoryExternalBindingStatus

    _asset(session, "monitor-1", InventoryAssetType.MONITOR)
    session.add(
        _binding(
            asset_id="monitor-1",
            external_id=DEVICE_A,
            status=InventoryExternalBindingStatus.CANDIDATE,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_bound_pc_cannot_be_retyped_as_non_pc(session) -> None:
    from app.inventory.models import InventoryAssetType, InventoryExternalBindingStatus

    asset = _asset(session, "pc-1", InventoryAssetType.PC)
    session.add(
        _binding(
            asset_id="pc-1",
            external_id=DEVICE_A,
            status=InventoryExternalBindingStatus.CONFIRMED,
        )
    )
    session.commit()
    asset.asset_type = InventoryAssetType.MONITOR

    with pytest.raises(IntegrityError):
        session.flush()


def test_active_candidate_is_deduplicated_but_ended_history_can_be_reused(
    session,
) -> None:
    from app.inventory.models import InventoryAssetType, InventoryExternalBindingStatus

    _asset(session, "pc-1", InventoryAssetType.PC)
    original = _binding(
        asset_id="pc-1",
        external_id=DEVICE_A,
        status=InventoryExternalBindingStatus.CANDIDATE,
    )
    session.add(original)
    session.commit()

    session.add(
        _binding(
            asset_id="pc-1",
            external_id=DEVICE_A,
            status=InventoryExternalBindingStatus.CANDIDATE,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()

    original = session.get(type(original), original.id)
    original.status = InventoryExternalBindingStatus.ENDED
    original.ended_at = NOW
    session.commit()

    replacement = _binding(
        asset_id="pc-1",
        external_id=DEVICE_A,
        status=InventoryExternalBindingStatus.CANDIDATE,
    )
    session.add(replacement)
    session.flush()
    assert replacement.id != original.id


def test_endpoint_observation_source_and_state_keep_hash_freshness_separate(
    session,
) -> None:
    from app.inventory.models import (
        InventoryEndpointState,
        InventoryObservation,
        InventoryObservationSource,
    )

    assert InventoryObservationSource.ENDPOINT.value == "endpoint"
    assert {
        "baseline_semantic_hash",
        "health_semantic_hash",
        "network_semantic_hash",
        "last_checked_at",
        "safe_context_json",
    } <= set(InventoryEndpointState.__table__.columns.keys())
    assert {
        "binding_id",
        "endpoint_device_id",
        "profile",
        "snapshot_id",
        "semantic_hash",
        "collected_at",
    } <= set(InventoryObservation.__table__.columns.keys())


def test_json_payloads_default_to_independent_empty_mappings(session) -> None:
    from app.inventory.models import (
        InventoryAssetType,
        InventoryEndpointState,
        InventoryExternalBindingStatus,
    )

    _asset(session, "pc-1", InventoryAssetType.PC)
    binding = _binding(
        asset_id="pc-1",
        external_id=DEVICE_A,
        status=InventoryExternalBindingStatus.CONFIRMED,
    )
    session.add(binding)
    session.flush()
    state = InventoryEndpointState(
        binding_id=binding.id,
        asset_id="pc-1",
        endpoint_device_id=DEVICE_A,
    )
    session.add(state)
    session.flush()

    assert binding.evidence_json == {}
    assert state.safe_context_json == {}
    assert binding.evidence_json is not state.safe_context_json


def test_sync_control_is_a_singleton(session) -> None:
    from app.inventory.models import InventoryEndpointSyncControl

    session.add(InventoryEndpointSyncControl(id=1))
    session.commit()
    session.add(InventoryEndpointSyncControl(id=2))

    with pytest.raises(IntegrityError):
        session.flush()


def test_narrow_initializer_migrates_legacy_inventory_without_broad_init(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite:///{tmp_path / 'legacy-inventory.sqlite'}"
    )

    import app.db as db_module
    from app.db import get_engine, init_inventory_endpoint_schema, reset_engine_cache

    reset_engine_cache()
    with get_engine().begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE inventory_assets ("
                "id VARCHAR(36) PRIMARY KEY, asset_type VARCHAR(16) NOT NULL)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE inventory_observations ("
                "id VARCHAR(36) PRIMARY KEY, source VARCHAR(16) NOT NULL, "
                "observed_at DATETIME NOT NULL, data_json JSON NOT NULL)"
            )
        )

    monkeypatch.setattr(
        db_module, "init_db", lambda: pytest.fail("narrow initializer called init_db")
    )
    init_inventory_endpoint_schema()

    inspector = inspect(get_engine())
    assert {
        "inventory_external_bindings",
        "inventory_endpoint_state",
        "inventory_endpoint_sync_control",
    } <= set(inspector.get_table_names())
    assert "web_users" not in inspector.get_table_names()
    assert {
        "binding_id",
        "endpoint_device_id",
        "profile",
        "snapshot_id",
        "semantic_hash",
        "collected_at",
    } <= {column["name"] for column in inspector.get_columns("inventory_observations")}

    index_names = {
        index["name"] for index in inspector.get_indexes("inventory_external_bindings")
    }
    assert {
        "uq_inventory_endpoint_confirmed_asset",
        "uq_inventory_endpoint_confirmed_device",
        "uq_inventory_endpoint_active_candidate",
    } <= index_names


def test_narrow_initializer_does_not_mutate_unrelated_legacy_tables(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv(
        "DATABASE_URL", f"sqlite:///{tmp_path / 'legacy-unrelated.sqlite'}"
    )

    from app.db import get_engine, init_inventory_endpoint_schema, reset_engine_cache

    reset_engine_cache()
    with get_engine().begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE web_users ("
                "id INTEGER PRIMARY KEY, is_admin BOOLEAN NOT NULL)"
            )
        )
        connection.execute(text("INSERT INTO web_users (id, is_admin) VALUES (1, 1)"))
        connection.execute(
            text(
                "CREATE TABLE inventory_assets ("
                "id VARCHAR(36) PRIMARY KEY, asset_type VARCHAR(16) NOT NULL, "
                "notes TEXT, description TEXT)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO inventory_assets "
                "(id, asset_type, notes, description) "
                "VALUES ('pc-1', 'PC', 'leave untouched', NULL)"
            )
        )
        connection.execute(
            text("CREATE TABLE inventory_printer_details (asset_id VARCHAR(36) PRIMARY KEY)")
        )
        connection.execute(
            text("CREATE TABLE inventory_pc_details (asset_id VARCHAR(36) PRIMARY KEY)")
        )
        connection.execute(
            text(
                "CREATE TABLE inventory_observations ("
                "id VARCHAR(36) PRIMARY KEY, source VARCHAR(16) NOT NULL, "
                "observed_at DATETIME NOT NULL, data_json JSON NOT NULL)"
            )
        )

    init_inventory_endpoint_schema()

    inspector = inspect(get_engine())
    assert "is_network_admin" not in {
        column["name"] for column in inspector.get_columns("web_users")
    }
    assert "connection_type" not in {
        column["name"]
        for column in inspector.get_columns("inventory_printer_details")
    }
    assert "os_version" not in {
        column["name"] for column in inspector.get_columns("inventory_pc_details")
    }
    with get_engine().connect() as connection:
        row = connection.execute(
            text("SELECT notes, description FROM inventory_assets WHERE id = 'pc-1'")
        ).one()
    assert row == ("leave untouched", None)


def test_endpoint_datetimes_round_trip_as_utc_aware(session) -> None:
    from app.inventory.models import (
        InventoryAssetType,
        InventoryEndpointState,
        InventoryEndpointSyncControl,
        InventoryExternalBindingStatus,
        InventoryObservation,
        InventoryObservationSource,
    )

    source_time = datetime(
        2026, 9, 18, 13, 30, 45, tzinfo=timezone(timedelta(hours=5))
    )
    expected_utc = datetime(2026, 9, 18, 8, 30, 45, tzinfo=timezone.utc)
    _asset(session, "pc-1", InventoryAssetType.PC)
    binding = _binding(
        asset_id="pc-1",
        external_id=DEVICE_A,
        status=InventoryExternalBindingStatus.ENDED,
        ended_at=source_time,
    )
    binding.first_seen_at = source_time
    binding.last_verified_at = source_time
    session.add(binding)
    session.flush()
    state = InventoryEndpointState(
        binding_id=binding.id,
        asset_id="pc-1",
        endpoint_device_id=DEVICE_A,
        last_seen_at=source_time,
        last_checked_at=source_time,
        refreshed_at=source_time,
        last_success_at=source_time,
        unavailable_since=source_time,
    )
    control = InventoryEndpointSyncControl(
        id=1,
        lease_expires_at=source_time,
        last_presence_sync_at=source_time,
        last_full_sync_at=source_time,
        last_reconciliation_requested_at=source_time,
    )
    observation = InventoryObservation(
        asset_id="pc-1",
        source=InventoryObservationSource.ENDPOINT,
        observed_at=source_time,
        binding_id=binding.id,
        endpoint_device_id=DEVICE_A,
        profile="baseline_v1",
        collected_at=source_time,
    )
    session.add_all((state, control, observation))
    session.commit()

    binding_id = binding.id
    observation_id = observation.id
    session.expunge_all()
    binding = session.get(type(binding), binding_id)
    state = session.get(InventoryEndpointState, binding_id)
    control = session.get(InventoryEndpointSyncControl, 1)
    observation = session.get(InventoryObservation, observation_id)

    persisted_values = (
        binding.first_seen_at,
        binding.last_verified_at,
        binding.ended_at,
        binding.created_at,
        binding.updated_at,
        state.last_seen_at,
        state.last_checked_at,
        state.refreshed_at,
        state.last_success_at,
        state.unavailable_since,
        state.created_at,
        state.updated_at,
        control.lease_expires_at,
        control.last_presence_sync_at,
        control.last_full_sync_at,
        control.last_reconciliation_requested_at,
        control.created_at,
        control.updated_at,
        observation.collected_at,
    )
    assert all(value.tzinfo is not None for value in persisted_values)
    assert all(value.utcoffset() == timedelta(0) for value in persisted_values)
    assert binding.first_seen_at == expected_utc
    assert binding.ended_at == expected_utc
    assert state.last_checked_at == expected_utc
    assert control.lease_expires_at == expected_utc
    assert observation.collected_at == expected_utc
