from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.inventory.models import (
    InventoryAssetIdentifier,
    InventoryAssetType,
    InventoryIdentifierType,
    InventoryObservationSource,
)
from app.inventory.service import InventoryService


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory.sqlite'}")
    from app.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db()
    with get_sessionmaker()() as session:
        yield session


@pytest.fixture
def service() -> InventoryService:
    return InventoryService()


def _asset_with_identifiers(db, service, *, mac: str, ip: str | None = None):
    asset = service.create_asset(db, InventoryAssetType.PC)
    identifiers = [{"identifier_type": "mac", "value": mac}]
    if ip is not None:
        identifiers.append({"identifier_type": "ip", "value": ip})
    service.sync_identifiers(db, asset, identifiers)
    return asset


def _current_values(db, asset_id: str) -> dict[str, str]:
    rows = db.scalars(
        select(InventoryAssetIdentifier).where(
            InventoryAssetIdentifier.asset_id == asset_id,
            InventoryAssetIdentifier.is_current.is_(True),
        )
    )
    return {row.identifier_type.value: row.value for row in rows}


def test_reconcile_updates_ip_and_hostname_but_not_mac(db, service):
    """Removing MAC anchoring or replacing all identifiers must fail this test."""
    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")

    result = service.reconcile_netctl_identifiers(
        db,
        [{"mac": "aa-bb-cc-dd-ee-ff", "ip": "192.168.100.20", "hostname": "pc-01"}],
        observed_at=datetime(2026, 9, 18, tzinfo=UTC),
    )

    assert result.matched_assets == 1
    assert result.updated_assets == 1
    assert result.skipped_assets == 0
    assert _current_values(db, asset.id) == {
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.168.100.20",
        "hostname": "pc-01",
    }


def test_reconcile_preserves_current_values_when_observation_omits_them(db, service):
    """Clearing a current identifier when Netctl omits it is a data-loss bug."""
    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")
    service.sync_identifiers(
        db,
        asset,
        [
            {"identifier_type": "mac", "value": "AA:BB:CC:DD:EE:FF"},
            {"identifier_type": "ip", "value": "192.168.100.10"},
            {"identifier_type": "hostname", "value": "pc-old"},
        ],
    )

    result = service.reconcile_netctl_identifiers(
        db,
        [{"mac": "AA:BB:CC:DD:EE:FF"}],
        observed_at=datetime(2026, 9, 18, tzinfo=UTC),
    )

    assert result.matched_assets == 1
    assert result.updated_assets == 0
    assert _current_values(db, asset.id) == {
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.168.100.10",
        "hostname": "pc-old",
    }


def test_reconcile_skips_invalid_or_ambiguous_macs(db, service):
    """Matching malformed or non-unique MACs can transfer identity between cards."""
    first = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF")
    second = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF")
    unique = _asset_with_identifiers(db, service, mac="11:22:33:44:55:66")

    result = service.reconcile_netctl_identifiers(
        db,
        [
            {"mac": "not-a-mac", "ip": "192.168.100.20"},
            {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.21"},
            {"mac": "11:22:33:44:55:66", "ip": "192.168.100.22"},
            {"mac": "11-22-33-44-55-66", "ip": "192.168.100.23"},
        ],
        observed_at=datetime(2026, 9, 18, tzinfo=UTC),
    )

    assert result.matched_assets == 0
    assert result.updated_assets == 0
    assert result.skipped_assets == 3
    assert _current_values(db, first.id) == {"mac": "AA:BB:CC:DD:EE:FF"}
    assert _current_values(db, second.id) == {"mac": "AA:BB:CC:DD:EE:FF"}
    assert _current_values(db, unique.id) == {"mac": "11:22:33:44:55:66"}


def test_reconcile_marks_manual_ip_historical_before_netctl_replacement(db, service):
    """Overwriting manual values in place would destroy the required identifier history."""
    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")

    service.reconcile_netctl_identifiers(
        db,
        [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.20"}],
        observed_at=datetime(2026, 9, 18, tzinfo=UTC),
    )

    ip_history = list(
        db.scalars(
            select(InventoryAssetIdentifier).where(
                InventoryAssetIdentifier.asset_id == asset.id,
                InventoryAssetIdentifier.identifier_type == InventoryIdentifierType.IP,
            )
        )
    )
    assert {(row.value, row.is_current, row.source) for row in ip_history} == {
        ("192.168.100.10", False, InventoryObservationSource.MANUAL),
        ("192.168.100.20", True, InventoryObservationSource.NETCTL),
    }
