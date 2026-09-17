from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.inventory.models import (
    InventoryAssetIdentifier,
    InventoryAssetType,
    InventoryIdentifierType,
    InventoryObservationSource,
)
from app.inventory.service import InventoryService


def _snapshot_page(
    *,
    snapshot_id: int = 7,
    generated_at: str = "2026-09-18T10:00:00Z",
    stale: bool = False,
    page: int = 1,
    pages: int = 1,
    limit: int = 250,
    total: int | None = None,
    hosts: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    page_hosts = hosts or []
    return {
        "snapshot": {
            "snapshot_id": snapshot_id,
            "generated_at": generated_at,
            "stale": stale,
        },
        "hosts": page_hosts,
        "pagination": {"page": page, "limit": limit, "total": len(page_hosts) if total is None else total, "pages": pages},
    }


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


def test_reconcile_skips_duplicate_current_mac_rows_on_one_asset(db, service):
    """Collapsing duplicate anchor rows to one asset can overwrite its identifiers."""
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
    db.add(
        InventoryAssetIdentifier(
            asset_id=asset.id,
            identifier_type=InventoryIdentifierType.MAC,
            value="AA-BB-CC-DD-EE-FF",
            normalized_value="AA:BB:CC:DD:EE:FF",
            source=InventoryObservationSource.MANUAL,
        )
    )
    db.flush()

    result = service.reconcile_netctl_identifiers(
        db,
        [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.20", "hostname": "pc-new"}],
        observed_at=datetime(2026, 9, 18, tzinfo=UTC),
    )

    assert result.matched_assets == 0
    assert result.updated_assets == 0
    assert result.skipped_assets == 1
    current = _current_values(db, asset.id)
    current_mac_rows = list(
        db.scalars(
            select(InventoryAssetIdentifier).where(
                InventoryAssetIdentifier.asset_id == asset.id,
                InventoryAssetIdentifier.identifier_type == InventoryIdentifierType.MAC,
                InventoryAssetIdentifier.is_current.is_(True),
            )
        )
    )
    assert current["ip"] == "192.168.100.10"
    assert current["hostname"] == "pc-old"
    assert len(current_mac_rows) == 2


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


def test_worker_pages_one_current_snapshot(db):
    """Changing page arguments or accepting mixed snapshots must fail this test."""
    from app.inventory.netctl_sync import synchronize_current_snapshot

    calls = []

    def fake_netctl(args, timeout=None):
        assert not set(args) & {"collect", "refresh", "nmap", "snmp", "availability"}
        calls.append(args)
        return _snapshot_page(page=int(args[-3]), pages=2, total=500, hosts=[{}] * 250)

    summary = synchronize_current_snapshot(netctl_call=fake_netctl, session_factory=lambda: db)

    assert summary.status == "success"
    assert calls == [
        ["hosts", "list", "--status=current", "--page", "1", "--limit", "250"],
        ["hosts", "list", "--status=current", "--page", "2", "--limit", "250"],
    ]


@pytest.mark.parametrize(
    "page",
    [
        _snapshot_page(stale=True, pages=0, total=0),
        _snapshot_page(generated_at="2026-09-18T10:00:00"),
        {"snapshot": {"snapshot_id": 7, "generated_at": "2026-09-18T10:00:00Z", "stale": False}, "hosts": [], "pagination": {"page": 1}},
    ],
)
def test_worker_rejects_stale_or_malformed_snapshot_without_identifier_changes(db, service, page):
    """A stale or structurally incomplete publication must never reach reconciliation."""
    from app.inventory.netctl_sync import synchronize_current_snapshot
    from app.inventory.models import InventoryIdentifierSyncRun

    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")
    db.commit()
    summary = synchronize_current_snapshot(netctl_call=lambda args, timeout=None: page, session_factory=lambda: db)

    expected_status = "skipped" if page.get("snapshot", {}).get("stale") else "failed"
    assert summary.status == expected_status
    assert _current_values(db, asset.id) == {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.10"}
    ledger = db.scalar(select(InventoryIdentifierSyncRun).order_by(InventoryIdentifierSyncRun.started_at.desc()))
    assert ledger is not None
    assert ledger.status == expected_status


@pytest.mark.parametrize(
    ("snapshot_id", "generated_at"),
    [
        (8, "2026-09-18T10:00:00Z"),
        (7, "2026-09-18T10:02:00Z"),
    ],
)
def test_worker_rejects_snapshot_identity_change_during_pagination(db, snapshot_id, generated_at):
    """Reading page two from another publication could mix device identities."""
    from app.inventory.netctl_sync import synchronize_current_snapshot
    from app.inventory.models import InventoryIdentifierSyncRun

    def fake_netctl(args, timeout=None):
        page = int(args[-3])
        return _snapshot_page(
            page=page,
            pages=2,
            snapshot_id=snapshot_id if page == 2 else 7,
            generated_at=generated_at if page == 2 else "2026-09-18T10:00:00Z",
            total=500,
            hosts=[{}] * 250,
        )

    summary = synchronize_current_snapshot(netctl_call=fake_netctl, session_factory=lambda: db)

    assert summary.status == "failed"
    assert db.scalar(select(InventoryIdentifierSyncRun.status)) == "failed"


def test_worker_skips_previously_successful_snapshot_id_without_second_reconciliation(db, service):
    """Removing the successful-ID guard would overwrite a later manual correction."""
    from app.inventory.netctl_sync import synchronize_current_snapshot
    from app.inventory.models import InventoryIdentifierSyncRun

    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")
    db.commit()
    page = _snapshot_page(hosts=[{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.20"}])

    first = synchronize_current_snapshot(netctl_call=lambda args, timeout=None: page, session_factory=lambda: db)
    assert _current_values(db, asset.id)["ip"] == "192.168.100.20"
    first_ledger = db.scalar(select(InventoryIdentifierSyncRun).where(InventoryIdentifierSyncRun.status == "success"))
    assert first_ledger is not None
    assert (first_ledger.matched_assets, first_ledger.updated_assets, first_ledger.skipped_assets) == (1, 1, 0)
    service.sync_identifiers(db, asset, [
        {"identifier_type": "mac", "value": "AA:BB:CC:DD:EE:FF"},
        {"identifier_type": "ip", "value": "192.168.100.99"},
    ])
    second = synchronize_current_snapshot(netctl_call=lambda args, timeout=None: page, session_factory=lambda: db)

    assert first.status == "success"
    assert second.status == "skipped"
    assert _current_values(db, asset.id)["ip"] == "192.168.100.99"
    assert [row.status for row in db.scalars(select(InventoryIdentifierSyncRun).order_by(InventoryIdentifierSyncRun.started_at))] == [
        "success",
        "skipped",
    ]


def test_worker_records_netctl_error_as_failure_without_mutation(db, service):
    """A command failure must not be mistaken for an empty snapshot."""
    from app.inventory.netctl_sync import synchronize_current_snapshot
    from app.inventory.models import InventoryIdentifierSyncRun
    from app.netctl_client import NetctlError

    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")
    db.commit()
    summary = synchronize_current_snapshot(
        netctl_call=lambda args, timeout=None: (_ for _ in ()).throw(NetctlError("private payload")),
        session_factory=lambda: db,
    )

    assert summary.status == "failed"
    assert _current_values(db, asset.id)["ip"] == "192.168.100.10"
    ledger = db.scalar(select(InventoryIdentifierSyncRun))
    assert ledger is not None
    assert ledger.status == "failed"
    assert ledger.failure_reason == "netctl snapshot unavailable"


def test_worker_rolls_back_identifier_writes_before_recording_failure(db, service, monkeypatch):
    """A reconciliation exception after a write must leave no partial identifier set."""
    from app.inventory import netctl_sync
    from app.inventory.models import InventoryIdentifierSyncRun

    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")
    db.commit()
    original = InventoryService.reconcile_netctl_identifiers

    def fail_after_reconcile(self, session, hosts, *, observed_at):
        original(self, session, hosts, observed_at=observed_at)
        raise RuntimeError("private host details")

    monkeypatch.setattr(netctl_sync.InventoryService, "reconcile_netctl_identifiers", fail_after_reconcile)
    summary = netctl_sync.synchronize_current_snapshot(
        netctl_call=lambda args, timeout=None: _snapshot_page(hosts=[{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.20"}]),
        session_factory=lambda: db,
    )

    assert summary.status == "failed"
    assert _current_values(db, asset.id)["ip"] == "192.168.100.10"
    ledger = db.scalar(select(InventoryIdentifierSyncRun))
    assert ledger is not None
    assert ledger.status == "failed"
    assert ledger.failure_reason == "database synchronization failed"


def test_worker_main_returns_zero_for_skipped_and_one_for_failure(monkeypatch):
    """The one-shot entry point must expose only service-friendly exit statuses."""
    from app.inventory import netctl_sync

    calls = []
    monkeypatch.setattr(netctl_sync, "init_db", lambda: calls.append("init"))
    monkeypatch.setattr(netctl_sync, "synchronize_current_snapshot", lambda: netctl_sync.SyncSummary(status="skipped"))
    assert netctl_sync.main() == 0
    monkeypatch.setattr(netctl_sync, "synchronize_current_snapshot", lambda: netctl_sync.SyncSummary(status="failed"))
    assert netctl_sync.main() == 1
    assert calls == ["init", "init"]


@pytest.mark.parametrize(
    "pages",
    [
        {
            1: _snapshot_page(page=1, pages=2, total=500, hosts=[{}] * 250),
            2: _snapshot_page(page=2, pages=1, total=500, hosts=[{}] * 250),
        },
        {
            1: _snapshot_page(page=1, pages=2, total=500, hosts=[{}] * 250),
            2: _snapshot_page(page=2, pages=3, total=750, hosts=[{}] * 250),
            3: _snapshot_page(page=3, pages=3, total=750, hosts=[{}] * 250),
        },
        {
            1: _snapshot_page(page=1, pages=2, total=500, hosts=[{}] * 250),
            2: _snapshot_page(page=2, pages=2, limit=500, total=1000, hosts=[{}] * 250),
        },
    ],
)
def test_worker_rejects_changed_or_invalid_pagination_metadata(db, pages):
    """Changing any page metadata can otherwise produce a mixed or partial snapshot."""
    from app.inventory.netctl_sync import synchronize_current_snapshot

    summary = synchronize_current_snapshot(
        netctl_call=lambda args, timeout=None: pages[int(args[-3])],
        session_factory=lambda: db,
    )

    assert summary.status == "failed"


def test_worker_rejects_incomplete_final_host_count(db):
    """Returning success with fewer hosts than published total drops inventory evidence."""
    from app.inventory.netctl_sync import synchronize_current_snapshot

    summary = synchronize_current_snapshot(
        netctl_call=lambda args, timeout=None: _snapshot_page(total=2, hosts=[{}]),
        session_factory=lambda: db,
    )

    assert summary.status == "failed"


def test_worker_accepts_netctl_empty_snapshot_shape(db):
    """Netctl publishes an empty current snapshot as page 1 of 0 pages."""
    from app.inventory.netctl_sync import SyncSummary, synchronize_current_snapshot
    from app.inventory.models import InventoryIdentifierSyncRun

    summary = synchronize_current_snapshot(
        netctl_call=lambda args, timeout=None: _snapshot_page(page=1, pages=0, total=0, hosts=[]),
        session_factory=lambda: db,
    )

    assert summary == SyncSummary(
        status="success",
        snapshot_id=7,
    )
    ledger = db.scalar(select(InventoryIdentifierSyncRun))
    assert ledger is not None
    assert (ledger.status, ledger.matched_assets, ledger.updated_assets, ledger.skipped_assets) == ("success", 0, 0, 0)


def test_success_snapshot_unique_index_rolls_back_losing_identifier_update(db, service):
    """A second worker that passed its preflight must not commit a second success or IP."""
    from app.db import get_sessionmaker
    from app.inventory.models import InventoryIdentifierSyncRun

    asset = _asset_with_identifiers(db, service, mac="AA:BB:CC:DD:EE:FF", ip="192.168.100.10")
    db.commit()
    winner = get_sessionmaker()()
    loser = get_sessionmaker()()
    observed_at = datetime(2026, 9, 18, tzinfo=UTC)
    try:
        assert winner.scalar(select(InventoryIdentifierSyncRun).where(InventoryIdentifierSyncRun.snapshot_id == 88)) is None
        assert loser.scalar(select(InventoryIdentifierSyncRun).where(InventoryIdentifierSyncRun.snapshot_id == 88)) is None
        loser.rollback()

        InventoryService().reconcile_netctl_identifiers(
            winner,
            [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.20"}],
            observed_at=observed_at,
        )
        winner.add(InventoryIdentifierSyncRun(snapshot_id=88, status="success"))
        winner.commit()

        InventoryService().reconcile_netctl_identifiers(
            loser,
            [{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.100.30"}],
            observed_at=observed_at,
        )
        loser.add(InventoryIdentifierSyncRun(snapshot_id=88, status="success"))
        with pytest.raises(IntegrityError):
            loser.commit()
        loser.rollback()
    finally:
        winner.close()
        loser.close()

    db.expire_all()
    assert _current_values(db, asset.id)["ip"] == "192.168.100.20"
    successes = db.scalars(
        select(InventoryIdentifierSyncRun).where(
            InventoryIdentifierSyncRun.snapshot_id == 88,
            InventoryIdentifierSyncRun.status == "success",
        )
    ).all()
    assert len(successes) == 1
