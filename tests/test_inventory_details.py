from __future__ import annotations

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'inventory-details.sqlite'}")
    from app.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db()
    with get_sessionmaker()() as session:
        yield session


@pytest.mark.parametrize(
    ("asset_type", "payload", "expected"),
    [
        ("PC", {"os_name": "Windows 11", "ram_gb": 16, "storage_gb": 512}, {"ram_gb": 16}),
        ("PRINTER", {"page_counter": 1200}, {"page_counter": 1200}),
        ("PHONE", {"extension": "129"}, {"extension": "129"}),
        ("MONITOR", {"diagonal_inches": "24"}, {"diagonal_inches": "24"}),
        ("UPS", {"power_va": 900}, {"power_va": 900}),
    ],
)
def test_each_asset_type_persists_its_own_nullable_detail_fields(db, asset_type, payload, expected):
    """Mapping a device type to the wrong details table would lose physical inventory data."""
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService

    service = InventoryService()
    asset = service.create_asset(db, InventoryAssetType(asset_type))
    service.update_details(db, asset, payload)

    assert expected.items() <= service.details_for(db, asset).items()


def test_details_reject_fields_not_owned_by_asset_type(db):
    """Accepting a PC field for a monitor would weaken the normalized v1 model."""
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService, InventoryValidationError

    asset = InventoryService().create_asset(db, InventoryAssetType.MONITOR)
    with pytest.raises(InventoryValidationError, match="detail fields"):
        InventoryService().update_details(db, asset, {"ram_gb": 16})


def test_printer_persists_connection_type_as_a_printer_detail(db):
    """A printer connection method must survive the same edit path as its page counter."""
    from app.inventory.models import InventoryAssetType
    from app.inventory.service import InventoryService

    service = InventoryService()
    printer = service.create_asset(db, InventoryAssetType.PRINTER)

    details = service.update_details(db, printer, {"connection_type": "network"})

    assert getattr(details["connection_type"], "value", details["connection_type"]) == "network"


@pytest.mark.parametrize(
    ("has_current_ip", "description", "notes", "expected"),
    [
        (True, "Подключен по USB", None, "network"),
        (False, "Подключен по ЮСБ", None, "usb"),
        (False, None, "USB-кабель", "usb"),
        (False, "Без сканера", None, None),
    ],
)
def test_infers_printer_connection_type_from_current_ip_or_comment(has_current_ip, description, notes, expected):
    from app.inventory import service as inventory_service

    result = inventory_service.infer_printer_connection_type(
        has_current_ip=has_current_ip,
        description=description,
        notes=notes,
    )

    assert getattr(result, "value", result) == expected


def test_detail_repair_replaces_cross_type_detail_row_with_the_asset_own_type(db):
    """A printer must not retain a PC-details row after an old form mismatch."""
    from app.inventory.models import InventoryAssetType, InventoryPCDetails, InventoryPrinterDetails
    from app.inventory.service import InventoryService

    service = InventoryService()
    printer = service.create_asset(db, InventoryAssetType.PRINTER)
    db.add(InventoryPCDetails(asset_id=printer.id, cpu_model="wrong"))
    db.flush()

    repaired = service.repair_detail_integrity(db)

    assert repaired == 1
    assert db.get(InventoryPCDetails, printer.id) is None
    assert db.get(InventoryPrinterDetails, printer.id) is not None
