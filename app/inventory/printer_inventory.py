"""Minimal read-only inventory projection. Never initialize or migrate the DB."""

from __future__ import annotations

from sqlalchemy import select

from .models import (
    InventoryAsset,
    InventoryAssetIdentifier,
    InventoryLocation,
    InventoryPrinterDetails,
)


def read_inventory(session) -> dict:
    assets = list(
        session.scalars(
            select(InventoryAsset)
            .where(InventoryAsset.deleted_at.is_(None))
            .order_by(InventoryAsset.id)
            .limit(10001)
        )
    )
    if len(assets) > 10000:
        raise ValueError("printer_inventory_limit")
    ids = {a.id for a in assets}
    identifiers = list(
        session.scalars(
            select(InventoryAssetIdentifier)
            .where(InventoryAssetIdentifier.is_current.is_(True))
            .order_by(InventoryAssetIdentifier.id)
            .limit(50001)
        )
    )
    if len(identifiers) > 50000:
        raise ValueError("printer_inventory_limit")
    return {
        "assets": [
            {
                "id": a.id,
                "type": a.asset_type.value,
                "location_id": a.location_id,
                "manufacturer": a.manufacturer,
                "model": a.model,
                "serial": a.serial_number,
                "status": a.status.value if a.status else None,
                "revision": a.manual_revision,
            }
            for a in assets
        ],
        "locations": sorted(session.scalars(select(InventoryLocation.id))),
        "identifiers": [
            {
                "asset_id": i.asset_id,
                "type": i.identifier_type.value,
                "value": i.normalized_value,
            }
            for i in identifiers
            if i.asset_id in ids and i.identifier_type.value in ("ip", "mac")
        ],
        "printer_details": [
            {
                "asset_id": p.asset_id,
                "connection_type": p.connection_type.value
                if p.connection_type
                else None,
            }
            for p in session.scalars(
                select(InventoryPrinterDetails).order_by(
                    InventoryPrinterDetails.asset_id
                )
            )
            if p.asset_id in ids
        ],
    }
