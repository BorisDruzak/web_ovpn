from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    InventoryAsset,
    InventoryAssetRelation,
    InventoryAssetType,
    InventoryLocation,
)


class InventoryValidationError(ValueError):
    """A request would violate the fixed two-level inventory model."""


RELATED_DEVICE_TYPES = frozenset(
    {
        InventoryAssetType.MONITOR,
        InventoryAssetType.PRINTER,
        InventoryAssetType.PHONE,
        InventoryAssetType.UPS,
        InventoryAssetType.OTHER,
    }
)
ASSET_FIELDS = frozenset(
    {
        "custom_name",
        "manufacturer",
        "model",
        "serial_number",
        "inventory_number",
        "status",
        "assigned_person_name",
        "login_name",
        "description",
        "notes",
        "last_verified_at",
    }
)


class InventoryService:
    def create_location(self, db: Session, *, name: str | None = None, comment: str | None = None) -> InventoryLocation:
        location = InventoryLocation(name=self._nullable_text(name), comment=self._nullable_text(comment))
        db.add(location)
        db.flush()
        return location

    def update_location(self, location: InventoryLocation, *, name: str | None = None, comment: str | None = None) -> InventoryLocation:
        location.name = self._nullable_text(name)
        location.comment = self._nullable_text(comment)
        return location

    def create_asset(
        self,
        db: Session,
        asset_type: InventoryAssetType,
        *,
        location_id: str | None = None,
        **fields: Any,
    ) -> InventoryAsset:
        self._validate_asset_fields(fields)
        asset = InventoryAsset(asset_type=asset_type, location_id=location_id, **fields)
        db.add(asset)
        db.flush()
        return asset

    def update_asset(self, asset: InventoryAsset, **fields: Any) -> InventoryAsset:
        self._validate_asset_fields(fields)
        for name, value in fields.items():
            setattr(asset, name, value)
        return asset

    def create_workplace(
        self,
        db: Session,
        *,
        location_id: str | None,
        pc_fields: Mapping[str, Any] | None = None,
        child_payloads: Sequence[Mapping[str, Any]] = (),
        actor: str,
    ) -> tuple[InventoryAsset, tuple[InventoryAsset, ...]]:
        """Persist a PC and its child assets atomically inside a savepoint."""
        with db.begin_nested():
            pc = self.create_asset(
                db,
                InventoryAssetType.PC,
                location_id=location_id,
                **dict(pc_fields or {}),
            )
            children: list[InventoryAsset] = []
            for payload in child_payloads:
                raw_type = payload.get("asset_type")
                try:
                    child_type = raw_type if isinstance(raw_type, InventoryAssetType) else InventoryAssetType(str(raw_type))
                except ValueError:
                    raise InventoryValidationError("invalid related device type") from None
                fields = {key: value for key, value in payload.items() if key != "asset_type"}
                child = self.create_asset(db, child_type, location_id=pc.location_id, **fields)
                self.attach_existing_asset(db, pc.id, child.id, actor=actor)
                children.append(child)
        return pc, tuple(children)

    def attach_existing_asset(
        self, db: Session, parent_asset_id: str, child_asset_id: str, *, actor: str, note: str | None = None
    ) -> InventoryAssetRelation:
        parent = self._asset_or_error(db, parent_asset_id)
        child = self._asset_or_error(db, child_asset_id)
        if parent.asset_type is not InventoryAssetType.PC:
            raise InventoryValidationError("only PC can have related devices")
        if child.asset_type is InventoryAssetType.PC:
            raise InventoryValidationError("PC cannot be a related device")
        if child.asset_type not in RELATED_DEVICE_TYPES:
            raise InventoryValidationError("asset type cannot be a related device")
        if parent.location_id != child.location_id:
            raise InventoryValidationError("parent and child must belong to the same location")
        existing = db.scalar(
            select(InventoryAssetRelation).where(
                InventoryAssetRelation.child_asset_id == child.id,
                InventoryAssetRelation.ended_at.is_(None),
            )
        )
        if existing is not None:
            raise InventoryValidationError("related device already has an active relation")
        relation = InventoryAssetRelation(
            parent_asset_id=parent.id,
            child_asset_id=child.id,
            created_by=actor,
            note=self._nullable_text(note),
        )
        db.add(relation)
        db.flush()
        return relation

    def detach_relation(self, db: Session, relation_id: str, *, note: str | None = None) -> InventoryAssetRelation:
        relation = db.get(InventoryAssetRelation, relation_id)
        if relation is None:
            raise InventoryValidationError("inventory relation not found")
        if relation.ended_at is not None:
            raise InventoryValidationError("inventory relation is already ended")
        relation.ended_at = datetime.now(timezone.utc)
        if note is not None:
            relation.note = self._nullable_text(note)
        db.flush()
        return relation

    def location_tree(self, db: Session, location_id: str | None) -> dict[str, Any]:
        assets = list(
            db.scalars(
                select(InventoryAsset)
                .where(InventoryAsset.location_id == location_id)
                .order_by(InventoryAsset.created_at, InventoryAsset.id)
            )
        )
        asset_ids = {asset.id for asset in assets}
        relations = list(
            db.scalars(
                select(InventoryAssetRelation).where(
                    InventoryAssetRelation.ended_at.is_(None),
                    InventoryAssetRelation.parent_asset_id.in_(asset_ids),
                    InventoryAssetRelation.child_asset_id.in_(asset_ids),
                )
            )
        ) if asset_ids else []
        child_ids = {relation.child_asset_id for relation in relations}
        by_id = {asset.id: asset for asset in assets}
        related_by_parent: dict[str, list[InventoryAsset]] = {}
        for relation in relations:
            related_by_parent.setdefault(relation.parent_asset_id, []).append(by_id[relation.child_asset_id])
        return {
            "location": db.get(InventoryLocation, location_id) if location_id else None,
            "top_level_assets": [asset for asset in assets if asset.id not in child_ids],
            "related_by_parent": related_by_parent,
        }

    @staticmethod
    def _nullable_text(value: str | None) -> str | None:
        return value.strip() if isinstance(value, str) and value.strip() else None

    @staticmethod
    def _validate_asset_fields(fields: Mapping[str, Any]) -> None:
        unexpected = set(fields) - ASSET_FIELDS
        if unexpected:
            raise InventoryValidationError(f"unsupported asset fields: {', '.join(sorted(unexpected))}")

    @staticmethod
    def _asset_or_error(db: Session, asset_id: str) -> InventoryAsset:
        asset = db.get(InventoryAsset, asset_id)
        if asset is None:
            raise InventoryValidationError("inventory asset not found")
        return asset
