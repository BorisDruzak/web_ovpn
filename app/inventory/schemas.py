from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..endpoint_context_adapter import SafeProfile

from .models import (
    InventoryAssetStatus,
    InventoryAssetType,
    InventoryCheckResult,
    InventoryIdentifierType,
    InventoryObservationSource,
)


class IdentifierPayload(BaseModel):
    identifier_type: InventoryIdentifierType
    value: str = Field(min_length=1, max_length=255)
    source: InventoryObservationSource = InventoryObservationSource.MANUAL


class LocationCreate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    comment: str | None = None


class LocationUpdate(LocationCreate):
    pass


class AssetPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_type: InventoryAssetType
    location_id: str | None = None
    custom_name: str | None = Field(default=None, max_length=255)
    manufacturer: str | None = Field(default=None, max_length=255)
    model: str | None = Field(default=None, max_length=255)
    serial_number: str | None = Field(default=None, max_length=255)
    inventory_number: str | None = Field(default=None, max_length=255)
    status: InventoryAssetStatus | None = None
    assigned_person_name: str | None = Field(default=None, max_length=255)
    login_name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    last_verified_at: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    identifiers: list[IdentifierPayload] | None = None

    def asset_fields(self) -> dict[str, Any]:
        return self.model_dump(exclude={"asset_type", "location_id", "details", "identifiers"}, exclude_unset=True)


class AssetUpdate(AssetPayload):
    asset_type: InventoryAssetType | None = None

    def asset_fields(self) -> dict[str, Any]:
        return self.model_dump(exclude={"asset_type", "location_id", "details", "identifiers"}, exclude_unset=True)


class WorkplacePCPayload(AssetPayload):
    asset_type: InventoryAssetType = InventoryAssetType.PC


class WorkplaceCreate(BaseModel):
    location_id: str | None = None
    pc: WorkplacePCPayload
    children: list[AssetPayload] = Field(default_factory=list)


class RelationCreate(BaseModel):
    parent_asset_id: str
    child_asset_id: str
    note: str | None = None


class LookupRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=255)
    asset_id: str | None = None


class SessionCreate(BaseModel):
    pass


class SessionCheckCreate(BaseModel):
    asset_id: str
    location_id: str | None = None
    result: InventoryCheckResult
    notes: str | None = None


class EndpointRefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: SafeProfile = "baseline_v1"


class EndpointDiscrepancyResolution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["accept_endpoint", "keep_manual", "mark_verified"]
    expected_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
