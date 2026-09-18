from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import utcnow


def new_inventory_id() -> str:
    return str(uuid4())


class InventoryAssetType(StrEnum):
    PC = "PC"
    MONITOR = "MONITOR"
    PRINTER = "PRINTER"
    PHONE = "PHONE"
    UPS = "UPS"
    OTHER = "OTHER"


class InventoryAssetStatus(StrEnum):
    IN_USE = "in_use"
    STORAGE = "storage"
    RESERVE = "reserve"
    BROKEN = "broken"
    REPAIR = "repair"
    TO_WRITEOFF = "to_writeoff"
    WRITTEN_OFF = "written_off"
    UNKNOWN = "unknown"


class InventoryIdentifierType(StrEnum):
    IP = "ip"
    MAC = "mac"
    HOSTNAME = "hostname"
    EXTENSION = "extension"
    OTHER = "other"


class InventoryObservationSource(StrEnum):
    NETCTL = "netctl"
    NMAP = "nmap"
    MANUAL = "manual"
    ENDPOINT = "endpoint"


class InventoryExternalBindingStatus(StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    REPLACED = "replaced"
    ENDED = "ended"


class InventoryCheckResult(StrEnum):
    CONFIRMED = "confirmed"
    NEW = "new"
    MOVED = "moved"
    MISSING = "missing"
    DAMAGED = "damaged"
    UNKNOWN = "unknown"


class InventoryPhotoType(StrEnum):
    GENERAL = "general"
    SERIAL_LABEL = "serial_label"
    INVENTORY_LABEL = "inventory_label"
    STATUS_PAGE = "status_page"
    DAMAGE = "damage"
    OTHER = "other"


class InventoryPrinterConnectionType(StrEnum):
    NETWORK = "network"
    USB = "usb"


class InventoryLocation(Base):
    __tablename__ = "inventory_locations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class InventoryAsset(Base):
    __tablename__ = "inventory_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    asset_type: Mapped[InventoryAssetType] = mapped_column(Enum(InventoryAssetType), nullable=False)
    location_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_locations.id"), index=True)
    custom_name: Mapped[str | None] = mapped_column(String(255))
    manufacturer: Mapped[str | None] = mapped_column(String(255))
    model: Mapped[str | None] = mapped_column(String(255))
    serial_number: Mapped[str | None] = mapped_column(String(255))
    inventory_number: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[InventoryAssetStatus | None] = mapped_column(Enum(InventoryAssetStatus))
    assigned_person_name: Mapped[str | None] = mapped_column(String(255))
    login_name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InventoryAssetIdentifier(Base):
    __tablename__ = "inventory_asset_identifiers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), index=True, nullable=False)
    identifier_type: Mapped[InventoryIdentifierType] = mapped_column(Enum(InventoryIdentifierType), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    source: Mapped[InventoryObservationSource] = mapped_column(Enum(InventoryObservationSource), nullable=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class InventoryExternalBinding(Base):
    __tablename__ = "inventory_external_bindings"
    __table_args__ = (
        CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name="ck_inventory_binding_confidence",
        ),
        Index(
            "uq_inventory_endpoint_confirmed_asset",
            "asset_id",
            "source",
            unique=True,
            sqlite_where=text("status = 'confirmed' AND ended_at IS NULL"),
            postgresql_where=text("status = 'confirmed' AND ended_at IS NULL"),
        ),
        Index(
            "uq_inventory_endpoint_confirmed_device",
            "source",
            "external_id",
            unique=True,
            sqlite_where=text("status = 'confirmed' AND ended_at IS NULL"),
            postgresql_where=text("status = 'confirmed' AND ended_at IS NULL"),
        ),
        Index(
            "uq_inventory_endpoint_active_candidate",
            "asset_id",
            "source",
            "external_id",
            unique=True,
            sqlite_where=text("status = 'candidate' AND ended_at IS NULL"),
            postgresql_where=text("status = 'candidate' AND ended_at IS NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_inventory_id
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("inventory_assets.id"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(
        String(64), default="endpoint_platform", nullable=False
    )
    external_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    status: Mapped[InventoryExternalBindingStatus] = mapped_column(
        Enum(
            InventoryExternalBindingStatus,
            values_callable=lambda enum_type: [member.value for member in enum_type],
            native_enum=False,
        ),
        nullable=False,
    )
    binding_method: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_json: Mapped[dict[str, object]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class InventoryEndpointState(Base):
    __tablename__ = "inventory_endpoint_state"

    binding_id: Mapped[str] = mapped_column(
        ForeignKey("inventory_external_bindings.id"), primary_key=True
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("inventory_assets.id"), index=True, nullable=False
    )
    endpoint_device_id: Mapped[str] = mapped_column(
        String(255), index=True, nullable=False
    )
    online: Mapped[bool | None] = mapped_column(Boolean)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    agent_version: Mapped[str | None] = mapped_column(String(128))
    baseline_snapshot_id: Mapped[str | None] = mapped_column(String(255))
    health_snapshot_id: Mapped[str | None] = mapped_column(String(255))
    network_snapshot_id: Mapped[str | None] = mapped_column(String(255))
    baseline_semantic_hash: Mapped[str | None] = mapped_column(String(64))
    health_semantic_hash: Mapped[str | None] = mapped_column(String(64))
    network_semantic_hash: Mapped[str | None] = mapped_column(String(64))
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    refreshed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    unavailable_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    safe_context_json: Mapped[dict[str, object]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class InventoryEndpointSyncControl(Base):
    __tablename__ = "inventory_endpoint_sync_control"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_inventory_endpoint_sync_singleton"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    lease_owner: Mapped[str | None] = mapped_column(String(255))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_presence_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_full_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_safe_error_code: Mapped[str | None] = mapped_column(String(64))
    last_reconciliation_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class InventoryIdentifierSyncRun(Base):
    __tablename__ = "inventory_identifier_sync_runs"
    __table_args__ = (
        Index(
            "uq_inventory_identifier_sync_success_snapshot",
            "snapshot_id",
            unique=True,
            sqlite_where=text("status = 'success'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    snapshot_id: Mapped[int | None] = mapped_column(Integer, index=True)
    snapshot_generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    matched_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    skipped_assets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text)


class InventoryAssetRelation(Base):
    __tablename__ = "inventory_asset_relations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    parent_asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), index=True, nullable=False)
    child_asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), index=True, nullable=False)
    relation_type: Mapped[str] = mapped_column(String(64), default="WORKPLACE_DEVICE", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), default="system", nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str | None] = mapped_column(Text)


class InventoryPCDetails(Base):
    __tablename__ = "inventory_pc_details"

    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), primary_key=True)
    os_name: Mapped[str | None] = mapped_column(String(255))
    os_version: Mapped[str | None] = mapped_column(String(255))
    cpu_model: Mapped[str | None] = mapped_column(String(255))
    cpu_generation: Mapped[str | None] = mapped_column(String(100))
    ram_type: Mapped[str | None] = mapped_column(String(100))
    ram_gb: Mapped[int | None] = mapped_column(Integer)
    storage_type: Mapped[str | None] = mapped_column(String(100))
    storage_gb: Mapped[int | None] = mapped_column(Integer)


class InventoryPrinterDetails(Base):
    __tablename__ = "inventory_printer_details"

    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), primary_key=True)
    page_counter: Mapped[int | None] = mapped_column(Integer)
    connection_type: Mapped[InventoryPrinterConnectionType | None] = mapped_column(
        Enum(InventoryPrinterConnectionType)
    )


class InventoryPhoneDetails(Base):
    __tablename__ = "inventory_phone_details"

    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), primary_key=True)
    extension: Mapped[str | None] = mapped_column(String(64))


class InventoryMonitorDetails(Base):
    __tablename__ = "inventory_monitor_details"

    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), primary_key=True)
    diagonal_inches: Mapped[str | None] = mapped_column(String(32))


class InventoryUPSDetails(Base):
    __tablename__ = "inventory_ups_details"

    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), primary_key=True)
    power_va: Mapped[int | None] = mapped_column(Integer)
    battery_replaced_at: Mapped[date | None] = mapped_column(Date)


class InventoryObservation(Base):
    __tablename__ = "inventory_observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_assets.id"), index=True)
    source: Mapped[InventoryObservationSource] = mapped_column(Enum(InventoryObservationSource), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    data_json: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    binding_id: Mapped[str | None] = mapped_column(
        ForeignKey("inventory_external_bindings.id"), index=True
    )
    endpoint_device_id: Mapped[str | None] = mapped_column(String(255), index=True)
    profile: Mapped[str | None] = mapped_column(String(32))
    snapshot_id: Mapped[str | None] = mapped_column(String(255))
    semantic_hash: Mapped[str | None] = mapped_column(String(64))
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InventorySession(Base):
    __tablename__ = "inventory_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)


class InventoryCheck(Base):
    __tablename__ = "inventory_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    session_id: Mapped[str] = mapped_column(ForeignKey("inventory_sessions.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), nullable=False)
    location_id: Mapped[str | None] = mapped_column(ForeignKey("inventory_locations.id"))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    checked_by: Mapped[str] = mapped_column(String(120), nullable=False)
    result: Mapped[InventoryCheckResult] = mapped_column(Enum(InventoryCheckResult), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)


class InventoryAssetPhoto(Base):
    __tablename__ = "inventory_asset_photos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    asset_id: Mapped[str] = mapped_column(ForeignKey("inventory_assets.id"), index=True, nullable=False)
    photo_type: Mapped[InventoryPhotoType] = mapped_column(Enum(InventoryPhotoType), default=InventoryPhotoType.GENERAL, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(255))
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)


class InventoryLocationPhoto(Base):
    __tablename__ = "inventory_location_photos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_inventory_id)
    location_id: Mapped[str] = mapped_column(ForeignKey("inventory_locations.id"), index=True, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
