"""Local observations and explicit links; controller execution remains remote."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, JSON, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base, UTCDateTime
from ..models import utcnow


def new_id():
    return str(uuid.uuid4())


class SchemaVersion(Base):
    __tablename__ = 'workstation_schema'
    __table_args__ = (CheckConstraint('id = 1', name='ck_workstation_schema_singleton'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class SourceRun(Base):
    __tablename__ = 'workstation_source_runs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    batch_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    generation: Mapped[str | None] = mapped_column(String(128))
    error_code: Mapped[str | None] = mapped_column(String(128))
    object_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class SourceSnapshot(Base):
    __tablename__ = 'workstation_source_snapshots'
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    generation: Mapped[str] = mapped_column(String(128), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    inventory_revision: Mapped[int | None] = mapped_column(Integer)
    data_json: Mapped[dict] = mapped_column(JSON, nullable=False)


class DirectoryLink(Base):
    __tablename__ = 'workstation_directory_links'
    __table_args__ = (Index('uq_workstation_confirmed_device', 'device_key', unique=True,
        sqlite_where=text("status = 'confirmed' AND ended_at IS NULL"),
        postgresql_where=text("status = 'confirmed' AND ended_at IS NULL")),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    machine_uuid: Mapped[str | None] = mapped_column(String(36))
    inventory_asset_id: Mapped[str | None] = mapped_column(ForeignKey('inventory_assets.id'))
    network_keys_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    user_guid: Mapped[str] = mapped_column(String(36), nullable=False)
    user_sid: Mapped[str] = mapped_column(String(192), nullable=False)
    user_login: Mapped[str] = mapped_column(String(192), nullable=False)
    computer_guid: Mapped[str | None] = mapped_column(String(36))
    computer_sid: Mapped[str | None] = mapped_column(String(192))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default='preview')
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_inventory_revision: Mapped[int | None] = mapped_column(Integer)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_by: Mapped[str | None] = mapped_column(String(160))
    confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    reason: Mapped[str | None] = mapped_column(Text)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    ended_by: Mapped[str | None] = mapped_column(String(160))
    end_reason: Mapped[str | None] = mapped_column(Text)


class Finding(Base):
    __tablename__ = 'workstation_findings'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), default='open', nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    acknowledged_by: Mapped[str | None] = mapped_column(String(160))
    acknowledgement_reason: Mapped[str | None] = mapped_column(Text)


class WorkstationRequest(Base):
    __tablename__ = 'workstation_requests'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    panel_operation_id: Mapped[str | None] = mapped_column(String(80), unique=True)
    actor: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    permission: Mapped[str] = mapped_column(String(64), nullable=False)
    intent_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    parameters_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    data_json: Mapped[dict | None] = mapped_column(JSON)
    phases_json: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


TABLES = (SchemaVersion.__table__, SourceRun.__table__, SourceSnapshot.__table__,
          DirectoryLink.__table__, Finding.__table__, WorkstationRequest.__table__)
