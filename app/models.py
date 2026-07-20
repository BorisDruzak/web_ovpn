from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WebUser(Base):
    __tablename__ = "web_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuditLog(Base):
    __tablename__ = "web_audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target_client: Mapped[str] = mapped_column(String(180), nullable=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(Text, default="", nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    ip_address: Mapped[str] = mapped_column(String(80), default="", nullable=False)


class DownloadToken(Base):
    __tablename__ = "download_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    client_name: Mapped[str] = mapped_column(String(180), index=True, nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_type: Mapped[str] = mapped_column(String(20), nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(160), unique=True, index=True, nullable=False)
    value: Mapped[str] = mapped_column(Text, default="", nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ServerDraft(Base):
    """Public metadata for an SSH access-check draft.

    Private key material and raw host keys are deliberately owned by the
    separate worker and are never represented in the web database.
    """

    __tablename__ = "server_drafts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    ssh_user: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class ServerDraftCleanupOutbox(Base):
    """Durable, public-only cleanup intent for a deleted server draft.

    This intentionally has no foreign key: the draft row and its cleanup
    intent are committed atomically, and the draft must then be removable.
    """

    __tablename__ = "server_draft_cleanup_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    draft_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class ServerDraftCheckOutbox(Base):
    """Durable, audited consumption of one confirmed pin generation."""

    __tablename__ = "server_draft_check_outbox"
    __table_args__ = (
        UniqueConstraint("draft_id", "pin_generation", name="uq_server_draft_check_generation"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    draft_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    pin_generation: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
