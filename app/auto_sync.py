from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from .audit import write_audit
from .models import AppSetting, WebUser, utcnow
from .vpnctl_client import VpnctlError, run_vpnctl

AUTO_SYNC_SETTING = "clients.last_auto_sync_at"


def _error_message(exc: VpnctlError) -> str:
    suffix = exc.stderr.strip() or exc.stdout.strip()
    if suffix:
        return f"{exc.message}: {suffix[:500]}"
    return exc.message


def _last_sync_at(db: Session) -> datetime | None:
    setting = db.query(AppSetting).filter(AppSetting.key == AUTO_SYNC_SETTING).one_or_none()
    if setting is None or not setting.value:
        return None
    try:
        parsed = datetime.fromisoformat(setting.value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _save_sync_at(db: Session) -> None:
    value = utcnow().isoformat()
    setting = db.query(AppSetting).filter(AppSetting.key == AUTO_SYNC_SETTING).one_or_none()
    if setting is None:
        db.add(AppSetting(key=AUTO_SYNC_SETTING, value=value, updated_at=utcnow()))
    else:
        setting.value = value
        setting.updated_at = utcnow()
    db.commit()


def force_client_sync(
    db: Session,
    request: Request,
    actor: WebUser | str,
    reason: str,
    action: str = "auto-sync",
) -> tuple[dict[str, Any], str | None]:
    try:
        data = run_vpnctl(["sync"], timeout=180)
    except VpnctlError as exc:
        message = _error_message(exc)
        write_audit(db, request, actor, action, "error", f"{reason}: {message}")
        return {}, message
    _save_sync_at(db)
    count = data.get("imported_or_updated", 0)
    write_audit(db, request, actor, action, "ok", f"{reason}: count={count}")
    return data, None


def maybe_client_sync(
    db: Session,
    request: Request,
    actor: WebUser | str,
    reason: str,
    min_interval_seconds: int = 60,
) -> str | None:
    last_sync = _last_sync_at(db)
    if last_sync and utcnow() - last_sync < timedelta(seconds=min_interval_seconds):
        return None
    _, error = force_client_sync(db, request, actor, reason, action="auto-sync")
    return error
