from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from .config import get_settings
from .db import session_scope
from .models import DownloadToken


def hash_token(token: str) -> str:
    secret = get_settings().app_secret_key.encode("utf-8")
    return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def assert_allowed_file(path: str | Path) -> Path:
    resolved = Path(path).expanduser().resolve()
    roots = [root.expanduser().resolve() for root in get_settings().allowed_download_roots]
    if not any(_inside(resolved, root) for root in roots):
        raise ValueError("file path is outside allowed download roots")
    if not resolved.is_file():
        raise ValueError("download file does not exist")
    return resolved


def create_download_token(
    *,
    client_name: str,
    file_path: str | Path,
    file_type: str,
    created_by: str,
    expires_at: datetime,
) -> tuple[str, DownloadToken]:
    resolved = assert_allowed_file(file_path)
    token = secrets.token_urlsafe(32)
    record = DownloadToken(
        token_hash=hash_token(token),
        client_name=client_name,
        file_path=str(resolved),
        file_type=file_type,
        created_by=created_by,
        expires_at=expires_at,
    )
    with session_scope() as db:
        db.add(record)
        db.flush()
        db.refresh(record)
        db.expunge(record)
    return token, record


def consume_download_token(token: str) -> DownloadToken | None:
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        record = db.scalar(select(DownloadToken).where(DownloadToken.token_hash == token_hash))
        if record is None or record.used_at is not None or record.revoked_at is not None:
            return None
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            return None
        record.used_at = now
        db.flush()
        db.refresh(record)
        db.expunge(record)
        return record
