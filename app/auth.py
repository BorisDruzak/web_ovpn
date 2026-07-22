from __future__ import annotations

import hmac
import hashlib
import json
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import write_audit
from .config import get_settings
from .models import WebUser

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
NETWORK_CHANGE_SCOPES = frozenset({"network:read", "network:plan", "network:apply", "network:rollback"})


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def ensure_admin_user(db: Session) -> None:
    settings = get_settings()
    if not settings.admin_password:
        return
    user = db.scalar(select(WebUser).where(WebUser.username == settings.admin_username))
    if user is None:
        db.add(
            WebUser(
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
                is_active=True,
                is_admin=True,
                is_network_admin=True,
            )
        )
        return
    if not verify_password(settings.admin_password, user.password_hash):
        user.password_hash = hash_password(settings.admin_password)
    user.is_active = True
    user.is_admin = True
    user.is_network_admin = True


def authenticate_user(db: Session, username: str, password: str) -> WebUser | None:
    user = db.scalar(select(WebUser).where(WebUser.username == username))
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return user


def current_user(request: Request, db: Session) -> WebUser | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = db.get(WebUser, int(user_id))
    if user is None or not user.is_active:
        request.session.clear()
        return None
    return user


def require_user(request: Request, db: Session) -> WebUser:
    user = current_user(request, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return user


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


async def verify_csrf(request: Request) -> None:
    form = await request.form()
    sent = str(form.get("csrf_token") or "")
    expected = str(request.session.get("csrf_token") or "")
    if not expected or not hmac.compare_digest(sent, expected):
        raise HTTPException(status_code=400, detail="CSRF token mismatch")


def _network_change_tokens() -> tuple[dict[str, object], ...]:
    """Load only hashed, explicitly scoped control-plane credentials."""
    try:
        raw = json.loads(get_settings().network_change_tokens_json)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ()
    if not isinstance(raw, list):
        return ()
    result: list[dict[str, object]] = []
    for record in raw:
        if not isinstance(record, dict):
            continue
        token_hash = record.get("token_hash")
        actor = record.get("actor")
        scopes = record.get("scopes")
        if not isinstance(token_hash, str) or not isinstance(actor, str) or not isinstance(scopes, list):
            continue
        clean_scopes = frozenset(str(scope) for scope in scopes)
        if clean_scopes <= NETWORK_CHANGE_SCOPES:
            result.append({"token_hash": token_hash, "actor": actor, "scopes": clean_scopes})
    return tuple(result)


def _deny_network_change(request: Request, db: Session, actor: str, reason: str, status_code: int = 403) -> None:
    write_audit(db, request, actor, "network-change-authorize", "denied", reason)
    raise HTTPException(status_code=status_code, detail=reason)


def _require_trusted_https(request: Request, db: Session, actor: str) -> None:
    settings = get_settings()
    if not settings.network_change_trusted_https:
        _deny_network_change(request, db, actor, "trusted HTTPS mode is not configured", status_code=503)
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    is_https = request.url.scheme == "https" or (settings.network_change_trust_proxy and forwarded_proto == "https")
    if not is_https:
        _deny_network_change(request, db, actor, "trusted HTTPS is required")


def authorize_network_change(request: Request, authorization: str | None, db: Session, required_scope: str) -> str:
    """Authorize a future network-control action without accepting the legacy API token."""
    if required_scope not in NETWORK_CHANGE_SCOPES:
        raise ValueError("invalid network change scope")
    if not authorization or not authorization.startswith("Bearer "):
        _deny_network_change(request, db, "anonymous", "scoped bearer token required", status_code=401)
    digest = hashlib.sha256(authorization.removeprefix("Bearer ").strip().encode("utf-8")).hexdigest()
    selected: dict[str, object] | None = None
    for record in _network_change_tokens():
        if hmac.compare_digest(digest, str(record["token_hash"])):
            selected = record
            break
    if selected is None:
        _deny_network_change(request, db, "anonymous", "invalid scoped bearer token", status_code=401)
    actor = str(selected["actor"])
    scopes = selected["scopes"]
    if required_scope not in scopes:
        _deny_network_change(request, db, actor, f"missing required scope: {required_scope}")
    _require_trusted_https(request, db, actor)
    return actor


def authorize_network_change_session(request: Request, user: WebUser | None, db: Session, required_scope: str) -> WebUser:
    if required_scope not in NETWORK_CHANGE_SCOPES:
        raise ValueError("invalid network change scope")
    actor = user.username if user is not None else "anonymous"
    if user is None or not user.is_active or not user.is_network_admin:
        _deny_network_change(request, db, actor, "network admin role is required")
    _require_trusted_https(request, db, actor)
    return user
