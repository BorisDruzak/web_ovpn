from __future__ import annotations

import hmac
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import WebUser

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
            )
        )
        return
    if not verify_password(settings.admin_password, user.password_hash):
        user.password_hash = hash_password(settings.admin_password)
    user.is_active = True
    user.is_admin = True


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
