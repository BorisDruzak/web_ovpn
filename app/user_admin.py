"""Administrator-only capability assignment; never changes passwords or roles."""
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import write_audit
from .auth import csrf_token, require_user, verify_csrf
from .db import get_db
from .models import WebUser
from .permissions import PERMISSIONS, PERMISSION_LABELS

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["csrf_token"] = csrf_token


def administrator(request: Request, db: Session) -> WebUser:
    user = require_user(request, db)
    # admin:users is intentionally not a delegable administrator role.
    if not user.is_admin:
        raise HTTPException(403, "Только администратор может назначать права")
    return user


@router.get("/admin/users")
def users(request: Request, db: Session = Depends(get_db)):
    user = administrator(request, db)
    accounts = db.scalars(select(WebUser).order_by(WebUser.username)).all()
    grants = {}
    for account in accounts:
        try:
            grants[account.id] = json.loads(account.permissions_json or "[]")
        except (TypeError, ValueError):
            grants[account.id] = []
    return templates.TemplateResponse("user_permissions.html", {
        "request": request, "user": user, "accounts": accounts,
        "permissions": sorted(PERMISSIONS - {"admin:users"}), "grants": grants,
        "permission_labels": PERMISSION_LABELS,
        "flashes": [],
    })


@router.post("/admin/users/{user_id}/permissions")
async def assign_permissions(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = administrator(request, db)
    await verify_csrf(request)
    form = await request.form()
    selected = set(form.getlist("permission"))
    if not selected <= (PERMISSIONS - {"admin:users"}):
        raise HTTPException(400, "Неизвестное право доступа")
    account = db.get(WebUser, user_id)
    if account is None:
        raise HTTPException(404, "Учётная запись не найдена")
    account.permissions_json = json.dumps(sorted(selected))
    write_audit(db, request, user, "user-permissions", "ok",
        f"user_id={account.id}; permissions={','.join(sorted(selected))}", commit=False)
    db.commit()
    return RedirectResponse("/admin/users", status_code=303)
