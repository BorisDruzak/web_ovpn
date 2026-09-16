from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..auth import csrf_token, current_user, require_user, verify_csrf
from ..config import get_settings
from ..db import get_db
from .models import InventoryAsset, InventoryAssetRelation, InventoryAssetType, InventoryLocation
from .service import InventoryService, InventoryValidationError


router = APIRouter(tags=["inventory-web"])
service = InventoryService()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
templates.env.globals["csrf_token"] = csrf_token
ASSET_LABELS = {
    InventoryAssetType.PC: "ПК",
    InventoryAssetType.MONITOR: "МОНИТОР",
    InventoryAssetType.PRINTER: "МФУ / ПРИНТЕР",
    InventoryAssetType.PHONE: "ТЕЛЕФОН",
    InventoryAssetType.UPS: "ИБП",
    InventoryAssetType.OTHER: "ДРУГОЕ",
}


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _flash(request: Request, category: str, message: str) -> None:
    items = list(request.session.get("flashes", []))
    items.append({"category": category, "message": message})
    request.session["flashes"] = items[-5:]


def _render(request: Request, template: str, context: dict[str, Any], db: Session) -> HTMLResponse:
    user = current_user(request, db)
    context.update(
        {
            "request": request,
            "user": user,
            "settings": get_settings(),
            "flashes": list(request.session.get("flashes", [])),
        }
    )
    request.session["flashes"] = []
    return templates.TemplateResponse(template, context)


def _current_location(request: Request, db: Session) -> InventoryLocation | None:
    selected = str(request.session.get("inventory_current_location_id") or "")
    location = db.get(InventoryLocation, selected) if selected else None
    if location is None:
        location = db.scalar(select(InventoryLocation).order_by(InventoryLocation.created_at, InventoryLocation.id))
        if location is not None:
            request.session["inventory_current_location_id"] = location.id
    return location


@router.get("/inventory", response_class=HTMLResponse)
def inventory_home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    location = _current_location(request, db)
    tree = service.location_tree(db, location.id) if location else {"top_level_assets": [], "related_by_parent": {}}
    locations = list(db.scalars(select(InventoryLocation).order_by(InventoryLocation.name, InventoryLocation.id)))
    return _render(
        request,
        "inventory.html",
        {"location": location, "locations": locations, "tree": tree, "asset_labels": ASSET_LABELS},
        db,
    )


@router.post("/inventory/locations")
async def inventory_create_location(request: Request, name: str = Form(default=""), comment: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    location = service.create_location(db, name=name, comment=comment)
    request.session["inventory_current_location_id"] = location.id
    write_audit(db, request, user, "inventory.location.create", "ok", location.name or "", target_client=location.id)
    _flash(request, "ok", "Локация сохранена")
    return _redirect("/inventory")


@router.post("/inventory/location/comment")
async def inventory_update_location_comment(request: Request, comment: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    location = _current_location(request, db)
    if location is None:
        _flash(request, "bad", "Сначала создайте локацию")
        return _redirect("/inventory")
    service.update_location(location, name=location.name, comment=comment)
    write_audit(db, request, user, "inventory.location.update", "ok", "comment", target_client=location.id)
    _flash(request, "ok", "Комментарий локации сохранён")
    return _redirect("/inventory")


@router.post("/inventory/location/select")
async def inventory_select_location(request: Request, location_id: str = Form(), db: Session = Depends(get_db)) -> RedirectResponse:
    require_user(request, db)
    await verify_csrf(request)
    if db.get(InventoryLocation, location_id) is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    request.session["inventory_current_location_id"] = location_id
    return _redirect("/inventory")


@router.get("/inventory/assets/new", response_class=HTMLResponse)
def inventory_new_asset(asset_type: InventoryAssetType = InventoryAssetType.PC, parent_asset_id: str = "", request: Request = None, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    location = _current_location(request, db)
    return _render(request, "inventory_asset_form.html", {"asset": None, "asset_type": asset_type, "parent_asset_id": parent_asset_id, "location": location, "asset_labels": ASSET_LABELS}, db)


@router.get("/inventory/assets/{asset_id}", response_class=HTMLResponse)
def inventory_asset_detail(asset_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    location = _current_location(request, db)
    return _render(request, "inventory_asset_form.html", {"asset": asset, "asset_type": asset.asset_type, "parent_asset_id": "", "location": location, "asset_labels": ASSET_LABELS}, db)


@router.post("/inventory/assets")
async def inventory_create_asset(request: Request, asset_type: InventoryAssetType = Form(), custom_name: str = Form(default=""), manufacturer: str = Form(default=""), model: str = Form(default=""), serial_number: str = Form(default=""), inventory_number: str = Form(default=""), assigned_person_name: str = Form(default=""), login_name: str = Form(default=""), description: str = Form(default=""), notes: str = Form(default=""), parent_asset_id: str = Form(default=""), save_next: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    location = _current_location(request, db)
    if location is None:
        _flash(request, "bad", "Сначала создайте локацию")
        return _redirect("/inventory")
    try:
        asset = service.create_asset(db, asset_type, location_id=location.id, custom_name=custom_name or None, manufacturer=manufacturer or None, model=model or None, serial_number=serial_number or None, inventory_number=inventory_number or None, assigned_person_name=assigned_person_name or None, login_name=login_name or None, description=description or None, notes=notes or None)
        if parent_asset_id:
            service.attach_existing_asset(db, parent_asset_id, asset.id, actor=user.username)
            write_audit(db, request, user, "inventory.relation.create", "ok", "WORKPLACE_DEVICE", target_client=asset.id)
    except InventoryValidationError as exc:
        _flash(request, "bad", str(exc))
        return _redirect("/inventory")
    write_audit(db, request, user, "inventory.asset.create", "ok", asset.asset_type.value, target_client=asset.id)
    _flash(request, "ok", "Устройство сохранено")
    if save_next:
        return _redirect(f"/inventory/assets/new?asset_type={asset_type.value}")
    return _redirect(f"/inventory/assets/{asset.id}")


@router.post("/inventory/assets/{asset_id}")
async def inventory_update_asset(asset_id: str, request: Request, custom_name: str = Form(default=""), manufacturer: str = Form(default=""), model: str = Form(default=""), serial_number: str = Form(default=""), inventory_number: str = Form(default=""), assigned_person_name: str = Form(default=""), login_name: str = Form(default=""), description: str = Form(default=""), notes: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    service.update_asset(asset, custom_name=custom_name or None, manufacturer=manufacturer or None, model=model or None, serial_number=serial_number or None, inventory_number=inventory_number or None, assigned_person_name=assigned_person_name or None, login_name=login_name or None, description=description or None, notes=notes or None)
    write_audit(db, request, user, "inventory.asset.update", "ok", asset.asset_type.value, target_client=asset.id)
    _flash(request, "ok", "Устройство обновлено")
    return _redirect(f"/inventory/assets/{asset.id}")


@router.post("/inventory/relations/{relation_id}/detach")
async def inventory_detach_relation(relation_id: str, request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    try:
        relation = service.detach_relation(db, relation_id)
    except InventoryValidationError as exc:
        _flash(request, "bad", str(exc))
        return _redirect("/inventory")
    write_audit(db, request, user, "inventory.relation.end", "ok", "", target_client=relation.id)
    _flash(request, "ok", "Связь завершена; устройство осталось в локации")
    return _redirect("/inventory")
