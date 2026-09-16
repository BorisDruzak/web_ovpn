from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..auth import csrf_token, current_user, require_user, verify_csrf
from ..config import get_settings
from ..db import get_db
from ..netctl_client import run_netctl
from .lookup import InventoryLookup, InventoryLookupError
from .models import (
    InventoryAsset,
    InventoryAssetPhoto,
    InventoryAssetRelation,
    InventoryAssetStatus,
    InventoryAssetType,
    InventoryCheckResult,
    InventoryIdentifierType,
    InventoryLocation,
    InventoryObservationSource,
    InventoryPhotoType,
    InventorySession,
)
from .service import InventoryService, InventoryValidationError
from .storage import InventoryPhotoError, InventoryPhotoStorage


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
ASSET_STATUS_LABELS = {
    InventoryAssetStatus.IN_USE: "В эксплуатации",
    InventoryAssetStatus.STORAGE: "На хранении",
    InventoryAssetStatus.RESERVE: "Резерв",
    InventoryAssetStatus.BROKEN: "Неисправно",
    InventoryAssetStatus.REPAIR: "В ремонте",
    InventoryAssetStatus.TO_WRITEOFF: "К списанию",
    InventoryAssetStatus.WRITTEN_OFF: "Списано",
    InventoryAssetStatus.UNKNOWN: "Неизвестно",
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


def _photo_storage() -> InventoryPhotoStorage:
    settings = get_settings()
    return InventoryPhotoStorage(settings.inventory_photo_root, max_bytes=settings.inventory_photo_max_bytes)


async def _detail_form(request: Request, asset_type: InventoryAssetType) -> dict[str, Any]:
    form = await request.form()
    names = {
        InventoryAssetType.PC: ("os_name", "cpu_model", "cpu_generation", "ram_type", "ram_gb", "storage_type", "storage_gb"),
        InventoryAssetType.PRINTER: ("page_counter",),
        InventoryAssetType.PHONE: ("extension",),
        InventoryAssetType.MONITOR: ("diagonal_inches",),
        InventoryAssetType.UPS: ("power_va", "battery_replaced_at"),
    }.get(asset_type, ())
    result: dict[str, Any] = {}
    for name in names:
        value = str(form.get(name) or "").strip()
        if name in {"ram_gb", "storage_gb", "page_counter", "power_va"}:
            result[name] = int(value) if value.isdigit() else None
        elif name == "battery_replaced_at":
            result[name] = date.fromisoformat(value) if value else None
        else:
            result[name] = value or None
    return result


async def _identifier_form(request: Request) -> list[dict[str, str]]:
    form = await request.form()
    names = (("ip_address", InventoryIdentifierType.IP), ("mac_address", InventoryIdentifierType.MAC), ("hostname", InventoryIdentifierType.HOSTNAME))
    return [
        {"identifier_type": identifier_type.value, "value": value, "source": InventoryObservationSource.MANUAL.value}
        for field, identifier_type in names
        if (value := str(form.get(field) or "").strip())
    ]


def _workplace_drafts(raw: str) -> list[dict[str, str]]:
    if not raw.strip():
        return []
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InventoryValidationError("черновик связанных устройств повреждён") from exc
    if not isinstance(values, list) or len(values) > 20:
        raise InventoryValidationError("можно добавить от 1 до 20 связанных устройств")
    drafts: list[dict[str, str]] = []
    for item in values:
        if not isinstance(item, dict):
            raise InventoryValidationError("черновик связанных устройств повреждён")
        try:
            asset_type = InventoryAssetType(str(item.get("asset_type") or ""))
        except ValueError as exc:
            raise InventoryValidationError("неверный тип связанного устройства") from exc
        if asset_type is InventoryAssetType.PC:
            raise InventoryValidationError("ПК нельзя добавить как связанное устройство")
        name = str(item.get("custom_name") or "").strip()
        drafts.append({"asset_type": asset_type.value, "custom_name": name or None})
    return drafts


def _status_form(value: str) -> InventoryAssetStatus | None:
    if not value:
        return None
    try:
        return InventoryAssetStatus(value)
    except ValueError as exc:
        raise InventoryValidationError("неверный статус устройства") from exc


async def _read_photo(upload: UploadFile, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise InventoryPhotoError("image size exceeds the limit")
        chunks.append(chunk)


@router.get("/inventory", response_class=HTMLResponse)
def inventory_home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    location = _current_location(request, db)
    tree = service.location_tree(db, location.id) if location else {"top_level_assets": [], "related_by_parent": {}}
    locations = list(db.scalars(select(InventoryLocation).order_by(InventoryLocation.name, InventoryLocation.id)))
    session_id = str(request.session.get("inventory_current_session_id") or "")
    walk_session = db.get(InventorySession, session_id) if session_id else None
    if walk_session is not None and walk_session.finished_at is not None:
        request.session.pop("inventory_current_session_id", None)
        walk_session = None
    return _render(
        request,
        "inventory.html",
        {
            "location": location,
            "locations": locations,
            "tree": tree,
            "asset_labels": ASSET_LABELS,
            "walk_session": walk_session,
            "show_new_location": bool(request.session.pop("inventory_location_form_open", False)),
        },
        db,
    )


@router.post("/inventory/locations")
async def inventory_create_location(request: Request, name: str = Form(default=""), comment: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    normalized_name = name.strip()
    if not normalized_name:
        request.session["inventory_location_form_open"] = True
        _flash(request, "bad", "Введите название локации")
        return _redirect("/inventory")
    location = service.create_location(db, name=normalized_name, comment=comment)
    request.session["inventory_current_location_id"] = location.id
    request.session.pop("inventory_location_form_open", None)
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
    if location_id == "__new__":
        request.session["inventory_location_form_open"] = True
        return _redirect("/inventory")
    if db.get(InventoryLocation, location_id) is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    request.session["inventory_current_location_id"] = location_id
    return _redirect("/inventory")


@router.get("/inventory/assets/new", response_class=HTMLResponse)
def inventory_new_asset(asset_type: InventoryAssetType = InventoryAssetType.PC, parent_asset_id: str = "", request: Request = None, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    location = _current_location(request, db)
    return _render(request, "inventory_asset_form.html", {"asset": None, "asset_type": asset_type, "parent_asset_id": parent_asset_id, "location": location, "asset_labels": ASSET_LABELS, "asset_status_labels": ASSET_STATUS_LABELS, "details": {}, "identifiers": {}, "asset_statuses": InventoryAssetStatus, "walk_session": None}, db)


@router.get("/inventory/assets/{asset_id}", response_class=HTMLResponse)
def inventory_asset_detail(asset_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    location = _current_location(request, db)
    photos = list(db.scalars(select(InventoryAssetPhoto).where(InventoryAssetPhoto.asset_id == asset.id).order_by(InventoryAssetPhoto.created_at, InventoryAssetPhoto.id)))
    identifiers = {item.identifier_type.value: item.value for item in service.identifiers_for(db, asset)}
    session_id = str(request.session.get("inventory_current_session_id") or "")
    walk_session = db.get(InventorySession, session_id) if session_id else None
    lookup_result = request.session.pop(f"inventory_lookup_{asset.id}", None)
    return _render(request, "inventory_asset_form.html", {"asset": asset, "asset_type": asset.asset_type, "parent_asset_id": "", "location": location, "asset_labels": ASSET_LABELS, "asset_status_labels": ASSET_STATUS_LABELS, "photos": photos, "details": service.details_for(db, asset), "identifiers": identifiers, "asset_statuses": InventoryAssetStatus, "walk_session": walk_session if walk_session and walk_session.finished_at is None else None, "lookup_result": lookup_result}, db)


@router.post("/inventory/assets")
async def inventory_create_asset(request: Request, asset_type: InventoryAssetType = Form(), custom_name: str = Form(default=""), manufacturer: str = Form(default=""), model: str = Form(default=""), serial_number: str = Form(default=""), inventory_number: str = Form(default=""), status: str = Form(default=""), assigned_person_name: str = Form(default=""), login_name: str = Form(default=""), description: str = Form(default=""), notes: str = Form(default=""), parent_asset_id: str = Form(default=""), related_devices_json: str = Form(default=""), save_next: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    location = _current_location(request, db)
    if location is None:
        _flash(request, "bad", "Сначала создайте локацию")
        return _redirect("/inventory")
    try:
        common_fields = {"custom_name": custom_name or None, "manufacturer": manufacturer or None, "model": model or None, "serial_number": serial_number or None, "inventory_number": inventory_number or None, "status": _status_form(status), "assigned_person_name": assigned_person_name or None, "login_name": login_name or None, "description": description or None, "notes": notes or None}
        drafts = _workplace_drafts(related_devices_json) if asset_type is InventoryAssetType.PC else []
        if drafts:
            asset, children = service.create_workplace(db, location_id=location.id, pc_fields=common_fields, child_payloads=drafts, actor=user.username)
            for child in children:
                write_audit(db, request, user, "inventory.relation.create", "ok", "WORKPLACE_DEVICE", target_client=child.id)
        else:
            asset = service.create_asset(db, asset_type, location_id=location.id, **common_fields)
        service.update_details(db, asset, await _detail_form(request, asset_type))
        service.sync_identifiers(db, asset, await _identifier_form(request))
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
async def inventory_update_asset(asset_id: str, request: Request, custom_name: str = Form(default=""), manufacturer: str = Form(default=""), model: str = Form(default=""), serial_number: str = Form(default=""), inventory_number: str = Form(default=""), status: str = Form(default=""), assigned_person_name: str = Form(default=""), login_name: str = Form(default=""), description: str = Form(default=""), notes: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    service.update_asset(asset, custom_name=custom_name or None, manufacturer=manufacturer or None, model=model or None, serial_number=serial_number or None, inventory_number=inventory_number or None, status=_status_form(status), assigned_person_name=assigned_person_name or None, login_name=login_name or None, description=description or None, notes=notes or None)
    service.update_details(db, asset, await _detail_form(request, asset.asset_type))
    service.sync_identifiers(db, asset, await _identifier_form(request))
    write_audit(db, request, user, "inventory.asset.update", "ok", asset.asset_type.value, target_client=asset.id)
    _flash(request, "ok", "Устройство обновлено")
    return _redirect(f"/inventory/assets/{asset.id}")


@router.post("/inventory/sessions")
async def inventory_start_session(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    session = InventorySession(created_by=user.username)
    db.add(session)
    db.flush()
    request.session["inventory_current_session_id"] = session.id
    write_audit(db, request, user, "inventory.session.start", "ok", "", target_client=session.id)
    _flash(request, "ok", "Обход начат")
    return _redirect("/inventory")


@router.post("/inventory/sessions/{session_id}/finish")
async def inventory_finish_session(session_id: str, request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    session = db.get(InventorySession, session_id)
    if session is None or session.finished_at is not None:
        _flash(request, "bad", "Обход не найден или уже завершён")
        return _redirect("/inventory")
    session.finished_at = datetime.now(timezone.utc)
    request.session.pop("inventory_current_session_id", None)
    write_audit(db, request, user, "inventory.session.finish", "ok", "", target_client=session.id)
    _flash(request, "ok", "Обход завершён")
    return _redirect("/inventory")


@router.post("/inventory/assets/{asset_id}/confirm")
async def inventory_confirm_asset(asset_id: str, request: Request, notes: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    session_id = str(request.session.get("inventory_current_session_id") or "")
    try:
        check = service.record_check(db, session_id=session_id, asset_id=asset_id, actor=user.username, result=InventoryCheckResult.CONFIRMED, notes=notes)
    except InventoryValidationError as exc:
        _flash(request, "bad", str(exc))
        return _redirect(f"/inventory/assets/{asset_id}")
    write_audit(db, request, user, "inventory.check.create", check.result.value, check.notes or "", target_client=check.id)
    _flash(request, "ok", "Устройство подтверждено в обходе")
    return _redirect(f"/inventory/assets/{asset_id}")


@router.post("/inventory/assets/{asset_id}/lookup")
async def inventory_lookup_asset(asset_id: str, request: Request, identifier: str = Form(), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    try:
        result = InventoryLookup(run_netctl).lookup(identifier, actor=user.username)
    except InventoryLookupError as exc:
        _flash(request, "bad", str(exc))
        return _redirect(f"/inventory/assets/{asset_id}")
    source = InventoryObservationSource.NMAP if result.source == "nmap" else InventoryObservationSource.NETCTL
    observation = service.record_observation(db, asset_id=asset.id, source=source, data=result.observation)
    write_audit(db, request, user, "inventory.lookup", result.status, result.source, target_client=observation.id)
    request.session[f"inventory_lookup_{asset.id}"] = {"status": result.status, "message": result.message, "suggestions": result.suggestions}
    return _redirect(f"/inventory/assets/{asset_id}")


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


@router.post("/inventory/assets/{asset_id}/photos")
async def inventory_upload_asset_photo(asset_id: str, request: Request, photo: UploadFile = File(), photo_type: InventoryPhotoType = Form(default=InventoryPhotoType.GENERAL), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    storage = _photo_storage()
    try:
        stored = storage.save(photo.filename or "", photo.content_type or "", await _read_photo(photo, storage.max_bytes))
    except InventoryPhotoError as exc:
        _flash(request, "bad", str(exc))
        return _redirect(f"/inventory/assets/{asset_id}")
    record = InventoryAssetPhoto(asset_id=asset.id, photo_type=photo_type, storage_path=stored.storage_path, original_filename=stored.original_filename, mime_type=stored.mime_type, size_bytes=stored.size_bytes, created_by=user.username)
    try:
        db.add(record)
        db.flush()
        write_audit(db, request, user, "inventory.photo.add", "ok", record.mime_type, target_client=record.id)
    except Exception:
        db.rollback()
        storage.cleanup_many((stored,))
        raise
    _flash(request, "ok", "Фотография добавлена")
    return _redirect(f"/inventory/assets/{asset_id}")


@router.get("/inventory/photos/{photo_id}")
def inventory_photo_read(photo_id: str, request: Request, db: Session = Depends(get_db)) -> FileResponse:
    require_user(request, db)
    photo = db.get(InventoryAssetPhoto, photo_id)
    if photo is None:
        raise HTTPException(status_code=404, detail="inventory photo not found")
    try:
        path = _photo_storage().path_for(photo.storage_path)
    except InventoryPhotoError as exc:
        raise HTTPException(status_code=404, detail="inventory photo not found") from exc
    if not path.is_file():
        raise HTTPException(status_code=404, detail="inventory photo is unavailable")
    return FileResponse(path, media_type=photo.mime_type, filename=photo.original_filename or "image")
