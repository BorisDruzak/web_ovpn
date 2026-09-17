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
from .lookup import InventoryLookup, InventoryLookupError, classify_identifier
from .models import (
    InventoryAsset,
    InventoryAssetPhoto,
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
MANUAL_RELATED_ASSET_TYPES = frozenset({
    InventoryAssetType.MONITOR,
    InventoryAssetType.PRINTER,
    InventoryAssetType.UPS,
    InventoryAssetType.OTHER,
})
MANUAL_LOCATION_ASSET_TYPES = frozenset({
    InventoryAssetType.MONITOR,
    InventoryAssetType.UPS,
    InventoryAssetType.OTHER,
})
DETAIL_FIELD_NAMES = {
    InventoryAssetType.PC: ("os_name", "cpu_model", "cpu_generation", "ram_type", "ram_gb", "storage_type", "storage_gb"),
    InventoryAssetType.PRINTER: ("page_counter", "connection_type"),
    InventoryAssetType.PHONE: ("extension",),
    InventoryAssetType.MONITOR: ("diagonal_inches",),
    InventoryAssetType.UPS: ("power_va", "battery_replaced_at"),
}
NEW_ASSET_FORM_FIELDS = (
    "custom_name", "manufacturer", "model", "serial_number", "inventory_number", "status",
    "assigned_person_name", "login_name", "description", "notes", "ip_address", "mac_address", "hostname",
    "os_name", "cpu_model", "cpu_generation", "ram_type", "ram_gb", "storage_type", "storage_gb",
    "page_counter", "connection_type", "extension", "diagonal_inches", "power_va", "battery_replaced_at", "related_devices_json",
)
IDENTIFIER_FIELD_LABELS = {
    "ip_address": "IP-адрес",
    "mac_address": "MAC-адрес",
    "hostname": "hostname",
}
LOOKUP_STATUS_LABELS = {
    "found": "Найдено",
    "not_found": "Не найдено",
    "unavailable": "Поиск недоступен",
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


def _location_url(location_id: str) -> str:
    return f"/inventory/locations/{location_id}"


def _location_or_error(db: Session, location_id: str) -> InventoryLocation:
    location = db.get(InventoryLocation, location_id)
    if location is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    return location


def _flow_location(request: Request, db: Session, location_id: str) -> InventoryLocation | None:
    return _location_or_error(db, location_id) if location_id else _current_location(request, db)


def _asset_url(asset_id: str, return_location_id: str = "") -> str:
    suffix = f"?location_id={return_location_id}" if return_location_id else ""
    return f"/inventory/assets/{asset_id}{suffix}"


def _photo_storage() -> InventoryPhotoStorage:
    settings = get_settings()
    return InventoryPhotoStorage(settings.inventory_photo_root, max_bytes=settings.inventory_photo_max_bytes)


def _new_asset_url(asset_type: InventoryAssetType, parent_asset_id: str = "", manual: bool = False, location_id: str = "") -> str:
    suffix = f"&location_id={location_id}" if location_id else ""
    if parent_asset_id:
        suffix += f"&parent_asset_id={parent_asset_id}"
    if manual:
        suffix += "&manual=1"
    return f"/inventory/assets/new?asset_type={asset_type.value}{suffix}"


def _new_asset_flow_key(asset_type: InventoryAssetType, parent_asset_id: str, location_id: str = "") -> str:
    return f"inventory_new_asset_flow:{asset_type.value}:{location_id}:{parent_asset_id}"


def _new_asset_draft_key(asset_type: InventoryAssetType, parent_asset_id: str, location_id: str = "") -> str:
    return f"{_new_asset_flow_key(asset_type, parent_asset_id, location_id)}:draft"


def _asset_edit_draft_key(asset_id: str) -> str:
    return f"inventory_asset_edit_draft:{asset_id}"


def _is_direct_manual_asset(asset_type: InventoryAssetType, parent_asset: InventoryAsset | None, manual: bool) -> bool:
    if not manual:
        return False
    allowed_types = MANUAL_RELATED_ASSET_TYPES if parent_asset is not None else MANUAL_LOCATION_ASSET_TYPES
    return asset_type in allowed_types


async def _new_asset_form_draft(request: Request) -> dict[str, str]:
    form = await request.form()
    return {field: str(form.get(field) or "") for field in NEW_ASSET_FORM_FIELDS if field in form}


def _new_asset_form_context(
    *,
    asset_type: InventoryAssetType,
    parent_asset_id: str,
    manual_mode: bool,
    location: InventoryLocation,
    flow: dict[str, Any] | None,
    draft: dict[str, str] | None,
) -> dict[str, Any]:
    suggestions = flow.get("suggestions") if isinstance(flow, dict) and isinstance(flow.get("suggestions"), dict) else {}
    details = flow.get("details") if isinstance(flow, dict) and isinstance(flow.get("details"), dict) else {}
    values = {
        "custom_name": str(suggestions.get("custom_name") or suggestions.get("display_name") or ""),
        "manufacturer": str(suggestions.get("manufacturer") or ""),
        "model": str(suggestions.get("model") or ""),
        "serial_number": str(suggestions.get("serial_number") or ""),
        "inventory_number": str(suggestions.get("inventory_number") or ""),
        "status": str(suggestions.get("status") or ""),
        "assigned_person_name": str(suggestions.get("assigned_person_name") or ""),
        "login_name": str(suggestions.get("login_name") or ""),
        "description": str(suggestions.get("description") or ""),
        "notes": str(suggestions.get("notes") or ""),
    }
    identifiers = {key: str(suggestions.get(key) or "") for key in ("ip", "mac", "hostname")}
    if draft:
        values.update({field: draft[field] for field in values if field in draft})
        identifiers.update({identifier: draft[field] for field, identifier in (("ip_address", "ip"), ("mac_address", "mac"), ("hostname", "hostname")) if field in draft})
        details = {**details, **{field: draft[field] for field in DETAIL_FIELD_NAMES.get(asset_type, ()) if field in draft}}
    return {
        "asset": None,
        "asset_type": asset_type,
        "parent_asset_id": parent_asset_id,
        "manual_mode": manual_mode,
        "location": location,
        "return_location_id": location.id,
        "asset_labels": ASSET_LABELS,
        "asset_status_labels": ASSET_STATUS_LABELS,
        "form_values": values,
        "details": details,
        "identifiers": identifiers,
        "prefill": {"custom_name": values["custom_name"]},
        "asset_statuses": InventoryAssetStatus,
        "walk_session": None,
        "prelookup": {"source": "manual", "message": "Заполните полную карточку устройства вручную."} if manual_mode else flow,
    }


def _augment_printer_suggestions(
    suggestions: dict[str, str], details: dict[str, Any]
) -> dict[str, Any] | None:
    """Add bounded printer SNMP values without replacing fresher collection identity."""
    target_ip = suggestions.get("ip")
    if not target_ip:
        return None
    try:
        payload = run_netctl(["printer", "inspect-ip", "--target", target_ip], 20)
    except Exception:
        return None
    printer = payload.get("printer") if isinstance(payload, dict) else None
    if not isinstance(printer, dict) or printer.get("status") != "found":
        return None
    discovered = printer.get("suggestions")
    accepted: dict[str, str] = {}
    if isinstance(discovered, dict):
        for key in ("model", "serial_number", "description", "mac"):
            value = discovered.get(key)
            if not isinstance(value, str) or not value or suggestions.get(key):
                continue
            suggestions[key] = value
            accepted[key] = value
    printer_details = printer.get("details")
    accepted_details: dict[str, int] = {}
    if isinstance(printer_details, dict):
        page_counter = printer_details.get("page_counter")
        if (
            isinstance(page_counter, int)
            and not isinstance(page_counter, bool)
            and page_counter >= 0
            and "page_counter" not in details
        ):
            details["page_counter"] = page_counter
            accepted_details["page_counter"] = page_counter
    version = printer.get("snmp_version")
    return {
        "status": "found",
        "snmp_version": version if isinstance(version, str) else "",
        "suggestions": accepted,
        "details": accepted_details,
    }


def _related_parent_or_error(db: Session, parent_asset_id: str, location: InventoryLocation | None = None) -> InventoryAsset | None:
    if not parent_asset_id:
        return None
    parent = db.get(InventoryAsset, parent_asset_id)
    if parent is None or parent.asset_type is not InventoryAssetType.PC:
        raise HTTPException(status_code=404, detail="inventory parent asset not found")
    if location is not None and parent.location_id != location.id:
        raise HTTPException(status_code=404, detail="inventory parent asset not found")
    return parent


async def _detail_form(request: Request, asset_type: InventoryAssetType) -> dict[str, Any]:
    form = await request.form()
    names = DETAIL_FIELD_NAMES.get(asset_type, ())
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
    identifiers: list[dict[str, str]] = []
    for field, identifier_type in names:
        value = str(form.get(field) or "").strip()
        if not value:
            continue
        try:
            actual_type, _ = classify_identifier(value)
        except InventoryLookupError as exc:
            raise InventoryValidationError(
                f"Проверьте поле «{IDENTIFIER_FIELD_LABELS[field]}»: значение имеет неверный формат."
            ) from exc
        if actual_type != identifier_type.value:
            raise InventoryValidationError(
                f"Проверьте поле «{IDENTIFIER_FIELD_LABELS[field]}»: значение имеет неверный формат."
            )
        identifiers.append(
            {"identifier_type": identifier_type.value, "value": value, "source": InventoryObservationSource.MANUAL.value}
        )
    return identifiers


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
    locations = list(db.scalars(select(InventoryLocation).order_by(InventoryLocation.name, InventoryLocation.id)))
    return _render(request, "inventory.html", {"locations": locations}, db)


@router.get("/inventory/locations/new", response_class=HTMLResponse)
def inventory_new_location(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    return _render(request, "inventory_location_form.html", {}, db)


@router.get("/inventory/locations/{location_id}", response_class=HTMLResponse)
def inventory_location_detail(location_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    tree = service.location_tree(db, location_id)
    if tree["location"] is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    request.session["inventory_current_location_id"] = location_id
    return _render(request, "inventory_location_detail.html", {"location": tree["location"], "tree": tree, "asset_labels": ASSET_LABELS}, db)


@router.post("/inventory/locations")
async def inventory_create_location(request: Request, name: str = Form(default=""), comment: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    normalized_name = name.strip()
    if not normalized_name:
        _flash(request, "bad", "Введите название локации")
        return _redirect("/inventory/locations/new")
    location = service.create_location(db, name=normalized_name, comment=comment)
    request.session["inventory_current_location_id"] = location.id
    write_audit(db, request, user, "inventory.location.create", "ok", location.name or "", target_client=location.id)
    _flash(request, "ok", "Локация сохранена")
    return _redirect(f"/inventory/locations/{location.id}")


@router.post("/inventory/locations/{location_id}")
async def inventory_update_location(location_id: str, request: Request, name: str = Form(default=""), comment: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    location = db.get(InventoryLocation, location_id)
    if location is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    normalized_name = name.strip()
    if not normalized_name:
        _flash(request, "bad", "Введите название локации")
        return _redirect(f"/inventory/locations/{location.id}")
    service.update_location(location, name=normalized_name, comment=comment)
    write_audit(db, request, user, "inventory.location.update", "ok", location.name or "", target_client=location.id)
    _flash(request, "ok", "Локация обновлена")
    return _redirect(f"/inventory/locations/{location.id}")


@router.post("/inventory/location/select")
async def inventory_select_location(request: Request, location_id: str = Form(), db: Session = Depends(get_db)) -> RedirectResponse:
    require_user(request, db)
    await verify_csrf(request)
    if location_id == "__new__":
        return _redirect("/inventory/locations/new")
    if db.get(InventoryLocation, location_id) is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    request.session["inventory_current_location_id"] = location_id
    return _redirect(f"/inventory/locations/{location_id}")


@router.get("/inventory/assets/new", response_class=HTMLResponse)
def inventory_new_asset(asset_type: InventoryAssetType = InventoryAssetType.PC, location_id: str = "", parent_asset_id: str = "", manual: bool = False, request: Request = None, db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    location = _flow_location(request, db, location_id)
    parent_asset = _related_parent_or_error(db, parent_asset_id, location if location_id else None)
    if parent_asset is not None and (location is None or parent_asset.location_id != location.id):
        location = _location_or_error(db, parent_asset.location_id)
    return_location_id = location.id if location is not None else ""
    manual_mode = location is not None and _is_direct_manual_asset(asset_type, parent_asset, manual)
    draft = request.session.get(_new_asset_draft_key(asset_type, parent_asset_id, return_location_id))
    draft = draft if isinstance(draft, dict) else None
    if manual_mode:
        return _render(request, "inventory_asset_form.html", _new_asset_form_context(asset_type=asset_type, parent_asset_id=parent_asset_id, manual_mode=True, location=location, flow=None, draft=draft), db)
    flow = request.session.get(_new_asset_flow_key(asset_type, parent_asset_id, return_location_id))
    if not isinstance(flow, dict) or not flow.get("ready"):
        return _render(request, "inventory_asset_discovery.html", {"asset_type": asset_type, "parent_asset_id": parent_asset_id, "parent_asset": parent_asset, "location": location, "return_location_id": return_location_id, "asset_labels": ASSET_LABELS, "lookup_status_labels": LOOKUP_STATUS_LABELS, "lookup_result": flow}, db)
    return _render(request, "inventory_asset_form.html", _new_asset_form_context(asset_type=asset_type, parent_asset_id=parent_asset_id, manual_mode=False, location=location, flow=flow, draft=draft), db)


@router.get("/inventory/assets/{asset_id}/related/new", response_class=HTMLResponse)
def inventory_related_asset_picker(asset_id: str, request: Request, location_id: str = "", db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    location = _flow_location(request, db, location_id)
    parent_asset = _related_parent_or_error(db, asset_id, location if location_id else None)
    if location is None or parent_asset.location_id != location.id:
        location = _location_or_error(db, parent_asset.location_id)
    return _render(request, "inventory_related_asset_picker.html", {"parent_asset": parent_asset, "return_location_id": location.id, "asset_labels": ASSET_LABELS}, db)


@router.post("/inventory/assets/new/lookup")
async def inventory_lookup_new_asset(request: Request, asset_type: InventoryAssetType = Form(), location_id: str = Form(default=""), parent_asset_id: str = Form(default=""), identifier: str = Form(), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    location = _flow_location(request, db, location_id)
    parent_asset = _related_parent_or_error(db, parent_asset_id, location if location_id else None)
    if parent_asset is not None and (location is None or parent_asset.location_id != location.id):
        location = _location_or_error(db, parent_asset.location_id)
    target_url = _new_asset_url(asset_type, parent_asset_id, location_id=location.id if location is not None else "")
    if location is None:
        _flash(request, "bad", "Сначала создайте локацию")
        return _redirect("/inventory")
    try:
        result = InventoryLookup(run_netctl).lookup(identifier, actor=user.username)
    except InventoryLookupError as exc:
        _flash(request, "bad", str(exc))
        return _redirect(target_url)
    suggestions = dict(result.suggestions)
    details = {field: value for field, value in result.suggestions.items() if field == "os_name"}
    printer_snmp = (
        _augment_printer_suggestions(suggestions, details)
        if asset_type is InventoryAssetType.PRINTER and result.status == "found"
        else None
    )
    source = InventoryObservationSource.NMAP if result.source == "nmap" else InventoryObservationSource.NETCTL
    observation_data = dict(result.observation)
    if printer_snmp is not None:
        observation_data["printer_snmp"] = printer_snmp
    observation = service.record_observation(db, asset_id=None, source=source, data=observation_data)
    write_audit(db, request, user, "inventory.lookup", result.status, result.source, target_client=observation.id)
    request.session[_new_asset_flow_key(asset_type, parent_asset_id, location.id)] = {
        "status": result.status,
        "source": result.source,
        "message": result.message,
        "suggestions": suggestions,
        "details": details,
        "identifier": identifier.strip(),
        "ready": result.status == "found",
    }
    request.session.pop(_new_asset_draft_key(asset_type, parent_asset_id, location.id), None)
    return _redirect(target_url)


@router.post("/inventory/assets/new/manual")
async def inventory_continue_new_asset_manually(request: Request, asset_type: InventoryAssetType = Form(), location_id: str = Form(default=""), parent_asset_id: str = Form(default=""), identifier: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    require_user(request, db)
    await verify_csrf(request)
    location = _flow_location(request, db, location_id)
    if location is None:
        _flash(request, "bad", "Сначала создайте локацию")
        return _redirect("/inventory")
    parent_asset = _related_parent_or_error(db, parent_asset_id, location if location_id else None)
    if parent_asset is not None and parent_asset.location_id != location.id:
        location = _location_or_error(db, parent_asset.location_id)
    target_url = _new_asset_url(asset_type, parent_asset_id, location_id=location.id)
    flow = request.session.get(_new_asset_flow_key(asset_type, parent_asset_id, location.id))
    if parent_asset is None and (not isinstance(flow, dict) or flow.get("status") not in {"not_found", "unavailable"}):
        _flash(request, "bad", "Сначала выполните поиск устройства")
        return _redirect(target_url)
    if not isinstance(flow, dict):
        flow = {"identifier": identifier.strip()}
    try:
        identifier_type, normalized = classify_identifier(identifier)
    except InventoryLookupError:
        identifier_type, normalized = "hostname", ""
    flow.update({"ready": True, "source": "manual", "message": "Данные не найдены: заполните карточку вручную.", "suggestions": {identifier_type: normalized} if normalized else {}})
    request.session[_new_asset_flow_key(asset_type, parent_asset_id, location.id)] = flow
    return _redirect(target_url)


@router.get("/inventory/assets/{asset_id}", response_class=HTMLResponse)
def inventory_asset_detail(asset_id: str, request: Request, location_id: str = "", db: Session = Depends(get_db)) -> HTMLResponse:
    require_user(request, db)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    location = _flow_location(request, db, location_id)
    if location_id and location is not None and asset.location_id != location.id:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    if asset.location_id is None:
        location = None
    elif location is None or location.id != asset.location_id:
        location = _location_or_error(db, asset.location_id)
    photos = list(db.scalars(select(InventoryAssetPhoto).where(InventoryAssetPhoto.asset_id == asset.id).order_by(InventoryAssetPhoto.created_at, InventoryAssetPhoto.id)))
    identifiers = {item.identifier_type.value: item.value for item in service.identifiers_for(db, asset)}
    form_values = {field: str(getattr(asset, field) or "") for field in ("custom_name", "manufacturer", "model", "serial_number", "inventory_number", "assigned_person_name", "login_name", "description", "notes")}
    form_values["status"] = asset.status.value if asset.status is not None else ""
    details = service.details_for(db, asset)
    draft = request.session.get(_asset_edit_draft_key(asset.id))
    if isinstance(draft, dict):
        form_values.update({field: draft[field] for field in form_values if field in draft})
        identifiers.update({identifier: draft[field] for field, identifier in (("ip_address", "ip"), ("mac_address", "mac"), ("hostname", "hostname")) if field in draft})
        details = {**details, **{field: draft[field] for field in DETAIL_FIELD_NAMES.get(asset.asset_type, ()) if field in draft}}
    return _render(request, "inventory_asset_form.html", {"asset": asset, "asset_type": asset.asset_type, "parent_asset_id": "", "manual_mode": False, "location": location, "return_location_id": location.id if location is not None else "", "asset_labels": ASSET_LABELS, "asset_status_labels": ASSET_STATUS_LABELS, "photos": photos, "form_values": form_values, "details": details, "identifiers": identifiers, "prefill": {}, "asset_statuses": InventoryAssetStatus, "prelookup": None}, db)


@router.post("/inventory/assets")
async def inventory_create_asset(request: Request, asset_type: InventoryAssetType = Form(), custom_name: str = Form(default=""), manufacturer: str = Form(default=""), model: str = Form(default=""), serial_number: str = Form(default=""), inventory_number: str = Form(default=""), status: str = Form(default=""), assigned_person_name: str = Form(default=""), login_name: str = Form(default=""), description: str = Form(default=""), notes: str = Form(default=""), return_location_id: str = Form(default=""), parent_asset_id: str = Form(default=""), manual_mode: str = Form(default=""), related_devices_json: str = Form(default=""), save_next: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    has_explicit_return = bool(return_location_id)
    location = _flow_location(request, db, return_location_id)
    if location is None:
        _flash(request, "bad", "Сначала создайте локацию")
        return _redirect("/inventory")
    parent_asset = _related_parent_or_error(db, parent_asset_id, location if return_location_id else None)
    if parent_asset is not None and parent_asset.location_id != location.id:
        location = _location_or_error(db, parent_asset.location_id)
    flow_key = _new_asset_flow_key(asset_type, parent_asset_id, location.id)
    flow = request.session.get(flow_key)
    direct_manual = _is_direct_manual_asset(asset_type, parent_asset, manual_mode == "1")
    submitted_draft = await _new_asset_form_draft(request)
    if not direct_manual and (not isinstance(flow, dict) or not flow.get("ready")):
        _flash(request, "bad", "Сначала выполните поиск или выберите ручное заполнение")
        return _redirect(_new_asset_url(asset_type, parent_asset_id, location_id=location.id if has_explicit_return else ""))
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
        if parent_asset:
            service.attach_existing_asset(db, parent_asset.id, asset.id, actor=user.username)
            write_audit(db, request, user, "inventory.relation.create", "ok", "WORKPLACE_DEVICE", target_client=asset.id)
    except InventoryValidationError as exc:
        request.session[_new_asset_draft_key(asset_type, parent_asset_id, location.id)] = submitted_draft
        _flash(request, "bad", str(exc))
        return _redirect(_new_asset_url(asset_type, parent_asset_id, manual=direct_manual, location_id=location.id if has_explicit_return else ""))
    write_audit(db, request, user, "inventory.asset.create", "ok", asset.asset_type.value, target_client=asset.id)
    request.session.pop(flow_key, None)
    request.session.pop(_new_asset_draft_key(asset_type, parent_asset_id, location.id), None)
    _flash(request, "ok", "Устройство сохранено")
    if save_next:
        return _redirect(_new_asset_url(asset_type, location_id=location.id if has_explicit_return else ""))
    return _redirect(_location_url(location.id) if has_explicit_return else _asset_url(asset.id))


@router.post("/inventory/assets/{asset_id}")
async def inventory_update_asset(asset_id: str, request: Request, custom_name: str = Form(default=""), manufacturer: str = Form(default=""), model: str = Form(default=""), serial_number: str = Form(default=""), inventory_number: str = Form(default=""), status: str = Form(default=""), assigned_person_name: str = Form(default=""), login_name: str = Form(default=""), description: str = Form(default=""), notes: str = Form(default=""), return_location_id: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    if return_location_id:
        location = _location_or_error(db, return_location_id)
        if asset.location_id != location.id:
            raise HTTPException(status_code=404, detail="inventory asset not found")
    submitted_draft = await _new_asset_form_draft(request)
    try:
        service.update_asset(asset, custom_name=custom_name or None, manufacturer=manufacturer or None, model=model or None, serial_number=serial_number or None, inventory_number=inventory_number or None, status=_status_form(status), assigned_person_name=assigned_person_name or None, login_name=login_name or None, description=description or None, notes=notes or None)
        service.update_details(db, asset, await _detail_form(request, asset.asset_type))
        service.sync_identifiers(db, asset, await _identifier_form(request))
    except InventoryValidationError as exc:
        request.session[_asset_edit_draft_key(asset.id)] = submitted_draft
        _flash(request, "bad", str(exc))
        return _redirect(_asset_url(asset.id, return_location_id))
    write_audit(db, request, user, "inventory.asset.update", "ok", asset.asset_type.value, target_client=asset.id)
    request.session.pop(_asset_edit_draft_key(asset.id), None)
    _flash(request, "ok", "Устройство обновлено")
    return _redirect(_location_url(return_location_id) if return_location_id else _asset_url(asset.id))


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
async def inventory_confirm_asset(asset_id: str, request: Request, notes: str = Form(default=""), return_location_id: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    session_id = str(request.session.get("inventory_current_session_id") or "")
    try:
        check = service.record_check(db, session_id=session_id, asset_id=asset_id, actor=user.username, result=InventoryCheckResult.CONFIRMED, notes=notes)
    except InventoryValidationError as exc:
        _flash(request, "bad", str(exc))
        return _redirect(_asset_url(asset_id, return_location_id))
    write_audit(db, request, user, "inventory.check.create", check.result.value, check.notes or "", target_client=check.id)
    _flash(request, "ok", "Устройство подтверждено в обходе")
    return _redirect(_asset_url(asset_id, return_location_id))


@router.post("/inventory/assets/{asset_id}/lookup")
async def inventory_lookup_asset(asset_id: str, request: Request, identifier: str = Form(), return_location_id: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    if return_location_id:
        location = _location_or_error(db, return_location_id)
        if asset.location_id != location.id:
            raise HTTPException(status_code=404, detail="inventory asset not found")
    try:
        result = InventoryLookup(run_netctl).lookup(identifier, actor=user.username)
    except InventoryLookupError as exc:
        _flash(request, "bad", str(exc))
        return _redirect(_asset_url(asset_id, return_location_id))
    source = InventoryObservationSource.NMAP if result.source == "nmap" else InventoryObservationSource.NETCTL
    observation = service.record_observation(db, asset_id=asset.id, source=source, data=result.observation)
    write_audit(db, request, user, "inventory.lookup", result.status, result.source, target_client=observation.id)
    request.session[f"inventory_lookup_{asset.id}"] = {"status": result.status, "message": result.message, "suggestions": result.suggestions}
    return _redirect(_asset_url(asset_id, return_location_id))


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
async def inventory_upload_asset_photo(asset_id: str, request: Request, photo: UploadFile = File(), photo_type: InventoryPhotoType = Form(default=InventoryPhotoType.GENERAL), return_location_id: str = Form(default=""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = require_user(request, db)
    await verify_csrf(request)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    if return_location_id:
        location = _location_or_error(db, return_location_id)
        if asset.location_id != location.id:
            raise HTTPException(status_code=404, detail="inventory asset not found")
    storage = _photo_storage()
    try:
        stored = storage.save(photo.filename or "", photo.content_type or "", await _read_photo(photo, storage.max_bytes))
    except InventoryPhotoError as exc:
        _flash(request, "bad", str(exc))
        return _redirect(_asset_url(asset_id, return_location_id))
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
    return _redirect(_asset_url(asset_id, return_location_id))


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
