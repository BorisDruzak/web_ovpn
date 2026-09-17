from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..api import require_api_actor
from ..audit import write_audit
from ..auth import verify_api_csrf
from ..config import get_settings
from ..db import get_db
from ..netctl_client import run_netctl
from .lookup import InventoryLookup, InventoryLookupError
from .models import InventoryAsset, InventoryAssetPhoto, InventoryAssetRelation, InventoryLocation, InventoryObservationSource, InventoryPhotoType, InventorySession
from .schemas import AssetPayload, AssetUpdate, LocationCreate, LocationUpdate, LookupRequest, RelationCreate, SessionCheckCreate, WorkplaceCreate
from .service import InventoryService, InventoryValidationError
from .storage import InventoryPhotoError, InventoryPhotoStorage, StoredPhoto


router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])
service = InventoryService()


def _asset_dict(asset: InventoryAsset, db: Session | None = None) -> dict[str, Any]:
    data = {
        "id": asset.id,
        "asset_type": asset.asset_type.value,
        "location_id": asset.location_id,
        "custom_name": asset.custom_name,
        "manufacturer": asset.manufacturer,
        "model": asset.model,
        "serial_number": asset.serial_number,
        "inventory_number": asset.inventory_number,
        "status": asset.status.value if asset.status else None,
        "assigned_person_name": asset.assigned_person_name,
        "login_name": asset.login_name,
        "description": asset.description,
        "last_verified_at": asset.last_verified_at.isoformat() if asset.last_verified_at else None,
    }
    if db is not None:
        data["details"] = service.details_for(db, asset)
        data["identifiers"] = [
            {"identifier_type": item.identifier_type.value, "value": item.value, "normalized_value": item.normalized_value, "source": item.source.value, "is_current": item.is_current}
            for item in service.identifiers_for(db, asset)
        ]
    return data


def _location_dict(location: InventoryLocation) -> dict[str, Any]:
    return {"id": location.id, "name": location.name, "comment": location.comment}


def _relation_dict(relation: InventoryAssetRelation) -> dict[str, Any]:
    return {
        "id": relation.id,
        "parent_asset_id": relation.parent_asset_id,
        "child_asset_id": relation.child_asset_id,
        "relation_type": relation.relation_type,
        "ended_at": relation.ended_at.isoformat() if relation.ended_at else None,
    }


def _mutation(request: Request, csrf: str | None) -> None:
    verify_api_csrf(request, csrf)


def _photo_dict(photo: InventoryAssetPhoto) -> dict[str, Any]:
    return {"id": photo.id, "asset_id": photo.asset_id, "photo_type": photo.photo_type.value, "original_filename": photo.original_filename, "mime_type": photo.mime_type, "size_bytes": photo.size_bytes}


def _photo_storage() -> InventoryPhotoStorage:
    settings = get_settings()
    return InventoryPhotoStorage(settings.inventory_photo_root, max_bytes=settings.inventory_photo_max_bytes)


async def _read_upload(upload: UploadFile, limit: int) -> bytes:
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


def _validation_error(exc: InventoryValidationError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


@router.get("/locations")
def list_locations(actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    del actor
    return {"status": "ok", "data": [_location_dict(item) for item in db.scalars(select(InventoryLocation).order_by(InventoryLocation.name, InventoryLocation.id))]}


@router.post("/locations", status_code=status.HTTP_201_CREATED)
def create_location(payload: LocationCreate, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    location = service.create_location(db, name=payload.name, comment=payload.comment)
    write_audit(db, request, actor, "inventory.location.create", "ok", location.name or "", target_client=location.id)
    return {"status": "ok", "data": _location_dict(location)}


@router.get("/locations/{location_id}")
def get_location(location_id: str, actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    del actor
    location = db.get(InventoryLocation, location_id)
    if location is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    return {"status": "ok", "data": _location_dict(location)}


@router.patch("/locations/{location_id}")
def update_location(location_id: str, payload: LocationUpdate, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    location = db.get(InventoryLocation, location_id)
    if location is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    service.update_location(location, name=payload.name, comment=payload.comment)
    write_audit(db, request, actor, "inventory.location.update", "ok", location.name or "", target_client=location.id)
    return {"status": "ok", "data": _location_dict(location)}


@router.get("/locations/{location_id}/tree")
def location_tree(location_id: str, actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    del actor
    tree = service.location_tree(db, location_id)
    if tree["location"] is None:
        raise HTTPException(status_code=404, detail="inventory location not found")
    return {"status": "ok", "data": {"location": _location_dict(tree["location"]), "top_level_assets": [_asset_dict(item, db) for item in tree["top_level_assets"]], "related_by_parent": {parent: [_asset_dict(item, db) for item in children] for parent, children in tree["related_by_parent"].items()}}}


@router.get("/assets")
def list_assets(location_id: str | None = None, actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    del actor
    statement = select(InventoryAsset).order_by(InventoryAsset.created_at, InventoryAsset.id)
    if location_id is not None:
        statement = statement.where(InventoryAsset.location_id == location_id)
    return {"status": "ok", "data": [_asset_dict(item, db) for item in db.scalars(statement)]}


@router.post("/assets", status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetPayload, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    try:
        asset = service.create_asset(db, payload.asset_type, location_id=payload.location_id, **payload.asset_fields())
        service.update_details(db, asset, payload.details)
        if payload.identifiers is not None:
            service.sync_identifiers(db, asset, payload.identifiers)
    except InventoryValidationError as exc:
        raise _validation_error(exc) from exc
    write_audit(db, request, actor, "inventory.asset.create", "ok", asset.asset_type.value, target_client=asset.id)
    return {"status": "ok", "data": _asset_dict(asset, db)}


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str, actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    del actor
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    return {"status": "ok", "data": _asset_dict(asset, db)}


@router.patch("/assets/{asset_id}")
def update_asset(asset_id: str, payload: AssetUpdate, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    try:
        service.update_asset(asset, **payload.asset_fields())
        service.update_details(db, asset, payload.details)
        if payload.identifiers is not None:
            service.sync_identifiers(db, asset, payload.identifiers)
    except InventoryValidationError as exc:
        raise _validation_error(exc) from exc
    write_audit(db, request, actor, "inventory.asset.update", "ok", asset.asset_type.value, target_client=asset.id)
    return {"status": "ok", "data": _asset_dict(asset, db)}


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: str, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    active_relation = db.scalar(select(InventoryAssetRelation).where((InventoryAssetRelation.parent_asset_id == asset_id) | (InventoryAssetRelation.child_asset_id == asset_id), InventoryAssetRelation.ended_at.is_(None)))
    if active_relation is not None:
        raise HTTPException(status_code=409, detail="end active inventory relations before deleting asset")
    db.delete(asset)
    write_audit(db, request, actor, "inventory.asset.delete", "ok", "", target_client=asset_id)
    return {"status": "ok", "data": {"id": asset_id}}


@router.post("/workplaces", status_code=status.HTTP_201_CREATED)
def create_workplace(payload: WorkplaceCreate, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    if payload.pc.asset_type.value != "PC":
        raise HTTPException(status_code=400, detail="workplace PC payload must have PC asset type")
    try:
        pc, children = service.create_workplace(
            db,
            location_id=payload.location_id,
            pc_fields=payload.pc.asset_fields(),
            child_payloads=[{"asset_type": child.asset_type, **child.asset_fields()} for child in payload.children],
            actor=actor,
        )
        service.update_details(db, pc, payload.pc.details)
        if payload.pc.identifiers is not None:
            service.sync_identifiers(db, pc, payload.pc.identifiers)
        for child, child_payload in zip(children, payload.children, strict=True):
            service.update_details(db, child, child_payload.details)
            if child_payload.identifiers is not None:
                service.sync_identifiers(db, child, child_payload.identifiers)
    except InventoryValidationError as exc:
        raise _validation_error(exc) from exc
    relations = list(db.scalars(select(InventoryAssetRelation).where(InventoryAssetRelation.parent_asset_id == pc.id, InventoryAssetRelation.ended_at.is_(None))))
    write_audit(db, request, actor, "inventory.asset.create", "ok", "PC workplace", target_client=pc.id)
    for relation in relations:
        write_audit(db, request, actor, "inventory.relation.create", "ok", relation.relation_type, target_client=relation.id)
    return {"status": "ok", "data": {"pc": _asset_dict(pc, db), "children": [_asset_dict(child, db) for child in children], "relations": [_relation_dict(item) for item in relations]}}


@router.post("/relations", status_code=status.HTTP_201_CREATED)
def attach_relation(payload: RelationCreate, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    try:
        relation = service.attach_existing_asset(db, payload.parent_asset_id, payload.child_asset_id, actor=actor, note=payload.note)
    except InventoryValidationError as exc:
        raise _validation_error(exc) from exc
    write_audit(db, request, actor, "inventory.relation.create", "ok", relation.relation_type, target_client=relation.id)
    return {"status": "ok", "data": _relation_dict(relation)}


@router.delete("/relations/{relation_id}")
def detach_relation(relation_id: str, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    try:
        relation = service.detach_relation(db, relation_id)
    except InventoryValidationError as exc:
        raise _validation_error(exc) from exc
    write_audit(db, request, actor, "inventory.relation.end", "ok", "", target_client=relation.id)
    return {"status": "ok", "data": _relation_dict(relation)}


@router.post("/lookup")
def lookup(payload: LookupRequest, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    try:
        result = InventoryLookup(run_netctl).lookup(payload.identifier, actor=actor)
    except InventoryLookupError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    source = InventoryObservationSource.NMAP if result.source == "nmap" else InventoryObservationSource.NETCTL
    observation = service.record_observation(db, asset_id=payload.asset_id, source=source, data=result.observation)
    write_audit(db, request, actor, "inventory.lookup", result.status, result.source, target_client=observation.id)
    return {"status": "ok", "data": {"status": result.status, "source": result.source, "suggestions": result.suggestions, "observation": result.observation, "message": result.message}}


@router.post("/sessions", status_code=status.HTTP_201_CREATED)
def start_session(request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    session = InventorySession(created_by=actor)
    db.add(session)
    db.flush()
    write_audit(db, request, actor, "inventory.session.start", "ok", "", target_client=session.id)
    return {"status": "ok", "data": {"id": session.id, "started_at": session.started_at.isoformat()}}


@router.post("/sessions/{session_id}/checks", status_code=status.HTTP_201_CREATED)
def create_session_check(session_id: str, payload: SessionCheckCreate, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    try:
        check = service.record_check(db, session_id=session_id, asset_id=payload.asset_id, actor=actor, result=payload.result, location_id=payload.location_id, notes=payload.notes)
    except InventoryValidationError as exc:
        raise _validation_error(exc) from exc
    write_audit(db, request, actor, "inventory.check.create", check.result.value, check.notes or "", target_client=check.id)
    return {"status": "ok", "data": {"id": check.id, "session_id": check.session_id, "asset_id": check.asset_id, "location_id": check.location_id, "result": check.result.value, "checked_at": check.checked_at.isoformat()}}


@router.post("/assets/{asset_id}/photos", status_code=status.HTTP_201_CREATED)
async def upload_asset_photo(asset_id: str, request: Request, photo: UploadFile = File(), photo_type: InventoryPhotoType = Form(default=InventoryPhotoType.GENERAL), csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    asset = db.get(InventoryAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="inventory asset not found")
    storage = _photo_storage()
    try:
        content = await _read_upload(photo, storage.max_bytes)
        stored = storage.save(photo.filename or "", photo.content_type or "", content)
    except InventoryPhotoError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record = InventoryAssetPhoto(asset_id=asset.id, photo_type=photo_type, storage_path=stored.storage_path, original_filename=stored.original_filename, mime_type=stored.mime_type, size_bytes=stored.size_bytes, created_by=actor)
    try:
        db.add(record)
        db.flush()
        write_audit(db, request, actor, "inventory.photo.add", "ok", record.mime_type, target_client=record.id)
    except Exception:
        db.rollback()
        storage.cleanup_many((stored,))
        raise
    return {"status": "ok", "data": _photo_dict(record)}


@router.get("/photos/{photo_id}")
def read_asset_photo(photo_id: str, actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> FileResponse:
    del actor
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


@router.delete("/photos/{photo_id}")
def delete_asset_photo(photo_id: str, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    photo = db.get(InventoryAssetPhoto, photo_id)
    if photo is None:
        raise HTTPException(status_code=404, detail="inventory photo not found")
    try:
        _photo_storage().delete(StoredPhoto(photo.storage_path, photo.original_filename or "image", photo.mime_type, photo.size_bytes))
    except InventoryPhotoError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    db.delete(photo)
    write_audit(db, request, actor, "inventory.photo.delete", "ok", "", target_client=photo_id)
    return {"status": "ok", "data": {"id": photo_id}}


@router.post("/sessions/{session_id}/finish")
def finish_session(session_id: str, request: Request, csrf: str | None = Header(default=None, alias="X-CSRF-Token"), actor: str = Depends(require_api_actor), db: Session = Depends(get_db)) -> dict[str, Any]:
    _mutation(request, csrf)
    session = db.get(InventorySession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="inventory session not found")
    session.finished_at = datetime.now(timezone.utc)
    write_audit(db, request, actor, "inventory.session.finish", "ok", "", target_client=session.id)
    return {"status": "ok", "data": {"id": session.id, "finished_at": session.finished_at.isoformat()}}
