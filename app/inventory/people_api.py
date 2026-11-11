"""Employee assignment writes and the narrow Helpdesk read boundary."""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime
from typing import Annotated, Iterator, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import and_, select, update
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from ..audit import write_audit
from ..auth import current_user, verify_api_csrf
from ..config import get_settings
from ..db import get_db
from ..models import utcnow
from ..permissions import check_user_permission
from .endpoint import SOURCE, STATE_MAX_AGE, _parsed
from .lifecycle import lock_active_asset
from .revision import InventoryRevisionConflict
from .models import (
    InventoryAsset,
    InventoryAssetType,
    InventoryEndpointState,
    InventoryExternalBinding,
    InventoryExternalBindingStatus,
    InventoryPCDetails,
    InventoryPerson,
    InventoryPersonAssignment,
)

operator_router = APIRouter(prefix="/api/v1/inventory/people", tags=["inventory"])
helpdesk_router = APIRouter(prefix="/api/internal/helpdesk/v1/inventory/people", include_in_schema=False)
Db = Annotated[Session, Depends(get_db)]
Label = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=240)]


class PersonInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    full_name: Label
    department: Label


class AssignmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["primary", "shared"]


class EndInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


def _operator_write(
    request: Request,
    db: Db,
    csrf: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> str:
    actor = _operator_read(request, db)
    verify_api_csrf(request, csrf)
    return actor


def _operator_read(request: Request, db: Db) -> str:
    user = current_user(request, db)
    if user is None:
        raise HTTPException(401, "Operator session required")
    check_user_permission(user, "workstations:link")
    return user.username


def _helpdesk(authorization: Annotated[str | None, Header()] = None) -> None:
    expected = get_settings().helpdesk_inventory_token_hash
    if not expected:
        raise HTTPException(503, "Helpdesk inventory service is not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Helpdesk bearer token required")
    token = authorization.removeprefix("Bearer ")
    if not token or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), expected):
        raise HTTPException(401, "Invalid Helpdesk bearer token")


Operator = Annotated[str, Depends(_operator_write)]



def _person(db: Session, person_id: UUID) -> InventoryPerson:
    person = db.get(InventoryPerson, str(person_id))
    if person is None:
        raise HTTPException(404, {"code": "inventory_person_not_found"})
    return person


def _person_view(person: InventoryPerson) -> dict:
    return {
        "inventory_person_id": person.id,
        "full_name": person.full_name,
        "department": person.department,
        "profile_updated_at": person.updated_at,
    }


def _assignment_view(row: InventoryPersonAssignment) -> dict:
    return {
        "assignment_id": row.id,
        "inventory_asset_id": row.asset_id,
        "role": row.role,
        "assigned_at": row.created_at,
        "ended_at": row.ended_at,
    }


def _search_key(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).casefold().split())


def _people_query(q: str):
    query = select(InventoryPerson)
    if term := _search_key(q):
        query = query.where(InventoryPerson.search_key.contains(term, autoescape=True))
    return query


@operator_router.get("", dependencies=[Depends(_operator_read)])
def list_people(
    response: Response,
    db: Db,
    q: Annotated[str, Query(max_length=120)] = "",
    page: Annotated[int, Query(ge=1, le=10000)] = 1,
) -> dict:
    size = 50
    rows = list(db.scalars(_people_query(q).order_by(InventoryPerson.search_key, InventoryPerson.id)
                           .offset((page - 1) * size).limit(size + 1)))
    response.headers["Cache-Control"] = "no-store"
    return {"people": [_person_view(row) for row in rows[:size]], "page": page, "has_more": len(rows) > size}


@operator_router.post("", status_code=201)
def create_person(payload: PersonInput, request: Request, db: Db, actor: Operator) -> dict:
    person = InventoryPerson(**payload.model_dump(), search_key=_search_key(f"{payload.full_name} {payload.department}"))
    db.add(person)
    db.flush()
    write_audit(db, request, actor, "inventory.person.create", "ok", target_client=person.id)
    return _person_view(person)


@operator_router.put("/{person_id}")
def update_person(person_id: UUID, payload: PersonInput, request: Request, db: Db, actor: Operator) -> dict:
    person = _person(db, person_id)
    if (person.full_name, person.department) != (payload.full_name, payload.department):
        person.full_name, person.department = payload.full_name, payload.department
        person.search_key = _search_key(f"{payload.full_name} {payload.department}")
        write_audit(db, request, actor, "inventory.person.update", "ok", target_client=person.id)
    return _person_view(person)


@operator_router.put("/{person_id}/assignments/{asset_id}")
def assign(person_id: UUID, asset_id: UUID, payload: AssignmentInput, request: Request, db: Db, actor: Operator) -> dict:
    person = _person(db, person_id)
    try:
        lock_active_asset(db, str(asset_id))
    except InventoryRevisionConflict as exc:
        raise HTTPException(409, "Inventory asset is unavailable") from exc
    asset = db.get(InventoryAsset, str(asset_id))
    if asset is None:
        raise HTTPException(404, "Inventory asset not found")
    if asset.asset_type != InventoryAssetType.PC:
        raise HTTPException(409, "Only a PC can be assigned")
    active = list(db.scalars(select(InventoryPersonAssignment).where(
        InventoryPersonAssignment.asset_id == asset.id,
        InventoryPersonAssignment.ended_at.is_(None),
    )))
    existing = next((row for row in active if row.person_id == person.id), None)
    if existing:
        if existing.role != payload.role:
            raise HTTPException(409, "End the current assignment explicitly before changing its role")
        return _assignment_view(existing)
    if payload.role == "primary" and any(row.role == "primary" for row in active):
        raise HTTPException(409, "The PC already has a primary assignment")
    row = InventoryPersonAssignment(person_id=person.id, asset_id=asset.id, role=payload.role, created_by=actor)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Assignment changed concurrently; refresh and retry") from exc
    write_audit(db, request, actor, "inventory.person.assignment.create", "ok", target_client=row.id)
    return _assignment_view(row)


@operator_router.post("/{person_id}/assignments/{assignment_id}/end")
def end_assignment(person_id: UUID, assignment_id: UUID, payload: EndInput, request: Request, db: Db, actor: Operator) -> dict:
    row = db.get(InventoryPersonAssignment, str(assignment_id))
    if row is None or row.person_id != str(person_id):
        raise HTTPException(404, "Inventory assignment not found")
    result = db.execute(update(InventoryPersonAssignment).where(
        InventoryPersonAssignment.id == row.id,
        InventoryPersonAssignment.ended_at.is_(None),
    ).values(ended_at=utcnow(), ended_by=actor, end_reason=payload.reason))
    if result.rowcount:
        write_audit(db, request, actor, "inventory.person.assignment.end", "ok", target_client=row.id)
    db.refresh(row)
    return _assignment_view(row)


def _endpoint_status(state: InventoryEndpointState | None, now) -> str:
    if not get_settings().endpoint_platform_enabled or not state or state.unavailable_since:
        return "unknown"
    checked_at = _parsed(state.safe_context_json.get("identity_checked_at"))
    if (state.safe_context_json.get("identity_status") != "available" or checked_at is None
            or checked_at > now or now - checked_at > STATE_MAX_AGE or state.online is None):
        return "unknown"
    return "online" if state.online else "offline"


def _assignment_views(db: Session, person_filter: ColumnElement[bool], now: datetime) -> Iterator[tuple[str, dict]]:
    row = InventoryPersonAssignment
    binding = InventoryExternalBinding
    state = InventoryEndpointState
    candidate = aliased(binding)
    has_candidate = select(candidate.id).where(
        candidate.asset_id == InventoryAsset.id,
        candidate.source == SOURCE,
        candidate.status == InventoryExternalBindingStatus.CANDIDATE,
        candidate.ended_at.is_(None),
    ).exists()
    result = db.execute(
        select(row, InventoryAsset, InventoryPCDetails.os_name, binding, state, has_candidate)
        .join(InventoryAsset, InventoryAsset.id == row.asset_id)
        .outerjoin(InventoryPCDetails, InventoryPCDetails.asset_id == row.asset_id)
        .outerjoin(binding, and_(
            binding.asset_id == row.asset_id, binding.source == SOURCE,
            binding.status == InventoryExternalBindingStatus.CONFIRMED, binding.ended_at.is_(None),
        ))
        .outerjoin(state, and_(
            state.binding_id == binding.id, state.asset_id == row.asset_id, state.endpoint_device_id == binding.external_id,
        ))
        .where(person_filter, row.ended_at.is_(None), InventoryAsset.deleted_at.is_(None),
               InventoryAsset.asset_type == InventoryAssetType.PC)
        .order_by(row.created_at, row.id)
    )
    for assignment, asset, os_name, link, cached, needs_review in result:
        try:
            device_id = str(UUID(link.external_id)) if link else None
        except ValueError:
            device_id = None
        binding_state = "confirmed" if device_id else "review" if needs_review or link else "unbound"
        endpoint_status = _endpoint_status(cached, now) if device_id else "unknown" if link else "not_detected"
        yield assignment.person_id, {
            **_assignment_view(assignment),
            "name": asset.custom_name,
            "inventory_number": asset.inventory_number,
            "os_name": os_name,
            "endpoint_binding_state": binding_state,
            "endpoint_binding_id": link.id if device_id else None,
            "endpoint_binding_updated_at": link.updated_at if device_id else None,
            "endpoint_device_id": device_id,
            "endpoint_status": endpoint_status,
            "last_seen_at": cached.last_seen_at if cached and device_id else None,
            "agent_version": cached.agent_version if cached and device_id else None,
        }


DirectoryState = Literal["all", "no_pcs", "not_detected", "offline", "unknown", "review", "online"]


def operator_directory(db: Session, q: str, page: int, state: DirectoryState) -> dict:
    """Count matches over the search result before slicing the selected filter."""
    people = _people_query(q)
    assigned = defaultdict(list)
    matching_people = people.with_only_columns(InventoryPerson.id)
    person_filter = InventoryPersonAssignment.person_id.in_(matching_people)
    for person_id, assignment in _assignment_views(db, person_filter, utcnow()):
        assigned[person_id].append(assignment)

    size = 50
    offset = (page - 1) * size
    rows = []
    totals = Counter()
    matched = 0
    for person in db.scalars(people.order_by(InventoryPerson.search_key, InventoryPerson.id)):
        devices = assigned.get(person.id, ())
        statuses = Counter(
            "review" if device["endpoint_binding_state"] == "review" else device["endpoint_status"]
            for device in devices
        )
        filters = {"all"}
        if not devices:
            filters.add("no_pcs")
        filters.update(status for status in statuses if status != "online")
        if devices and statuses["online"] == len(devices):
            filters.add("online")
        totals.update(filters)
        if state not in filters:
            continue
        matched += 1
        if offset < matched <= offset + size:
            seen = [device["last_seen_at"] for device in devices if device["last_seen_at"]]
            rows.append({
                **_person_view(person), "pc_count": len(devices),
                "agent_count": sum(device["endpoint_device_id"] is not None for device in devices),
                "endpoint_counts": dict(statuses), "last_seen_at": max(seen, default=None),
            })
    return {"people": rows, "page": page, "has_more": matched > offset + size, "totals": dict(totals)}


@operator_router.get("/{person_id}", dependencies=[Depends(_operator_read)])
@helpdesk_router.get("/{person_id}", dependencies=[Depends(_helpdesk)])
def read_person(person_id: UUID, response: Response, db: Db) -> dict:
    person = _person(db, person_id)
    now = utcnow()
    assignments = [item for _, item in _assignment_views(db, InventoryPersonAssignment.person_id == person.id, now)]
    response.headers["Cache-Control"] = "no-store"
    return {**_person_view(person), "observed_at": now, "assignments": assignments}
