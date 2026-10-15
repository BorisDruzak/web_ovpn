"""Permission-scoped browser/MCP facade for the restricted controller gateway."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..auth import authorize_workstations
from ..config import get_settings
from ..db import get_db, get_sessionmaker
from ..permissions import required_permission
from .client import WorkstationsClient
from .journal import JournalService, error_details, public_payload, safe_code
from .models import DirectoryLink, Finding, SourceRun, SourceSnapshot
from .service import WorkstationsService
from .sources import MAX_AGE, SourceError, valid_uuid
from .projection import relationship_revision
from ..inventory.network_projection import projection_epoch

controller_client = WorkstationsClient
UUIDText = Annotated[str, Field(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
SHA = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
JobID = Annotated[str, Field(pattern=r'^job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$')]
DeviceKey = Annotated[str, Field(pattern=r'^(?:(?:machine|inventory|ad):[0-9a-f-]{36}|mac:(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})$')]
CatalogID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_.-]{0,127}$')]


class SafeRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def safe(request):
            status, code = 'ok', None
            try:
                if request.method == 'POST' and len(await request.body()) > 32768:
                    raise HTTPException(413, 'workstations_request_limit')
                response = await handler(request)
            except RequestValidationError:
                status, code = 'error', 'workstations_validation_invalid'
                response = JSONResponse({'status': status, 'data': None, 'error': error_details(code)}, status_code=422)
            except HTTPException as exc:
                status = 'error'
                code = {401: 'workstations_auth_required', 403: 'workstations_permission_denied', 400: 'workstations_csrf_invalid',
                        404: 'workstations_not_found'}.get(exc.status_code, safe_code(exc.detail))
                response = JSONResponse({'status': status, 'data': None, 'error': error_details(code)}, status_code=exc.status_code)
            except Exception as exc:
                status, code = 'error', safe_code(getattr(exc, 'code', 'workstations_internal_error'))
                response = JSONResponse({'status': status, 'data': None, 'error': error_details(code,
                    uncertain=getattr(exc, 'uncertain', False))}, status_code=409 if isinstance(exc, SourceError) else 502)
            response.headers['Cache-Control'] = 'private, no-store'
            response.headers['X-Request-ID'] = str(getattr(request.state, 'request_id', ''))
            # Names, request bodies, remote diagnostics and route parameters are absent.
            try:
                with get_sessionmaker()() as db:
                    write_audit(db, request, getattr(request.state, 'workstations_actor', 'anonymous'),
                        'workstations.' + self.name, status, code or 'completed')
            except Exception:
                return JSONResponse({'status': 'error', 'data': None, 'error': error_details('workstations_audit_unavailable')},
                    status_code=503, headers={'Cache-Control': 'private, no-store'})
            return response
        return safe


router = APIRouter(prefix='/api/v1/workstations', tags=['workstations'], route_class=SafeRoute)


def actor(request: Request, db: Session = Depends(get_db)):
    value = authorize_workstations(request, db, required_permission(request.url.path, request.method))
    request.state.workstations_actor = value
    return value


def response(data):
    return {'status': 'ok', 'data': public_payload(data)}


def query(request, keys):
    if set(request.query_params) - set(keys) or any(len(request.query_params.getlist(key)) != 1 for key in request.query_params):
        raise HTTPException(422, 'workstations_query_invalid')


def _call(operation, parameters):
    return controller_client().call(operation, parameters, request_id=str(uuid.uuid4()))


def snapshot_state(db, snapshot):
    reasons = []
    if not timedelta(0) <= datetime.now(timezone.utc) - snapshot.observed_at <= MAX_AGE:
        reasons.append('source_stale')
    if snapshot.inventory_revision != projection_epoch(db):
        reasons.append('inventory_changed')
    if snapshot.data_json.get('link_revision') != relationship_revision(db):
        reasons.append('links_changed')
    return {'stale': bool(reasons), 'stale_reasons': reasons, 'observed_at': snapshot.observed_at.isoformat()}


class Body(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class RequestBody(Body):
    request_id: UUIDText


class Search(Body):
    query: str = Field(min_length=2, max_length=160)
    limit: int = Field(default=50, ge=1, le=50)


class LinkPreview(RequestBody):
    device_key: DeviceKey
    user_guid: UUIDText
    computer_guid: UUIDText | None = None
    source_revision: SHA


class LinkConfirm(RequestBody):
    preview_id: UUIDText
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=2000)


class EndBody(RequestBody):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=2000)


class Plan(RequestBody):
    machine_uuid: UUIDText
    user_login: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,191}$')
    user_guid: UUIDText
    user_sid: str = Field(pattern=r'^S-1-[0-9]+(?:-[0-9]+)+$')
    ou_id: SHA
    software_profile: CatalogID
    remote_access_profile: Literal['none', 'krfb'] = 'none'


class ComponentPlan(RequestBody):
    machine_uuid: UUIDText
    component_id: CatalogID


class Apply(RequestBody):
    sha256: SHA
    kind: Literal['full_setup', 'component']


class Cancel(RequestBody):
    sha256: SHA


def start(action, body, owner, **extra):
    parameters = body.model_dump(exclude={'request_id'})
    result = WorkstationsService(client=controller_client()).start(action, dict(parameters, **extra), actor=owner, request_id=body.request_id)
    if result['status'] == 'conflict':
        raise HTTPException(409, result['error_code'])
    return response(result)


@router.get('/status')
def status(request: Request, owner=Depends(actor)):
    query(request, ())
    value = {'enabled': get_settings().workstations_enabled, 'execution_mode': 'sequential', 'queue_status': 'unavailable'}
    if value['enabled']:
        try:
            native = _call('status', {})
            value.update({key: native[key] for key in ('queued_count', 'historical_unknown_count', 'unresolved_legacy_count', 'observer_configured') if key in native})
            value.update(queue_status=native.get('admission_status'), executing_count=len(native.get('executing', [])))
        except Exception as exc:
            value['error_code'] = safe_code(getattr(exc, 'code', 'workstations_source_unavailable'))
    return response(value)


@router.get('/devices')
def devices(request: Request, offset: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=100),
            owner=Depends(actor), db: Session = Depends(get_db)):
    query(request, ('offset', 'limit'))
    snapshot = db.get(SourceSnapshot, 'reconciliation')
    if snapshot is None:
        # Registered machines remain selectable when the directory has not yet
        # supplied a coherent reconciliation. Native planning still verifies it.
        native = _call('machines.list', {'offset': offset, 'limit': limit})
        return response(dict(native, devices=[dict(row, device_key='machine:' + row['uuid'], machine_uuid=row['uuid']) for row in native['machines']], evidence='registry_only'))
    rows = snapshot.data_json['devices']
    return response({'devices': rows[offset:offset + limit], 'total': len(rows), 'next_offset': min(len(rows), offset + limit),
                     'source_revision': snapshot.generation, **snapshot_state(db, snapshot)})


@router.get('/devices/{device_key}')
def device(request: Request, device_key: DeviceKey, owner=Depends(actor), db: Session = Depends(get_db)):
    query(request, ())
    snapshot = db.get(SourceSnapshot, 'reconciliation')
    row = next((row for row in snapshot.data_json['devices'] if row['device_key'] == device_key), None) if snapshot else None
    if row is None and device_key.startswith('machine:'):
        row = _call('machines.show', {'machine_uuid': valid_uuid(device_key[8:])})['machine']
    if row is None:
        raise HTTPException(404)
    from .links import public_link
    links = [public_link(link) for link in db.scalars(select(DirectoryLink).where(DirectoryLink.device_key == device_key).order_by(DirectoryLink.created_at.desc()).limit(100))]
    return response({'device': row, 'links': links, 'source_revision': snapshot.generation if snapshot else None,
                     **(snapshot_state(db, snapshot) if snapshot else {})})


@router.get('/catalog')
def catalog(request: Request, owner=Depends(actor)):
    query(request, ())
    return response(_call('catalog.list', {}))


@router.post('/directory/search')
def search(request: Request, body: Search, owner=Depends(actor)):
    query(request, ())
    return response(_call('directory.search', body.model_dump()))


@router.post('/links/preview')
def link_preview(body: LinkPreview, owner=Depends(actor)):
    return start('links.preview', body, owner)


@router.post('/links/confirm')
def link_confirm(body: LinkConfirm, owner=Depends(actor)):
    return start('links.confirm', body, owner)


@router.post('/links/{link_id}/end')
def link_end(link_id: UUIDText, body: EndBody, owner=Depends(actor)):
    return start('links.end', body, owner, link_id=link_id)


@router.post('/plans')
def plan(body: Plan, owner=Depends(actor)):
    return start('plans.create', body, owner)


@router.post('/component-plans')
def component_plan(body: ComponentPlan, owner=Depends(actor)):
    return start('component_plans.create', body, owner)


@router.post('/plans/{plan_id}/apply')
def apply(plan_id: Annotated[str, Field(pattern=r'^setup-(?:component-)?[0-9a-f]{64}$')], body: Apply, owner=Depends(actor)):
    prefix = 'setup-' if body.kind == 'full_setup' else 'setup-component-'
    if plan_id != prefix + body.sha256:
        raise HTTPException(422, 'workstations_confirmation_mismatch')
    return start('plans.apply', body, owner, plan_id=plan_id)


@router.get('/operations/{operation_id}')
@router.get('/reconcile/{operation_id}')
def operation(operation_id: UUIDText, request: Request, owner=Depends(actor), db: Session = Depends(get_db)):
    query(request, ())
    service = WorkstationsService(client=controller_client())
    original = service.record(operation_id, actor=owner)
    authorize_workstations(request, db, original['permission'])
    if request.url.path.startswith('/api/v1/workstations/reconcile/') and original['action'] != 'reconcile':
        raise HTTPException(404)
    return response(service.operation(operation_id, actor=owner))


@router.get('/jobs')
def jobs(request: Request, machine_uuid: UUIDText | None = None, offset: int = Query(0, ge=0, le=10000),
         limit: int = Query(100, ge=1, le=100), owner=Depends(actor)):
    query(request, ('machine_uuid', 'offset', 'limit'))
    return response(_call('jobs.list', dict(offset=offset, limit=limit, **({'machine_uuid': machine_uuid} if machine_uuid else {}))))


@router.get('/jobs/{job_id}')
def job(job_id: JobID, request: Request, owner=Depends(actor)):
    query(request, ())
    return response(_call('jobs.status', {'job_id': job_id}))


@router.get('/jobs/{job_id}/events')
def events(job_id: JobID, request: Request, after: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=1000), owner=Depends(actor)):
    query(request, ('after', 'limit'))
    return response(_call('jobs.events', dict(job_id=job_id, after=after, limit=limit)))


@router.post('/jobs/{job_id}/verify')
def verify(job_id: JobID, body: RequestBody, owner=Depends(actor)):
    return start('jobs.verify', body, owner, job_id=job_id)


@router.post('/jobs/{job_id}/cancel')
def cancel(job_id: JobID, body: Cancel, owner=Depends(actor)):
    return start('jobs.cancel', body, owner, job_id=job_id)


@router.post('/reconcile')
def reconcile(body: RequestBody, owner=Depends(actor)):
    return start('reconcile', body, owner)


@router.get('/sources')
def sources(request: Request, owner=Depends(actor), db: Session = Depends(get_db)):
    query(request, ())
    result = []
    for name in ('controller', 'ad', 'dns', 'netctl'):
        snapshot = db.get(SourceSnapshot, name)
        attempt = db.scalar(select(SourceRun).where(SourceRun.source == name).order_by(SourceRun.started_at.desc()).limit(1))
        result.append({'source': name, 'generation': snapshot.generation if snapshot else None,
            'observed_at': snapshot.observed_at.isoformat() if snapshot else None,
            'last_attempt': attempt.started_at.isoformat() if attempt else None,
            'status': attempt.status if attempt else 'unavailable', 'error_code': attempt.error_code if attempt else None,
            'object_count': attempt.object_count if attempt else 0,
            'stale': not snapshot or not timedelta(0) <= datetime.now(timezone.utc) - snapshot.observed_at <= MAX_AGE})
    return response({'sources': result})


@router.get('/findings')
def findings(request: Request, offset: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=100), owner=Depends(actor), db: Session = Depends(get_db)):
    query(request, ('offset', 'limit'))
    rows = list(db.scalars(select(Finding).where(Finding.status != 'resolved').order_by(Finding.first_seen_at, Finding.id).offset(offset).limit(limit + 1)))
    return response({'findings': [{'id': row.id, 'device_key': row.device_key, 'code': row.code, 'status': row.status,
        'revision': row.revision, 'evidence': row.evidence_json, 'first_seen_at': row.first_seen_at.isoformat(),
        'last_seen_at': row.last_seen_at.isoformat()} for row in rows[:limit]], 'next_offset': offset + limit if len(rows) > limit else None})


@router.post('/findings/{finding_id}/acknowledge')
def acknowledge(finding_id: SHA, body: EndBody, owner=Depends(actor)):
    return start('findings.ack', body, owner, finding_id=finding_id)


@router.get('/journal')
@router.get('/journal/export')
def journal(request: Request, device_key: DeviceKey | None = None, job_id: JobID | None = None,
            component: CatalogID | None = None, stage: str | None = Query(None, max_length=64, pattern=r'^[a-z0-9_]+$'),
            severity: Literal['info', 'error'] | None = None, cursor: str | None = Query(None, max_length=1024),
            limit: int = Query(100, ge=1, le=1000), owner=Depends(actor), db: Session = Depends(get_db)):
    query(request, ('device_key', 'job_id', 'component', 'stage', 'severity', 'cursor', 'limit'))
    filters = {key: value for key, value in dict(device_key=device_key, job_id=job_id, component=component, stage=stage, severity=severity).items() if value}
    service = JournalService(client=controller_client())
    data = service.export(db, filters=filters, cursor=cursor, limit=limit) if request.url.path.endswith('/export') else service.list(db, filters=filters, cursor=cursor, limit=limit)
    if request.url.path.endswith('/export'):
        return JSONResponse(response(data), headers={'Content-Disposition': 'attachment; filename="workstations-journal.json"'})
    return response(data)
