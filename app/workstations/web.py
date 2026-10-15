"""Session-only pages; all controller actions go through the scoped JSON API."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_user
from ..db import get_db
from ..permissions import check_user_permission, user_has_permission
from .api import DeviceKey, JobID
from .journal import public_payload
from .models import WorkstationRequest

router = APIRouter()


def page(request, db, template, view, **context):
    from ..main import render
    user = require_user(request, db)
    capabilities = {name: user_has_permission(user, 'workstations:' + name) for name in ('read', 'plan', 'apply', 'link', 'diagnose')}
    response = render(request, template, dict(view=view, capabilities=capabilities, **context), db)
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@router.get('/workstations')
def workstations(request: Request, view: str = Query('devices', pattern='^(devices|jobs)$'),
                 inventory_asset_id: str = Query('', max_length=128), network_key: str = Query('', max_length=128), db: Session = Depends(get_db)):
    return page(request, db, 'workstations.html', view, inventory_asset_id=inventory_asset_id, network_key=network_key)


@router.get('/workstations/devices/{device_key}')
def workstation_device(request: Request, device_key: DeviceKey, db: Session = Depends(get_db)):
    return page(request, db, 'workstations_device.html', 'device', device_key=device_key)


@router.get('/workstations/plans/{plan_id}')
def workstation_plan(request: Request, plan_id: str, db: Session = Depends(get_db)):
    import re
    if not re.fullmatch(r'setup-(?:component-)?[0-9a-f]{64}', plan_id):
        raise HTTPException(404)
    user = require_user(request, db)
    check_user_permission(user, 'workstations:plan')
    record = db.scalar(select(WorkstationRequest).where(WorkstationRequest.actor == 'user:' + str(user.id),
        WorkstationRequest.action.in_(('plans.create', 'component_plans.create')),
        WorkstationRequest.status == 'succeeded', WorkstationRequest.data_json['plan_id'].as_string() == plan_id))
    if record is None:
        raise HTTPException(404)
    submitted = db.scalar(select(WorkstationRequest).where(WorkstationRequest.actor == 'user:' + str(user.id),
        WorkstationRequest.action == 'plans.apply', WorkstationRequest.status != 'duplicate',
        WorkstationRequest.parameters_json['plan_id'].as_string() == plan_id).order_by(WorkstationRequest.created_at.desc()))
    return page(request, db, 'workstations_plan.html', 'plan', plan=public_payload(record.data_json),
                submitted=submitted is not None, previous_apply=public_payload(submitted.data_json or {}) if submitted else {},
                previous_status=submitted.status if submitted else None, previous_operation=submitted.panel_operation_id if submitted else None)


@router.get('/workstations/jobs/{job_id}')
def workstation_job(request: Request, job_id: JobID, db: Session = Depends(get_db)):
    return page(request, db, 'workstations_job.html', 'job', job_id=job_id)


@router.get('/workstations/reconcile')
def workstation_reconcile(request: Request, db: Session = Depends(get_db)):
    return page(request, db, 'workstations_reconcile.html', 'reconcile')


@router.get('/workstations/sources')
def workstation_sources(request: Request, db: Session = Depends(get_db)):
    return page(request, db, 'workstations_sources.html', 'sources')
