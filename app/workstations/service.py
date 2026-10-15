"""Durable feature receipts around the existing panel executor and native gateway."""
from __future__ import annotations

import copy
import json
import re
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .. import panel_operations
from ..db import get_sessionmaker
from ..models import PanelOperation
from .client import WorkstationsClient
from .journal import error_details, public_payload, safe_code
from .models import Finding, WorkstationRequest
from .projection import fingerprint
from .sources import valid_uuid

ACTIONS = {'plans.create': 'workstations:plan', 'component_plans.create': 'workstations:plan',
    'plans.apply': 'workstations:apply', 'jobs.cancel': 'workstations:apply', 'jobs.verify': 'workstations:diagnose',
    'links.preview': 'workstations:link', 'links.confirm': 'workstations:link', 'links.end': 'workstations:link',
    'reconcile': 'workstations:diagnose', 'findings.ack': 'workstations:diagnose'}


class WorkstationsService:
    def __init__(self, *, client=None, session_factory=None):
        self.client = client or WorkstationsClient()
        self.factory = session_factory or get_sessionmaker()

    def start(self, action, parameters, *, actor, request_id):
        valid_uuid(request_id)
        if action not in ACTIONS or not isinstance(actor, str) or not 1 <= len(actor) <= 160:
            raise HTTPException(422, 'workstations_action_invalid')
        parameters = copy.deepcopy(parameters)
        digest = fingerprint([action, parameters])
        with self.factory() as db:
            existing = db.get(WorkstationRequest, request_id)
            if existing is not None:
                if existing.actor != actor or existing.intent_sha256 != digest:
                    return {'status': 'conflict', 'error_code': 'workstations_request_conflict', 'request_id': request_id}
                return self._public(existing)
            row = WorkstationRequest(id=request_id, actor=actor, action=action, permission=ACTIONS[action],
                intent_sha256=digest, status='registered', parameters_json=parameters,
                phases_json=[{'stage': 'registered', 'status': 'running', 'timestamp': datetime.now(timezone.utc).isoformat()}])
            db.add(row)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return self.start(action, parameters, actor=actor, request_id=request_id)
        try:
            value, created = panel_operations.register(actor, 'workstations.' + action, ACTIONS[action],
                json.dumps([request_id, parameters], sort_keys=True).encode(),
                lambda: self._execute(request_id), factory=self.factory,
                intent=json.dumps(parameters, sort_keys=True).encode())
            with self.factory() as db:
                row = db.get(WorkstationRequest, request_id)
                if created:
                    row.panel_operation_id = value['id']
                else:
                    row.status, row.data_json = 'duplicate', {'operation_id': value['id']}
                    row.finished_at = datetime.now(timezone.utc)
                db.commit()
                return dict(self._public(row), operation_id=value['id'])
        except Exception as exc:
            with self.factory() as db:
                row = db.get(WorkstationRequest, request_id)
                if row.status == 'registered':
                    row.status, row.error_code = 'failed', 'workstations_executor_unavailable'
                    row.finished_at = datetime.now(timezone.utc)
                    db.commit()
            raise HTTPException(503, 'workstations_executor_unavailable') from None

    def _execute(self, request_id):
        with self.factory() as db:
            claimed = db.execute(update(WorkstationRequest).where(WorkstationRequest.id == request_id,
                WorkstationRequest.status == 'registered').values(status='running')).rowcount
            db.commit()
            if claimed != 1:
                return {'status': 'unknown'}
            row = db.get(WorkstationRequest, request_id)
            action, params, actor = row.action, copy.deepcopy(row.parameters_json), row.actor
        status, data, code = 'succeeded', None, None
        stage = 'controller' if not action.startswith(('links.', 'findings.')) and action != 'reconcile' else 'comparison'
        with self.factory() as db:
            row = db.get(WorkstationRequest, request_id)
            row.phases_json = [{'stage': 'registered', 'status': 'succeeded'},
                              {'stage': stage, 'status': 'running', 'timestamp': datetime.now(timezone.utc).isoformat()}]
            db.commit()
        try:
            if action.startswith('links.'):
                from . import links
                with self.factory() as db:
                    if action == 'links.preview':
                        data = links.preview_link(db, **params, actor=actor)
                    elif action == 'links.confirm':
                        data = links.confirm_link(db, **params, actor=actor, client=self.client)
                    else:
                        data = links.end_link(db, **params, actor=actor)
                    db.commit()
            elif action == 'findings.ack':
                from .links import LinkConflict, _reason
                reason = _reason(actor, params['reason'])
                with self.factory() as db:
                    changed = db.execute(update(Finding).where(Finding.id == params['finding_id'], Finding.revision == params['expected_revision'],
                        Finding.status.in_(('open', 'acknowledged'))).values(status='acknowledged', revision=Finding.revision + 1,
                            acknowledged_by=actor, acknowledgement_reason=reason)).rowcount
                    if changed != 1:
                        raise LinkConflict('workstations_finding_changed')
                    db.commit()
                    data = {'id': params['finding_id'], 'status': 'acknowledged', 'revision': params['expected_revision'] + 1}
            elif action == 'reconcile':
                from .reconcile import reconcile_once
                data = reconcile_once(client=self.client, session_factory=self.factory)
                if data['status'] != 'success':
                    status, code = 'failed', 'workstations_reconciliation_incomplete'
            else:
                data = self.client.call(action, params, request_id=request_id, scope='execute')
            data = public_payload(data)
        except Exception as exc:
            status = 'unknown' if getattr(exc, 'uncertain', False) else 'failed'
            code = safe_code(getattr(exc, 'code', 'workstations_operation_failed'))
            if not hasattr(exc, 'code') and action in ('plans.apply', 'jobs.cancel'):
                status = 'unknown'
        finished = datetime.now(timezone.utc)
        phases = [{'stage': 'registered', 'status': 'succeeded'},
                  {'stage': stage, 'status': status, 'timestamp': finished.isoformat(), 'code': code}]
        with self.factory() as db:
            row = db.get(WorkstationRequest, request_id)
            row.status, row.data_json, row.error_code = status, data, code
            row.finished_at, row.phases_json = finished, phases
            db.commit()
        panel_operations.phase('workstations.result', 'succeeded' if status == 'succeeded' else 'unknown' if status == 'unknown' else 'failed')
        return {'status': status}

    def _public(self, row):
        return {'request_id': row.id, 'operation_id': row.panel_operation_id or (row.data_json or {}).get('operation_id'),
            'status': row.status, 'action': row.action, 'permission': row.permission,
            'data': public_payload(row.data_json), 'phases': public_payload(row.phases_json),
            'error': error_details(row.error_code, uncertain=row.status == 'unknown') if row.error_code else None}

    def record(self, operation_id, *, actor):
        valid_uuid(operation_id)
        with self.factory() as db:
            rows = list(db.scalars(select(WorkstationRequest).where(
                (WorkstationRequest.panel_operation_id == operation_id) | (WorkstationRequest.id == operation_id)).limit(2)))
            if len(rows) != 1 or rows[0].actor != actor:
                raise HTTPException(404, 'workstations_operation_not_found')
            row = rows[0]
            return self._public(row)

    def operation(self, operation_id, *, actor):
        result = self.record(operation_id, actor=actor)
        if result['status'] in ('registered', 'running'):
            with self.factory() as db:
                operation = db.get(PanelOperation, result['operation_id']) if result['operation_id'] else None
                if result['operation_id'] is None:
                    pending = db.get(WorkstationRequest, result['request_id'])
                    if (datetime.now(timezone.utc) - pending.created_at).total_seconds() < panel_operations.LEASE_SECONDS:
                        return result
                expired = operation is None or operation.lease_until.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
                if expired:
                    row = db.get(WorkstationRequest, result['request_id'])
                    row.status, row.error_code = 'unknown', 'workstations_executor_outcome_unknown'
                    row.finished_at = datetime.now(timezone.utc)
                    db.commit()
                    result = self._public(row)
        if result['status'] == 'unknown' and result['action'] == 'plans.apply':
            result = self._native_receipt(result, actor=actor)
        return result

    def _native_receipt(self, result, *, actor):
        """Resolve admission only from the original read-only native receipt.

        Historical UNKNOWN phases and the generic panel ledger remain intact.
        Native job UNKNOWN is independent from proof that this request admitted it.
        """
        try:
            receipt = self.client.call('receipts.status', {'request_id': result['request_id']},
                request_id=str(uuid.uuid4()), scope='read')
            if receipt.get('request_id') != result['request_id'] or receipt.get('state') != 'successful':
                return result
            data = receipt['data']
            if not isinstance(data, dict) or not re.fullmatch(r'job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', data.get('job_id', '')):
                return result
            valid_uuid(data.get('machine_uuid'))
            with self.factory() as db:
                row = db.get(WorkstationRequest, result['request_id'])
                if row.actor != actor or row.action != 'plans.apply' or row.status != 'unknown':
                    return self._public(row)
                if data.get('plan_id') != row.parameters_json['plan_id'] or data.get('plan_sha256') != row.parameters_json['sha256']:
                    return result
                row.data_json = public_payload({key: data[key] for key in
                    ('job_id', 'machine_uuid', 'state', 'plan_id', 'plan_sha256') if key in data})
                row.status, row.error_code = 'succeeded', None
                row.phases_json = list(row.phases_json) + [{'stage': 'native_receipt', 'status': 'succeeded',
                    'timestamp': datetime.now(timezone.utc).isoformat()}]
                db.commit()
                return self._public(row)
        except Exception:
            return result
