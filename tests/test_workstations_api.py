import json
import uuid

import pytest
from sqlalchemy import select

from tests.test_inventory_web import _client


def test_search_is_csrf_protected_no_store_and_query_is_not_audited(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    from app.workstations import api
    calls = []
    class Controller:
        def call(self, operation, parameters, **kwargs):
            calls.append(operation)
            return {'users': [{'object_guid': str(uuid.uuid4()), 'login': 'synthetic', 'display_name': 'Private Synthetic Person'}], 'truncated': False}
    monkeypatch.setattr(api, 'controller_client', Controller)
    assert client.post('/api/v1/workstations/directory/search', json={'query': 'Private Synthetic Person'}).status_code == 400
    response = client.post('/api/v1/workstations/directory/search', json={'query': 'Private Synthetic Person'}, headers={'X-CSRF-Token': csrf})
    assert response.status_code == 200 and 'no-store' in response.headers['cache-control']
    assert calls == ['directory.search']
    from app.db import get_sessionmaker
    from app.models import WebAuditLog
    with get_sessionmaker()() as db:
        assert 'Private Synthetic Person' not in repr([(row.action, row.message) for row in db.scalars(select(WebAuditLog))])


def test_extra_fields_and_untyped_ids_are_rejected_without_echoing_input(tmp_path, monkeypatch):
    client, csrf = _client(tmp_path, monkeypatch)
    headers = {'X-CSRF-Token': csrf}
    response = client.post('/api/v1/workstations/directory/search', headers=headers, json={'query': 'Synthetic', 'command': 'private-marker'})
    assert response.status_code == 422 and 'private-marker' not in response.text
    for path in ('devices/192.0.2.1', 'jobs/../../raw', 'operations/not-an-id'):
        assert client.get('/api/v1/workstations/' + path).status_code in (404, 422)


def test_safe_planning_result_survives_executor_memory_loss_and_checks_owner(database, monkeypatch):
    from app.workstations.service import WorkstationsService
    from app.panel_operations import execution_future, forget_future
    class Controller:
        def call(self, operation, parameters, **kwargs):
            return {'plan_id': 'setup-' + 'a' * 64, 'sha256': 'a' * 64, 'raw_output': 'private-marker'}
    service = WorkstationsService(client=Controller(), session_factory=database)
    request_id = str(uuid.uuid4())
    value = service.start('plans.create', {'machine_uuid': str(uuid.uuid4())}, actor='user:synthetic', request_id=request_id)
    execution_future(value['operation_id']).result(timeout=5)
    forget_future(value['operation_id'])
    result = service.operation(value['operation_id'], actor='user:synthetic')
    assert result['status'] == 'succeeded' and result['data']['plan_id'].startswith('setup-')
    assert 'private-marker' not in json.dumps(result)
    from fastapi import HTTPException
    with pytest.raises(HTTPException): service.operation(value['operation_id'], actor='user:other')
    assert service.start('plans.create', {'machine_uuid': 'changed'}, actor='user:synthetic', request_id=request_id)['status'] == 'conflict'


def test_uncertain_apply_does_not_become_failed_or_retry_after_restart(database):
    from app.workstations.service import WorkstationsService
    from app.workstations.client import WorkstationsTransportError
    from app.panel_operations import execution_future
    calls = []
    class Controller:
        def call(self, operation, parameters, **kwargs):
            calls.append(operation)
            raise WorkstationsTransportError('workstations_transport_timeout', kwargs['request_id'], uncertain=True)
    service = WorkstationsService(client=Controller(), session_factory=database)
    parameters = {'plan_id': 'setup-' + 'a' * 64, 'sha256': 'a' * 64, 'kind': 'full_setup'}
    request_id = str(uuid.uuid4())
    value = service.start('plans.apply', parameters, actor='service:synthetic', request_id=request_id)
    execution_future(value['operation_id']).result(timeout=5)
    assert service.operation(value['operation_id'], actor='service:synthetic')['status'] == 'unknown'
    from app.models import PanelOperation
    with database() as db:
        assert db.get(PanelOperation, value['operation_id']).status == 'unknown'
    assert service.start('plans.apply', parameters, actor='service:synthetic', request_id=request_id)['operation_id'] == value['operation_id']
    assert calls == ['plans.apply']


def test_lost_initial_reply_can_be_read_by_original_request_id_without_resubmission(database):
    import threading
    from app.workstations.service import WorkstationsService
    from app.panel_operations import execution_future
    entered, release = threading.Event(), threading.Event()
    calls = []
    class Controller:
        def call(self, *args, **kwargs):
            calls.append(kwargs['request_id']); entered.set()
            assert release.wait(5)
            return {'job_id': 'job-20261015T000000Z-12345678'}
    service = WorkstationsService(client=Controller(), session_factory=database)
    request_id = str(uuid.uuid4())
    value = service.start('plans.apply', {}, actor='user:synthetic', request_id=request_id)
    try:
        assert entered.wait(5)
        observed = service.operation(request_id, actor='user:synthetic')
        assert observed['status'] == 'running' and observed['operation_id'] == value['operation_id']
        from fastapi import HTTPException
        with pytest.raises(HTTPException): service.operation(request_id, actor='user:other')
    finally:
        release.set(); execution_future(value['operation_id']).result(timeout=5)
    assert service.operation(request_id, actor='user:synthetic')['data']['job_id'].startswith('job-')
    assert calls == [request_id]


def test_request_lookup_during_registration_does_not_erase_pending_dispatch(database):
    from app.workstations.models import WorkstationRequest
    from app.workstations.service import WorkstationsService
    from datetime import datetime, timedelta, timezone
    request_id = str(uuid.uuid4())
    with database() as db:
        db.add(WorkstationRequest(id=request_id, actor='user:synthetic', action='plans.apply', permission='workstations:apply',
            intent_sha256='a' * 64, status='registered', parameters_json={}, phases_json=[])); db.commit()
    service = WorkstationsService(session_factory=database)
    assert service.operation(request_id, actor='user:synthetic')['status'] == 'registered'
    with database() as db:
        db.get(WorkstationRequest, request_id).created_at = datetime.now(timezone.utc) - timedelta(hours=1); db.commit()
    assert service.operation(request_id, actor='user:synthetic')['status'] == 'unknown'


def test_running_operation_publishes_its_current_phase_before_remote_reply(database):
    import threading
    from app.workstations.service import WorkstationsService
    from app.panel_operations import execution_future
    entered, release = threading.Event(), threading.Event()
    class Controller:
        def call(self, *args, **kwargs):
            entered.set()
            assert release.wait(5)
            return {'plan_id': 'setup-' + 'a' * 64}
    service = WorkstationsService(client=Controller(), session_factory=database)
    value = service.start('plans.create', {}, actor='user:synthetic', request_id=str(uuid.uuid4()))
    try:
        assert entered.wait(5)
        current = service.operation(value['operation_id'], actor='user:synthetic')
        assert current['status'] == 'running'
        assert current['phases'][-1]['stage'] == 'controller' and current['phases'][-1]['status'] == 'running'
    finally:
        release.set()
        execution_future(value['operation_id']).result(timeout=5)


from test_workstations_reconcile import database
