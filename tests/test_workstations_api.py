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
    assert calls.count('plans.apply') == 1 and set(calls) <= {'plans.apply', 'receipts.status'}


@pytest.mark.parametrize('proof', ['valid', 'missing', 'other_request', 'other_plan'])
def test_uncertain_apply_reads_original_native_receipt_without_replaying(database, proof):
    from app.workstations.service import WorkstationsService
    from app.workstations.client import WorkstationsTransportError
    from app.panel_operations import execution_future
    from app.workstations.models import WorkstationRequest
    request_id, machine_id = str(uuid.uuid4()), str(uuid.uuid4())
    job_id, sha = 'job-20261015T000000Z-12345678', 'a' * 64
    calls = []
    class Controller:
        def call(self, action, parameters, **kwargs):
            calls.append((action, parameters))
            if action == 'plans.apply': raise WorkstationsTransportError('workstations_transport_timeout', request_id, uncertain=True)
            assert action == 'receipts.status' and parameters == {'request_id': request_id} and kwargs['scope'] == 'read'
            data = {'job_id': job_id, 'machine_uuid': machine_id, 'plan_id': 'setup-' + sha, 'plan_sha256': sha, 'state': 'unknown_requires_review'}
            if proof == 'other_plan': data['plan_id'] = 'setup-' + 'b' * 64
            return {'request_id': str(uuid.uuid4()) if proof == 'other_request' else request_id,
                'state': 'not_found' if proof == 'missing' else 'successful', 'data': data}
    service = WorkstationsService(client=Controller(), session_factory=database)
    result = service.start('plans.apply', {'plan_id': 'setup-' + sha, 'sha256': sha, 'kind': 'full_setup'}, actor='user:synthetic', request_id=request_id)
    execution_future(result['operation_id']).result(timeout=5)
    observed = service.operation(request_id, actor='user:synthetic')
    if proof == 'valid':
        assert observed['status'] == 'succeeded' and observed['data']['job_id'] == job_id
        assert observed['data']['state'] == 'unknown_requires_review'  # admission proof does not turn the job green
        assert any(phase['status'] == 'unknown' for phase in observed['phases'])
        assert observed['phases'][-1]['stage'] == 'native_receipt'
        with database() as db: assert db.get(WorkstationRequest, request_id).data_json['job_id'] == job_id
    else:
        assert observed['status'] == 'unknown' and not observed['data']
    assert [call[0] for call in calls] == ['plans.apply', 'receipts.status']


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


@pytest.mark.parametrize('ambiguous', [False, True])
def test_device_detail_keeps_mac_link_after_registration_only_for_verified_alias(database, tmp_path, ambiguous):
    import copy
    from starlette.requests import Request
    from app.workstations import api
    from app.workstations.models import DirectoryLink, SourceSnapshot
    from test_workstations_reconcile import run, MACHINE, USER, MAC
    with database() as db:
        link = DirectoryLink(device_key='mac:' + MAC, user_guid=USER, user_sid='S-1-5-21-1', user_login='synthetic',
            source_revision='a' * 64, status='confirmed', evidence_json={'user': {'object_guid': USER, 'login': 'synthetic'}})
        db.add(link); db.commit(); link_id = link.id
    assert run(database, tmp_path)['status'] == 'success'
    with database() as db:
        snapshot = db.get(SourceSnapshot, 'reconciliation')
        value = copy.deepcopy(snapshot.data_json)
        row = next(row for row in value['devices'] if row['machine_uuid'] == MACHINE)
        assert row['employee_binding_state'] == 'confirmed'
        if ambiguous:
            row['identity_state'] = 'ambiguous'; snapshot.data_json = value; db.commit()
        result = api.device(Request({'type': 'http', 'query_string': b''}), 'machine:' + MACHINE, owner='user:synthetic', db=db)['data']
        assert [row['id'] for row in result['links']] == ([] if ambiguous else [link_id])


@pytest.mark.parametrize('change', ['failed', 'running', 'generation'])
def test_retained_comparison_is_marked_unavailable_when_source_attempt_changes(database, tmp_path, monkeypatch, change):
    from app.workstations import api
    from app.workstations.models import SourceRun, SourceSnapshot
    from test_workstations_reconcile import run, Client, NOW
    from datetime import datetime, timedelta
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None): return NOW + timedelta(seconds=3)
    monkeypatch.setattr(api, 'datetime', Clock)
    assert run(database, tmp_path)['status'] == 'success'
    with database() as db:
        assert api.snapshot_state(db, db.get(SourceSnapshot, 'reconciliation'))['stale'] is False
    if change == 'failed':
        controller = Client(); controller.failure = 'dns'
        assert run(database, tmp_path, client=controller, clock=lambda: NOW + timedelta(seconds=1))['status'] == 'degraded'
    else:
        with database() as db:
            if change == 'running':
                db.add(SourceRun(batch_id=str(uuid.uuid4()), source='dns', status='running', started_at=NOW + timedelta(seconds=1)))
            else: db.get(SourceSnapshot, 'dns').generation = 'changed'
            db.commit()
    with database() as db:
        result = api.snapshot_state(db, db.get(SourceSnapshot, 'reconciliation'))
        assert result['stale'] is True
        assert {'failed': 'source_unavailable', 'running': 'refresh_in_progress', 'generation': 'source_changed'}[change] in result['stale_reasons']


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


def test_inventory_endpoint_plan_uses_only_the_fresh_exact_workstation(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    from app.db import session_scope
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryPCDetails
    from app.models import WebUser
    from app.workstations import api
    from app.workstations.models import SourceSnapshot, WorkstationRequest

    monkeypatch.setenv("WORKSTATIONS_ENABLED", "true")
    client, csrf = _client(tmp_path, monkeypatch)
    asset_id, machine, unrelated = (str(uuid.uuid4()) for _ in range(3))
    with session_scope() as db:
        db.add(InventoryAsset(id=asset_id, asset_type=InventoryAssetType.PC, custom_name="Synthetic ALT PC"))
        db.flush()
        db.add(InventoryPCDetails(asset_id=asset_id, os_name="ALT Workstation K 11"))
        db.flush()
        revision = db.get(InventoryAsset, asset_id, populate_existing=True).manual_revision
        db.add(SourceSnapshot(source="reconciliation", generation="fixture", batch_id=str(uuid.uuid4()), observed_at=datetime.now(timezone.utc),
            inventory_revision=0, data_json={"devices": [
                {"inventory_asset_id": asset_id, "inventory_revision": revision, "machine_uuid": machine,
                 "registration_state": "ready", "identity_state": "observed"},
                {"inventory_asset_id": str(uuid.uuid4()), "inventory_revision": 1, "machine_uuid": unrelated,
                 "registration_state": "ready", "identity_state": "observed"},
            ]}))
    stale = False
    published = True
    calls = []
    monkeypatch.setattr(api, "snapshot_state", lambda *_: {"stale": stale})
    monkeypatch.setattr(api, "_call", lambda *_: {"components": [{"id": "software.endpoint_agent"}] if published else []})

    def start(action, body, owner, **extra):
        calls.append((action, extra))
        return api.response({"status": "accepted"})

    monkeypatch.setattr(api, "start", start)
    route = f"/api/v1/workstations/inventory/{asset_id}/endpoint-agent-plan"
    headers = {"X-CSRF-Token": csrf}
    payload = {"request_id": str(uuid.uuid4())}
    assert client.post(route, json=payload).status_code == 400
    assert client.post(route, json={**payload, "machine_uuid": unrelated}, headers=headers).status_code == 422
    response = client.post(route, json=payload, headers=headers)
    assert response.status_code == 200, response.text
    assert calls == [("component_plans.create", {"machine_uuid": machine, "component_id": "software.endpoint_agent", "_inventory_asset_id": asset_id})]
    view = client.get(f"/workstations/inventory/{asset_id}/endpoint-agent")
    assert 'data-endpoint-plan=' in view.text and 'Synthetic ALT PC' in view.text
    published = False
    view = client.get(f"/workstations/inventory/{asset_id}/endpoint-agent")
    assert 'ещё не опубликован' in view.text and 'data-endpoint-plan=' not in view.text
    assert client.post(route, json=payload, headers=headers).status_code == 409
    assert len(calls) == 1

    sha = "a" * 64
    plan_id = f"setup-component-{sha}"
    with session_scope() as db:
        user = db.scalar(select(WebUser).where(WebUser.username == "admin"))
        db.add(WorkstationRequest(actor=f"user:{user.id}", action="component_plans.create",
            permission="workstations:plan", intent_sha256="b" * 64, status="succeeded",
            parameters_json=dict(calls[0][1], inventory_installation_id=f"inventory-{asset_id}-{machine}-" + "a" * 32),
            data_json={"plan_id": plan_id}))
    apply_url = f"/api/v1/workstations/plans/{plan_id}/apply"
    apply_body = {"request_id": str(uuid.uuid4()), "sha256": sha, "kind": "component"}
    stale = True
    assert client.post(apply_url, json=apply_body, headers=headers).status_code == 409
    assert client.post(route, json=payload, headers=headers).status_code == 409
    assert len(calls) == 1
    stale = False
    assert client.post(apply_url, json=apply_body, headers=headers).status_code == 200
    assert calls[-1] == ("plans.apply", {"plan_id": plan_id})


def test_inventory_installation_id_is_created_once_and_kept_out_of_operation_projection(database):
    import re

    from app.panel_operations import execution_future
    from app.workstations.models import WorkstationRequest
    from app.workstations.service import WorkstationsService

    asset, machine, request_id = (str(uuid.uuid4()) for _ in range(3))
    native_calls = []

    class Controller:
        def call(self, action, parameters, **kwargs):
            native_calls.append((action, parameters))
            return {'plan_id': 'setup-component-' + 'a' * 64}

    service = WorkstationsService(client=Controller(), session_factory=database)
    params = {'machine_uuid': machine, 'component_id': 'software.endpoint_agent', '_inventory_asset_id': asset}
    result = service.start('component_plans.create', params, actor='user:fixture', request_id=request_id)
    execution_future(result['operation_id']).result(timeout=5)
    with database() as db:
        stored = db.get(WorkstationRequest, request_id).parameters_json['inventory_installation_id']
    assert re.fullmatch(f'inventory-{asset}-{machine}-[0-9a-f]{{32}}', stored)
    assert native_calls == [('component_plans.create', {'machine_uuid': machine, 'component_id': 'software.endpoint_agent',
                                                        'inventory_installation_id': stored})]
    replay = service.start('component_plans.create', params, actor='user:fixture', request_id=request_id)
    assert replay['operation_id'] == result['operation_id']
    assert stored not in json.dumps(replay)
    assert len(native_calls) == 1
