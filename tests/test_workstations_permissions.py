import hashlib
import json
from types import SimpleNamespace

import pytest

from tests.test_inventory_web import _client
from tests.test_panel_permissions import login_operator


def scoped(tmp_path, monkeypatch, records):
    path = tmp_path / 'scoped-credentials.json'
    path.write_text(json.dumps(records), encoding='utf-8'); path.chmod(0o600)
    monkeypatch.setenv('WORKSTATIONS_API_CREDENTIALS_FILE', str(path))
    return path


def record(token='synthetic-scoped', grants=('workstations:read',), actor='integration'):
    return dict(token_hash=hashlib.sha256(token.encode()).hexdigest(), actor=actor, grants=list(grants))


def test_generic_read_shortcut_does_not_expose_directory():
    from app.permissions import user_has_permission, PERMISSIONS, LEGACY_SERVICE_PERMISSIONS
    user = SimpleNamespace(is_active=True, is_admin=False, is_network_admin=False, permissions_json='[]')
    assert user_has_permission(user, 'inventory:read')
    assert not user_has_permission(user, 'workstations:read')
    assert all('workstations:' + name in PERMISSIONS for name in ('read', 'plan', 'apply', 'link', 'diagnose'))
    assert 'workstations:' not in LEGACY_SERVICE_PERMISSIONS


def test_observer_can_read_summary_but_no_personal_surfaces(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    login_operator(client)
    assert client.get('/api/v1/workstations/status').status_code == 200
    for path in ('devices', 'catalog', 'sources', 'findings', 'jobs', 'journal', 'journal/export'):
        assert client.get('/api/v1/workstations/' + path).status_code == 403
    assert client.post('/api/v1/workstations/directory/search', json={'query': 'Synthetic'}).status_code == 403


@pytest.mark.parametrize('path,payload', [('/plans', {}), ('/component-plans', {}), ('/links/preview', {}),
    ('/reconcile', {}), ('/jobs/job-20261015T000000Z-12345678/verify', {}),
    ('/plans/setup-' + 'a' * 64 + '/apply', {})])
def test_scoped_read_cannot_mutate_before_validation_or_transport(tmp_path, monkeypatch, path, payload):
    scoped(tmp_path, monkeypatch, [record()])
    client, _ = _client(tmp_path, monkeypatch)
    response = client.post('/api/v1/workstations' + path, headers={'Authorization': 'Bearer synthetic-scoped'}, json=payload)
    assert response.status_code == 403


def test_scoped_identity_and_invalid_configuration_fail_closed(tmp_path, monkeypatch):
    path = scoped(tmp_path, monkeypatch, [record()])
    client, _ = _client(tmp_path, monkeypatch)
    headers = {'Authorization': 'Bearer synthetic-scoped'}
    response = client.get('/api/v1/workstations/sources', headers=headers)
    assert response.status_code == 200
    path.write_text('[{"token_hash":"invalid","actor":"integration","grants":["workstations:apply"]}]')
    assert client.get('/api/v1/workstations/sources', headers=headers).status_code == 401


def test_legacy_token_defaults_cannot_access_directory_or_execute(tmp_path, monkeypatch):
    from tests.test_inventory_api import _client as api_client
    client, headers = api_client(tmp_path, monkeypatch)
    assert client.get('/api/v1/workstations/devices', headers=headers).status_code == 403
    assert client.post('/api/v1/workstations/plans', json={}, headers=headers).status_code == 403


def test_operation_polling_requires_original_owner_and_current_grant(tmp_path, monkeypatch):
    import uuid
    from app.db import get_sessionmaker
    from app.workstations.models import WorkstationRequest
    operation_id, request_id = str(uuid.uuid4()), str(uuid.uuid4())
    path = scoped(tmp_path, monkeypatch, [record(grants=('workstations:read', 'workstations:apply'))])
    client, _ = _client(tmp_path, monkeypatch)
    with get_sessionmaker()() as db:
        db.add(WorkstationRequest(id=request_id, panel_operation_id=operation_id, actor='service:workstations:integration',
            action='plans.apply', permission='workstations:apply', intent_sha256='a' * 64, status='succeeded', data_json={'job_id': 'synthetic'}))
        db.commit()
    headers = {'Authorization': 'Bearer synthetic-scoped'}
    url = '/api/v1/workstations/operations/' + operation_id
    assert client.get(url, headers=headers).status_code == 200
    path.write_text(json.dumps([record(grants=('workstations:read',))]))
    assert client.get(url, headers=headers).status_code == 403
    path.write_text(json.dumps([record(actor='other', grants=('workstations:read', 'workstations:apply'))]))
    assert client.get(url, headers=headers).status_code == 404


def test_diagnose_can_poll_own_reconciliation_without_unrelated_read_grant(tmp_path, monkeypatch):
    import uuid
    from app.db import get_sessionmaker
    from app.workstations.models import WorkstationRequest
    scoped(tmp_path, monkeypatch, [record(grants=('workstations:diagnose',))])
    client, _ = _client(tmp_path, monkeypatch)
    operation_id = str(uuid.uuid4())
    with get_sessionmaker()() as db:
        db.add(WorkstationRequest(id=str(uuid.uuid4()), panel_operation_id=operation_id, actor='service:workstations:integration',
            action='reconcile', permission='workstations:diagnose', intent_sha256='a' * 64, status='succeeded'))
        db.commit()
    assert client.get('/api/v1/workstations/reconcile/' + operation_id, headers={'Authorization': 'Bearer synthetic-scoped'}).status_code == 200


def test_finding_acknowledgement_requires_diagnose_not_link(tmp_path, monkeypatch):
    scoped(tmp_path, monkeypatch, [record(grants=('workstations:link',))])
    client, _ = _client(tmp_path, monkeypatch)
    response = client.post('/api/v1/workstations/findings/' + 'a' * 64 + '/acknowledge',
                           headers={'Authorization': 'Bearer synthetic-scoped'}, json={})
    assert response.status_code == 403
