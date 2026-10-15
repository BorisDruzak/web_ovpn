import re
import uuid

from tests.test_inventory_web import _client
from tests.test_panel_permissions import login_operator


def test_navigation_and_six_stage_wizard_include_disabled_employee_creation(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    page = client.get('/workstations')
    assert page.status_code == 200
    assert 'no-store' in page.headers['cache-control']
    assert 'href="/workstations"' in page.text and 'Рабочие места' in page.text
    for stage in ('device', 'employee', 'options', 'plan', 'confirm', 'watch'):
        assert 'data-step="' + stage + '"' in page.text
    assert re.search(r'<button[^>]*id="employee-create"[^>]*disabled', page.text)
    assert 'Создание пользователей пока недоступно' in page.text
    assert 'data-workstations' in page.text and '/static/workstations.js' in page.text


def test_observer_sees_summary_without_employee_controls_or_private_payload(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    login_operator(client)
    page = client.get('/workstations')
    assert page.status_code == 200 and 'Общая сводка' in page.text
    assert 'data-employee-search' not in page.text
    assert 'data-setup-form' not in page.text
    for path in ('sources', 'reconcile', 'devices/machine:' + str(uuid.uuid4())):
        assert client.get('/workstations/' + path).status_code == 403


def test_job_source_reconciliation_pages_use_stable_typed_identifiers(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    for path in ('sources', 'reconcile', 'jobs/job-20261015T000000Z-12345678', 'devices/machine:' + str(uuid.uuid4())):
        response = client.get('/workstations/' + path)
        assert response.status_code == 200 and 'data-workstations' in response.text
    assert client.get('/workstations/jobs/192.0.2.1').status_code in (404, 422)
    sources = client.get('/workstations/sources').text
    assert 'name="device_key"' in sources and 'name="component"' in sources
    assert 'data-journal-evidence' in sources


def test_plan_view_is_owned_escapes_directory_text_and_requires_current_permission(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.models import WebUser
    from app.workstations.models import WorkstationRequest
    from sqlalchemy import select
    plan_id = 'setup-' + 'a' * 64
    with get_sessionmaker()() as db:
        user = db.scalar(select(WebUser).where(WebUser.username == 'admin'))
        db.add(WorkstationRequest(actor='user:' + str(user.id), action='plans.create', permission='workstations:plan', intent_sha256='b' * 64,
            status='succeeded', data_json={'plan_id': plan_id, 'sha256': 'a' * 64, 'expires_at': '2099-01-01T00:00:00+00:00',
            'machine': {'hostname': 'Synthetic PC'}, 'user': {'login': 'synthetic', 'display_name': '<script>private-marker</script>'}, 'components': []}))
        db.commit()
    page = client.get('/workstations/plans/' + plan_id)
    assert page.status_code == 200 and '<script>private-marker</script>' not in page.text
    assert 'Подтверждаю показанный план' in page.text and 'data-apply-plan' in page.text
    with get_sessionmaker()() as db:
        db.add(WorkstationRequest(actor='user:' + str(user.id), action='plans.apply', permission='workstations:apply', intent_sha256='d' * 64,
            status='succeeded', parameters_json={'plan_id': plan_id}, data_json={'job_id': 'job-20261015T000000Z-12345678'}))
        db.commit()
    closed = client.get('/workstations/plans/' + plan_id)
    assert 'data-submitted="true"' in closed.text
    assert '/workstations/jobs/job-20261015T000000Z-12345678' in closed.text
    login_operator(client, permissions=['workstations:read', 'workstations:plan'])
    assert client.get('/workstations/plans/' + plan_id).status_code == 404


def test_apply_receipt_cannot_be_used_as_a_plan_page(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.models import WebUser
    from app.workstations.models import WorkstationRequest
    from sqlalchemy import select
    plan_id = 'setup-' + 'd' * 64
    with get_sessionmaker()() as db:
        user = db.scalar(select(WebUser).where(WebUser.username == 'admin'))
        db.add(WorkstationRequest(actor='user:' + str(user.id), action='plans.apply', permission='workstations:apply',
            intent_sha256='a' * 64, status='succeeded', data_json={'plan_id': plan_id, 'job_id': 'job-20261015T000000Z-12345678'}))
        db.commit()
        db.add(WorkstationRequest(actor='user:' + str(user.id), action='plans.create', permission='workstations:plan',
            intent_sha256='b' * 64, status='succeeded', data_json={'plan_id': plan_id, 'sha256': 'd' * 64,
            'machine': {'hostname': 'Actual plan machine'}, 'user': {}, 'components': [], 'expires_at': '2099-01-01T00:00:00Z'}))
        db.commit()
    response = client.get('/workstations/plans/' + plan_id)
    assert response.status_code == 200 and 'Actual plan machine' in response.text


def test_blocked_component_plan_shows_reason_and_disables_confirmation(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    from app.db import get_sessionmaker
    from app.models import WebUser
    from app.workstations.models import WorkstationRequest
    from sqlalchemy import select
    plan_id = 'setup-component-' + 'c' * 64
    with get_sessionmaker()() as db:
        user = db.scalar(select(WebUser).where(WebUser.username == 'admin'))
        db.add(WorkstationRequest(actor='user:' + str(user.id), action='component_plans.create',
            permission='workstations:plan', intent_sha256='b' * 64, status='succeeded',
            data_json={'plan_id': plan_id, 'sha256': 'c' * 64, 'machine': {}, 'user': {}, 'components': [],
                'expires_at': '2099-01-01T00:00:00Z', 'action': 'blocked',
                'preflight': {'ready': False, 'error_code': 'component_package_source_unverified'},
                'verification': {'software.onlyoffice': {'status': 'unknown', 'acceptance_status': 'pending'}}}))
        db.commit()
    page = client.get('/workstations/plans/' + plan_id)
    assert page.status_code == 200 and 'Установка заблокирована' in page.text
    assert 'component_package_source_unverified' in page.text and 'unknown' in page.text and 'pending' in page.text
    assert re.search(r'<input[^>]*name="confirmed"[^>]*disabled', page.text)
    assert re.search(r'<button[^>]*type="submit"[^>]*disabled', page.text)
