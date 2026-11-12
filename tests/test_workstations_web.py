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


def test_ordinary_wizard_fixes_full_preset_and_direct_vnc(tmp_path,monkeypatch):
    client,_=_client(tmp_path,monkeypatch)
    page=client.get('/workstations').text
    assert re.search(r'<input[^>]*name="software_profile"[^>]*value="workstation-full-v1"',page)
    assert re.search(r'<input[^>]*name="remote_access_profile"[^>]*value="krfb"',page)
    assert '<select name="software_profile"' not in page
    assert '<select name="remote_access_profile"' not in page
    assert 'data-complete-preset' in page
    assert '5900' in page
    assert 'data-workflow-phases' in client.get('/workstations/jobs/job-20261015T000000Z-12345678').text


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


def test_windows_inventory_install_view_hands_off_to_the_enrollment_console(tmp_path, monkeypatch):
    from app.db import session_scope
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryPCDetails

    monkeypatch.setenv("ENDPOINT_PLATFORM_ENABLED", "true")
    monkeypatch.setenv("ENDPOINT_PLATFORM_BASE_URL", "https://endpoint.fixture.invalid")
    client, _csrf = _client(tmp_path, monkeypatch)
    asset_id = str(uuid.uuid4())
    with session_scope() as db:
        db.add(InventoryAsset(id=asset_id, asset_type=InventoryAssetType.PC, custom_name="Fixture Windows PC"))
        db.flush()
        db.add(InventoryPCDetails(asset_id=asset_id, os_name="Windows 11"))

    route = f"/workstations/inventory/{asset_id}/endpoint-agent"
    card = client.get(f"/inventory/assets/{asset_id}")
    assert card.status_code == 200 and route in card.text
    response = client.get(route)
    assert response.status_code == 200
    assert "Fixture Windows PC" in response.text
    assert "https://endpoint.fixture.invalid/admin/enrollment" in response.text
    assert "data-endpoint-plan=" not in response.text


def test_windows_staging_assignment_is_owned_retriable_and_binds_only_on_heartbeat(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from fastapi.testclient import TestClient
    from sqlalchemy import select
    from app.db import get_sessionmaker, session_scope
    from app.config import get_settings
    from app.endpoint_platform_client import EndpointPlatformServiceUnavailable
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryExternalBinding, InventoryPCDetails
    from app.workstations import windows_installation
    from app.workstations.endpoint_receipts import sync_installation_receipts
    from app.workstations.models import WorkstationRequest

    asset_id, request_id, release_id, device_id = (uuid.uuid4() for _ in range(4))
    fingerprint = 'sha256:' + 'a' * 64
    issued_at = None
    calls = []

    class Endpoint:
        def issue_inventory_installation(self, assignment_id, proof, platform):
            nonlocal issued_at
            calls.append(assignment_id)
            assert proof == fingerprint and platform == 'windows'
            with session_scope() as db:
                db.add(InventoryAsset(id=str(uuid.uuid4()), asset_type=InventoryAssetType.PC))
            if len(calls) == 1:
                raise EndpointPlatformServiceUnavailable()
            issued_at = datetime.now(timezone.utc)
            return SimpleNamespace(issued_at=issued_at, expires_at=issued_at + timedelta(minutes=30))

        def lookup_inventory_installation(self, assignment_id):
            assert assignment_id == calls[0]
            assert issued_at is not None
            return SimpleNamespace(state='connected', device_id=device_id,
                registered_at=issued_at + timedelta(seconds=4), heartbeat_at=issued_at + timedelta(seconds=5))

        def close(self):
            pass

    monkeypatch.setenv('WORKSTATIONS_ENABLED', 'true')
    monkeypatch.setenv('ENDPOINT_PLATFORM_ENABLED', 'true')
    monkeypatch.setenv('ENDPOINT_PLATFORM_BASE_URL', 'https://endpoint-staging.sosnadmin.local')
    monkeypatch.setenv('ENDPOINT_PLATFORM_INSTALLATION_TOKEN_FILE', str(tmp_path / 'test.token'))
    monkeypatch.setenv('ENDPOINT_PLATFORM_WINDOWS_INVENTORY_SETUP_RELEASE', str(release_id))
    monkeypatch.setattr(windows_installation, 'get_endpoint_installation_client', lambda _: Endpoint())
    client, _ = _client(tmp_path, monkeypatch)
    with session_scope() as db:
        db.add(InventoryAsset(id=str(asset_id), asset_type=InventoryAssetType.PC, manual_revision=1))
        db.flush()
        db.add(InventoryPCDetails(asset_id=str(asset_id), os_name='Windows 11'))

    view = f'/workstations/inventory/{asset_id}/endpoint-agent'
    page = client.get(view)
    assert f'/installer/releases/{release_id}/download' in page.text and 'data-windows-assignment' in page.text
    csrf = re.search(r'data-csrf="([^"]+)"', page.text).group(1)
    api = f'/api/v1/workstations/inventory/{asset_id}/endpoint-agent-assignment'
    revision = int(re.search(r'data-asset-revision="(\d+)"', page.text).group(1))
    payload = {'request_id': str(request_id), 'expected_revision': revision, 'hardware_fingerprint': fingerprint, 'confirmed': True}
    apply_only = TestClient(client.app)
    login_operator(apply_only, permissions=['workstations:read', 'workstations:apply'])
    restricted = apply_only.get(view)
    assert restricted.status_code == 200 and 'data-windows-assignment' not in restricted.text
    operator_csrf = re.search(r'data-csrf="([^"]+)"', restricted.text).group(1)
    assert apply_only.post(api, json=payload, headers={'X-CSRF-Token': operator_csrf}).status_code == 403
    apply_only.close()
    assert client.post(api, json=payload).status_code == 400
    headers = {'X-CSRF-Token': csrf}
    assert client.post(api, json={**payload, 'expected_revision': revision + 1}, headers=headers).status_code == 409
    assert client.post(api, json=payload, headers=headers).status_code == 503
    assert f'data-request-id="{request_id}"' in client.get(view).text
    assert client.post(api, json={**payload, 'request_id': str(uuid.uuid4())}, headers=headers).status_code == 409
    first = client.post(api, json=payload, headers=headers)
    assert first.status_code == 200, first.text
    assert calls == [calls[0], calls[0]]
    assert 'no-store' in first.headers['cache-control']
    handoff = first.json()['data']['assignment']
    assert handoff == {'schema_version': 'endpoint_windows_inventory_assignment_v1',
                       'installation_id': calls[0], 'hardware_fingerprint': fingerprint}
    repeated = client.post(api, json=payload, headers=headers)
    assert repeated.status_code == 200 and repeated.json()['data']['assignment'] == handoff
    assert client.post(api, json={**payload, 'request_id': str(uuid.uuid4())}, headers=headers).status_code == 409
    assert client.post(api, json={**payload, 'hardware_fingerprint': 'sha256:' + 'b' * 64}, headers=headers).status_code == 409
    with session_scope() as db:
        row = db.get(WorkstationRequest, str(request_id))
        assert fingerprint not in str(row.parameters_json) and calls[0] not in str(row.parameters_json)
        assert db.scalar(select(InventoryExternalBinding)) is None
    assert calls[0] not in client.get(view).text
    assert issued_at is not None
    sync_installation_receipts(get_sessionmaker(), Endpoint(), clock=lambda: issued_at + timedelta(seconds=6),
                               windows_secret=get_settings().app_secret_key)
    with session_scope() as db:
        row = db.get(WorkstationRequest, str(request_id))
        assert row.data_json['installation_binding_state'] == 'connected'
        assert db.scalar(select(InventoryExternalBinding)).external_id == str(device_id)
