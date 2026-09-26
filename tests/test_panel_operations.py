import importlib
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db
from app.models import PanelOperation
from app.panel_operations import register, phase, recover


def setup_app(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{(tmp_path / "web.sqlite").as_posix()}')
    monkeypatch.setenv('APP_SECRET_KEY', 'synthetic-secret')
    monkeypatch.setenv('ADMIN_USERNAME', 'admin')
    monkeypatch.setenv('ADMIN_PASSWORD', 'admin-pass')
    db.reset_engine_cache()
    import app.main
    return importlib.reload(app.main)


def wait_status(operation_id, expected):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with db.get_sessionmaker()() as session:
            row = session.get(PanelOperation, operation_id)
            if row.status == expected:
                return row
        threading.Event().wait(.01)
    raise AssertionError(f'operation did not reach {expected}')


def login(client):
    page = client.get('/login')
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post('/login', data={'username':'admin','password':'admin-pass','csrf_token':csrf}, follow_redirects=False)
    assert response.status_code == 303
    return csrf


def test_cli_barrier_keeps_independent_request_responsive_and_reload(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    calls = []
    def synthetic_sync(*args, **kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(5)
        phase('vpnctl:sync', 'succeeded')
        return {'imported_or_updated':1}
    import app.auto_sync
    monkeypatch.setattr(app.auto_sync, 'run_vpnctl', synthetic_sync)
    with TestClient(main.app) as client:
        csrf = login(client)
        response = client.post('/clients/sync', data={'csrf_token':csrf}, follow_redirects=False)
        assert response.status_code == 303
        operation_id = response.headers['x-operation-id']
        try:
            assert entered.wait(2)
            page = client.get('/operations/' + operation_id)
            assert page.status_code == 200
            assert 'data-operation-status="running"' in page.text
            assert client.get('/login').status_code == 200
            duplicate = client.post('/clients/sync', data={'csrf_token':csrf}, follow_redirects=False)
            assert duplicate.headers['x-operation-id'] == operation_id
            assert len(calls) == 1
        finally:
            release.set()
        wait_status(operation_id, 'succeeded')
        assert 'data-operation-status="succeeded"' in client.get('/operations/'+operation_id).text
        assert client.post('/clients/sync', data={'csrf_token':'wrong'}, follow_redirects=False).status_code == 400


def test_concurrent_deduplication_and_distinct_parameters(tmp_path, monkeypatch):
    setup_app(tmp_path, monkeypatch)
    db.init_db()
    entered, release = threading.Event(), threading.Event()
    calls = []
    def execute():
        calls.append(1)
        entered.set()
        assert release.wait(5)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(register, 'admin', 'synthetic', 'vpn:manage', b'alpha', execute) for _ in range(2)]
        result = [future.result() for future in futures]
    try:
        assert result[0][0]['id'] == result[1][0]['id']
        assert sum(created for _, created in result) == 1
        assert entered.wait(2)
        assert len(calls) == 1
        different, created = register('admin','synthetic','vpn:manage',b'beta',lambda:None)
        assert created and different['id'] != result[0][0]['id']
    finally:
        release.set()
    wait_status(result[0][0]['id'],'succeeded')
    wait_status(different['id'],'succeeded')


def test_restart_expiry_does_not_reexecute_and_partial_success(tmp_path, monkeypatch):
    setup_app(tmp_path, monkeypatch)
    db.init_db()
    from datetime import timedelta
    from app.models import utcnow
    with db.get_sessionmaker()() as session:
        session.add(PanelOperation(id='lost', owner='admin', fingerprint='lost', action='generate',
            permission='vpn:manage', status='running', lease_until=utcnow()-timedelta(seconds=1)))
        session.commit()
    recover()
    with db.get_sessionmaker()() as session:
        assert session.get(PanelOperation,'lost').status == 'unknown'
    def partial():
        phase('vpnctl:generate','succeeded')
        phase('vpnctl:sync','unknown')
    operation, _ = register('admin','generate','vpn:manage',b'parameters',partial)
    row = wait_status(operation['id'],'partial')
    assert 'parameters' not in row.phases_json
    assert 'generate' in row.phases_json and 'sync' in row.phases_json

def test_real_executor_process_restart_retains_unknown_and_no_replay(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys
    setup_app(tmp_path, monkeypatch)
    database = tmp_path / 'web.sqlite'
    marker = tmp_path / 'entered.txt'
    environment = dict(os.environ)
    environment['DATABASE_URL'] = f'sqlite:///{database.as_posix()}'
    code = '''
import threading
from pathlib import Path
from app.db import init_db
from app import panel_operations as operations
init_db()
operations.LEASE_SECONDS = 1
marker = Path(__import__('sys').argv[1])
def execute():
    marker.write_text('one execution', encoding='utf-8')
    threading.Event().wait(60)
operation, _ = operations.register('admin','synthetic-restart','vpn:manage',b'alpha',execute)
print(operation['id'], flush=True)
threading.Event().wait(60)
'''
    process = subprocess.Popen([sys.executable, '-c', code, str(marker)], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        operation_id = process.stdout.readline().strip()
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            threading.Event().wait(.01)
        assert marker.exists()
    finally:
        process.kill()
        process.communicate(timeout=5)
    threading.Event().wait(1.1)
    recover()
    executed = []
    operation, created = register('admin','synthetic-restart','vpn:manage',b'alpha',lambda:executed.append(1))
    assert operation['id'] == operation_id
    assert not created and operation['status'] == 'unknown'
    assert executed == []
    assert marker.read_text(encoding='utf-8') == 'one execution'


def test_operation_owner_and_capability_visibility(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    from app.models import WebUser, utcnow
    from datetime import timedelta
    with TestClient(main.app) as client:
        login(client)
        with db.get_sessionmaker()() as session:
            session.add(PanelOperation(id='private', owner='other', fingerprint='private', action='disable',
                permission='vpn:manage',status='succeeded',lease_until=utcnow()+timedelta(seconds=60)))
            session.add(PanelOperation(id='own', owner='user:admin', fingerprint='own', action='disable',
                permission='vpn:manage',status='succeeded',lease_until=utcnow()+timedelta(seconds=60)))
            session.commit()
        assert client.get('/operations/private').status_code == 404
        assert client.get('/operations/private/result').status_code == 404
        assert 'private' not in client.get('/operations').text
        with db.get_sessionmaker()() as session:
            user = session.scalar(select(WebUser).where(WebUser.username == 'admin'))
            user.is_admin = False
            user.is_network_admin = False
            user.permissions_json = '[]'
            session.commit()
        assert client.get('/operations/own').status_code == 403
        assert client.get('/operations/own/result').status_code == 403
        assert 'data-operation-id="own"' not in client.get('/operations').text

def test_generation_success_sync_failure_is_partial_with_audit_no_secret(tmp_path, monkeypatch):
    from test_routes_smoke import make_fake_vpnctl
    main = setup_app(tmp_path, monkeypatch)
    monkeypatch.setenv('VPNCTL_PATH', str(make_fake_vpnctl(tmp_path / 'vpnctl')))
    monkeypatch.setenv('VPNCTL_USE_SUDO', '0')
    db.reset_engine_cache()
    import app.auto_sync
    from app.vpnctl_client import VpnctlError
    from app.models import WebAuditLog
    def fail_sync(*args, **kwargs):
        phase('vpnctl:sync', 'unknown')
        raise VpnctlError('synthetic failure', stderr='SECRET-SYNTHETIC-DO-NOT-EXPOSE')
    monkeypatch.setattr(app.auto_sync, 'run_vpnctl', fail_sync)
    with TestClient(main.app) as client:
        csrf = login(client)
        response = client.post('/clients/new', data={'csrf_token':csrf,'action':'generate',
            'client':'alpha','profile':'directum','access_mode':'template'}, follow_redirects=False)
        operation_id = response.headers['x-operation-id']
        row = wait_status(operation_id, 'partial')
        page = client.get('/operations/' + operation_id)
        assert 'vpnctl:generate-batch' in page.text
        assert 'vpnctl:sync' in page.text
        assert 'SECRET-SYNTHETIC' not in page.text
        assert 'SECRET-SYNTHETIC' not in row.phases_json
        result = client.get('/operations/' + operation_id + '/result')
        assert result.status_code == 200
        assert 'SECRET-SYNTHETIC' not in result.text
        assert 'Внешняя операция не завершена' in result.text
        with db.get_sessionmaker()() as session:
            assert session.scalar(select(WebAuditLog).where(WebAuditLog.action=='client-batch-generate')).result == 'ok'
            assert session.scalar(select(WebAuditLog).where(WebAuditLog.action=='auto-sync')).result == 'error'


def test_additive_operation_schema_init_twice_preserves_existing_user(tmp_path, monkeypatch):
    setup_app(tmp_path, monkeypatch)
    from sqlalchemy import create_engine, inspect, text
    engine = db.get_engine()
    from app.models import WebUser
    WebUser.__table__.create(engine)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO web_users (id, username, password_hash, is_active, is_admin, is_network_admin, permissions_json, created_at) VALUES (42, 'existing', 'unchanged', 1, 0, 0, '[]', CURRENT_TIMESTAMP)"))
    db.init_db()
    db.init_db()
    assert 'panel_operations' in inspect(engine).get_table_names()
    with db.get_sessionmaker()() as session:
        user = session.get(WebUser,42)
        assert user.password_hash == 'unchanged'
        assert not user.is_admin
        assert user.permissions_json == '[]'

def test_api_respond_async_is_owned_and_keeps_barrier_request_responsive(tmp_path, monkeypatch):
    import hashlib
    main = setup_app(tmp_path, monkeypatch)
    monkeypatch.setenv('OPENVPN_WEB_API_TOKEN_HASH',hashlib.sha256(b'synthetic-api-token').hexdigest())
    monkeypatch.setenv('OPENVPN_WEB_API_PERMISSIONS','vpn:read,vpn:manage')
    monkeypatch.setenv('OPENVPN_WEB_API_ACTOR','synthetic-service')
    db.reset_engine_cache()
    import app.api
    entered, release = threading.Event(), threading.Event()
    calls = []
    def synthetic_cli(args, **kwargs):
        assert args == ['sync']
        calls.append(1)
        entered.set()
        assert release.wait(5)
        phase('vpnctl:sync','succeeded')
        return {'status':'ok','imported_or_updated':1}
    monkeypatch.setattr(app.api,'run_vpnctl',synthetic_cli)
    headers={'Authorization':'Bearer synthetic-api-token','Prefer':'respond-async'}
    with TestClient(main.app) as client:
        accepted = client.post('/api/v1/clients/sync',headers=headers)
        assert accepted.status_code == 202
        operation_id = accepted.json()['operation']['id']
        assert accepted.json()['operation']['status_url'] == '/api/v1/operations/' + operation_id
        try:
            assert entered.wait(2)
            retry = client.post('/api/v1/clients/sync',headers=headers)
            assert retry.json()['operation']['id'] == operation_id
            assert calls == [1]
            assert client.get('/api/v1/operations/'+operation_id).status_code == 401
            status = client.get('/api/v1/operations/'+operation_id,headers=headers)
            assert status.json()['operation']['status'] == 'running'
        finally:
            release.set()
        wait_status(operation_id,'succeeded')
        assert client.get('/api/v1/operations/'+operation_id,headers=headers).json()['operation']['status'] == 'succeeded'
        result_url = '/api/v1/operations/'+operation_id+'/result'
        assert client.get(result_url).status_code == 401
        assert client.get(result_url,headers=headers).json()['data']['imported_or_updated'] == 1

def test_unknown_effect_needs_operator_check_even_with_new_intent_key(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    with TestClient(main.app) as client:
        csrf = login(client)
        def uncertain():
            phase('vpnctl:disable','unknown')
        first, _ = register('user:admin','disable','vpn:manage',b'first-key',uncertain,intent=b'alpha')
        wait_status(first['id'],'unknown')
        executions = []
        blocked, created = register('user:admin','disable','vpn:manage',b'new-key',lambda:executions.append(1),intent=b'alpha')
        assert not created and blocked['id'] == first['id']
        assert executions == []
        assert client.post('/operations/'+first['id']+'/verify',data={'csrf_token':csrf}).status_code == 400
        assert client.post('/operations/'+first['id']+'/verify',data={'csrf_token':'wrong','checked_external_result':'1'}).status_code == 400
        acknowledgement = client.post('/operations/'+first['id']+'/verify',data={'csrf_token':csrf,'checked_external_result':'1'},follow_redirects=False)
        assert acknowledgement.status_code == 303
        allowed, created = register('user:admin','disable','vpn:manage',b'new-key',lambda:executions.append(1),intent=b'alpha')
        assert created and allowed['id'] != first['id']
        wait_status(allowed['id'],'succeeded')
        assert executions == [1]


@pytest.mark.parametrize('result_status', ['unknown', 'partial'])
def test_intent_insert_race_stays_blocked_after_first_finishes_uncertain(tmp_path, monkeypatch, result_status):
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    setup_app(tmp_path, monkeypatch)
    db.init_db()
    preflight_finished, resume_insert = threading.Event(), threading.Event()
    executions = []
    result = []
    def hold_insert(session, *_args):
        if threading.current_thread().name == 'delayed-intent-insert' and any(
                isinstance(row, PanelOperation) for row in session.new):
            preflight_finished.set()
            assert resume_insert.wait(5)
    event.listen(Session, 'before_flush', hold_insert)
    def second():
        result.append(register('user:admin', 'race', 'vpn:manage', b'second-key',
            lambda: executions.append('second'), intent=b'same-effect'))
    thread = threading.Thread(target=second, name='delayed-intent-insert')
    try:
        thread.start()
        assert preflight_finished.wait(2)
        def first():
            executions.append('first')
            if result_status == 'partial':
                phase('vpnctl:generate', 'succeeded')
            phase('vpnctl:sync', 'unknown')
        operation, created = register('user:admin', 'race', 'vpn:manage', b'first-key', first, intent=b'same-effect')
        assert created
        wait_status(operation['id'], result_status)
        resume_insert.set()
        thread.join(5)
        assert not thread.is_alive()
        assert result[0][0]['id'] == operation['id'] and not result[0][1]
        assert executions == ['first']
    finally:
        resume_insert.set()
        thread.join(5)
        event.remove(Session, 'before_flush', hold_insert)


def test_fingerprint_background_effect_is_owned_until_cli_finishes(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    executions = []
    def synthetic_cli(args, **kwargs):
        assert args == ['fingerprint', 'ensure', '--asset-key', 'mac:AA:BB:CC:DD:EE:01']
        executions.append(1)
        entered.set()
        assert release.wait(5)
        phase('netctl:external-action', 'succeeded')
        return {'status': 'ok'}
    monkeypatch.setattr(main, 'run_netctl', synthetic_cli)
    with TestClient(main.app) as client:
        csrf = login(client)
        response = client.post('/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/ensure',
            data={'csrf_token': csrf}, follow_redirects=False)
        assert response.status_code == 202
        operation_id = response.headers['x-operation-id']
        try:
            assert entered.wait(2)
            assert 'data-operation-status="running"' in client.get('/operations/'+operation_id).text
            assert client.get('/login').status_code == 200
            retry = client.post('/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/ensure', data={'csrf_token':csrf})
            assert retry.headers['x-operation-id'] == operation_id
            assert executions == [1]
        finally:
            release.set()
        row = wait_status(operation_id, 'succeeded')
        assert 'netctl:external-action' in row.phases_json
        fresh = client.post('/network/assets/mac:AA:BB:CC:DD:EE:01/fingerprint/ensure',
            data={'csrf_token':csrf,'operation_key':'fresh-panel-intent'})
        assert fresh.headers['x-operation-id'] != operation_id
        wait_status(fresh.headers['x-operation-id'], 'succeeded')
        assert executions == [1,1]


def test_init_db_upgrades_existing_ledger_intent_guard(tmp_path, monkeypatch):
    from sqlalchemy import inspect, text
    setup_app(tmp_path, monkeypatch)
    db.init_db()
    engine = db.get_engine()
    with engine.begin() as connection:
        connection.execute(text('DROP INDEX uq_panel_operations_unresolved_intent'))
        connection.execute(text("CREATE UNIQUE INDEX uq_panel_operations_active_intent ON panel_operations (intent_hash) WHERE status IN ('registered', 'running')"))
    db.init_db()
    index_names = {index['name'] for index in inspect(engine).get_indexes('panel_operations')}
    assert 'uq_panel_operations_unresolved_intent' in index_names


def test_custom_preview_preserves_html_and_tracks_catalogue_effect(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    from app.panel_operations import observed_cli
    calls = []
    @observed_cli('vpnctl')
    def synthetic(args, **kwargs):
        calls.append(args)
        if args == ['profiles']:
            return {'profiles': []}
        if args == ['networks', 'list']:
            return {'networks': []}
        if args[:2] == ['networks', 'add']:
            return {'status':'ok'}
        assert args[0] == 'generate-batch' and '--dry-run' in args
        return {'status':'preview','ccd_preview':['CCD-PREVIEW-SYNTHETIC'],'generated_count':1}
    monkeypatch.setattr(main, 'run_vpnctl', synthetic)
    with TestClient(main.app) as client:
        csrf = login(client)
        response = client.post('/clients/new', data={'csrf_token':csrf,'action':'preview',
            'client':'alpha','access_mode':'custom','custom_cidrs':'192.0.2.0/24','dns':'1','comment':'review-marker'})
        assert response.status_code == 200
        assert 'CCD-PREVIEW-SYNTHETIC' in response.text
        assert 'review-marker' in response.text and '192.0.2.0/24' in response.text
        assert calls[-1] == ['generate-batch','--client','alpha','--cidr','192.0.2.0/24','--dns','--comment','review-marker','--dry-run']
        row = wait_status(response.headers['x-operation-id'], 'succeeded')
        assert 'vpnctl:networks' in row.phases_json


def test_invalid_generate_has_owned_result_with_validation_and_original_values(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    monkeypatch.setattr(main, 'run_vpnctl', lambda args, **kwargs: {'profiles':[]})
    with TestClient(main.app) as client:
        csrf = login(client)
        accepted = client.post('/clients/new', data={'csrf_token':csrf,'action':'generate',
            'creation_mode':'bulk','client_names':'invalid name','access_mode':'custom',
            'custom_cidrs':'invalid-cidr','comment':'retained-input'},follow_redirects=False)
        operation_id = accepted.headers['x-operation-id']
        row = wait_status(operation_id, 'failed')
        page = client.get('/operations/'+operation_id)
        assert 'Открыть результат и сообщения' in page.text
        result = client.get('/operations/'+operation_id+'/result')
        assert result.status_code == 400
        assert 'invalid client name: invalid name' in result.text
        assert 'invalid-cidr' in result.text and 'retained-input' in result.text
        assert '<textarea name="client_names">invalid name</textarea>' in result.text
        assert 'retained-input' not in row.phases_json
        from app.panel_operations import forget_future
        forget_future(operation_id)
        assert client.get('/operations/'+operation_id+'/result').status_code == 410
        assert 'data-operation-status="failed"' in client.get('/operations/'+operation_id).text


def test_csv_clone_generate_result_and_artifact_survive_response_cache_loss(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    for name in ['OUT_DIR','SHARE_OUT_DIR','ARCHIVE_DIR']:
        monkeypatch.setenv(name,str(tmp_path))
    db.reset_engine_cache()
    from app.panel_operations import observed_cli, forget_future
    import app.auto_sync
    calls = []
    @observed_cli('vpnctl')
    def synthetic(args, **kwargs):
        calls.append(args)
        if args == ['profiles']:
            return {'profiles': []}
        if args == ['sync']:
            return {'status':'ok','imported_or_updated':2}
        assert args == ['generate-batch','--client','alpha','--client','beta','--template','synthetic','--comment','csv-marker']
        rows = []
        for name in ['alpha','beta']:
            path = tmp_path/(name+'.ovpn')
            path.write_text('synthetic profile\n')
            rows.append({'client':name,'ovpn_path':str(path)})
        return {'status':'ok','generated_count':2,'clients':rows}
    monkeypatch.setattr(main, 'run_vpnctl', synthetic)
    monkeypatch.setattr(app.auto_sync, 'run_vpnctl', synthetic)
    with TestClient(main.app) as client:
        csrf = login(client)
        response = client.post('/clients/new', data={'csrf_token':csrf,'action':'generate',
            'creation_mode':'bulk','access_mode':'template','profile':'synthetic','comment':'csv-marker'},
            files={'clients_csv':('clients.csv',b'client_name\nalpha\nbeta\n','text/csv')},follow_redirects=False)
        operation_id = response.headers['x-operation-id']
        row = wait_status(operation_id,'succeeded')
        result = client.get('/operations/'+operation_id+'/result')
        assert result.status_code == 200 and '2 / 2' in result.text
        assert 'Скачать ZIP' in result.text and 'csv-marker' in result.text
        assert len([call for call in calls if call[0]=='generate-batch']) == 1
        import json
        artifact_id = json.loads(row.artifact_ids_json)[0]
        forget_future(operation_id)
        downloaded = client.get(f'/operations/{operation_id}/files/{artifact_id}')
        assert downloaded.status_code == 200
        import io, zipfile
        assert zipfile.ZipFile(io.BytesIO(downloaded.content)).namelist() == ['alpha.ovpn','beta.ovpn']


def test_cli_flash_result_is_sanitized_before_cache_and_redirect_session(tmp_path, monkeypatch):
    main = setup_app(tmp_path, monkeypatch)
    import app.auto_sync
    from app.vpnctl_client import VpnctlError
    from app.panel_operations import execution_future
    def failed_sync(*args, **kwargs):
        phase('vpnctl:sync','unknown')
        raise VpnctlError('SECRET-SYNTHETIC-MESSAGE',stdout='SECRET-SYNTHETIC-STDOUT',stderr='SECRET-SYNTHETIC-STDERR')
    monkeypatch.setattr(app.auto_sync,'run_vpnctl',failed_sync)
    monkeypatch.setattr(main,'run_vpnctl',lambda args,**kwargs: {'profiles':[],'clients':[]})
    with TestClient(main.app) as client:
        csrf = login(client)
        accepted = client.post('/clients/sync',data={'csrf_token':csrf},follow_redirects=False)
        operation_id = accepted.headers['x-operation-id']
        wait_status(operation_id,'unknown')
        cached = execution_future(operation_id).result()
        assert 'SECRET-SYNTHETIC' not in str(cached._panel_flashes)
        result = client.get('/operations/'+operation_id+'/result')
        assert result.status_code == 200
        assert 'SECRET-SYNTHETIC' not in result.text
        assert 'Внешняя операция не завершена' in result.text


def test_cli_diagnostic_payload_is_sanitized_before_operation_handler(tmp_path, monkeypatch):
    setup_app(tmp_path,monkeypatch)
    db.init_db()
    from app.panel_operations import observed_cli, execution_future
    @observed_cli('vpnctl')
    def external(args):
        return {'status':'error','message':'SECRET-SYNTHETIC','nested':{'stderr':'SECRET-SYNTHETIC'},
            'errors':[{'message':'SECRET-SYNTHETIC','count':1}],'client':'alpha'}
    operation,_ = register('user:admin','synthetic-json','vpn:manage',b'synthetic',lambda:external(['reconnect-client']))
    wait_status(operation['id'],'unknown')
    result = execution_future(operation['id']).result()
    assert 'SECRET-SYNTHETIC' not in str(result)
    assert result['client'] == 'alpha'
    assert isinstance(result['errors'],list) and result['errors'][0]['count'] == 1


def test_default_api_reply_remains_recoverable_after_identical_transport_retry(tmp_path,monkeypatch):
    import hashlib
    main = setup_app(tmp_path,monkeypatch)
    monkeypatch.setenv('OPENVPN_WEB_API_TOKEN_HASH',hashlib.sha256(b'synthetic-api-token').hexdigest())
    monkeypatch.setenv('OPENVPN_WEB_API_PERMISSIONS','vpn:read,vpn:manage')
    monkeypatch.setenv('OPENVPN_WEB_API_ACTOR','synthetic-service')
    db.reset_engine_cache()
    import app.api
    calls = []
    def synthetic_cli(args,**kwargs):
        assert args == ['sync']
        calls.append(1)
        phase('vpnctl:sync','succeeded')
        return {'status':'ok','imported_or_updated':123}
    monkeypatch.setattr(app.api,'run_vpnctl',synthetic_cli)
    headers={'Authorization':'Bearer synthetic-api-token','Idempotency-Key':'one-intent'}
    with TestClient(main.app) as client:
        first = client.post('/api/v1/clients/sync',headers=headers)
        assert first.status_code == 200 and first.json()['data']['imported_or_updated'] == 123
        operation_id = first.headers['x-operation-id']
        # Treat the first reply as lost in transport: retry must recover its
        # original result without asking the CLI to execute again.
        retry = client.post('/api/v1/clients/sync',headers=headers)
        assert retry.status_code == 202
        operation = retry.json()['operation']
        assert operation['id'] == operation_id and operation['result_available']
        recovered = client.get(operation['result_url'],headers=headers)
        assert recovered.status_code == 200 and recovered.json() == first.json()
        assert calls == [1]
