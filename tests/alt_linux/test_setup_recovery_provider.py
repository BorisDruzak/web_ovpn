from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest, private_read
from alt_deploy.setup_recovery import RecoveryPlanStore, RecoveryAttemptStore, evidence_document
from test_setup_recovery_credential import codec_fixture
from test_setup_recovery_state import NOW, RUN, GUID, evidence


def scenario(root):
    from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
    from alt_deploy.setup_recovery_provider import RecoveryPasswordProvider, PROVIDER
    machine = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    computer = {'object_guid': GUID, 'object_sid': 'S-1-5-21-111-222-333-1002',
        'dn': 'CN=alt-a1-pc3,OU=Synthetic,DC=sosnadmin,DC=local',
        'dns_hostname': 'alt-a1-pc3.sosnadmin.local', 'sam_account_name': 'alt-a1-pc3$',
        'when_created': NOW.isoformat(), 'pwd_last_set': 134046000000000000, 'kvno': 2,
        'uac': 4096, 'spns': ['HOST/alt-a1-pc3', 'HOST/alt-a1-pc3.sosnadmin.local',
            'RestrictedKrbHost/alt-a1-pc3', 'RestrictedKrbHost/alt-a1-pc3.sosnadmin.local'],
        'dc': {'uri': 'ldap://synthetic-dc.sosnadmin.local', 'is_writable': True}}
    raw = evidence()
    snapshot = {'failed_run_id': RUN, 'computer_guid': GUID, 'machine_uuid': machine,
        'computer_sid': computer['object_sid'], 'evidence_sha256': digest(evidence_document(raw)),
        'computer': copy.deepcopy(computer), 'machine': {'hostname': 'alt-a1-pc3'},
        'prerequisites': {'source_sha256': 'e' * 64}, 'execution_available': False}
    payload = {key: snapshot[key] for key in ('failed_run_id', 'computer_guid', 'machine_uuid', 'computer_sid', 'evidence_sha256')}
    payload.update(execution_available=True, provider=PROVIDER, snapshot=copy.deepcopy(snapshot))
    plans = RecoveryPlanStore(root, clock=lambda: NOW); plan = plans.create(payload)
    attempts = RecoveryAttemptStore(root, clock=lambda: NOW)
    claim = attempts.reserve(plan['plan_id'], plan['sha256'], raw)
    codec, _, _ = codec_fixture(root); credentials = RecoveryCredentialStore(root, codec=codec)
    sealed = credentials.create(RUN, GUID)
    calls, cleaned = [], []
    transport = SimpleNamespace(config=SimpleNamespace(uri=computer['dc']['uri'], auth='gssapi', credential_source='join-vault'), minimum_ssf=128)
    @contextmanager
    def authenticate(environment):
        try: yield dict(environment, KRB5CCNAME='FILE:/synthetic/cache'), []
        finally: cleaned.append(True)
    transport._credentials = authenticate
    directory = SimpleNamespace(transport=transport, inspect_computer=lambda hostname, guid: copy.deepcopy(computer))
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        computer['kvno'] += 1; computer['pwd_last_set'] += 10000000
        return 0, 'SYNTHETIC_SECRET_STDOUT', 'SYNTHETIC_SECRET_STDERR'
    def prepare(payload, claim, sealed, password):
        return {'schema_version': 1, 'claim_sha256': digest(claim), 'sealed_sha256': sealed['sealed_sha256'],
            'snapshot_sha256': digest(payload['snapshot']), 'controller_backup_verified': True,
            'workstation_backup_verified': True, 'local_rehearsal_verified': True,
            'controller_backup_sha256': '1' * 64, 'workstation_backup_sha256': '2' * 64,
            'local_rehearsal_sha256': '3' * 64,'services_quiesced_verified':True,'services_quiesced_sha256':'4'*64}
    prepare.last_service_check=lambda payload,claim,sealed,password,prepared:copy.deepcopy(prepared)
    def build(**changes):
        options = dict(directory=directory, credentials=credentials, fresh_check=lambda payload: copy.deepcopy(snapshot),
            prewrite=prepare, runner=runner, fingerprint=lambda: 'e' * 64, clock=lambda: NOW)
        options.update(changes)
        return RecoveryPasswordProvider(SimpleNamespace(state_root=root, lock_file=root/'workstationctl.lock'), **options)
    return build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare


def test_one_guid_only_write_has_durable_intent_and_safe_result(tmp_path):
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    provider = build()
    original = provider.runner
    def checked(command, **kwargs):
        assert private_read(provider.intent_path(RUN, GUID))['status'] == 'write_intended'
        return original(command, **kwargs)
    provider.runner = checked
    result = provider.write_once(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'directory_password_written' and len(calls) == 1 and cleaned == [True]
    command, arguments = calls[0]
    assert command[0] == '/usr/bin/ldapmodify' and 'minssf=128' in command
    assert '-C' not in command and '-c' not in command and '-n' not in command
    assert arguments['environment']['LDAPNOINIT'] == '1'
    assert 'LDAPURI' not in arguments['environment']
    password = credentials.open(RUN, GUID)
    assert password not in str(command) and 'SYNTHETIC_SECRET' not in str(result)
    ldif = arguments['input_text']; assert ldif.startswith('dn: <GUID=' + GUID + '>\n')
    assert ldif.count('changetype: modify') == 1 and ldif.count('replace: unicodePwd') == 1
    value = ldif.split('unicodePwd:: ')[1].splitlines()[0]
    assert base64.b64decode(value).decode('utf-16-le') == '"' + password + '"'
    with pytest.raises(ControlError): provider.write_once(plan['plan_id'], plan['sha256'])
    assert len(calls) == 1


def test_preparation_without_verified_service_quiescence_never_writes(tmp_path):
    build,plan,attempts,credentials,computer,snapshot,calls,cleaned,prepare=scenario(tmp_path)
    def missing(*args):
        result=prepare(*args)
        result.pop('services_quiesced_verified',None)
        result.pop('services_quiesced_sha256',None)
        return result
    missing.last_service_check=prepare.last_service_check
    with pytest.raises(ControlError):build(prewrite=missing).write_once(plan['plan_id'],plan['sha256'])
    assert calls==[]


@pytest.mark.parametrize('guard', ['unimplemented', 'snapshot', 'source', 'uri', 'auth', 'credential_source',
    'ssf', 'computer', 'backup', 'local_backup', 'rehearsal', 'preparation_identity', 'expired', 'sha'])
def test_guards_never_call_ldap_writer(tmp_path, guard):
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    changes = {}
    if guard == 'unimplemented': changes['prewrite'] = None
    elif guard == 'snapshot': snapshot['machine']['hostname'] = 'alt-a1-pc4'
    elif guard == 'source': changes['fingerprint'] = lambda: 'f' * 64
    elif guard == 'computer': computer['object_guid'] = snapshot['machine_uuid']
    elif guard == 'expired': changes['clock'] = lambda: NOW + timedelta(minutes=30)
    elif guard in ('backup', 'local_backup', 'rehearsal', 'preparation_identity'):
        def bad(*args):
            value = prepare(*args)
            key = {'backup':'controller_backup_verified', 'local_backup':'workstation_backup_verified',
                'rehearsal':'local_rehearsal_verified', 'preparation_identity':'claim_sha256'}[guard]
            value[key] = False if key.endswith('verified') else 'f'*64
            return value
        bad.last_service_check=prepare.last_service_check
        changes['prewrite'] = bad
    provider = build(**changes)
    if guard == 'uri': provider.directory.transport.config.uri = 'ldap://other-dc.sosnadmin.local'
    elif guard == 'auth': provider.directory.transport.config.auth = 'starttls'
    elif guard == 'credential_source': provider.directory.transport.config.credential_source = 'ticket'
    elif guard == 'ssf': provider.directory.transport.minimum_ssf = 56
    sha = 'f'*64 if guard == 'sha' else plan['sha256']
    with pytest.raises(ControlError): provider.write_once(plan['plan_id'], sha)
    assert calls == []


@pytest.mark.parametrize('failure', ['returncode', 'timeout', 'changed_identity', 'missing_increment', 'result_storage'])
def test_ambiguous_write_remains_non_retryable_without_diagnostics(tmp_path, monkeypatch, failure):
    from alt_deploy import setup_recovery_provider as module
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    provider = build(); original = provider.runner
    def failed(command, **kwargs):
        original(command, **kwargs)
        if failure == 'timeout': raise RuntimeError('SYNTHETIC_SECRET')
        if failure == 'changed_identity': computer['dn'] = 'CN=other,OU=Other,DC=sosnadmin,DC=local'
        if failure == 'missing_increment': computer['kvno'] -= 1
        return (50 if failure == 'returncode' else 0), 'SYNTHETIC_SECRET', 'SYNTHETIC_SECRET'
    provider.runner = failed
    if failure == 'result_storage':
        old = module.private_create
        def fail_result(path, value):
            if path.name.endswith('.ad-write-result.json'): raise OSError('SYNTHETIC_SECRET')
            return old(path, value)
        monkeypatch.setattr(module, 'private_create', fail_result)
    with pytest.raises(ControlError) as caught: provider.write_once(plan['plan_id'], plan['sha256'])
    assert 'SYNTHETIC_SECRET' not in str(caught.value) and len(calls) == 1 and cleaned == [True]
    receipt = private_read(attempts._path(RUN, GUID, '.receipt.json'))
    assert receipt['status'] == 'ambiguous'
    with pytest.raises(ControlError): provider.write_once(plan['plan_id'], plan['sha256'])
    assert len(calls) == 1


@pytest.mark.parametrize('drift', ['identity', 'expiry'])
def test_authentication_delay_or_drift_is_checked_before_intent(tmp_path, drift):
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    now = [NOW]
    provider = build(clock=lambda: now[0])
    @contextmanager
    def changed(environment):
        if drift == 'identity': computer['dn'] = 'CN=other,OU=Other,DC=sosnadmin,DC=local'
        else: now[0] = NOW + timedelta(minutes=30)
        try: yield environment, []
        finally: cleaned.append(True)
    provider.directory.transport._credentials = changed
    with pytest.raises(ControlError): provider.write_once(plan['plan_id'], plan['sha256'])
    assert calls == [] and cleaned == [True]
    assert not provider.intent_path(RUN, GUID).exists()


@pytest.mark.parametrize('failure', ['intent_storage', 'intent_sync', 'authentication'])
def test_failure_before_writer_never_sends_modify(tmp_path, monkeypatch, failure):
    from alt_deploy import setup_recovery_provider as module
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    provider = build()
    if failure == 'intent_storage':
        original = module.private_create
        def broken(path, value):
            if path == provider.intent_path(RUN, GUID): raise OSError('SYNTHETIC_SECRET')
            return original(path, value)
        monkeypatch.setattr(module, 'private_create', broken)
    elif failure == 'intent_sync':
        monkeypatch.setattr(module, '_sync_directory', lambda path: (_ for _ in ()).throw(OSError('SYNTHETIC_SECRET')))
    else:
        @contextmanager
        def failed(environment):
            raise RuntimeError('SYNTHETIC_SECRET')
            yield
        provider.directory.transport._credentials = failed
    with pytest.raises(ControlError) as caught: provider.write_once(plan['plan_id'], plan['sha256'])
    assert calls == [] and 'SYNTHETIC_SECRET' not in str(caught.value)
    assert private_read(attempts._path(RUN, GUID, '.receipt.json'))['status'] == 'failed'


def test_concurrent_requests_send_at_most_one_modify(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    def execute():
        try: return build().write_once(plan['plan_id'], plan['sha256'])['status']
        except ControlError: return 'refused'
    with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(lambda _: execute(), range(2)))
    assert sorted(results) == ['directory_password_written', 'refused'] and len(calls) == 1


@pytest.mark.parametrize('stage', ['open', 'rehearsal', 'authentication', 'intent_sync'])
def test_credential_change_refuses_modify(tmp_path, monkeypatch, stage):
    import hashlib, json
    from alt_deploy.setup_plans import private_replace
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    provider = build()
    def replace_credential():
        path = credentials.path(RUN, GUID); document = private_read(path)
        inner = json.loads(credentials.codec.unseal(document['ciphertext']))
        inner['machine_password'] = 'Aa9!' + 'b' * 64
        document['ciphertext'] = credentials.codec.seal(json.dumps(inner))
        document['sealed_sha256'] = hashlib.sha256(document['ciphertext'].encode()).hexdigest()
        private_replace(path, document)
        ready_path = credentials._ready_path(RUN, GUID); ready = private_read(ready_path)
        ready['sealed_sha256'] = document['sealed_sha256']; ready['document_sha256'] = digest(document)
        private_replace(ready_path, ready)
    if stage == 'rehearsal':
        def changed(payload, claim, sealed, password):
            result = prepare(payload, claim, sealed, password)
            replace_credential()
            return result
        changed.last_service_check=prepare.last_service_check
        provider.prewrite = changed
    elif stage == 'open':
        original = credentials.open
        def changed(**pair):
            password = original(**pair)
            replace_credential()
            return password
        monkeypatch.setattr(credentials, 'open', changed)
    elif stage == 'authentication':
        @contextmanager
        def changed(environment):
            replace_credential()
            yield environment, []
        provider.directory.transport._credentials = changed
    else:
        from alt_deploy import setup_recovery_provider as module
        original = module._sync_directory
        def changed(path):
            original(path)
            replace_credential()
        monkeypatch.setattr(module, '_sync_directory', changed)
    with pytest.raises(ControlError): provider.write_once(plan['plan_id'], plan['sha256'])
    assert calls == []


def test_readonly_plan_is_not_an_execution_authorization(tmp_path):
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    payload = copy.deepcopy(plan['payload']); payload['execution_available'] = False
    readonly = RecoveryPlanStore(tmp_path, clock=lambda: NOW).create(payload)
    with pytest.raises(ControlError): build().write_once(readonly['plan_id'], readonly['sha256'])
    assert calls == []


def test_expiry_during_final_credential_open_refuses_modify(tmp_path, monkeypatch):
    build, plan, attempts, credentials, computer, snapshot, calls, cleaned, prepare = scenario(tmp_path)
    now = [NOW]
    provider = build(clock=lambda: now[0])
    original = credentials.open
    def delayed(**pair):
        password = original(**pair)
        if provider.intent_path(RUN, GUID).exists():
            now[0] = NOW + timedelta(minutes=30)
        return password
    monkeypatch.setattr(credentials, 'open', delayed)
    with pytest.raises(ControlError): provider.write_once(plan['plan_id'], plan['sha256'])
    assert calls == [] and provider.intent_path(RUN, GUID).exists()
    assert private_read(attempts._path(RUN, GUID, '.receipt.json'))['status'] == 'failed'


def test_missing_fixed_last_service_check_refuses_before_intent(tmp_path):
    build,plan,attempts,credentials,computer,snapshot,calls,cleaned,prepare=scenario(tmp_path)
    del prepare.last_service_check
    provider=build()
    with pytest.raises(ControlError):provider.write_once(plan['plan_id'],plan['sha256'])
    assert calls==[] and not provider.intent_path(RUN,GUID).exists()


@pytest.mark.parametrize('change',['expiry','source'])
def test_final_service_delay_rechecks_ttl_and_source_before_modify(tmp_path,change):
    build,plan,attempts,credentials,computer,snapshot,calls,cleaned,prepare=scenario(tmp_path)
    now=[NOW];source=['e'*64]
    def delayed(payload,claim,sealed,password,prepared):
        if change=='expiry':now[0]=NOW+timedelta(minutes=30)
        else:source[0]='f'*64
        return copy.deepcopy(prepared)
    prepare.last_service_check=delayed
    provider=build(clock=lambda:now[0],fingerprint=lambda:source[0])
    with pytest.raises(ControlError):provider.write_once(plan['plan_id'],plan['sha256'])
    assert calls==[]
