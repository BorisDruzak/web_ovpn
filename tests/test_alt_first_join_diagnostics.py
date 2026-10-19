"""Lost native replies cannot become retry authority or leak raw diagnostics."""
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest

from test_alt_first_join_compat import helper, native_join_argv

ASSETS = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible/roles/domain_join/files'
BINDING = {'schema_version': 1, 'configuration_run_id': 'a' * 32,
           'invocation_id': 'b' * 32, 'identity_sha256': 'c' * 64}


def test_admission_rejection_precedes_native_local_switch(tmp_path, monkeypatch):
    m = helper()
    source = tmp_path / 'system-auth'
    source.write_text('net_cmd="/usr/bin/net"\n# target-server:\n')
    monkeypatch.setattr(m, 'trusted_file', lambda path: source)
    monkeypatch.setattr(m, 'adapt_system_auth', lambda text, wrapper: text)
    monkeypatch.setattr(m, 'SYSTEM_KEYTAB', str(tmp_path / 'absent'))
    monkeypatch.setattr(m, 'ldap', lambda *args: '')
    temporary = m.tempfile.TemporaryDirectory
    monkeypatch.setattr(m.tempfile, 'TemporaryDirectory',
                        lambda **kw: temporary(prefix=kw['prefix'], dir=tmp_path))
    writes = []
    def native(argv, **kwargs):
        if argv[0] == '/usr/bin/rpm':
            return SimpleNamespace(returncode=0, stdout='4.21.10', stderr='')
        if argv == ['/usr/bin/net', 'ads', 'testjoin']:
            return SimpleNamespace(returncode=1, stdout='', stderr='')
        if argv == ['/usr/sbin/system-auth', 'status']:
            return SimpleNamespace(returncode=0, stdout='local', stderr='')
        writes.append(argv)
        raise AssertionError('A write was reached before AD admission')
    monkeypatch.setattr(m, 'run', native)
    def rejected(*args):
        raise ValueError('ad_join_quota_exhausted')
    monkeypatch.setattr(m, 'check_ad_join', rejected, raising=False)
    command = ['system-auth', 'write', 'ad', 'example.test', 'vm-test', 'EXAMPLE',
               'join-user', '--createcomputer=TEST', '--gpo']
    with pytest.raises(ValueError, match='ad_join_quota_exhausted'):
        m.first_join('ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', command)
    assert writes == []


def diagnostics():
    path = ASSETS / 'first_join_diagnostics.py'
    assert path.exists(), 'Missing durable safe first-join diagnostic contract'
    spec = spec_from_file_location('first_join_diagnostics', path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('message', ['WERR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED',
    'ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED', 'NT_STATUS_QUOTA_EXCEEDED',
    'The maximum number of computer accounts you are allowed to create has been exceeded'])
def test_native_quota_failure_has_its_own_code(message):
    assert diagnostics().native_failure_code(message) == 'first_join_native_quota_exhausted'


def test_safe_timeline_retains_every_phase_and_native_status_without_raw_output(tmp_path):
    m = diagnostics()
    d = m.Diagnostics(BINDING, root=tmp_path / 'private')
    assert callable(getattr(d, 'native_result', None)), 'Native failure context is discarded'
    d.intent('native_execution')
    d.native_result(subprocess.CompletedProcess(['net'], 255,
        'PRIVATE_PASSWORD_SENTINEL NT_STATUS_PRIVATE_PASSWORD_SENTINEL',
        'LDAP error 50 WERR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED PRIVATE_KEYTAB_SENTINEL'))
    d.result('native_execution', code='first_join_native_quota_exhausted', returncode=255)
    d.publish()
    path = d.directory / (BINDING['invocation_id'] + '.timeline.jsonl')
    raw = path.read_text()
    assert 'SENTINEL' not in raw
    records = [json.loads(line) for line in raw.splitlines()]
    native = next(r for r in records if r['event'] == 'native_result')
    assert native['phase'] == 'native_execution' and native['returncode'] == 255
    assert native['observed_at'].endswith('+00:00')
    assert native['statuses'] == ['WERR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED']
    assert native['ldap_result_codes'] == [50]
    assert len(native['stderr_sha256']) == 64
    assert any(r['event'] == 'state' and r['directory_effect'] == 'dispatch_entered' for r in records)
    assert path.stat().st_mode & 0o777 == 0o600


def test_confirmed_ad_admission_records_the_quota_exemption(tmp_path):
    d = diagnostics().Diagnostics(BINDING, root=tmp_path / 'private')
    assert callable(getattr(d, 'admission_result', None)), 'Fresh AD admission facts are discarded'
    d.intent('admission')
    d.admission_result({'domain_quota': 10, 'created_computers': 10, 'quota_remaining': 0,
                        'quota_applicable': False, 'creation_mode': 'delegated',
                        'unrelated_secret': 'PRIVATE_SENTINEL'})
    raw = d.timeline.read_text()
    assert 'PRIVATE_SENTINEL' not in raw
    value = json.loads(raw.splitlines()[-1])
    assert value['event'] == 'ad_admission' and value['creation_mode'] == 'delegated'
    assert value['quota_applicable'] is False and value['created_computers'] == 10


def test_safe_timeline_rejects_a_foreign_symlink(tmp_path):
    d = diagnostics().Diagnostics(BINDING, root=tmp_path / 'private')
    assert callable(getattr(d, 'native_result', None)), 'No protected timeline exists'
    foreign = tmp_path / 'foreign'
    foreign.write_text('preserve')
    (d.directory / (BINDING['invocation_id'] + '.timeline.jsonl')).symlink_to(foreign)
    with pytest.raises((ValueError, OSError)):
        d.native_result(subprocess.CompletedProcess(['net'], 255, '', 'error'))
    assert foreign.read_text() == 'preserve'


def test_native_admission_rejects_changed_reviewed_identity(tmp_path, monkeypatch):
    m = helper()
    actual = {'join_principal_guid': '1'*32, 'join_principal_sid': 'S-1-5-21-1',
              'ou_guid': '2'*32, 'dc': 'dc.example.test'}
    reviewed = dict(actual, ou_guid='3'*32)
    asset = tmp_path / 'admission_fixture.py'
    asset.write_text('read_process=None\ndef check(*args): return ' + repr(actual) + '\n')
    monkeypatch.setattr(m, 'trusted_file', lambda path: asset)
    monkeypatch.setenv('ALT_FIRST_JOIN_AD_SCOPE', json.dumps(reviewed))
    with pytest.raises(ValueError, match='identity'):
        m.check_ad_join('ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', 'join-user')


def test_wrapper_reply_loss_retains_uncertain_effect(tmp_path):
    m = diagnostics()
    root = tmp_path / 'evidence'
    parent = m.Diagnostics(BINDING, root=root)
    child = m.Diagnostics(BINDING, root=root)
    child.intent('native_execution')
    # Parent has no successful child reply; it must read shared write intent.
    result = parent.publish()
    assert result['directory_effect'] == 'uncertain'
    assert result['code'] == 'first_join_internal_error'
    with pytest.raises(ValueError):
        child.result('native_execution', code='first_join_ok', returncode=0)


def test_receipt_survives_private_wrapper_cleanup(tmp_path):
    m = diagnostics()
    root = tmp_path / 'evidence'
    native_directory = tmp_path / 'private-wrapper'
    native_directory.mkdir()
    d = m.Diagnostics(BINDING, root=root)
    d.intent('native_execution')
    d.result('native_execution', code='first_join_ok', returncode=0)
    d.intent('keytab_bind')
    d.result('keytab_bind', code='first_join_keytab_bind_failed', returncode=None)
    d.publish()
    native_directory.rmdir()
    public = m.read_public(BINDING, root=root)
    assert public == {**BINDING, 'phase': 'keytab_bind',
                      'code': 'first_join_keytab_bind_failed',
                      'directory_effect': 'returned_success'}
    assert 'returncode' not in public


@pytest.mark.parametrize('change', ['foreign', 'unsafe_mode', 'symlink', 'oversized'])
def test_foreign_or_unsafe_receipt_is_never_read(tmp_path, change):
    m = diagnostics()
    root = tmp_path / 'evidence'
    d = m.Diagnostics(BINDING, root=root)
    d.result('request', code='first_join_request_invalid', returncode=None)
    d.publish()
    path = root / BINDING['configuration_run_id'] / (BINDING['invocation_id'] + '.json')
    request = dict(BINDING)
    if change == 'foreign':
        request['identity_sha256'] = 'd' * 64
    elif change == 'unsafe_mode':
        path.chmod(0o644)
    elif change == 'symlink':
        real = path.with_suffix('.retained')
        path.rename(real)
        path.symlink_to(real)
    else:
        path.write_text('x' * 4097)
    with pytest.raises(ValueError):
        m.read_public(request, root=root)


def test_unrecognized_result_cannot_serialize_private_text(tmp_path):
    m = diagnostics()
    root = tmp_path / 'evidence'
    d = m.Diagnostics(BINDING, root=root)
    with pytest.raises(ValueError):
        d.result('native_execution', code='SENTINEL-private-native-output', returncode=1)
    d.publish()
    assert 'SENTINEL' not in ''.join(p.read_text() for p in root.rglob('*.json'))


@pytest.mark.parametrize('phase,code', [
    ('request', 'request_invalid'), ('native_interface', 'native_interface_invalid'),
    ('preconditions', 'local_state_conflict'), ('directory_observation', 'directory_unavailable'),
    ('native_arguments', 'native_arguments_invalid'), ('native_execution', 'native_failed'),
    ('offline_keytab', 'keytab_create_failed'), ('keytab_bind', 'keytab_bind_failed'),
    ('trust_verify', 'trust_failed'), ('machine_as', 'machine_as_failed'),
])
def test_failure_phase_is_retained_without_exception_text(tmp_path, phase, code):
    m = diagnostics()
    d = m.Diagnostics(BINDING, root=tmp_path / 'evidence')
    d.result(phase, code='first_join_' + code, returncode=1)
    receipt = d.publish()
    assert receipt['phase'] == phase
    assert receipt['code'] == 'first_join_' + code
    assert receipt['directory_effect'] == 'not_dispatched'


@pytest.mark.parametrize('output,expected', [
    ('NT_STATUS_ACCESS_DENIED SENTINEL-private', 'first_join_native_access_denied'),
    ('NT_STATUS_LOGON_FAILURE SENTINEL-private', 'first_join_native_kerberos_failed'),
    ('NT_STATUS_OBJECT_NAME_COLLISION SENTINEL-private', 'first_join_native_name_collision'),
    ('No credentials cache found SENTINEL-private', 'first_join_native_cache_unavailable'),
    ('SENTINEL-private-unrecognized', 'first_join_native_failed'),
])
def test_native_classification_returns_only_fixed_codes(output, expected):
    assert diagnostics().native_failure_code(output) == expected


def test_native_contract_probe_has_no_directory_writer(monkeypatch):
    m = helper()
    def forbidden(*args, **kwargs):
        pytest.fail('A pure native contract check called a subprocess')
    monkeypatch.setattr(m.subprocess, 'run', forbidden)
    source = 'net_cmd="/usr/bin/net"\n# target-server:\n'
    assert 'net_cmd=' in m.adapt_system_auth(source, '/run/alt-first-join-synthetic/net')
    argv = m.native_join_args(native_join_argv(), 'vm-test', 'example.test',
                             'dc.example.test', 'OU=TEST,DC=example,DC=test')
    assert argv == ['ads', 'join', '--use-kerberos=required', '--no-dns-updates',
                    '--use-krb5-ccache=FILE:/tmp/synthetic-ticket',
                    'createcomputer=TEST', '-S', 'dc.example.test']


def test_native_output_limit_counts_encoded_bytes(monkeypatch):
    m = helper()
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k:
        SimpleNamespace(returncode=0, stdout='я' * 40000, stderr=''))
    with pytest.raises(ValueError, match='Oversized native result'):
        m.run(['synthetic-read-only-output'])


@pytest.mark.parametrize('failure,expected,effect', [
    ('timeout', 'first_join_timeout', 'uncertain'),
    ('child', 'first_join_native_access_denied', 'returned_failure'),
    ('unexpected', 'first_join_internal_error', 'not_dispatched'),
])
def test_bound_main_retains_failure_without_raw_native_output(tmp_path, monkeypatch, capsys, failure, expected, effect):
    m, d = helper(), diagnostics()
    root = tmp_path / 'evidence'
    original = d.Diagnostics
    facade = SimpleNamespace(binding=d.binding, Diagnostics=lambda value: original(value, root=root))
    monkeypatch.setattr(m, 'diagnostic_module', lambda: facade)
    monkeypatch.setattr(m, 'os', SimpleNamespace(geteuid=lambda: 0, environ={}))
    monkeypatch.setattr(m.sys, 'argv', ['helper', '--diagnostic', json.dumps(BINDING),
                                      'ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', 'unused'])
    def native(*args):
        if failure == 'timeout':
            m.phase('native_execution')
            raise subprocess.TimeoutExpired('SENTINEL-private-command', 180, output='SENTINEL-private-output')
        if failure == 'child':
            child = original(BINDING, root=root)
            child.intent('native_execution')
            child.result('native_execution', code='first_join_native_access_denied', returncode=1)
            raise ValueError('SENTINEL-private-native-output')
        raise RuntimeError('SENTINEL-private-internal-error')
    monkeypatch.setattr(m, 'first_join', native)
    with pytest.raises(Exception):
        m.main()
    value = d.read_public(BINDING, root=root)
    assert value['code'] == expected and value['directory_effect'] == effect
    captured = capsys.readouterr()
    assert 'SENTINEL' not in json.dumps(value) + captured.out + captured.err


def test_missing_child_completion_receipt_cannot_report_bound_success(tmp_path, monkeypatch):
    m, d = helper(), diagnostics()
    root = tmp_path / 'evidence'
    monkeypatch.setattr(m, 'diagnostic_module', lambda: SimpleNamespace(
        binding=d.binding, Diagnostics=lambda value: d.Diagnostics(value, root=root)))
    monkeypatch.setattr(m, 'os', SimpleNamespace(geteuid=lambda: 0, environ={}))
    monkeypatch.setattr(m.sys, 'argv', ['helper', '--diagnostic', json.dumps(BINDING),
                                      'ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', 'unused'])
    def incomplete_native(*args):
        m.phase('native_execution')
        # A success-like later probe cannot replace the native writer receipt.
        m.diagnostic_result('machine_as', 'first_join_ok', 0)
        return 0
    monkeypatch.setattr(m, 'first_join', incomplete_native)
    with pytest.raises(RuntimeError, match='completion receipt'):
        m.main()
    value = d.read_public(BINDING, root=root)
    assert value['directory_effect'] == 'uncertain'
    assert value['code'] == 'first_join_internal_error'


def test_bound_native_completion_and_machine_check_can_report_success(tmp_path, monkeypatch):
    m, d = helper(), diagnostics()
    root = tmp_path / 'evidence'
    monkeypatch.setattr(m, 'diagnostic_module', lambda: SimpleNamespace(
        binding=d.binding, Diagnostics=lambda value: d.Diagnostics(value, root=root)))
    monkeypatch.setattr(m, 'os', SimpleNamespace(geteuid=lambda: 0, environ={}))
    monkeypatch.setattr(m.sys, 'argv', ['helper', '--diagnostic', json.dumps(BINDING),
                                      'ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', 'unused'])
    def verified_native(*args):
        m.phase('native_execution')
        child = d.Diagnostics(BINDING, root=root)
        child.result('native_execution', code='first_join_ok', returncode=0)
        m.diagnostic_result('machine_as', 'first_join_ok', 0)
        return 0
    monkeypatch.setattr(m, 'first_join', verified_native)
    assert m.main() == 0
    value = d.read_public(BINDING, root=root)
    assert value['code'] == 'first_join_ok' and value['directory_effect'] == 'returned_success'


@pytest.mark.parametrize('child_status,effect', [
    (None, 'uncertain'), (0, 'returned_success'), (1, 'returned_failure')])
def test_outer_native_failure_cannot_invent_writer_completion(tmp_path, monkeypatch, child_status, effect):
    # This test isolates native writer uncertainty; live AD admission is a
    # separately tested external read boundary.
    m, d = helper(), diagnostics()
    monkeypatch.setattr(m, 'check_ad_join', lambda *args: {})
    root = tmp_path/'evidence'
    m.DIAGNOSTICS = d.Diagnostics(BINDING, root=root)
    m.DIAGNOSTIC_BINDING = BINDING
    monkeypatch.setattr(m, 'diagnostic_module', lambda: d)
    monkeypatch.setattr(m, 'SYSTEM_KEYTAB', str(tmp_path/'absent.keytab'))
    source = tmp_path/'system-auth-source'
    source.write_text('net_cmd="/usr/bin/net"\n# target-server:\n')
    monkeypatch.setattr(m, 'trusted_file', lambda path: source)
    monkeypatch.setattr(m, 'adapt_system_auth', lambda text, wrapper: text)
    temporary = m.tempfile.TemporaryDirectory
    monkeypatch.setattr(m.tempfile, 'TemporaryDirectory', lambda **kw: temporary(prefix=kw['prefix'], dir=tmp_path))
    monkeypatch.setattr(m, 'ldap', lambda *args: '')
    calls = []
    def native(argv, **kwargs):
        if argv[0] == '/usr/bin/rpm': return SimpleNamespace(returncode=0, stdout='4.21.10', stderr='')
        if argv == ['/usr/bin/net', 'ads', 'testjoin']: return SimpleNamespace(returncode=1, stdout='', stderr='')
        if argv == ['/usr/sbin/system-auth', 'status']: return SimpleNamespace(returncode=0, stdout='local', stderr='')
        calls.append(argv)
        if child_status is not None:
            child = d.Diagnostics(BINDING, root=root)
            child.intent('native_execution')
            child.result('native_execution', code='first_join_ok' if child_status == 0 else 'first_join_native_access_denied', returncode=child_status)
        return SimpleNamespace(returncode=1, stdout='SENTINEL-private-wrapper-output', stderr='')
    monkeypatch.setattr(m, 'run', native)
    command = ['system-auth', 'write', 'ad', 'example.test', 'vm-test', 'EXAMPLE', 'join-user', '--createcomputer=TEST', '--gpo']
    with pytest.raises(ValueError, match='Native first-join configuration did not complete') as error:
        m.first_join('ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', command)
    m.diagnostic_error(error.value)
    value = m.DIAGNOSTICS.publish()
    assert value['directory_effect'] == effect
    assert len(calls) == 1 and 'SENTINEL' not in json.dumps(value)
