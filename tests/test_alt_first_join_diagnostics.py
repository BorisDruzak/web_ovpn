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


def diagnostics():
    path = ASSETS / 'first_join_diagnostics.py'
    assert path.exists(), 'Missing durable safe first-join diagnostic contract'
    spec = spec_from_file_location('first_join_diagnostics', path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
