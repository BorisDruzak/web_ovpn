from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

HELPER = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible/roles/domain_join/files/first_join.py'


def helper():
    assert HELPER.exists(), 'The supported first join needs a compatibility adapter'
    spec = spec_from_file_location('first_join', HELPER)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('version, expected', [('4.21.9', True), ('4.21.0', True), ('4.21.10', False), ('4.22.0', False)])
def test_only_affected_samba_versions_use_the_adapter(version, expected):
    assert helper().affected(version) is expected


def test_native_system_auth_adaptation_is_narrow_and_rejects_changed_interface():
    m = helper()
    source = '#!/bin/sh\nnet_cmd="/usr/bin/net"\n# target-server:\n'
    result = m.adapt_system_auth(source, '/run/alt-first-join-abc/net')
    assert result.replace('/run/alt-first-join-abc/net', '/usr/bin/net') == source
    for bad in [source + 'net_cmd="/usr/bin/net"\n', source.replace('net_cmd=', 'other='), source.replace('target-server:', '')]:
        with pytest.raises(ValueError):
            m.adapt_system_auth(bad, '/run/alt-first-join-abc/net')


def test_net_adapter_uses_offline_keys_without_dc_sync_or_shell_interpolation():
    m = helper()
    command = m.net_command('/run/alt-first-join-abc/offline.keytab', 'vm-test', 'example.test', ['ads', 'join', 'createcomputer=TEST'])
    assert command[0] == '/usr/bin/net'
    option = command[1]
    assert 'account_name' in option and 'machine_password' in option
    assert 'sync_kvno' not in option and 'sync_spns' not in option
    assert command[2:] == ['ads', 'join', 'createcomputer=TEST']


def test_account_result_requires_exact_host_dn_and_positive_kvno():
    m = helper()
    raw = 'dn: CN=VM-TEST,OU=TEST,DC=example,DC=test\nsAMAccountName: VM-TEST$\ndNSHostName: vm-test.example.test\nmsDS-KeyVersionNumber: 1\n'
    assert m.account_kvno(raw, 'vm-test', 'example.test', 'OU=TEST,DC=example,DC=test') == 1
    for bad in [raw + raw, raw.replace(': 1', ': 0'), raw.replace('OU=TEST', 'OU=OTHER'), raw.replace('vm-test.example', 'other.example'), raw.replace('msDS-KeyVersionNumber', 'unknown')]:
        with pytest.raises(ValueError):
            m.account_kvno(bad, 'vm-test', 'example.test', 'OU=TEST,DC=example,DC=test')


@pytest.mark.parametrize('hostname, realm, dc', [('bad;cmd', 'example.test', 'dc.example.test'), ('vm-test', 'example.test', 'dc.other.test'), ('vm-test', 'bad/realm', 'dc.example.test'), ('a'*16, 'example.test', 'dc.example.test')])
def test_unsafe_or_unsupported_identity_is_rejected_before_join(hostname, realm, dc):
    with pytest.raises(ValueError):
        helper().validate_identity(hostname, realm, dc)


def test_unaffected_native_failure_preserves_retry_evidence(monkeypatch, capsys):
    m = helper()
    replies = iter([SimpleNamespace(returncode=0, stdout='4.21.10', stderr=''),
                    SimpleNamespace(returncode=1, stdout='native result\n', stderr='Connection timed out\n')])
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return next(replies)
    monkeypatch.setattr(m, 'run', run)
    command = ['system-auth', 'write', 'ad', 'example.test', 'vm-test', 'EXAMPLE', 'joiner', '--createcomputer=TEST', '--gpo']
    assert m.first_join('ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', command) == 1
    output = capsys.readouterr()
    assert output.out == 'native result\n' and output.err == 'Connection timed out\n'
    assert calls[-1] == ['/usr/sbin/system-auth', *command[1:]]


@pytest.mark.parametrize('native_rc,machine_rc', [(0, 0), (0, 1), (1, 0)])
def test_affected_execution_requires_machine_as_exchange_even_with_valid_trust(tmp_path, monkeypatch, native_rc, machine_rc):
    m = helper()
    native_source = tmp_path / 'stock-system-auth'
    native_source.write_text('net_cmd="/usr/bin/net"\n# target-server:\n')
    original_tempdir = tempfile.TemporaryDirectory
    monkeypatch.setattr(m.tempfile, 'TemporaryDirectory', lambda **kwargs: original_tempdir(dir=tmp_path))
    monkeypatch.setattr(m, 'trusted_file', lambda path: native_source)
    monkeypatch.setattr(m, 'adapt_system_auth', lambda source, path: source)
    monkeypatch.setattr(m, 'keytab_parser', lambda: SimpleNamespace())
    monkeypatch.setattr(m, 'ldap', lambda *args: '')
    monkeypatch.setattr(m, 'SYSTEM_KEYTAB', str(tmp_path/'keytab'))
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == '/usr/bin/rpm':
            rc, out = 0, '4.21.9'
        elif argv[:2] == ['/usr/sbin/system-auth', 'status']:
            rc, out = 0, 'local\n'
        elif argv == ['/usr/bin/net', 'ads', 'testjoin']:
            rc, out = 1, ''
        elif argv[0] == '/usr/bin/kinit':
            assert kwargs['env']['KRB5CCNAME'].startswith('FILE:')
            assert 'kdc = dc.example.test' in Path(kwargs['env']['KRB5_CONFIG']).read_text()
            rc, out = machine_rc, ''
        elif Path(argv[0]).name == 'system-auth' and argv[1] == 'write':
            rc, out = native_rc, ''
        else:
            rc, out = 0, ''
        return SimpleNamespace(returncode=rc, stdout=out, stderr='')
    monkeypatch.setattr(m, 'run', run)
    command = ['system-auth', 'write', 'ad', 'example.test', 'vm-test', 'EXAMPLE', 'joiner', '--createcomputer=TEST', '--gpo']
    if native_rc:
        with pytest.raises(ValueError, match='configuration did not complete'):
            m.first_join('ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', command)
    elif machine_rc:
        with pytest.raises(ValueError, match='machine credentials verification'):
            m.first_join('ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', command)
    else:
        assert m.first_join('ldap://dc.example.test', 'OU=TEST,DC=example,DC=test', command) == 0
    assert sum(Path(argv[0]).name == 'system-auth' and argv[1] == 'write' for argv, _ in calls) == 1
    assert not list(tmp_path.glob('tmp*'))


def test_role_refuses_adapter_failure_before_trust_only_reconciliation():
    import yaml
    role = yaml.safe_load((HELPER.parents[1] / 'tasks/main.yml').read_text())
    block = next(task['block'] for task in role if 'block' in task)
    names = [task['name'] for task in block]
    assert names.index('Refuse compatibility failure even when Samba trust exists') < names.index('Reconcile Samba trust after domain join result')
    gate = block[names.index('Refuse compatibility failure even when Samba trust exists')]
    from jinja2 import Environment
    env = Environment()
    observed = {'rc': 89, 'stdout': '', 'stderr': 'ALT_PREFLIGHT_FAILURE:domain_join_compatibility_failed'}
    rendered = env.from_string('{{ ' + gate['ansible.builtin.assert']['that'] + ' }}').render(domain_join_command=observed)
    assert rendered == 'False'


@pytest.mark.parametrize('join_rc,keytab_rc', [(0, 0), (1, 0), (0, 1)])
def test_join_disables_inline_sync_and_creates_offline_keys_after_success(
        tmp_path, monkeypatch, join_rc, keytab_rc):
    m = helper()
    monkeypatch.setattr(m, 'trusted_file', lambda path: path)
    calls, bindings = [], []
    def run(argv, **kwargs):
        calls.append(argv)
        rc = keytab_rc if argv[-3:] == ['ads', 'keytab', 'create'] else join_rc
        return SimpleNamespace(returncode=rc, stdout='', stderr='')
    monkeypatch.setattr(m, 'run', run)
    monkeypatch.setattr(m, 'bind_keytab', lambda *args: bindings.append(args))
    argv = ['ads', 'join', '-S', 'dc.example.test', 'createcomputer=TEST']
    result = m.net_wrapper(tmp_path, 'vm-test', 'example.test', 'dc.example.test',
                           'OU=TEST,DC=example,DC=test', argv)
    assert calls[0] == ['/usr/bin/net', '--option=sync machine password to keytab=disabled', *argv]
    if join_rc:
        assert result == join_rc and len(calls) == 1 and not bindings
    else:
        assert calls[1] == m.net_command(str(tmp_path/'offline.keytab'), 'vm-test',
                                       'example.test', ['ads', 'keytab', 'create'])
        assert result == keytab_rc
        assert bool(bindings) == (keytab_rc == 0)
