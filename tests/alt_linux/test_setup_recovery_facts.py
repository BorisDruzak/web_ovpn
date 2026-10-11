from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError

UUID = '11111111-2222-3333-4444-555555555555'
HOST = 'alt-a1-pc3'


def api():
    from alt_deploy import setup_recovery_probe
    return setup_recovery_probe


def collect(probe, root, runner):
    return probe.collect(root=root, runner=runner, owner=os.geteuid())


def protocol_document(probe, root, runner):
    document = collect(probe, root, runner)
    # Root is required in production. The isolated filesystem fixture may be
    # owned by an ordinary CI runner; fabricate root metadata for wire tests.
    for group in ('files', 'tools'):
        for metadata in document[group].values():
            if metadata['present']:
                metadata['uid'] = 0
    return document


def scenario(root):
    probe = api()
    for relative in ('sys/class/dmi/id/product_uuid', *[path.lstrip('/') for path in probe.AUTH_FILES],
                     *[path.lstrip('/') for path in probe.TOOLS.values()]):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.write_bytes(UUID.encode() if relative.endswith('product_uuid') else b'SYNTHETIC_SECRET_CONTENT')
        path.chmod(0o600 if '/' + relative in probe.AUTH_FILES and probe.AUTH_FILES['/' + relative] else 0o644)
    (root / 'proc' / '1').mkdir(parents=True)
    (root / 'proc' / '1' / 'comm').write_text('python3\n')
    calls = []
    values = {'netbios name': HOST.upper(), 'workgroup': 'SOSNADM', 'realm': 'SOSNADMIN.LOCAL',
              'security': 'ADS', 'server role': 'member server', 'private dir': '/var/lib/samba/private',
              'kerberos method': 'secrets only', 'sync machine password to keytab': 'disabled',
              'sync machine password script': ''}
    def runner(argv):
        calls.append(argv)
        if argv[0] == '/usr/bin/rpm':
            return 'synthetic-package 4.21.9-alt1'
        if argv == ['/usr/bin/net', '--version']:
            return 'Version 4.21.9'
        if argv[0] == '/usr/bin/testparm':
            return values[argv[-1]]
        if argv[0] == '/usr/bin/hostname':
            return HOST
        if argv[0] == '/usr/bin/timedatectl':
            return 'yes'
        raise AssertionError(argv)
    return probe, calls, values, runner


def test_initial_facts_freeze_getent_executable_before_any_recovery(tmp_path):
    probe,calls,values,runner=scenario(tmp_path)
    facts=probe.collect(root=tmp_path,runner=runner,owner=os.geteuid())
    assert facts['tools']['getent']['present'] is True
    assert '/usr/bin/getent'==probe.TOOLS['getent'] and facts['tools']['getent']['sha256']
    assert probe.TOOLS['nss_sss']=='/usr/lib64/libnss_sss.so.2'
    assert facts['tools']['nss_sss']['present'] is True and facts['tools']['nss_sss']['sha256']


def test_collect_keeps_only_fixed_file_hashes_and_never_returns_secret_bytes(tmp_path):
    probe, calls, _, runner = scenario(tmp_path)
    before = {path: (tmp_path / path.lstrip('/')).read_bytes() for path in probe.AUTH_FILES}
    document = collect(probe, tmp_path, runner)
    assert document['uuid'] == UUID and document['hostname'] == HOST
    assert document['keytab_present'] is True and document['clock_synchronized'] is True
    assert document['incompatible_processes'] == []
    assert set(document['files']) == set(probe.AUTH_FILES)
    assert document['files']['/etc/krb5.keytab']['sha256'] == hashlib.sha256(b'SYNTHETIC_SECRET_CONTENT').hexdigest()
    assert 'SYNTHETIC_SECRET_CONTENT' not in json.dumps(document)
    assert {path: (tmp_path / path.lstrip('/')).read_bytes() for path in probe.AUTH_FILES} == before
    assert all('join' not in argv and 'changesecretpw' not in argv and 'create' not in argv for argv in calls)


def test_missing_keytab_and_optional_tool_are_explicit_absence(tmp_path):
    probe, _, _, runner = scenario(tmp_path)
    (tmp_path / 'etc/krb5.keytab').unlink()
    (tmp_path / 'usr/bin/ktutil').unlink()
    document = collect(probe, tmp_path, runner)
    assert document['keytab_present'] is False
    assert document['files']['/etc/krb5.keytab'] == {'present': False}
    assert document['tools']['ktutil'] == {'present': False}


@pytest.mark.parametrize('unsafe', ['symlink', 'ancestor_symlink', 'mode', 'owner', 'oversize'])
def test_unsafe_authentication_file_is_refused_without_mutation(tmp_path, monkeypatch, unsafe):
    probe, _, _, runner = scenario(tmp_path)
    keytab = tmp_path / 'etc/krb5.keytab'
    if unsafe == 'symlink':
        keytab.unlink(); keytab.symlink_to(tmp_path / 'etc/krb5.conf')
    elif unsafe == 'ancestor_symlink':
        directory = tmp_path / 'var/lib/samba/private'
        directory.rename(tmp_path / 'redirected-private')
        directory.symlink_to(tmp_path / 'redirected-private', target_is_directory=True)
    elif unsafe == 'mode':
        keytab.chmod(0o644)
    elif unsafe == 'owner':
        original = Path.lstat
        def changed_owner(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return os.stat_result((*info[:4], os.geteuid() + 1, *info[5:])) if path == keytab else info
        monkeypatch.setattr(Path, 'lstat', changed_owner)
    else:
        keytab.write_bytes(b'x' * (probe.MAX_AUTH_BYTES + 1))
    with pytest.raises((ValueError, OSError)):
        collect(probe, tmp_path, runner)


def test_native_process_and_clock_are_reported_without_process_arguments(tmp_path):
    probe, _, _, runner = scenario(tmp_path)
    (tmp_path / 'proc/1/comm').write_text('net\n')
    document = collect(probe, tmp_path, runner)
    assert document['incompatible_processes'] == ['net']
    assert 'cmdline' not in json.dumps(document)


def test_configured_password_hook_refuses_collection_without_returning_hook_text(tmp_path):
    probe, _, values, runner = scenario(tmp_path)
    values['sync machine password script'] = 'SYNTHETIC_SECRET_COMMAND'
    with pytest.raises(ValueError) as caught:
        collect(probe, tmp_path, runner)
    assert 'SYNTHETIC_SECRET_COMMAND' not in str(caught.value)


def runtime(tmp_path, document, *, rc=0):
    from alt_deploy.setup_recovery_runtime import RecoveryPlanningRuntime
    calls = []
    settings = SimpleNamespace(known_hosts_file=tmp_path / 'known_hosts', private_key_file=tmp_path / 'key')
    instance = RecoveryPlanningRuntime(settings,
        runner=lambda argv, **kwargs: calls.append((argv, kwargs)) or (rc, json.dumps(document), 'SYNTHETIC_SECRET_STDERR'))
    return instance, calls


def test_runtime_uses_registered_address_strict_ssh_and_returns_verified_digest(tmp_path):
    probe, _, _, runner = scenario(tmp_path)
    document = protocol_document(probe, tmp_path, runner)
    instance, calls = runtime(tmp_path, document)
    result = instance.facts(SimpleNamespace(ip='192.0.2.10', uuid=UUID, hostname=HOST))
    assert len(result['snapshot_sha256']) == 64
    command = calls[0][0]
    assert 'StrictHostKeyChecking=yes' in command and 'ProxyCommand=none' in command
    assert command[-2] == 'ansible@192.0.2.10'
    assert command[-1].startswith('sudo -n /usr/bin/python3 -I -B -c ')
    assert 'SYNTHETIC_SECRET' not in str(result)


@pytest.mark.parametrize('change', ['uuid', 'hostname', 'extra', 'keytab_truthy', 'missing_file', 'unsafe_mode', 'bad_hash'])
def test_runtime_refuses_malformed_or_mismatched_fixed_snapshot(tmp_path, change):
    probe, _, _, runner = scenario(tmp_path)
    document = protocol_document(probe, tmp_path, runner)
    if change in ('uuid', 'hostname'):
        document[change] = 'changed'
    elif change == 'extra':
        document['raw_credentials'] = 'SYNTHETIC_SECRET'
    elif change == 'keytab_truthy':
        document['keytab_present'] = 1
    elif change == 'missing_file':
        del document['files']['/etc/krb5.conf']
    elif change == 'unsafe_mode':
        document['files']['/etc/krb5.keytab']['mode'] = 0o644
    else:
        document['files']['/etc/krb5.conf']['sha256'] = 'bad'
    instance, _ = runtime(tmp_path, document)
    with pytest.raises(ControlError) as caught:
        instance.facts(SimpleNamespace(ip='192.0.2.10', uuid=UUID, hostname=HOST))
    assert 'SYNTHETIC_SECRET' not in str(caught.value)


def test_runtime_failure_and_address_injection_expose_no_diagnostics(tmp_path):
    instance, calls = runtime(tmp_path, {}, rc=255)
    with pytest.raises(ControlError) as caught:
        instance.facts(SimpleNamespace(ip='192.0.2.10', uuid=UUID, hostname=HOST))
    assert 'SYNTHETIC_SECRET_STDERR' not in str(caught.value)
    calls.clear()
    with pytest.raises(ControlError):
        instance.facts(SimpleNamespace(ip='--ProxyCommand=bad', uuid=UUID, hostname=HOST))
    assert calls == []


def test_runtime_refuses_duplicate_json_fields(tmp_path):
    from alt_deploy.setup_recovery_runtime import RecoveryPlanningRuntime
    probe, _, _, runner = scenario(tmp_path)
    document = protocol_document(probe, tmp_path, runner)
    raw = json.dumps(document)
    raw = raw[:-1] + ', "keytab_present": true}'
    settings = SimpleNamespace(known_hosts_file=tmp_path / 'known_hosts', private_key_file=tmp_path / 'key')
    instance = RecoveryPlanningRuntime(settings, runner=lambda *a, **kw: (0, raw, ''))
    with pytest.raises(ControlError):
        instance.facts(SimpleNamespace(ip='192.0.2.10', uuid=UUID, hostname=HOST))


def test_process_enumeration_accepts_unrelated_unicode_names(tmp_path):
    probe, _, _, runner = scenario(tmp_path)
    (tmp_path / 'proc/1/comm').write_text('Программа\n', encoding='utf-8')
    assert collect(probe, tmp_path, runner)['incompatible_processes'] == []


@pytest.mark.parametrize('unsafe', ['symlink', 'writable', 'oversize'])
def test_probe_source_refuses_redirection_or_unprotected_code(tmp_path, unsafe):
    from alt_deploy.setup_recovery_runtime import _read_source
    path = tmp_path / 'fixed_probe.py'
    path.write_text('print("synthetic")\n')
    path.chmod(0o644)
    if unsafe == 'symlink':
        redirected = tmp_path / 'other.py'
        path.rename(redirected); path.symlink_to(redirected)
    elif unsafe == 'writable':
        path.chmod(0o666)
    else:
        path.write_bytes(b'x' * 131073)
    with pytest.raises(ControlError):
        _read_source(path, owner=os.geteuid())


def test_probe_source_checks_mode_again_after_open(tmp_path, monkeypatch):
    from alt_deploy.setup_recovery_runtime import _read_source
    path = tmp_path / 'fixed_probe.py'
    path.write_text('print("synthetic")\n')
    path.chmod(0o644)
    original = os.open
    def changed_mode(target, *args, **kwargs):
        if Path(target) == path:
            path.chmod(0o666)
        return original(target, *args, **kwargs)
    monkeypatch.setattr(os, 'open', changed_mode)
    with pytest.raises(ControlError):
        _read_source(path, owner=os.geteuid())
