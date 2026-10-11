"""Post-start evidence is historical proof, never an active-service trust claim."""
from __future__ import annotations

import copy

import pytest

from test_setup_recovery_sssd_policy import scenario


def prepared(root):
    policy, request, args, calls = scenario(root)
    receipt = policy.install_once(request, **args)
    original = args['collect']
    def running():
        facts = copy.deepcopy(original())
        facts['incompatible_processes'] = ['sssd', 'sssd_be', 'sssd_nss']
        return facts
    args['collect'] = running
    calls.clear()
    return policy, request, args, calls, receipt


def test_retained_proof_survives_process_change_without_authentication_or_service_query(tmp_path):
    policy, request, args, calls, receipt = prepared(tmp_path)
    with pytest.raises(ValueError):
        policy.verify(request, **args)
    calls.clear()
    assert policy.verify_artifacts(request, **args) == receipt
    assert receipt['trust_verified'] is False
    assert calls and all(command[0] == '/usr/bin/rpm' for command, _ in calls)


@pytest.mark.parametrize('change', [
    'secret', 'keytab', 'main', 'snippet', 'import_receipt', 'kerberos_receipt',
    'kerberos_intent', 'policy_receipt', 'backup', 'tool', 'module', 'failed',
    'uuid', 'clock', 'samba', 'unknown_fact', 'missing_processes', 'malformed_processes',
])
def test_post_start_artifacts_refuse_changed_credentials_history_or_static_facts(tmp_path, change):
    policy, request, args, calls, _ = prepared(tmp_path)
    kerberos = args['kerberos']; importer = args['importer']; backup = args['backup']
    bound = request['kerberos_request']; imported = bound['import_request']
    paths = {
        'secret': tmp_path / 'var/lib/samba/private/secrets.tdb',
        'keytab': tmp_path / 'etc/krb5.keytab',
        'main': tmp_path / 'etc/sssd/sssd.conf',
        'snippet': tmp_path / policy.SNIPPET.lstrip('/'),
        'import_receipt': importer.path_for(imported, backup=backup, root=tmp_path) / 'installed.json',
        'kerberos_receipt': kerberos.path_for(bound, backup=backup, root=tmp_path) / 'verified.json',
        'kerberos_intent': kerberos.path_for(bound, backup=backup, root=tmp_path) / 'intent.json',
        'policy_receipt': policy.path_for(request, backup=backup, root=tmp_path) / 'verified.json',
        'backup': backup.path_for(imported['rehearsal_request']['backup_request'], root=tmp_path) / 'request.json',
        'tool': tmp_path / 'usr/bin/kinit',
        'module': tmp_path / policy.MODULE_DIRECTORY.lstrip('/') / 'tdb.so',
        'failed': policy.path_for(request, backup=backup, root=tmp_path) / 'failed.json',
    }
    if change in paths:
        paths[change].write_bytes(b'changed')
    else:
        original = args['collect']
        def changed():
            facts = original()
            if change == 'uuid': facts['uuid'] = '11111111-1111-1111-1111-111111111111'
            elif change == 'clock': facts['clock_synchronized'] = False
            elif change == 'samba': facts['samba'] = {}
            elif change == 'missing_processes': facts.pop('incompatible_processes')
            elif change == 'malformed_processes': facts['incompatible_processes'] = [False]
            else: facts['unknown'] = True
            return facts
        args['collect'] = changed
    with pytest.raises(ValueError):
        policy.verify_artifacts(request, **args)
    assert all(command[0] == '/usr/bin/rpm' for command, _ in calls)


def test_strict_pre_start_verifier_still_refuses_active_service_even_with_unchanged_facts(tmp_path):
    policy, request, args, calls = scenario(tmp_path)
    policy.install_once(request, **args)
    original = args['runner']
    def active(command, **options):
        if command[0] == '/usr/bin/systemctl': return 0, 'active\ninactive\ninactive\ninactive\n', ''
        return original(command, **options)
    args['runner'] = active
    with pytest.raises(ValueError, match='inactive'):
        policy.verify(request, **args)


@pytest.mark.parametrize('stage,change', [
    (stage, change) for stage in ('kerberos', 'policy')
    for change in ('keytab', 'import_receipt', 'kerberos_receipt', 'kerberos_tool', 'policy_tool', 'module')
    if stage == 'policy' or change not in ('policy_tool', 'module')
])
def test_change_during_native_read_is_not_a_retained_success(tmp_path, stage, change):
    policy, request, args, calls, _ = prepared(tmp_path)
    backup = args['backup']; kerberos = args['kerberos']; importer = args['importer']
    bound = request['kerberos_request']; imported = bound['import_request']
    paths = {
        'keytab': tmp_path / 'etc/krb5.keytab',
        'import_receipt': importer.path_for(imported, backup=backup, root=tmp_path) / 'installed.json',
        'kerberos_receipt': kerberos.path_for(bound, backup=backup, root=tmp_path) / 'verified.json',
        'kerberos_tool': tmp_path / 'usr/bin/kinit',
        'policy_tool': tmp_path / 'usr/sbin/sssd',
        'module': tmp_path / policy.MODULE_DIRECTORY.lstrip('/') / 'tdb.so',
    }
    original = args['runner']; changed = []
    trigger = '/usr/bin/kdestroy' if stage == 'kerberos' else policy.MODULE_DIRECTORY + '/tdb.so'
    def racing(command, **options):
        result = original(command, **options)
        if command[0] == '/usr/bin/rpm' and command[2] == trigger and not changed:
            paths[change].write_bytes(b'changed during final RPM read')
            changed.append(True)
        return result
    args['runner'] = racing
    with pytest.raises(ValueError):
        if stage == 'policy': policy.verify_artifacts(request, **args)
        else:
            kerberos.verify_artifacts(bound, **{key:value for key,value in args.items() if key != 'kerberos'})
    assert changed


@pytest.mark.parametrize('stage', ['kerberos', 'policy'])
def test_pre_start_refuses_service_activated_during_package_query(tmp_path, stage):
    policy, request, args, calls = scenario(tmp_path)
    policy.install_once(request, **args)
    original = args['runner']; activated = []
    trigger = '/usr/bin/kdestroy' if stage == 'kerberos' else policy.MODULE_DIRECTORY + '/tdb.so'
    def racing(command, **options):
        if command[0] == '/usr/bin/systemctl' and activated:
            return 0, 'active\ninactive\ninactive\ninactive\n', ''
        result = original(command, **options)
        if command[0] == '/usr/bin/rpm' and command[2] == trigger: activated.append(True)
        return result
    args['runner'] = racing
    with pytest.raises(ValueError, match='inactive'):
        if stage == 'policy': policy.verify(request, **args)
        else: args['kerberos'].verify(request['kerberos_request'], **{key:value for key,value in args.items() if key != 'kerberos'})
    assert activated


@pytest.mark.parametrize('path', ['/etc/krb5.keytab', '/etc/samba/smb.conf', '/usr/bin/net'])
def test_import_artifacts_recheck_bytes_after_collector_commands(tmp_path, path):
    policy, request, args, calls, _ = prepared(tmp_path)
    original = args['collect']
    def stale():
        facts = original()
        (tmp_path / path.lstrip('/')).write_bytes(b'changed after collected metadata')
        return facts
    with pytest.raises(ValueError):
        args['importer'].verify_artifacts(request['kerberos_request']['import_request'],
            **{key:value for key,value in args.items() if key in ('backup', 'probe', 'root', 'owner')}, collect=stale)
