"""Fixed native collector reads actual fixture files, never auth writers."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_setup_closed_failure import backend
from test_setup_service import UUID

BOOT = 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
REQUEST = {'schema_version': 1, 'uuid': UUID, 'hostname': 'alt-a1-pc3',
           'domain': 'sosnadmin.local', 'workgroup': 'SOSNADM'}


@pytest.fixture
def native_fixture(tmp_path):
    root = tmp_path/'target'; root.mkdir()
    files = {
        '/sys/class/dmi/id/product_uuid': UUID+'\n', '/proc/sys/kernel/random/boot_id': BOOT+'\n',
        '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nansible:x:1001:1001:managed:/home/ansible:/bin/bash\n',
        '/etc/group': 'root:x:0:\nansible:x:1001:\n',
        '/etc/tcb/ansible/shadow': 'SENTINEL-private-password-hash\n',
        '/etc/nsswitch.conf': 'passwd: files sss\ngroup: files sss\nshadow: tcb files sss\n',
        '/etc/samba/smb.conf': '[global]\nsecurity=ads\n',
        '/etc/sssd/sssd.conf': '[sssd]\ndomains=sosnadmin.local\n',
        '/etc/krb5.conf': '[libdefaults]\n', '/var/lib/samba/private/secrets.tdb': 'synthetic-SID-only\n',
    }
    tools = ('/usr/sbin/system-auth', '/usr/sbin/control', '/etc/control.d/functions',
        '/etc/control.d/facilities/system-auth', '/bin/alterator-datetime-functions', '/bin/shell-config',
        '/bin/shell-ini-config', '/bin/shell-quote', '/bin/shell-error', '/usr/sbin/service',
        '/usr/sbin/chkconfig', '/bin/systemctl', '/usr/bin/rpm', '/usr/bin/sudo',
        '/bin/hostname', '/usr/bin/timedatectl')
    files.update({p: '#!/bin/sh\n# read-only synthetic tool '+p+'\n' for p in tools})
    for name in ('system-auth-local', 'system-auth-sss', 'system-auth-use_first_pass-local',
                 'system-auth-use_first_pass-sss', 'system-policy-local', 'system-policy-remote'):
        files['/etc/pam.d/'+name] = 'synthetic-pam '+name+'\n'
    for name, data in files.items():
        path = root/name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data); path.chmod(0o755 if name in tools else 0o600 if '/sssd/' in name or '/tcb/' in name or name.endswith('secrets.tdb') else 0o644)
    for name, target in [('system-auth', 'system-auth-sss'),
                         ('system-auth-use_first_pass', 'system-auth-use_first_pass-sss'), ('system-policy', 'system-policy-remote')]:
        (root/'etc/pam.d'/name).symlink_to(target)
    def run(argv, **kwargs):
        name = Path(argv[0]).name
        if name == 'system-auth' and argv[1:] == ['status']:
            out, rc = 'ad SOSNADMIN.LOCAL ALT-A1-PC3 SOSNADM\n', 0
        elif name == 'hostname' and argv[1:] == ['-s']:
            out, rc = 'alt-a1-pc3\n', 0
        elif name == 'systemctl' and argv[1] == 'show' and argv[2] in ('sssd.service', 'winbind.service'):
            out, rc = 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nFragmentPath=\nDropInPaths=\n', 0
        elif name == 'rpm' and argv[1:3] == ['-q', 'gnome-online-accounts']:
            out, rc = '', 1
        elif name == 'timedatectl':
            out, rc = 'yes\n', 0
        elif name == 'sudo' and argv[1:] == ['-n', '-u', 'ansible', 'sudo', '-n', 'true']:
            out, rc = '', 0
        else:
            pytest.fail('Collector attempted an unsupported or mutating command: '+repr(argv))
        return SimpleNamespace(stdout=out, stderr='', returncode=rc)
    return root, run


def probe_module(native_fixture, monkeypatch):
    root, run = native_fixture
    module = backend('partial_local_probe')
    monkeypatch.setattr(module.subprocess, 'run', run)
    return module, root


def test_probe_never_writes_authentication_files(native_fixture, monkeypatch):
    module, root = probe_module(native_fixture, monkeypatch)
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    result = module.collect(REQUEST, root=root, owner=os.getuid())
    assert result['uuid'] == UUID and result['hostname'] == 'alt-a1-pc3'
    assert result['auth_scheme'] == 'ad' and result['domain'] == 'sosnadmin.local'
    assert result['clock_synchronized'] is True and result['local_admin']['sudo'] is True
    assert result['files']['/etc/pam.d/system-auth']['target'] == 'system-auth-sss'
    assert result['files']['/etc/krb5.keytab'] == {'present': False}
    assert 'SENTINEL' not in json.dumps(result)
    assert {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('fault', ['pam_escape', 'tool_mode', 'auth_symlink', 'duplicate_admin', 'ancestor', 'replace'])
def test_probe_rejects_unsafe_links_tools_and_local_identity(native_fixture, monkeypatch, fault):
    module, root = probe_module(native_fixture, monkeypatch)
    if fault == 'pam_escape':
        path = root/'etc/pam.d/system-auth'; path.unlink(); path.symlink_to('../passwd')
    elif fault == 'tool_mode':
        (root/'usr/sbin/system-auth').chmod(0o777)
    elif fault == 'auth_symlink':
        path = root/'etc/nsswitch.conf'; path.unlink(); path.symlink_to('passwd')
    elif fault == 'duplicate_admin':
        path = root/'etc/passwd'; path.write_text(path.read_text()+'ansible:x:1002:1002:other:/tmp:/bin/bash\n')
    elif fault == 'ancestor':
        (root/'etc/pam.d').chmod(0o777)
    else:
        original = module.os.open
        def replaced(path, flags):
            if Path(path).name == 'nsswitch.conf':
                Path(path).rename(Path(path).with_suffix('.old'))
                Path(path).write_text('passwd: files\n')
            return original(path, flags)
        monkeypatch.setattr(module.os, 'open', replaced)
    with pytest.raises(ValueError):
        module.collect(REQUEST, root=root, owner=os.getuid())


def test_probe_accepts_only_fixed_usrmerge_alias(native_fixture, monkeypatch):
    module, root = probe_module(native_fixture, monkeypatch)
    for path in (root/'bin').iterdir():
        path.rename(root/'usr/bin'/path.name)
    (root/'bin').rmdir()
    (root/'bin').symlink_to('usr/bin')
    assert module.collect(REQUEST, root=root, owner=os.getuid())['auth_scheme'] == 'ad'
    (root/'bin').unlink()
    (root/'bin').symlink_to('/usr/bin')
    with pytest.raises(ValueError): module.collect(REQUEST, root=root, owner=os.getuid())


def test_all_local_tcb_accounts_are_bound_without_exporting_hashes(native_fixture, monkeypatch):
    module, root = probe_module(native_fixture, monkeypatch)
    path = root/'etc/tcb/root/shadow'
    path.parent.mkdir()
    path.write_text('root:SENTINEL-other-private-hash\n')
    path.chmod(0o600)
    first = module.collect(REQUEST, root=root, owner=os.getuid())
    path.write_text('root:SENTINEL-changed-private-hash\n')
    second = module.collect(REQUEST, root=root, owner=os.getuid())
    assert first['local_accounts_sha256'] != second['local_accounts_sha256']
    assert 'SENTINEL' not in json.dumps(second)
