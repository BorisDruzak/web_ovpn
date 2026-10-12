from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/alt-linux/control'))
from alt_deploy.errors import ControlError


def test_source_fingerprint_binds_role_scripts_templates_and_excludes_vault(tmp_path):
    from alt_deploy.setup_runtime import source_fingerprint
    project = tmp_path / 'ansible'
    script = project / 'roles/plasma_baseline/files/apply_existing_power.py'
    template = project / 'roles/plasma_baseline/templates/power.j2'
    vault = project / 'group_vars/vault.yml'
    for path in (script, template, vault):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('original')
    control = tmp_path / 'control'
    control.mkdir()
    (control / 'setup.py').write_text('original')
    first = source_fingerprint(project, control)
    vault.write_text('secret changed')
    assert source_fingerprint(project, control) == first
    script.write_text('changed runtime')
    second = source_fingerprint(project, control)
    assert second != first
    template.write_text('changed template')
    assert source_fingerprint(project, control) != second


def test_probe_uses_strict_ssh_and_fixed_readonly_script(tmp_path):
    from alt_deploy.setup_runtime import SetupRuntime
    calls = []
    observed = {'uuid': '11111111-2222-3333-4444-555555555555', 'hostname': 'alt-a1-pc3',
                'domain': '', 'trust': False, 'sssd': False, 'user_lookup': False,
                'local_duplicate': False, 'home_exists': False, 'computer_identity': None}
    settings = SimpleNamespace(known_hosts_file=tmp_path / 'known_hosts', private_key_file=tmp_path / 'key')
    machine = SimpleNamespace(ip='192.0.2.10')
    runtime = SetupRuntime(settings, runner=lambda cmd, **kw: calls.append((cmd, kw)) or (0, json.dumps(observed), ''))
    assert runtime.probe(machine, {'login': 'synthetic.user', 'upn': 'synthetic.user@sosnadmin.local'}) == observed
    command = calls[0][0]
    assert 'StrictHostKeyChecking=yes' in command
    assert 'ProxyCommand=none' in command
    assert command[-2] == 'ansible@192.0.2.10'
    assert command[-1].startswith('sudo -n /usr/bin/python3 -I -B -c ')
    assert 'net' in command[-1] and 'testjoin' in command[-1]
    assert 'reboot' not in command[-1] and 'gpupdate' not in command[-1]


def test_probe_rejects_address_injection_and_suppresses_errors(tmp_path):
    from alt_deploy.setup_runtime import SetupRuntime
    settings = SimpleNamespace(known_hosts_file=tmp_path / 'known_hosts', private_key_file=tmp_path / 'key')
    runtime = SetupRuntime(settings, runner=lambda cmd, **kw: (255, '', 'SECRET'))
    with pytest.raises(ControlError) as caught:
        runtime.probe(SimpleNamespace(ip='192.0.2.10'), {'login': 'user', 'upn': 'user@sosnadmin.local'})
    assert 'SECRET' not in str(caught.value)
    with pytest.raises(ControlError):
        runtime.probe(SimpleNamespace(ip='--ProxyCommand=bad'), {'login': 'user', 'upn': 'user@sosnadmin.local'})


@pytest.mark.parametrize('reply_count', [1, 2])
def test_native_probe_requests_identity_attributes_missing_from_samba_status(monkeypatch, capsys, reply_count):
    import subprocess
    from alt_deploy.setup_runtime import PROBE_SCRIPT
    identity = ('Got %s replies\n\ndistinguishedName: CN=ALT-TEST-PC1,OU=TEST,DC=sosnadmin,DC=local\n'
                'objectGUID: 11111111-2222-4333-8444-555555555555\n'
                'objectSid: S-1-5-21-1-2-3-1010\n'
                'sAMAccountName: ALT-TEST-PC1$\ndNSHostName: alt-test-pc1.sosnadmin.local\n') % reply_count
    def native(args, **kwargs):
        outputs = {('system-auth', 'status'): 'ad SOSNADMIN.LOCAL ALT-TEST-PC1 SOSNADM',
                   ('hostname', '-s'): 'alt-test-pc1', ('net', 'ads', 'testjoin'): 'Join is OK',
                   ('net', '-P', 'ads', 'status'): 'sAMAccountName: ALT-TEST-PC1$\n',
                   ('systemctl', 'is-active', 'sssd'): 'active',
                   ('getent', 'passwd', 'synthetic.user@sosnadmin.local'): 'synthetic.user:*:123:123::/home/synthetic.user:/bin/bash'}
        expected = ['net', '-P', 'ads', 'search', '(&(objectClass=computer)(sAMAccountName=alt-test-pc1$))',
                    'objectGUID', 'objectSid', 'sAMAccountName', 'distinguishedName', 'dNSHostName']
        if args[:4] == ['net', '-P', 'ads', 'search']:
            assert args == expected
            return subprocess.CompletedProcess(args, 0, identity, '')
        return subprocess.CompletedProcess(args, 0, outputs[tuple(args)], '')
    monkeypatch.setattr(subprocess, 'run', native)
    monkeypatch.setattr(sys, 'argv', ['probe', 'synthetic.user', 'synthetic.user@sosnadmin.local'])
    monkeypatch.setattr(Path, 'read_text', lambda self: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' if str(self).endswith('product_uuid') else 'root:x:0:0::/root:/bin/bash')
    if reply_count == 2:
        with pytest.raises(RuntimeError, match='ambiguous'):
            exec(PROBE_SCRIPT, {'__name__': 'native_probe'})
    else:
        exec(PROBE_SCRIPT, {'__name__': 'native_probe'})
        observed = json.loads(capsys.readouterr().out)
        assert observed['computer_identity']['object_guid'] == '11111111-2222-4333-8444-555555555555'
        assert observed['trust'] and observed['sssd'] and observed['user_lookup']
