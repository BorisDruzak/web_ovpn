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
