"""Run the real policy task slice against temporary files, never a workstation.

The read-only source-selector boundary is supplied here; its real provenance
and file validation are covered by test_alt_yandex_gpo_handoff.py.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

pytestmark = pytest.mark.skipif(not shutil.which('ansible-playbook'), reason='Ansible runtime required')
ROOT = Path(__file__).resolve().parents[2]
TASKS = ROOT / 'deploy/alt-linux/ansible/roles/software_gosuslugi_plugin/tasks/main.yml'
EXTENSION = 'jabjbhgjaidecageckilhonbggakppme;https://clients2.google.com/service/update2/crx'


@pytest.mark.parametrize('source,problem', [('ansible', None), ('gpo', None), ('gpo', 'conflict'),
    ('ansible', 'native_origin'), ('ansible', 'native_origin_string'), ('ansible', 'native_origin_mapping'),
    ('ansible', 'native_origin_mixed'), ('ansible', 'native_manifest_list')])
def test_cryptopro_policy_installs_without_changing_gosplugin_or_gpo(tmp_path, source, problem):
    managed = tmp_path / 'managed'
    managed.mkdir()
    gos = managed / ('policies.json' if source == 'gpo' else 'alt-signature-suite.json')
    existing = {'ExtensionInstallForcelist': [EXTENSION], 'HomepageLocation': 'https://example.org'}
    if problem == 'conflict':
        existing['ExtensionSettings'] = {'*': {'installation_mode': 'blocked'}}
    gos.write_text(json.dumps(existing))
    before = gos.read_bytes()
    manifest = tmp_path / 'native.json'
    origin = 'chrome-extension://epebfcehmdedogndhlcacafjaacknbcm/'
    origins = {origin: True} if problem == 'native_origin_mapping' else origin if problem == 'native_origin_string' else [] if problem == 'native_origin' else [origin]
    if problem == 'native_origin_mixed':
        origins.append(123)
    manifest.write_text(json.dumps([origin] if problem == 'native_manifest_list' else {'allowed_origins': origins}))
    names = [
        'Verify CryptoPro browser policy ownership', 'Record CryptoPro browser policy candidate',
        'Read approved CryptoPro browser native manifest', 'Require approved CryptoPro browser extension origin',
        'Install CryptoPro browser extension automatically', 'Read back CryptoPro browser extension policy',
        'Verify CryptoPro automatic extension policy',
    ]
    original = yaml.safe_load(TASKS.read_text())
    selected = [copy.deepcopy(next(t for t in original if t['name'] == name)) for name in names]
    helper = TASKS.parents[1] / 'files/cryptopro_browser_policy.py'
    code = ("import importlib.util,json,os; from pathlib import Path; "
            f"s=importlib.util.spec_from_file_location('policy',{str(helper)!r}); "
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m); "
            f"print(json.dumps(m.inspect_directory(Path({str(managed)!r}),expected_uid=os.geteuid())))")
    selected[0].pop('ansible.builtin.script')
    selected[0].pop('args')
    selected[0]['ansible.builtin.command'] = {'argv': [sys.executable, '-c', code]}
    selected[2]['ansible.builtin.slurp']['src'] = str(manifest)
    for task in selected:
        if 'ansible.builtin.copy' in task:
            task['ansible.builtin.copy'].pop('owner', None)
            task['ansible.builtin.copy'].pop('group', None)
    play = tmp_path / 'cryptopro.yml'
    play.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False,
        'vars': {'ansible_python_interpreter': sys.executable}, 'tasks': selected}]))
    args = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(play)]
    env = dict(os.environ, ANSIBLE_NOCOLOR='1')
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=60)
    assert gos.read_bytes() == before
    policy = managed / 'alt-cryptopro-cades.json'
    if problem:
        assert result.returncode != 0
        assert not policy.exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(policy.read_text()) == {'ExtensionSettings': {'epebfcehmdedogndhlcacafjaacknbcm': {
            'installation_mode': 'force_installed', 'update_url': 'https://extension-updates.opera.com/api/omaha/update/'}}}
        repeated = subprocess.run(args, env=env, text=True, capture_output=True, timeout=60)
        assert repeated.returncode == 0, repeated.stdout + repeated.stderr
        assert 'changed=0' in repeated.stdout
        assert gos.read_bytes() == before


@pytest.mark.parametrize('source', ['ansible', 'gpo', 'invalid'])
def test_policy_tasks_respect_verified_source_and_preserve_generated_file(tmp_path, source):
    managed = tmp_path / 'managed'
    managed.mkdir()
    legacy = managed / 'alt-signature-suite.json'
    generated = managed / 'policies.json'
    legacy.write_text(json.dumps({'ExtensionInstallForcelist': [EXTENSION]}))
    generated.write_text(json.dumps({'ExtensionInstallForcelist': [EXTENSION, 'other;https://example.org/update']}))
    before = hashlib.sha256(generated.read_bytes()).hexdigest()
    original_legacy = legacy.read_bytes()
    tasks = yaml.safe_load(TASKS.read_text(encoding='utf-8'))
    first = next(i for i, task in enumerate(tasks) if task['name'] == 'Verify the selected signature browser policy source')
    last = next(i for i, task in enumerate(tasks) if task['name'] == 'Verify the fixed signature extension policy')
    selected = copy.deepcopy(tasks[first:last + 1])
    proof = {'source': source, 'policy_path': str(generated if source == 'gpo' else legacy)}
    code = 'import sys; sys.exit(2)' if source == 'invalid' else 'print(' + repr(json.dumps(proof)) + ')'
    selected[0].pop('ansible.builtin.script')
    selected[0].pop('args')
    selected[0]['ansible.builtin.command'] = {'argv': [sys.executable, '-c', code]}
    for task in selected:
        for module in ('ansible.builtin.file', 'ansible.builtin.copy'):
            if module in task:
                for key in ('path', 'dest'):
                    value = task[module].get(key)
                    if isinstance(value, str) and value.startswith('/etc/opt/yandex/browser/policies/managed'):
                        task[module][key] = value.replace('/etc/opt/yandex/browser/policies/managed', str(managed), 1)
                # Temporary fixtures belong to the current test user.
                task[module].pop('owner', None)
                task[module].pop('group', None)
    play = tmp_path / 'policy.yml'
    play.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False,
                                    'vars': {'ansible_python_interpreter': sys.executable}, 'tasks': selected}]))
    env = dict(os.environ, ANSIBLE_HOST_KEY_CHECKING='False', ANSIBLE_NOCOLOR='1')
    args = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(play)]
    result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=60)
    assert hashlib.sha256(generated.read_bytes()).hexdigest() == before
    if source == 'invalid':
        assert result.returncode != 0
        assert legacy.read_bytes() == original_legacy
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        if source == 'gpo':
            assert not legacy.exists()
        else:
            assert json.loads(legacy.read_text()) == {'ExtensionInstallForcelist': [EXTENSION]}
        repeated = subprocess.run(args, env=env, text=True, capture_output=True, timeout=60)
        assert repeated.returncode == 0, repeated.stdout + repeated.stderr
        assert 'changed=0' in repeated.stdout
