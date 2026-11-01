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
