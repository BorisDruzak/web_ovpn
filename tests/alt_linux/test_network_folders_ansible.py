"""Run the actual optional Ansible boundary with synthetic probe outcomes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


SOURCE = Path(__file__).resolve().parents[2] / 'deploy/alt-linux/ansible'


def test_published_bundle_executes_without_target_installation_or_root_fallback():
    if os.geteuid() == 0:
        pytest.skip('This case verifies the unprivileged entry guard')
    spec = importlib.util.spec_from_file_location('network_filter', SOURCE / 'filter_plugins/alt_network_folders.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    bundle = module.program(SOURCE / 'roles/desktop_shortcuts')
    run = subprocess.run([sys.executable, '-I', '-B', '-c', bundle], input='{}',
                         capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)['status'] == 'unknown'


@pytest.mark.parametrize('outcome', ['failed', 'unknown', 'ok', 'malformed'])
def test_optional_network_failure_preserves_later_setup_tasks(tmp_path, outcome):
    executable = shutil.which('ansible-playbook')
    if not executable:
        pytest.skip('Ansible runtime required')
    tasks = yaml.safe_load((SOURCE / 'roles/desktop_shortcuts/tasks/network_folders.yml').read_text())
    tasks = copy.deepcopy(tasks)
    command = next(t for t in tasks if 'ansible.builtin.command' in t)
    # Replace only the external process; never contact AD, SMB or a workstation.
    value = {'status': outcome, 'code': 'checked', 'ad_verified': outcome == 'ok',
             'changed': False, 'created_count': 0}
    program = ('import sys;sys.exit(3)' if outcome == 'failed' else
               'print("not-json")' if outcome == 'malformed' else 'print(' + repr(json.dumps(value)) + ')')
    command['ansible.builtin.command'] = {'argv': [sys.executable, '-c', program]}
    marker = tmp_path / 'continued.json'
    tasks.append({'name': 'Continue the full setup after optional networking', 'ansible.builtin.copy': {
        'dest': str(marker), 'content': '{{ desktop_network_folders_result | to_json }}'}})
    play = tmp_path / 'play.yml'
    play.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False,
        'vars': {'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable,
                 'desktop_shortcuts_user_home': {'stat': {'exists': True}}}, 'tasks': tasks}]))
    config = tmp_path / 'ansible.cfg'
    config.write_text('[defaults]\nfilter_plugins=' + str(SOURCE / 'filter_plugins') + '\n')
    result = subprocess.run([executable, '-i', 'localhost,', str(play)], capture_output=True,
                            text=True, timeout=30, env=dict(os.environ, ANSIBLE_CONFIG=str(config)))
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(marker.read_text())['status'] == ('ok' if outcome == 'ok' else 'unknown')
    assert 'failed=0' in result.stdout and 'rescued=0' in result.stdout
