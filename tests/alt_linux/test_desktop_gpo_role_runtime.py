"""Exercise actual role writes; the independently tested selector is a boundary fixture."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

pytestmark = pytest.mark.skipif(not shutil.which('ansible-playbook'), reason='Ansible runtime required')
ROLE = Path(__file__).resolve().parents[2]/'deploy/alt-linux/ansible/roles/desktop_shortcuts'


@pytest.mark.parametrize('source', ['ansible', 'gpo', 'invalid', 'stale'])
def test_role_writes_only_ansible_owned_launchers(tmp_path, source):
    role = yaml.safe_load((ROLE/'tasks/main.yml').read_text())
    guard = next(task for task in role if task['name'] == 'Verify desktop launcher policy ownership')
    writes = [task for task in role if any(key in task for key in
              ('ansible.builtin.file', 'ansible.builtin.copy'))]
    record = next(task for task in role if task['name'] == 'Record verified desktop launcher policy ownership')
    tasks = copy.deepcopy([guard, record, *writes])
    result = {'source': 'gpo' if source == 'stale' else source, 'verified': True,
              'home_deferred': False, 'legacy_home_links':
              [str(tmp_path/'home/Desktop/Home')] if source == 'stale' else []}
    code = 'import sys;sys.exit(2)' if source == 'invalid' else 'print('+repr(json.dumps(result))+')'
    tasks[0].pop('ansible.builtin.script')
    tasks[0].pop('args')
    tasks[0]['ansible.builtin.command'] = {'argv': [sys.executable, '-c', code]}
    apps, skel, home = (tmp_path/name for name in ('apps', 'skel', 'home'))
    managed = []
    for base in (skel, home):
        for rel in ('Desktop/office.desktop', 'Desktop/nextcloud-client.desktop', '.config/autostart/nextcloud-client.desktop'):
            p = base/rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('[Desktop Entry]\nType=Application\nName=GPO owned\nExec=/bin/true\nX-GPO-Test=keep\n')
            managed.append(p)
    apps.mkdir()
    for name in ('office.desktop', 'nextcloud-client.desktop'):
        (apps/name).write_text('[Desktop Entry]\nType=Application\nName=Distro default\nExec=/bin/true\n')
    before = {str(p): p.read_bytes() for p in managed}
    if source == 'stale':
        # Model a symlink replaced with personal data after a verifier snapshot.
        replacement = home/'Desktop/Home'
        replacement.mkdir()
        (replacement/'personal.txt').write_text('preserve this directory')
    for task in tasks:
        for module in ('ansible.builtin.file', 'ansible.builtin.copy'):
            if module not in task: continue
            task[module].pop('owner', None)
            task[module].pop('group', None)
            for key in ('path', 'dest'):
                value = task[module].get(key)
                if value == '/usr/local/libexec': task[module][key] = str(tmp_path/'libexec')
                elif isinstance(value, str) and value.startswith('/usr/local/libexec/'):
                    task[module][key] = value.replace('/usr/local/libexec', str(tmp_path/'libexec'), 1)
    variables = {'role_path': str(ROLE), 'ansible_python_interpreter': sys.executable,
                 'desktop_shortcuts_policy_source': result,
                 'desktop_shortcuts_selected_entries': ['office.desktop', 'nextcloud-client.desktop'],
                 'desktop_shortcuts_skel_dir': str(skel/'Desktop'),
                 'desktop_shortcuts_applications_dir': str(apps),
                 'desktop_shortcuts_nextcloud_autostart_dir': str(skel/'.config/autostart'),
                 'desktop_shortcuts_nextcloud_entry': 'nextcloud-client.desktop',
                 'desktop_shortcuts_user_desktop_name': 'Desktop',
                 'desktop_shortcuts_relative_links': [{'name': 'Home', 'src': '..'}],
                 'desktop_shortcuts_user_home': {'stat': {'exists': True}},
                 'desktop_shortcuts_user_fields': ['synthetic', 'x', str(os.getuid()), str(os.getgid()), '', str(home), '/bin/bash']}
    play = tmp_path/'policy.yml'
    play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,'tasks':tasks}]))
    env = dict(os.environ, ANSIBLE_NOCOLOR='1')
    argv = ['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(play)]
    first = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)
    if source == 'invalid':
        assert first.returncode != 0
        assert {str(p): p.read_bytes() for p in managed} == before
        assert not (tmp_path/'libexec').exists()
        return
    assert first.returncode == 0, first.stdout+first.stderr
    if source in ('gpo', 'stale'):
        assert {str(p): p.read_bytes() for p in managed} == before
        if source == 'stale':
            assert (home/'Desktop/Home/personal.txt').read_text() == 'preserve this directory'
        else:
            assert not (home/'Desktop/Home').exists()
    else:
        assert (home/'Desktop/office.desktop').read_bytes() == (apps/'office.desktop').read_bytes()
    again = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)
    assert again.returncode == 0, again.stdout+again.stderr
    assert 'changed=0' in again.stdout
