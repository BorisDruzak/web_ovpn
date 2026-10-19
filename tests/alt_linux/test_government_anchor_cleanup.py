"""Real Ansible cleanup in a fixture tree; no live system trust mutation."""
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from test_component_catalog import SOURCE


@pytest.mark.parametrize('case', ['absent', 'managed', 'mismatch', 'symlink', 'mixed'])
def test_cleanup_preserves_unrelated_trust_and_rejects_unproven_entries(tmp_path, case):
    executable = Path(sys.executable).with_name('ansible-playbook')
    if not executable.exists():
        pytest.skip('Pinned real Ansible is unavailable')
    entries = yaml.safe_load((SOURCE/'roles/government_ca/defaults/main.yml').read_text())['government_ca_certificates']
    intermediates = [e for e in entries if e['kind']=='intermediate']
    anchors = tmp_path/'etc/pki/ca-trust/source/anchors'; anchors.mkdir(parents=True)
    vendor = tmp_path/'usr/share/pki/ca-trust-source/anchors'; vendor.mkdir(parents=True)
    ordinary = tmp_path/'etc/pki/ca-trust/source'/intermediates[0]['filename']
    ordinary.write_bytes(b'NON-ANCHOR-ADMINISTRATOR-DATA')
    root = next(e for e in entries if e['kind']=='root')
    (anchors/root['filename']).write_bytes((SOURCE/'files/government_ca'/root['filename']).read_bytes())
    (vendor/intermediates[0]['filename']).write_bytes(b'DISTRIBUTION-OWNED-TRUST')
    candidate = anchors/intermediates[0]['filename']
    if case != 'absent':
        candidate.write_bytes((SOURCE/'files/government_ca'/intermediates[0]['filename']).read_bytes())
        candidate.chmod(0o644)
    if case == 'mismatch': candidate.write_bytes(b'UNKNOWN-CA-DO-NOT-DELETE')
    if case == 'symlink':
        candidate.unlink(); candidate.symlink_to(vendor/intermediates[0]['filename'])
    if case == 'mixed':
        (anchors/intermediates[1]['filename']).write_bytes(b'UNKNOWN-CA-DO-NOT-DELETE')
    source = yaml.safe_load((SOURCE/'roles/government_ca/tasks/main.yml').read_text())
    start = next(i for i,t in enumerate(source) if t.get('name')=='Inspect only managed intermediate anchor paths before cleanup')
    end = next(i for i,t in enumerate(source) if t.get('name')=='Keep managed intermediate certificates outside system trust anchors')
    tasks = source[start:end+1]
    for task in tasks:
        for module in ('ansible.builtin.stat', 'ansible.builtin.file'):
            if module in task:
                task[module]['path'] = task[module]['path'].replace('/etc/pki/ca-trust/source/anchors',str(anchors))
        if 'ansible.builtin.assert' in task:
            # Only the synthetic root UID differs from the deployed role.
            task['ansible.builtin.assert']['that'] = [s.replace('.uid == 0','.uid == '+str(os.getuid()))
                                                     for s in task['ansible.builtin.assert']['that']]
    play = tmp_path/'play.yml'
    play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':{
        'government_ca_certificates':entries, 'ansible_connection':'local',
        'ansible_python_interpreter':sys.executable, 'ansible_become':False},'tasks':tasks}],sort_keys=False))
    cfg = tmp_path/'ansible.cfg'; cfg.write_text('[defaults]\nretry_files_enabled=False\n')
    env = dict(os.environ, ANSIBLE_CONFIG=str(cfg))
    before = {p.relative_to(tmp_path).as_posix():p.read_bytes() for p in (ordinary, vendor/intermediates[0]['filename'], anchors/root['filename'])}
    result = subprocess.run([str(executable),'-i','localhost,',str(play)],cwd=tmp_path,
                            env=env,text=True,capture_output=True,timeout=30)
    success = case in ('managed','absent')
    assert (result.returncode==0) is success, result.stdout+result.stderr
    assert {name:(tmp_path/name).read_bytes() for name in before} == before
    if success:
        assert not candidate.exists()
        again = subprocess.run([str(executable),'-i','localhost,',str(play)],cwd=tmp_path,
                               env=env,text=True,capture_output=True,timeout=30)
        assert again.returncode==0, again.stdout+again.stderr
        assert 'changed=0' in again.stdout
    else:
        assert candidate.exists() or candidate.is_symlink()
