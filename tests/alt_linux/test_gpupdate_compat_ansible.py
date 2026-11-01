"""Real standalone Ansible flow; only package/target boundaries use fixtures."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from test_component_ansible_runtime import ansible_runtime
from test_component_catalog import project
from test_gpupdate_compat import helper, fixture, tree, ROLE


@pytest.mark.parametrize('invalid',[False,True])
def test_standalone_check_apply_repeat_and_failure_are_real_ansible(ansible_runtime,tmp_path,invalid):
    executable,project,env=ansible_runtime
    root=tmp_path/'client';root.mkdir()
    m,packages=fixture(root)
    if invalid:
        p=root/m.PATCHES[-1]['path'].lstrip('/');p.write_bytes(p.read_bytes()+b'\n# unreviewed\n')
    # Avoid package management on the test runner, retain the real nested role.
    p=project/'roles/alt_group_policy_prerequisites/tasks/main.yml'
    tasks=yaml.safe_load(p.read_text());tasks[0]={'ansible.builtin.assert':{'that':[
        'alt_group_policy_prerequisite_packages == ["gpupdate", "alterator-gpupdate"]',
        'alt_package_lock_retry_attempts | int > 1', 'alt_package_lock_retry_delay | int > 0',
        'alt_package_transient_pattern | length > 0', 'alt_package_fatal_pattern | length > 0']}}
    p.write_text(yaml.safe_dump(tasks))
    # Relocate the helper's filesystem/RPM boundary, without replacing its repair logic.
    code='''import importlib.util,json,os,sys
s=importlib.util.spec_from_file_location('compat',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
root=m.Path(sys.argv[2]);packages=lambda path:next((p['package'],p['evr']) for p in m.PATCHES if str(path).endswith(p['path']))
try:print(json.dumps(m.repair(root=root,owner=os.getuid(),package_query=packages,busy=lambda:False,apply='--apply' in sys.argv)))
except ValueError as e:print(json.dumps({'status':'error','code':str(e)}));sys.exit(2)
'''
    wrapper=tmp_path/'run-helper.py';wrapper.write_text(code)
    tasks=yaml.safe_load((project/'roles/alt_group_policy_compat/tasks/main.yml').read_text())
    tasks[0].pop('ansible.builtin.script');tasks[0].pop('args')
    tasks[0]['ansible.builtin.command']={'argv':[sys.executable,str(wrapper),str(ROLE/'files/gpupdate_compat.py'),str(root),
        "{{ '--check' if ansible_check_mode else '--apply' }}"]}
    (project/'roles/alt_group_policy_compat/tasks/main.yml').write_text(yaml.safe_dump(tasks))
    argv=[str(executable),'-i','localhost,','-c','local','-e',json.dumps({'ansible_become':False,'ansible_python_interpreter':sys.executable}),
          str(project/'playbooks/08-gpupdate-client-fixes.yml')]
    before=tree(root)
    check=subprocess.run(argv+['--check'],cwd=project,env=env,capture_output=True,text=True,timeout=45)
    if invalid:
        assert check.returncode!=0 and 'source_unknown' in check.stdout
        assert tree(root)==before
        result=subprocess.run(argv,cwd=project,env=env,capture_output=True,text=True,timeout=45)
        assert result.returncode!=0 and tree(root)==before
        return
    assert check.returncode==0 and 'changed=1' in check.stdout,check.stdout+check.stderr
    assert tree(root)==before
    first=subprocess.run(argv,cwd=project,env=env,capture_output=True,text=True,timeout=45)
    assert first.returncode==0 and 'changed=1' in first.stdout,first.stdout+first.stderr
    after=tree(root)
    second=subprocess.run(argv,cwd=project,env=env,capture_output=True,text=True,timeout=45)
    assert second.returncode==0 and 'changed=0' in second.stdout,second.stdout+second.stderr
    assert tree(root)==after


def test_standalone_rejects_multiple_hosts_before_package_or_module_work(ansible_runtime,tmp_path):
    executable,project,env=ansible_runtime
    result=subprocess.run([str(executable),'-i','client1,client2,','-c','local','-e','ansible_become=false',
        str(project/'playbooks/08-gpupdate-client-fixes.yml')],cwd=project,env=env,capture_output=True,text=True,timeout=30)
    assert result.returncode!=0
    assert 'Select exactly one ALT host' in result.stdout
    assert 'Install the ALT Group Policy client' not in result.stdout
