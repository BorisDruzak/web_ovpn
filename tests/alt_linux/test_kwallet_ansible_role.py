"""Real Ansible exercises the fixed wallet helper contract on synthetic files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from test_component_catalog import SOURCE
from test_krfb_managed_runtime import runtime_request


ROLE=SOURCE/'roles/kwallet_empty_name_repair'


@pytest.mark.parametrize('case',['repair','healthy','owned_previous','unknown','private_error','bad_context','bad_name','changed_source','foreign_helper'])
def test_actual_ansible_never_runs_unbound_wallet_repair_or_displays_private_output(tmp_path,case):
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned real Ansible is unavailable')
    tasks=yaml.safe_load((ROLE/'tasks/main.yml').read_text())
    marker=tmp_path/'applied'
    disposition='noop' if case=='healthy' else 'repair'
    program=('import sys,json\nfrom pathlib import Path\n'+
        'def arg(v):return sys.argv[sys.argv.index(v)+1]\n'+
        'if "--observe" in sys.argv:\n'+
        ' value='+repr({'readiness_sha256':'a'*64,'disposition':disposition})+'\n'+
        ' value.update(helper_installed=True,installed_helper_sha256=arg("--helper-sha256"),helper_sha256=arg("--helper-sha256"))\n'+
        ' print(json.dumps({"schema_version":1,"status":"ok","observation":value}))\n'+
        'else:\n Path('+repr(str(marker))+').write_text(sys.stdin.read())\n'+
        ' value='+repr({'schema_version':1,'status':'blocked' if case in ('unknown','private_error') else 'ok',
            'result':{'status':'unknown' if case in ('unknown','private_error') else 'repaired','changed':True,
                      'code':'PRIVATE-SECRET-SENTINEL' if case=='private_error' else 'kwallet_dbus_unverified' if case=='unknown' else None}})+'\n'+
        ' value.update(helper_sha256=arg("--helper-sha256"),operation_sha256=arg("--operation-sha256"))\n print(json.dumps(value))\n')
    digest=hashlib.sha256(program.encode()).hexdigest()
    expected={'schema_version':1,'machine_uuid':'11111111-2222-3333-4444-555555555555','hostname':'alt-test-pc1',
        'login':'synthetic.user','wallet_name':'recovered-wallet','helper_sha256':digest,'readiness_sha256':'a'*64,
        'installed_helper_sha256':None,'helper_installed':False,'disposition':disposition}
    context=runtime_request()['context']
    if case=='bad_context':context['phase']='system'
    if case=='changed_source':expected['helper_sha256']='0'*64
    installed=tmp_path/'usr/local/libexec/alt-kwallet-empty-name-repair'
    installed.parent.mkdir(parents=True)
    if case=='foreign_helper':installed.write_text('FOREIGN-DO-NOT-OVERWRITE');installed.chmod(0o700)
    if case=='owned_previous':
        installed.write_text('APPROVED-OLDER-HELPER');installed.chmod(0o700)
        expected.update(helper_installed=True,installed_helper_sha256=hashlib.sha256(installed.read_bytes()).hexdigest())
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
        'machine_uuid':context['machine_uuid'],'final_hostname':'alt-test-pc1','kwallet_repair_user':'synthetic.user',
        'kwallet_repair_new_name':'unplanned-wallet' if case=='bad_name' else 'recovered-wallet',
        'kwallet_repair_previous_helper_sha256':[],'alt_setup_workflow_context':context,
        'alt_setup_wallet_readiness':expected,'kwallet_helper_program':program,'kwallet_helper_sha256':digest}
    if case=='owned_previous':variables['kwallet_repair_previous_helper_sha256']=[expected['installed_helper_sha256']]
    tasks=[t for t in tasks if t.get('name')!='Build the fixed published wallet helper']
    for task in tasks:
        for key,value in list(task.items()):
            if key.startswith('ansible.builtin.') and isinstance(value,dict):
                for field,data in list(value.items()):
                    if isinstance(data,str) and data.startswith('/usr'):
                        value[field]=str(tmp_path)+data
                for field in ('owner','group'):
                    if field in value:value[field]=str(os.getuid() if field=='owner' else os.getgid())
        if 'loop' in task and isinstance(task['loop'],list):
            task['loop']=[str(tmp_path)+p if isinstance(p,str) and p.startswith('/usr') else p for p in task['loop']]
        if 'ansible.builtin.command' in task:
            task['ansible.builtin.command']['argv']=[s.replace('/usr/local/libexec/alt-kwallet-empty-name-repair',str(installed))
                                                    for s in task['ansible.builtin.command']['argv']]
        if 'ansible.builtin.assert' in task:
            task['ansible.builtin.assert']['that']=[s.replace('.uid == 0','.uid == '+str(os.getuid()))
                                                  for s in task['ansible.builtin.assert']['that']]
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,'tasks':tasks}],sort_keys=False))
    filters=tmp_path/'filters';filters.mkdir()
    (filters/'safe.py').write_text('class FilterModule:\n def filters(self):\n  return {"alt_wallet_safe_code":lambda v:v if v=="kwallet_dbus_unverified" else "kwallet_repair_outcome_unverified"}\n')
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nretry_files_enabled=False\nfilter_plugins='+str(filters)+'\n')
    result=subprocess.run([str(executable),'-i','localhost,',str(play)],cwd=tmp_path,
                          env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),capture_output=True,text=True,timeout=25)
    assert (result.returncode==0) is (case in ('repair','healthy','owned_previous')),result.stdout+result.stderr
    assert marker.exists() is (case in ('repair','owned_previous','unknown','private_error'))
    assert 'PRIVATE-SECRET-SENTINEL' not in result.stdout+result.stderr
    if case=='unknown':assert 'kwallet_dbus_unverified' in result.stdout
    if case=='repair':assert 'changed=2' in result.stdout
    if case in ('repair','healthy','owned_previous','unknown','private_error'):
        assert hashlib.sha256(installed.read_bytes()).hexdigest()==digest
    if case=='healthy':
        expected.update(helper_installed=True,installed_helper_sha256=digest)
        variables['alt_setup_workflow_context']['claim_sha256']='f'*64
        play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,'tasks':tasks}],sort_keys=False))
        second=subprocess.run([str(executable),'-i','localhost,',str(play)],cwd=tmp_path,
            env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),capture_output=True,text=True,timeout=25)
        assert second.returncode==0 and 'changed=0' in second.stdout,second.stdout+second.stderr
        assert not marker.exists()
    if case=='foreign_helper':assert installed.read_text()=='FOREIGN-DO-NOT-OVERWRITE'
    if case in ('bad_context','bad_name','changed_source'):assert not installed.exists()


def test_fixed_playbook_requires_one_confirmed_wallet_component_job():
    play=yaml.safe_load((SOURCE/'playbooks/06-kwallet-empty-name-repair.yml').read_text())[0]
    assert play['serial']==1 and play['become'] is True
    assert play['tasks'][-1]['ansible.builtin.import_tasks']=='tasks/setup_component_execution.yml'
    gate=play['tasks'][0]['ansible.builtin.assert']['that']
    assert "setup_component_id == 'desktop.kwallet_repair'" in gate
    assert 'ansible_play_hosts_all | length == 1' in gate
    assert 'vault.yml' not in str(play['vars_files'])
