"""Real Ansible exercises phase binding and safe DNS outcome classification."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from test_component_catalog import SOURCE
from test_workstation_final_dns import UUID


ROLE=SOURCE/'roles/workstation_final_dns'


@pytest.mark.parametrize('case',['applied','noop','rollback','unknown','changed_network','wrong_phase','wrong_policy','private_code','foreign_helper'])
def test_real_role_preserves_phase_guards_and_never_logs_private_output(tmp_path,case):
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned Ansible is unavailable')
    marker=tmp_path/'applied';observation={'schema_version':1,'machine_uuid':UUID,'hostname':'alt-test-pc1','snapshot_sha256':'a'*64}
    result={'status':'outcome_unverified' if case in ('unknown','private_code') else 'rolled_back_verified' if case=='rollback' else 'applied_verified',
        'changed':case=='applied','code':'PRIVATE-SECRET-SENTINEL' if case=='private_code' else 'final_dns_rollback_unverified'}
    program=('import sys,json\nfrom pathlib import Path\nd=json.load(sys.stdin)\n'+
        'if "--observe" in sys.argv:\n v='+repr(observation)+'\n'+
        (' v["snapshot_sha256"]="f"*64\n' if case=='changed_network' else '')+
        ' print(json.dumps({"schema_version":1,"status":"ok","helper_sha256":d["helper_sha256"],"observation":v}))\n'+
        'else:\n Path('+repr(str(marker))+').write_text(json.dumps(d))\n'+
        ' print(json.dumps({"schema_version":1,"status":'+repr('blocked' if case in ('unknown','private_code') else 'ok')+
        ',"helper_sha256":d["helper_sha256"],"claim_sha256":d["context"]["claim_sha256"],"result":'+repr(result)+'}))\n')
    sha=hashlib.sha256(program.encode()).hexdigest()
    context={'schema_version':1,'kind':'complete_workstation','phase':'user' if case=='wrong_phase' else 'final_dns',
        'machine_uuid':UUID,'claim_sha256':'b'*64,'policy_sha256':'0'*64 if case=='wrong_policy' else
        hashlib.sha256(b'{"servers":["192.0.2.53"]}').hexdigest()}
    variables={'ansible_connection':'local','ansible_python_interpreter':sys.executable,'machine_uuid':UUID,
        'final_hostname':'alt-test-pc1','alt_setup_workflow_context':context,
        'alt_setup_final_dns_request':{'schema_version':1,'machine_uuid':UUID,'hostname':'alt-test-pc1','servers':['192.0.2.53']},
        'alt_setup_final_dns_readiness':{'status':'ok','helper_sha256':sha,'observation':observation},
        'final_dns_helper_program':program,'final_dns_previous_helper_sha256':[]}
    installed=tmp_path/'usr/local/libexec/alt-workstation-final-dns';installed.parent.mkdir(parents=True)
    if case=='foreign_helper':installed.write_text('FOREIGN-DO-NOT-OVERWRITE');installed.chmod(0o700)
    tasks=[t for t in yaml.safe_load((ROLE/'tasks/main.yml').read_text()) if t['name']!='Render the fixed published final DNS helper']
    for task in tasks:
        for key,value in list(task.items()):
            if key.startswith('ansible.builtin.') and isinstance(value,dict):
                for field,data in list(value.items()):
                    if isinstance(data,str) and data.startswith('/usr'):value[field]=str(tmp_path)+data
                for field in ('owner','group'):
                    if field in value:value[field]=str(os.getuid() if field=='owner' else os.getgid())
        if isinstance(task.get('loop'),list):task['loop']=[str(tmp_path)+p if p.startswith('/usr') else p for p in task['loop']]
        if 'ansible.builtin.command' in task:
            task['ansible.builtin.command']['argv']=[v.replace('/usr/local/libexec/alt-workstation-final-dns',str(installed)) for v in task['ansible.builtin.command']['argv']]
        if 'ansible.builtin.assert' in task:
            task['ansible.builtin.assert']['that']=[v.replace('.uid == 0','.uid == '+str(os.getuid())) for v in task['ansible.builtin.assert']['that']]
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,'tasks':tasks}],sort_keys=False))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nretry_files_enabled=False\nfilter_plugins='+str(SOURCE/'filter_plugins')+'\n')
    completed=subprocess.run([str(executable),'-i','localhost,',str(play)],cwd=tmp_path,
        env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),capture_output=True,text=True,timeout=25)
    assert (completed.returncode==0) is (case in ('applied','noop','rollback')),completed.stdout+completed.stderr
    assert marker.exists() is (case in ('applied','noop','rollback','unknown','private_code'))
    assert 'PRIVATE-SECRET-SENTINEL' not in completed.stdout+completed.stderr
    if case=='applied':assert 'changed=2' in completed.stdout
    if case in ('noop','rollback'):assert 'changed=1' in completed.stdout
    if case=='foreign_helper':assert installed.read_text()=='FOREIGN-DO-NOT-OVERWRITE'


def test_real_ansible_template_is_exactly_the_published_program(tmp_path):
    from alt_deploy.final_dns_program import target_program
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned Ansible is unavailable')
    digest=hashlib.sha256(target_program(SOURCE).encode()).hexdigest()
    tasks=[{'ansible.builtin.set_fact':{'program':"{{ lookup('ansible.builtin.template', template_path) }}"}},
        {'ansible.builtin.assert':{'that':["(program | hash('sha256')) == expected"]}}]
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,
        'vars':{'role_path':str(ROLE),'template_path':str(ROLE/'templates/alt-workstation-final-dns.py.j2'),'expected':digest},'tasks':tasks}]))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nfilter_plugins='+str(SOURCE/'filter_plugins')+'\n')
    completed=subprocess.run([str(executable),'-i','localhost,',str(play)],cwd=tmp_path,
        env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),capture_output=True,text=True,timeout=15)
    assert completed.returncode==0,completed.stdout+completed.stderr
