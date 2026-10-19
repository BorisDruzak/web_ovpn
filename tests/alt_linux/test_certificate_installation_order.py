"""Certificate completion must follow the selected provider, including add-ons."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_probe import desired_queries
from test_component_catalog import SOURCE


@pytest.mark.parametrize('profile,components,required',[
    ('office-standard-v1',['certificates.government'],False),
    ('base',['certificates.government'],False),
    ('core-apps',['certificates.government'],True),
    ('office-signature-v1',['certificates.government'],True),
    ('base',['software.cryptopro','certificates.government'],True),
])
def test_fresh_ca_verification_knows_when_csp_is_required(profile,components,required):
    catalog=ComponentCatalog.load(SOURCE)
    queries=desired_queries(SOURCE,catalog,[catalog.component(c) for c in components],profile_id=profile)
    certificate=next(q for q in queries if q['recipe']=='government_ca')
    assert certificate['require_cryptopro'] is required


@pytest.mark.parametrize('mode',['full','addon','provider_failure'])
def test_real_ansible_certificate_import_runs_after_provider_success(tmp_path,mode):
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned real Ansible is unavailable')
    if mode=='full':
        document=yaml.safe_load((SOURCE/'playbooks/tasks/configure_critical_phase.yml').read_text())
        block=next(t['block'] for t in document if 'block' in t)
        tasks=[t for t in block if t.get('ansible.builtin.include_role',{}).get('name') in
               ('standard_software','government_ca')]
    else:
        document=yaml.safe_load((SOURCE/'playbooks/tasks/setup_component_execution.yml').read_text())
        start=next(i for i,t in enumerate(document) if t.get('name')=='Execute only the selected published role')
        end=next(i for i,t in enumerate(document) if t.get('name')=='Write completion evidence after the selected role and its cleanup')
        tasks=document[start:end]
    roles=tmp_path/'roles'
    software=[{'ansible.builtin.fail':{'msg':'PROVIDER-FAILED'}}] if mode=='provider_failure' else [
        {'ansible.builtin.set_fact':{'provider_ready':True,'installation_trace':['cryptopro']}}]
    for name,body in {
        'standard_software':[{'ansible.builtin.include_role':{'name':'software_cryptopro'}}],
        'software_cryptopro':software,
        'government_ca':[
            {'ansible.builtin.assert':{'that':['provider_ready is sameas true']}},
            {'ansible.builtin.set_fact':{'installation_trace':"{{ installation_trace + ['machine_ca', 'user_ca'] }}"}},
            {'ansible.builtin.copy':{'dest':str(tmp_path/'result.json'),'content':"{{ installation_trace | to_json }}",'mode':'0600'}}],
    }.items():
        folder=roles/name/'tasks';folder.mkdir(parents=True)
        (folder/'main.yml').write_text(yaml.safe_dump(body,sort_keys=False))
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
        'setup_component_id':'software.cryptopro','setup_selected_catalog':{
            'execution_components':[{'id':'software.cryptopro','execution':{'role':'software_cryptopro'}}]}}
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,
        'vars':variables,'tasks':tasks}],sort_keys=False))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nretry_files_enabled=False\nroles_path='+str(roles)+'\n')
    result=subprocess.run([str(executable),'-i','localhost,',str(play)],env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),
                          cwd=tmp_path,text=True,capture_output=True,timeout=25)
    if mode=='provider_failure':
        assert result.returncode and not (tmp_path/'result.json').exists()
    else:
        assert result.returncode==0,result.stdout+result.stderr
        assert json.loads((tmp_path/'result.json').read_text())==['cryptopro','machine_ca','user_ca']


@pytest.mark.parametrize('selected,available,success',[(True,False,False),(True,True,True),(False,False,True),('profile',False,False)])
def test_real_ansible_missing_required_provider_blocks_before_trust_writes(tmp_path,selected,available,success):
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned real Ansible is unavailable')
    tasks=yaml.safe_load((SOURCE/'roles/government_ca/tasks/main.yml').read_text())
    end=next(i for i,t in enumerate(tasks) if t.get('name')=='Require the selected provider before changing its certificate stores')
    assert end<next(i for i,t in enumerate(tasks) if t.get('name')=='Install certificate management prerequisites')
    tasks=tasks[:end+1]
    manager=tmp_path/'certmgr'
    if available:manager.write_text('#!/bin/sh\nexit 0\n');manager.chmod(0o755)
    for task in tasks:
        if 'ansible.builtin.stat' in task:task['ansible.builtin.stat']['path']=str(manager)
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
        'setup_selected_catalog':{'execution_components':[{'id':'software.cryptopro'}] if selected is True else []},
        'government_ca_certificates':yaml.safe_load((SOURCE/'roles/government_ca/defaults/main.yml').read_text())['government_ca_certificates']}
    if selected=='profile':variables['setup_selected_catalog']['profile_component_ids']=['software.cryptopro','certificates.government']
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,'tasks':tasks}]))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nretry_files_enabled=False\n')
    result=subprocess.run([str(executable),'-i','localhost,',str(play)],env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),
                          cwd=tmp_path,text=True,capture_output=True,timeout=20)
    assert (result.returncode==0) is success,result.stdout+result.stderr
    assert 'changed=0' in result.stdout


def test_real_ansible_machine_roots_precede_intermediates_and_import_is_idempotent(tmp_path):
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned real Ansible is unavailable')
    tasks=yaml.safe_load((SOURCE/'roles/government_ca/tasks/main.yml').read_text())
    entries=yaml.safe_load((SOURCE/'roles/government_ca/defaults/main.yml').read_text())['government_ca_certificates']
    names={'Determine whether the selected installation requires CryptoPro trust',
        'Inspect installed CryptoPro certificate manager','Require the selected provider before changing its certificate stores',
        'Query approved certificates in CryptoPro machine stores',
        'Import missing government certificates into CryptoPro machine stores',
        'Verify all government certificates in their CryptoPro machine stores'}
    tasks=[t for t in tasks if t.get('name') in names]
    state=tmp_path/'state.json';state.write_text(json.dumps({'vendor':'preserve','installed':{},'imports':[]}))
    manager=tmp_path/'certmgr'
    manager.write_text('#!'+sys.executable+'\nimport sys,json\nfrom pathlib import Path\n'+
        'p=Path('+repr(str(state))+');v=json.loads(p.read_text());entries='+repr(entries)+'\n'+
        'args=sys.argv[1:];store=args[args.index("-store")+1]\n'+
        'if "-install" in args:\n'+
        ' filename=Path(args[args.index("-file")+1]).name;e=next(e for e in entries if e["filename"]==filename)\n'+
        ' v["installed"][store+":"+e["thumbprint_sha1"]]=True;v["imports"].append([store,e["kind"]]);p.write_text(json.dumps(v));raise SystemExit(0)\n'+
        'thumb=args[args.index("-thumbprint")+1];print(thumb);raise SystemExit(0 if store+":"+thumb in v["installed"] else 44)\n')
    manager.chmod(0o755)
    for task in tasks:
        if 'ansible.builtin.stat' in task:task['ansible.builtin.stat']['path']=str(manager)
        if 'ansible.builtin.command' in task:
            task['ansible.builtin.command']['argv'][0]=str(manager)
            task['ansible.builtin.command']['argv']=[s.replace('/usr/local/share/alt-government-ca',str(SOURCE/'files/government_ca'))
                                                    for s in task['ansible.builtin.command']['argv']]
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
        'government_ca_certificates':entries,'setup_selected_catalog':{'execution_components':[{'id':'software.cryptopro'}]}}
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,'tasks':tasks}],sort_keys=False))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nretry_files_enabled=False\n')
    for iteration in range(2):
        result=subprocess.run([str(executable),'-i','localhost,',str(play)],env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)),
                              cwd=tmp_path,text=True,capture_output=True,timeout=35)
        assert result.returncode==0,result.stdout+result.stderr
        if iteration:assert 'changed=0' in result.stdout
    observed=json.loads(state.read_text())
    assert observed['vendor']=='preserve'
    assert observed['imports']==[['mRoot','root']]*3+[['mCA','intermediate']]*3
