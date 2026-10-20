"""Exercise actual Ansible selection, with only synthetic target roles."""
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys

import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.full_workflow import build_workflow_plan
from test_component_catalog import SOURCE,project


@pytest.mark.parametrize('phase',['user','final_dns','system','user_client_race'])
def test_real_ansible_phase_boundary_never_selects_a_system_or_join_role(project,tmp_path,phase):
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.exists():pytest.skip('Pinned Ansible unavailable')
    tasks=SOURCE/'playbooks/tasks/setup_workflow_phase_execution.yml'
    assert tasks.is_file()
    (project/'playbooks/tasks').mkdir(parents=True)
    shutil.copy2(tasks,project/'playbooks/tasks'/tasks.name)
    shutil.copytree(SOURCE/'filter_plugins',project/'filter_plugins',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(SOURCE.parent/'control',project.parent/'control',ignore=shutil.ignore_patterns('__pycache__'))
    catalog=ComponentCatalog.load(project);workflow=build_workflow_plan(catalog,{'servers':['192.0.2.53']})
    markers=tmp_path/'markers';markers.mkdir()
    for component in catalog.components():
        role=component['execution'].get('role')
        if not role:continue
        path=project/'roles'/role/'tasks/main.yml'
        path.write_text(yaml.safe_dump([{'ansible.builtin.copy':{'dest':str(markers/component['id']),'content':'executed'}},
            {'ansible.builtin.set_fact':{'alt_setup_final_dns_result':{'status':'applied_verified','code':'final_dns_applied'}}}],sort_keys=False))
    if phase=='user_client_race':
        path=project/'roles/remote_access_krfb/tasks/main.yml'
        tasks=yaml.safe_load(path.read_text());tasks.append({'ansible.builtin.fail':{'msg':'krfb_clients_connected'}})
        path.write_text(yaml.safe_dump(tasks))
    ca=project/'roles/government_ca/tasks/user_finalize.yml'
    ca.write_text(yaml.safe_dump([{'ansible.builtin.copy':{'dest':str(markers/'user-certificates'),'content':'executed'}}]))
    context={'schema_version':1,'kind':'complete_workstation','phase':'user' if phase=='user_client_race' else phase,'job_id':'job-20261020T000000Z-12345678',
        'claim_sha256':'1'*64,'plan_sha256':'2'*64,'machine_uuid':'11111111-2222-3333-4444-555555555555',
        'source_sha256':'3'*64,'workflow_policy_sha256':workflow['policy_sha256'],
        'policy_sha256':'4'*64}
    result=tmp_path/'result.json'
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
        'software_profile':'workstation-full-v1','remote_access_profile':'krfb','machine_uuid':context['machine_uuid'],
        'setup_job_id':context['job_id'],'setup_workflow':workflow,'alt_setup_workflow_context':context,
        'setup_phase_result_file':str(result)}
    play=project/'playbooks/test-phase.yml'
    play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':variables,
                                   'tasks':[{'ansible.builtin.import_tasks':'tasks/setup_workflow_phase_execution.yml'}]}],sort_keys=False))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nroles_path='+str(project/'roles')+'\nfilter_plugins='+str(project/'filter_plugins')+'\nretry_files_enabled=False\n')
    run=subprocess.run([str(executable),'-i','localhost,',str(play)],capture_output=True,text=True,timeout=25,
        cwd=project,env=dict(os.environ,ANSIBLE_CONFIG=str(cfg)))
    assert (run.returncode==0) is (phase in ('user','final_dns')),run.stdout+run.stderr
    expected={'desktop.kwallet_repair','desktop.shortcuts','remote.krfb','user-certificates'} if phase=='user' else {'network.final_dns'} if phase=='final_dns' else {'remote.krfb'} if phase=='user_client_race' else set()
    assert {p.name for p in markers.iterdir()}==expected
    if phase in ('user','final_dns'):assert json.loads(result.read_text())['context']==context
