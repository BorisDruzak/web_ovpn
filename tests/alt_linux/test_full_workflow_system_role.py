"""Real Ansible proves policy-before-join and absence of early user effects."""
import json
import subprocess
import sys

import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.full_workflow import build_workflow_plan
from alt_deploy.setup_plans import digest
from test_component_catalog import project
from test_component_ansible_runtime import ansible_runtime


@pytest.mark.parametrize('case',['complete','policy_failure','missing_context','legacy'])
def test_fixed_initial_playbook_defers_every_later_phase_and_never_joins_after_policy_failure(ansible_runtime,case):
    executable,project,env=ansible_runtime;trace=project/'called.jsonl';output=project/'configure-result.json'
    roles=['manual_preflight','workstation_identity','remote_access_policy','prejoin_upgrade','workstation_base',
        'alt_group_policy_prerequisites','workstation_network','domain_join','alt_group_policy_client','domain_login_baseline',
        'plasma_baseline','standard_software','government_ca','desktop_shortcuts','remote_access_krfb','domain_verify',
        'kwallet_empty_name_repair','workstation_final_dns']
    for role in roles:
        tasks=[{'ansible.builtin.command':{'argv':[sys.executable,'-c',
            'from pathlib import Path;p=Path('+repr(str(trace))+');p.open("a").write('+repr(role+'\n')+')']}}]
        if role=='remote_access_policy':
            if case=='policy_failure':tasks.append({'ansible.builtin.fail':{'msg':'Synthetic policy preparation failed'}})
            else:tasks.append({'ansible.builtin.set_fact':{'alt_vnc_policy_apply':{'rc':0,'stdout':json.dumps({'status':'ok','result':{'ready':True}})}}})
        if role=='domain_verify':tasks.append({'ansible.builtin.set_fact':{'domain_verification':{
            'domain_join':True,'sssd':True,'domain_user_lookup':True,'home_creation':True}}})
        if role=='alt_group_policy_client':tasks.append({'ansible.builtin.set_fact':{'alt_group_policy_machine_updated':True}})
        (project/'roles'/role/'tasks/main.yml').write_text(yaml.safe_dump(tasks))
    (project/'roles/remote_access_krfb/tasks/system.yml').write_text(yaml.safe_dump([
        {'ansible.builtin.command':{'argv':[sys.executable,'-c','from pathlib import Path;Path('+repr(str(trace))+').open("a").write("krfb_system_package\\n")']}}]))
    catalog=ComponentCatalog.load(project);workflow=build_workflow_plan(catalog,{'servers':['192.0.2.53']})
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
        'machine_uuid':'11111111-2222-3333-4444-555555555555','final_hostname':'alt-test-pc1','profile':'standard-domain',
        'software_profile':'office-standard-v1' if case=='legacy' else 'workstation-full-v1',
        'remote_access_profile':'none' if case=='legacy' else 'krfb','assigned_domain_user':'synthetic.user@sosnadmin.local',
        'configure_result_file':str(output)}
    if case!='legacy':
        variables['alt_setup_workflow']=workflow
        if case!='missing_context':variables['alt_setup_workflow_context']={
            'schema_version':1,'kind':'complete_workstation','phase':'system','machine_uuid':variables['machine_uuid'],
            'job_id':'job-20261020T010000Z-12345678','claim_sha256':'a'*64,'plan_sha256':'b'*64,
            'source_sha256':'c'*64,'workflow_policy_sha256':workflow['policy_sha256'],'policy_sha256':digest(workflow['policy']['vnc'])}
    parameters=project/'parameters.json';parameters.write_text(json.dumps(variables))
    completed=subprocess.run([str(executable),'-i','localhost,','-e','@'+str(parameters),
        str(project/'playbooks/03-configure-domain-workstation.yml')],cwd=project,env=env,capture_output=True,text=True,timeout=45)
    assert (completed.returncode==0) is (case in ('complete','legacy')),completed.stdout+completed.stderr
    calls=trace.read_text().splitlines() if trace.exists() else []
    if case in ('policy_failure','missing_context'):assert 'domain_join' not in calls
    if case=='complete':
        assert calls.index('remote_access_policy')<calls.index('prejoin_upgrade')<calls.index('krfb_system_package')<calls.index('domain_join')
        assert not set(calls)&{'desktop_shortcuts','remote_access_krfb','kwallet_empty_name_repair','workstation_final_dns'}
        result=json.loads(output.read_text());deferred=result['components']['workflow_deferred']
        assert deferred=={'schema_version':1,'status':'deferred','user':workflow['phases'][1]['component_ids'],
                          'final_dns':workflow['phases'][2]['component_ids']}
    if case=='legacy':
        assert 'remote_access_policy' not in calls and 'krfb_system_package' not in calls and 'desktop_shortcuts' in calls
        assert 'workflow_deferred' not in json.loads(output.read_text())['components']
