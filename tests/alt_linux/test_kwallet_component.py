"""Wallet repair uses the existing confirmed component/job/readonly boundaries."""
import copy
import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_probe import ComponentProbe,desired_queries
from alt_deploy.component_verification import VerificationEngine
from alt_deploy.errors import ControlError
from alt_deploy.setup_execution import ComponentExecutor
from alt_deploy.setup_plans import private_create,private_read
from test_component_catalog import SOURCE,project
from test_component_setup import component_service
from test_setup_jobs import jobs_fixture
from test_component_verification import evidence,UUID
from test_kwallet_runtime import observation


def test_wallet_component_and_queries_preserve_legacy_profile_definitions():
    catalog=ComponentCatalog.load(SOURCE);component=catalog.component('desktop.kwallet_repair')
    assert component['execution']['role']=='kwallet_empty_name_repair'
    assert component['execution']['requires_user_home'] is True and component['execution']['retry_policy']=='guarded'
    query=desired_queries(SOURCE,catalog,[component])[0]
    assert query['recipe']=='kwallet' and query['wallet']['wallet_name']=='recovered-wallet'
    assert len(query['wallet']['helper_sha256'])==64
    assert 'program' not in json.dumps(query)
    profiles=yaml.safe_load((SOURCE/'group_vars/software_catalog.yml').read_text())['setup_catalog']['profiles']
    assert hashlib.sha256(json.dumps(profiles,sort_keys=True,separators=(',',':')).encode()).hexdigest()=='6dd71b909ed4b17939b488a4e63340118b822340592d1d7cfc82ae49d761044f'


@pytest.mark.parametrize('case',['healthy','defect','helper_missing','no_session','private_observation','deferred'])
def test_controller_enriches_only_wallet_with_bounded_readonly_evidence(tmp_path,monkeypatch,case):
    from alt_deploy import kwallet_runtime
    catalog=ComponentCatalog.load(SOURCE);component=catalog.component('desktop.kwallet_repair')
    settings=SimpleNamespace(ansible_project_dir=SOURCE,known_hosts_file=tmp_path/'known',private_key_file=tmp_path/'key')
    machine=SimpleNamespace(uuid=UUID,hostname='alt-a1-pc3',ip='192.0.2.10')
    user={'login':'synthetic.user','upn':'synthetic.user@sosnadmin.local'}
    baseline=evidence(catalog)
    if case=='deferred':baseline['user'].update(uid=None,gid=None,home_exists=False,home_safe=False)
    calls=[]
    def observe(settings,machine,user,**options):
        calls.append(options)
        if case=='no_session':return {'status':'blocked','code':'graphical_session_unavailable'}
        request=dict(kwallet_runtime.specification(SOURCE),schema_version=1,machine_uuid=UUID,hostname=machine.hostname,login=user['login'])
        value=observation(request,installed=case!='helper_missing',disposition='repair' if case=='defect' else 'noop')
        value['boot_id']=baseline['machine']['boot_id']
        value['snapshot_sha256']=hashlib.sha256(kwallet_runtime.canonical({k:v for k,v in value.items() if k!='snapshot_sha256'})).hexdigest()
        if case=='private_observation':value['environment']='PRIVATE-SECRET-SENTINEL'
        return {'status':'ok','observation':value}
    monkeypatch.setattr(kwallet_runtime,'observe',observe)
    probe=ComponentProbe(settings,runner=lambda *a,**k:(0,json.dumps(baseline),''))
    if case=='private_observation':
        with pytest.raises(ControlError) as caught:probe.observe(machine,user,[component])
        assert 'SENTINEL' not in str(caught.value)
        return
    result=probe.observe(machine,user,[component],allow_unresolved=case=='deferred')
    fact=result['components'][component['id']]
    assert fact['checks']['ready'] is (case=='healthy')
    assert 'SENTINEL' not in json.dumps(result)
    if case=='no_session':assert fact['error_code']=='graphical_session_unavailable'
    elif case=='deferred':assert fact['deferred'] is True and calls==[]
    else:assert fact['wallet_readiness']['wallet_name']=='recovered-wallet'
    assert result['components']['software.onlyoffice']==baseline['components']['software.onlyoffice']


def test_verification_never_accepts_missing_wallet_readiness_metadata():
    catalog=ComponentCatalog.load(SOURCE);state=evidence(catalog)
    state['components']['desktop.kwallet_repair'].pop('wallet_readiness',None)
    result=VerificationEngine(catalog).evaluate(state,['desktop.kwallet_repair'])
    assert result['components']['desktop.kwallet_repair']['status']=='unknown'


@pytest.mark.parametrize('claimed',[False,True,'engine'])
def test_wallet_component_executor_uses_its_original_claim_and_fixed_playbook(component_service,tmp_path,claimed):
    service,setup,machine,user,state,*_=component_service
    from alt_deploy.kwallet_runtime import specification,canonical
    spec=specification(setup.settings.ansible_project_dir)
    request=dict(spec,schema_version=1,machine_uuid=UUID,hostname=machine.hostname,login=user['login'])
    value=observation(request,disposition='repair');value['boot_id']=state['machine']['boot_id']
    value['snapshot_sha256']=hashlib.sha256(canonical({k:v for k,v in value.items() if k!='snapshot_sha256'})).hexdigest()
    state['components']['desktop.kwallet_repair'].update(checks={'ready':False},wallet_readiness=value)
    jobs,_,settings=jobs_fixture(component_service)
    plan=service.plan(UUID,'desktop.kwallet_repair');job=jobs.submit(plan,operation='component')
    if claimed:job=jobs.claim(job.job_id,{'boot_id':state['machine']['boot_id'],'pid':1234,'start_ticks':100})
    settings.ansible_playbook_path=tmp_path/'ansible-playbook';settings.ansible_playbook_path.touch()
    calls=[]
    def runner(command,**options):
        calls.append(command)
        private_create(job.job_dir/'component-result.json',{'schema_version':1,'job_id':job.job_id,
            'plan_sha256':plan['sha256'],'machine_uuid':UUID,'component_id':'desktop.kwallet_repair',
            'component_version':1,'status':'applied','reboot_required':False})
        from alt_deploy.setup_events import SetupEventStore
        events=SetupEventStore(settings,clock=jobs.clock)
        for type_,code in [('component_start','started'),('component_completed','completed')]:
            events.append(job.job_id,{'schema_version':1,'component_id':'desktop.kwallet_repair','component_version':1,
                'stage':'apply','task_id':'component','type':type_,'changed':False,'code':code})
        if claimed=='engine':
            after=observation(request,disposition='noop');after['boot_id']=state['machine']['boot_id']
            after['snapshot_sha256']=hashlib.sha256(canonical({k:v for k,v in after.items() if k!='snapshot_sha256'})).hexdigest()
            state['components']['desktop.kwallet_repair'].update(checks={'ready':True},wallet_readiness=after)
        return subprocess.CompletedProcess(command,0)
    executor=ComponentExecutor(settings,ComponentCatalog.load(settings.ansible_project_dir),runner=runner)
    if not claimed:
        with pytest.raises(ControlError):executor.run(plan,job)
        assert calls==[]
        return
    if claimed=='engine':
        from alt_deploy.setup_execution import SetupExecutionEngine
        engine=SetupExecutionEngine(settings,components=service,jobs=jobs,component_executor=executor)
        result=engine.execute(job.job_id)
        assert result['state']=='successful',result
        assert engine.execute(job.job_id)==result and len(calls)==1
    else:
        result=executor.run(plan,job)
        assert result['status']=='applied'
    assert calls[0][-1].endswith('/playbooks/06-kwallet-empty-name-repair.yml')
    variables=private_read(job.job_dir/'component-vars.json')
    context=variables['alt_setup_wallet_component_context']
    assert context['job_id']==job.job_id and context['plan_sha256']==plan['sha256']
    assert context['source_sha256']==plan['payload']['source_sha256']
    assert context['component_id']=='desktop.kwallet_repair' and len(context['operation_sha256'])==64
    assert variables['alt_setup_wallet_readiness']==value
    assert variables['kwallet_repair_user']==user['upn'] and variables['kwallet_repair_new_name']=='recovered-wallet'
    assert 'PRIVATE-' not in json.dumps(variables)
