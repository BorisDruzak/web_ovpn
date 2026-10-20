"""Native Setup binds complete policy; legacy callers cannot enable managed mode."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.configure import ConfigurePlanner,ConfigureRequest
from alt_deploy.errors import ControlError
from alt_deploy.setup_runtime import SetupRuntime
from alt_deploy.vault import VaultHealthChecker
from test_component_catalog import SOURCE,project
from test_component_verification import evidence
from test_setup_service import scenario,UUID,OU


@pytest.fixture
def full_setup(tmp_path,project,monkeypatch):
    setup,machine,user,observed,computer,calls=scenario(tmp_path/'state')
    user['object_sid']='S-1-5-21-1-2-3-1001'
    setup.settings.ansible_project_dir=project;setup.settings.known_hosts_file=tmp_path/'known';setup.settings.private_key_file=tmp_path/'key'
    setup.catalog=ComponentCatalog.load(project);state=evidence(setup.catalog)
    setup.component_probe=SimpleNamespace(observe=lambda *a,**k:copy.deepcopy(state))
    monkeypatch.setattr('alt_deploy.component_probe.ssh_binding',lambda *a,**k:{'host_public_sha256':'1'*64,'controller_public_sha256':'2'*64})
    policy={'servers':['192.0.2.53']};monkeypatch.setattr(VaultHealthChecker,'full_workflow_policy',lambda self:copy.deepcopy(policy))
    options=[];setup.prerequisites=lambda request,**kwargs:options.append(kwargs) or {'ready':True}
    admission={'schema_version':1,'dc':'dc.sosnadmin.local','join_principal_guid':'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa',
        'join_principal_sid':'S-1-5-21-1-2-3-4001','ou_guid':'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
        'domain_quota':10,'created_computers':10,'quota_remaining':0,'quota_applicable':False,'creation_mode':'delegated'}
    setup.join_admission=lambda request:copy.deepcopy(admission)
    return setup,machine,user,state,policy,options,calls,admission


def test_plan_binds_complete_policy_original_identity_and_system_budget(full_setup):
    setup,machine,user,state,policy,options,calls,admission=full_setup
    plan=setup.plan(UUID,user['login'],OU,'workstation-full-v1','krfb');payload=plan['payload']
    assert payload['workflow']['policy']['final_dns']==policy
    assert payload['workflow']['phases'][0]['budget_seconds']==payload['execution_budget_seconds']==21600
    assert options==[{'managed_workflow':payload['workflow']}]
    assert payload['ad_join_admission']==admission and payload['ssh_binding']['host_public_sha256']=='1'*64
    assert 'network_restriction_confirmed' not in payload
    assert 'ensure_opt_in_krfb' not in payload['changes']
    assert calls==[] and not setup.settings.lock_file.exists()


@pytest.mark.parametrize('fault',['remote_optout','missing_policy','dns_backend','missing_dns_evidence','missing_admission',
                                 'vnc_backend','missing_vnc_evidence','vnc_external_blocker'])
def test_complete_plan_cannot_opt_out_or_hide_missing_policy_or_unknown_backend(full_setup,monkeypatch,fault):
    setup,machine,user,state,policy,options,calls,admission=full_setup
    if fault=='missing_policy':monkeypatch.setattr(VaultHealthChecker,'full_workflow_policy',lambda self:(_ for _ in ()).throw(ControlError('full_workflow_policy_unavailable','Safe',7)))
    if fault=='dns_backend':state['components']['network.final_dns'].update(checks={'ready':False},error_code='final_dns_backend_unverified')
    if fault=='missing_dns_evidence':state['components']['network.final_dns'].pop('final_dns')
    if fault=='missing_admission':setup.join_admission=None
    if fault=='vnc_backend':state['components']['remote.vnc_policy'].update(error_code='probe_failed')
    if fault=='missing_vnc_evidence':state['components'].pop('remote.vnc_policy')
    if fault=='vnc_external_blocker':state['components']['remote.vnc_policy']['checks']['external_policy_clear']=False
    with pytest.raises(ControlError) as caught:setup.plan(UUID,user['login'],OU,'workstation-full-v1','none' if fault=='remote_optout' else 'krfb')
    assert caught.value.code=={'remote_optout':'configure_request_invalid','missing_policy':'full_workflow_policy_unavailable',
                              'dns_backend':'full_workflow_dns_backend_unverified','missing_dns_evidence':'full_workflow_dns_backend_unverified',
                              'missing_admission':'full_workflow_admission_unverified',
                              'vnc_backend':'full_workflow_vnc_backend_unverified',
                              'missing_vnc_evidence':'full_workflow_vnc_backend_unverified',
                              'vnc_external_blocker':'full_workflow_vnc_backend_unverified'}[fault]
    assert calls==[] and not (setup.settings.state_root/'setup-plan-runs').exists()


def test_delegated_quota_diagnostics_do_not_stale_a_second_queued_pc(full_setup):
    setup,machine,user,state,policy,options,calls,admission=full_setup
    plan=setup.plan(UUID,user['login'],OU,'workstation-full-v1','krfb')
    admission['created_computers']=11
    current=setup._validate_job_plan(plan,own_job_id='job-20261020T010000Z-12345678')
    assert current['ad_join_admission']['created_computers']==11
    admission['join_principal_guid']='dddddddd-dddd-eeee-ffff-aaaaaaaaaaaa'
    with pytest.raises(ControlError) as caught:setup._validate_job_plan(plan,own_job_id='job-20261020T010000Z-12345678')
    assert caught.value.code=='setup_plan_drift' and calls==[]


def test_low_level_configure_cannot_select_managed_workflow_without_the_native_job(full_setup):
    setup,machine,user,state,policy,options,calls,admission=full_setup
    plan=setup.plan(UUID,user['login'],OU,'workstation-full-v1','krfb')
    request=ConfigureRequest.from_mapping(plan['payload']['request'],expected_uuid=UUID,catalog=setup.catalog)
    planner=ConfigurePlanner(setup.settings,machines=setup.machines)
    with pytest.raises(ControlError) as caught:planner.start(UUID,request)
    assert caught.value.code=='full_workflow_context_required'
    assert calls==[]


@pytest.mark.parametrize('fault',[None,'no_context','policy_changed','legacy_injection'])
def test_controller_preflight_managed_mode_is_explicit_and_does_not_set_legacy_network_flag(full_setup,monkeypatch,tmp_path,fault):
    from alt_deploy.full_workflow import build_workflow_plan
    setup,machine,user,state,policy,options,calls,admission=full_setup
    profile='core-apps' if fault=='legacy_injection' else 'workstation-full-v1'
    request=ConfigureRequest.from_mapping({'machine_uuid':UUID,'final_hostname':machine.hostname,'hostname_mode':'verify',
        'profile':'standard-domain','domain':'sosnadmin.local','realm':'SOSNADMIN.LOCAL','workgroup':'SOSNADM',
        'computer_ou':OU,'domain_test_user':user['upn'],'assigned_domain_user':user['upn'],
        'software_profile':profile,'remote_access_profile':'krfb'},expected_uuid=UUID,catalog=setup.catalog)
    workflow=build_workflow_plan(setup.catalog,policy)
    setup.settings.ansible_playbook_path=tmp_path/'ansible-playbook'
    for path in [setup.settings.ansible_playbook_path,setup.settings.private_key_file,setup.settings.known_hosts_file,
        setup.settings.ansible_project_dir/'ansible.cfg',
        setup.settings.ansible_project_dir/'playbooks/03-setup-controller-preflight.yml',
        setup.settings.ansible_project_dir/'playbooks/03-configure-domain-workstation.yml']:
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
    monkeypatch.setattr(VaultHealthChecker,'check_ad_join',lambda self:{'status':'ok'})
    monkeypatch.setattr(VaultHealthChecker,'check_krfb',lambda self:{'status':'ok'})
    monkeypatch.delenv('ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED',raising=False)
    if fault=='policy_changed':policy['servers']=['192.0.2.54']
    commands=[];runtime=SetupRuntime(setup.settings,runner=lambda command,**kw:commands.append((command,kw)) or (0,'',''))
    if fault:
        with pytest.raises(ControlError):runtime.prerequisites(request,**({} if fault=='no_context' else {'managed_workflow':workflow}))
        assert commands==[]
    else:
        ready=runtime.prerequisites(request,managed_workflow=workflow)
        assert ready['ready'] is True and ready['workflow_policy_sha256']==workflow['policy_sha256']
        assert len(commands)==1 and 'localhost,' in commands[0][0]
        assert 'ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED' not in commands[0][1]['environment']


@pytest.mark.parametrize('fault',[None,'no_flock','later_phase','policy','source'])
def test_initial_system_context_requires_original_process_claim_and_real_lifecycle_ownership(full_setup,fault):
    from alt_deploy.full_workflow import native_system_context
    from alt_deploy.setup_jobs import SetupJobRepository,setup_job_execution
    from alt_deploy.setup_worker import process_identity
    from alt_deploy.locks import exclusive_lock
    from alt_deploy.setup_plans import digest,private_read
    setup,machine,user,state,policy,options,calls,admission=full_setup
    plan=setup.plan(UUID,user['login'],OU,'workstation-full-v1','krfb')
    request=ConfigureRequest.from_mapping(plan['payload']['request'],expected_uuid=UUID,catalog=setup.catalog)
    jobs=SetupJobRepository(setup.settings,clock=setup.clock)
    job=jobs.submit(plan,operation='full_setup')
    def perform():
        jobs.claim(job.job_id,process_identity(setup.settings))
        jobs.transition(job.job_id,'running',stage={'id':'workflow.user.apply' if fault=='later_phase' else 'full_setup.apply'})
        if fault=='source':(setup.settings.ansible_project_dir/'roles/workstation_base/source-drift.txt').write_text('source drift')
        if fault=='policy':policy['servers']=['192.0.2.54']
        with setup_job_execution(setup.settings,job.job_id,plan):
            if fault:
                with pytest.raises(ControlError):native_system_context(setup.settings,request,plan['payload']['workflow'])
            else:
                context=native_system_context(setup.settings,request,plan['payload']['workflow'])
                claim=private_read(jobs.claims/(plan['sha256']+'.json'))
                assert context=={'schema_version':1,'kind':'complete_workstation','phase':'system','job_id':job.job_id,
                    'claim_sha256':digest(claim),'plan_sha256':plan['sha256'],'machine_uuid':UUID,
                    'source_sha256':plan['payload']['source_sha256'],'workflow_policy_sha256':plan['payload']['workflow']['policy_sha256'],
                    'policy_sha256':digest(plan['payload']['workflow']['policy']['vnc'])}
    if fault=='no_flock':perform()
    else:
        with exclusive_lock(setup.settings.lock_file):perform()
    assert calls==[]


@pytest.mark.parametrize('missing_marker',[False,True])
def test_real_public_configure_binds_one_original_system_claim_and_six_hour_budget(full_setup,monkeypatch,tmp_path,missing_marker):
    import subprocess
    from alt_deploy.locks import exclusive_lock
    from alt_deploy.setup_jobs import SetupJobRepository,setup_job_execution
    from alt_deploy.setup_worker import process_identity
    from alt_deploy.setup_events import SetupEventStore
    from alt_deploy.full_workflow import deferred_system_result
    setup,machine,user,state,policy,options,calls,admission=full_setup
    computer={'object_guid':'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa','object_sid':'S-1-5-21-1-2-3-2001',
        'dn':'CN='+machine.hostname+','+OU,'dns_hostname':machine.hostname+'.sosnadmin.local'}
    setup.directory.computer=lambda name:{'hostname':name,'exists':True,'objects':[computer]}
    setup.probe=lambda *a:{'uuid':UUID,'hostname':machine.hostname,'domain':'sosnadmin.local','trust':True,
        'sssd':True,'user_lookup':True,'local_duplicate':False,'home_exists':True,
        'computer_identity':dict(computer,sam_account_name=machine.hostname+'$')}
    setup.settings.ansible_playbook_path=tmp_path/'ansible-playbook'
    for path in [setup.settings.ansible_playbook_path,setup.settings.known_hosts_file,setup.settings.private_key_file,
        setup.settings.ansible_project_dir/'playbooks/03-configure-domain-workstation.yml']:
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
    plan=setup.plan(UUID,user['login'],OU,'workstation-full-v1','krfb');workflow=plan['payload']['workflow']
    request=ConfigureRequest.from_mapping(plan['payload']['request'],expected_uuid=UUID,catalog=setup.catalog)
    jobs=SetupJobRepository(setup.settings,clock=setup.clock);job=jobs.submit(plan,operation='full_setup')
    binding=setup.assignments.identity_binding(UUID,user,OU,'workstation-full-v1','krfb')
    reserved='setup-run-'+'e'*32
    setup.assignments.write(binding,run_id=reserved,result='running',date=setup.clock().isoformat(),revision=1)
    monkeypatch.setattr(VaultHealthChecker,'check_ad_join',lambda self:{'status':'ok'})
    monkeypatch.setattr(VaultHealthChecker,'check_krfb',lambda self:{'status':'ok'})
    monkeypatch.setattr('alt_deploy.krfb_runtime.observe_vnc_policy',lambda *a,**kw:{
        'ssh_binding':plan['payload']['ssh_binding'],'observation':{'source_sha256':plan['payload']['source_sha256']}})
    command_calls=[]
    def runner(command,**kw):
        command_calls.append((command,kw))
        assert kw['timeout']==21600 and 'ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED' not in kw['env']
        parameters=next(v[1:] for v in command if v.startswith('@') and v.endswith('workflow-vars.json'))
        values=json.loads(Path(parameters).read_text())
        assert Path(parameters).stat().st_mode&0o777==0o600
        assert values['alt_setup_workflow_context']['phase']=='system' and values['alt_setup_workflow']==workflow
        target=Path(next(v.split('=',1)[1] for v in command if v.startswith('configure_result_file=')))
        result={'schema_version':1,'machine_uuid':UUID,'hostname':machine.hostname,'profile':'standard-domain',
            'status':'successful','phase':'finalize','retryable':False,'recovered':False,'reboot_required':True,
            'error':None,'components':{} if missing_marker else {'workflow_deferred':deferred_system_result(workflow)},
            'verification':{'group_policy':True}}
        target.write_text(json.dumps(result));target.chmod(0o600)
        SetupEventStore(setup.settings).append(job.job_id,{'schema_version':1,'component_id':'domain.ready',
            'component_version':1,'stage':'complete','task_id':'component','type':'component_completed','changed':True,'code':'completed'})
        return subprocess.CompletedProcess(command,0)
    monkeypatch.setattr('alt_deploy.configure.subprocess.run',runner)
    planner=ConfigurePlanner(setup.settings,machines=setup.machines)
    with exclusive_lock(setup.settings.lock_file):
        jobs.claim(job.job_id,process_identity(setup.settings));jobs.transition(job.job_id,'running',stage={'id':'full_setup.apply'})
        with setup_job_execution(setup.settings,job.job_id,plan):
            if missing_marker:
                with pytest.raises(ControlError) as caught:planner.start(UUID,request,_lock_held=True,setup_run_id=reserved,setup_workflow=workflow)
                assert caught.value.code=='domain_verification_failed'
            else:
                result=planner.start(UUID,request,_lock_held=True,setup_run_id=reserved,setup_workflow=workflow)
                assert result['components']['workflow_deferred']==deferred_system_result(workflow)
    assert len(command_calls)==1 and calls==[]
