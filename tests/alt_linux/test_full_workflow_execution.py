"""Later phases keep the original job and never enter the domain adapter."""
import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.setup_execution import SetupExecutionEngine
from alt_deploy.setup_plans import private_read
from test_setup_phases import phase_job,phase_result
from test_setup_phases import system_result
from test_full_workflow_binding import full_setup
from test_component_catalog import project
from test_setup_service import OU


def test_initial_engine_retains_one_protected_run_and_defers_even_an_existing_home(full_setup):
    from alt_deploy.setup_jobs import SetupJobRepository,legacy_setup_execution
    from alt_deploy.setup_worker import process_identity
    from alt_deploy.setup_plans import private_create
    from alt_deploy.full_workflow import deferred_system_result
    setup,machine,user,facts,policy,options,calls,admission=full_setup
    original_start=setup.planner.start;original_probe=setup.probe;original_computer=setup.directory.computer
    done=[];computer=system_result()['computer'];config_id='d'*32
    setup.directory.computer=lambda hostname:({'exists':True,'objects':[copy.deepcopy(computer)]} if done else original_computer(hostname))
    def observe(machine,user):
        value=original_probe(machine,user)
        if value['trust']:value['computer_identity']=dict(computer,sam_account_name=machine.hostname+'$')
        return value
    setup.probe=observe
    plan=setup.plan(machine.uuid,user['login'],OU,'workstation-full-v1','krfb')
    def critical(identifier,request,**kwargs):
        with legacy_setup_execution(setup.settings,machine.uuid,machine.hostname,operation='configure',run_id=config_id):
            original_start(identifier,request,**kwargs);done.append(True)
            result={'schema_version':1,'machine_uuid':machine.uuid,'hostname':machine.hostname,'profile':request.profile,
                'status':'successful','phase':'finalize','retryable':False,'recovered':False,'reboot_required':True,
                'error':None,'components':{'workflow_deferred':deferred_system_result(plan['payload']['workflow'])},
                'verification':{'group_policy':True}}
            private_create(setup.settings.state_root/'configure-runs'/config_id/'request.json',request.to_dict())
            private_create(setup.settings.state_root/'configure-runs'/config_id/'result.json',result)
            return dict(result,run_id=config_id)
    setup.planner.start=critical
    jobs=SetupJobRepository(setup.settings,clock=setup.clock);job=jobs.submit(plan,operation='full_setup')
    engine=SetupExecutionEngine(setup.settings,jobs=jobs,setup=setup)
    engine._verified=lambda *a:pytest.fail('Legacy verifier cannot finish deferred phases')
    with exclusive_lock(setup.settings.lock_file):
        jobs.claim(job.job_id,process_identity(setup.settings));value=engine.execute(job.job_id)
    assert value['state']==jobs.get(job.job_id).state=='waiting_reboot'
    assert len(calls)==1 and len(done)==1
    assert value['workflow']['phase']=='user'
    from alt_deploy.setup_phases import WorkflowPhaseStore
    records=WorkflowPhaseStore(setup.settings).records(jobs.get(job.job_id))
    assert records['system']['result']['result']['computer']==computer
    assert records['user']['ticket'] is None and records['final_dns']['ticket'] is None


@pytest.mark.parametrize('phase',['user','final_dns'])
def test_later_phase_dispatches_once_under_original_claim_without_any_setup_adapter(phase_job,phase):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    protected=[];calls=[]
    setup._execute_locked=lambda *a,**k:protected.append('JOIN') or pytest.fail('Protected adapter was called')
    setup.planner.start=lambda *a,**k:pytest.fail('ConfigurePlanner was called')
    def run(j,p,claim):
        calls.append((j.job_id,p,claim['claim_sha256'] if 'claim_sha256' in claim else claim['ticket_sha256']))
        return phase_result()
    engine=SetupExecutionEngine(setup.settings,jobs=jobs,setup=setup,phase_executor=SimpleNamespace(run=run))
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        if phase=='final_dns':
            store.complete(jobs.get(job.job_id),'user',phase_result())
            ready=dict(ready,phase='final_dns');store.readiness=lambda j,p:copy.deepcopy(ready)
            store.enqueue(jobs.get(job.job_id),phase,ready);store.claim(jobs.get(job.job_id),phase,identity)
        engine.execute_phase(job.job_id,phase)
        with pytest.raises(ControlError):engine.execute_phase(job.job_id,phase)
    assert len(calls)==1 and calls[0][0]==job.job_id and protected==[]
    assert store.records(jobs.get(job.job_id))[phase]['result'] is not None


def test_workflow_manual_continuation_is_read_only_and_cannot_mark_unfinished_phases_successful(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    engine=SetupExecutionEngine(setup.settings,jobs=jobs,setup=setup)
    before={p:p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}
    engine._post=lambda j:pytest.fail('Legacy full verification must not finish pending phases')
    result=engine.verify_continuation(job.job_id)
    assert result['state']=='waiting_first_login'
    assert all(p.read_bytes()==raw for p,raw in before.items())
    assert store.records(jobs.get(job.job_id))['user']['claim'] is None


@pytest.mark.parametrize('code,expected',[('workflow_package_manager_busy','workflow_package_manager_busy'),
    ('workflow_phase_timeout','workflow_phase_timeout'),('unrecognized_private_code','workflow_phase_outcome_unverified')])
def test_lost_or_failed_phase_reply_burns_claim_once_without_private_output(phase_job,code,expected):
    store,jobs,job,ready,identity,admissions,setup=phase_job;calls=[]
    def failed(*args):
        calls.append(True);raise ControlError(code,'PRIVATE-SENTINEL',7)
    engine=SetupExecutionEngine(setup.settings,jobs=jobs,setup=setup,phase_executor=SimpleNamespace(run=failed))
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        result=engine.execute_phase(job.job_id,'user')
        with pytest.raises(ControlError):engine.execute_phase(job.job_id,'user')
    assert len(calls)==1 and jobs.get(job.job_id).state=='unknown_requires_review'
    assert result['error_code']==expected
    assert 'SENTINEL' not in str(result)


@pytest.mark.parametrize('fault',['none','changed_after_claim','bad_result','missing_events','changed_after_apply'])
def test_fixed_final_dns_executor_rechecks_readiness_and_requires_exact_completion(phase_job,monkeypatch,fault):
    from alt_deploy.setup_phase_execution import WorkflowPhaseExecutor
    from alt_deploy.setup_events import SetupEventStore
    from alt_deploy.setup_plans import private_create
    store,jobs,job,ready,identity,admissions,setup=phase_job
    setup.settings.ansible_playbook_path=Path('/usr/bin/ansible-playbook')
    calls=[];observations=[]
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        store.complete(jobs.get(job.job_id),'user',phase_result())
        ready['phase']='final_dns'
        store.enqueue(jobs.get(job.job_id),'final_dns',ready);claim=store.claim(jobs.get(job.job_id),'final_dns',identity)
        job=store.start(jobs.get(job.job_id),'final_dns',claim)
        def prepare(j,p):
            current=copy.deepcopy(ready);observations.append(p)
            if fault=='changed_after_claim':current['observation']['dns_sha256']='0'*64
            if fault=='changed_after_apply' and len(observations)>1:current['scope']['computer_sid']+='-1'
            return current,{'dns':{'status':'ok','observation':{}},
                'verification':{'components':{c['id']:{'status':'compliant'} for c in j.request['plan']['payload']['components']}}}
        def run(settings,j,p,c,command,**options):
            calls.append(command);variables=private_read(j.job_dir/'phase-final_dns-vars.json')
            assert command[-1].endswith('/playbooks/05-setup-workflow-phase.yml')
            assert options['timeout']==300 and variables['alt_setup_workflow_context']['phase']=='final_dns'
            context=copy.deepcopy(variables['alt_setup_workflow_context'])
            if fault=='bad_result':context['claim_sha256']='0'*64
            private_create(Path(variables['setup_phase_result_file']),{'schema_version':1,'context':context,
                'status':'applied_verified','code':'final_dns_applied'})
            if fault!='missing_events':SetupEventStore(settings).append(j.job_id,{'schema_version':1,
                'component_id':'network.final_dns','component_version':1,'stage':'complete','task_id':'component',
                'type':'component_completed','code':'completed','changed':False})
            return 0
        probe=SimpleNamespace(prepare=prepare,setup=setup)
        monkeypatch.setattr('alt_deploy.krfb_runtime.probe_krfb',lambda *a,**k:{'ready':True})
        executor=WorkflowPhaseExecutor(setup.settings,readiness=probe,runner=run)
        if fault=='none':assert executor.run(job,'final_dns',claim)['status']=='applied_verified'
        else:
            with pytest.raises(ControlError):executor.run(job,'final_dns',claim)
        assert len(calls)==(0 if fault=='changed_after_claim' else 1)


@pytest.mark.parametrize('outcome',['success','rollback','no_gui'])
def test_final_success_requires_all_three_original_results_and_fresh_proof(phase_job,monkeypatch,outcome):
    from alt_deploy.component_verification import VerificationEngine
    store,jobs,job,ready,identity,admissions,setup=phase_job
    verification=VerificationEngine(setup.catalog).evaluate(setup.component_probe.observe(),
        [c['id'] for c in job.request['plan']['payload']['components']])
    def prepare(j,p):
        if outcome=='no_gui':raise ControlError('graphical_session_unavailable','Waiting',7)
        return copy.deepcopy(ready),{'verification':verification}
    engine=SetupExecutionEngine(setup.settings,jobs=jobs,setup=setup,
        workflow_probe=SimpleNamespace(prepare=prepare))
    monkeypatch.setattr('alt_deploy.krfb_runtime.probe_krfb',lambda *a,**k:{'ready':True})
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        store.complete(jobs.get(job.job_id),'user',phase_result())
        ready['phase']='final_dns'
        store.enqueue(jobs.get(job.job_id),'final_dns',ready);store.claim(jobs.get(job.job_id),'final_dns',identity)
        end=phase_result(status='rolled_back_verified',code='final_dns_rolled_back') if outcome=='rollback' else phase_result()
        store.complete(jobs.get(job.job_id),'final_dns',end)
        result=engine.finalize_workflow(job.job_id)
        if outcome=='no_gui':
            before={p:p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}
            engine.finalize_workflow(job.job_id)
            assert all(p.read_bytes()==raw for p,raw in before.items())
    expected={'success':'successful','rollback':'degraded','no_gui':'waiting_first_login'}[outcome]
    assert result['state']==jobs.get(job.job_id).state==expected
    if outcome=='no_gui':assert result['workflow']['waiting_reason']=='workflow_final_verification_unavailable'
