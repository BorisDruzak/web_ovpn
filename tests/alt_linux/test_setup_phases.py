"""Immutable phase authority retains the initial job, claim and historical bytes."""
import copy
import hashlib
import json
import os
import multiprocessing
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.setup_jobs import SetupJobRepository
from alt_deploy.setup_plans import digest,private_create,private_read
from alt_deploy.setup_worker import process_identity
from test_component_catalog import project
from test_full_workflow_binding import full_setup
from test_setup_service import UUID,OU


def system_result():
    return {'status':'applied_verified','changed':True,'code':None,'verification_sha256':'4'*64,
        'target_processes_absent':True,'original_boot_id':'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee','reboot_required':False,
        'computer':{'object_guid':'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa','object_sid':'S-1-5-21-1-2-3-2001',
                    'dn':'CN=alt-a1-pc3,'+OU,'dns_hostname':'alt-a1-pc3.sosnadmin.local'}}


def phase_result(**changes):
    return dict({'status':'applied_verified','changed':True,'code':None,'verification_sha256':'5'*64,
                 'target_processes_absent':True},**changes)


@pytest.fixture
def phase_job(full_setup):
    from alt_deploy.setup_phases import WorkflowPhaseStore
    setup,machine,user,state,policy,options,calls,admission=full_setup
    plan=setup.plan(UUID,user['login'],OU,'workstation-full-v1','krfb')
    jobs=SetupJobRepository(setup.settings,clock=setup.clock);job=jobs.submit(plan,operation='full_setup')
    identity=process_identity(setup.settings)
    ready={'schema_version':1,'status':'ready','job_id':job.job_id,'phase':'user',
        'source_sha256':plan['payload']['source_sha256'],'catalog_sha256':plan['payload']['catalog_sha256'],
        'workflow_policy_sha256':plan['payload']['workflow']['policy_sha256'],
        'scope':{'machine_uuid':UUID,'hostname':machine.hostname,'ip':machine.ip,
            'registration_sha256':plan['payload']['machine']['registration_sha256'],'ssh_binding':plan['payload']['ssh_binding'],
            'login':user['login'],'upn':user['upn'],'user_guid':user['object_guid'],'user_sid':user['object_sid'],
            'uid':10001,'gid':10001,'home_sha256':'3'*64,'computer_guid':system_result()['computer']['object_guid'],
            'computer_sid':system_result()['computer']['object_sid'],'ou_guid':plan['payload']['ou_identity']['object_guid'],
            'ou_dn':OU,'connection_uuid':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','interface':'eth0','backend':'nm_etcnet'},
        'observation':{'boot_id':'cccccccc-cccc-dddd-eeee-ffffffffffff','session_sha256':'1'*64,
            'wallet_sha256':'2'*64,'krfb_sha256':'3'*64,'dns_sha256':'4'*64,'certificates_sha256':'5'*64,
            'package_health_sha256':'6'*64,'helpers':{k:'7'*64 for k in ('wallet','krfb','dns','vnc_policy','certificates')}}}
    admissions=[]
    def admit(job_id,phase,ticket_sha256):
        admissions.append((job_id,phase,ticket_sha256))
        return {'schema_version':1,'job_id':job_id,'phase':phase,'ticket_sha256':ticket_sha256,
                'review_sha256':'a'*64,'excluded_job_ids':[],'excluded_lease_ids':[],
                'readiness':dict(copy.deepcopy(ready),phase=phase)}
    store=WorkflowPhaseStore(setup.settings,clock=setup.clock,readiness=lambda job,phase:dict(copy.deepcopy(ready),phase=phase),admission=admit)
    with exclusive_lock(setup.settings.lock_file):
        job=jobs.claim(job.job_id,identity);jobs.transition(job.job_id,'running',stage={'id':'full_setup.apply'})
        # The real engine creates this initial compatible result before phase
        # publication. It is local fixture state, never an executed target.
        private_create(job.job_dir/'execution.json',{'schema_version':2,'operation':'setup_execution','job_id':job.job_id,
            'machine_uuid':UUID,'plan_id':plan['plan_id'],'plan_sha256':plan['sha256'],
            'components':{c['id']:{'version':c['version'],'changed':False,'verification':None} for c in plan['payload']['components']},
            'original_boot_id':system_result()['original_boot_id'],'reboot_required':False,'operator_action_required':True,
            'error_code':None,'created_at':setup.clock().isoformat(),'finished_at':None,'state':'running','stage':'full_setup.apply'})
        store.complete(jobs.get(job.job_id),'system',system_result())
    return store,jobs,jobs.get(job.job_id),ready,identity,admissions,setup


def historical_bytes(jobs,job):
    return {p:p.read_bytes() for p in (job.job_dir/'request.json',jobs.claims/(job.status['plan_sha256']+'.json'),
                                     jobs.reservations/(job.job_id+'.json'))}


def test_exclusive_phase_claim_preserves_original_authority_and_never_replays(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job;before=historical_bytes(jobs,job)
    assert job.state=='waiting_first_login'
    with exclusive_lock(setup.settings.lock_file):
        ticket=store.enqueue(job,'user',ready)
        assert ticket['admission_sequence']>job.status['admission_sequence']
        claim=store.claim(jobs.get(job.job_id),'user',identity)
        assert claim['ticket_sha256']==digest(ticket) and claim['readiness_sha256']==digest(ready)
        assert jobs.get(job.job_id).status['process_identity']==identity
        for _ in range(2):
            with pytest.raises(ControlError):store.claim(jobs.get(job.job_id),'user',identity)
        result=store.complete(jobs.get(job.job_id),'user',phase_result())
        assert result['claim_sha256']==digest(claim)
        assert store.records(jobs.get(job.job_id))['user']['result']==result
        assert jobs.get(job.job_id).state=='waiting_first_login'
        with pytest.raises(ControlError):store.enqueue(jobs.get(job.job_id),'user',ready)
    assert len(admissions)==1 and historical_bytes(jobs,job)==before


def test_original_flock_is_required_for_all_phase_mutations(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    for operation in (lambda:store.enqueue(job,'user',ready),lambda:store.claim(job,'user',identity),
                      lambda:store.complete(job,'user',phase_result())):
        with pytest.raises(ControlError):operation()
    assert jobs.get(job.job_id).state=='waiting_first_login'


@pytest.mark.parametrize('fault',['machine','employee','computer','ssh','source','catalog','policy','connection','waiting','private'])
def test_fresh_claim_cannot_retarget_ticket_or_dispatch_unready_state(phase_job,fault):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        ticket=store.enqueue(job,'user',ready)
        if fault=='machine':ready['scope']['machine_uuid']='99999999-2222-3333-4444-555555555555'
        elif fault=='employee':ready['scope']['user_guid']='99999999-2222-3333-4444-555555555555'
        elif fault=='computer':ready['scope']['computer_guid']='99999999-2222-3333-4444-555555555555'
        elif fault=='ssh':ready['scope']['ssh_binding']['host_public_sha256']='0'*64
        elif fault in ('source','catalog'):ready[fault+'_sha256']='0'*64
        elif fault=='policy':ready['workflow_policy_sha256']='0'*64
        elif fault=='connection':ready['scope']['connection_uuid']='99999999-2222-3333-4444-555555555555'
        elif fault=='waiting':ready['status']='waiting'
        else:ready['environment']='PRIVATE-SECRET-SENTINEL'
        with pytest.raises(ControlError) as caught:store.claim(jobs.get(job.job_id),'user',identity)
        assert 'SENTINEL' not in str(caught.value)
        assert store.records(jobs.get(job.job_id))['user']['claim'] is None
        assert store.records(jobs.get(job.job_id))['user']['ticket']==ticket
    assert admissions==[]


def test_new_genuine_session_before_claim_gets_a_fresh_digest_without_rewriting_ticket(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        ticket=store.enqueue(job,'user',ready);original=copy.deepcopy(ticket)
        ready['observation']['session_sha256']='8'*64
        claim=store.claim(jobs.get(job.job_id),'user',identity)
        assert claim['readiness_sha256']==digest(ready) and claim['readiness_sha256']!=ticket['readiness_sha256']
        assert store.records(jobs.get(job.job_id))['user']['ticket']==original


def test_final_dns_requires_the_original_verified_user_phase(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        with pytest.raises(ControlError):store.enqueue(job,'final_dns',dict(ready,phase='final_dns'))
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        store.complete(jobs.get(job.job_id),'user',phase_result())
        ticket=store.enqueue(jobs.get(job.job_id),'final_dns',dict(ready,phase='final_dns'))
        assert ticket['component_ids']==['network.final_dns'] and ticket['budget_seconds']==300


def test_result_and_state_publication_gap_consumes_phase_and_preserves_uncertainty(phase_job,monkeypatch):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        original=store._publish_status
        monkeypatch.setattr(store,'_publish_status',lambda *a,**k:(_ for _ in ()).throw(OSError('PRIVATE-SECRET-SENTINEL')))
        with pytest.raises(ControlError):store.complete(jobs.get(job.job_id),'user',phase_result())
        monkeypatch.setattr(store,'_publish_status',original)
        store.reconcile(jobs.get(job.job_id))
        assert jobs.get(job.job_id).state=='unknown_requires_review'
        assert store.records(jobs.get(job.job_id))['user']['result']['result']['status']=='applied_verified'
        with pytest.raises(ControlError):store.claim(jobs.get(job.job_id),'user',identity)


@pytest.mark.parametrize('field',['ticket_sha256','claim_sha256','result_sha256'])
def test_changed_retained_reference_is_corruption_not_a_recoverable_gap(phase_job,field):
    from alt_deploy.setup_jobs import publish
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
        store.complete(jobs.get(job.job_id),'user',phase_result())
        job=jobs.get(job.job_id);status=copy.deepcopy(job.status)
        status['workflow']['phases']['user'][field]='0'*64
        publish(job.job_dir/'status.json',status)
        with pytest.raises(ControlError):store.records(jobs.get(job.job_id))


@pytest.mark.parametrize('kind',['ticket','claim'])
def test_interrupted_publication_is_consumed_without_dispatch(phase_job,monkeypatch,kind):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        if kind=='claim':store.enqueue(job,'user',ready)
        original=store._publish_status
        monkeypatch.setattr(store,'_publish_status',lambda *a,**k:(_ for _ in ()).throw(OSError('interrupted')))
        with pytest.raises(ControlError):
            if kind=='ticket':store.enqueue(jobs.get(job.job_id),'user',ready)
            else:store.claim(jobs.get(job.job_id),'user',identity)
        monkeypatch.setattr(store,'_publish_status',original)
        store.reconcile(jobs.get(job.job_id))
        job=jobs.get(job.job_id)
        assert job.state=='unknown_requires_review'
        assert store.records(job)['user'][kind] is not None
        with pytest.raises(ControlError):store.enqueue(job,'user',ready)
        with pytest.raises(ControlError):store.claim(job,'user',identity)


@pytest.mark.parametrize('patch',[{'status':'applied_verified','code':'workflow_phase_timeout'},
    {'status':'outcome_unverified','code':None},{'status':'rolled_back_verified','code':None}])
def test_phase_result_cannot_claim_success_and_failure_simultaneously(phase_job,patch):
    from alt_deploy.setup_phases import validate_result
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with pytest.raises(ControlError):validate_result(job,'final_dns',phase_result(**patch))


def test_legacy_verification_cannot_finish_a_workflow_with_unexecuted_phases(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        with pytest.raises(ControlError):jobs.transition(job.job_id,'verifying',stage={'id':'verify'})
    assert jobs.get(job.job_id).state=='waiting_first_login'


def test_phase_tickets_and_initial_jobs_share_fifo_but_unready_sessions_do_not_block(phase_job):
    from alt_deploy.setup_phases import eligible_candidates
    store,jobs,job,ready,identity,admissions,setup=phase_job
    payload=copy.deepcopy(job.request['plan']['payload'])
    payload['machine'].update(uuid='99999999-2222-3333-4444-555555555555',hostname='alt-other')
    with exclusive_lock(setup.settings.lock_file):
        user_ticket=store.enqueue(job,'user',ready)
        other=jobs.submit(setup.plans.create(payload),operation='full_setup')
        assert other.status['admission_sequence']==user_ticket['admission_sequence']+1
        candidates=eligible_candidates(setup.settings,readiness=lambda j,p:copy.deepcopy(ready))
        assert [(v[1],v[2]) for v in candidates]==[(job.job_id,'user'),(other.job_id,None)]
        def absent(j,p):raise ControlError('graphical_session_unavailable','Waiting',7)
        assert [(v[1],v[2]) for v in eligible_candidates(setup.settings,readiness=absent)]==[(other.job_id,None)]
        ready['observation']['session_sha256']='9'*64
        # A fresh genuine session may change mechanically before the claim.
        assert eligible_candidates(setup.settings,readiness=lambda j,p:copy.deepcopy(ready))[0][1]==job.job_id


def test_live_worker_without_the_previous_critical_section_cannot_resume_consumed_phase(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
    with exclusive_lock(setup.settings.lock_file):
        assert store.reconcile(jobs.get(job.job_id))['uncertain'] is True
        assert jobs.get(job.job_id).state=='unknown_requires_review'
        with pytest.raises(ControlError):store.claim(jobs.get(job.job_id),'user',identity)


def test_two_real_workers_can_publish_only_one_phase_claim(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):store.enqueue(job,'user',ready)
    context=multiprocessing.get_context('fork');results=context.Queue()
    def claimant():
        try:
            with exclusive_lock(setup.settings.lock_file):
                store.claim(jobs.get(job.job_id),'user',process_identity(setup.settings))
            results.put('claimed')
        except ControlError:results.put('consumed')
    processes=[context.Process(target=claimant) for _ in range(2)]
    for process in processes:process.start()
    for process in processes:process.join(15);assert process.exitcode==0
    assert sorted(results.get(timeout=2) for _ in processes)==['claimed','consumed']
    current=jobs.get(job.job_id)
    assert store.records(current)['user']['claim'] is not None
    assert current.status['process_identity']==identity


def test_only_intact_idle_workflows_can_yield_the_mutator_to_another_pc(phase_job):
    from alt_deploy.setup_phases import idle_workflow,effective_identity
    store,jobs,job,ready,identity,admissions,setup=phase_job
    assert idle_workflow(setup.settings,job) is True
    assert effective_identity(setup.settings,job)['computer_guid']==system_result()['computer']['object_guid']
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready)
        assert idle_workflow(setup.settings,jobs.get(job.job_id)) is True
        store.claim(jobs.get(job.job_id),'user',identity)
        assert idle_workflow(setup.settings,jobs.get(job.job_id)) is False
        store.complete(jobs.get(job.job_id),'user',phase_result())
        assert idle_workflow(setup.settings,jobs.get(job.job_id)) is True


def test_new_ad_computer_guid_remains_reserved_without_rewriting_original_claim(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    before=historical_bytes(jobs,job)
    payload=copy.deepcopy(job.request['plan']['payload'])
    payload['machine'].update(uuid='99999999-2222-3333-4444-555555555555',hostname='alt-other')
    payload['computer'].update(exists=True,objects=[system_result()['computer']])
    plan=setup.plans.create(payload)
    with pytest.raises(ControlError) as caught:jobs.submit(plan,operation='full_setup')
    assert caught.value.code=='setup_job_identity_reserved'
    assert historical_bytes(jobs,job)==before


def test_published_system_result_is_bound_before_any_user_ticket(phase_job):
    from alt_deploy.setup_jobs import publish
    store,jobs,job,*_=phase_job
    path=store._path('result',job,'system');value=private_read(path)
    value['result']['verification_sha256']='0'*64
    publish(path,value)
    with pytest.raises(ControlError):store.records(jobs.get(job.job_id))


def test_claim_uses_the_last_native_readiness_not_the_earlier_queue_probe(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    original=store.admission
    def native(job_id,phase,ticket_sha):
        value=original(job_id,phase,ticket_sha)
        ready['observation']['session_sha256']='9'*64
        return dict(value,readiness=dict(copy.deepcopy(ready),phase=phase))
    store.admission=native
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready)
        claim=store.claim(jobs.get(job.job_id),'user',identity)
    assert claim['readiness_sha256']==digest(ready)
    assert 'readiness' not in claim['admission']
