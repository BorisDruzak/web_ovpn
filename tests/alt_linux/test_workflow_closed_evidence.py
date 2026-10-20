"""A late UNKNOWN retains the successful domain run and consumed phase."""
import copy

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.locks import exclusive_lock
from alt_deploy.setup_jobs import publish
from alt_deploy.setup_plans import private_create,private_read
from alt_deploy.full_workflow import deferred_system_result
from alt_deploy_backup.setup_phase_admission import PhaseAdmissionReview
from test_setup_phases import phase_job,phase_result
from test_full_workflow_binding import full_setup
from test_component_catalog import project


@pytest.fixture
def closed_workflow(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    root=setup.settings.state_root;payload=job.request['plan']['payload'];run_id='setup-run-'+'a'*32;configure_id='b'*32
    result={'schema_version':1,'machine_uuid':job.machine_uuid,'hostname':payload['machine']['hostname'],
        'profile':payload['request']['profile'],'status':'successful','phase':'finalize','retryable':False,
        'recovered':False,'reboot_required':False,'error':None,
        'components':{'workflow_deferred':deferred_system_result(payload['workflow'])},'verification':{'group_policy':True}}
    computer=store.records(job)['system']['result']['result']['computer']
    run={'schema_version':1,'run_id':run_id,'plan_id':job.status['plan_id'],'plan_sha256':job.status['plan_sha256'],
        'machine_uuid':job.machine_uuid,'status':'successful','created_at':setup.clock().isoformat(),
        'finished_at':setup.clock().isoformat(),'configuration_run_id':configure_id,'result':dict(result,run_id=configure_id),
        'computer':{'hostname':payload['machine']['hostname'],'exists':True,'objects':[computer]},'reboot_required':False}
    private_create(root/'configure-runs'/configure_id/'request.json',payload['request'])
    private_create(root/'configure-runs'/configure_id/'result.json',result)
    private_create(root/'setup-runs'/(run_id+'.json'),run)
    private_create(root/'setup-plan-runs'/(job.status['plan_id']+'.json'),{'run_id':run_id})
    private_create(root/'domain-assignments'/(job.machine_uuid+'.json'),dict(payload['binding'],schema_version=1,
        revision=(payload.get('existing_assignment') or {}).get('revision',0)+1,run_id=run_id,date=run['created_at'],result='successful'))
    for index,(operation,identifier) in enumerate((('full_setup',run_id),('configure',configure_id))):
        nonce=str(index+1)*32
        private_create(root/'legacy-setup-reservations'/(nonce+'.json'),{'schema_version':1,'operation':operation,
            'reservation_id':nonce,'machine_uuid':job.machine_uuid,'hostname':payload['machine']['hostname'],
            'state':'completed','run_id':identifier,'supersedes':[]})
    execution=private_read(job.job_dir/'execution.json');execution['legacy_run']=run;publish(job.job_dir/'execution.json',execution)
    store.admission=PhaseAdmissionReview(setup.settings,clock=setup.clock,readiness=store.readiness).admit_phase_candidate
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);claim=store.claim(jobs.get(job.job_id),'user',identity)
        store.complete(jobs.get(job.job_id),'user',phase_result(status='outcome_unverified',changed=None,
            code='workflow_phase_timeout',verification_sha256=None,target_processes_absent=False))
    return store,jobs,jobs.get(job.job_id),setup,run,claim


def test_closed_late_phase_does_not_relabel_the_successful_domain_run(closed_workflow):
    from alt_deploy_backup.setup_workflow_closed import ClosedWorkflowEvidence
    store,jobs,job,setup,run,claim=closed_workflow
    before={p:p.read_bytes() for p in setup.settings.state_root.rglob('*') if p.is_file()}
    value=ClosedWorkflowEvidence(setup.settings).load(job.job_id)
    assert value['kind']=='closed_workflow_phase' and value['legacy_run_id']==run['run_id']
    assert value['lease_ids']==[] and value['phase']=='user'
    assert store.records(job)['user']['claim']==claim and job.state=='unknown_requires_review'
    assert private_read(setup.settings.state_root/'setup-runs'/(run['run_id']+'.json'))['status']=='successful'
    assert all(p.read_bytes()==data for p,data in before.items())


@pytest.mark.parametrize('fault',['initial_result','binding','computer','lease','phase_record'])
def test_closed_late_phase_requires_intact_original_success_and_phase_authority(closed_workflow,fault):
    from alt_deploy_backup.setup_workflow_closed import ClosedWorkflowEvidence
    store,jobs,job,setup,run,claim=closed_workflow;root=setup.settings.state_root
    if fault=='phase_record':(root/'setup-phase-claims'/(job.job_id+'--user.json')).unlink()
    else:
        path={'initial_result':root/'configure-runs'/('b'*32)/'result.json',
              'binding':root/'domain-assignments'/(job.machine_uuid+'.json'),
              'computer':root/'setup-runs'/(run['run_id']+'.json'),
              'lease':root/'legacy-setup-reservations'/('1'*32+'.json')}[fault]
        value=private_read(path)
        if fault=='initial_result':value['status']='failed'
        elif fault=='binding':value['object_guid']='0'*36
        elif fault=='computer':value['computer']['objects'][0]['object_guid']='0'*36
        else:value['state']='running'
        publish(path,value)
    with pytest.raises(ControlError):ClosedWorkflowEvidence(setup.settings).load(job.job_id)
