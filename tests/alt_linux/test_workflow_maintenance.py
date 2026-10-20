"""Fresh controller-only coverage includes late phases without replay authority."""
import copy
from datetime import timedelta

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_read
from alt_deploy_backup.setup_compat import history_fingerprint
from test_workflow_closed_evidence import closed_workflow
from test_setup_phases import phase_job
from test_full_workflow_binding import full_setup
from test_component_catalog import project


@pytest.fixture
def workflow_maintenance(closed_workflow):
    from alt_deploy_backup.setup_workflow_maintenance import WorkflowMaintenanceCoverage
    store,jobs,job,setup,run,claim=closed_workflow
    original=job.request['plan']['payload'];ready=claim['readiness']
    facts={'machine':original['machine'],'user':original['user'],'ou_identity':original['ou_identity'],
        'computer':run['computer'],'observed':dict(original['observed'],uuid=job.machine_uuid,
            hostname=original['machine']['hostname'],domain='sosnadmin.local',trust=True,sssd=True,user_lookup=True,local_duplicate=False,
            computer_identity=dict(run['computer']['objects'][0],sam_account_name=original['machine']['hostname']+'$')),
        'ssh_binding':original['ssh_binding'],
        'package_manager':{k:True for k in ('processes_absent','remote_execution_absent','locks_clear','database_readable','dependencies_healthy')},
        'boot_id':ready['observation']['boot_id'],'user_runtime':{'login':original['user']['login'],
            'uid':ready['scope']['uid'],'gid':ready['scope']['gid'],'home_exists':True,'home_safe':True}}
    quiet={'schema_version':1,'machine_uuid':job.machine_uuid,'hostname':original['machine']['hostname'],
           'boot_id':facts['boot_id'],'quiet':True}
    date=[setup.clock()]
    review=WorkflowMaintenanceCoverage(setup.settings,clock=lambda:date[0],observer=lambda j:copy.deepcopy(facts),
        quiet=lambda j:copy.deepcopy(quiet))
    return review,store,jobs,job,setup,facts,quiet,date


def test_late_phase_maintenance_preserves_unknown_and_completed_domain_history(workflow_maintenance):
    review,store,jobs,job,setup,facts,quiet,date=workflow_maintenance
    before={k:v for k,v in history_fingerprint(setup.settings.state_root).items() if not k.startswith('setup-maintenance-')}
    plan=review.plan();assert plan['schema_version']==3
    receipt=review.confirm(plan['plan_id'],plan['sha256'])
    assert receipt['purpose']=='controller_maintenance_only'
    assert review.exclusions(plan['sha256'])=={'job_ids':{job.job_id},'lease_ids':set()}
    after={k:v for k,v in history_fingerprint(setup.settings.state_root).items() if not k.startswith('setup-maintenance-')}
    assert before==after and jobs.get(job.job_id).state=='unknown_requires_review'
    assert store.records(job)['user']['result']['result']['status']=='outcome_unverified'


@pytest.mark.parametrize('fault',['live_target','changed_computer','changed_history','expired'])
def test_maintenance_requires_fresh_identity_quiet_processes_and_original_ttl(workflow_maintenance,fault):
    review,store,jobs,job,setup,facts,quiet,date=workflow_maintenance
    plan=review.plan()
    if fault=='live_target':quiet['quiet']=False
    elif fault=='changed_computer':facts['computer']['objects'][0]['object_guid']='99999999-2222-3333-4444-555555555555'
    elif fault=='expired':date[0]+=timedelta(minutes=31)
    else:
        path=job.job_dir/'execution.json';path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ControlError):review.confirm(plan['plan_id'],plan['sha256'])


def test_existing_native_entrypoint_dispatches_schema_three_without_extending_its_ttl(workflow_maintenance,monkeypatch):
    from alt_deploy_backup.setup_maintenance_review import MaintenanceReview
    from alt_deploy_backup.setup_workflow_closed import ClosedWorkflowEvidence
    from alt_deploy_backup.setup_compat import validate_ledger
    review,store,jobs,job,setup,facts,quiet,date=workflow_maintenance
    plan=review.plan()
    monkeypatch.setattr('alt_deploy_backup.setup_maintenance_coverage.native_observe',lambda *a,**k:copy.deepcopy(facts))
    monkeypatch.setattr(ClosedWorkflowEvidence,'quiet',lambda self,j:copy.deepcopy(quiet))
    native=MaintenanceReview(setup.settings,clock=lambda:date[0])
    receipt=native.confirm(plan['plan_id'],plan['sha256'])
    assert receipt['schema_version']==3
    assert native.exclusions(plan['sha256'])=={'job_ids':{job.job_id},'lease_ids':set()}
    validate_ledger(setup.settings.state_root)
    date[0]+=timedelta(hours=7)
    with pytest.raises(ControlError):native.exclusions(plan['sha256'])


def test_retained_v2_validator_names_survive_additive_native_code_shipping():
    from alt_deploy_backup.setup_compat import MAINTENANCE_V2_MODULES,MAINTENANCE_MODULES,valid_validator_catalog
    old={key:'1'*64 for key in MAINTENANCE_V2_MODULES}
    assert valid_validator_catalog(old)
    assert valid_validator_catalog({key:'2'*64 for key in MAINTENANCE_MODULES})
    assert not valid_validator_catalog(dict(old,untrusted_python_module='3'*64))
    old.pop(next(iter(old)))
    assert not valid_validator_catalog(old)


def test_late_phase_maintenance_plan_accepts_large_retained_history(workflow_maintenance, monkeypatch):
    from alt_deploy.setup_plans import digest
    import alt_deploy_backup.setup_maintenance_coverage as module
    history = {f'jobs/retained-job/events/{index:08d}.json': digest({'index': index})
               for index in range(5000)}
    monkeypatch.setattr(module, 'history_fingerprint', lambda _: dict(history))
    review = workflow_maintenance[0]
    plan = review.plan()
    assert (review.plans/(plan['plan_id']+'.json')).stat().st_size <= review.io.MAX_STATE_BYTES
    review.confirm(plan['plan_id'], plan['sha256'])
    history[next(iter(history))] = 'e'*64
    with pytest.raises(ControlError): review.exclusions(plan['sha256'])
