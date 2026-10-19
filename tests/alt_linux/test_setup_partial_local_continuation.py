"""Only a successful local recovery can offer one ordinary fresh Setup."""
import copy
from datetime import timedelta

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import SetupJobRepository
from alt_deploy.setup_plans import private_read
from test_setup_partial_local_state import control
from test_setup_partial_local import service_for
from test_setup_closed_failure import partial_failure, retained
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_maintenance_coverage import mixed, stopped


def recovered(partial_failure):
    service, runtime, calls, native = service_for(partial_failure)
    plan = service.plan(partial_failure[1].job_id)
    result = service.apply(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'successful'
    return service, runtime, plan, result, native, calls


def continuation(partial_failure):
    service, runtime, recovery, result, native, calls = recovered(partial_failure)
    setup = partial_failure[0]
    module = control('setup_partial_local_continuation')
    follow = module.PartialLocalContinuation(setup.settings, setup=setup, runtime=runtime, clock=setup.clock)
    return follow, recovery, result, service, calls


def test_successful_local_recovery_offers_new_plan_without_join(partial_failure):
    follow, recovery, result, service, calls = continuation(partial_failure)
    setup, old, *_ = partial_failure
    before = retained(setup.settings.state_root)
    plan = follow.plan(recovery['plan_id'])
    assert len(calls) == 1
    assert plan['payload']['partial_local_resolution']['recovery_plan_id'] == recovery['plan_id']
    assert plan['payload']['predecessor_job']['job_id'] == old.job_id
    assert plan['payload']['profile']['id'] == 'office-standard-v1'
    assert plan['payload']['existing_assignment']['result'] == 'failed'
    for name, raw in before.items(): assert (setup.settings.state_root/name).read_bytes() == raw


def test_only_one_successor_consumes_partial_resolution(partial_failure):
    follow, recovery, result, service, calls = continuation(partial_failure)
    setup, old, *_, date = partial_failure
    plan = follow.plan(recovery['plan_id'])
    submitted = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    date[0] += timedelta(seconds=1)
    second = follow.plan(recovery['plan_id'])
    with pytest.raises(ControlError): setup.apply(second['plan_id'], second['sha256'], detach=True)
    jobs = SetupJobRepository(setup.settings).list()
    assert len(jobs) == 2 and submitted['job_id'] != old.job_id
    assert SetupJobRepository(setup.settings).get(old.job_id).state == 'unknown_requires_review'
    assert len(calls) == 1


def test_archival_resolution_survives_assignment_revision(partial_failure):
    from alt_deploy.setup_plans import private_replace
    follow, recovery, result, service, calls = continuation(partial_failure)
    setup, old, machine, *_ = partial_failure
    plan = follow.plan(recovery['plan_id'])
    proof = plan['payload']['partial_local_resolution']
    path = setup.settings.state_root/'domain-assignments'/(machine.uuid+'.json')
    binding = private_read(path)
    private_replace(path, dict(binding, revision=2, result='successful', run_id='setup-run-'+'e'*32))
    module = control('setup_partial_local_continuation')
    archived = module.load_resolution(setup.settings, proof, archival=True)
    assert archived['closed']['binding'] == binding
    assert archived['result'] == result
    assert service.store.load_closed(proof['history_sha256'])['binding'] == binding


@pytest.mark.parametrize('other', ['prejoin_retry', 'recovery_resolution'])
def test_partial_proof_cannot_be_combined_with_another_continuation(partial_failure, other):
    from alt_deploy.setup_jobs import validate_plan
    follow, recovery, result, service, calls = continuation(partial_failure)
    plan = follow.plan(recovery['plan_id'])
    payload = copy.deepcopy(plan['payload']); payload[other] = {'synthetic': True}
    changed = partial_failure[0].plans.create(payload)
    with pytest.raises((ControlError, ValueError)): validate_plan(changed, 'full_setup')


def dispatch_followup(partial_failure, *, fail=False):
    from alt_deploy.setup_jobs import legacy_setup_execution
    from alt_deploy.setup_plans import private_create
    from alt_deploy.setup_execution import SetupExecutionEngine
    from alt_deploy.setup_worker import SetupWorker
    follow, recovery, result, service, calls = continuation(partial_failure)
    setup, old, machine, user, state, current, date = partial_failure
    plan = follow.plan(recovery['plan_id'])
    before = retained(old.job_dir)
    submitted = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    computer = {'object_guid': 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa', 'object_sid': 'S-1-5-21-1-2-3-2001',
                'dn': 'CN='+machine.hostname+','+plan['payload']['computer_ou'], 'dns_hostname': machine.hostname+'.sosnadmin.local'}
    def configure(identifier, request, **kwargs):
        config_id = 'e'*32
        with legacy_setup_execution(setup.settings, machine.uuid, machine.hostname, operation='configure', run_id=config_id):
            private_create(setup.settings.state_root/'configure-runs'/config_id/'request.json', request.to_dict())
            current.update(domain='sosnadmin.local', trust=not fail, sssd=not fail, user_lookup=not fail,
                home_exists=not fail, computer_identity=None if fail else dict(computer, sam_account_name=machine.hostname+'$'))
            setup.directory.computer = lambda hostname: {'hostname': hostname, 'exists': True, 'objects': [copy.deepcopy(computer)]}
            result = {'schema_version':1,'machine_uuid':machine.uuid,'hostname':machine.hostname,'profile':request.profile,
                'status':'failed' if fail else 'successful','phase':'domain_join' if fail else 'complete',
                'retryable':False,'recovered':False,'reboot_required':False,
                'error':{'code':'configure_critical_phase_failed','class':'fatal-invariant','safe_message':'Synthetic new join failure'} if fail else None,
                'components':{},'verification':{'group_policy_flag_preserved':True}}
            private_create(setup.settings.state_root/'configure-runs'/config_id/'result.json', result)
            if fail: raise ControlError('domain_join_failed','Synthetic new failure',7,{'run_id':config_id,'phase':'domain_join'})
            state['user'].update(uid=10001,gid=10001,home_exists=True,home_safe=True)
            state['components']['domain.ready']['checks']['ready'] = True
            return dict(result, run_id=config_id, verification={'domain_join':True,'sssd':True,'domain_user_lookup':True,'group_policy':True})
    setup.planner.start = configure
    jobs = SetupJobRepository(setup.settings, clock=lambda:date[0])
    outcome = SetupWorker(setup.settings, engine=SetupExecutionEngine(setup.settings,setup=setup,jobs=jobs), clock=lambda:date[0]).run_once()
    return plan, jobs.get(submitted['job_id']), outcome, before, computer


def test_ordinary_new_job_advances_assignment_and_preserves_predecessor_bytes(partial_failure):
    plan, job, outcome, before, computer = dispatch_followup(partial_failure)
    setup, old, machine, *_ = partial_failure
    assert outcome['status'] == 'successful'
    assert job.job_id != old.job_id and retained(old.job_dir) == before
    assert setup.assignments.get(machine.uuid)['revision'] == 2
    proof = plan['payload']['partial_local_resolution']
    assert control('setup_partial_local_continuation').load_resolution(setup.settings, proof, archival=True)['closed']['binding']['revision'] == 1


def test_guid_recovery_can_read_partial_successor_failure(partial_failure):
    from alt_deploy.setup_recovery_history import RecoveryHistoryStore
    from alt_deploy.setup_recovery_resolution import RecoveryResolutionStore
    from alt_deploy.setup_recovery import evidence_document
    from alt_deploy.setup_plans import private_replace
    plan, job, outcome, before, computer = dispatch_followup(partial_failure, fail=True)
    setup, old, machine, *_ = partial_failure
    assert outcome['status'] == 'unknown_requires_review' and retained(old.job_dir) == before
    run_id = private_read(job.job_dir/'execution.json')['legacy_error_run_id']
    history = RecoveryHistoryStore(setup.settings.state_root).load(run_id)
    assert history['identity']['failed_run_id'] == run_id
    pair = {'failed_run_id':run_id,'computer_guid':computer['object_guid']}
    document = {'schema_version':1,'pair':pair,'identity':history['identity'],
        'terminal':dict(pair,evidence_sha256=history['identity']['evidence_sha256']), 'evidence':evidence_document(history['raw_files'])}
    store = RecoveryResolutionStore(setup.settings)
    store.retain(document)
    path = setup.assignments.root/(machine.uuid+'.json')
    private_replace(path, dict(private_read(path), revision=3, result='successful'))
    assert store.load(**pair) == document


def test_verified_own_predecessor_leases_do_not_block_foreign_joined_queue_review(mixed):
    from types import SimpleNamespace
    from alt_deploy.setup_assignments import DomainAssignmentStore
    from alt_deploy.setup_plans import SetupPlanStore
    from alt_deploy_backup.setup_queue_review import QueueAdmissionReview
    settings, joined, old_partial, facts, date = mixed
    partial = settings._partial_fixture
    setup, old, machine, user, state, current, own_date = partial
    setup.settings = settings
    setup.assignments = DomainAssignmentStore(settings.state_root)
    setup.plans = SetupPlanStore(settings.state_root, clock=lambda:date[0])
    setup.clock = lambda:date[0]
    setup.machines = SimpleNamespace(resolve=lambda identifier:machine, get=lambda identifier:machine)
    follow, recovery, result, service, calls = continuation(partial)
    plan = follow.plan(recovery['plan_id'])
    submitted = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    review = QueueAdmissionReview(settings, observer=lambda job:copy.deepcopy(facts[job.job_id]), clock=lambda:date[0])
    candidate = review.plan(joined.job_id, submitted['job_id'])
    receipt = review.confirm(candidate['plan_id'], candidate['sha256'])
    assert review.for_candidate(submitted['job_id'])['job_ids'] == {joined.job_id}
    assert SetupJobRepository(settings).get(old_partial.job_id).state == 'unknown_requires_review'
    assert SetupJobRepository(settings).get(joined.job_id).state == 'unknown_requires_review'
