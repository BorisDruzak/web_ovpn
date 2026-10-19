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


def dispatch_followup(partial_failure, *, fail=False, absent=False, prepared=None, configuration_id='e'*32):
    from alt_deploy.setup_jobs import legacy_setup_execution
    from alt_deploy.setup_plans import private_create
    from alt_deploy.setup_execution import SetupExecutionEngine
    from alt_deploy.setup_worker import SetupWorker
    follow, recovery, result, service, calls = prepared or continuation(partial_failure)
    setup, old, machine, user, state, current, date = partial_failure
    plan = follow.plan(recovery['plan_id'])
    before = retained(old.job_dir)
    submitted = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    computer = {'object_guid': 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa', 'object_sid': 'S-1-5-21-1-2-3-2001',
                'dn': 'CN='+machine.hostname+','+plan['payload']['computer_ou'], 'dns_hostname': machine.hostname+'.sosnadmin.local'}
    def configure(identifier, request, **kwargs):
        config_id = configuration_id
        with legacy_setup_execution(setup.settings, machine.uuid, machine.hostname, operation='configure', run_id=config_id):
            private_create(setup.settings.state_root/'configure-runs'/config_id/'request.json', request.to_dict())
            current.update(domain='sosnadmin.local', trust=not fail, sssd=not fail, user_lookup=not fail,
                home_exists=not fail, computer_identity=None if fail else dict(computer, sam_account_name=machine.hostname+'$'))
            setup.directory.computer = lambda hostname: {'hostname': hostname, 'exists': not absent,
                'objects': [] if absent else [copy.deepcopy(computer)]}
            result = {'schema_version':1,'machine_uuid':machine.uuid,'hostname':machine.hostname,'profile':request.profile,
                'status':'failed' if fail else 'successful','phase':'domain_join' if fail else 'complete',
                'retryable':False,'recovered':False,'reboot_required':False,
                'error':{'code':'configure_critical_phase_failed','class':'fatal-invariant','safe_message':'Synthetic new join failure'} if fail else None,
                'components':{},'verification':{'group_policy_flag_preserved':True}}
            private_create(setup.settings.state_root/'configure-runs'/config_id/'result.json', result)
            if fail:
                from alt_deploy.setup_events import SetupEventStore
                store = SetupEventStore(setup.settings, clock=setup.clock)
                for kind, code in [('task_start', 'started'), ('task_failed', 'first_join_native_failed')]:
                    store.append(submitted['job_id'], {'schema_version': 1, 'component_id': 'domain.ready',
                        'component_version': 1, 'stage': 'domain_join', 'task_id': 'task-'+'1'*16,
                        'type': kind, 'changed': False, 'code': code})
                raise ControlError('domain_join_failed','Synthetic new failure',7,{'run_id':config_id,'phase':'domain_join'})
            state['user'].update(uid=10001,gid=10001,home_exists=True,home_safe=True)
            state['components']['domain.ready']['checks']['ready'] = True
            return dict(result, run_id=config_id, verification={'domain_join':True,'sssd':True,'domain_user_lookup':True,'group_policy':True})
    setup.planner.start = configure
    jobs = SetupJobRepository(setup.settings, clock=lambda:date[0])
    outcome = SetupWorker(setup.settings, engine=SetupExecutionEngine(setup.settings,setup=setup,jobs=jobs), clock=lambda:date[0]).run_once()
    return plan, jobs.get(submitted['job_id']), outcome, before, computer


def test_closed_absent_object_successor_can_be_sealed_without_replaying_ancestor(partial_failure):
    from alt_deploy_backup.setup_closed_failure import ClosedFailureEvidence
    plan, job, outcome, old_bytes, _ = dispatch_followup(partial_failure, fail=True, absent=True)
    setup, old, *_ = partial_failure
    assert outcome['status'] == 'unknown_requires_review'
    before = retained(setup.settings.state_root)
    closed = ClosedFailureEvidence(setup.settings).load(job.job_id)
    assert closed['job_id'] == job.job_id and len(closed['lease_ids']) == 2
    assert closed['binding']['revision'] == 2
    assert closed['original']['partial_local_resolution']['job_id'] == old.job_id
    assert retained(old.job_dir) == old_bytes
    assert retained(setup.settings.state_root) == before


def dispatch_after_two_failures(partial_failure):
    plan, failed, outcome, old_bytes, _ = dispatch_followup(partial_failure, fail=True, absent=True)
    setup, old, machine, user, state, current, date = partial_failure
    assert outcome['status'] == 'unknown_requires_review'
    original_claims = retained(setup.settings.state_root/'setup-partial-local-claims')
    next_fixture = setup, failed, machine, user, state, current, date
    service, runtime, calls, native = service_for(next_fixture)
    recovery = service.plan(failed.job_id)
    restored = service.apply(recovery['plan_id'], recovery['sha256'])
    assert restored['status'] == 'successful' and len(calls) == 1
    with pytest.raises(ControlError): service.apply(recovery['plan_id'], recovery['sha256'])
    follow = control('setup_partial_local_continuation').PartialLocalContinuation(
        setup.settings, setup=setup, runtime=runtime, clock=setup.clock)
    third_plan, third, final, failed_bytes, _ = dispatch_followup(next_fixture,
        prepared=(follow, recovery, restored, service, calls), configuration_id='d'*32)
    assert final['status'] == 'successful', private_read(third.job_dir/'execution.json')
    assert len({old.job_id, failed.job_id, third.job_id}) == 3
    assert setup.assignments.get(machine.uuid)['revision'] == 3
    assert retained(old.job_dir) == old_bytes and retained(failed.job_dir) == failed_bytes
    for name, raw in original_claims.items():
        assert (setup.settings.state_root/'setup-partial-local-claims'/name).read_bytes() == raw
    assert len(list((setup.settings.state_root/'setup-partial-local-claims').glob('*.json'))) == 2
    return third_plan, third, final


def test_distinct_failed_successor_gets_one_local_claim_and_one_fresh_setup(partial_failure):
    dispatch_after_two_failures(partial_failure)


@pytest.mark.parametrize('fault', ['missing_review', 'missing_claim', 'unknown_result',
                                  'foreign_supersedes', 'missing_supersedes', 'unreviewed_lease'])
def test_failed_successor_requires_complete_verified_ancestor_closure(partial_failure, fault):
    from alt_deploy_backup.setup_closed_failure import ClosedFailureEvidence
    from alt_deploy.setup_jobs import legacy_execution_reservations
    from alt_deploy.setup_plans import private_create, private_replace
    _, job, _, _, _ = dispatch_followup(partial_failure, fail=True, absent=True)
    setup, old, *_ = partial_failure
    root = setup.settings.state_root
    if fault == 'missing_review':
        (root/'setup-job-reviews'/(old.job_id+'.json')).unlink()
    elif fault == 'missing_claim':
        next((root/'setup-partial-local-claims').glob('*.json')).unlink()
    elif fault == 'unknown_result':
        path = next((root/'setup-partial-local-results').glob('*.json'))
        private_replace(path, dict(private_read(path), status='unknown_requires_review'))
    else:
        run_id = private_read(job.job_dir/'execution.json')['legacy_error_run_id']
        records = legacy_execution_reservations(setup.settings)
        lease = next(r for r in records if r['run_id'] == run_id)
        if fault == 'unreviewed_lease':
            value = dict(lease, reservation_id='b'*32, run_id='setup-run-'+'b'*32, supersedes=[])
            private_create(root/'legacy-setup-reservations'/('b'*32+'.json'), value)
        else:
            references = lease['supersedes']+['b'*32] if fault == 'foreign_supersedes' else lease['supersedes'][:-1]
            private_replace(root/'legacy-setup-reservations'/(lease['reservation_id']+'.json'),
                            dict(lease, supersedes=references))
    with pytest.raises(ControlError): ClosedFailureEvidence(setup.settings).load(job.job_id)


def test_archived_successor_capsule_rechecks_original_recovery_claim(partial_failure):
    from alt_deploy_backup.setup_closed_failure import ClosedFailureEvidence
    from alt_deploy.setup_partial_local_state import PartialLocalStore
    _, job, _, _, _ = dispatch_followup(partial_failure, fail=True, absent=True)
    setup = partial_failure[0]
    closed = ClosedFailureEvidence(setup.settings).load(job.job_id)
    store = PartialLocalStore(setup.settings)
    store.retain_closed(closed)
    assert store.load_closed(closed['history_sha256']) == closed
    next((setup.settings.state_root/'setup-partial-local-claims').glob('*.json')).unlink()
    with pytest.raises(ControlError): store.load_closed(closed['history_sha256'])


def test_maintenance_covers_only_distinct_failed_successor_and_its_pair(partial_failure):
    from alt_deploy_backup.setup_closed_failure import ClosedFailureEvidence
    from alt_deploy_backup.setup_maintenance_coverage import MaintenanceCoverage
    from test_setup_partial_observation import observer
    _, job, _, _, _ = dispatch_followup(partial_failure, fail=True, absent=True)
    setup, old, machine, user, state, current, date = partial_failure
    fresh, *_ = observer((setup, job, machine, user, state, current, date))
    def observe(selected):
        assert selected.job_id == job.job_id
        return fresh.observe(ClosedFailureEvidence(setup.settings).load(job.job_id), mode='partial_ad')
    service = MaintenanceCoverage(setup.settings, observer=observe, clock=setup.clock)
    plan = service.plan()
    service.confirm(plan['plan_id'], plan['sha256'])
    result = service.exclusions(plan['sha256'])
    assert result['job_ids'] == {job.job_id} and len(result['lease_ids']) == 2
    assert SetupJobRepository(setup.settings).get(old.job_id).state == 'unknown_requires_review'


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
