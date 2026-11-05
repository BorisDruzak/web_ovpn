"""A sealed compatibility failure before first join permits one fresh successor."""
import copy
import json
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import legacy_setup_execution
from alt_deploy.setup_plans import private_create, private_read, private_replace
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_closed_failure import backend
from test_setup_detach import full_fixture
from test_setup_partial_observation import native_facts
from test_setup_service import UUID, OU


COMPAT = 'task-5735ab09588eb5b5'
FINALIZERS = ('task-3bff097f8cfb64be', 'task-55f514a300181b34',
              'task-0df1c31dec416be0', 'task-aa008671aca81205')


@pytest.fixture
def prejoin(component_service, monkeypatch, request):
    early = getattr(request, 'param', None) == 'early_upgrade'
    phase = 'upgrade' if early else 'network'
    assertion = 'task-3be8f8abf2e42bb2' if early else COMPAT
    _, setup, machine, user, facts, date, calls = component_service
    (setup.assignments.root/(UUID+'.json')).unlink()
    current = dict(uuid=UUID, hostname=machine.hostname, domain='', trust=False,
                   sssd=False, user_lookup=False, local_duplicate=False,
                   home_exists=False, computer_identity=None)
    setup.probe = lambda *args: copy.deepcopy(current)
    setup.directory.computer = lambda hostname: dict(hostname=hostname, exists=False, objects=[])
    setup.prerequisites = lambda request: dict(ready=True, directory_uri='ldap://dc.sosnadmin.local')
    facts['user'].update(uid=None, gid=None, home_exists=False, home_safe=False)
    facts['components']['domain.ready']['checks']['ready'] = False
    setup, jobs, engine, worker, _ = full_fixture(component_service, monkeypatch)
    original_start = setup.planner.start
    config_id = 'e'*32
    def fail_before_join(identifier, request, **kwargs):
        from alt_deploy.setup_events import SetupEventStore
        with legacy_setup_execution(setup.settings, UUID, machine.hostname,
                                    operation='configure', run_id=config_id):
            root = setup.settings.state_root/'configure-runs'/config_id
            private_create(root/'request.json', request.to_dict())
            private_create(root/'result.json', dict(schema_version=1, machine_uuid=UUID,
                hostname=machine.hostname, profile=request.profile, status='failed', phase=phase,
                retryable=False, recovered=False, reboot_required=not early, components={},
                verification={'group_policy': False}, error={'code':'configure_critical_phase_failed',
                'class':'fatal-invariant', 'safe_message':'Synthetic prejoin compatibility failure'}))
            (root/'ansible.log').write_text('Protected callback only\n'); (root/'ansible.log').chmod(0o600)
            job = next(j for j in jobs.list() if j.machine_uuid == UUID)
            events = SetupEventStore(setup.settings, clock=setup.clock)
            rows = [('task-upgrade', 'download' if early else 'transaction', 'task_ok', not early),
                    (assertion, phase, 'task_start', False), (assertion, phase, 'task_failed', False)]
            for task in FINALIZERS:
                rows.extend([(task, 'apply', 'task_start', False),
                             (task, 'apply', 'task_failed' if task==FINALIZERS[-1] else 'task_ok',
                              task==FINALIZERS[-2])])
            for task, stage, kind, changed in rows:
                events.append(job.job_id, dict(schema_version=1, component_id='domain.ready',
                    component_version=1, stage=stage, task_id='task-'+'1'*16 if task=='task-upgrade' else task,
                    type=kind, changed=changed, code={'task_ok':'ok','task_start':'started','task_failed':'task_failed'}[kind]))
            raise ControlError('domain_join_failed', 'Synthetic failure', 7, {'run_id':config_id,'phase':phase})
    setup.planner.start = fail_before_join
    plan = setup.plan(UUID, user['login'], OU, 'office-standard-v1')
    submitted = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    assert worker.run_once()['status']=='unknown_requires_review'
    job = jobs.get(submitted['job_id'])
    machine.active_job = dict(schema_version=2, kind='setup', job_id=job.job_id,
        state='unknown_requires_review', machine_uuid=UUID, plan_sha256=job.status['plan_sha256'])
    setup.planner.start = original_start
    setup.retry_probe = lambda *args: dict(uuid=UUID, hostname=machine.hostname,
                                           credentials_absent=True, processes_absent=True)
    native = native_facts(machine)
    native.update(auth_scheme='local', domain='')
    for name in ('system-auth','system-auth-use_first_pass','system-policy'):
        native['files']['/etc/pam.d/'+name]['target']=name+'-local'
    quiet = dict(uuid=UUID,hostname=machine.hostname,credentials_absent=True,processes_absent=True)
    collisions = dict(complete=True,matches=0)
    observer = backend('setup_partial_observation').PartialLocalObserver(setup.settings,
        setup=setup, target_probe=lambda *a: copy.deepcopy(native), quiet_probe=lambda *a: copy.deepcopy(quiet),
        package_probe=SimpleNamespace(observe=lambda *a,**k: copy.deepcopy(facts)),
        collision_query=lambda *a: copy.deepcopy(collisions), directory_uri='ldap://dc.sosnadmin.local')
    return setup,jobs,job,machine,user,facts,current,native,quiet,collisions,observer,worker,date


def inject_bridge(monkeypatch, prejoin):
    setup,*_ = prejoin
    module = backend('setup_partial_observation')
    monkeypatch.setattr('alt_deploy.setup_maintenance_review_bridge.prejoin_compatibility_service',
        lambda settings: module.PrejoinCompatibilityHistory(settings, observer=prejoin[10]),raising=False)


def test_prejoin_local_maintenance_is_readonly_and_covers_exact_original_leases(prejoin):
    setup,jobs,job,*_ = prejoin
    module=backend('setup_partial_observation')
    closed=backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
    before={p:p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}
    fresh=prejoin[10].observe(closed,mode='prejoin_local')
    review=backend('setup_maintenance_coverage').MaintenanceCoverage(setup.settings,
        observer=lambda job:copy.deepcopy(fresh),clock=setup.clock)
    plan=review.plan();receipt=review.confirm(plan['plan_id'],plan['sha256'])
    assert receipt['purpose']=='controller_maintenance_only'
    assert review.exclusions(plan['sha256'])=={'job_ids':{job.job_id},'lease_ids':set(closed['lease_ids'])}
    assert jobs.get(job.job_id).state=='unknown_requires_review'
    assert {p:p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}==before


def test_new_identity_preserving_plan_seals_result_and_complete_journal(prejoin,monkeypatch):
    inject_bridge(monkeypatch,prejoin)
    setup,jobs,job,machine,user,*_=prejoin
    before={p:p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}
    plan=setup.plan(UUID,user['login'],OU,'office-standard-v1')
    proof=plan['payload']['prejoin_retry']
    assert 'result' in proof['evidence_sha256'] and any(k.startswith('event_') for k in proof['evidence_sha256'])
    assert plan['payload']['predecessor_job']['job_id']==job.job_id
    submitted=setup.apply(plan['plan_id'],plan['sha256'],detach=True)
    assert submitted['job_id']!=job.job_id and jobs.get(submitted['job_id']).state=='queued'
    assert jobs.get(job.job_id).state=='unknown_requires_review'
    assert {p:p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}==before


@pytest.mark.parametrize('fault',['credentials','processes','collision','native','clock','package'])
def test_successor_rechecks_live_safety_at_apply(prejoin,monkeypatch,fault):
    inject_bridge(monkeypatch,prejoin)
    setup,jobs,job,machine,user,facts,current,native,quiet,collisions,*_=prejoin
    plan=setup.plan(UUID,user['login'],OU,'office-standard-v1')
    if fault=='credentials':quiet['credentials_absent']=False
    elif fault=='processes':quiet['processes_absent']=False
    elif fault=='collision':collisions['matches']=1
    elif fault=='native':native['files']['/etc/pam.d/system-auth']['target']='system-auth-sss'
    elif fault=='clock':native['clock_synchronized']=False
    else:facts['package_manager']['processes_absent']=False
    with pytest.raises(ControlError):setup.apply(plan['plan_id'],plan['sha256'],detach=True)
    assert jobs.get(job.job_id).state=='unknown_requires_review' and len(jobs.list())==1


@pytest.mark.parametrize('fault',['join','missing_event','reorder','other_assert','other_finalizer','result','source_change'])
def test_unproven_or_changed_history_never_admits_a_successor(prejoin,monkeypatch,fault):
    inject_bridge(monkeypatch,prejoin)
    setup,jobs,job,machine,user,*_=prejoin
    root=setup.settings.state_root
    paths=sorted((job.job_dir/'events').glob('*.json'))
    path=paths[1];value=private_read(path)
    if fault=='join':value['stage']='domain_join';private_replace(path,value)
    elif fault=='missing_event':paths[0].unlink()
    elif fault=='reorder':
        value['task_id']='task-'+'a'*16;private_replace(path,value)
    elif fault=='other_assert':
        path=paths[2];value=private_read(path);value['task_id']='task-'+'b'*16;private_replace(path,value)
    elif fault=='other_finalizer':
        path=paths[-1];value=private_read(path);value['task_id']='task-'+'c'*16;private_replace(path,value)
    elif fault=='result':
        path=root/'configure-runs'/('e'*32)/'result.json';value=private_read(path);value['phase']='domain_join';private_replace(path,value)
    else:
        # Sealed result bytes changing after planning must invalidate the plan.
        plan=setup.plan(UUID,user['login'],OU,'office-standard-v1')
        path=root/'configure-runs'/('e'*32)/'result.json';path.write_bytes(path.read_bytes()+b' ')
        with pytest.raises(ControlError):setup.apply(plan['plan_id'],plan['sha256'],detach=True)
        return
    with pytest.raises(ControlError):setup.plan(UUID,user['login'],OU,'office-standard-v1')


def test_archival_prejoin_proof_stays_valid_after_assignment_advances(prejoin,monkeypatch):
    inject_bridge(monkeypatch,prejoin)
    setup,jobs,job,machine,user,*_=prejoin
    plan=setup.plan(UUID,user['login'],OU,'office-standard-v1')
    p=plan['payload'];proof=p['prejoin_retry']
    setup.assignments.write(p['binding'],run_id='setup-run-'+'d'*32,result='successful',
                            date=setup.clock().isoformat(),revision=2)
    from alt_deploy.setup_prejoin_retry import historical_prejoin_retry_evidence
    assert historical_prejoin_retry_evidence(setup.settings.state_root,p['existing_assignment'],
        p['machine'],p['user'],p['ou_identity'],p['observed'],p['computer'])==proof


@pytest.mark.parametrize('fault',['credentials','processes','collision','native','clock','package'])
def test_worker_rechecks_local_safety_after_submission_before_dispatch(prejoin,monkeypatch,fault):
    inject_bridge(monkeypatch,prejoin)
    setup,jobs,job,machine,user,facts,current,native,quiet,collisions,observer,worker,date=prejoin
    plan=setup.plan(UUID,user['login'],OU,'office-standard-v1')
    submitted=setup.apply(plan['plan_id'],plan['sha256'],detach=True)
    run_files=set((setup.settings.state_root/'setup-runs').glob('*.json'))
    if fault=='credentials':quiet['credentials_absent']=False
    elif fault=='processes':quiet['processes_absent']=False
    elif fault=='collision':collisions['matches']=1
    elif fault=='native':native['files']['/etc/pam.d/system-auth']['target']='system-auth-sss'
    elif fault=='clock':native['clock_synchronized']=False
    else:facts['package_manager']['processes_absent']=False
    assert worker.run_once()['status']=='failed'
    assert jobs.get(submitted['job_id']).state=='failed'
    assert jobs.get(job.job_id).state=='unknown_requires_review'
    assert set((setup.settings.state_root/'setup-runs').glob('*.json'))==run_files


def test_duplicate_successor_submission_does_not_create_another_job(prejoin,monkeypatch):
    inject_bridge(monkeypatch,prejoin)
    setup,jobs,job,machine,user,*_=prejoin
    plan=setup.plan(UUID,user['login'],OU,'office-standard-v1')
    first=setup.apply(plan['plan_id'],plan['sha256'],detach=True)
    # Production registration exposes the queued successor, not the reviewed
    # old UNKNOWN. Receipt lookup must not re-run target admission.
    machine.active_job=dict(jobs.get(first['job_id']).status)
    prejoin[8]['credentials_absent']=False
    second=setup.apply(plan['plan_id'],plan['sha256'],detach=True)
    assert first['job_id']==second['job_id'] and len(jobs.list())==2
    assert jobs.get(job.job_id).state=='unknown_requires_review'


@pytest.mark.parametrize('prejoin', ['early_upgrade'], indirect=True)
def test_early_refusal_has_one_fresh_successor_without_replaying_old_job(prejoin, monkeypatch):
    inject_bridge(monkeypatch, prejoin)
    setup, jobs, old, machine, user, *_ = prejoin
    before = {p:p.read_bytes() for p in old.job_dir.rglob('*') if p.is_file()}
    plan = setup.plan(UUID, user['login'], OU, 'office-standard-v1')
    submitted = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    assert submitted['job_id'] != old.job_id and jobs.get(submitted['job_id']).state == 'queued'
    assert jobs.get(old.job_id).state == 'unknown_requires_review'
    assert {p:p.read_bytes() for p in old.job_dir.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('prejoin', ['early_upgrade'], indirect=True)
@pytest.mark.parametrize('fault', ['transaction', 'other_failure', 'credentials', 'collision'])
def test_early_refusal_cannot_authorize_unproven_history_or_unsafe_live_state(prejoin, monkeypatch, fault):
    inject_bridge(monkeypatch, prejoin)
    setup, jobs, old, machine, user, *_ = prejoin
    if fault in ('transaction', 'other_failure'):
        path = sorted((old.job_dir/'events').glob('*.json'))[0 if fault == 'transaction' else 2]
        value = private_read(path)
        if fault == 'transaction': value['stage'] = 'transaction'
        else: value['task_id'] = 'task-'+'f'*16
        private_replace(path, value)
    elif fault == 'credentials': prejoin[8]['credentials_absent'] = False
    else: prejoin[9]['matches'] = 1
    with pytest.raises(ControlError): setup.plan(UUID, user['login'], OU, 'office-standard-v1')
    assert len(jobs.list()) == 1


@pytest.mark.parametrize('prejoin', ['early_upgrade'], indirect=True)
def test_early_refusal_maintenance_uses_same_prejoin_observer(prejoin, monkeypatch):
    setup, jobs, old, *_ = prejoin
    review = backend('setup_maintenance_review')
    monkeypatch.setattr(review, 'observe', lambda *a: {'observed': {'trust': False}})
    monkeypatch.setattr(backend('setup_partial_observation'), 'PartialLocalObserver', lambda *a: prejoin[10])
    fresh = review.coverage_observe(setup.settings, old)
    assert fresh['partial_local']['mode'] == 'prejoin_local'
