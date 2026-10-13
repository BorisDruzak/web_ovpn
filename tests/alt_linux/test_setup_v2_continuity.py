"""V2 jobs reuse original prejoin/recovery gates without replaying a claim."""
import copy

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_execution import SetupExecutionEngine
from alt_deploy.setup_events import SetupEventStore
from alt_deploy.setup_jobs import SetupJobRepository
from alt_deploy.setup_plans import private_create
from alt_deploy.setup_worker import SetupWorker
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_detach import full_fixture
from test_setup_service import UUID, OU


def test_completed_domain_with_unknown_deep_result_allows_only_reviewed_component(component_service, monkeypatch):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    original = engine._post
    def unknown(job):
        facts, verification = original(job)
        facts['package_manager']['dependencies_healthy'] = False
        return facts, verification
    engine._post = unknown
    plan = setup.plan(UUID, component_service[3]['login'], OU, 'core-apps')
    old_id = setup.apply(plan['plan_id'], plan['sha256'], detach=True)['job_id']
    assert worker.run_once()['status'] == 'unknown_requires_review'
    component_service[2].active_job = dict(jobs.get(old_id).status)
    service = component_service[0]
    new = service.plan(UUID, 'software.onlyoffice', after_job=old_id)
    assert new['payload']['action'] == 'noop'
    assert 'legacy_run_sha256' in new['payload']['predecessor_job']
    successor = service.apply(new['plan_id'], new['sha256'])
    assert successor['state'] == 'queued' and len(calls) == 1
    engine._post = original
    engine.components, engine._components_injected = service, True
    assert worker.run_once()['status'] == 'successful'
    assert len(calls) == 1
    with pytest.raises(ControlError):
        service.plan(UUID, 'domain.ready', after_job=old_id)


def failed_full(component_service, monkeypatch, phase='transaction', profile='core-apps'):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    (setup.assignments.root/(UUID+'.json')).unlink()
    machine = component_service[2]
    joined_computer, joined_probe = setup.directory.computer, setup.probe
    setup.directory.computer = lambda host: {'hostname': host, 'exists': False, 'objects': []}
    setup.probe = lambda machine, user: {'uuid': machine.uuid, 'hostname': machine.hostname, 'domain': '',
        'trust': False, 'sssd': False, 'user_lookup': False, 'local_duplicate': False, 'home_exists': False}
    original = setup.planner.start
    config_id = 'f'*32
    def timeout(identifier, request, **kwargs):
        job = next(j for j in jobs.list() if j.state == 'running')
        private_create(setup.settings.state_root/'configure-runs'/config_id/'request.json', request.to_dict())
        log = setup.settings.state_root/'configure-runs'/config_id/'ansible.log'
        log.write_text('')
        log.chmod(0o600)
        SetupEventStore(setup.settings).append(job.job_id, {'schema_version': 1, 'component_id': 'domain.ready',
            'component_version': 1, 'stage': phase, 'task_id': 'task-'+'a'*16, 'type': 'task_start',
            'changed': False, 'code': 'started'})
        raise ControlError('setup_upgrade_timeout', 'Safe timeout', 7, {'run_id': config_id, 'phase': 'upgrade'})
    setup.planner.start = timeout
    old_plan = setup.plan(UUID, component_service[3]['login'], OU, profile)
    job_id = setup.apply(old_plan['plan_id'], old_plan['sha256'], detach=True)['job_id']
    assert worker.run_once()['status'] == 'unknown_requires_review'
    old = jobs.get(job_id)
    machine.active_job = dict(old.status)
    def success(*a, **k):
        setup.directory.computer, setup.probe = joined_computer, joined_probe
        return original(*a, **k)
    setup.planner.start = success
    quiet = {'uuid': UUID, 'hostname': machine.hostname, 'credentials_absent': True, 'processes_absent': True}
    setup.retry_probe = lambda *a: copy.deepcopy(quiet)
    return setup, jobs, worker, old, quiet


def test_v2_prejoin_timeout_uses_safe_events_and_new_confirmed_plan(component_service, monkeypatch):
    setup, jobs, worker, old, quiet = failed_full(component_service, monkeypatch)
    old_bytes = (old.job_dir/'status.json').read_bytes()
    failed_run = setup.assignments.get(UUID)['run_id']
    run_bytes = setup._run_path(failed_run).read_bytes()
    new = setup.plan(UUID, component_service[3]['login'], OU, 'core-apps')
    assert new['payload']['prejoin_retry']['failed_run_id'] == failed_run
    assert new['payload']['predecessor_job']['job_id'] == old.job_id
    submitted = setup.apply(new['plan_id'], new['sha256'], detach=True)
    assert submitted['job_id'] != old.job_id
    # No dispatcher or role is executed by planning or admission.
    assert jobs.get(submitted['job_id']).state == 'queued'
    assert worker.run_once()['status'] == 'waiting_reboot'
    assert jobs.get(old.job_id).state == 'unknown_requires_review'
    assert (old.job_dir/'status.json').read_bytes() == old_bytes
    assert setup._run_path(failed_run).read_bytes() == run_bytes


@pytest.mark.parametrize('fault', ['remote_busy', 'join_started', 'changed_events'])
def test_v2_prejoin_requires_original_gate_and_fresh_absence(component_service, monkeypatch, fault):
    setup, jobs, worker, old, quiet = failed_full(component_service, monkeypatch,
        phase='domain_join' if fault == 'join_started' else 'transaction')
    if fault == 'remote_busy': quiet['processes_absent'] = False
    if fault == 'changed_events':
        event = next((old.job_dir/'events').glob('*.json'))
        event.write_text('{}')
    with pytest.raises(ControlError): setup.plan(UUID, component_service[3]['login'], OU, 'core-apps')
    assert jobs.get(old.job_id).state == 'unknown_requires_review'


def test_frozen_new_profile_is_read_by_original_prejoin_gate(component_service, monkeypatch):
    setup, jobs, worker, old, quiet = failed_full(component_service, monkeypatch, profile='office-standard-v1')
    new = setup.plan(UUID, component_service[3]['login'], OU, 'office-standard-v1')
    assert new['payload']['profile']['id'] == 'office-standard-v1'
    assert new['payload']['predecessor_job']['job_id'] == old.job_id


@pytest.mark.parametrize('fault', ['healthy', 'wrong_run', 'wrong_job', 'running'])
def test_recovery_exclusion_allows_only_exact_closed_full_job(component_service, monkeypatch, fault):
    from alt_deploy.setup_retry import closed_full_job_only
    setup, jobs, _, old, _ = failed_full(component_service, monkeypatch)
    machine = component_service[2]
    failed = setup.assignments.get(UUID)['run_id']
    if fault == 'wrong_job': machine.active_job['job_id'] = 'job-20261013T000000Z-ffffffff'
    if fault == 'wrong_run': failed = 'setup-run-'+'b'*32
    if fault == 'running': machine.active_job['state'] = 'running'
    assert closed_full_job_only(setup.settings, machine, failed) is (fault == 'healthy')
