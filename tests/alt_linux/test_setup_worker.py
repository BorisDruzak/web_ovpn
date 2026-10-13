"""Restart reconciliation never repeats a consumed mutating command."""
import copy
from types import SimpleNamespace

import pytest

from alt_deploy.setup_worker import SetupWorker, process_identity, process_alive
from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from test_setup_jobs import jobs_fixture
from test_component_setup import component_service
from test_component_catalog import project


def new_plan(service, original, number):
    payload = copy.deepcopy(original['payload'])
    payload['machine'].update(uuid=f'{number:08x}-2222-3333-4444-555555555555', hostname=f'alt-test-{number}')
    payload['computer']['objects'][0]['object_guid'] = f'{number:08x}-bbbb-cccc-dddd-eeeeeeeeeeee'
    return service.plans.create(payload)


def engine(jobs, calls):
    def execute(job_id):
        calls.append(job_id)
        jobs.transition(job_id, 'running')
        jobs.transition(job_id, 'verifying')
        jobs.transition(job_id, 'successful')
        return {'status': 'successful'}
    return SimpleNamespace(execute=execute)


def test_worker_fifo_and_single_claim(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    first = jobs.submit(plan, operation='component')
    second = jobs.submit(new_plan(component_service[0], plan, 2), operation='component')
    calls = []
    worker = SetupWorker(settings, engine=engine(jobs, calls), clock=jobs.clock)
    assert worker.run_once()['job_id'] == first.job_id
    assert worker.run_once()['job_id'] == second.job_id
    assert worker.run_once()['status'] == 'idle'
    assert calls == [first.job_id, second.job_id]
    assert jobs.submit(plan, operation='component').job_id == first.job_id


@pytest.mark.parametrize('observation', [False, None, 'raises'])
def test_worker_restart_never_replays_claim(component_service, observation):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    jobs.claim(job.job_id, process_identity(settings))
    jobs.transition(job.job_id, 'running')
    calls = []
    def probe(identity):
        if observation == 'raises': raise OSError('SENTINEL-PRIVATE-ERROR')
        return observation
    worker = SetupWorker(settings, engine=engine(jobs, calls), process_probe=probe, clock=jobs.clock)
    result = worker.reconcile()
    assert jobs.get(job.job_id).state == 'unknown_requires_review'
    assert jobs.get(job.job_id).request['plan']['plan_id'] == plan['plan_id']
    assert 'SENTINEL' not in str(result)
    assert worker.run_once()['status'] == 'blocked'
    assert calls == []


def test_live_claim_and_waiting_state_are_never_resumed(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    jobs.claim(job.job_id, process_identity(settings))
    jobs.transition(job.job_id, 'running')
    calls = []
    worker = SetupWorker(settings, engine=engine(jobs, calls), process_probe=lambda i: True, clock=jobs.clock)
    assert worker.reconcile()['changed'] == []
    assert worker.run_once()['status'] == 'blocked'
    jobs.transition(job.job_id, 'waiting_first_login')
    assert worker.reconcile()['changed'] == []
    assert worker.run_once()['status'] == 'idle'
    assert calls == []


def test_legacy_worker_outside_lock_blocks_dispatch(component_service):
    from test_jobs import provision_request
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    JobRepository(settings).create(provision_request('22222222-2222-3333-4444-555555555555'))
    calls = []
    worker = SetupWorker(settings, engine=engine(jobs, calls), clock=jobs.clock)
    result = worker.run_once()
    assert result['status'] == 'blocked' and result['code'] == 'legacy_job_active'
    assert jobs.get(job.job_id).status['claimed'] is False and calls == []


def test_return_value_without_durable_result_is_unknown(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    worker = SetupWorker(settings, engine=SimpleNamespace(execute=lambda i: {'status': 'successful'}), clock=jobs.clock)
    worker.run_once()
    assert jobs.get(job.job_id).state == 'unknown_requires_review'


def test_pid_reuse_and_controller_reboot_are_not_live(component_service):
    jobs, _, settings = jobs_fixture(component_service)
    current = process_identity(settings)
    assert process_alive(settings, current) is True
    assert process_alive(settings, dict(current, start_ticks=current['start_ticks']+1)) is False
    assert process_alive(settings, dict(current, boot_id='00000000-0000-0000-0000-000000000000')) is False


def test_crashed_legacy_configuration_blocks_worker_and_preserves_evidence(component_service):
    from alt_deploy.setup_jobs import legacy_setup_execution, legacy_execution_reservations
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    with pytest.raises(KeyboardInterrupt):
        with legacy_setup_execution(settings, '22222222-2222-3333-4444-555555555555', 'alt-other',
                                    operation='configure', run_id='b'*32):
            raise KeyboardInterrupt('synthetic loss')
    prior = legacy_execution_reservations(settings)
    assert prior[0]['state'] == 'unknown_requires_review'
    calls = []
    worker = SetupWorker(settings, engine=engine(jobs, calls), clock=jobs.clock)
    assert worker.run_once()['code'] == 'legacy_execution_unresolved'
    assert legacy_execution_reservations(settings) == prior
    assert calls == [] and jobs.get(job.job_id).status['claimed'] is False
    from alt_deploy.controller_readiness import ControllerReadinessChecker
    assert ControllerReadinessChecker(settings).active_jobs_empty() is False


def test_malformed_legacy_execution_is_a_safe_control_error(component_service):
    from alt_deploy.setup_jobs import legacy_setup_execution, legacy_execution_reservations
    from alt_deploy.setup_plans import private_read, private_replace
    jobs, _, settings = jobs_fixture(component_service)
    with legacy_setup_execution(settings, '22222222-2222-3333-4444-555555555555', 'alt-other',
                                operation='configure', run_id='b'*32):
        pass
    path = next((settings.state_root/'legacy-setup-reservations').glob('*.json'))
    payload = private_read(path)
    payload['machine_uuid'] = {'secret': 'SENTINEL'}
    private_replace(path, payload)
    with pytest.raises(ControlError) as caught: legacy_execution_reservations(settings)
    assert caught.value.code == 'setup_state_invalid' and 'SENTINEL' not in str(caught.value)
