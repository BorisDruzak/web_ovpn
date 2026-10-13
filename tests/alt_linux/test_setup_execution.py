"""Dispatch and independent verification retain uncertainty without replay."""
import copy
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_execution import SetupExecutionEngine
from alt_deploy.setup_plans import private_read
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_jobs import jobs_fixture


def claimed(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    jobs.claim(job.job_id, {'boot_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'pid': 1234, 'start_ticks': 100})
    return jobs, plan, settings, job


def engine_for(component_service, jobs, settings, action=None):
    calls = []
    def run(plan, job):
        calls.append(plan['payload']['component']['id'])
        if action: return action(plan, job)
        return {'status': 'noop', 'changed': False, 'reboot_required': False}
    engine = SetupExecutionEngine(settings, components=component_service[0], jobs=jobs,
                                  component_executor=SimpleNamespace(run=run))
    return engine, calls


def test_noop_never_invokes_ansible(component_service):
    jobs, plan, settings, job = claimed(component_service)
    engine, calls = engine_for(component_service, jobs, settings)
    result = engine.execute(job.job_id)
    assert jobs.get(job.job_id).state == 'successful', result
    assert result['components']['software.onlyoffice']['changed'] is False
    assert calls == []
    assert result['components']['software.onlyoffice']['verification']['status'] == 'compliant'
    assert engine.execute(job.job_id) == result
    assert calls == []


@pytest.mark.parametrize('fault', ['dependency', 'identity', 'busy'])
def test_fresh_preflight_failure_has_no_dispatch(component_service, fault):
    jobs, _, settings, job = claimed(component_service)
    if fault == 'dependency': component_service[4]['components']['domain.ready']['checks']['ready'] = False
    if fault == 'identity': component_service[3]['object_guid'] = 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'
    if fault == 'busy': component_service[4]['package_manager']['processes_absent'] = False
    engine, calls = engine_for(component_service, jobs, settings)
    result = engine.execute(job.job_id)
    assert jobs.get(job.job_id).state == 'failed'
    assert result['stage'] == 'preflight' and result['error_code']
    assert calls == []


@pytest.mark.parametrize('fault', ['timeout', 'invalid_result', 'ssh_loss', 'post_probe'])
def test_partial_application_retains_safe_stage(component_service, fault):
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, _, settings, job = claimed(component_service)
    def action(plan, job):
        if fault == 'post_probe':
            component_service[0].probe.observe = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('private sentinel'))
            return {'status': 'applied', 'changed': True, 'reboot_required': False}
        raise ControlError('setup_component_timeout' if fault == 'timeout' else 'setup_component_result_invalid',
                           'private sentinel', 7)
    engine, calls = engine_for(component_service, jobs, settings, action)
    result = engine.execute(job.job_id)
    assert jobs.get(job.job_id).state == 'unknown_requires_review'
    assert result['operator_action_required'] is True
    assert calls == ['software.onlyoffice']
    assert 'private sentinel' not in str(result)
    assert engine.execute(job.job_id) == result and len(calls) == 1


def test_missing_component_is_applied_once_then_independently_verified(component_service):
    good = copy.deepcopy(component_service[4]['components']['software.onlyoffice'])
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, _, settings, job = claimed(component_service)
    def action(plan, job):
        component_service[4]['components']['software.onlyoffice'] = good
        return {'status': 'applied', 'changed': True, 'reboot_required': False}
    engine, calls = engine_for(component_service, jobs, settings, action)
    result = engine.execute(job.job_id)
    assert result['state'] == 'successful' and calls == ['software.onlyoffice'], result
    assert result['components']['software.onlyoffice']['changed'] is True


def test_known_controller_preflight_failure_is_failed_without_remote_change(component_service):
    from alt_deploy.setup_events import SetupEventStore
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, _, settings, job = claimed(component_service)
    def action(plan, job):
        SetupEventStore(settings).append(job.job_id, {'schema_version': 1, 'component_id': 'software.onlyoffice',
            'component_version': 1, 'stage': 'preflight', 'task_id': 'task-'+'a'*16,
            'type': 'task_failed', 'changed': False, 'code': 'component_preflight_failed'})
        raise ControlError('setup_component_execution_failed', 'Safe failure', 7)
    engine, calls = engine_for(component_service, jobs, settings, action)
    result = engine.execute(job.job_id)
    assert result['state'] == 'failed' and result['components']['software.onlyoffice']['changed'] is False


@pytest.mark.parametrize('wait', ['reboot', 'first_login'])
def test_waiting_continuation_is_read_only_and_requires_fresh_state(component_service, wait):
    good = copy.deepcopy(component_service[4]['components']['software.onlyoffice'])
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, _, settings, job = claimed(component_service)
    def action(plan, job):
        component_service[4]['components']['software.onlyoffice'] = good
        if wait == 'first_login':
            component_service[4]['user']['home_exists'] = False
            component_service[4]['components']['software.onlyoffice']['deferred'] = True
        return {'status': 'applied', 'changed': True, 'reboot_required': wait == 'reboot'}
    engine, calls = engine_for(component_service, jobs, settings, action)
    first = engine.execute(job.job_id)
    assert first['state'] == ('waiting_reboot' if wait == 'reboot' else 'waiting_first_login')
    assert engine.verify_continuation(job.job_id)['state'] == first['state']
    if wait == 'reboot': component_service[4]['machine']['boot_id'] = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'
    else:
        component_service[4]['user']['home_exists'] = True
        component_service[4]['components']['software.onlyoffice'].pop('deferred')
    assert engine.verify_continuation(job.job_id)['state'] == 'successful'
    assert calls == ['software.onlyoffice']
    assert private_read(job.job_dir/'execution.json')['components']['software.onlyoffice']['changed'] is True
    assert private_read(job.job_dir/'execution.json')['reboot_required'] is False


def test_waiting_reboot_cannot_accept_a_changed_original_boot_proof(component_service):
    from alt_deploy.setup_plans import private_replace
    good = copy.deepcopy(component_service[4]['components']['software.onlyoffice'])
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, _, settings, job = claimed(component_service)
    def applied(plan, job):
        component_service[4]['components']['software.onlyoffice'] = good
        return {'status':'applied','changed':True,'reboot_required':True}
    engine, _ = engine_for(component_service, jobs, settings, applied)
    result = engine.execute(job.job_id)
    assert result['state'] == 'waiting_reboot'
    result['original_boot_id'] = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    private_replace(job.job_dir/'execution.json', result)
    with pytest.raises(ControlError) as rejected: engine.verify_continuation(job.job_id)
    assert rejected.value.code == 'setup_execution_result_invalid'
    assert jobs.get(job.job_id).state == 'waiting_reboot'
