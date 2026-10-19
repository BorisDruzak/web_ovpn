"""Controller orchestration never redispatches an entered local recovery."""
import copy

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from test_setup_partial_local_state import control
from test_setup_closed_failure import backend, partial_failure
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_partial_observation import observer


def service_for(partial_failure, *, lost=False):
    setup, job, machine, user, state, current, date = partial_failure
    observed, native, *_ = observer(partial_failure)
    calls = []
    class Runtime:
        source_hash = 'a'*64
        def source(self): return self.source_hash
        def rehearsal(self, fresh):
            return {'status': 'passed', 'helper_sha256': 'b'*64, 'native_sha256': 'c'*64}
        def apply(self, plan, claim):
            calls.append(claim)
            current['domain'] = ''
            native.update(auth_scheme='local', domain='')
            for name in ('system-auth', 'system-auth-use_first_pass', 'system-policy'):
                native['files']['/etc/pam.d/'+name]['target'] = name+'-local'
            if lost: raise TimeoutError('Synthetic connection loss')
            return {'schema_version': 1, 'claim_key': claim['claim_key'], 'plan_sha256': plan['sha256'],
                'status': 'successful', 'backup_sha256': 'd'*64,
                'before_sha256': digest(plan['payload']['evidence']['partial_local']['native']),
                'after_sha256': digest(native)}
        def verify(self, plan, result):
            closed = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
            return observed.observe(closed, mode='local')
    runtime = Runtime()
    service = control('setup_partial_local').PartialLocalService(setup.settings,
        observer=observed, runtime=runtime, clock=lambda: date[0],
        history=backend('setup_closed_failure').ClosedFailureEvidence(setup.settings))
    return service, runtime, calls, native


def test_plan_and_status_are_read_only_with_respect_to_workstation(partial_failure):
    service, runtime, calls, native = service_for(partial_failure)
    job = partial_failure[1]
    plan = service.plan(job.job_id)
    assert calls == [] and native['auth_scheme'] == 'ad'
    assert service.status(plan['plan_id'])['status'] == 'planned'
    assert calls == []


def test_successful_recovery_requires_separate_new_setup_plan(partial_failure):
    service, runtime, calls, native = service_for(partial_failure)
    plan = service.plan(partial_failure[1].job_id)
    result = service.apply(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'successful' and len(calls) == 1
    assert service.status(plan['plan_id']) == result
    assert service.store.pending_attempts() == []
    with pytest.raises(ControlError): service.apply(plan['plan_id'], plan['sha256'])
    assert len(calls) == 1
    assert partial_failure[1].state == 'unknown_requires_review'


def test_disconnect_after_dispatch_stays_unknown(partial_failure):
    service, runtime, calls, native = service_for(partial_failure, lost=True)
    plan = service.plan(partial_failure[1].job_id)
    result = service.apply(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'unknown_requires_review' and len(calls) == 1
    assert len(service.store.pending_attempts()) == 1
    assert service.status(plan['plan_id']) == result
    with pytest.raises(ControlError): service.apply(plan['plan_id'], plan['sha256'])
    assert len(calls) == 1


@pytest.mark.parametrize('fault', ['source', 'boot', 'wrong_sha'])
def test_native_hash_or_boot_drift_denies_before_claim(partial_failure, fault):
    service, runtime, calls, native = service_for(partial_failure)
    plan = service.plan(partial_failure[1].job_id)
    sha = plan['sha256']
    if fault == 'source': runtime.source_hash = 'f'*64
    elif fault == 'boot': native['boot_id'] = 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa'
    else: sha = 'f'*64
    with pytest.raises(ControlError): service.apply(plan['plan_id'], sha)
    assert calls == []
    assert not list((service.settings.state_root/'setup-partial-local-claims').glob('*.json'))


def test_termination_after_claim_blocks_without_target_dispatch(partial_failure, monkeypatch):
    service, runtime, calls, native = service_for(partial_failure)
    plan = service.plan(partial_failure[1].job_id)
    create = service.store.claim_once
    def interrupted(plan):
        create(plan)
        raise KeyboardInterrupt()
    monkeypatch.setattr(service.store, 'claim_once', interrupted)
    with pytest.raises(KeyboardInterrupt): service.apply(plan['plan_id'], plan['sha256'])
    assert calls == []
    assert service.status(plan['plan_id'])['status'] == 'unknown_requires_review'
    assert len(service.store.pending_attempts()) == 1


def test_result_publication_interruption_retains_one_claim(partial_failure, monkeypatch):
    service, runtime, calls, native = service_for(partial_failure)
    plan = service.plan(partial_failure[1].job_id)
    def interrupted(*args): raise KeyboardInterrupt()
    monkeypatch.setattr(service.store, 'publish_result', interrupted)
    with pytest.raises(KeyboardInterrupt): service.apply(plan['plan_id'], plan['sha256'])
    assert len(calls) == 1 and service.status(plan['plan_id'])['status'] == 'unknown_requires_review'
    with pytest.raises(ControlError): service.apply(plan['plan_id'], plan['sha256'])
    assert len(calls) == 1


def test_controller_process_loss_after_dispatch_never_resumes(partial_failure, monkeypatch):
    import multiprocessing
    import os
    service, runtime, calls, native = service_for(partial_failure)
    plan = service.plan(partial_failure[1].job_id)
    marker = service.settings.state_root/'synthetic-target-dispatched'
    def dispatch_and_exit(*args):
        marker.write_text('one fixture dispatch')
        os._exit(73)
    monkeypatch.setattr(runtime, 'apply', dispatch_and_exit)
    ctx = multiprocessing.get_context('fork')
    child = ctx.Process(target=service.apply, args=(plan['plan_id'], plan['sha256']))
    child.start(); child.join(15)
    try:
        assert child.exitcode == 73 and marker.exists()
        assert service.status(plan['plan_id'])['status'] == 'unknown_requires_review'
        assert len(service.store.pending_attempts()) == 1
        with pytest.raises(ControlError): service.apply(plan['plan_id'], plan['sha256'])
        assert marker.read_text() == 'one fixture dispatch'
    finally:
        if child.is_alive(): child.terminate(); child.join(5)


@pytest.mark.parametrize('state', ['running', 'unknown_requires_review'])
def test_uncovered_foreign_legacy_execution_blocks_local_recovery(partial_failure, state):
    from alt_deploy.setup_plans import private_read, private_create
    service, runtime, calls, native = service_for(partial_failure)
    root = service.settings.state_root/'legacy-setup-reservations'
    value = private_read(next(root.glob('*.json')))
    value.update(reservation_id='e'*32, run_id='e'*32, operation='configure', state=state,
                 machine_uuid='22222222-3333-4444-5555-666666666666', hostname='alt-t2-pc2')
    private_create(root/('e'*32+'.json'), value)
    with pytest.raises(ControlError): service.plan(partial_failure[1].job_id)
    assert calls == []


def test_concurrent_apply_processes_dispatch_only_once(partial_failure, monkeypatch):
    import multiprocessing
    service, runtime, calls, native = service_for(partial_failure)
    plan = service.plan(partial_failure[1].job_id)
    marker = service.settings.state_root/'synthetic-concurrent-writes'
    apply = runtime.apply
    def record(*args):
        with marker.open('a') as stream: stream.write('one\n')
        return apply(*args)
    monkeypatch.setattr(runtime, 'apply', record)
    ctx = multiprocessing.get_context('fork'); ready = ctx.Event(); results = ctx.Queue()
    def invoke():
        ready.wait()
        try: result = service.apply(plan['plan_id'], plan['sha256'])
        except ControlError: results.put('blocked')
        else: results.put(result['status'])
    children = [ctx.Process(target=invoke) for _ in range(2)]
    for child in children: child.start()
    ready.set()
    try:
        assert sorted(results.get(timeout=15) for _ in children) == ['blocked', 'successful']
        assert marker.read_text() == 'one\n'
    finally:
        for child in children:
            child.join(10)
            if child.is_alive(): child.terminate(); child.join(5)
