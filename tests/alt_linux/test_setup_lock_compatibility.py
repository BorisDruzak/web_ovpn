"""Separate processes prove short queue admission and the legacy race boundary."""
import multiprocessing

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.jobs import JobRepository
from alt_deploy.locks import exclusive_lock
from alt_deploy.setup_jobs import legacy_setup_admission
from test_setup_jobs import jobs_fixture
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_worker import new_plan


def hold_lifecycle(settings, ready, release):
    with exclusive_lock(settings.lock_file):
        ready.send(True)
        release.recv()


def test_different_machine_admission_and_readonly_are_not_blocked_by_execution(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    first = jobs.submit(plan, operation='component')
    context = multiprocessing.get_context('fork')
    ready_recv, ready_send = context.Pipe(False)
    release_recv, release_send = context.Pipe(False)
    child = context.Process(target=hold_lifecycle, args=(settings, ready_send, release_recv))
    child.start()
    try:
        assert ready_recv.poll(5) and ready_recv.recv()
        second = jobs.submit(new_plan(component_service[0], plan, 2), operation='component')
        assert jobs.get(first.job_id).state == 'queued'
        assert jobs.get(second.job_id).state == 'queued'
    finally:
        release_send.send(True)
        child.join(5)
        if child.is_alive(): child.terminate()
    assert child.exitcode == 0


def legacy_admit(settings, identity, ready, release, output):
    from test_jobs import provision_request
    try:
        with exclusive_lock(settings.lock_file):
            with legacy_setup_admission(settings, identity['uuid'], identity['hostname']):
                ready.send(True)
                release.recv()
                request = provision_request(identity['uuid'])
                request['final_hostname'] = identity['hostname']
                JobRepository(settings).create(request)
        output.send('admitted')
    except ControlError as exc:
        output.send(exc.code)


def submit_in_child(jobs, plan, output):
    try:
        jobs.submit(plan, operation='component')
        output.send('admitted')
    except ControlError as exc:
        output.send(exc.code)


@pytest.mark.parametrize('first', ['setup', 'legacy'])
def test_both_admission_race_orders_block_conflicting_mutation(component_service, first):
    jobs, plan, settings = jobs_fixture(component_service)
    context = multiprocessing.get_context('fork')
    ready_recv, ready_send = context.Pipe(False)
    release_recv, release_send = context.Pipe(False)
    result_recv, result_send = context.Pipe(False)
    identity = plan['payload']['machine']
    if first == 'setup': jobs.submit(plan, operation='component')
    legacy = context.Process(target=legacy_admit, args=(settings, identity, ready_send, release_recv, result_send))
    legacy.start()
    if first == 'legacy':
        assert ready_recv.poll(5) and ready_recv.recv()
        setup_recv, setup_send = context.Pipe(False)
        setup = context.Process(target=submit_in_child, args=(jobs, plan, setup_send))
        setup.start()
        assert not setup_recv.poll(.1)
        release_send.send(True)
        assert setup_recv.poll(5) and setup_recv.recv() == 'setup_active_job'
        setup.join(5)
    else:
        assert result_recv.poll(5) and result_recv.recv() == 'setup_job_identity_reserved'
    legacy.join(5)
    assert legacy.exitcode == 0
