"""Real FLOCK handoffs preserve protected review's freshness and identity checks."""
from contextlib import contextmanager
import copy
from datetime import timedelta
import fcntl
import multiprocessing
import sys
import time

import pytest

from alt_deploy.errors import ControlError
from alt_deploy_backup import setup_maintenance_review as module
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_maintenance_review import stopped, service


@contextmanager
def held_lock(path):
    context = multiprocessing.get_context('fork')
    ready_recv, ready_send = context.Pipe(False)
    release_recv, release_send = context.Pipe(False)

    def hold():
        with path.open('r') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            ready_send.send(True)
            release_recv.recv()

    child = context.Process(target=hold)
    child.start()
    try:
        assert ready_recv.poll(5) and ready_recv.recv()
        yield lambda: release_send.send(True)
    finally:
        try:
            release_send.send(True)
        except OSError:
            pass
        child.join(5)
        if child.is_alive():
            child.terminate()
            child.join(5)
        assert child.exitcode == 0


@contextmanager
def after_real_contention(action):
    previous = sys.getprofile()
    observed = []

    def profile(frame, event, function):
        if (event == 'c_exception' and function is fcntl.flock
                and frame.f_code.co_name == 'maintenance_lock' and not observed):
            observed.append(True)
            action()

    # The real kernel reports busy first. Only then do we release the holder;
    # no mock can grant admission or replace the native lock return value.
    sys.setprofile(profile)
    try:
        yield
    finally:
        sys.setprofile(previous)
    assert observed


@pytest.mark.parametrize('operation', ['plan', 'confirm', 'exclusions'])
def test_review_completes_after_brief_idle_lock_handoff(stopped, operation):
    settings, job, facts, date = stopped
    review = service(stopped)
    if operation != 'plan':
        plan = review.plan(job.job_id)
    if operation == 'exclusions':
        review.confirm(plan['plan_id'], plan['sha256'])
    with held_lock(settings.lock_file) as release, after_real_contention(release):
        if operation == 'plan':
            assert review.plan(job.job_id)['purpose'] == 'controller_maintenance_only'
        elif operation == 'confirm':
            assert review.confirm(plan['plan_id'], plan['sha256'])['review_sha256'] == plan['sha256']
        else:
            assert review.exclusions(plan['sha256'])['job_ids'] == {job.job_id}


def test_persistent_holder_times_out_without_observation(stopped, monkeypatch):
    settings, job, facts, date = stopped
    monkeypatch.setattr(module, '_LOCK_WAIT_SECONDS', .15, raising=False)
    observed = []
    review = module.MaintenanceReview(settings,
        observer=lambda job: observed.append(job) or copy.deepcopy(facts), clock=lambda: date[0])
    with held_lock(settings.lock_file):
        start = time.monotonic()
        with pytest.raises(ControlError):
            review.plan(job.job_id)
        elapsed = time.monotonic()-start
    assert .1 <= elapsed < 2
    assert observed == []


@pytest.mark.parametrize('replacement', ['file', 'symlink', 'unsafe_mode'])
def test_handoff_revalidates_named_lock_before_observation(stopped, tmp_path, replacement):
    settings, job, facts, date = stopped
    observed = []
    review = module.MaintenanceReview(settings,
        observer=lambda job: observed.append(job) or copy.deepcopy(facts), clock=lambda: date[0])
    outside = tmp_path/'outside'
    outside.write_bytes(b'untouched')

    with held_lock(settings.lock_file) as release:
        def change_then_release():
            if replacement == 'unsafe_mode':
                settings.lock_file.chmod(0o644)
            else:
                settings.lock_file.unlink()
                if replacement == 'file':
                    settings.lock_file.write_bytes(b'')
                    settings.lock_file.chmod(0o600)
                else:
                    settings.lock_file.symlink_to(outside)
            release()

        with after_real_contention(change_then_release), pytest.raises(ControlError):
            review.plan(job.job_id)
    assert observed == []
    assert outside.read_bytes() == b'untouched'


def test_confirmation_expired_during_wait_still_denies(stopped):
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    with held_lock(settings.lock_file) as release:
        def expire_then_release():
            date[0] += timedelta(minutes=30)
            release()

        with after_real_contention(expire_then_release), pytest.raises(ControlError):
            review.confirm(plan['plan_id'], plan['sha256'])


def test_receipt_history_changed_during_wait_still_denies(stopped):
    settings, job, facts, date = stopped
    review = service(stopped)
    plan = review.plan(job.job_id)
    review.confirm(plan['plan_id'], plan['sha256'])
    path = job.job_dir/'status.json'
    with held_lock(settings.lock_file) as release:
        def change_then_release():
            path.write_bytes(path.read_bytes()+b' ')
            release()

        with after_real_contention(change_then_release), pytest.raises(ControlError):
            review.exclusions(plan['sha256'])
