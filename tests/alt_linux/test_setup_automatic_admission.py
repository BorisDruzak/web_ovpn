"""Fresh queued work passes closed history without replay or manual review."""
import copy
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import SetupPlanStore, private_read, private_replace
from alt_deploy.setup_worker import SetupWorker
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_maintenance_review import stopped
from test_setup_queue_review import queued, review_for, freeze_old


def worker_for(queued, monkeypatch):
    from alt_deploy import setup_maintenance_review_bridge
    settings, old, candidate, facts, date, jobs = queued
    review = review_for(queued)
    monkeypatch.setattr(setup_maintenance_review_bridge, 'queue_review_service', lambda settings: review)
    calls = []
    def execute(job_id):
        calls.append(job_id)
        jobs.transition(job_id, 'running')
        jobs.transition(job_id, 'verifying')
        jobs.transition(job_id, 'successful')
    return SetupWorker(settings, engine=SimpleNamespace(execute=execute), clock=lambda: date[0]), review, calls


def test_new_job_runs_automatically_once_and_retains_unknown(queued, monkeypatch):
    settings, old, candidate, facts, date, jobs = queued
    before = freeze_old(old, settings.state_root)
    worker, review, calls = worker_for(queued, monkeypatch)
    assert worker.run_once() == {'status': 'successful', 'job_id': candidate.job_id}
    assert calls == [candidate.job_id]
    assert jobs.get(old.job_id).state == 'unknown_requires_review'
    assert freeze_old(old, settings.state_root) == before
    assert private_read(review.reviews/(candidate.job_id+'.json'))['candidate_job_id'] == candidate.job_id
    worker.run_once()
    assert calls == [candidate.job_id]
    from alt_deploy_backup.setup_compat import validate_ledger
    validate_ledger(settings.state_root)


@pytest.mark.parametrize('failure', ['busy', 'uncertain', 'history', 'receipt', 'expired'])
def test_automatic_check_fails_closed_without_claim_or_history_changes(queued, monkeypatch, failure):
    from datetime import timedelta
    settings, old, candidate, facts, date, jobs = queued
    worker, review, calls = worker_for(queued, monkeypatch)
    if failure == 'busy': facts['package_manager']['processes_absent'] = False
    elif failure == 'uncertain': facts['package_manager']['processes_absent'] = None
    elif failure == 'history':
        path = old.job_dir/'execution.json'
        value = private_read(path); value.pop('finished_at'); private_replace(path, value)
    elif failure == 'receipt':
        plan = review.plan(old.job_id, candidate.job_id)
        review.confirm(plan['plan_id'], plan['sha256'])
        (review.reviews/(candidate.job_id+'.json')).chmod(0o644)
    else: date[0] += timedelta(minutes=31)
    before = freeze_old(old, settings.state_root)
    assert worker.run_once()['status'] == 'blocked'
    assert not jobs.get(candidate.job_id).status['claimed']
    assert calls == [] and freeze_old(old, settings.state_root) == before
    from alt_deploy.setup_jobs_view import SetupJobsService
    projected = SetupJobsService(settings).status(candidate.job_id)['job']
    assert projected['error_code'] == 'setup_queue_admission_unverified'


def test_automatic_admission_preserves_fifo_with_multiple_new_jobs(queued, monkeypatch):
    settings, old, candidate, facts, date, jobs = queued
    payload = copy.deepcopy(candidate.request['plan']['payload'])
    payload['machine'].update(uuid='bbbbbbbb-3333-4444-5555-666666666666', hostname='alt-t2-pc4')
    payload['computer']['objects'][0]['object_guid'] = 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
    second = jobs.submit(SetupPlanStore(settings.state_root, clock=lambda: date[0]).create(payload), operation='full_setup')
    worker, review, calls = worker_for(queued, monkeypatch)
    with pytest.raises(ControlError): review.plan(old.job_id, second.job_id)
    assert worker.run_once()['job_id'] == candidate.job_id
    assert worker.run_once()['job_id'] == second.job_id
    assert calls == [candidate.job_id, second.job_id]
    assert jobs.get(old.job_id).state == 'unknown_requires_review'


def test_busy_check_can_clear_on_same_unclaimed_job(queued, monkeypatch):
    settings, old, candidate, facts, date, jobs = queued
    worker, review, calls = worker_for(queued, monkeypatch)
    facts['package_manager']['processes_absent'] = False
    assert worker.run_once()['status'] == 'blocked'
    facts['package_manager']['processes_absent'] = True
    assert worker.run_once()['status'] == 'successful'
    assert calls == [candidate.job_id]


def test_diagnostic_record_never_grants_permission(queued, monkeypatch):
    from alt_deploy.setup_jobs import record_queue_check
    from alt_deploy_backup.setup_compat import validate_ledger, history_fingerprint
    settings, old, candidate, facts, date, jobs = queued
    worker, review, calls = worker_for(queued, monkeypatch)
    record_queue_check(settings, candidate, code=None, checked_at=date[0].isoformat())
    facts['package_manager']['processes_absent'] = False
    assert worker.run_once()['status'] == 'blocked'
    assert calls == [] and not jobs.get(candidate.job_id).status['claimed']
    validate_ledger(settings.state_root)
    assert 'jobs/'+candidate.job_id+'/admission-check.json' in history_fingerprint(settings.state_root)
    path = candidate.job_dir/'admission-check.json'
    value = private_read(path); value['request_sha256'] = 'f'*64; private_replace(path, value)
    with pytest.raises(ControlError): worker.run_once()
    with pytest.raises((ControlError, ValueError)): validate_ledger(settings.state_root)
    assert calls == [] and not jobs.get(candidate.job_id).status['claimed']
