"""The serialized worker alone owns post-login phase execution."""
import copy
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_worker import SetupWorker
from alt_deploy.setup_phases import WorkflowPhaseStore
from alt_deploy.locks import exclusive_lock
from test_setup_phases import phase_job,phase_result
from test_full_workflow_binding import full_setup
from test_component_catalog import project


def test_worker_automatically_claims_ready_user_phase_once_and_retains_original_job(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job;calls=[]
    def execute_phase(job_id,phase):
        calls.append((job_id,phase))
        store.complete(jobs.get(job_id),phase,phase_result())
    engine=SimpleNamespace(execute_phase=execute_phase,execute=lambda *a:pytest.fail('Initial Setup replay'),
        finalize_workflow=lambda *a:pytest.fail('Final phase has not run'))
    probe=SimpleNamespace(observe=lambda j,p:dict(copy.deepcopy(ready),phase=p))
    worker=SetupWorker(setup.settings,engine=engine,phase_store=store,phase_probe=probe)
    result=worker.run_once()
    assert result['job_id']==job.job_id and result['status']=='waiting_first_login'
    assert calls==[(job.job_id,'user')]
    assert store.records(jobs.get(job.job_id))['user']['result'] is not None


def test_absent_or_ambiguous_real_login_never_enqueues_or_executes(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    def waiting(j,p):raise ControlError('graphical_session_unavailable','Waiting',7)
    engine=SimpleNamespace(execute=lambda *a:pytest.fail('No target dispatch'),execute_phase=lambda *a:pytest.fail('No phase dispatch'))
    worker=SetupWorker(setup.settings,engine=engine,phase_store=store,phase_probe=SimpleNamespace(observe=waiting))
    assert worker.run_once()['status']=='idle'
    assert store.records(jobs.get(job.job_id))['user']['ticket'] is None
    assert jobs.get(job.job_id).state=='waiting_first_login'
    from alt_deploy.setup_jobs_view import SetupJobsService
    assert SetupJobsService(setup.settings).status(job.job_id)['job']['workflow']['waiting_reason']=='graphical_session_unavailable'
    before={p:p.read_bytes() for p in job.job_dir.rglob('*') if p.is_file()}
    assert worker.run_once()['status']=='idle'
    assert all(p.read_bytes()==raw for p,raw in before.items())


def test_restart_after_phase_claim_marks_unknown_even_if_worker_pid_still_exists(phase_job):
    store,jobs,job,ready,identity,admissions,setup=phase_job
    with exclusive_lock(setup.settings.lock_file):
        store.enqueue(job,'user',ready);store.claim(jobs.get(job.job_id),'user',identity)
    worker=SetupWorker(setup.settings,engine=SimpleNamespace(execute_phase=lambda *a:pytest.fail('Consumed phase')),
        phase_store=store,phase_probe=SimpleNamespace(observe=lambda j,p:dict(copy.deepcopy(ready),phase=p)))
    assert worker.reconcile()['changed'][0]['state']=='unknown_requires_review'
    assert jobs.get(job.job_id).state=='unknown_requires_review'
