"""Synthetic AD/target integration; this is not live ALT VM acceptance."""
import copy
import multiprocessing
import os
from types import SimpleNamespace

from alt_deploy.setup_jobs_view import SetupJobsService
from alt_deploy.setup_worker import SetupWorker
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_detach import full_fixture
from test_setup_service import UUID, OU


def test_full_setup_reboot_login_component_interruption_and_new_worker(component_service, monkeypatch):
    service, _, machine, user, facts, *_ = component_service
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    facts['user']['home_exists'] = False
    full = setup.plan(UUID, user['login'], OU, 'core-apps')
    submitted = setup.apply(full['plan_id'], full['sha256'], detach=True)
    assert submitted['state'] == 'queued' and calls == []
    assert worker.run_once()['status'] == 'waiting_reboot'
    machine.active_job = dict(jobs.get(submitted['job_id']).status)
    facts['machine']['boot_id'] = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    boot_observed = engine.verify_continuation(submitted['job_id'])
    assert boot_observed['state'] == 'waiting_first_login'
    assert boot_observed['reboot_required'] is False
    facts['user']['home_exists'] = True
    assert engine.verify_continuation(submitted['job_id'])['state'] == 'successful'
    assert len(calls) == 1
    machine.active_job = None
    assert service.plan(UUID, 'software.onlyoffice')['payload']['action'] == 'noop'
    good = copy.deepcopy(facts['components']['software.onlyoffice'])
    facts['components']['software.onlyoffice'].update(packages=[], executable=False)
    plan = service.plan(UUID, 'software.onlyoffice')
    component = service.apply(plan['plan_id'], plan['sha256'])
    engine.components, engine._components_injected = service, True
    # A real child dies after dispatch, leaving durable running state. The
    # synthetic executor sends no live Ansible, SSH or AD command.
    engine.component_executor = SimpleNamespace(run=lambda *a: os._exit(0))
    child = multiprocessing.get_context('fork').Process(target=worker.run_once)
    child.start(); child.join(5)
    assert child.exitcode == 0
    assert jobs.get(component['job_id']).state == 'running'
    fresh = SetupWorker(setup.settings, engine=engine, clock=service.clock)
    assert fresh.reconcile()['changed'][0]['state'] == 'unknown_requires_review'
    old_bytes = (jobs.get(component['job_id']).job_dir/'status.json').read_bytes()
    machine.active_job = dict(jobs.get(component['job_id']).status)
    facts['components']['software.onlyoffice'] = good
    retry = service.plan(UUID, 'software.onlyoffice', after_job=component['job_id'])
    assert retry['payload']['action'] == 'noop'
    successor = service.apply(retry['plan_id'], retry['sha256'])
    assert fresh.run_once()['status'] == 'successful'
    assert (jobs.get(component['job_id']).job_dir/'status.json').read_bytes() == old_bytes
    view = SetupJobsService(setup.settings).status(successor['job_id'])['job']
    assert view['components']['software.onlyoffice']['changed'] is False
    assert len(calls) == 1
