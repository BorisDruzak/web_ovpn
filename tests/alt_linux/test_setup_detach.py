"""New full plans share durable worker dispatch; old result files remain readable."""
import pytest

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.configure import ConfigureRequest
from alt_deploy.errors import ControlError
from alt_deploy.setup_execution import SetupExecutionEngine
from alt_deploy.setup_jobs import SetupJobRepository
from alt_deploy.setup_worker import SetupWorker
from test_component_setup import component_service
from test_component_catalog import project, edit
from test_setup_service import UUID, OU


def full_fixture(component_service, monkeypatch):
    component, setup, machine, user, state, date, calls = component_service
    setup.catalog = ComponentCatalog.load(setup.settings.ansible_project_dir)
    setup.component_probe = component.probe
    setup.clock = component.clock
    setup.plans.clock = component.clock
    monkeypatch.setattr('alt_deploy.component_probe.ssh_binding', lambda *a, **k:
                        {'host_public_sha256': '1'*64, 'controller_public_sha256': '2'*64})
    jobs = SetupJobRepository(setup.settings, clock=component.clock)
    engine = SetupExecutionEngine(setup.settings, setup=setup, jobs=jobs)
    worker = SetupWorker(setup.settings, engine=engine, clock=component.clock)
    setup.job_waiter = lambda job: (worker.run_once(), engine.jobs.get(job.job_id))[1]
    return setup, jobs, engine, worker, calls


def test_full_setup_sync_and_detach_share_engine(component_service, monkeypatch):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    plan = setup.plan(UUID, component_service[3]['login'], OU, 'core-apps')
    detached = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    assert detached['state'] == 'queued' and calls == []
    outcome = worker.run_once()
    from alt_deploy.setup_plans import private_read
    assert outcome['status'] == 'waiting_reboot', private_read(jobs.get(detached['job_id']).job_dir/'execution.json')
    assert len(calls) == 1
    result = setup.apply(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'successful' and result['reboot_required'] is True
    assert result == setup.status(result['run_id'])
    assert len(calls) == 1
    assert jobs.get(detached['job_id']).status['claimed'] is True


def test_sync_submits_and_waits_without_invoking_planner_in_cli(component_service, monkeypatch):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    plan = setup.plan(UUID, component_service[3]['login'], OU, 'core-apps')
    waiting = []
    def wait(job):
        assert calls == [] and jobs.get(job.job_id).state == 'queued'
        waiting.append(job.job_id)
        worker.run_once()
        return jobs.get(job.job_id)
    setup.job_waiter = wait
    result = setup.apply(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'successful' and len(calls) == len(waiting) == 1


@pytest.mark.parametrize('profile,signature', [('office-standard-v1', False), ('office-signature-v1', True)])
def test_full_setup_versioned_profiles(component_service, monkeypatch, profile, signature):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    # A fresh employee assignment can select a profile; existing bindings cannot be silently changed.
    (setup.assignments.root/(UUID+'.json')).unlink()
    plan = setup.plan(UUID, component_service[3]['login'], OU, profile)
    ids = [c['id'] for c in plan['payload']['components']]
    assert ('software.cryptopro' in ids) is signature
    assert plan['payload']['profile']['id'] == profile
    assert ConfigureRequest.from_mapping(plan['payload']['request'], expected_uuid=UUID,
                                        catalog=setup.catalog).software_profile == profile
    with pytest.raises(ControlError):
        ConfigureRequest.from_mapping(plan['payload']['request'], expected_uuid=UUID)
    setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    edit(setup.settings.ansible_project_dir, lambda c: c.update(version=2))
    setup.catalog = None
    result = worker.run_once()
    assert result['status'] == 'failed' and calls == []


def test_full_plan_own_reservation_cannot_hide_other_active_job(component_service, monkeypatch):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    plan = setup.plan(UUID, component_service[3]['login'], OU, 'core-apps')
    job = jobs.submit(plan, operation='full_setup')
    component_service[2].active_job = dict(job.status)
    assert worker.run_once()['status'] == 'waiting_reboot'
    assert len(calls) == 1


def test_new_unjoined_machine_can_plan_with_explicit_unresolved_sss_user(component_service, monkeypatch):
    setup, jobs, engine, worker, calls = full_fixture(component_service, monkeypatch)
    (setup.assignments.root/(UUID+'.json')).unlink()
    setup.directory.computer = lambda hostname: {'hostname': hostname, 'exists': False, 'objects': []}
    setup.probe = lambda machine, user: {'uuid': machine.uuid, 'hostname': machine.hostname, 'domain': '',
        'trust': False, 'sssd': False, 'user_lookup': False, 'local_duplicate': False, 'home_exists': False}
    component_service[4]['user'].update(uid=None, gid=None, home_exists=False, home_safe=False)
    plan = setup.plan(UUID, component_service[3]['login'], OU, 'office-standard-v1')
    assert plan['payload']['component_observed']['user']['uid'] is None
    assert plan['payload']['component_verification']['overall_status'] == 'unknown_requires_review'
    assert plan['payload']['execution_budget_seconds'] == 21600 and calls == []


def test_exited_cli_does_not_own_worker_process(component_service):
    import copy
    import multiprocessing
    from types import SimpleNamespace
    from test_setup_jobs import jobs_fixture
    service = component_service[0]
    good = copy.deepcopy(component_service[4]['components']['software.onlyoffice'])
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, plan, settings = jobs_fixture(component_service)
    context = multiprocessing.get_context('fork')
    cli_recv, cli_send = context.Pipe(False)
    def submit(): cli_send.send(service.apply(plan['plan_id'], plan['sha256']))
    cli_child = context.Process(target=submit)
    cli_child.start()
    assert cli_recv.poll(5)
    submitted = cli_recv.recv()
    cli_child.join(5)
    assert cli_child.exitcode == 0 and jobs.get(submitted['job_id']).state == 'queued'
    started_recv, started_send = context.Pipe(False)
    finish_recv, finish_send = context.Pipe(False)
    def run(plan, job):
        started_send.send(job.job_id)
        finish_recv.recv()
        component_service[4]['components']['software.onlyoffice'] = good
        return {'status': 'applied', 'changed': True, 'reboot_required': False}
    def work():
        engine = SetupExecutionEngine(settings, components=service,
            component_executor=SimpleNamespace(run=run), jobs=jobs)
        SetupWorker(settings, engine=engine, clock=service.clock).run_once()
    worker_child = context.Process(target=work)
    worker_child.start()
    try:
        assert started_recv.poll(5) and started_recv.recv() == submitted['job_id']
        assert not cli_child.is_alive() and worker_child.is_alive()
        assert jobs.get(submitted['job_id']).state == 'running'
        finish_send.send(True)
        worker_child.join(5)
        assert worker_child.exitcode == 0
        assert jobs.get(submitted['job_id']).state == 'successful'
    finally:
        if worker_child.is_alive():
            worker_child.terminate()
            worker_child.join(5)
