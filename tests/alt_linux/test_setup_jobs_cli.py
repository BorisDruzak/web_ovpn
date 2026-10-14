"""Operator job reads expose safe durable projections without AD or SSH."""
import io
import json

import pytest

from alt_deploy import cli
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_jobs import jobs_fixture


def test_cancel_cli_retains_claim_and_is_idempotent_without_target_access(component_service, monkeypatch):
    from alt_deploy import setup_cli
    from alt_deploy.setup_plans import private_read
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    monkeypatch.setattr(setup_cli, 'SetupService', lambda *a: pytest.fail('Cancellation must not contact AD/SSH'))
    code, result = invoke(settings, 'cancel', job.job_id, '--confirm-plan-sha256', plan['sha256'])
    assert code == 0 and result['state'] == 'failed'
    assert result['target_changes_started'] is False
    assert jobs.get(job.job_id).stage == 'operator_cancelled_before_execution'
    before = {p.name: p.read_bytes() for p in job.job_dir.iterdir() if p.is_file()}
    assert invoke(settings, 'cancel', job.job_id, '--confirm-plan-sha256', plan['sha256']) == (code, result)
    assert {p.name: p.read_bytes() for p in job.job_dir.iterdir() if p.is_file()} == before
    assert private_read(jobs.claims/(plan['sha256']+'.json'))['job_id'] == job.job_id
    status = invoke(settings, 'status', job.job_id)[1]['job']
    assert status['state'] == 'failed' and status['error_code'] == 'operator_cancelled_before_execution'
    assert status['components']['software.onlyoffice']['changed'] is False
    assert invoke(settings, 'events', job.job_id)[1]['total'] == 0


def test_cancel_wrong_sha_does_not_consume_worker_claim(component_service):
    from alt_deploy.setup_jobs_view import SetupJobsService
    from alt_deploy.errors import ControlError
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    before = (job.job_dir/'status.json').read_bytes()
    service = SetupJobsService(settings, jobs=jobs)
    assert hasattr(service, 'cancel'), 'Operator cancellation API is missing'
    with pytest.raises(ControlError) as error: service.cancel(job.job_id, 'f'*64)
    assert error.value.code == 'setup_cancel_plan_mismatch'
    assert (job.job_dir/'status.json').read_bytes() == before


@pytest.mark.parametrize('state', ['preflight', 'running', 'unknown_requires_review'])
def test_cancel_never_changes_claimed_or_unknown_job(component_service, state):
    from alt_deploy.setup_jobs_view import SetupJobsService
    from alt_deploy.setup_worker import process_identity
    from alt_deploy.errors import ControlError
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    jobs.claim(job.job_id, process_identity(settings))
    if state != 'preflight': jobs.transition(job.job_id, state)
    before = (job.job_dir/'status.json').read_bytes()
    service = SetupJobsService(settings, jobs=jobs)
    assert hasattr(service, 'cancel'), 'Operator cancellation API is missing'
    with pytest.raises(ControlError) as error: service.cancel(job.job_id, plan['sha256'])
    assert error.value.code == 'setup_cancel_not_permitted'
    assert (job.job_dir/'status.json').read_bytes() == before


def test_cancel_crash_after_claim_is_reconciled_unknown_without_replay(component_service, monkeypatch):
    from alt_deploy import setup_jobs_view
    from alt_deploy.setup_worker import SetupWorker
    from alt_deploy.errors import ControlError
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    service = setup_jobs_view.SetupJobsService(settings, jobs=jobs)
    assert hasattr(service, 'cancel'), 'Operator cancellation API is missing'
    monkeypatch.setattr(setup_jobs_view, 'publish', lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt): service.cancel(job.job_id, plan['sha256'])
    assert jobs.get(job.job_id).status['claimed'] and jobs.get(job.job_id).state == 'preflight'
    assert not (job.job_dir/'execution.json').exists()
    worker = SetupWorker(settings, process_probe=lambda identity: False)
    assert worker.reconcile()['changed'][0]['state'] == 'unknown_requires_review'
    with pytest.raises(ControlError): service.cancel(job.job_id, plan['sha256'])
    assert worker.run_once()['status'] == 'blocked'


def invoke(settings, *args):
    output = io.StringIO()
    code = cli.main(['--json', 'setup', 'jobs', *args], settings=settings, stdout=output)
    return code, json.loads(output.getvalue())


def test_jobs_cli_reads_never_construct_directory_or_contact_workstation(component_service, monkeypatch):
    from alt_deploy import setup_cli
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    monkeypatch.setattr(setup_cli, 'SetupService', lambda *a: pytest.fail('Job read cannot construct AD'))
    for args, operation in [(('list', '--machine', job.machine_uuid), 'setup_jobs_list'),
                            (('status', job.job_id), 'setup_job_status'),
                            (('events', job.job_id), 'setup_job_events')]:
        code, result = invoke(settings, *args)
        assert code == 0 and result['schema_version'] == 2 and result['operation'] == operation
        assert 'request' not in str(result) and 'ansible.log' not in str(result)
    assert invoke(settings, 'status', job.job_id)[1]['job']['state'] == 'queued'


def test_cli_no_arbitrary_execution_inputs_or_abbreviations():
    for command in ['list', 'status', 'events', 'verify-continuation']:
        base = ['setup', 'jobs', command]+([] if command == 'list' else ['job-test'])
        for suffix in [['--vars-file', 'payload'], ['--role', 'domain_join'], ['--command', 'arbitrary'], ['--mach', 'uuid']]:
            with pytest.raises(SystemExit): cli.build_parser().parse_args(base+suffix)


def test_operator_flow_only_uses_workstationctl(component_service, monkeypatch):
    from alt_deploy import component_setup
    from alt_deploy.setup_execution import SetupExecutionEngine
    from alt_deploy.setup_worker import SetupWorker
    service = component_service[0]
    monkeypatch.setattr(component_setup, 'ComponentSetupService', lambda settings: service)
    settings = service.settings
    def command(*args):
        output = io.StringIO()
        assert cli.main(['--json', 'setup', *args], settings=settings, stdout=output) == 0
        return json.loads(output.getvalue())
    assert command('components', 'list')['catalog_version'] == 1
    plan = command('component', 'plan', '--machine', component_service[2].uuid, '--component', 'software.onlyoffice')
    applied = command('component', 'apply', plan['plan_id'], '--confirm-sha256', plan['sha256'])
    engine = SetupExecutionEngine(settings, components=service)
    assert SetupWorker(settings, engine=engine).run_once()['status'] == 'successful'
    status = command('jobs', 'status', applied['job_id'])
    assert status['job']['state'] == 'successful'
    assert status['job']['components']['software.onlyoffice']['changed'] is False
    assert command('jobs', 'events', applied['job_id'])['total'] == 0
    assert command('component', 'verify', '--machine', component_service[2].uuid,
                   '--component', 'software.onlyoffice')['overall_status'] == 'successful'
    assert command('component', 'plan', '--machine', component_service[2].uuid,
                   '--component', 'software.onlyoffice')['payload']['action'] == 'noop'
