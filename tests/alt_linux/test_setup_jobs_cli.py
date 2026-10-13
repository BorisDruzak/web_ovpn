"""Operator job reads expose safe durable projections without AD or SSH."""
import io
import json

import pytest

from alt_deploy import cli
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_jobs import jobs_fixture


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
