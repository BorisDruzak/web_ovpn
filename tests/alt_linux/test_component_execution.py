"""A component executor selects one approved role and never invokes domain join."""
import subprocess

import pytest
import yaml

from alt_deploy.setup_execution import ComponentExecutor, catalog_selection
from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.errors import ControlError
from test_setup_jobs import jobs_fixture
from test_component_setup import component_service
from test_component_catalog import project, SOURCE


def test_catalog_drives_legacy_order_and_component_role_without_dependencies():
    catalog = ComponentCatalog.load(SOURCE)
    core = catalog_selection(catalog, profile='core-apps')
    assert core['selected_software_components'] == ['browser', 'onlyoffice', 'nextcloud_desktop', 'directum',
                                                  'cryptopro', 'cryptopro_cades', 'gosuslugi_plugin']
    assert catalog_selection(catalog, profile='base')['selected_software_components'] == []
    selected = catalog_selection(catalog, component_id='software.onlyoffice')
    assert selected['execution_components'] == [catalog.component('software.onlyoffice')]
    assert selected['selected_software_components'] == ['onlyoffice']
    assert 'domain_join' not in str(selected)
    with pytest.raises(ControlError): catalog_selection(catalog, component_id='domain.ready')


def test_noop_never_contacts_workstation_or_loads_vault(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    executor = ComponentExecutor(settings, ComponentCatalog.load(settings.ansible_project_dir),
                                 runner=lambda *a, **k: pytest.fail('noop cannot execute'))
    result = executor.run(plan, job)
    assert result['changed'] is False and result['status'] == 'noop'


def test_executor_uses_fixed_playbook_and_safe_result_not_log_output(component_service, tmp_path):
    service = component_service[0]
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    settings.ansible_playbook_path = tmp_path/'ansible-playbook'
    settings.ansible_playbook_path.write_text('synthetic')
    calls = []
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        from alt_deploy.setup_plans import private_create
        private_create(job.job_dir/'component-result.json', {'schema_version': 1, 'job_id': job.job_id,
            'plan_sha256': plan['sha256'], 'machine_uuid': job.machine_uuid, 'component_id': 'software.onlyoffice',
            'component_version': 1, 'status': 'applied', 'reboot_required': False})
        from alt_deploy.setup_events import SetupEventStore
        events = SetupEventStore(settings, clock=jobs.clock)
        for event_type, code in [('component_start', 'started'), ('component_completed', 'completed')]:
            events.append(job.job_id, {'schema_version': 1, 'component_id': 'software.onlyoffice', 'component_version': 1,
                'stage': 'apply', 'task_id': 'component', 'type': event_type, 'changed': False, 'code': code})
        return subprocess.CompletedProcess(command, 0)
    executor = ComponentExecutor(settings, ComponentCatalog.load(settings.ansible_project_dir), runner=runner)
    result = executor.run(plan, job)
    assert result['status'] == 'applied'
    command, options = calls[0]
    assert command[-1].endswith('/playbooks/04-setup-component.yml')
    assert all('03-configure' not in part and 'domain_join' not in part for part in command)
    assert options['shell'] is False and options['env']['ANSIBLE_STDOUT_CALLBACK'] == 'alt_setup_events'
    variables = yaml.safe_load((job.job_dir/'component-vars.json').read_text())
    assert variables['setup_component_id'] == 'software.onlyoffice'
    assert 'vault_cryptopro_license' not in variables


@pytest.mark.parametrize('failure', ['stderr', 'missing_result', 'bad_result', 'missing_completion_event'])
def test_missing_or_failed_result_is_safe_and_never_success(component_service, tmp_path, failure):
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    settings.ansible_playbook_path = tmp_path/'ansible-playbook'
    settings.ansible_playbook_path.touch()
    sentinel = 'SENTINEL-secret-output'
    def runner(command, **kwargs):
        kwargs['stdout'].write(sentinel+'\n')
        if failure == 'bad_result': (job.job_dir/'component-result.json').write_text('{"password":"'+sentinel+'"}')
        if failure == 'missing_completion_event':
            from alt_deploy.setup_plans import private_create
            private_create(job.job_dir/'component-result.json', {'schema_version': 1, 'job_id': job.job_id,
                'plan_sha256': plan['sha256'], 'machine_uuid': job.machine_uuid, 'component_id': 'software.onlyoffice',
                'component_version': 1, 'status': 'applied', 'reboot_required': False})
        return subprocess.CompletedProcess(command, 1 if failure == 'stderr' else 0)
    executor = ComponentExecutor(settings, ComponentCatalog.load(settings.ansible_project_dir), runner=runner)
    with pytest.raises(ControlError) as caught: executor.run(plan, job)
    assert sentinel not in str(caught.value) and sentinel not in str(caught.value.details)


def test_fixed_playbook_preflight_precedes_selected_role_and_has_no_critical_adapter():
    text = (SOURCE/'playbooks/04-setup-component.yml').read_text()
    fragment = (SOURCE/'playbooks/tasks/setup_component_execution.yml').read_text()
    assert 'setup_component_execution.yml' in text
    assert fragment.index('configure_component_preflight.yml') < fragment.index('ansible.builtin.include_role:')
    assert 'domain_join' not in text+fragment and 'configure_critical_phase.yml' not in text+fragment
