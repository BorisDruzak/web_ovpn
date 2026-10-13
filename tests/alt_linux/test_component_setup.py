"""Component plans preserve actual Setup identity safeguards without applying Setup."""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_setup import ComponentSetupService
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_create
from test_component_catalog import project
from test_component_verification import evidence, UUID
from test_setup_service import scenario, OU


@pytest.fixture
def component_service(tmp_path, project, monkeypatch):
    from alt_deploy import component_setup
    setup, machine, user, observed, computer, calls = scenario(tmp_path/'state')
    user['object_sid'] = 'S-1-5-21-1-2-3-1001'
    observed.update(domain='sosnadmin.local', trust=True, sssd=True, user_lookup=True, home_exists=True)
    computer.update(exists=True, objects=[{'object_guid': 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa',
        'object_sid': 'S-1-5-21-1-2-3-2001', 'dn': 'CN=alt-a1-pc3,'+OU,
        'dns_hostname': 'alt-a1-pc3.sosnadmin.local'}])
    run_id = 'setup-run-'+'a'*32
    binding = setup.assignments.identity_binding(UUID, user, OU, 'core-apps', 'none')
    setup.assignments.write(binding, run_id=run_id, result='successful', date='2026-10-13T12:00:00+00:00', revision=1)
    private_create(setup._run_path(run_id), {'schema_version': 1, 'run_id': run_id, 'status': 'successful',
                                           'computer': copy.deepcopy(computer)})
    setup.settings.ansible_project_dir = project
    setup.settings.known_hosts_file = tmp_path/'known'
    setup.settings.private_key_file = tmp_path/'key'
    catalog = ComponentCatalog.load(project)
    state = evidence(catalog)
    date = [datetime(2026, 10, 13, 12, tzinfo=timezone.utc)]
    def binding_probe(*args, **kwargs):
        return {'host_public_sha256': '1'*64, 'controller_public_sha256': '2'*64}
    monkeypatch.setattr(component_setup, 'ssh_binding', binding_probe)
    probe = SimpleNamespace(observe=lambda *a, **k: copy.deepcopy(state))
    service = ComponentSetupService(setup.settings, setup=setup, probe=probe, clock=lambda: date[0],
                                    preflight=lambda c: {'ready': True})
    return service, setup, machine, user, state, date, calls


@pytest.mark.parametrize('change,action', [('ready', 'noop'), ('missing', 'install'), ('drifted', 'repair'), ('unknown', 'blocked'), ('dependency', 'blocked')])
def test_component_plan_noop_missing_drift_unknown(component_service, change, action):
    service, setup, machine, _, state, _, calls = component_service
    fact = state['components']['software.onlyoffice']
    if change == 'missing': fact.update(packages=[], executable=False)
    elif change == 'drifted': fact['packages'][0]['evr'] = '0.0-alt1'
    elif change == 'unknown': fact['error_code'] = 'probe_unavailable'
    elif change == 'dependency': state['components']['domain.ready']['checks']['ready'] = False
    before = setup.assignments.get(UUID)
    plan = service.plan(UUID, 'software.onlyoffice')
    assert plan['schema_version'] == 2
    assert plan['operation'] == 'component_plan'
    assert plan['payload']['action'] == action
    assert plan['plan_id'].startswith('setup-component-')
    assert setup.assignments.get(UUID) == before
    assert not setup.settings.lock_file.exists()
    assert calls == []
    assert not (setup.settings.state_root/'jobs').exists()


@pytest.mark.parametrize('drift', ['user', 'computer', 'registration', 'ssh', 'source', 'catalog', 'facts', 'home', 'busy'])
def test_component_plan_drift_blocks_before_any_mutation(component_service, drift, monkeypatch):
    service, setup, machine, user, state, _, calls = component_service
    plan = service.plan(UUID, 'software.onlyoffice')
    if drift == 'user': user['object_guid'] = 'aaaaaaaa-bbbb-cccc-dddd-ffffffffffff'
    elif drift == 'computer': state['machine']['uuid'] = '22222222-2222-3333-4444-555555555555'
    elif drift == 'registration': machine.raw['new_revision'] = 2
    elif drift == 'ssh': monkeypatch.setattr('alt_deploy.component_setup.ssh_binding', lambda *a, **k: {'host_public_sha256': '3'*64})
    elif drift == 'source': (setup.settings.ansible_project_dir/'roles/software_onlyoffice/new-source.txt').write_text('source changed')
    elif drift == 'catalog':
        from test_component_catalog import edit
        edit(setup.settings.ansible_project_dir, lambda c: c.update(version=2))
    elif drift == 'facts': state['components']['software.onlyoffice']['packages'][0]['evr'] = '0.0-alt1'
    elif drift == 'home': state['user']['home_safe'] = False
    elif drift == 'busy': state['package_manager']['processes_absent'] = False
    with pytest.raises(ControlError):
        service.validate(plan['plan_id'], plan['sha256'])
    assert calls == []


def test_observation_time_is_not_drift_but_ttl_sha_and_active_job_are(component_service):
    service, _, machine, _, state, date, _ = component_service
    plan = service.plan(UUID, 'software.onlyoffice')
    state['observed_at'] = '2026-10-13T12:01:00+00:00'
    assert service.validate(plan['plan_id'], plan['sha256'])['action'] == 'noop'
    with pytest.raises(ControlError): service.validate(plan['plan_id'], 'f'*64)
    machine.active_job = {'job_id': 'another-job'}
    with pytest.raises(ControlError): service.validate(plan['plan_id'], plan['sha256'])
    machine.active_job = None
    date[0] += timedelta(minutes=30)
    with pytest.raises(ControlError) as caught: service.validate(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'setup_plan_expired'


def test_protected_domain_and_unknown_target_cannot_create_executable_plan(component_service):
    service, setup, machine, _, _, _, _ = component_service
    assert service.plan(UUID, 'domain.ready')['payload']['action'] == 'blocked'
    machine.registration_state = 'pending'
    with pytest.raises(ControlError): service.plan(UUID, 'software.onlyoffice')
    with pytest.raises(ControlError): service.plan(UUID, 'software.unpublished')


def test_own_queued_reservation_must_match_plan_and_identity(component_service):
    service, _, machine, _, _, _, _ = component_service
    plan = service.plan(UUID, 'software.onlyoffice')
    machine.active_job = {'schema_version': 2, 'kind': 'setup', 'job_id': 'job-own',
                          'plan_id': plan['plan_id'], 'plan_sha256': plan['sha256'], 'machine_uuid': UUID}
    assert service.validate(plan['plan_id'], plan['sha256'], own_job_id='job-own')['action'] == 'noop'
    machine.active_job['plan_id'] = 'different'
    with pytest.raises(ControlError): service.validate(plan['plan_id'], plan['sha256'], own_job_id='job-own')


def test_selected_cryptopro_secret_is_checked_without_exposing_value(component_service, monkeypatch):
    service, _, _, _, _, _, _ = component_service
    from alt_deploy.vault import VaultHealthChecker
    component = ComponentCatalog.load(service.settings.ansible_project_dir).component('software.cryptopro')
    service.catalog = SimpleNamespace(artifact=lambda *a: {'source': 'alt-repository'})
    monkeypatch.setattr(VaultHealthChecker, '_build_checks', lambda *a: {'protected': True})
    monkeypatch.setattr(VaultHealthChecker, '_decrypt', lambda *a: 'vault_cryptopro_license: ""\n')
    result = service._preflight(component)
    assert result == {'ready': False, 'error_code': 'component_secret_unavailable'}


def test_compliant_noop_does_not_require_an_installation_artifact(component_service):
    service, _, _, _, _, _, _ = component_service
    calls = []
    def unavailable(component):
        calls.append(component['id'])
        return {'ready': False, 'error_code': 'component_artifact_unverified'}
    service.preflight = unavailable
    assert service.plan(UUID, 'software.onlyoffice')['payload']['action'] == 'noop'
    assert calls == []


def test_existing_assignment_cannot_bypass_current_approved_ou(component_service):
    service, setup, _, _, _, _, _ = component_service
    setup.approved_ous = ()
    with pytest.raises(ControlError) as caught:
        service.plan(UUID, 'software.onlyoffice')
    assert caught.value.code == 'setup_ou_not_approved'
