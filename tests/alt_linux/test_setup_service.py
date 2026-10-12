from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip('fcntl', reason='POSIX controller lifecycle lock')
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/alt-linux/control'))
from alt_deploy.errors import ControlError

UUID = '11111111-2222-3333-4444-555555555555'
OU = 'OU=Synthetic,DC=sosnadmin,DC=local'
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)


def scenario(tmp_path):
    from alt_deploy.setup import SetupService
    machine = SimpleNamespace(uuid=UUID, hostname='alt-a1-pc3', ip='192.0.2.10',
                              registration_state='ready', raw={'uuid': UUID, 'hostname': 'alt-a1-pc3'},
                              assignment=None, active_job=None)
    user = {'object_guid': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'login': 'synthetic.user',
            'upn': 'synthetic.user@sosnadmin.local', 'state': 'enabled', 'dn': 'CN=Synthetic,' + OU}
    observed = {'uuid': UUID, 'hostname': machine.hostname, 'domain': '', 'trust': False,
                'sssd': False, 'user_lookup': False, 'local_duplicate': False, 'home_exists': False}
    computer = {'hostname': machine.hostname, 'exists': False, 'objects': []}
    calls = []
    settings = SimpleNamespace(state_root=tmp_path, lock_file=tmp_path / 'lifecycle.lock')
    class Directory:
        def user(self, login):
            assert login == user['login']
            return copy.deepcopy(user)
        def ous(self):
            return [{'dn': OU, 'object_guid': 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'}]
        def computer(self, hostname):
            assert hostname == machine.hostname
            return copy.deepcopy(computer)
    class Machines:
        def resolve(self, identifier):
            assert identifier in (UUID, machine.hostname)
            return machine
        def get(self, identifier):
            assert identifier == UUID
            return machine
    class Planner:
        def preview(self, identifier, request):
            assert request.domain_test_user == request.assigned_domain_user == user['upn']
            return {'actions': request.actions(), 'deferred_actions': []}
        def start(self, identifier, request, **kwargs):
            calls.append(request.to_dict())
            observed.update(domain='sosnadmin.local', trust=True, sssd=True, user_lookup=True)
            computer.update(exists=True, objects=[{'object_guid': 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa',
                'dn': 'CN=alt-a1-pc3,' + OU, 'dns_hostname': 'alt-a1-pc3.sosnadmin.local'}])
            return {'run_id': 'c' * 32, 'status': 'successful', 'reboot_required': True,
                    'verification': {'domain_join': True, 'sssd': True, 'domain_user_lookup': True, 'group_policy': True}}
    def probe(machine, user):
        result = copy.deepcopy(observed)
        result['computer_identity'] = dict(computer['objects'][0],
            sam_account_name=machine.hostname + '$') if observed['trust'] and computer['objects'] else None
        return result
    service = SetupService(settings, directory=Directory(), machines=Machines(), planner=Planner(),
                           approved_ous=(OU,), probe=probe,
                           prerequisites=lambda request: {'ready': True}, clock=lambda: NOW)
    return service, machine, user, observed, computer, calls


def test_plan_is_nonmutating_and_apply_uses_selected_user(tmp_path):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(machine.hostname, user['login'], OU, 'base', 'none')
    assert calls == []
    assert not (tmp_path / 'domain-assignments').exists()
    assert plan['payload']['machine']['uuid'] == UUID
    assert plan['payload']['computer_ou'] == OU
    assert 'domain_join' in plan['payload']['changes']
    observed.update(domain='sosnadmin.local', trust=True, sssd=True, user_lookup=True)
    computer.update(exists=True, objects=[{'object_guid': 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa',
        'dn': 'CN=alt-a1-pc3,' + OU, 'dns_hostname': 'alt-a1-pc3.sosnadmin.local'}])
    # Changed trust must require a new plan before any execution.
    with pytest.raises(ControlError) as caught:
        service.apply(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'setup_plan_drift'
    assert calls == []
    observed.update(domain='', trust=False, sssd=False, user_lookup=False)
    computer.update(exists=False, objects=[])
    result = service.apply(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'successful'
    assert result['reboot_required'] is True
    assert len(calls) == 1
    assert service.status(result['run_id']) == result
    assert service.apply(plan['plan_id'], plan['sha256']) == result
    assert len(calls) == 1


@pytest.mark.parametrize('endpoint_changed', [False, True])
def test_confirmed_directory_endpoint_is_bound_and_forwarded(tmp_path, endpoint_changed):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    endpoint = ['ldap://dc-test.sosnadmin.local']
    service.prerequisites = lambda request: {'ready': True, 'directory_uri': endpoint[0]}
    original = service.planner.start
    seen = []
    def start(identifier, request, **kwargs):
        seen.append(kwargs)
        return original(identifier, request, **kwargs)
    service.planner.start = start
    plan = service.plan(machine.hostname, user['login'], OU, 'base', 'none')
    if endpoint_changed:
        endpoint[0] = 'ldap://other-test.sosnadmin.local'
        with pytest.raises(ControlError) as caught:
            service.apply(plan['plan_id'], plan['sha256'])
        assert caught.value.code == 'setup_plan_drift'
        assert seen == calls == []
    else:
        result = service.apply(plan['plan_id'], plan['sha256'])
        assert result['status'] == 'successful'
        assert seen[0]['setup_directory_uri'] == endpoint[0]


@pytest.mark.parametrize('change,code', [
    ('user_guid', 'setup_plan_drift'), ('login', 'setup_plan_drift'),
    ('ip', 'setup_plan_drift'), ('registration', 'setup_plan_drift'),
    ('job', 'setup_active_job'), ('local_assignment', 'assignment_conflict'),
])
def test_apply_drift_or_conflict_blocks_before_pipeline(tmp_path, change, code):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    if change == 'user_guid': user['object_guid'] = 'f' * 36
    elif change == 'login': user['upn'] = 'other@sosnadmin.local'
    elif change == 'ip': machine.ip = '192.0.2.11'
    elif change == 'registration': machine.raw['registered_at'] = 'later'
    elif change == 'job': machine.active_job = {'state': 'running'}
    elif change == 'local_assignment': machine.assignment = {'employee_login': user['login']}
    with pytest.raises(ControlError) as caught:
        service.apply(plan['plan_id'], plan['sha256'])
    assert caught.value.code == code
    assert calls == []


def test_unapproved_ou_and_existing_unjoined_computer_block(tmp_path):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    with pytest.raises(ControlError) as caught:
        service.plan(UUID, user['login'], 'OU=Other,DC=sosnadmin,DC=local', 'base', 'none')
    assert caught.value.code == 'setup_ou_not_approved'
    computer.update(exists=True, objects=[{'object_guid': 'c' * 36, 'dn': 'CN=alt-a1-pc3,' + OU}])
    with pytest.raises(ControlError) as caught:
        service.plan(UUID, user['login'], OU, 'base', 'none')
    assert caught.value.code == 'domain_computer_conflict'
    assert calls == []


def test_joined_machine_plan_skips_join_and_rejects_other_ou(tmp_path):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    observed.update(domain='sosnadmin.local', trust=True, sssd=True, user_lookup=True)
    computer.update(exists=True, objects=[{'object_guid': 'c' * 36, 'dn': 'CN=alt-a1-pc3,' + OU,
                                          'dns_hostname': 'alt-a1-pc3.sosnadmin.local'}])
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    assert 'domain_join' not in plan['payload']['changes']
    computer['objects'][0]['dn'] = 'CN=alt-a1-pc3,OU=Other,DC=sosnadmin,DC=local'
    with pytest.raises(ControlError) as caught:
        service.apply(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'domain_computer_conflict'
    assert calls == []


def test_computer_in_unapproved_child_ou_is_not_the_selected_ou(tmp_path):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    observed.update(domain='sosnadmin.local', trust=True, sssd=True, user_lookup=True)
    computer.update(exists=True, objects=[{'object_guid': 'c' * 36,
        'dn': 'CN=alt-a1-pc3,OU=UnapprovedChild,' + OU,
        'dns_hostname': 'alt-a1-pc3.sosnadmin.local'}])
    with pytest.raises(ControlError) as caught:
        service.plan(UUID, user['login'], OU, 'base', 'none')
    assert caught.value.code == 'domain_computer_conflict'


def test_postverify_failure_retains_configuration_result_and_reboot(tmp_path):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    original = service.planner.start
    def start(identifier, request, **kwargs):
        result = original(identifier, request, **kwargs)
        observed['sssd'] = False
        return result
    service.planner.start = start
    with pytest.raises(ControlError) as caught:
        service.apply(plan['plan_id'], plan['sha256'])
    run = service.status(caught.value.details['run_id'])
    assert run['status'] == 'failed'
    assert run['configuration_run_id'] == 'c' * 32
    assert run['reboot_required'] is True
    assert run['result']['status'] == 'successful'


def test_execution_failure_without_result_keeps_reboot_unknown(tmp_path):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    def start(*args, **kwargs):
        raise ControlError('configure_failed', 'Synthetic failure', 7, {'run_id': 'd' * 32})
    service.planner.start = start
    with pytest.raises(ControlError) as caught:
        service.apply(plan['plan_id'], plan['sha256'])
    run = service.status(caught.value.details['run_id'])
    assert run['configuration_result_unavailable'] is True
    assert run['reboot_required'] is None


def test_legacy_configure_cannot_bypass_domain_binding(tmp_path, monkeypatch):
    from alt_deploy.configure import ConfigurePlanner, ConfigureRequest
    from alt_deploy.setup_plans import private_create
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    binding = plan['payload']['binding']
    private_create(tmp_path / 'domain-assignments' / (UUID + '.json'), dict(binding, result='successful', revision=1,
        schema_version=1, run_id='setup-run-' + 'd' * 32, date=NOW.isoformat()))
    request = ConfigureRequest.from_mapping(plan['payload']['request'], expected_uuid=UUID)
    planner = ConfigurePlanner(service.settings, machines=service.machines)
    monkeypatch.setattr(planner, '_start_unlocked', lambda *args: pytest.fail('legacy bypass reached pipeline'), raising=False)
    with pytest.raises(ControlError) as caught:
        planner.start(UUID, request)
    assert caught.value.code == 'setup_assignment_managed'


def test_concurrent_apply_executes_confirmed_plan_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: service.apply(plan['plan_id'], plan['sha256']), range(2)))
    assert results[0] == results[1]
    assert len(calls) == 1


def test_source_prerequisite_drift_blocks_before_execution(tmp_path):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    service.prerequisites = lambda request: {'ready': True, 'source_sha256': 'changed'}
    with pytest.raises(ControlError) as caught:
        service.apply(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'setup_plan_drift'
    assert calls == []


@pytest.mark.parametrize('identity', ['object_guid', 'object_sid'])
def test_verify_rejects_replaced_ad_computer_identity(tmp_path, identity):
    service, machine, user, observed, computer, calls = scenario(tmp_path)
    plan = service.plan(UUID, user['login'], OU, 'base', 'none')
    service.apply(plan['plan_id'], plan['sha256'])
    assert service.verify(UUID)['status'] == 'successful'
    computer['objects'][0][identity] = ('ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb'
                                      if identity == 'object_guid' else 'S-1-5-21-100-200-300-999')
    assert service.verify(UUID)['status'] == 'failed'
    assert len(calls) == 1
