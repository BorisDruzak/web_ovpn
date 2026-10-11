from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_assignments import DomainAssignmentStore
from alt_deploy.setup_plans import SetupPlanStore, private_create, private_read, private_replace

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
UUID = '11111111-2222-3333-4444-555555555555'
USER_GUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
OU = 'OU=Synthetic,DC=sosnadmin,DC=local'
RUN = 'setup-run-' + 'a' * 32
CONFIG = 'b' * 32


def scenario(root):
    from alt_deploy.configure import ConfigureRequest
    user = {'object_guid': USER_GUID, 'object_sid': 'S-1-5-21-111-222-333-1001',
            'login': 'synthetic.user', 'upn': 'synthetic.user@sosnadmin.local', 'state': 'enabled'}
    request = ConfigureRequest.from_mapping({
        'machine_uuid': UUID, 'final_hostname': 'alt-a1-pc3', 'hostname_mode': 'verify',
        'profile': 'standard-domain', 'domain': 'sosnadmin.local', 'realm': 'SOSNADMIN.LOCAL',
        'workgroup': 'SOSNADM', 'computer_ou': OU, 'domain_test_user': user['upn'],
        'assigned_domain_user': user['upn'], 'software_profile': 'core-apps', 'remote_access_profile': 'none',
    }, expected_uuid=UUID)
    binding = DomainAssignmentStore.identity_binding(UUID, user, OU, 'core-apps', 'none')
    payload = {'machine': {'uuid': UUID, 'hostname': 'alt-a1-pc3', 'ip': '192.0.2.10',
                           'registration_sha256': 'c' * 64},
               'user': user, 'request': request.to_dict(), 'binding': binding,
               'computer_ou': OU, 'ou_identity': {'dn': OU, 'object_guid': 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff'},
               'computer': {'hostname': 'alt-a1-pc3', 'exists': False, 'objects': []},
               'observed': {'uuid': UUID, 'hostname': 'alt-a1-pc3', 'domain': '', 'trust': False,
                            'sssd': False, 'user_lookup': False, 'local_duplicate': False, 'home_exists': False},
               'existing_assignment': None, 'changes': ['domain_join']}
    plan = SetupPlanStore(root, clock=lambda: NOW).create(payload)
    result = {'schema_version': 1, 'machine_uuid': UUID, 'hostname': 'alt-a1-pc3',
              'profile': 'standard-domain', 'status': 'failed', 'phase': 'domain_join',
              'error': {'class': 'fatal-invariant', 'code': 'configure_critical_phase_failed',
                        'safe_message': 'Critical phase configuration failed'},
              'retryable': False, 'recovered': False, 'reboot_required': True,
              'components': {}, 'verification': {'group_policy': False}}
    date = (NOW + timedelta(seconds=1)).isoformat()
    run = {'schema_version': 1, 'run_id': RUN, 'plan_id': plan['plan_id'],
           'plan_sha256': plan['sha256'], 'machine_uuid': UUID, 'status': 'failed',
           'created_at': date, 'finished_at': (NOW + timedelta(seconds=2)).isoformat(),
           'partial_failure': True, 'configuration_run_id': CONFIG, 'result': result,
           'reboot_required': True, 'error': {'code': 'domain_join_failed', 'message': 'Synthetic failed setup'}}
    paths = {'plan': root / 'setup-plans' / (plan['plan_id'] + '.json'),
             'run': root / 'setup-runs' / (RUN + '.json'),
             'index': root / 'setup-plan-runs' / (plan['plan_id'] + '.json'),
             'binding': root / 'domain-assignments' / (UUID + '.json'),
             'configuration_result': root / 'configure-runs' / CONFIG / 'result.json'}
    private_create(paths['run'], run)
    private_create(paths['index'], {'run_id': RUN})
    private_create(paths['configuration_result'], result)
    DomainAssignmentStore(root).write(binding, run_id=RUN, result='failed', date=date, revision=1)
    return plan, paths


def load(root):
    from alt_deploy.setup_recovery_history import RecoveryHistoryStore
    return RecoveryHistoryStore(root).load(RUN)


def test_expired_original_plan_can_be_read_as_history_without_replay(tmp_path):
    plan, paths = scenario(tmp_path)
    before = {label: path.read_bytes() for label, path in paths.items()}
    entries_before = set(tmp_path.iterdir())
    with pytest.raises(ControlError) as caught:
        SetupPlanStore(tmp_path, clock=lambda: NOW + timedelta(days=1)).load(plan['plan_id'], plan['sha256'])
    assert caught.value.code == 'setup_plan_expired'
    history = load(tmp_path)
    assert history['identity']['failed_run_id'] == RUN
    assert history['identity']['machine_uuid'] == UUID
    assert history['identity']['employee_guid'] == USER_GUID
    assert history['raw_files'] == before
    assert {label: path.read_bytes() for label, path in paths.items()} == before
    assert set(tmp_path.iterdir()) == entries_before


@pytest.mark.parametrize('label,key,value', [
    ('run', 'run_id', 'setup-run-' + 'd' * 32),
    ('run', 'machine_uuid', USER_GUID),
    ('run', 'status', 'successful'),
    ('run', 'partial_failure', 1),
    ('run', 'configuration_run_id', '../outside'),
    ('run', 'plan_sha256', 'd' * 64),
    ('run', 'created_at', (NOW + timedelta(minutes=30)).isoformat()),
    ('run', 'finished_at', NOW.isoformat()),
    ('run', 'configuration_result_unavailable', True),
    ('run', 'error', {'code': 'domain_computer_conflict', 'message': 'Synthetic conflict'}),
    ('index', 'run_id', 'setup-run-' + 'd' * 32),
    ('binding', 'result', 'running'),
    ('binding', 'run_id', 'setup-run-' + 'd' * 32),
    ('binding', 'object_guid', UUID),
    ('binding', 'object_sid', 'S-1-5-21-111-222-333-1002'),
    ('binding', 'computer_ou', 'OU=Other,DC=sosnadmin,DC=local'),
    ('binding', 'software_profile', 'base'),
    ('binding', 'revision', 2),
    ('binding', 'date', NOW.isoformat()),
    ('configuration_result', 'status', 'successful'),
    ('configuration_result', 'phase', 'software'),
    ('configuration_result', 'machine_uuid', USER_GUID),
    ('configuration_result', 'recovered', True),
])
def test_cross_document_drift_is_refused(tmp_path, label, key, value):
    _, paths = scenario(tmp_path)
    document = private_read(paths[label])
    document[key] = value
    private_replace(paths[label], document)
    with pytest.raises(ControlError) as caught:
        load(tmp_path)
    assert caught.value.code == 'recovery_history_invalid'
    assert not (tmp_path / 'setup-recovery-attempts').exists()


@pytest.mark.parametrize('field,value', [
    ('computer', {'hostname': 'alt-a1-pc3', 'exists': True, 'objects': [{}]}),
    ('existing_assignment', {}),
    ('changes', []),
    ('computer_ou', 'OU=Other,DC=sosnadmin,DC=local'),
])
def test_rehashed_plan_without_first_join_provenance_is_refused(tmp_path, field, value):
    from alt_deploy.setup_plans import digest
    _, paths = scenario(tmp_path)
    plan = private_read(paths['plan'])
    plan['payload'][field] = value
    plan['content_sha256'] = digest(plan['payload'])
    sha = digest({key: value for key, value in plan.items() if key not in ('sha256', 'plan_id')})
    plan.update(sha256=sha, plan_id='setup-' + sha)
    private_create(paths['plan'].parent / (plan['plan_id'] + '.json'), plan)
    private_create(paths['index'].parent / (plan['plan_id'] + '.json'), {'run_id': RUN})
    run = private_read(paths['run'])
    run.update(plan_id=plan['plan_id'], plan_sha256=sha)
    private_replace(paths['run'], run)
    with pytest.raises(ControlError) as caught:
        load(tmp_path)
    assert caught.value.code == 'recovery_history_invalid'


@pytest.mark.parametrize('label', ['plan', 'run', 'index', 'binding', 'configuration_result'])
def test_missing_protected_historical_document_is_refused(tmp_path, label):
    _, paths = scenario(tmp_path)
    paths[label].unlink()
    with pytest.raises(ControlError) as caught:
        load(tmp_path)
    assert caught.value.code == 'recovery_history_invalid'
