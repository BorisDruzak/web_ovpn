from __future__ import annotations

import copy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest, private_create
from test_setup_recovery_history import NOW, OU, RUN, UUID, scenario as historical_scenario

COMPUTER_GUID = 'cccccccc-dddd-eeee-ffff-111111111111'


def scenario(root):
    plan, paths = historical_scenario(root)
    user = copy.deepcopy(plan['payload']['user'])
    machine = SimpleNamespace(uuid=UUID, hostname='alt-a1-pc3', ip='192.0.2.10',
        registration_state='ready', assignment=None, active_job=None, raw={'uuid': UUID, 'hostname': 'alt-a1-pc3'})
    computer = {'object_guid': COMPUTER_GUID, 'object_sid': 'S-1-5-21-111-222-333-1002',
        'dn': 'CN=alt-a1-pc3,' + OU, 'dns_hostname': 'alt-a1-pc3.sosnadmin.local',
        'sam_account_name': 'alt-a1-pc3$', 'when_created': (NOW + timedelta(seconds=1)).isoformat(),
        'dc': {'is_writable': True}, 'kvno': 2}
    ou = copy.deepcopy(plan['payload']['ou_identity'])
    observed = copy.deepcopy(plan['payload']['observed'])
    observed['domain'] = 'sosnadmin.local'
    facts = {'snapshot': {'uuid': UUID, 'hostname': 'alt-a1-pc3', 'clock_synchronized': True,
        'incompatible_processes': [], 'keytab_present': False, 'files': {}, 'tools': {}},
        'probe_source_sha256': 'd' * 64}
    facts['snapshot_sha256'] = digest(facts['snapshot'])
    ready = {'ready': True, 'source_sha256': 'e' * 64}
    calls = []
    class Directory:
        def user(self, login):
            calls.append(('user', login)); return user
        def ous(self):
            calls.append(('ous',)); return [ou]
        def inspect_computer(self, hostname, guid):
            calls.append(('computer', hostname, guid)); return computer
    class Runtime:
        def probe(self, m, u):
            calls.append(('probe',)); return observed
        def facts(self, m):
            calls.append(('facts',)); return facts
        def prerequisites(self, request):
            calls.append(('prerequisites',)); return ready
    def build():
        from alt_deploy.setup_recovery_planning import RecoveryPlanningService
        return RecoveryPlanningService(SimpleNamespace(state_root=root), directory=Directory(),
            machines=SimpleNamespace(resolve=lambda identifier: machine), runtime=Runtime(),
            approved_ous=[OU], clock=lambda: NOW + timedelta(days=1))
    return build, paths, machine, user, computer, ou, observed, facts, ready, calls


def test_plan_preserves_originals_and_proposes_one_non_executable_operation(tmp_path):
    build, paths, *rest = scenario(tmp_path)
    before = {key: path.read_bytes() for key, path in paths.items()}
    result = build().plan(RUN, COMPUTER_GUID)
    payload = result['payload']
    assert result['plan_id'].startswith('recovery-')
    assert payload['failed_run_id'] == RUN and payload['machine_uuid'] == UUID
    assert payload['computer_guid'] == COMPUTER_GUID
    assert payload['operation'] == 'replace_selected_machine_password_once'
    assert payload['execution_available'] is False
    assert payload['computer_ou'] == OU
    assert payload['machine']['registration_sha256'] == digest(rest[0].raw)
    assert payload['evidence_sha256']
    assert {key: path.read_bytes() for key, path in paths.items()} == before
    assert not (tmp_path / 'setup-recovery-attempts').exists()
    assert not (tmp_path / 'workstationctl.lock').exists()


@pytest.mark.parametrize('change', ['machine_uuid', 'hostname', 'not_ready', 'active_job', 'assignment',
    'user_guid', 'user_sid', 'user_login', 'disabled', 'ou_guid', 'ou_missing', 'computer_guid',
    'computer_ou', 'computer_created_before', 'computer_created_after', 'computer_rodc',
    'trust', 'foreign_domain', 'local_duplicate', 'probe_uuid', 'facts_uuid', 'facts_digest',
    'clock', 'process', 'prerequisites'])
def test_drift_and_unsafe_state_refuse_without_plan_or_attempt(tmp_path, change):
    build, paths, machine, user, computer, ou, observed, facts, ready, calls = scenario(tmp_path)
    if change == 'machine_uuid': machine.uuid = COMPUTER_GUID
    elif change == 'hostname': machine.hostname = 'alt-a1-pc4'
    elif change == 'not_ready': machine.registration_state = 'stale'
    elif change == 'active_job': machine.active_job = {'id': 'synthetic'}
    elif change == 'assignment': machine.assignment = {'id': 'synthetic'}
    elif change == 'user_guid': user['object_guid'] = COMPUTER_GUID
    elif change == 'user_sid': user['object_sid'] = computer['object_sid']
    elif change == 'user_login': user['login'] = 'other.user'
    elif change == 'disabled': user['state'] = 'disabled'
    elif change == 'ou_guid': ou['object_guid'] = COMPUTER_GUID
    elif change == 'ou_missing': ou['dn'] = 'OU=Other,DC=sosnadmin,DC=local'
    elif change == 'computer_guid': computer['object_guid'] = UUID
    elif change == 'computer_ou': computer['dn'] = 'CN=alt-a1-pc3,OU=Other,DC=sosnadmin,DC=local'
    elif change == 'computer_created_before': computer['when_created'] = NOW.isoformat()
    elif change == 'computer_created_after': computer['when_created'] = (NOW + timedelta(seconds=3)).isoformat()
    elif change == 'computer_rodc': computer['dc']['is_writable'] = False
    elif change == 'trust': observed['trust'] = True
    elif change == 'foreign_domain': observed['domain'] = 'other.example'
    elif change == 'local_duplicate': observed['local_duplicate'] = True
    elif change == 'probe_uuid': observed['uuid'] = COMPUTER_GUID
    elif change == 'facts_uuid': facts['snapshot']['uuid'] = COMPUTER_GUID
    elif change == 'facts_digest': facts['snapshot_sha256'] = 'f' * 64
    elif change == 'clock': facts['snapshot']['clock_synchronized'] = False
    elif change == 'process': facts['snapshot']['incompatible_processes'] = ['net']
    else: ready['ready'] = False
    if change != 'facts_digest': facts['snapshot_sha256'] = digest(facts['snapshot'])
    before = {key: path.read_bytes() for key, path in paths.items()}
    with pytest.raises(ControlError): build().plan(RUN, COMPUTER_GUID)
    assert not (tmp_path / 'setup-recovery-plans').exists()
    assert not (tmp_path / 'setup-recovery-attempts').exists()
    assert {key: path.read_bytes() for key, path in paths.items()} == before


def test_existing_attempt_even_invalid_prevents_new_plan(tmp_path):
    from alt_deploy.setup_recovery import RecoveryAttemptStore
    build, _, *rest = scenario(tmp_path)
    claim = RecoveryAttemptStore(tmp_path).claim_path(RUN, COMPUTER_GUID)
    private_create(claim, {'interrupted': True})
    with pytest.raises(ControlError) as caught: build().plan(RUN, COMPUTER_GUID)
    assert caught.value.code == 'recovery_attempt_reserved'
    assert rest[-1] == []
    assert not (tmp_path / 'setup-recovery-plans').exists()


@pytest.mark.parametrize('drift', ['registry', 'history', 'attempt'])
def test_state_drift_during_workstation_reads_prevents_plan(tmp_path, drift):
    from alt_deploy.setup_plans import private_read, private_replace
    build, paths, machine, *rest = scenario(tmp_path)
    service = build()
    initial = service.runtime.facts
    def changed(machine_record):
        result = initial(machine_record)
        if drift == 'registry': machine.raw['revision'] = 2
        elif drift == 'history':
            document = private_read(paths['run']); document['reboot_required'] = False
            private_replace(paths['run'], document)
        else:
            private_create(service.attempts.claim_path(RUN, COMPUTER_GUID), {'interrupted': True})
        return result
    service.runtime.facts = changed
    with pytest.raises(ControlError): service.plan(RUN, COMPUTER_GUID)
    assert not (tmp_path / 'setup-recovery-plans').exists()
