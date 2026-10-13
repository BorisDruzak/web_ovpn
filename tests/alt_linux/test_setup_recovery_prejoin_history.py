"""Recovery reads a bounded prejoin-timeout chain without admitting replay."""
import copy
import hashlib
from datetime import timedelta

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import SetupPlanStore, digest, private_create, private_read, private_replace
from alt_deploy.setup_recovery import EVIDENCE_LABELS
from alt_deploy.setup_recovery_history import RecoveryHistoryStore
from alt_deploy.setup_assignments import DomainAssignmentStore
from alt_deploy.setup_recovery_resolution import RecoveryResolutionStore
from types import SimpleNamespace
from test_setup_recovery_history import NOW, RUN, UUID, scenario

OLD_RUN = 'setup-run-' + 'd' * 32
OLD_CONFIG = 'e' * 32


def chain(root, *, prior_schema=1, prior_revision=1, prior_finish=None, phantom_retry=False):
    original, paths = scenario(root)
    payload = copy.deepcopy(original['payload'])
    old_time = NOW - timedelta(hours=2)
    old_payload = copy.deepcopy(payload)
    if phantom_retry:
        old_payload['prejoin_retry'] = {}
    old_plan = SetupPlanStore(root, clock=lambda: old_time).create(old_payload)
    created = (old_time + timedelta(seconds=1)).isoformat()
    prior_binding = dict(payload['binding'], schema_version=prior_schema, revision=prior_revision,
                         run_id=OLD_RUN, date=created, result='failed')
    old_run = {'schema_version': 1, 'run_id': OLD_RUN, 'machine_uuid': UUID,
               'status': 'failed', 'partial_failure': True,
               'configuration_result_unavailable': True,
               'configuration_run_id': OLD_CONFIG,
               'plan_id': old_plan['plan_id'], 'plan_sha256': old_plan['sha256'],
               'created_at': created, 'finished_at': (prior_finish or old_time + timedelta(minutes=91)).isoformat(),
               'error': {'code': 'domain_join_timeout'}}
    prior = {'run': root/'setup-runs'/(OLD_RUN+'.json'),
             'plan': root/'setup-plans'/(old_plan['plan_id']+'.json'),
             'request': root/'configure-runs'/OLD_CONFIG/'request.json',
             'log': root/'configure-runs'/OLD_CONFIG/'ansible.log',
             'index': root/'setup-plan-runs'/(old_plan['plan_id']+'.json')}
    private_create(prior['run'], old_run)
    private_create(prior['index'], {'run_id': OLD_RUN})
    private_create(prior['request'], payload['request'])
    prior['log'].write_text('TASK [prejoin_upgrade : Perform the full ALT upgrade before first domain join] ***\n')
    prior['log'].chmod(0o600)
    payload['existing_assignment'] = prior_binding
    payload['prejoin_retry'] = {'failed_run_id': OLD_RUN, 'configuration_run_id': OLD_CONFIG,
                               'binding_sha256': digest(prior_binding),
                               'evidence_sha256': {key: hashlib.sha256(prior[key].read_bytes()).hexdigest()
                                                   for key in ('run', 'plan', 'request', 'log')}}
    new = SetupPlanStore(root, clock=lambda: NOW).create(payload)
    private_create(root/'setup-plan-runs'/(new['plan_id']+'.json'), {'run_id': RUN})
    run = private_read(paths['run'])
    run.update(plan_id=new['plan_id'], plan_sha256=new['sha256'])
    private_replace(paths['run'], run)
    binding = private_read(paths['binding']); binding['revision'] = 2
    private_replace(paths['binding'], binding)
    return prior, paths


def test_one_closed_prejoin_timeout_then_first_join_failure_is_read_only_history(tmp_path):
    chain(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    h = RecoveryHistoryStore(tmp_path).load(RUN)
    assert h['identity']['failed_run_id'] == RUN
    assert set(h['raw_files']) == EVIDENCE_LABELS
    assert {p: p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()} == before
    assert not (tmp_path/'setup-recovery-attempts').exists()


def test_archived_resolution_keeps_valid_chain_after_assignment_advance(tmp_path):
    _, paths = chain(tmp_path)
    h = RecoveryHistoryStore(tmp_path).load(RUN)
    from alt_deploy.setup_recovery import evidence_document
    guid = 'bbbbbbbb-1111-2222-3333-cccccccccccc'
    pair = {'failed_run_id': RUN, 'computer_guid': guid}
    doc = {'schema_version': 1, 'pair': pair, 'identity': h['identity'],
           'terminal': dict(pair, evidence_sha256=h['identity']['evidence_sha256']),
           'evidence': evidence_document(h['raw_files'])}
    store = RecoveryResolutionStore(SimpleNamespace(state_root=tmp_path))
    store.retain(doc)
    binding = private_read(paths['binding'])
    identity = {k: v for k, v in binding.items()
                if k not in ('schema_version', 'revision', 'run_id', 'date', 'result')}
    DomainAssignmentStore(tmp_path).write(identity, run_id='setup-run-'+'f'*32,
                                          result='successful', date=NOW.isoformat(), revision=3)
    assert store.load(**pair) == doc
    assert not (tmp_path/'setup-recovery-attempts').exists()


@pytest.mark.parametrize('options', [{'prior_schema': True}, {'prior_revision': True},
                                    {'prior_revision': 2}, {'phantom_retry': True},
                                    {'prior_finish': NOW + timedelta(minutes=1)}])
def test_rehashed_but_invalid_predecessor_metadata_is_not_authority(tmp_path, options):
    chain(tmp_path, **options)
    with pytest.raises(ControlError) as caught:
        RecoveryHistoryStore(tmp_path).load(RUN)
    assert caught.value.code == 'recovery_history_invalid'
    assert not (tmp_path/'setup-recovery-attempts').exists()


@pytest.mark.parametrize('drift', ['log_join', 'log_changed', 'missing_index', 'wrong_index',
                                  'result_present', 'prior_running', 'prior_unknown',
                                  'request_identity', 'revision_three'])
def test_unproven_or_changed_prejoin_chain_never_becomes_recovery_history(tmp_path, drift):
    prior, current = chain(tmp_path)
    if drift.startswith('log_'):
        with prior['log'].open('a') as f:
            f.write('TASK [domain_join : Join] ***\n' if drift == 'log_join' else 'changed\n')
    elif drift == 'missing_index':
        prior['index'].unlink()
    elif drift == 'wrong_index':
        private_replace(prior['index'], {'run_id': RUN})
    elif drift == 'result_present':
        private_create(prior['request'].parent/'result.json', {'status': 'failed'})
    elif drift in ('prior_running', 'prior_unknown'):
        old = private_read(prior['run']); old['status'] = drift.removeprefix('prior_')
        private_replace(prior['run'], old)
    elif drift == 'request_identity':
        request = private_read(prior['request']); request['final_hostname'] = 'alt-a1-pc4'
        private_replace(prior['request'], request)
    else:
        binding = private_read(current['binding']); binding['revision'] = 3
        private_replace(current['binding'], binding)
    with pytest.raises(ControlError) as caught:
        RecoveryHistoryStore(tmp_path).load(RUN)
    assert caught.value.code == 'recovery_history_invalid'
    assert not (tmp_path/'setup-recovery-attempts').exists()
