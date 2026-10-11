from __future__ import annotations

import base64
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from alt_deploy.errors import ControlError

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
RUN = 'setup-run-' + 'a' * 32
GUID = '11111111-2222-3333-4444-555555555555'
LABELS = ('plan', 'run', 'index', 'binding', 'configuration_result')


def evidence():
    # Preserve exact bytes, including formatting; do not canonicalize history.
    return {label: ('{ "label": "' + label + '", "status": "failed" }\n').encode()
            for label in LABELS}


def scenario(tmp_path, *, run_id=RUN, guid=GUID, offset=0):
    from alt_deploy.setup_recovery import RecoveryPlanStore, RecoveryAttemptStore, evidence_document
    from alt_deploy.setup_plans import digest
    raw = evidence()
    clock = lambda: NOW + timedelta(seconds=offset)
    plans = RecoveryPlanStore(tmp_path, clock=clock)
    plan = plans.create({'failed_run_id': run_id, 'computer_guid': guid,
                         'machine_uuid': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                         'computer_sid': 'S-1-5-21-111-222-333-1234',
                         'evidence_sha256': digest(evidence_document(raw))})
    return RecoveryAttemptStore(tmp_path, clock=clock), plan, raw


def test_recovery_plans_cannot_be_replayed_as_setup_plans(tmp_path):
    from alt_deploy.setup_plans import SetupPlanStore
    store, plan, raw = scenario(tmp_path)
    assert plan['plan_id'].startswith('recovery-')
    assert (tmp_path / 'setup-recovery-plans' / (plan['plan_id'] + '.json')).is_file()
    with pytest.raises(ControlError):
        SetupPlanStore(tmp_path, clock=lambda: NOW).load(plan['plan_id'], plan['sha256'])
    bad = dict(plan, sha256='b' * 64)
    with pytest.raises(ControlError):
        store.reserve(bad['plan_id'], bad['sha256'], raw)
    assert not list((tmp_path / 'setup-recovery-attempts').glob('*'))


def test_reservation_preserves_original_bytes_and_stays_immutable(tmp_path):
    from alt_deploy.setup_plans import private_read
    store, plan, raw = scenario(tmp_path)
    sources = []
    for label, content in raw.items():
        path = tmp_path / (label + '.original')
        path.write_bytes(content)
        sources.append(path)
    claim = store.reserve(plan['plan_id'], plan['sha256'], raw)
    claim_path = store.claim_path(RUN, GUID)
    original_claim = claim_path.read_bytes()
    preserved = private_read(store.evidence_path(RUN, GUID))
    for label, content in raw.items():
        assert base64.b64decode(preserved['files'][label]['bytes_b64'], validate=True) == content
        assert preserved['files'][label]['sha256'] == hashlib.sha256(content).hexdigest()
    assert [path.read_bytes() for path in sources] == list(raw.values())
    assert claim['failed_run_id'] == RUN and claim['computer_guid'] == GUID
    assert claim['plan_id'] == plan['plan_id']
    store.finish(RUN, GUID, status='ambiguous', error_code='recovery_transport_ambiguous')
    assert claim_path.read_bytes() == original_claim
    with pytest.raises(ControlError) as caught:
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert caught.value.code == 'recovery_attempt_reserved'


def test_fresh_plan_and_concurrent_attempts_do_not_bypass_pair_reservation(tmp_path):
    store, first, raw = scenario(tmp_path)
    _, second, _ = scenario(tmp_path, offset=1)
    store.clock = store.plans.clock = lambda: NOW + timedelta(seconds=2)
    assert first['plan_id'] != second['plan_id']
    def attempt(i):
        plan = first if i % 2 else second
        try:
            return store.reserve(plan['plan_id'], plan['sha256'], raw)['status']
        except ControlError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(16)))
    assert outcomes.count('reserved') == 1
    assert outcomes.count('recovery_attempt_reserved') == 15
    assert len(list(store.root.glob('*.claim.json'))) == 1
    assert len(list(store.root.glob('*.evidence.json'))) == 1


def test_interrupted_or_corrupted_claim_permanently_excludes_new_attempt(tmp_path):
    store, first, raw = scenario(tmp_path)
    store.reserve(first['plan_id'], first['sha256'], raw)
    # Simulate partial/corrupt durable state; never interpret it as permission.
    store.claim_path(RUN, GUID).write_bytes(b'{')
    _, new_plan, _ = scenario(tmp_path, offset=2)
    store.clock = store.plans.clock = lambda: NOW + timedelta(seconds=3)
    with pytest.raises(ControlError) as caught:
        store.reserve(new_plan['plan_id'], new_plan['sha256'], raw)
    assert caught.value.code == 'recovery_attempt_reserved'


@pytest.mark.parametrize('changed', ['plan', 'run', 'index', 'binding', 'configuration_result'])
def test_evidence_drift_is_refused_before_reservation(tmp_path, changed):
    store, plan, raw = scenario(tmp_path)
    raw[changed] += b' '
    with pytest.raises(ControlError) as caught:
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert caught.value.code == 'recovery_evidence_drift'
    assert not list(store.root.glob('*.claim.json'))


@pytest.mark.parametrize('change', ['missing', 'extra', 'invalid_json', 'duplicate', 'oversize'])
def test_invalid_evidence_never_creates_a_claim(tmp_path, change):
    from alt_deploy.setup_plans import MAX_STATE_BYTES
    store, plan, raw = scenario(tmp_path)
    if change == 'missing': raw.pop('binding')
    elif change == 'extra': raw['vault'] = b'{}'
    elif change == 'invalid_json': raw['run'] = b'not-json'
    elif change == 'duplicate': raw['run'] = b'{"a":1,"a":2}'
    else: raw['run'] = b' ' * (MAX_STATE_BYTES + 1)
    with pytest.raises(ControlError):
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert not list(store.root.glob('*.claim.json'))


@pytest.mark.parametrize('run_id,guid', [('other', GUID), (RUN, '../computer'),
    (RUN, 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')])
def test_invalid_or_noncanonical_identity_is_refused(tmp_path, run_id, guid):
    store, plan, raw = scenario(tmp_path, run_id=run_id, guid=guid)
    with pytest.raises(ControlError):
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert not list(store.root.glob('*.claim.json'))


def test_expired_plan_creates_no_attempt(tmp_path):
    from alt_deploy.setup_recovery import RecoveryAttemptStore
    _, plan, raw = scenario(tmp_path)
    expired = RecoveryAttemptStore(tmp_path, clock=lambda: NOW + timedelta(minutes=30))
    with pytest.raises(ControlError) as caught:
        expired.reserve(plan['plan_id'], plan['sha256'], raw)
    assert caught.value.code == 'setup_plan_expired'
    assert not list(expired.root.glob('*.claim.json'))


def test_terminal_receipt_is_append_only_and_rejects_unbounded_diagnostics(tmp_path):
    store, plan, raw = scenario(tmp_path)
    with pytest.raises(ControlError):
        store.finish(RUN, GUID, status='trust_recovered')
    store.reserve(plan['plan_id'], plan['sha256'], raw)
    with pytest.raises(ControlError):
        store.finish(RUN, GUID, status='successful')
    with pytest.raises(ControlError):
        store.finish(RUN, GUID, status='trust_recovered')
    with pytest.raises(ControlError):
        store.finish(RUN, GUID, status='failed', error_code='raw secret diagnostic !')
    receipt = store.finish(RUN, GUID, status='failed', error_code='recovery_local_failed')
    assert receipt['status'] == 'failed'
    with pytest.raises(ControlError):
        store.finish(RUN, GUID, status='trust_recovered')


@pytest.mark.parametrize('change', ['machine_uuid', 'computer_guid', 'computer_sid',
    'trust', 'keytab', 'sssd', 'user_lookup', 'local_duplicate', 'extra', 'truthy'])
def test_trust_receipt_requires_exact_pinned_identity_and_verified_checks(tmp_path, change):
    store, plan, raw = scenario(tmp_path)
    store.reserve(plan['plan_id'], plan['sha256'], raw)
    proof = {'machine_uuid': plan['payload']['machine_uuid'], 'computer_guid': GUID,
             'computer_sid': plan['payload']['computer_sid'], 'trust': True,
             'keytab': True, 'sssd': True, 'user_lookup': True, 'local_duplicate': False}
    if change in ('machine_uuid', 'computer_guid', 'computer_sid'): proof[change] = 'different'
    elif change == 'extra': proof['diagnostic'] = 'secret'
    elif change == 'truthy': proof['trust'] = 1
    else: proof[change] = not proof[change]
    with pytest.raises(ControlError):
        store.finish(RUN, GUID, status='trust_recovered', verification=proof)
    assert not list(store.root.glob('*.receipt.json'))


def test_valid_trust_receipt_does_not_rewrite_failed_history(tmp_path):
    store, plan, raw = scenario(tmp_path)
    store.reserve(plan['plan_id'], plan['sha256'], raw)
    claim_bytes = store.claim_path(RUN, GUID).read_bytes()
    evidence_bytes = store.evidence_path(RUN, GUID).read_bytes()
    proof = {'machine_uuid': plan['payload']['machine_uuid'], 'computer_guid': GUID,
             'computer_sid': plan['payload']['computer_sid'], 'trust': True,
             'keytab': True, 'sssd': True, 'user_lookup': True, 'local_duplicate': False}
    result = store.finish(RUN, GUID, status='trust_recovered', verification=proof)
    assert result['verification'] == proof
    assert store.claim_path(RUN, GUID).read_bytes() == claim_bytes
    assert store.evidence_path(RUN, GUID).read_bytes() == evidence_bytes


def test_archive_failure_leaves_reservation_exclusion(tmp_path, monkeypatch):
    import alt_deploy.setup_recovery as recovery
    store, plan, raw = scenario(tmp_path)
    create = recovery.private_create
    def broken_archive(path, payload):
        if path.name.endswith('.evidence.json'): raise OSError('synthetic disk failure')
        return create(path, payload)
    monkeypatch.setattr(recovery, 'private_create', broken_archive)
    with pytest.raises(ControlError):
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert store.claim_path(RUN, GUID).is_file()
    monkeypatch.setattr(recovery, 'private_create', create)
    with pytest.raises(ControlError) as caught:
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert caught.value.code == 'recovery_attempt_reserved'


def test_private_raw_reader_preserves_bytes_and_rejects_unsafe_sources(tmp_path):
    from alt_deploy.setup_plans import private_read_bytes
    path = tmp_path / 'source.json'
    raw = b'{ "a": 1 }\n'
    path.write_bytes(raw); path.chmod(0o600)
    assert private_read_bytes(path) == raw
    path.chmod(0o644)
    with pytest.raises(ControlError): private_read_bytes(path)
    path.chmod(0o600)
    alias = tmp_path / 'alias.json'; alias.symlink_to(path)
    with pytest.raises(ControlError): private_read_bytes(alias)


def test_reservation_syncs_directory_entry_before_returning(tmp_path, monkeypatch):
    import alt_deploy.setup_recovery as recovery
    store, plan, raw = scenario(tmp_path)
    synced = []
    real_sync = recovery._sync_directory
    def observe_sync(path):
        synced.append(path)
        return real_sync(path)
    monkeypatch.setattr(recovery, '_sync_directory', observe_sync)
    store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert store.root in synced
    assert store.root.parent in synced
    assert synced.index(store.root) < synced.index(store.root.parent)
    assert all(parent in synced for parent in store.root.parents)


def test_ancestor_symlink_cannot_redirect_historical_bytes(tmp_path):
    from alt_deploy.setup_plans import private_read_bytes
    real = tmp_path / 'real'; real.mkdir(mode=0o700)
    path = real / 'source.json'; path.write_bytes(b'{}'); path.chmod(0o600)
    alias = tmp_path / 'alias'; alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ControlError): private_read_bytes(alias / 'source.json')


def test_parent_sync_failure_cannot_return_a_mutation_authorization(tmp_path, monkeypatch):
    import alt_deploy.setup_recovery as recovery
    store, plan, raw = scenario(tmp_path)
    real_sync = recovery._sync_directory
    def fail_parent(path):
        if path == store.root.parent: raise OSError('synthetic directory sync failure')
        return real_sync(path)
    monkeypatch.setattr(recovery, '_sync_directory', fail_parent)
    with pytest.raises(ControlError) as caught:
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert caught.value.code == 'recovery_state_failed'
    assert store.claim_path(RUN, GUID).exists()
    with pytest.raises(ControlError) as caught:
        store.reserve(plan['plan_id'], plan['sha256'], raw)
    assert caught.value.code == 'recovery_attempt_reserved'
