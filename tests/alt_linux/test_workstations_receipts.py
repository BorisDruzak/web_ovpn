from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from alt_deploy.errors import ControlError


def store(tmp_path, **kwargs):
    from alt_deploy.workstations_receipts import GatewayReceiptStore
    return GatewayReceiptStore(tmp_path, **kwargs)


def test_same_request_is_executed_once_across_new_store_instances(tmp_path):
    request_id, calls = str(uuid.uuid4()), []
    intent = {'operation': 'plans.apply', 'parameters': {'plan_id': 'test'}}
    first = store(tmp_path).execute(request_id, intent, lambda: calls.append(1) or {'job_id': 'job-example'})
    second = store(tmp_path).execute(request_id, intent, lambda: pytest.fail('request replayed'))
    assert first == second
    assert first['state'] == 'successful' and first['data']['job_id'] == 'job-example'
    assert calls == [1]


def test_request_identity_cannot_be_reused_for_different_intent(tmp_path):
    request_id = str(uuid.uuid4())
    repository = store(tmp_path)
    repository.execute(request_id, {'operation': 'one'}, lambda: {})
    with pytest.raises(ControlError) as exc:
        repository.execute(request_id, {'operation': 'two'}, lambda: pytest.fail('different intent executed'))
    assert exc.value.code == 'workstations_request_conflict'


def test_concurrent_duplicate_requests_execute_once(tmp_path):
    request_id, calls = str(uuid.uuid4()), []
    def submit(_):
        return store(tmp_path).execute(request_id, {'operation': 'plans.apply'}, lambda: calls.append(1) or {'job_id': 'same'})
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, range(2)))
    assert results[0] == results[1]
    assert calls == [1]


def test_lost_apply_response_recovers_original_job_without_replay(tmp_path):
    request_id, calls = str(uuid.uuid4()), []
    intent = {'operation': 'plans.apply', 'parameters': {'plan_id': 'test'}}
    def admitted_but_interrupted():
        calls.append(1)
        raise ConnectionError('private transport diagnostic')
    with pytest.raises(ControlError):
        store(tmp_path).execute(request_id, intent, admitted_but_interrupted)
    repository = store(tmp_path, recover=lambda old: {'job_id': 'original'} if old == intent else None)
    result = repository.execute(request_id, intent, lambda: pytest.fail('unsafe replay'))
    assert result['data']['job_id'] == 'original'
    assert result['state'] == 'successful'
    assert calls == [1]


def test_unproven_interruption_stays_unknown(tmp_path):
    request_id = str(uuid.uuid4())
    def interrupted():
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        store(tmp_path).execute(request_id, {'operation': 'plans.create'}, interrupted)
    result = store(tmp_path).execute(request_id, {'operation': 'plans.create'}, lambda: pytest.fail('interrupted work replayed'))
    assert result['state'] == 'unknown'
    assert result['error_code'] == 'workstations_request_unresolved'


@pytest.mark.parametrize('request_id', ['../redirect', '-x', 'not-a-uuid', '0' * 36])
def test_invalid_request_id_never_writes(tmp_path, request_id):
    before = set(tmp_path.iterdir())
    with pytest.raises(ControlError):
        store(tmp_path).execute(request_id, {}, lambda: {})
    assert set(tmp_path.iterdir()) == before


def test_receipt_symlink_is_rejected(tmp_path):
    repository = store(tmp_path)
    request_id = str(uuid.uuid4())
    repository.execute(request_id, {}, lambda: {})
    path = repository.root / (request_id + '.json')
    original = tmp_path / 'outside'
    original.write_text('private', encoding='utf-8')
    path.unlink()
    path.symlink_to(original)
    with pytest.raises(ControlError):
        repository.status(request_id)


@pytest.mark.parametrize('code',['ad_user_disabled','full_workflow_dns_backend_unverified',
                                'full_workflow_admission_unverified','full_workflow_policy_changed'])
def test_known_preflight_error_keeps_safe_code_and_is_not_retried(tmp_path,code):
    request_id = str(uuid.uuid4())
    intent = {'operation': 'plans.create'}
    def rejected():
        raise ControlError(code, 'private directory identity')
    with pytest.raises(ControlError) as exc:
        store(tmp_path).execute(request_id, intent, rejected)
    assert exc.value.code == code
    result = store(tmp_path).execute(request_id, intent, lambda: pytest.fail('rejected request replayed'))
    assert result['state'] == 'error'
    assert result['error_code'] == code
    assert 'private directory identity' not in str(result)


@pytest.mark.parametrize('code',['private_unapproved','full_workflow_UPPERCASE','full_workflow_private/path',
                                'full_workflow_'+'a'*100])
def test_unapproved_preflight_error_remains_masked(tmp_path,code):
    request_id=str(uuid.uuid4());intent={'operation':'plans.create'}
    def rejected():raise ControlError(code,'PRIVATE-SECRET-SENTINEL')
    with pytest.raises(ControlError) as caught:store(tmp_path).execute(request_id,intent,rejected)
    assert caught.value.code=='workstations_controller_error'
    result=store(tmp_path).status(request_id)
    assert result['state']=='error' and result['error_code']=='workstations_controller_error'
    assert 'SENTINEL' not in str(result)
