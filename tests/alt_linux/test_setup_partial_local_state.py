"""The original failure, not a replaceable plan ID, owns one recovery claim."""
from datetime import timedelta
import importlib
import multiprocessing
import os
import pwd
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from test_setup_closed_failure import backend, partial_failure
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_partial_observation import observer


def control(name):
    path = Path(__file__).resolve().parents[2]/'deploy/alt-linux/control/alt_deploy'/(name+'.py')
    assert path.exists(), 'Missing one-shot local recovery contract: '+name
    return importlib.import_module('alt_deploy.'+name)


def prepared(partial_failure):
    setup, job, *_, date = partial_failure
    closed = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
    fresh = observer(partial_failure)[0].observe(closed, mode='partial_ad')
    store = control('setup_partial_local_state').PartialLocalStore(setup.settings, clock=lambda: date[0])
    evidence = store.retain_closed(closed)
    payload = {'job_id': job.job_id, 'failed_run_id': closed['failed_run_id'],
        'configuration_run_id': closed['configuration_run_id'], 'machine': closed['machine'],
        'history_sha256': evidence['history_sha256'], 'evidence': fresh, 'source_sha256': 'a'*64,
        'rehearsal': {'status': 'passed', 'helper_sha256': 'b'*64, 'native_sha256': 'c'*64},
        'effects': ['native_local_pam_nss', 'disable_previous_auth_services', 'goa_absent_no_write']}
    return store, payload, closed, date


def test_one_claim_per_original_failure_across_plans(partial_failure):
    store, payload, closed, date = prepared(partial_failure)
    first = store.create(payload)
    claim = store.claim_once(first)
    date[0] += timedelta(seconds=1)
    second = store.create(payload)
    assert second['plan_id'] != first['plan_id']
    assert claim['claim_key'] == digest({'job_id': closed['job_id'], 'failed_run_id': closed['failed_run_id']})
    for plan in (first, second):
        with pytest.raises(ControlError): store.claim_once(plan)
    assert len(store.pending_attempts()) == 1


def test_archival_plan_does_not_extend_execution_ttl(partial_failure):
    store, payload, _, date = prepared(partial_failure)
    plan = store.create(payload)
    date[0] += timedelta(minutes=30)
    with pytest.raises(ControlError): store.load(plan['plan_id'], plan['sha256'])
    assert store.load(plan['plan_id'], plan['sha256'], archival=True) == plan


def test_archive_summary_must_match_its_exact_retained_files(partial_failure):
    from alt_deploy.setup_plans import private_read, private_replace
    store, payload, closed, date = prepared(partial_failure)
    path = store.evidence/closed['history_sha256']/'manifest.json'
    value = private_read(path); value['configuration_run_id'] = 'e'*32
    private_replace(path, value)
    with pytest.raises(ControlError): store.load_closed(closed['history_sha256'])


def test_retained_history_has_separate_exact_files_and_survives_current_assignment_advance(partial_failure):
    store, payload, closed, date = prepared(partial_failure)
    archive = store.load_closed(payload['history_sha256'])
    assert archive['files'] == closed['files']
    path = store.settings.state_root/'domain-assignments'/(closed['machine']['uuid']+'.json')
    from alt_deploy.setup_plans import private_read, private_replace
    value = private_read(path); value['revision'] += 1; value['result'] = 'successful'
    private_replace(path, value)
    assert store.load_closed(payload['history_sha256'])['files'] == closed['files']
    assert 'files' not in store.create(payload)['payload']


def test_concurrent_claims_in_separate_processes_have_one_winner(partial_failure):
    store, payload, *_ = prepared(partial_failure)
    plan = store.create(payload)
    ctx = multiprocessing.get_context('fork')
    ready = ctx.Event(); result = ctx.Queue()
    def attempt():
        ready.wait()
        try: store.claim_once(plan)
        except ControlError: result.put('blocked')
        else: result.put('claimed')
    children = [ctx.Process(target=attempt) for _ in range(2)]
    for child in children: child.start()
    ready.set()
    try:
        assert sorted(result.get(timeout=10) for _ in children) == ['blocked', 'claimed']
    finally:
        for child in children:
            child.join(10)
            if child.is_alive(): child.terminate(); child.join(5)
    assert len(store.pending_attempts()) == 1


@pytest.mark.parametrize('fault', ['archive', 'plan', 'claim', 'foreign_result'])
def test_corrupt_or_incomplete_artifacts_cannot_release_pending_claim(partial_failure, fault):
    store, payload, closed, date = prepared(partial_failure)
    plan = store.create(payload); claim = store.claim_once(plan)
    if fault == 'foreign_result':
        with pytest.raises(ControlError): store.publish_result(claim, {'schema_version': 1, 'status': 'successful'})
    else:
        directory = {'archive': 'setup-partial-local-evidence', 'plan': 'setup-partial-local-plans',
                     'claim': 'setup-partial-local-claims'}[fault]
        path = next(p for p in (store.settings.state_root/directory).rglob('*') if p.is_file())
        path.chmod(0o644)
        with pytest.raises(ControlError): store.validate_artifacts()
        with pytest.raises(ControlError): store.pending_attempts()


@pytest.mark.skipif(os.geteuid() != 0, reason='Real root reading a differing service UID')
def test_root_backup_validates_service_owned_partial_artifacts(partial_failure):
    store, payload, closed, date = prepared(partial_failure)
    plan = store.create(payload); store.claim_once(plan)
    account = pwd.getpwnam('nobody')
    root = store.settings.state_root
    for path in [root, *root.rglob('*')]: os.chown(path, account.pw_uid, account.pw_gid)
    store.settings.service_user = 'nobody'
    reader = control('setup_partial_local_state').PartialLocalStore(store.settings, clock=lambda: date[0])
    assert reader.load(plan['plan_id'], plan['sha256'], archival=True) == plan
    assert len(reader.pending_attempts()) == 1
