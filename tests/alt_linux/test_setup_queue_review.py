"""One confirmed candidate may pass a freshly proven closed foreign UNKNOWN."""
import copy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import SetupJobRepository, legacy_setup_execution
from alt_deploy.setup_plans import SetupPlanStore, private_read, private_replace
from alt_deploy.setup_worker import SetupWorker
from test_component_setup import component_service
from test_component_catalog import project
from test_setup_maintenance_review import stopped


@pytest.fixture
def queued(stopped):
    settings, old, facts, date = stopped
    payload = copy.deepcopy(old.request['plan']['payload'])
    payload['machine'].update(uuid='22222222-3333-4444-5555-666666666666', hostname='alt-t2-pc2')
    payload['request'].update(machine_uuid=payload['machine']['uuid'], final_hostname=payload['machine']['hostname'])
    payload['computer']['objects'][0]['object_guid'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    plan = SetupPlanStore(settings.state_root, clock=lambda: date[0]).create(payload)
    jobs = SetupJobRepository(settings, clock=lambda: date[0])
    candidate = jobs.submit(plan, operation='full_setup')
    return settings, old, candidate, facts, date, jobs


def review_for(queued):
    from alt_deploy_backup import setup_queue_review
    assert hasattr(setup_queue_review, 'QueueAdmissionReview')
    settings, _, _, facts, date, _ = queued
    return setup_queue_review.QueueAdmissionReview(settings,
        observer=lambda job: copy.deepcopy(facts), clock=lambda: date[0])


def freeze_old(old, root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()
            and (old.job_id in str(p) or p.parent.name == 'legacy-setup-reservations')}


def test_second_confirmation_rejection_preserves_valid_history(queued):
    from alt_deploy_backup.setup_compat import history_fingerprint, validate_ledger
    settings, old, candidate, _, date, _ = queued
    review = review_for(queued)
    first = review.plan(old.job_id, candidate.job_id)
    receipt = review.confirm(first['plan_id'], first['sha256'])
    date[0] += timedelta(seconds=1)
    second = review.plan(old.job_id, candidate.job_id)
    assert first['sha256'] != second['sha256']
    before = history_fingerprint(settings.state_root)
    with pytest.raises(ControlError): review.confirm(second['plan_id'], second['sha256'])
    validate_ledger(settings.state_root)
    assert history_fingerprint(settings.state_root) == before
    assert review.confirm(first['plan_id'], first['sha256']) == receipt


def test_interrupted_confirmation_retries_without_orphan_receipt(queued, monkeypatch):
    from alt_deploy_backup.setup_compat import validate_ledger
    settings, old, candidate, _, _, _ = queued
    review = review_for(queued)
    plan = review.plan(old.job_id, candidate.job_id)
    create = review.io.private_create
    def interrupted(path, value):
        create(path, value)
        if path.parent.name in ('setup-queue-reviews', '.pending'):
            raise KeyboardInterrupt()
    with monkeypatch.context() as patch:
        patch.setattr(review.io, 'private_create', interrupted)
        with pytest.raises(KeyboardInterrupt): review.confirm(plan['plan_id'], plan['sha256'])
    validate_ledger(settings.state_root)
    review.confirm(plan['plan_id'], plan['sha256'])
    assert review.for_candidate(candidate.job_id)['job_ids'] == {old.job_id}
    validate_ledger(settings.state_root)


@pytest.mark.parametrize('published', [False, True])
def test_atomic_publication_interruption_preserves_authority_and_exact_retry(queued, monkeypatch, published):
    from alt_deploy_backup import setup_queue_review
    from alt_deploy_backup.setup_compat import validate_ledger
    settings, old, candidate, _, _, _ = queued
    review = review_for(queued)
    plan = review.plan(old.job_id, candidate.job_id)
    link = setup_queue_review.os.link
    def interrupted(source, destination, **kwargs):
        if published: link(source, destination, **kwargs)
        raise KeyboardInterrupt()
    with monkeypatch.context() as patch:
        patch.setattr(setup_queue_review.os, 'link', interrupted)
        with pytest.raises(KeyboardInterrupt): review.confirm(plan['plan_id'], plan['sha256'])
    validate_ledger(settings.state_root)
    if published:
        assert review.for_candidate(candidate.job_id)['job_ids'] == {old.job_id}
        before = private_read(review.reviews/(candidate.job_id+'.json'))
    else:
        with pytest.raises(ControlError): review.for_candidate(candidate.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    if published: assert receipt == before
    assert review.for_candidate(candidate.job_id)['job_ids'] == {old.job_id}


@pytest.mark.parametrize('unsafe', [None, 'directory', 'mode', 'symlink', 'name'])
def test_partial_staging_bytes_never_authorize_and_unsafe_staging_is_rejected(queued, unsafe):
    from alt_deploy.setup_plans import private_directory
    from alt_deploy_backup.setup_compat import history_fingerprint, validate_ledger
    settings, old, candidate, _, _, _ = queued
    review = review_for(queued)
    plan = review.plan(old.job_id, candidate.job_id)
    pending = review.reviews/'.pending'
    private_directory(review.reviews)
    private_directory(pending)
    path = pending/('a'*32+'.tmp')
    path.write_bytes(b'{"schema_version":')
    path.chmod(0o600)
    if unsafe == 'directory': pending.chmod(0o755)
    elif unsafe == 'mode': path.chmod(0o644)
    elif unsafe == 'symlink': path.unlink();path.symlink_to(plan['plan_id']+'.json')
    elif unsafe == 'name': path.rename(pending/'unexpected.json')
    with pytest.raises(ControlError): review.for_candidate(candidate.job_id)
    if unsafe:
        with pytest.raises(ControlError): validate_ledger(settings.state_root)
        with pytest.raises(ControlError): review.confirm(plan['plan_id'], plan['sha256'])
    else:
        validate_ledger(settings.state_root)
        before = history_fingerprint(settings.state_root)
        assert before['setup-queue-reviews/.pending/'+path.name]
        review.confirm(plan['plan_id'], plan['sha256'])
        assert path.read_bytes() == b'{"schema_version":'
        assert review.for_candidate(candidate.job_id)['job_ids'] == {old.job_id}


def test_confirmed_review_dispatches_only_candidate_without_rewriting_unknown(queued, monkeypatch):
    settings, old, candidate, facts, date, jobs = queued
    review = review_for(queued)
    before = freeze_old(old, settings.state_root)
    calls = []
    def execute(job_id):
        calls.append(job_id); jobs.transition(job_id, 'running')
        jobs.transition(job_id, 'verifying'); jobs.transition(job_id, 'successful')
    from alt_deploy import setup_maintenance_review_bridge
    monkeypatch.setattr(setup_maintenance_review_bridge, 'queue_review_service', lambda settings: review)
    worker = SetupWorker(settings, engine=SimpleNamespace(execute=execute), clock=lambda: date[0])
    assert worker.run_once()['status'] == 'blocked' and calls == []
    plan = review.plan(old.job_id, candidate.job_id)
    assert plan['purpose'] == 'queued_other_machine_only'
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    assert receipt['purpose'] == 'queued_other_machine_only'
    assert review.for_candidate(candidate.job_id)['job_ids'] == {old.job_id}
    assert worker.run_once()['status'] == 'successful' and calls == [candidate.job_id]
    assert freeze_old(old, settings.state_root) == before
    with pytest.raises(ControlError): review.for_candidate(candidate.job_id)
    assert worker.run_once()['status'] in ('idle', 'blocked') and calls == [candidate.job_id]


@pytest.mark.parametrize('drift', ['uuid', 'hostname', 'computer_guid', 'source', 'expired_candidate', 'extra_lease'])
def test_candidate_or_unexplained_legacy_state_denies_plan(queued, drift):
    settings, old, candidate, facts, date, jobs = queued
    review = review_for(queued)
    if drift == 'expired_candidate': date[0] += timedelta(minutes=30)
    elif drift == 'source': (settings.ansible_project_dir/'roles/software_onlyoffice/queue-source-drift.txt').write_text('changed')
    elif drift == 'extra_lease':
        with pytest.raises(KeyboardInterrupt):
            with legacy_setup_execution(settings, 'bbbbbbbb-3333-4444-5555-666666666666', 'alt-other', operation='configure', run_id='b'*32):
                raise KeyboardInterrupt()
    else:
        # Exercise identity policy separately from immutable claim validation.
        identity = dict(candidate.request['identities'])
        identity[drift] = (old.request['identities'].get(drift) if drift != 'computer_guid'
                           else facts['computer']['objects'][0]['object_guid'])
        assert hasattr(review, 'distinct_candidate'), 'Exact identity exclusion policy is missing'
        with pytest.raises(ControlError): review.distinct_candidate(identity, old.request['identities'], facts['computer'])
        return
    with pytest.raises(ControlError): review.plan(old.job_id, candidate.job_id)


@pytest.mark.parametrize('drift', ['history', 'status', 'source', 'busy', 'unknown_process', 'boot', 'plan_ttl', 'receipt_ttl', 'unsafe'])
def test_fresh_dispatch_review_denies_changed_or_expired_evidence(queued, drift):
    settings, old, candidate, facts, date, jobs = queued
    review = review_for(queued)
    plan = review.plan(old.job_id, candidate.job_id)
    receipt = review.confirm(plan['plan_id'], plan['sha256'])
    if drift == 'history':
        p=old.job_dir/'execution.json';d=private_read(p);d['finished_at']=date[0].isoformat();d['error_code']='changed';private_replace(p,d)
    elif drift == 'status':
        from alt_deploy.setup_worker import process_identity
        jobs.claim(candidate.job_id, process_identity(settings))
    elif drift == 'source': (settings.ansible_project_dir/'roles/software_onlyoffice/queue-source-drift.txt').write_text('changed')
    elif drift in ('busy', 'unknown_process'):
        facts['package_manager']['processes_absent'] = False if drift == 'busy' else None
    elif drift == 'boot': facts['boot_id'] = 'aaaaaaaa-3333-4444-5555-666666666666'
    elif drift == 'plan_ttl': date[0] += timedelta(minutes=30)
    elif drift == 'receipt_ttl': date[0] += timedelta(hours=6)
    elif drift == 'unsafe': (review.reviews/(candidate.job_id+'.json')).chmod(0o644)
    with pytest.raises(ControlError): review.for_candidate(candidate.job_id)


def test_confirmation_is_exact_and_detects_fresh_drift(queued):
    _, old, candidate, facts, date, _ = queued
    review=review_for(queued);plan=review.plan(old.job_id,candidate.job_id)
    with pytest.raises(ControlError): review.confirm(plan['plan_id'],'f'*64)
    facts['package_manager']['processes_absent']=False
    with pytest.raises(ControlError): review.confirm(plan['plan_id'],plan['sha256'])


@pytest.mark.parametrize('consumed', [False, True])
def test_expired_and_consumed_review_remains_retained_restore_history(queued, consumed):
    from alt_deploy_backup.setup_compat import history_fingerprint, validate_ledger
    settings, old, candidate, _, date, jobs=queued
    review=review_for(queued);plan=review.plan(old.job_id,candidate.job_id)
    review.confirm(plan['plan_id'],plan['sha256'])
    if consumed:
        from alt_deploy.setup_worker import process_identity
        jobs.claim(candidate.job_id,process_identity(settings));jobs.transition(candidate.job_id,'failed')
    before=history_fingerprint(settings.state_root)
    assert any(k.startswith('setup-queue-') for k in before)
    date[0]+=timedelta(hours=7)
    validate_ledger(settings.state_root)
    assert history_fingerprint(settings.state_root)==before
    with pytest.raises(ControlError): review.for_candidate(candidate.job_id)


def test_unrelated_provision_job_remains_a_blocker(queued):
    from alt_deploy.jobs import JobRepository
    from test_jobs import provision_request
    settings,old,candidate,*_=queued
    JobRepository(settings).create(provision_request('bbbbbbbb-3333-4444-5555-666666666666'))
    with pytest.raises(ControlError):review_for(queued).plan(old.job_id,candidate.job_id)


def test_review_never_skips_another_queued_job_or_excludes_it(queued):
    settings,old,candidate,facts,date,jobs=queued
    payload=copy.deepcopy(candidate.request['plan']['payload'])
    payload['machine'].update(uuid='bbbbbbbb-3333-4444-5555-666666666666',hostname='alt-t2-pc4')
    payload['computer']['objects'][0]['object_guid']='bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'
    plan=SetupPlanStore(settings.state_root,clock=lambda:date[0]).create(payload)
    other=jobs.submit(plan,operation='full_setup')
    review=review_for(queued)
    for target in (candidate,other):
        with pytest.raises(ControlError):review.plan(old.job_id,target.job_id)
    assert not jobs.get(candidate.job_id).status['claimed']
    assert not jobs.get(other.job_id).status['claimed']


def test_wrong_purpose_or_missing_candidate_mapping_never_authorizes_dispatch(queued):
    from alt_deploy.setup_plans import private_create
    settings,old,candidate,*_=queued
    review=review_for(queued);plan=review.plan(old.job_id,candidate.job_id)
    receipt=review.confirm(plan['plan_id'],plan['sha256'])
    path=review.reviews/(candidate.job_id+'.json')
    pointer=private_read(path);pointer['purpose']='controller_maintenance_only';private_replace(path,pointer)
    with pytest.raises(ControlError):review.for_candidate(candidate.job_id)
    assert not SetupJobRepository(settings).get(candidate.job_id).status['claimed']


def test_candidate_request_tampering_is_denied_without_changing_original(queued):
    settings,old,candidate,*_=queued
    before=freeze_old(old,settings.state_root)
    p=candidate.job_dir/'request.json';d=private_read(p);d['admission_sequence']+=1;private_replace(p,d)
    with pytest.raises(ControlError):review_for(queued).plan(old.job_id,candidate.job_id)
    assert freeze_old(old,settings.state_root)==before


def test_native_reviewed_component_unknown_does_not_block_its_new_candidate_review(queued, component_service):
    from alt_deploy.component_setup import ComponentPlanStore
    from alt_deploy.setup_retry import predecessor, reviewed_jobs
    from alt_deploy.setup_worker import process_identity
    settings,old,full,facts,date,jobs=queued
    # Complete the first synthetic candidate; no legacy target writes occur here.
    jobs.claim(full.job_id,process_identity(settings));jobs.transition(full.job_id,'failed')
    payload=copy.deepcopy(full.request['plan']['payload'])
    payload.pop('engine_schema_version')
    payload['component']=next(c for c in payload['components'] if c['id']=='software.onlyoffice')
    payload['observed']=copy.deepcopy(component_service[4])
    store=ComponentPlanStore(settings.state_root,clock=lambda:date[0])
    interrupted=jobs.submit(store.create(payload),operation='component')
    jobs.claim(interrupted.job_id,process_identity(settings));jobs.transition(interrupted.job_id,'unknown_requires_review')
    payload['predecessor_job']=predecessor(settings,interrupted.job_id,payload['component'],interrupted.machine_uuid)
    successor=jobs.submit(store.create(payload),operation='component')
    assert interrupted.job_id in reviewed_jobs(settings)
    before=freeze_old(old,settings.state_root)
    review=review_for(queued)
    plan=review.plan(old.job_id,successor.job_id)
    review.confirm(plan['plan_id'],plan['sha256'])
    assert review.for_candidate(successor.job_id)['job_ids']=={old.job_id}
    assert freeze_old(old,settings.state_root)==before


@pytest.mark.parametrize('field', ['status_sha256','source_sha256','identities','job_id'])
def test_retained_plan_validates_candidate_reference_even_with_recomputed_outer_hash(queued, field):
    from alt_deploy.setup_plans import digest,private_create
    from alt_deploy_backup.setup_compat import validate_ledger
    settings,old,candidate,*_=queued;review=review_for(queued)
    plan=review.plan(old.job_id,candidate.job_id)
    path=review.plans/(plan['plan_id']+'.json');value=private_read(path)
    reference=value['payload']['candidate']
    if field=='identities':reference[field]=dict(reference[field],hostname='alt-t2-pc999')
    elif field=='job_id':reference[field]=old.job_id
    else:reference[field]='f'*64
    value['content_sha256']=digest(value['payload'])
    sha=digest({k:v for k,v in value.items() if k not in ('plan_id','sha256')})
    value.update(plan_id=review.prefix+sha,sha256=sha)
    path.unlink();private_create(review.plans/(value['plan_id']+'.json'),value)
    with pytest.raises((ControlError,ValueError)):validate_ledger(settings.state_root)


def test_queue_cli_routes_to_native_review_and_rejects_extra_execution_inputs(queued, monkeypatch):
    from alt_deploy import cli,setup_maintenance_review_bridge
    import io,json
    settings,old,candidate,*_=queued;review=review_for(queued)
    monkeypatch.setattr(setup_maintenance_review_bridge,'queue_review_service',lambda settings:review)
    def invoke(*args):
        out=io.StringIO();assert cli.main(['--json','setup','jobs',*args],settings=settings,stdout=out)==0
        return json.loads(out.getvalue())
    plan=invoke('queue-review-plan',old.job_id,'--candidate',candidate.job_id)
    assert invoke('queue-review-confirm',plan['plan_id'],'--confirm-sha256',plan['sha256'])['purpose']=='queued_other_machine_only'
    for suffix in (['--role','domain_join'],['--command','arbitrary'],['--cand','job-x']):
        with pytest.raises(SystemExit):cli.build_parser().parse_args(['setup','jobs','queue-review-plan',old.job_id,'--candidate',candidate.job_id,*suffix])
