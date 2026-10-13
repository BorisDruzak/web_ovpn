"""Exact reserved recovery context for a read-only native controller snapshot.

This does not resolve an UNKNOWN job or authorize any workstation/AD writer.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import re

from .ad_directory import fail
from .setup_jobs import SetupJobRepository, service_uid
from .setup_plans import digest, private_create, private_read
from .setup_retry import full_predecessor


def prepare(producer, payload, identity, intent):
    settings = producer.settings
    if not (settings.state_root/'jobs').exists():
        return None
    jobs = [j for j in SetupJobRepository(settings).list(payload['machine_uuid'])
            if j.state == 'unknown_requires_review' and j.request['operation'] == 'full_setup']
    if not jobs:
        return None
    if len(jobs) != 1:
        raise fail('recovery_backup_admission_invalid', 'Recovery snapshot requires one exact closed full job')
    reference = full_predecessor(settings, jobs[0].job_id, payload['machine_uuid'], payload['failed_run_id'])
    record = {'schema_version': 1, 'operation': 'recovery_controller_snapshot_admission',
              'identity': identity, 'predecessor_job': reference,
              'intent_relative': str(intent.relative_to(settings.state_root))}
    key = digest(record)
    private_create(settings.state_root/'setup-recovery-backup-admissions'/(key+'.json'), record)
    return key


def load(settings, key):
    try:
        return _load(settings, key)
    except Exception:
        raise fail('recovery_backup_admission_invalid', 'Exact reserved recovery snapshot admission is invalid') from None


def _load(settings, key):
    if not isinstance(key, str) or not re.fullmatch('[0-9a-f]{64}', key):
        raise ValueError
    uid = service_uid(settings)
    read = lambda path: private_read(path, owner_uid=uid)
    record = read(settings.state_root/'setup-recovery-backup-admissions'/(key+'.json'))
    if (set(record) != {'schema_version', 'operation', 'identity', 'predecessor_job', 'intent_relative'}
            or record['schema_version'] != 1 or record['operation'] != 'recovery_controller_snapshot_admission'
            or digest(record) != key):
        raise ValueError
    identity = record['identity']
    pair = {k: identity[k] for k in ('failed_run_id', 'computer_guid')}
    from .setup_recovery import _pair
    _pair(**pair)
    relative = record['intent_relative']
    if (not isinstance(relative, str) or relative.startswith('/') or '\\' in relative
            or '..' in relative.split('/') or not relative.startswith('setup-recovery-')
            or not relative.endswith('/'+digest(pair)+'.controller-backup.intent.json')):
        raise ValueError
    intent = settings.state_root/relative
    prefix = digest(pair)
    root = intent.parent
    if any((root/(prefix+suffix)).exists() or (root/(prefix+suffix)).is_symlink() for suffix in
           ('.receipt.json', '.controller-backup.failed.json', '.controller-backup.receipt.json')):
        raise ValueError
    if read(intent) != identity:
        raise ValueError
    claim = read(root/(prefix+'.claim.json'))
    credential = read(root/(prefix+'.credential.json'))
    ready = read(root/(prefix+'.credential-verified.json'))
    evidence = read(root/(prefix+'.evidence.json'))
    created = datetime.fromisoformat(claim['created_at'])
    if (created.tzinfo is None or not created <= datetime.now(timezone.utc) <= created+timedelta(minutes=30)
            or claim['schema_version'] != 1 or claim['status'] != 'reserved'
            or any(claim[k] != value for k, value in pair.items())
            or digest(claim) != identity['claim_sha256'] or digest(evidence) != identity['evidence_sha256']
            or claim['plan_sha256'] != identity['plan_sha256']
            or digest(credential) != identity['document_sha256']
            or hashlib.sha256(credential['ciphertext'].encode('ascii')).hexdigest() != identity['sealed_sha256']
            or set(credential) != set(identity)-{'snapshot_sha256', 'document_sha256'} | {'ciphertext'}
            or any(credential[k] != v for k, v in identity.items() if k not in ('snapshot_sha256', 'document_sha256'))
            or ready != dict(schema_version=1, claim_sha256=identity['claim_sha256'],
                sealed_sha256=identity['sealed_sha256'], document_sha256=identity['document_sha256'])):
        raise ValueError
    # Validate the retained recovery envelope and exact snapshot, without
    # decrypting any credential or bypassing the caller's fresh AD gate.
    plan = read(settings.state_root/'setup-recovery-plans'/(claim['plan_id']+'.json'))
    context = plan['payload']['snapshot'].get('recovery_attempt_context')
    expected_root = settings.state_root/'setup-recovery-attempts'
    if context is not None:
        from .setup_recovery_attempt_context import context_layout, validate_context
        validate_context(settings.state_root, context, pair, owner_uid=uid)
        expected_root = settings.state_root/context_layout(context)[2]/context['attempt_id']
    body = {k:v for k,v in plan.items() if k not in ('plan_id', 'sha256')}
    if (root != expected_root or not created <= datetime.now(timezone.utc) <= datetime.fromisoformat(plan['expires_at'])
            or digest(body) != claim['plan_sha256'] or plan['sha256'] != claim['plan_sha256']
            or plan['content_sha256'] != digest(plan['payload'])
            or plan['payload']['evidence_sha256'] != identity['evidence_sha256']
            or digest(plan['payload']['snapshot']) != identity['snapshot_sha256']
            or any(plan['payload'][k] != v for k,v in pair.items())
            or plan['payload']['machine_uuid'] != identity['machine_uuid']):
        raise ValueError
    actual = full_predecessor(settings, record['predecessor_job']['job_id'], identity['machine_uuid'], pair['failed_run_id'])
    if actual != record['predecessor_job']:
        raise ValueError
    run = read(settings.state_root/'setup-runs'/(pair['failed_run_id']+'.json'))
    from .setup_jobs import legacy_execution_reservations
    job = SetupJobRepository(settings).get(actual['job_id'])
    lease_ids = {r['reservation_id'] for r in legacy_execution_reservations(settings)
                 if r['machine_uuid'] == identity['machine_uuid']
                 and r['hostname'].casefold() == job.request['identities']['hostname']
                 and (r['operation'], r['run_id']) in
                     {('full_setup', pair['failed_run_id']), ('configure', run['configuration_run_id'])}}
    return {'job_ids': {actual['job_id']}, 'lease_ids': lease_ids}
