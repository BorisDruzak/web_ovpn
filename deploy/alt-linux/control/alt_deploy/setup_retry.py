"""A new confirmed idempotent component plan may review one unknown predecessor."""
from .ad_directory import fail
from .component_verification import package_health_ready
from .setup_jobs import SetupJobRepository, publish, service_uid, fsync_directory
from .setup_plans import digest, private_read, private_directory


def predecessor(settings, job_id, component, machine_uuid):
    job = SetupJobRepository(settings).get(job_id)
    if (job.state != 'unknown_requires_review' or job.machine_uuid != machine_uuid
            or component['execution']['retry_policy'] != 'idempotent' or component['execution'].get('adapter')):
        raise fail('setup_retry_not_permitted', 'Only the same idempotent component can have a newly reviewed plan')
    reference = {'job_id': job_id, 'request_sha256': digest(job.request), 'status_sha256': digest(job.status)}
    if job.request['operation'] == 'component':
        if job.request['plan']['payload']['component']['id'] != component['id']:
            raise fail('setup_retry_not_permitted', 'The original component differs')
        return reference
    result = private_read(job.job_dir/'execution.json', owner_uid=service_uid(settings))
    run = result.get('legacy_run')
    from .setup import RUN_RE
    if (not isinstance(run, dict) or not RUN_RE.fullmatch(str(run.get('run_id', '')))
            or run.get('status') not in ('successful', 'degraded')
            or run.get('machine_uuid') != machine_uuid or run.get('plan_id') != job.status['plan_id']
            or run.get('plan_sha256') != job.status['plan_sha256']
            or run != private_read(settings.state_root/'setup-runs'/(run['run_id']+'.json'), owner_uid=service_uid(settings))
            or result.get('schema_version') != 2 or result.get('job_id') != job_id
            or result.get('plan_sha256') != job.status['plan_sha256']
            or not any(c['id'] == component['id'] and c['version'] == component['version']
                       for c in job.request['plan']['payload']['components'])):
        raise fail('setup_retry_not_permitted', 'Full predecessor requires an intact completed protected Setup; no domain replay')
    return dict(reference, execution_sha256=digest(result), legacy_run_sha256=digest(run))


def full_predecessor(settings, job_id, machine_uuid, failed_run_id):
    job = SetupJobRepository(settings).get(job_id)
    result = private_read(job.job_dir/'execution.json', owner_uid=service_uid(settings))
    run = private_read(settings.state_root/'setup-runs'/(failed_run_id+'.json'), owner_uid=service_uid(settings))
    if (job.state != 'unknown_requires_review' or job.request['operation'] != 'full_setup'
            or job.machine_uuid != machine_uuid or result.get('legacy_error_run_id') != failed_run_id
            or result.get('job_id') != job.job_id or result.get('schema_version') != 2
            or result.get('plan_sha256') != job.status['plan_sha256']
            or run.get('status') != 'failed' or run.get('run_id') != failed_run_id or run.get('partial_failure') is not True
            or run.get('plan_id') != job.status['plan_id']
            or run.get('plan_sha256') != job.status['plan_sha256'] or run.get('machine_uuid') != machine_uuid):
        raise fail('setup_retry_not_permitted', 'Unknown full job is not the original closed failed Setup run')
    return {'job_id': job_id, 'request_sha256': digest(job.request), 'status_sha256': digest(job.status)}


def closed_full_job_only(settings, machine, failed_run_id):
    """Additional V2 exclusion adapter; original recovery gates still run in full."""
    active = machine.active_job
    if active is None:
        return True
    if not isinstance(active, dict):
        return False
    try:
        full_predecessor(settings, active['job_id'], machine.uuid, failed_run_id)
        job = SetupJobRepository(settings).get(active['job_id'])
        return (active.get('schema_version') == 2 and active.get('kind') == 'setup'
                and active.get('state') == 'unknown_requires_review'
                and active.get('machine_uuid') == machine.uuid
                and active.get('plan_sha256') == job.status['plan_sha256'])
    except (KeyError, TypeError, ValueError, OSError):
        return False
    except Exception:
        return False


def reviewed_full_runs(settings, payload):
    proof = payload.get('prejoin_retry') or payload.get('recovery_resolution') or payload.get('partial_local_resolution')
    if not proof:
        return set()
    run_id = proof['failed_run_id']
    run = private_read(settings.state_root/'setup-runs'/(run_id+'.json'), owner_uid=service_uid(settings))
    return {run_id, run['configuration_run_id']}


def reviewed_legacy_runs(settings):
    result = set()
    jobs = SetupJobRepository(settings)
    for old_id in reviewed_jobs(settings):
        review = private_read(settings.state_root/'setup-job-reviews'/(old_id+'.json'), owner_uid=service_uid(settings))
        successor = jobs.get(review['successor_job_id'])
        if successor.request['operation'] == 'full_setup':
            result.update(reviewed_full_runs(settings, successor.request['plan']['payload']))
    return result


def validate_predecessor(settings, plan):
    payload = plan['payload']
    reference = payload.get('predecessor_job')
    if reference is None:
        return None
    try:
        if payload.get('engine_schema_version') == 2:
            proof = payload.get('prejoin_retry') or payload.get('recovery_resolution') or payload.get('partial_local_resolution')
            if not proof:
                raise fail('setup_retry_not_permitted', 'Full successor requires the existing prejoin or terminal recovery gate')
            if payload.get('partial_local_resolution'):
                from .setup_partial_local_continuation import load_resolution
                document = load_resolution(settings, proof, archival=True)
                if payload.get('existing_assignment') != document['closed']['binding']:
                    raise fail('setup_retry_not_permitted', 'Partial-local predecessor binding differs')
            actual = full_predecessor(settings, reference['job_id'], payload['machine']['uuid'], proof['failed_run_id'])
        else:
            actual = predecessor(settings, reference['job_id'], payload['component'], payload['machine']['uuid'])
    except (KeyError, TypeError) as exc:
        raise fail('setup_retry_not_permitted', 'Predecessor review reference is invalid') from exc
    if reference != actual or not package_health_ready(payload.get('component_observed', payload['observed'])):
        raise fail('setup_retry_requires_fresh_health', 'Predecessor or fresh package/remote health differs')
    return reference['job_id']


def publish_review(settings, job):
    old_id = validate_predecessor(settings, job.request['plan'])
    if old_id is None:
        return
    root = settings.state_root/'setup-job-reviews'
    private_directory(root)
    fsync_directory(settings.state_root)
    reference = job.request['plan']['payload']['predecessor_job']
    publish(root/(old_id+'.json'), {'schema_version': 1, **reference,
        'successor_job_id': job.job_id, 'successor_plan_sha256': job.status['plan_sha256']}, create=True)


def reviewed_jobs(settings):
    root = settings.state_root/'setup-job-reviews'
    if not root.exists() and not root.is_symlink():
        return set()
    # Root/read-only maintenance may inspect service-owned protected evidence.
    uid = service_uid(settings)
    import stat
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid != uid or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise fail('setup_job_admission_requires_review', 'Setup review directory is unsafe')
    jobs = SetupJobRepository(settings)
    reviewed = set()
    try:
        for path in root.glob('*.json'):
            review = private_read(path, owner_uid=uid)
            successor = jobs.get(review['successor_job_id'])
            reference = successor.request['plan']['payload']['predecessor_job']
            if (review != {'schema_version': 1, **reference, 'successor_job_id': successor.job_id,
                           'successor_plan_sha256': successor.status['plan_sha256']}
                    or path.name != reference['job_id']+'.json'
                    or validate_predecessor(settings, successor.request['plan']) != reference['job_id']):
                raise ValueError
            reviewed.add(reference['job_id'])
    except Exception as exc:
        raise fail('setup_job_admission_requires_review', 'Setup review evidence differs or is incomplete') from exc
    return reviewed
