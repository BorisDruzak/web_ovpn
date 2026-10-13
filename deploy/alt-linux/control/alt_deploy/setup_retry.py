"""A new confirmed idempotent component plan may review one unknown predecessor."""
from .ad_directory import fail
from .component_verification import package_health_ready
from .setup_jobs import SetupJobRepository, publish, service_uid, fsync_directory
from .setup_plans import digest, private_read, private_directory


def predecessor(settings, job_id, component, machine_uuid):
    job = SetupJobRepository(settings).get(job_id)
    if (job.state != 'unknown_requires_review' or job.request['operation'] != 'component'
            or job.machine_uuid != machine_uuid or component['execution']['retry_policy'] != 'idempotent'
            or component['execution'].get('adapter')
            or job.request['plan']['payload']['component']['id'] != component['id']):
        raise fail('setup_retry_not_permitted', 'Only the same idempotent component can have a newly reviewed plan')
    return {'job_id': job_id, 'request_sha256': digest(job.request), 'status_sha256': digest(job.status)}


def validate_predecessor(settings, plan):
    payload = plan['payload']
    reference = payload.get('predecessor_job')
    if reference is None:
        return None
    try:
        actual = predecessor(settings, reference['job_id'], payload['component'], payload['machine']['uuid'])
    except (KeyError, TypeError) as exc:
        raise fail('setup_retry_not_permitted', 'Predecessor review reference is invalid') from exc
    if reference != actual or not package_health_ready(payload['observed']):
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
