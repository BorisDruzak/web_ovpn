"""Use trusted installed control validators; never import restored runtime code."""
import hashlib
import importlib
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

from .errors import BackupError
from .fs import read_regular_bytes


def control_module(name):
    if 'alt_deploy' not in sys.modules:
        root = Path('/opt/alt-deploy-control')
        for path in (root, *root.parents):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise BackupError('backup_source_unsafe', 'Installed control validators are unsafe', 4)
        sys.path.insert(0, str(root))
    return importlib.import_module('alt_deploy.'+name)


def validate_job(request, status, job_dir):
    control_module('setup_jobs').validate_setup_record(request, status, job_id=job_dir.name)
    event_module = control_module('setup_events')
    store = event_module.SetupEventStore.__new__(event_module.SetupEventStore)
    job = SimpleNamespace(job_id=job_dir.name, request=request, status=status)
    scope = store._scope(job)
    allowed = {'request.json', 'status.json', 'execution.json', 'component-vars.json',
               'component-result.json', 'ansible.log', 'events.lock', 'events'}
    for path in job_dir.iterdir():
        if path.name not in allowed:
            raise ValueError('Unexpected Setup job object')
        info = path.lstat()
        if info.st_uid != job_dir.stat().st_uid:
            raise ValueError('Setup job ownership differs')
        if path.name == 'events':
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('Unsafe events directory')
            paths = sorted(path.iterdir())
            if len(paths) > event_module.MAX_EVENTS:
                raise ValueError('Event limit exceeded')
            from .state_validation import _read_object
            for number, item in enumerate(paths, 1):
                event_info = item.lstat()
                if (not stat.S_ISREG(event_info.st_mode) or event_info.st_uid != info.st_uid
                        or stat.S_IMODE(event_info.st_mode) != 0o600):
                    raise ValueError('Unsafe event file')
                event, _ = _read_object(item, maximum=2048)
                store._validate(event, scope, persisted=True)
                if item.name != f'{number:012d}.json' or event['sequence'] != number or event['job_id'] != job_dir.name:
                    raise ValueError('Invalid event identity')
        elif not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Unsafe Setup job file')


def setup_settings(root):
    import pwd
    return SimpleNamespace(state_root=root, jobs_dir=root/'jobs',
                           service_user=pwd.getpwuid(root.stat().st_uid).pw_name)


def ledger_present(root):
    return any((root/name).exists() or (root/name).is_symlink() for name in
               ('setup-job-plan-claims', 'setup-job-reservations', 'setup-job-reviews', 'legacy-setup-reservations', 'setup-functional-acceptance',
                'setup-maintenance-plans', 'setup-maintenance-reviews',
                'setup-queue-review-plans', 'setup-queue-reviews', 'setup-queue-admissions'))


def validate_ledger(root):
    from .state_validation import _read_object, _safe_directory
    typed_jobs = any(_read_object(path/'status.json')[0].get('kind') == 'setup'
                     for path in (root/'jobs').iterdir()) if _safe_directory(root/'jobs', optional=True) else False
    if not ledger_present(root) and not typed_jobs:
        return
    module = control_module('setup_jobs')
    settings = setup_settings(root)
    module.SetupJobRepository(settings)._check_admissions()
    module.legacy_execution_reservations(settings)
    from .setup_maintenance_review import validate_artifacts
    validate_artifacts(root)
    from .setup_queue_review import validate_artifacts as validate_queue_artifacts
    validate_queue_artifacts(root)
    acceptance = root/'setup-functional-acceptance'
    if acceptance.exists() or acceptance.is_symlink():
        import re
        info = acceptance.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != root.stat().st_uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Unsafe functional acceptance directory')
        for path in acceptance.iterdir():
            metadata = path.lstat()
            record, _ = _read_object(path)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != info.st_uid or stat.S_IMODE(metadata.st_mode) != 0o600
                    or not re.fullmatch('[0-9a-f]{64}\\.json', path.name)
                    or record.get('schema_version') != 1 or record.get('operation') != 'component_functional_acceptance'
                    or record.get('proof_sha256') != path.stem or record.get('confirmed_functional') is not True):
                raise ValueError('Invalid functional acceptance receipt')


def unresolved_jobs(root, recovery_admission=None, *, maintenance_review=None, maintenance_settings=None):
    module = control_module('setup_jobs')
    settings = setup_settings(root)
    validate_ledger(root)
    reviewed = control_module('setup_retry').reviewed_jobs(settings)
    exclusion = {'job_ids': set(), 'lease_ids': set()}
    if recovery_admission is not None:
        exclusion = control_module('setup_recovery_backup_admission').load(settings, recovery_admission)
    if maintenance_review is not None:
        if recovery_admission is not None:
            raise ValueError('Maintenance and recovery scopes cannot be combined')
        from dataclasses import replace
        from .setup_maintenance_review import MaintenanceReview
        scoped_settings = maintenance_settings or replace(control_module('config').Settings.from_env(),
                                                          state_root=root, jobs_dir=root/'jobs')
        exclusion = MaintenanceReview(scoped_settings).exclusions(maintenance_review)
    jobs = [j.job_id for j in module.SetupJobRepository(settings).list()
            if j.state in module.ACTIVE_SETUP_STATES and j.job_id not in reviewed | exclusion['job_ids']]
    reviewed_runs = control_module('setup_retry').reviewed_legacy_runs(settings)
    if any(r['run_id'] not in reviewed_runs and r['reservation_id'] not in exclusion['lease_ids']
           for r in module.unresolved_legacy_reservations(settings)):
        jobs.append('legacy_setup_execution_unresolved')
    return jobs


def history_fingerprint(root):
    """Conservative restore admission: no loss or change to retained V2 ledger."""
    result = {}
    if not root.exists():
        return result
    validate_ledger(root)
    paths = [root/name for name in ('setup-job-plan-claims', 'setup-job-reservations',
                                   'setup-job-reviews', 'legacy-setup-reservations', 'setup-functional-acceptance',
                                   'setup-maintenance-plans', 'setup-maintenance-reviews',
                                   'setup-queue-review-plans', 'setup-queue-reviews', 'setup-queue-admissions') if (root/name).exists()]
    jobs_root = root/'jobs'
    if jobs_root.exists():
        from .state_validation import _read_object
        for job in jobs_root.iterdir():
            status, _ = _read_object(job/'status.json')
            if status.get('kind') == 'setup':
                paths.append(job)
    for path in paths:
        for item in path.rglob('*'):
            info = item.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            raw = read_regular_bytes(item, max_bytes=64*1024*1024)
            result[str(item.relative_to(root))] = hashlib.sha256(raw).hexdigest()
    return result


def assert_restore_history(live, staged):
    if history_fingerprint(live) != history_fingerprint(staged):
        raise BackupError('setup_history_restore_conflict',
                          'Restore would change retained Setup history; use a current matching backup', 4)
