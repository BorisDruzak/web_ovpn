"""Durable, single-use Setup admissions shared with the legacy job registry.

Admission holds only the short queue lock. Dispatch takes lifecycle then queue;
it must never take the lifecycle lock while holding the queue lock.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
import fcntl
import os
from pathlib import Path
import pwd
import re
import stat

from .ad_directory import fail
from .assignments import assert_safe_payload
from .jobs import JobRepository
from .setup_plans import canonical, digest, private_create, private_directory, private_read, private_replace

ACTIVE_SETUP_STATES = frozenset({'queued', 'preflight', 'running', 'verifying',
                                'waiting_reboot', 'waiting_first_login', 'unknown_requires_review'})
TERMINAL_SETUP_STATES = frozenset({'successful', 'degraded', 'failed'})
STATES = ACTIVE_SETUP_STATES | TERMINAL_SETUP_STATES
TRANSITIONS = {
    'queued': {'preflight', 'failed', 'unknown_requires_review'},
    'preflight': {'running', 'verifying', 'failed', 'unknown_requires_review'},
    'running': {'running', 'waiting_reboot', 'waiting_first_login', 'verifying', 'failed', 'unknown_requires_review'},
    'verifying': {'successful', 'degraded', 'failed', 'waiting_reboot', 'waiting_first_login', 'unknown_requires_review'},
    # Continuation may only re-observe; it cannot return to running/apply.
    'waiting_reboot': {'verifying', 'unknown_requires_review'},
    'waiting_first_login': {'verifying', 'unknown_requires_review'},
    'unknown_requires_review': set(),
    'successful': set(), 'degraded': set(), 'failed': set(),
}
HEX = re.compile(r'^[0-9a-f]{64}$')
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
STAGE = re.compile(r'^[a-z][a-z0-9_.-]{0,95}$')
_LEGACY_CONTEXT = ContextVar('legacy_setup_reservation', default=None)
_SETUP_CONTEXT = ContextVar('setup_execution', default=None)


@contextmanager
def setup_job_execution(settings, job_id, plan):
    job = SetupJobRepository(settings).get(job_id)
    if (job.state != 'running' or not job.status['claimed']
            or job.request['operation'] != 'full_setup' or job.request['plan'] != plan):
        raise fail('setup_job_not_claimed', 'Managed full execution requires its exact claimed plan')
    token = _SETUP_CONTEXT.set(job_id)
    try:
        yield
    finally:
        _SETUP_CONTEXT.reset(token)


def current_setup_job(settings):
    job_id = _SETUP_CONTEXT.get()
    return SetupJobRepository(settings).get(job_id) if job_id else None


def service_uid(settings):
    try:
        return pwd.getpwnam(settings.service_user).pw_uid
    except KeyError as exc:
        raise fail('setup_job_actor_invalid', 'Setup service account is unavailable') from exc


def fsync_directory(path: Path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def setup_queue_lock(settings, *, allow_root=False):
    from .setup_maintenance import admission_guard
    with admission_guard(settings.state_root):
        with _setup_queue_lock(settings, allow_root=allow_root):
            yield


@contextmanager
def _setup_queue_lock(settings, *, allow_root=False):
    """One service-owned lock, shared by root legacy and service Setup admission."""
    uid = service_uid(settings)
    if os.geteuid() != uid and not (allow_root and os.geteuid() == 0):
        raise fail('setup_job_actor_invalid', 'Setup admission requires the configured service account')
    root = settings.state_root
    # Legacy state initialization already uses this permission contract.
    if not root.exists():
        private_directory(root)
    for ancestor in (root, *root.parents):
        if not stat.S_ISDIR(ancestor.lstat().st_mode):
            raise fail('setup_state_unsafe', 'Setup queue ancestor is unsafe')
    info = root.lstat()
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise fail('setup_state_unsafe', 'Setup queue root must be private and service-owned')
    path = root/'setup-queue.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
    else:
        if os.geteuid() == 0:
            account = pwd.getpwnam(settings.service_user)
            os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fsync(fd)
        fsync_directory(root)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise fail('setup_state_unsafe', 'Setup queue lock is unsafe')
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def legacy_setup_admission(settings, machine_uuid, hostname, *, own_job_id=None):
    """Caller retains lifecycle, then briefly takes queue across reservation."""
    with setup_queue_lock(settings, allow_root=True):
        from .setup_partial_local_state import assert_no_pending
        assert_no_pending(settings)
        jobs = SetupJobRepository(settings)
        jobs._check_admissions()
        from .setup_retry import reviewed_jobs
        reviewed = reviewed_jobs(settings)
        for job in jobs.list():
            if job.job_id in reviewed:
                continue
            if job.job_id == own_job_id:
                if (job.state != 'running' or not job.status['claimed']
                        or job.request['operation'] != 'full_setup'
                        or job.machine_uuid != machine_uuid
                        or job.request['identities']['hostname'] != hostname.casefold()):
                    raise fail('setup_job_identity_reserved', 'Managed execution ownership differs')
                continue
            identity = job.request['identities']
            if job.state in ACTIVE_SETUP_STATES and (identity['uuid'] == machine_uuid or identity['hostname'] == hostname.casefold()):
                raise fail('setup_job_identity_reserved', 'Machine identity is reserved by a Setup job')
        yield


def legacy_execution_reservations(settings):
    root = settings.state_root/'legacy-setup-reservations'
    if not root.exists() and not root.is_symlink():
        return []
    uid = service_uid(settings)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise fail('setup_state_unsafe', 'Legacy execution reservation directory is unsafe')
    records = []
    for path in root.glob('*.json'):
        record = private_read(path, owner_uid=uid)
        try:
            if (set(record) != {'schema_version', 'operation', 'reservation_id', 'machine_uuid', 'hostname', 'state', 'run_id', 'supersedes'}
                    or record['schema_version'] != 1 or type(record['schema_version']) is not int
                    or record['operation'] not in ('configure', 'full_setup')
                    or record['state'] not in ('running', 'completed', 'unknown_requires_review')
                    or not UUID.fullmatch(record['machine_uuid'])
                    or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,62}', record['hostname'])
                    or not re.fullmatch(r'[0-9a-f]{32}', record['reservation_id'])
                    or not re.fullmatch(r'(setup-run-)?[0-9a-f]{32}', record['run_id'])
                    or not isinstance(record['supersedes'], list)
                    or len(record['supersedes']) > 1024
                    or len(set(record['supersedes'])) != len(record['supersedes'])
                    or any(not re.fullmatch(r'[0-9a-f]{32}', value) for value in record['supersedes'])
                    or path.name != record['reservation_id']+'.json'):
                raise fail('setup_state_invalid', 'Legacy execution reservation is invalid')
        except (KeyError, TypeError, ValueError) as exc:
            raise fail('setup_state_invalid', 'Legacy execution reservation is invalid') from exc
        records.append(record)
    return records


def unresolved_legacy_reservations(settings):
    records = legacy_execution_reservations(settings)
    resolved = {identifier for r in records if r['state'] == 'completed' for identifier in r['supersedes']}
    return [r for r in records if r['state'] in ('running', 'unknown_requires_review') and r['reservation_id'] not in resolved]


def _legacy_publish(settings, path, record, *, create=False):
    """Root legacy callers publish service-owned evidence without weakening private I/O."""
    import secrets
    root = path.parent
    if not root.exists() and not root.is_symlink():
        root.mkdir(mode=0o700)
        if os.geteuid() == 0:
            account = pwd.getpwnam(settings.service_user)
            os.chown(root, account.pw_uid, account.pw_gid)
        fsync_directory(root.parent)
    # Validate the directory and every existing record before modifying it.
    legacy_execution_reservations(settings)
    target = path if create else path.with_name('.'+path.name+'-'+secrets.token_hex(8))
    if path.is_symlink():
        raise fail('setup_state_unsafe', 'Legacy execution reservation is unsafe')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if os.geteuid() == 0:
            account = pwd.getpwnam(settings.service_user)
            os.fchown(fd, account.pw_uid, account.pw_gid)
        with os.fdopen(fd, 'wb') as output:
            fd = -1
            output.write(canonical(record)+b'\n')
            output.flush()
            os.fsync(output.fileno())
        if not create:
            os.replace(target, path)
        fsync_directory(root)
    finally:
        if fd != -1: os.close(fd)
        if not create: target.unlink(missing_ok=True)


@contextmanager
def legacy_setup_execution(settings, machine_uuid, hostname, *, operation, run_id, reviewed_predecessor_runs=()):
    import uuid
    reservation_id = uuid.uuid4().hex
    path = settings.state_root/'legacy-setup-reservations'/(reservation_id+'.json')
    record = {'schema_version': 1, 'reservation_id': reservation_id, 'operation': operation,
              'machine_uuid': machine_uuid, 'hostname': hostname.casefold(), 'state': 'running',
              'run_id': run_id, 'supersedes': []}
    with legacy_setup_admission(settings, machine_uuid, hostname, own_job_id=_SETUP_CONTEXT.get()):
        existing = unresolved_legacy_reservations(settings)
        parent = _LEGACY_CONTEXT.get()
        inherited = parent['supersedes'] if parent and parent['machine_uuid'] == machine_uuid else []
        record['supersedes'] = [r['reservation_id'] for r in existing if r['machine_uuid'] == machine_uuid
                               and (r['run_id'] in reviewed_predecessor_runs or r['reservation_id'] in inherited)]
        if any((r['machine_uuid'] == machine_uuid or r['hostname'] == hostname.casefold())
               and r['reservation_id'] not in record['supersedes']
               and (parent is None or r['reservation_id'] != parent['reservation_id']) for r in existing):
            raise fail('setup_previous_run_unresolved', 'Earlier legacy execution requires review')
        _legacy_publish(settings, path, record, create=True)
    context = _LEGACY_CONTEXT.set(record)
    try:
        yield
    except BaseException:
        with setup_queue_lock(settings, allow_root=True):
            _legacy_publish(settings, path, dict(record, state='unknown_requires_review'))
        raise
    else:
        with setup_queue_lock(settings, allow_root=True):
            _legacy_publish(settings, path, dict(record, state='completed'))
    finally:
        _LEGACY_CONTEXT.reset(context)


def publish(path: Path, payload, *, create=False):
    (private_create if create else private_replace)(path, payload)
    fsync_directory(path.parent)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError
    return parsed


def validate_plan(plan, operation):
    """Validate retained snapshots without treating expiration as corruption."""
    if operation not in ('component', 'full_setup') or not isinstance(plan, dict):
        raise ValueError
    expected = {'schema_version', 'created_at', 'expires_at', 'content_sha256', 'payload', 'plan_id', 'sha256'}
    prefix = 'setup-'
    schema = 1
    if operation == 'component':
        expected.add('operation')
        prefix, schema = 'setup-component-', 2
        if plan.get('operation') != 'component_plan':
            raise ValueError
    if set(plan) != expected or type(plan['schema_version']) is not int or plan['schema_version'] != schema:
        raise ValueError
    sha = plan['sha256']
    if not isinstance(sha, str) or not HEX.fullmatch(sha) or plan['plan_id'] != prefix + sha:
        raise ValueError
    body = {k: v for k, v in plan.items() if k not in ('plan_id', 'sha256')}
    if (digest(body) != sha or not isinstance(plan['payload'], dict)
            or digest(plan['payload']) != plan['content_sha256']
            or timestamp(plan['expires_at']) - timestamp(plan['created_at']) != timedelta(minutes=30)):
        raise ValueError
    # The legacy full plan has fixed boolean readiness facts, never secret values.
    safe = copy.deepcopy(plan)
    if operation == 'full_setup':
        prerequisites = safe['payload'].get('prerequisites', {})
        if isinstance(prerequisites, dict):
            for key in ('vault_ad_join_ready', 'vault_krfb_ready'):
                if type(prerequisites.get(key)) is bool:
                    prerequisites.pop(key)
    assert_safe_payload(safe)
    if operation == 'full_setup':
        payload = plan['payload']
        proofs = [key for key in ('prejoin_retry', 'recovery_resolution', 'partial_local_resolution') if key in payload]
        if (len(proofs) > 1 or payload.get('predecessor_job') is not None and len(proofs) != 1
                or 'partial_local_resolution' in payload and payload.get('predecessor_job') is None): raise ValueError


def identities(plan):
    payload = plan['payload']
    machine = payload['machine']
    uuid = machine['uuid']
    host = machine['hostname']
    computer = payload['computer']
    objects = computer.get('objects', [])
    if (not isinstance(uuid, str) or not UUID.fullmatch(uuid) or not isinstance(host, str)
            or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,62}', host)
            or not isinstance(objects, list) or len(objects) > 1):
        raise ValueError
    result = {'uuid': uuid, 'hostname': host.casefold()}
    if objects:
        guid = objects[0]['object_guid'].lower()
        if not UUID.fullmatch(guid):
            raise ValueError
        result['computer_guid'] = guid
    return result


def valid_process(identity):
    return (isinstance(identity, dict) and set(identity) == {'boot_id', 'pid', 'start_ticks'}
            and isinstance(identity['boot_id'], str) and UUID.fullmatch(identity['boot_id'])
            and type(identity['pid']) is int and identity['pid'] > 0
            and type(identity['start_ticks']) is int and identity['start_ticks'] > 0)


def validate_setup_record(request, status, *, job_id):
    try:
        if (not isinstance(request, dict) or not isinstance(status, dict)
                or set(request) != {'schema_version', 'kind', 'operation', 'job_id', 'machine_uuid',
                                    'identities', 'plan', 'admission_sequence'}
                or set(status) != {'schema_version', 'kind', 'operation', 'job_id', 'machine_uuid',
                    'plan_id', 'plan_sha256', 'request_sha256', 'admission_sequence', 'state', 'stage',
                    'stage_history', 'created_at', 'updated_at', 'claimed', 'process_identity'}):
            raise ValueError
        if any(type(p['schema_version']) is not int or p['schema_version'] != 2
               or p['kind'] != 'setup' or p['job_id'] != job_id for p in (request, status)):
            raise ValueError
        validate_plan(request['plan'], request['operation'])
        identity = identities(request['plan'])
        if (request['identities'] != identity or request['machine_uuid'] != identity['uuid']
                or any(request[k] != status[k] for k in ('job_id', 'machine_uuid', 'operation', 'admission_sequence'))
                or type(request['admission_sequence']) is not int or request['admission_sequence'] < 1
                or status['plan_id'] != request['plan']['plan_id']
                or status['plan_sha256'] != request['plan']['sha256'] or status['request_sha256'] != digest(request)
                or status['state'] not in STATES or not isinstance(status['stage'], str)
                or not STAGE.fullmatch(status['stage']) or type(status['claimed']) is not bool
                or (status['claimed'] and not valid_process(status['process_identity']))
                or (not status['claimed'] and (status['process_identity'] is not None or status['state'] != 'queued'))):
            raise ValueError
        created, updated = timestamp(status['created_at']), timestamp(status['updated_at'])
        if updated < created:
            raise ValueError
        history = status['stage_history']
        if not isinstance(history, list) or not 1 <= len(history) <= 1024:
            raise ValueError
        prior_state, prior_date = None, created
        for entry in history:
            if (not isinstance(entry, dict) or set(entry) != {'state', 'stage', 'at'}
                    or entry['state'] not in STATES or not STAGE.fullmatch(entry['stage'])
                    or not prior_date <= timestamp(entry['at']) <= updated):
                raise ValueError
            if prior_state is None:
                if entry['state'] != 'queued' or entry['at'] != status['created_at']:
                    raise ValueError
            elif entry['state'] not in TRANSITIONS[prior_state]:
                raise ValueError
            prior_state, prior_date = entry['state'], timestamp(entry['at'])
        if history[-1]['state'] != status['state'] or history[-1]['stage'] != status['stage']:
            raise ValueError
        assert_safe_payload(status)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise fail('setup_job_invalid', 'Setup job schema or integrity is invalid') from exc


def read_setup_record(settings, job_dir):
    uid = service_uid(settings)
    try:
        info = job_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != uid:
            raise ValueError
        request = private_read(job_dir/'request.json', owner_uid=uid)
        status = private_read(job_dir/'status.json', owner_uid=uid)
        validate_setup_record(request, status, job_id=job_dir.name)
        return request, status
    except (OSError, ValueError) as exc:
        raise fail('setup_job_invalid', 'Setup job directory is unsafe') from exc


def queue_check(settings, job):
    """Read diagnostic evidence only; this record never grants execution."""
    path = job.job_dir/'admission-check.json'
    if not path.exists() and not path.is_symlink():
        return None
    value = private_read(path, owner_uid=service_uid(settings))
    if (set(value) != {'schema_version', 'job_id', 'request_sha256', 'code', 'checked_at'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['job_id'] != job.job_id or value['request_sha256'] != digest(job.request)
            or value['code'] not in (None, 'setup_queue_admission_unverified')):
        raise fail('setup_state_invalid', 'Queue diagnostic evidence is invalid')
    timestamp(value['checked_at'])
    return value


def record_queue_check(settings, job, *, code, checked_at):
    previous = queue_check(settings, job)
    if code not in (None, 'setup_queue_admission_unverified'):
        raise fail('setup_state_invalid', 'Queue diagnostic code is invalid')
    if previous is not None and previous['code'] == code:
        return
    publish(job.job_dir/'admission-check.json', {'schema_version': 1, 'job_id': job.job_id,
        'request_sha256': digest(job.request), 'code': code, 'checked_at': checked_at})


class SetupJobRepository:
    def __init__(self, settings, *, clock=None):
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.jobs = JobRepository(settings)
        self.claims = settings.state_root/'setup-job-plan-claims'
        self.reservations = settings.state_root/'setup-job-reservations'
        self.queue_lock = settings.state_root/'setup-queue.lock'

    @contextmanager
    def locked(self):
        if os.geteuid() != service_uid(self.settings):
            raise fail('setup_job_actor_invalid', 'Run Setup jobs as the configured service account')
        with setup_queue_lock(self.settings):
            for path in (self.claims, self.reservations, self.settings.jobs_dir):
                private_directory(path)
            fsync_directory(self.settings.state_root)
            yield

    def _read(self, path):
        return private_read(path, owner_uid=service_uid(self.settings))

    def get(self, job_id):
        job = self.jobs.get(job_id)
        if job.status.get('kind') != 'setup':
            raise fail('setup_job_not_found', 'This identifier is not a Setup job')
        return job

    def list(self, machine_uuid=None):
        return [job for job in self.jobs.list() if job.status.get('kind') == 'setup'
                and (machine_uuid is None or job.machine_uuid == machine_uuid)]

    def submit(self, plan, *, operation):
        try:
            validate_plan(plan, operation)
            identity = identities(plan)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise fail('setup_plan_invalid', 'Setup job requires an intact supported plan') from exc
        with self.locked():
            from .setup_partial_local_state import assert_no_pending
            assert_no_pending(self.settings)
            path = self.claims/(plan['sha256']+'.json')
            if path.exists() or path.is_symlink():
                claim = self._read(path)
                try:
                    old = self.get(claim['job_id'])
                    self._check_claim(old, claim)
                    if old.request['plan'] != plan or old.request['operation'] != operation:
                        raise ValueError
                except Exception as exc:
                    raise fail('setup_job_admission_requires_review', 'Consumed plan has incomplete or inconsistent admission evidence') from exc
                return old
            # Read the published immutable plan too; caller-provided snapshots alone are insufficient.
            from .component_setup import ComponentPlanStore
            from .setup_plans import SetupPlanStore
            store = (ComponentPlanStore if operation == 'component' else SetupPlanStore)(self.settings.state_root, clock=self.clock)
            if store.load(plan['plan_id'], plan['sha256']) != plan:
                raise fail('setup_plan_mismatch', 'Published Setup plan differs')
            self._check_admissions()
            from .setup_retry import validate_predecessor, reviewed_jobs, reviewed_full_runs
            prior = validate_predecessor(self.settings, plan)
            prior_runs = reviewed_full_runs(self.settings, plan['payload']) if operation == 'full_setup' and prior else set()
            reviewed = reviewed_jobs(self.settings)
            if prior in reviewed:
                raise fail('setup_retry_already_reviewed', 'This predecessor already has a confirmed successor')
            if any(r['state'] in ('running', 'unknown_requires_review') and
                   (r['machine_uuid'] == identity['uuid'] or r['hostname'] == identity['hostname'])
                    for r in unresolved_legacy_reservations(self.settings) if r['run_id'] not in prior_runs):
                raise fail('setup_active_job', 'Machine has an unresolved legacy execution')
            for reservation_path in self.reservations.glob('*.json'):
                reservation = self._read(reservation_path)
                job = self.get(reservation['job_id'])
                self._check_claim(job, reservation)
                if (job.job_id not in reviewed | ({prior} if prior else set()) and job.state in ACTIVE_SETUP_STATES
                        and any(identity.get(k) == v for k, v in reservation['identities'].items())):
                    raise fail('setup_job_identity_reserved', 'UUID, hostname or AD computer identity is already reserved')
            if any((job.machine_uuid == identity['uuid'] or str(job.request.get('final_hostname', '')).casefold() == identity['hostname'])
                   and job.state in ('queued', 'running')
                   for job in self.jobs.list() if job.status.get('kind') != 'setup'):
                raise fail('setup_active_job', 'Machine has an active legacy provision job')
            sequence = 1 + max((self._read(p)['admission_sequence'] for p in self.claims.glob('*.json')), default=0)
            job_id = self.jobs._generate_job_id()
            record = {'schema_version': 2, 'kind': 'setup', 'operation': operation,
                      'job_id': job_id, 'machine_uuid': identity['uuid'], 'identities': identity,
                      'plan': copy.deepcopy(plan), 'admission_sequence': sequence}
            claim = {'schema_version': 2, 'job_id': job_id, 'plan_id': plan['plan_id'],
                     'plan_sha256': plan['sha256'], 'request_sha256': digest(record),
                     'identities': identity, 'admission_sequence': sequence}
            # First write burns the plan. Any interrupted publication fails closed.
            publish(path, claim, create=True)
            publish(self.reservations/(job_id+'.json'), claim, create=True)
            job_dir = self.jobs._job_dir(job_id)
            job_dir.mkdir(mode=0o700)
            fsync_directory(self.settings.jobs_dir)
            publish(job_dir/'request.json', record, create=True)
            now = self.clock().isoformat()
            status = {'schema_version': 2, 'kind': 'setup', 'operation': operation, 'job_id': job_id,
                      'machine_uuid': identity['uuid'], 'plan_id': plan['plan_id'], 'plan_sha256': plan['sha256'],
                      'request_sha256': digest(record), 'admission_sequence': sequence,
                      'state': 'queued', 'stage': 'created', 'stage_history': [{'state': 'queued', 'stage': 'created', 'at': now}],
                      'created_at': now, 'updated_at': now, 'claimed': False, 'process_identity': None}
            publish(job_dir/'status.json', status, create=True)
            job = self.get(job_id)
            from .setup_retry import publish_review
            publish_review(self.settings, job)
            return job

    def _check_claim(self, job, claim):
        expected = {'schema_version': 2, 'job_id': job.job_id, 'plan_id': job.status['plan_id'],
                    'plan_sha256': job.status['plan_sha256'], 'request_sha256': job.status['request_sha256'],
                    'identities': job.request['identities'], 'admission_sequence': job.status['admission_sequence']}
        if claim != expected or self._read(self.reservations/(job.job_id+'.json')) != claim:
            raise fail('setup_job_admission_requires_review', 'Setup admission evidence differs or is missing')

    def _check_admissions(self):
        try:
            sequences = set()
            for path in self.claims.glob('*.json'):
                claim = self._read(path)
                job = self.get(claim['job_id'])
                if path.name != job.status['plan_sha256']+'.json' or claim['admission_sequence'] in sequences:
                    raise ValueError
                sequences.add(claim['admission_sequence'])
                self._check_claim(job, claim)
            for path in self.reservations.glob('*.json'):
                reservation = self._read(path)
                job = self.get(reservation['job_id'])
                if path.name != job.job_id+'.json' or self._read(self.claims/(job.status['plan_sha256']+'.json')) != reservation:
                    raise ValueError
                self._check_claim(job, reservation)
            for job in self.list():
                claim = self._read(self.claims/(job.status['plan_sha256']+'.json'))
                self._check_claim(job, claim)
            from .setup_retry import reviewed_jobs
            reviewed = reviewed_jobs(self.settings)
            for job in self.list():
                reference = job.request['plan']['payload'].get('predecessor_job')
                if reference is not None and reference.get('job_id') not in reviewed:
                    raise ValueError
        except Exception as exc:
            raise fail('setup_job_admission_requires_review', 'Interrupted or inconsistent Setup admission requires review') from exc

    def claim(self, job_id, process_identity):
        if not valid_process(process_identity):
            raise fail('setup_process_identity_invalid', 'Worker process identity is invalid')
        with self.locked():
            self._check_admissions()
            job = self.get(job_id)
            if job.state != 'queued' or job.status['claimed']:
                raise fail('setup_job_already_claimed', 'A Setup job can only be claimed once')
            status = copy.deepcopy(job.status)
            status.update(claimed=True, process_identity=copy.deepcopy(process_identity))
            self._transition(job, status, 'preflight')
            return self.get(job_id)

    def _transition(self, job, status, state, stage=None):
        if state not in TRANSITIONS[job.state]:
            raise fail('setup_job_transition_invalid', 'Setup job transition is invalid')
        stage_id = stage or state
        if not isinstance(stage_id, str) or not STAGE.fullmatch(stage_id):
            raise fail('setup_job_stage_invalid', 'Setup job stage identifier is invalid')
        now = self.clock().isoformat()
        status.update(state=state, stage=stage_id, updated_at=now)
        status['stage_history'].append({'state': state, 'stage': stage_id, 'at': now})
        validate_setup_record(job.request, status, job_id=job.job_id)
        publish(job.job_dir/'status.json', status)

    def transition(self, job_id, state, *, stage=None):
        with self.locked():
            job = self.get(job_id)
            if not job.status['claimed']:
                raise fail('setup_job_not_claimed', 'Setup transitions require the original worker claim')
            if stage is not None and (not isinstance(stage, dict) or set(stage) != {'id'}):
                raise fail('setup_job_stage_invalid', 'Setup job stage must contain only a safe identifier')
            self._transition(job, copy.deepcopy(job.status), state, stage['id'] if stage else None)
            return self.get(job_id)
