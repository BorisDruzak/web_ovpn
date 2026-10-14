"""Additive controller-only review of a closed UNKNOWN; never a target admission."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat

from .setup_compat import control_module, history_fingerprint, validate_job


def denied():
    return control_module('ad_directory').fail('setup_maintenance_review_invalid',
        'Maintenance review is missing, busy, changed, unsafe or expired; target execution remains blocked')


def validate_artifacts(root):
    """Validate retained metadata without requiring an unexpired admission."""
    io = control_module('setup_plans')
    uid = root.stat().st_uid
    for name in ('setup-maintenance-plans', 'setup-maintenance-reviews'):
        directory = root/name
        if not directory.exists() and not directory.is_symlink(): continue
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise denied()
        for path in directory.iterdir():
            value = io.private_read(path, owner_uid=uid)
            if name == 'setup-maintenance-plans':
                sha = value.get('sha256')
                if (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha)
                        or path.name != 'setup-maintenance-'+sha+'.json'
                        or value.get('plan_id') != path.stem
                        or set(value) != {'schema_version', 'operation', 'created_at', 'expires_at',
                                          'content_sha256', 'payload', 'plan_id', 'sha256'}
                        or type(value['schema_version']) is not int or value['schema_version'] != 1
                        or value['operation'] != 'setup_maintenance_plan'
                        or io.digest({k: v for k, v in value.items() if k not in ('plan_id', 'sha256')}) != sha
                        or io.digest(value['payload']) != value['content_sha256']): raise denied()
                created, expires = (datetime.fromisoformat(value[k]) for k in ('created_at', 'expires_at'))
                if created.tzinfo is None or expires.tzinfo is None or expires-created != timedelta(minutes=30): raise denied()
            else:
                sha = value.get('review_sha256')
                if (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha) or path.name != sha+'.json'
                        or set(value) != {'schema_version', 'purpose', 'review_sha256', 'confirmed_at', 'valid_until'}
                        or type(value['schema_version']) is not int or value['schema_version'] != 1
                        or value['purpose'] != 'controller_maintenance_only'): raise denied()
                plan = io.private_read(root/'setup-maintenance-plans'/('setup-maintenance-'+sha+'.json'), owner_uid=uid)
                confirmed, until = (datetime.fromisoformat(value[k]) for k in ('confirmed_at', 'valid_until'))
                if (confirmed.tzinfo is None or until.tzinfo is None or until-confirmed != timedelta(seconds=21600)
                        or not datetime.fromisoformat(plan['created_at']) <= confirmed < datetime.fromisoformat(plan['expires_at'])):
                    raise denied()


@contextmanager
def maintenance_lock(settings):
    """Read an existing lifecycle lock without changing its owner or metadata."""
    path = settings.lock_file
    uid = control_module('setup_jobs').service_uid(settings)
    for parent in path.parents:
        if not stat.S_ISDIR(parent.lstat().st_mode): raise denied()
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, uid)
            or stat.S_IMODE(before.st_mode) != 0o600): raise denied()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    acquired = False
    try:
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino): raise denied()
        # Native backup's second check already owns this lock. Reuse only the
        # kernel's exact exclusive FLOCK record, never a caller-supplied flag.
        token = f'{os.major(actual.st_dev):02x}:{os.minor(actual.st_dev):02x}:{actual.st_ino}'
        own = any(parts[1:5] == ['FLOCK', 'ADVISORY', 'WRITE', str(os.getpid())]
                  and parts[5] == token for line in Path('/proc/locks').read_text().splitlines()
                  if len(parts := line.split()) >= 8)
        if not own:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        yield
    finally:
        if acquired: fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def observe(settings, job):
    """Only existing fixed read-only AD, identity and package collectors."""
    module = control_module('setup')
    service = module.SetupService(settings)
    original = job.request['plan']['payload']
    machine = service.machines.resolve(job.machine_uuid)
    user = service.directory.user(original['user']['login'])
    ou = [entry for entry in service.directory.ous()
          if entry['dn'].casefold() == original['computer_ou'].casefold()]
    if original['computer_ou'] not in service.approved_ous or len(ou) != 1: raise denied()
    facts = control_module('component_probe').ComponentProbe(settings).observe(
        machine, user, original['components'], profile_id=original['profile']['id'], allow_unresolved=True)
    return {'machine': {'uuid': machine.uuid, 'hostname': machine.hostname, 'ip': machine.ip,
                       'registration_sha256': control_module('setup_plans').digest(machine.raw)},
            'user': user, 'ou_identity': ou[0], 'computer': service.directory.computer(machine.hostname),
            'observed': service.probe(machine, user),
            'ssh_binding': control_module('component_probe').ssh_binding(settings, machine),
            'package_manager': facts['package_manager'], 'boot_id': facts['machine']['boot_id'],
            'user_runtime': facts['user']}


def native_observe(settings, job):
    uid = control_module('setup_jobs').service_uid(settings)
    if os.geteuid() == uid: return observe(settings, job)
    if os.geteuid() != 0: raise denied()
    # AD transport may refresh its private Kerberos cache. Run it as its owner.
    # Both module roots are trusted root-owned runtime code, never restored code.
    import subprocess
    original_root = Path(__file__).resolve().parents[1]
    root = Path('/opt/alt-deploy-maintenance') if original_root == Path('/opt/alt-deploy-backup') else original_root
    control = Path(control_module('config').__file__).resolve().parents[1]
    for directory in (root, control):
        for path in (directory, *directory.parents):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise denied()
    for name in ('__init__.py', 'setup_maintenance_review.py', 'setup_queue_review.py', 'setup_compat.py', 'errors.py', 'fs.py',
                 'state_validation.py', 'manifest.py', 'components.py', 'settings.py', 'systemd.py', 'secrets.py'):
        path = root/'alt_deploy_backup'/name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or path.read_bytes() != (original_root/'alt_deploy_backup'/name).read_bytes()): raise denied()
    result = subprocess.run(['/usr/bin/sudo', '-n', '-u', settings.service_user,
        '/usr/bin/env', 'LC_ALL=C.UTF-8', 'PYTHONPATH='+str(root)+':'+str(control),
        'ALT_DEPLOY_STATE_ROOT='+str(settings.state_root),
        'ALT_DEPLOY_REGISTRATION_ROOT='+str(settings.registration_root),
        'ALT_DEPLOY_ANSIBLE_PROJECT='+str(settings.ansible_project_dir),
        'ALT_DEPLOY_PRIVATE_KEY='+str(settings.private_key_file),
        'ALT_DEPLOY_KNOWN_HOSTS='+str(settings.known_hosts_file),
        'ALT_DEPLOY_SERVICE_USER='+settings.service_user,
        '/usr/bin/python3', '-m', 'alt_deploy_backup.setup_maintenance_review', job.job_id],
        capture_output=True, timeout=180, check=False, env={'PATH': '/usr/bin:/bin'})
    if result.returncode or len(result.stdout) > 524288: raise denied()
    return control_module('setup_plans').decode_state_bytes(result.stdout)


class MaintenanceReview:
    prefix = 'setup-maintenance-'
    operation = 'setup_maintenance_plan'
    purpose = 'controller_maintenance_only'
    plan_directory = 'setup-maintenance-plans'
    review_directory = 'setup-maintenance-reviews'

    def __init__(self, settings, *, observer=None, clock=None):
        self.settings = settings
        self.observer = observer or (lambda job: native_observe(settings, job))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.plans = settings.state_root/self.plan_directory
        self.reviews = settings.state_root/self.review_directory
        self.io = control_module('setup_plans')
        self.jobs = control_module('setup_jobs')

    def _read(self, path):
        return self.io.private_read(path, owner_uid=self.jobs.service_uid(self.settings))

    def _history(self, job_id, *, candidate_job_id=None):
        root = self.settings.state_root
        repository = self.jobs.SetupJobRepository(self.settings)
        repository._check_admissions()
        job = repository.get(job_id)
        if (job.state != 'unknown_requires_review' or job.request['operation'] != 'full_setup'
                or not job.status['claimed']): raise denied()
        validate_job(job.request, job.status, job.job_dir)
        execution = self._read(job.job_dir/'execution.json')
        run_id = execution.get('legacy_error_run_id')
        if not isinstance(run_id, str) or not re.fullmatch('setup-run-[0-9a-f]{32}', run_id): raise denied()
        control_module('setup_retry').full_predecessor(self.settings, job_id, job.machine_uuid, run_id)
        if not isinstance(execution.get('finished_at'), str): raise denied()
        ended = datetime.fromisoformat(execution['finished_at'])
        if ended.tzinfo is None or ended > self.clock(): raise denied()
        run = self._read(root/'setup-runs'/(run_id+'.json'))
        configure_id = run.get('configuration_run_id')
        if not isinstance(configure_id, str) or not re.fullmatch('[0-9a-f]{32}', configure_id): raise denied()
        configure = root/'configure-runs'/configure_id
        request = control_module('configure').ConfigureRequest.from_mapping(
            job.request['plan']['payload']['request'], expected_uuid=job.machine_uuid,
            catalog=control_module('component_catalog').ComponentCatalog.load(self.settings.ansible_project_dir))
        if self._read(configure/'request.json') != request.to_dict(): raise denied()
        result = control_module('configure')._read_configure_result(self._read(configure/'result.json'), request)
        if result['status'] != 'failed': raise denied()
        leases = self.jobs.unresolved_legacy_reservations(self.settings)
        expected = {('full_setup', run_id), ('configure', configure_id)}
        if (len(leases) != 2 or {(r['operation'], r['run_id']) for r in leases} != expected
                or any(r['machine_uuid'] != job.machine_uuid or r['hostname'] != job.request['identities']['hostname']
                       or r['state'] != 'unknown_requires_review' or r['supersedes'] for r in leases)):
            raise denied()
        allowed = {job_id}
        if candidate_job_id is not None:
            candidate = repository.get(candidate_job_id)
            if (candidate.state != 'queued' or candidate.status['claimed']
                    or candidate.machine_uuid == job.machine_uuid
                    or candidate.request['identities']['hostname'] == job.request['identities']['hostname']):
                raise denied()
            allowed.add(candidate_job_id)
            # Native reviewed predecessors are historical, not unexplained work.
            # Their exact successor links are revalidated by the existing gate.
            allowed.update(control_module('setup_retry').reviewed_jobs(self.settings))
        if any(j.job_id not in allowed and j.state in self.jobs.ACTIVE_SETUP_STATES for j in repository.jobs.list()):
            raise denied()
        history = history_fingerprint(root)
        # Maintenance state is additive and is validated separately below.
        history = {k: v for k, v in history.items() if not k.startswith('setup-maintenance-')}
        if candidate_job_id is not None:
            exact = {'setup-job-plan-claims/'+job.status['plan_sha256']+'.json',
                     'setup-job-reservations/'+job_id+'.json'}
            exact.update('legacy-setup-reservations/'+r['reservation_id']+'.json' for r in leases)
            history = {k: v for k, v in history.items() if k in exact or k.startswith('jobs/'+job_id+'/')}
        for path in (root/'setup-runs'/(run_id+'.json'), configure/'request.json', configure/'result.json',
                     root/'domain-assignments'/(job.machine_uuid+'.json')):
            if path.exists() or path.is_symlink():
                history[str(path.relative_to(root))] = hashlib.sha256(
                    self.io.private_read_bytes(path, owner_uid=self.jobs.service_uid(self.settings))).hexdigest()
        return job, history, {r['reservation_id'] for r in leases}

    def _snapshot(self, job_id, *, candidate_job_id=None):
        job, history, leases = self._history(job_id, candidate_job_id=candidate_job_id)
        fresh = self.observer(job)
        original = job.request['plan']['payload']
        module = control_module('setup')
        if (set(fresh) != {'machine', 'user', 'ou_identity', 'computer', 'observed', 'ssh_binding',
                          'package_manager', 'boot_id', 'user_runtime'}
                or fresh['machine'] != original['machine'] or fresh['ssh_binding'] != original['ssh_binding']
                or fresh['ou_identity'] != original['ou_identity']
                or any(fresh['user'].get(k) != original['user'].get(k)
                       for k in ('object_guid', 'object_sid', 'upn', 'login'))
                or fresh['user'].get('state') != 'enabled'
                or not control_module('component_verification').package_health_ready(fresh)
                or not isinstance(fresh['boot_id'], str)
                or not self.jobs.UUID.fullmatch(fresh['boot_id'])): raise denied()
        observed = fresh['observed']
        runtime = fresh['user_runtime']
        if (not isinstance(runtime, dict) or set(runtime) != {'login', 'uid', 'gid', 'home_exists', 'home_safe'}
                or runtime['login'] != original['user']['login']
                or any(type(runtime[k]) is not int or runtime[k] <= 0 for k in ('uid', 'gid'))
                or type(runtime['home_exists']) is not bool or runtime['home_safe'] is not True): raise denied()
        objects = fresh['computer'].get('objects', [])
        if (not fresh['computer'].get('exists') or len(objects) != 1
                or observed.get('uuid') != job.machine_uuid
                or observed.get('hostname') != original['machine']['hostname']
                or observed.get('domain') != module.DOMAIN
                or any(observed.get(k) is not True for k in ('trust', 'sssd', 'user_lookup'))
                or observed.get('local_duplicate') is not False
                or not module.computer_matches(objects[0], original['machine']['hostname'], original['computer_ou'])
                or not module.observed_computer_matches(observed, objects[0], original['machine']['hostname'])
                or any(not isinstance(objects[0].get(k), str) for k in ('object_guid', 'object_sid'))): raise denied()
        initial = original['computer'].get('objects', [])
        if initial and any(initial[0].get(k) != objects[0].get(k) for k in ('object_guid', 'object_sid')): raise denied()
        if self._history(job_id, candidate_job_id=candidate_job_id)[1:] != (history, leases): raise denied()
        return {'job_id': job_id, 'history': history, 'lease_ids': sorted(leases), 'evidence': fresh,
                'validator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'purpose': self.purpose, 'execution_window_seconds': 21600}

    def _plan_snapshot(self, payload):
        return self._snapshot(payload['job_id'])

    def _protected_plan(self, plan_id, sha):
        if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha) or plan_id != self.prefix+sha:
            raise denied()
        plan = self._read(self.plans/(plan_id+'.json'))
        body = {k: v for k, v in plan.items() if k not in ('plan_id', 'sha256')}
        if (set(plan) != {'schema_version', 'operation', 'created_at', 'expires_at', 'content_sha256',
                         'payload', 'plan_id', 'sha256'} or plan['schema_version'] != 1
                or plan['operation'] != self.operation or self.io.digest(body) != sha
                or plan['sha256'] != sha or plan['plan_id'] != plan_id
                or self.io.digest(plan['payload']) != plan['content_sha256']): raise denied()
        created, expires = (datetime.fromisoformat(plan[k]) for k in ('created_at', 'expires_at'))
        if created.tzinfo is None or expires.tzinfo is None or expires-created != timedelta(minutes=30) or created > self.clock():
            raise denied()
        return plan, created, expires

    def plan(self, job_id):
        try:
            with maintenance_lock(self.settings):
                payload = self._snapshot(job_id)
                now = self.clock().replace(microsecond=0)
                body = {'schema_version': 1, 'operation': self.operation, 'created_at': now.isoformat(),
                        'expires_at': (now+timedelta(minutes=30)).isoformat(),
                        'payload': payload, 'content_sha256': self.io.digest(payload)}
                sha = self.io.digest(body)
                plan = dict(body, plan_id=self.prefix+sha, sha256=sha)
                path = self.plans/(plan['plan_id']+'.json')
                try: self.io.private_create(path, plan)
                except FileExistsError:
                    if self._read(path) != plan: raise denied()
                return dict({k: plan[k] for k in ('schema_version', 'plan_id', 'sha256', 'created_at', 'expires_at')},
                            purpose=payload['purpose'], execution_window_seconds=21600)
        except Exception: raise denied() from None

    def confirm(self, plan_id, sha):
        try:
            with maintenance_lock(self.settings):
                plan, created, expires = self._protected_plan(plan_id, sha)
                if self.clock() >= expires or self._plan_snapshot(plan['payload']) != plan['payload']: raise denied()
                path = self.reviews/(sha+'.json')
                if path.exists() or path.is_symlink():
                    record = self._receipt(sha)
                else:
                    now = self.clock().replace(microsecond=0)
                    record = {'schema_version': 1, 'purpose': self.purpose, 'review_sha256': sha,
                              'confirmed_at': now.isoformat(), 'valid_until': (now+timedelta(seconds=21600)).isoformat()}
                    self.io.private_create(path, record)
                return record
        except Exception: raise denied() from None

    def _receipt(self, sha):
        plan, created, expires = self._protected_plan(self.prefix+sha, sha)
        record = self._read(self.reviews/(sha+'.json'))
        if (set(record) != {'schema_version', 'purpose', 'review_sha256', 'confirmed_at', 'valid_until'}
                or record['schema_version'] != 1 or record['purpose'] != self.purpose
                or record['review_sha256'] != sha): raise denied()
        confirmed, until = (datetime.fromisoformat(record[k]) for k in ('confirmed_at', 'valid_until'))
        if (confirmed.tzinfo is None or until.tzinfo is None or not created <= confirmed < expires
                or until-confirmed != timedelta(seconds=21600) or not confirmed <= self.clock() < until): raise denied()
        return record

    def exclusions(self, sha):
        try:
            with maintenance_lock(self.settings):
                self._receipt(sha)
                plan, _, _ = self._protected_plan('setup-maintenance-'+sha, sha)
                if self._snapshot(plan['payload']['job_id']) != plan['payload']: raise denied()
                return {'job_ids': {plan['payload']['job_id']}, 'lease_ids': set(plan['payload']['lease_ids'])}
        except Exception: raise denied() from None


if __name__ == '__main__':
    import sys
    settings = control_module('config').Settings.from_env()
    job = control_module('setup_jobs').SetupJobRepository(settings).get(sys.argv[1])
    sys.stdout.buffer.write(control_module('setup_plans').canonical(observe(settings, job)))
