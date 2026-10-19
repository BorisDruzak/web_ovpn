"""Protected archival evidence and one original-failure recovery claim."""
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from .ad_directory import fail
from .setup_jobs import service_uid, fsync_directory
from .setup_plans import (SetupPlanStore, canonical, decode_state_bytes, digest, private_create,
                          private_directory, private_read, private_read_bytes, MAX_STATE_BYTES)

DIRECTORIES = ('setup-partial-local-evidence', 'setup-partial-local-plans',
               'setup-partial-local-claims', 'setup-partial-local-results')
EFFECTS = ['native_local_pam_nss', 'disable_previous_auth_services', 'goa_absent_no_write']
HEX = re.compile('[0-9a-f]{64}')


def denied():
    return fail('setup_partial_local_invalid', 'Partial-local evidence is invalid, changed, expired or already consumed; no repeat is admitted')


def claim_key(payload):
    return digest({key: payload[key] for key in ('job_id', 'failed_run_id')})


def assert_no_pending(settings):
    if not any((settings.state_root/name).exists() or (settings.state_root/name).is_symlink() for name in DIRECTORIES): return
    if PartialLocalStore(settings).pending_attempts():
        raise fail('setup_partial_local_unresolved', 'An entered partial-local recovery has no verified successful result; execution remains blocked')


def _write_bytes(path, raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_STATE_BYTES: raise denied()
    private_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fsync_directory(path.parent)


class PartialPlans(SetupPlanStore):
    prefix = 'partial-local-'
    directory = DIRECTORIES[1]
    plan_operation = 'partial_local_recovery'


class PartialLocalStore:
    def __init__(self, settings, *, clock=None):
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.uid = service_uid(settings)
        self.plans = PartialPlans(settings.state_root, clock=self.clock)
        self.evidence = settings.state_root/DIRECTORIES[0]
        self.claims = settings.state_root/DIRECTORIES[2]
        self.results = settings.state_root/DIRECTORIES[3]

    def _read(self, path): return private_read(path, owner_uid=self.uid)
    def _raw(self, path): return private_read_bytes(path, owner_uid=self.uid)

    def _directory(self, path, *, optional=False):
        if not path.exists() and not path.is_symlink() and optional: return False
        for parent in path.parents:
            if not stat.S_ISDIR(parent.lstat().st_mode): raise denied()
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or stat.S_IMODE(info.st_mode) != 0o700: raise denied()
        return True

    def retain_closed(self, closed):
        sha = closed['history_sha256']
        if (not isinstance(sha, str) or not HEX.fullmatch(sha)
                or {name: hashlib.sha256(raw).hexdigest() for name, raw in closed['files'].items()} != closed['manifest']
                or digest(closed['manifest']) != sha): raise denied()
        root = self.evidence/sha
        if root.exists() or root.is_symlink():
            if self.load_closed(sha) != closed: raise denied()
        else:
            private_directory(self.evidence)
            stage = Path(tempfile.mkdtemp(prefix='.retain-', dir=self.evidence))
            try:
                for name, raw in closed['files'].items():
                    _write_bytes(stage/'files'/(hashlib.sha256(name.encode()).hexdigest()+'.bin'), raw)
                private_create(stage/'manifest.json', {key: value for key, value in closed.items() if key != 'files'})
                fsync_directory(stage)
                os.rename(stage, root)
                fsync_directory(self.evidence)
            except BaseException:
                # No claim or target action exists; retain incomplete staging
                # evidence for review rather than hiding a publication failure.
                raise
        return {'history_sha256': sha}

    def load_closed(self, sha):
        try:
            if not isinstance(sha, str) or not HEX.fullmatch(sha): raise denied()
            root = self.evidence/sha
            self._directory(root); self._directory(root/'files')
            if {p.name for p in root.iterdir()} != {'manifest.json', 'files'}: raise denied()
            closed = self._read(root/'manifest.json')
            if (set(closed) != {'schema_version', 'job_id', 'failed_run_id', 'configuration_run_id', 'machine', 'binding',
                    'original', 'run', 'result', 'predecessor_job', 'lease_ids', 'history_sha256', 'manifest'}
                    or type(closed['schema_version']) is not int or closed['schema_version'] != 1
                    or closed['history_sha256'] != sha or digest(closed['manifest']) != sha
                    or not isinstance(closed['manifest'], dict) or not 1 <= len(closed['manifest']) <= 17000): raise denied()
            files = {}
            for name, expected in closed['manifest'].items():
                if (not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts
                        or not isinstance(expected, str) or not HEX.fullmatch(expected)): raise denied()
                raw = self._raw(root/'files'/(hashlib.sha256(name.encode()).hexdigest()+'.bin'))
                if hashlib.sha256(raw).hexdigest() != expected: raise denied()
                files[name] = raw
            expected_files = {hashlib.sha256(name.encode()).hexdigest()+'.bin' for name in files}
            if {p.name for p in (root/'files').iterdir()} != expected_files: raise denied()
            # The current assignment is the sole intentionally mutable original.
            # Its exact failed revision remains inside this immutable capsule.
            binding_path = 'domain-assignments/'+closed['machine']['uuid']+'.json'
            if decode_state_bytes(files[binding_path]) != closed['binding']: raise denied()
            if any(self._raw(self.settings.state_root/name) != raw for name, raw in files.items() if name != binding_path): raise denied()
            from .setup_retry import full_predecessor
            reference = full_predecessor(self.settings, closed['job_id'], closed['machine']['uuid'], closed['failed_run_id'])
            if reference != closed['predecessor_job']: raise denied()
            from .setup_jobs import SetupJobRepository
            job = SetupJobRepository(self.settings).get(closed['job_id'])
            if job.request['plan']['payload'] != closed['original'] or closed['machine'] != closed['original']['machine']: raise denied()
            run = decode_state_bytes(files['setup-runs/'+closed['failed_run_id']+'.json'])
            result = decode_state_bytes(files['configure-runs/'+closed['configuration_run_id']+'/result.json'])
            if (run != closed['run'] or run['configuration_run_id'] != closed['configuration_run_id']
                    or result != closed['result'] or run['result'] != result
                    or decode_state_bytes(files['setup-plans/'+run['plan_id']+'.json']) != job.request['plan']): raise denied()
            from .configure import historical_setup_request, _read_configure_result
            request = historical_setup_request(closed['original'], expected_uuid=closed['machine']['uuid'])
            if (decode_state_bytes(files['configure-runs/'+closed['configuration_run_id']+'/request.json']) != request.to_dict()
                    or _read_configure_result(result, request) != result): raise denied()
            expected_binding = dict(closed['original']['binding'], schema_version=1,
                revision=(closed['original'].get('existing_assignment') or {}).get('revision', 0)+1,
                run_id=closed['failed_run_id'], date=run['created_at'], result='failed')
            if closed['binding'] != expected_binding: raise denied()
            live = [path for path in job.job_dir.iterdir() if path.name != 'events']
            if (job.job_dir/'events').exists(): live += list((job.job_dir/'events').iterdir())
            if ({str(path.relative_to(self.settings.state_root)) for path in live}
                    != {name for name in files if name.startswith('jobs/'+job.job_id+'/')}): raise denied()
            lease_names = [name for name in files if name.startswith('legacy-setup-reservations/')]
            if (sorted(Path(name).stem for name in lease_names) != closed['lease_ids']
                    or len(lease_names) != 2
                    or {(value['operation'], value['run_id']) for name in lease_names
                        for value in [decode_state_bytes(files[name])]} != {
                            ('full_setup', closed['failed_run_id']), ('configure', closed['configuration_run_id'])}): raise denied()
            return dict(closed, files=files)
        except Exception: raise denied() from None

    def _payload(self, payload):
        closed = self.load_closed(payload['history_sha256'])
        if (set(payload) != {'job_id', 'failed_run_id', 'configuration_run_id', 'machine', 'history_sha256',
                            'evidence', 'source_sha256', 'rehearsal', 'effects'}
                or any(payload[k] != closed[k] for k in ('job_id', 'failed_run_id', 'configuration_run_id', 'machine'))
                or not isinstance(payload['source_sha256'], str) or not HEX.fullmatch(payload['source_sha256'])
                or payload['effects'] != EFFECTS
                or set(payload['rehearsal']) != {'status', 'helper_sha256', 'native_sha256'}
                or payload['rehearsal']['status'] != 'passed'
                or any(not HEX.fullmatch(payload['rehearsal'][k]) for k in ('helper_sha256', 'native_sha256'))
                or payload['evidence']['machine'] != closed['machine']
                or payload['evidence']['partial_local']['mode'] != 'partial_ad'): raise denied()
        return closed

    def create(self, payload):
        self._payload(payload)
        result = self.plans.create(payload)
        fsync_directory(self.plans.root)
        return result

    def load(self, plan_id, sha, *, archival=False):
        try:
            if not isinstance(plan_id, str) or plan_id != self.plans.prefix+sha or not HEX.fullmatch(sha): raise denied()
            plan = self._read(self.plans.root/(plan_id+'.json'))
            if (set(plan) != {'schema_version', 'operation', 'created_at', 'expires_at', 'content_sha256', 'payload', 'plan_id', 'sha256'}
                    or type(plan['schema_version']) is not int or plan['schema_version'] != 1
                    or plan['operation'] != 'partial_local_recovery' or plan['plan_id'] != plan_id or plan['sha256'] != sha
                    or digest({k: v for k, v in plan.items() if k not in ('plan_id', 'sha256')}) != sha
                    or not isinstance(plan['payload'], dict) or digest(plan['payload']) != plan['content_sha256']): raise denied()
            created, expires = (datetime.fromisoformat(plan[k]) for k in ('created_at', 'expires_at'))
            if (created.tzinfo is None or expires.tzinfo is None or expires-created != timedelta(minutes=30)
                    or created > self.clock() or not archival and self.clock() >= expires): raise denied()
            self._payload(plan['payload'])
            return plan
        except Exception: raise denied() from None

    def claim_once(self, plan):
        try:
            if self.load(plan['plan_id'], plan['sha256']) != plan: raise denied()
            key = claim_key(plan['payload'])
            claim = {'schema_version': 1, 'operation': 'partial_local_claim', 'claim_key': key,
                     'job_id': plan['payload']['job_id'], 'failed_run_id': plan['payload']['failed_run_id'],
                     'plan_id': plan['plan_id'], 'plan_sha256': plan['sha256'], 'entered_at': self.clock().isoformat()}
            private_create(self.claims/(key+'.json'), claim)
            fsync_directory(self.claims)
            return claim
        except Exception: raise denied() from None

    def _claim(self, path):
        claim = self._read(path)
        if (set(claim) != {'schema_version', 'operation', 'claim_key', 'job_id', 'failed_run_id',
                          'plan_id', 'plan_sha256', 'entered_at'}
                or type(claim['schema_version']) is not int or claim['schema_version'] != 1
                or claim['operation'] != 'partial_local_claim' or claim['claim_key'] != claim_key(claim)
                or path.name != claim['claim_key']+'.json'): raise denied()
        plan = self.load(claim['plan_id'], claim['plan_sha256'], archival=True)
        if any(claim[k] != plan['payload'][k] for k in ('job_id', 'failed_run_id')): raise denied()
        entered = datetime.fromisoformat(claim['entered_at'])
        if not datetime.fromisoformat(plan['created_at']) <= entered < datetime.fromisoformat(plan['expires_at']) or entered > self.clock(): raise denied()
        return claim

    def _result(self, claim, result):
        if (set(result) != {'schema_version', 'operation', 'claim_key', 'plan_id', 'plan_sha256', 'status',
                           'target', 'after', 'finished_at'}
                or type(result['schema_version']) is not int or result['schema_version'] != 1
                or result['operation'] != 'partial_local_result'
                or any(result[k] != claim[k] for k in ('claim_key', 'plan_id', 'plan_sha256'))
                or result['status'] not in ('successful', 'unknown_requires_review')
                or not datetime.fromisoformat(claim['entered_at']) <= datetime.fromisoformat(result['finished_at']) <= self.clock()): raise denied()
        if result['target'] is not None:
            from .setup_partial_local_runtime import validate_target_result
            validate_target_result(self.load(claim['plan_id'], claim['plan_sha256'], archival=True), result['target'])
        if result['status'] == 'unknown_requires_review' and result['after'] is not None: raise denied()
        if result['status'] == 'successful':
            plan = self.load(claim['plan_id'], claim['plan_sha256'], archival=True)
            target, after = result['target'], result['after']
            before = plan['payload']['evidence']
            if (target['status'] != 'successful' or target['claim_key'] != claim['claim_key']
                    or target['plan_sha256'] != claim['plan_sha256'] or not HEX.fullmatch(target['backup_sha256'])
                    or target['before_sha256'] != digest(before['partial_local']['native'])
                    or target['after_sha256'] != digest(after['partial_local']['native'])
                    or after['machine'] != before['machine'] or after['ssh_binding'] != before['ssh_binding']
                    or after['boot_id'] != before['boot_id'] or after['partial_local']['mode'] != 'local'
                    or after['partial_local']['native']['auth_scheme'] != 'local'
                    or after['partial_local']['quiet']['credentials_absent'] is not True
                    or after['partial_local']['quiet']['processes_absent'] is not True
                    or after['partial_local']['collisions'] != {'complete': True, 'matches': 0}): raise denied()
            from .setup_partial_local_runtime import validate_local_after, validate_target_result
            validate_target_result(plan, target)
            validate_local_after(plan['payload'], after)
        return result

    def publish_result(self, claim, result):
        try:
            if self._claim(self.claims/(claim['claim_key']+'.json')) != claim: raise denied()
            self._result(claim, result)
            private_create(self.results/(claim['claim_key']+'.json'), result)
            fsync_directory(self.results)
            return result
        except Exception: raise denied() from None

    def result_for(self, claim):
        path = self.results/(claim['claim_key']+'.json')
        if not path.exists() and not path.is_symlink(): return None
        return self._result(claim, self._read(path))

    def validate_artifacts(self):
        try:
            for name in DIRECTORIES:
                root = self.settings.state_root/name
                if not self._directory(root, optional=True): continue
                for path in root.iterdir():
                    if name == DIRECTORIES[0]: self.load_closed(path.name)
                    elif name == DIRECTORIES[1]:
                        if path.name != path.stem+'.json': raise denied()
                        self.load(path.stem, path.stem.removeprefix('partial-local-'), archival=True)
                    elif name == DIRECTORIES[2]: self._claim(path)
                    else:
                        claim = self._claim(self.claims/path.name)
                        self._result(claim, self._read(path))
        except Exception: raise denied() from None

    def pending_attempts(self):
        self.validate_artifacts()
        if not self._directory(self.claims, optional=True): return []
        return [claim for path in sorted(self.claims.iterdir())
                if (result := self.result_for(claim := self._claim(path))) is None or result['status'] != 'successful']
