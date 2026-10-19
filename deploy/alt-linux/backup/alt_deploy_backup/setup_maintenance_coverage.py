"""Exact complete-set controller maintenance review, including partial joins."""
from datetime import timedelta
import hashlib
from pathlib import Path
import re
import stat

from .setup_compat import control_module, history_fingerprint, MAINTENANCE_MODULES
from .setup_closed_failure import ClosedFailureEvidence
from .setup_maintenance_review import MaintenanceReview, maintenance_lock, native_observe, denied
from .setup_partial_observation import validate_evidence


def validate_payload(payload):
    if (set(payload) != {'covered', 'job_ids', 'lease_ids', 'history', 'validators', 'purpose', 'execution_window_seconds'}
            or payload['purpose'] != 'controller_maintenance_only' or payload['execution_window_seconds'] != 21600
            or not isinstance(payload['covered'], list) or not payload['covered'] or len(payload['covered']) > 1024
            or payload['job_ids'] != sorted(set(payload['job_ids']))
            or payload['lease_ids'] != sorted(set(payload['lease_ids']))
            or len(payload['covered']) != len(payload['job_ids']) or len(payload['lease_ids']) != 2*len(payload['job_ids'])
            or set(payload['validators']) != set(MAINTENANCE_MODULES)
            or any(not re.fullmatch('[0-9a-f]{64}', sha) for sha in payload['validators'].values())
            or not isinstance(payload['history'], dict)
            or any(not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts
                   or not re.fullmatch('[0-9a-f]{64}', sha) for name, sha in payload['history'].items())): raise denied()
    leases = []
    for index, record in enumerate(payload['covered']):
        if (set(record) != {'job_id', 'failed_run_id', 'configuration_run_id', 'history_sha256', 'lease_ids', 'mode', 'evidence'}
                or record['job_id'] != payload['job_ids'][index]
                or not re.fullmatch('setup-run-[0-9a-f]{32}', record['failed_run_id'])
                or not re.fullmatch('[0-9a-f]{32}', record['configuration_run_id'])
                or not re.fullmatch('[0-9a-f]{64}', record['history_sha256'])
                or record['mode'] not in ('joined', 'partial_ad') or len(record['lease_ids']) != 2
                or any(not re.fullmatch('[0-9a-f]{32}', identifier) for identifier in record['lease_ids'])
                or record['lease_ids'] != sorted(set(record['lease_ids'])) or not isinstance(record['evidence'], dict)): raise denied()
        leases += record['lease_ids']
    if sorted(leases) != payload['lease_ids']: raise denied()


class MaintenanceCoverage(MaintenanceReview):
    schema_version = 2

    def __init__(self, settings, *, observer=None, clock=None):
        super().__init__(settings, observer=observer or (lambda job: native_observe(settings, job, coverage=True)), clock=clock)

    def _discover(self):
        repository = self.jobs.SetupJobRepository(self.settings)
        repository._check_admissions()
        retry = control_module('setup_retry')
        reviewed = retry.reviewed_jobs(self.settings)
        active = [job for job in repository.jobs.list()
                  if job.state in self.jobs.ACTIVE_SETUP_STATES and job.job_id not in reviewed]
        if (not active or any(job.status.get('kind') != 'setup' or job.state != 'unknown_requires_review'
                or job.request.get('operation') != 'full_setup' or not job.status['claimed'] for job in active)): raise denied()
        ids = sorted(job.job_id for job in active)
        closed = [ClosedFailureEvidence(self.settings, clock=self.clock).load(identifier) for identifier in ids]
        lease_ids = sorted(identifier for value in closed for identifier in value['lease_ids'])
        unresolved = [record for record in self.jobs.unresolved_legacy_reservations(self.settings)
                      if record['run_id'] not in retry.reviewed_legacy_runs(self.settings)]
        if (len(lease_ids) != len(set(lease_ids)) or sorted(r['reservation_id'] for r in unresolved) != lease_ids
                or any(r['state'] != 'unknown_requires_review' for r in unresolved)): raise denied()
        return repository, closed, lease_ids

    def _validators(self):
        hashes = {}
        for name in MAINTENANCE_MODULES:
            path = Path(__file__).with_name(name)
            info = path.lstat()
            # Source sandbox uses its service owner; production code is checked
            # root-owned by the bridge/native observer before import.
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > 1048576: raise denied()
            from .fs import read_regular_bytes
            hashes[name] = hashlib.sha256(read_regular_bytes(path, max_bytes=1048576)).hexdigest()
        return hashes

    def _history(self, closed):
        history = {name: sha for name, sha in history_fingerprint(self.settings.state_root).items()
                   if not name.startswith('setup-maintenance-')}
        for value in closed:
            for name, sha in value['manifest'].items():
                if name in history and history[name] != sha: raise denied()
                history[name] = sha
        return history

    def _snapshot_all(self):
        repository, closed, leases = self._discover()
        history = self._history(closed)
        validators = self._validators()
        covered = []
        for value in closed:
            fresh = self.observer(repository.get(value['job_id']))
            if 'partial_local' in fresh:
                mode = 'partial_ad'
                validate_evidence(value, fresh, mode=mode)
            else:
                mode = 'joined'
                self._validate_joined(value['original'], fresh)
            covered.append({k: value[k] for k in ('job_id', 'failed_run_id', 'configuration_run_id', 'history_sha256', 'lease_ids')}
                           | {'mode': mode, 'evidence': fresh})
        _, after, after_leases = self._discover()
        if ([v['job_id'] for v in after] != [v['job_id'] for v in closed] or after_leases != leases
                or self._history(after) != history or self._validators() != validators): raise denied()
        payload = {'covered': covered, 'job_ids': [v['job_id'] for v in closed], 'lease_ids': leases,
                   'history': history, 'validators': validators, 'purpose': self.purpose, 'execution_window_seconds': 21600}
        validate_payload(payload)
        return payload

    def _plan_snapshot(self, payload):
        validate_payload(payload)
        return self._snapshot_all()

    def plan(self):
        try:
            with maintenance_lock(self.settings):
                payload = self._snapshot_all()
                now = self.clock().replace(microsecond=0)
                body = {'schema_version': 2, 'operation': self.operation, 'created_at': now.isoformat(),
                    'expires_at': (now+timedelta(minutes=30)).isoformat(), 'payload': payload,
                    'content_sha256': self.io.digest(payload)}
                sha = self.io.digest(body)
                plan = dict(body, plan_id=self.prefix+sha, sha256=sha)
                path = self.plans/(plan['plan_id']+'.json')
                try: self.io.private_create(path, plan)
                except FileExistsError:
                    if self._read(path) != plan: raise denied()
                return {**{k: plan[k] for k in ('schema_version', 'plan_id', 'sha256', 'created_at', 'expires_at')},
                        'purpose': self.purpose, 'covered_jobs': len(payload['job_ids']),
                        'covered_leases': len(payload['lease_ids']), 'execution_window_seconds': 21600}
        except Exception: raise denied() from None

    def exclusions(self, sha):
        try:
            with maintenance_lock(self.settings):
                self._receipt(sha)
                plan, _, _ = self._protected_plan(self.prefix+sha, sha)
                if self._plan_snapshot(plan['payload']) != plan['payload']: raise denied()
                return {'job_ids': set(plan['payload']['job_ids']), 'lease_ids': set(plan['payload']['lease_ids'])}
        except Exception: raise denied() from None
