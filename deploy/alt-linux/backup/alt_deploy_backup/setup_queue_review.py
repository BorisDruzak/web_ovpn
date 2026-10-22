"""One candidate-specific queue permission; never maintenance or original recovery."""
from datetime import timedelta, datetime
import copy
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid

from .setup_compat import control_module, setup_settings
from .setup_maintenance_review import MaintenanceReview, maintenance_lock


def denied():
    return control_module('ad_directory').fail('setup_queue_review_invalid',
        'Queue review is missing, changed, busy, unsafe or expired; execution remains blocked')


def initial_candidate_status(job, settings):
    """Rebuild admission bytes without later, independently validated phases."""
    initial = copy.deepcopy(job.status)
    if 'workflow' in initial:
        phases = control_module('setup_phases')
        phases.validate_workflow_status(job.request, initial)
        phases.WorkflowPhaseStore(settings).records(job)
        # submit() never writes this field. It is attached only after the
        # immutable system result, and remains validated in current history.
        initial.pop('workflow')
    initial.update(state='queued', stage='created', claimed=False, process_identity=None,
                   updated_at=initial['created_at'], stage_history=initial['stage_history'][:1])
    return initial


class QueueAdmissionReview(MaintenanceReview):
    prefix = 'setup-queue-review-'
    operation = 'queued_other_machine_review_plan'
    purpose = 'queued_other_machine_only'
    plan_directory = 'setup-queue-review-plans'
    review_directory = 'setup-queue-reviews'

    @staticmethod
    def distinct_candidate(identity, original, computer):
        if (identity['uuid'] == original['uuid'] or identity['hostname'] == original['hostname']
                or identity.get('computer_guid') is not None and any(
                    identity['computer_guid'].casefold() == obj['object_guid'].casefold()
                    for obj in computer.get('objects', []))):
            raise denied()

    def _candidate(self, job_id):
        repository = self.jobs.SetupJobRepository(self.settings)
        repository._check_admissions()
        job = repository.get(job_id)
        if job.state != 'queued' or job.status['claimed']: raise denied()
        queued = sorted((j for j in repository.list() if j.state == 'queued' and not j.status['claimed']),
                        key=lambda j: j.status['admission_sequence'])
        if not queued or queued[0].job_id != job_id: raise denied()
        from_phase=control_module('setup_phases')
        if any('workflow' in j.status and j.state=='queued' for j in repository.list()):
            eligible=from_phase.eligible_candidates(self.settings)
            if not eligible or eligible[0][1:]!=(job_id,None):raise denied()
        plan = job.request['plan']
        created, expires = (datetime.fromisoformat(plan[k]) for k in ('created_at', 'expires_at'))
        if not created <= self.clock() < expires: raise denied()
        runtime = control_module('setup_runtime')
        source = runtime.source_fingerprint(self.settings.ansible_project_dir,
            Path(control_module('setup').__file__).parent)
        if source != plan['payload'].get('source_sha256'): raise denied()
        return job, {'job_id': job_id, 'request_sha256': self.io.digest(job.request),
            'status_sha256': self.io.digest(job.status), 'plan_sha256': plan['sha256'],
            'identities': job.request['identities'], 'source_sha256': source}

    def _queue_snapshot(self, old_id, candidate_id):
        candidate, reference = self._candidate(candidate_id)
        snapshot = self._snapshot(old_id, candidate_job_id=candidate_id)
        old = self.jobs.SetupJobRepository(self.settings).get(old_id)
        self.distinct_candidate(candidate.request['identities'], old.request['identities'], snapshot['evidence']['computer'])
        phases=control_module('setup_phases')
        for idle in self.jobs.SetupJobRepository(self.settings).list():
            if idle.job_id in (old_id,candidate_id) or not phases.idle_workflow(self.settings,idle):continue
            identity=phases.effective_identity(self.settings,idle)
            self.distinct_candidate(identity,old.request['identities'],snapshot['evidence']['computer'])
            self.distinct_candidate(identity,candidate.request['identities'],candidate.request['plan']['payload']['computer'])
        if self._candidate(candidate_id)[1] != reference: raise denied()
        return dict(snapshot, candidate=reference,
            queue_validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())

    def _plan_snapshot(self, payload):
        return self._queue_snapshot(payload['job_id'], payload['candidate']['job_id'])

    def plan(self, blocked_job_id, candidate_job_id):
        try:
            with maintenance_lock(self.settings):
                payload = self._queue_snapshot(blocked_job_id, candidate_job_id)
                now = self.clock().replace(microsecond=0)
                body = {'schema_version': 1, 'operation': self.operation, 'created_at': now.isoformat(),
                    'expires_at': (now+timedelta(minutes=30)).isoformat(),
                    'payload': payload, 'content_sha256': self.io.digest(payload)}
                sha = self.io.digest(body)
                value = dict(body, plan_id=self.prefix+sha, sha256=sha)
                path = self.plans/(value['plan_id']+'.json')
                try: self.io.private_create(path, value)
                except FileExistsError:
                    if self._read(path) != value: raise denied()
                return {**{k: value[k] for k in ('schema_version', 'plan_id', 'sha256', 'created_at', 'expires_at')},
                        'purpose': self.purpose, 'candidate_job_id': candidate_job_id}
        except Exception: raise denied() from None

    def confirm(self, plan_id, sha):
        try:
            with maintenance_lock(self.settings):
                plan, _, expires = self._protected_plan(plan_id, sha)
                candidate = plan['payload']['candidate']['job_id']
                path = self.reviews/(candidate+'.json')
                # Reject a different confirmation before publishing any record.
                existing = self._receipt(sha) if path.exists() or path.is_symlink() else None
                if self.clock() >= expires or self._plan_snapshot(plan['payload']) != plan['payload']: raise denied()
                if existing is not None: return existing
                now = self.clock().replace(microsecond=0)
                record = {'schema_version': 1, 'purpose': self.purpose, 'candidate_job_id': candidate,
                          'review_sha256': sha, 'confirmed_at': now.isoformat(),
                          'valid_until': (now+timedelta(hours=6)).isoformat()}
                self._publish(path, record)
                return record
        except Exception: raise denied() from None

    @staticmethod
    def _sync(directory):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

    def _publish(self, path, record):
        self.io.private_directory(self.reviews)
        pending = self.reviews/'.pending'
        self.io.private_directory(pending)
        self._sync(self.reviews.parent)
        self._sync(self.reviews)
        temporary = pending/(uuid.uuid4().hex+'.tmp')
        try:
            self.io.private_create(temporary, record)
            # The final candidate-keyed receipt appears complete or not at all.
            # link refuses to overwrite any existing confirmation.
            os.link(temporary, path, follow_symlinks=False)
            self._sync(self.reviews)
        finally:
            temporary.unlink(missing_ok=True)
            self._sync(pending)

    def _receipt(self, sha):
        plan, created, expires = self._protected_plan(self.prefix+sha, sha)
        candidate = plan['payload']['candidate']['job_id']
        record = self._read(self.reviews/(candidate+'.json'))
        if (set(record) != {'schema_version','purpose','candidate_job_id','review_sha256','confirmed_at','valid_until'}
                or type(record['schema_version']) is not int or record['schema_version'] != 1
                or record['purpose'] != self.purpose or record['candidate_job_id'] != candidate
                or record['review_sha256'] != sha): raise denied()
        confirmed, until = (datetime.fromisoformat(record[k]) for k in ('confirmed_at','valid_until'))
        if (confirmed.tzinfo is None or until.tzinfo is None or not created <= confirmed < expires
                or until-confirmed != timedelta(hours=6) or not confirmed <= self.clock() < until): raise denied()
        return record

    def for_candidate(self, candidate_job_id):
        try:
            with maintenance_lock(self.settings):
                # Resolve first: a caller cannot supply a filesystem path.
                self.jobs.SetupJobRepository(self.settings).get(candidate_job_id)
                receipt = self._read(self.reviews/(candidate_job_id+'.json'))
                sha = receipt['review_sha256']
                self._receipt(sha)
                plan, _, _ = self._protected_plan(self.prefix+sha, sha)
                payload = plan['payload']
                if (payload['candidate']['job_id'] != candidate_job_id
                        or self._plan_snapshot(payload) != payload): raise denied()
                return {'job_ids': {payload['job_id']}, 'lease_ids': set(payload['lease_ids'])}
        except Exception: raise denied() from None

    def admit_candidate(self, candidate_job_id):
        """Worker-owned technical admission after the operator approved Setup.

        Only the unclaimed FIFO head can get a new receipt. Existing receipts
        remain immutable and must pass their original freshness checks.
        """
        try:
            with maintenance_lock(self.settings):
                self._candidate(candidate_job_id)
                path = self.reviews/(candidate_job_id+'.json')
                if not path.exists() and not path.is_symlink():
                    reviewed = control_module('setup_retry').reviewed_jobs(self.settings)
                    blocked = [job for job in self.jobs.SetupJobRepository(self.settings).list()
                               if job.state == 'unknown_requires_review' and job.job_id not in reviewed]
                    if len(blocked) != 1: raise denied()
                    plan = self.plan(blocked[0].job_id, candidate_job_id)
                    self.confirm(plan['plan_id'], plan['sha256'])
                return self.for_candidate(candidate_job_id)
        except Exception: raise denied() from None


def validate_artifacts(root):
    """Retained records stay protected history after expiration and consumption."""
    io = control_module('setup_plans')
    uid = root.stat().st_uid
    repository = control_module('setup_jobs').SetupJobRepository(setup_settings(root))
    plans = {}
    def documents(name):
        directory = root/name
        if not directory.exists() and not directory.is_symlink(): return []
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700: raise denied()
        values = []
        for path in directory.iterdir():
            if name == QueueAdmissionReview.review_directory and path.name == '.pending':
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700: raise denied()
                for temporary in path.iterdir():
                    if not re.fullmatch('[0-9a-f]{32}\\.tmp', temporary.name): raise denied()
                    # A killed writer may leave partial bytes here. They are
                    # protected history, never a dispatch authorization.
                    io.private_read_bytes(temporary, owner_uid=uid)
                continue
            values.append((path, io.private_read(path, owner_uid=uid)))
        return values
    for path, value in documents(QueueAdmissionReview.plan_directory):
        sha = value.get('sha256')
        if (not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha)
                or path.name != QueueAdmissionReview.prefix+sha+'.json'
                or set(value) != {'schema_version','operation','created_at','expires_at','payload','content_sha256','plan_id','sha256'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['operation'] != QueueAdmissionReview.operation or value['plan_id'] != path.stem
                or io.digest({k:v for k,v in value.items() if k not in ('plan_id','sha256')}) != sha
                or io.digest(value['payload']) != value['content_sha256']
                or value['payload'].get('purpose') != QueueAdmissionReview.purpose): raise denied()
        created, expires = (datetime.fromisoformat(value[k]) for k in ('created_at','expires_at'))
        if created.tzinfo is None or expires.tzinfo is None or expires-created != timedelta(minutes=30): raise denied()
        payload = value['payload']
        if (set(payload) != {'job_id','history','lease_ids','evidence','validator_sha256','purpose',
                             'execution_window_seconds','candidate','queue_validator_sha256'}
                or type(payload['execution_window_seconds']) is not int or payload['execution_window_seconds'] != 21600
                or not isinstance(payload['history'], dict) or not payload['history']
                or any(not isinstance(k,str) or Path(k).is_absolute() or '..' in Path(k).parts
                       or not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for k,v in payload['history'].items())
                or not isinstance(payload['lease_ids'],list) or len(set(payload['lease_ids'])) != 2
                or len(payload['lease_ids']) != 2
                or any(not isinstance(x,str) or not re.fullmatch('[0-9a-f]{32}',x) for x in payload['lease_ids'])
                or any(not isinstance(payload[k],str) or not re.fullmatch('[0-9a-f]{64}',payload[k])
                       for k in ('validator_sha256','queue_validator_sha256'))): raise denied()
        reference = payload['candidate']
        if (not isinstance(reference,dict) or set(reference) != {'job_id','request_sha256','status_sha256',
                                                              'plan_sha256','identities','source_sha256'}): raise denied()
        candidate = repository.get(reference['job_id'])
        old = repository.get(payload['job_id'])
        initial = initial_candidate_status(candidate, setup_settings(root))
        if reference != {'job_id':candidate.job_id,'request_sha256':io.digest(candidate.request),
            'status_sha256':io.digest(initial),'plan_sha256':candidate.status['plan_sha256'],
            'identities':candidate.request['identities'],
            'source_sha256':candidate.request['plan']['payload'].get('source_sha256')}: raise denied()
        QueueAdmissionReview.distinct_candidate(reference['identities'],old.request['identities'],payload['evidence']['computer'])
        plans[sha] = value
    for path, value in documents(QueueAdmissionReview.review_directory):
        sha = value.get('review_sha256')
        if (sha not in plans or path.name != plans[sha]['payload']['candidate']['job_id']+'.json'
                or set(value) != {'schema_version','purpose','candidate_job_id','review_sha256','confirmed_at','valid_until'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['candidate_job_id'] != plans[sha]['payload']['candidate']['job_id']
                or value['purpose'] != QueueAdmissionReview.purpose): raise denied()
        confirmed, until = (datetime.fromisoformat(value[k]) for k in ('confirmed_at','valid_until'))
        if (confirmed.tzinfo is None or until.tzinfo is None or until-confirmed != timedelta(hours=6)
                or not datetime.fromisoformat(plans[sha]['created_at']) <= confirmed < datetime.fromisoformat(plans[sha]['expires_at'])): raise denied()
    # The prepublication two-record prototype was never deployed.
    if (root/'setup-queue-admissions').exists() or (root/'setup-queue-admissions').is_symlink(): raise denied()
