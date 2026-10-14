"""One candidate-specific queue permission; never maintenance or original recovery."""
from datetime import timedelta, datetime
import copy
import hashlib
from pathlib import Path
import re
import stat

from .setup_compat import control_module, setup_settings
from .setup_maintenance_review import MaintenanceReview, maintenance_lock


def denied():
    return control_module('ad_directory').fail('setup_queue_review_invalid',
        'Queue review is missing, changed, busy, unsafe or expired; execution remains blocked')


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
                receipt = super().confirm(plan_id, sha)
                plan, _, _ = self._protected_plan(plan_id, sha)
                candidate = plan['payload']['candidate']['job_id']
                pointer = {'schema_version': 1, 'purpose': self.purpose,
                           'candidate_job_id': candidate, 'review_sha256': sha}
                path = self.settings.state_root/'setup-queue-admissions'/(candidate+'.json')
                try: self.io.private_create(path, pointer)
                except FileExistsError:
                    if self._read(path) != pointer: raise denied()
                return receipt
        except Exception: raise denied() from None

    def for_candidate(self, candidate_job_id):
        try:
            with maintenance_lock(self.settings):
                # Resolve first: a caller cannot supply a filesystem path.
                self.jobs.SetupJobRepository(self.settings).get(candidate_job_id)
                pointer = self._read(self.settings.state_root/'setup-queue-admissions'/(candidate_job_id+'.json'))
                sha = pointer['review_sha256']
                if pointer != {'schema_version': 1, 'purpose': self.purpose,
                    'candidate_job_id': candidate_job_id, 'review_sha256': sha}: raise denied()
                self._receipt(sha)
                plan, _, _ = self._protected_plan(self.prefix+sha, sha)
                payload = plan['payload']
                if (payload['candidate']['job_id'] != candidate_job_id
                        or self._plan_snapshot(payload) != payload): raise denied()
                return {'job_ids': {payload['job_id']}, 'lease_ids': set(payload['lease_ids'])}
        except Exception: raise denied() from None


def validate_artifacts(root):
    """Retained records stay protected history after expiration and consumption."""
    io = control_module('setup_plans')
    uid = root.stat().st_uid
    repository = control_module('setup_jobs').SetupJobRepository(setup_settings(root))
    plans, receipts, admissions = {}, {}, {}
    def documents(name):
        directory = root/name
        if not directory.exists() and not directory.is_symlink(): return []
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700: raise denied()
        return [(p, io.private_read(p, owner_uid=uid)) for p in directory.iterdir()]
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
        initial = copy.deepcopy(candidate.status)
        initial.update(state='queued',stage='created',claimed=False,process_identity=None,
                       updated_at=initial['created_at'],stage_history=initial['stage_history'][:1])
        if reference != {'job_id':candidate.job_id,'request_sha256':io.digest(candidate.request),
            'status_sha256':io.digest(initial),'plan_sha256':candidate.status['plan_sha256'],
            'identities':candidate.request['identities'],
            'source_sha256':candidate.request['plan']['payload'].get('source_sha256')}: raise denied()
        QueueAdmissionReview.distinct_candidate(reference['identities'],old.request['identities'],payload['evidence']['computer'])
        plans[sha] = value
    for path, value in documents(QueueAdmissionReview.review_directory):
        sha = value.get('review_sha256')
        if (sha not in plans or path.name != sha+'.json'
                or set(value) != {'schema_version','purpose','review_sha256','confirmed_at','valid_until'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['purpose'] != QueueAdmissionReview.purpose): raise denied()
        confirmed, until = (datetime.fromisoformat(value[k]) for k in ('confirmed_at','valid_until'))
        if (confirmed.tzinfo is None or until.tzinfo is None or until-confirmed != timedelta(hours=6)
                or not datetime.fromisoformat(plans[sha]['created_at']) <= confirmed < datetime.fromisoformat(plans[sha]['expires_at'])): raise denied()
        receipts[sha] = value
    for path, value in documents('setup-queue-admissions'):
        sha = value.get('review_sha256')
        if (sha not in receipts or type(value.get('schema_version')) is not int
                or value != {'schema_version':1,'purpose':QueueAdmissionReview.purpose,
                    'candidate_job_id':plans[sha]['payload']['candidate']['job_id'],'review_sha256':sha}
                or path.name != value['candidate_job_id']+'.json'): raise denied()
        admissions[sha] = value
    if set(receipts) != set(admissions): raise denied()
