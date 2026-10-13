"""Additive terminal resolution; original failed Setup evidence remains immutable."""
from __future__ import annotations
import base64
import re
from datetime import datetime, timedelta, timezone
import uuid
from .ad_directory import DOMAIN, fail
from .errors import ControlError
from .setup_plans import digest, private_create, private_read, private_read_bytes, decode_state_bytes
from .setup_recovery import _pair, evidence_document, _sync_directory
from .setup_recovery_history import RecoveryHistoryStore, _timestamp

class RecoveryResolutionStore:
    """prepare/validate require the caller's controller lifecycle lock.

    The trusted terminal_verifier must verify retained terminal state under that
    already-held lock; it must not call a public lock-acquiring runtime method.
    load is an archival read and grants no current execution authority.
    """
    def __init__(self, settings, *, terminal_verifier=None, clock=None):
        self.settings = settings
        self.root = settings.state_root / 'setup-recovery-resolutions'
        self.verifier = terminal_verifier
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _path(self, failed_run_id, computer_guid):
        return self.root / (digest(_pair(failed_run_id, computer_guid)) + '.json')

    def terminal(self, pair, identity, evidence_sha):
        if self.verifier is None:
            raise fail('recovery_terminal_unavailable', 'Genuine terminal verification is required for Setup continuation')
        document = self.verifier(**pair)
        try:
            expected = dict(pair, machine_uuid=identity['machine_uuid'], computer_ou=identity['computer_ou'],
                domain=DOMAIN, employee_guid=identity['employee_guid'], employee_sid=identity['employee_sid'],
                evidence_sha256=evidence_sha, status='successful')
            if not isinstance(document, dict) or any(document.get(k) != v for k,v in expected.items()):
                raise ValueError
            for key in ('terminal_receipt_sha256', 'execution_plan_sha256'):
                if not isinstance(document.get(key), str) or not re.fullmatch('[0-9a-f]{64}',document[key]): raise ValueError
            if document.get('execution_plan_id') != 'recovery-' + document['execution_plan_sha256']: raise ValueError
            if not isinstance(document.get('terminal_id'), str) or not document['terminal_id']: raise ValueError
            if not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',document.get('computer_sid','')): raise ValueError
            date = datetime.fromisoformat(document['finished_at'])
            now = self.clock()
            if date.tzinfo is None or not date <= now < date + timedelta(minutes=30): raise ValueError
        except (TypeError, KeyError, ValueError, AttributeError):
            raise fail('recovery_terminal_invalid', 'Successful fresh terminal receipt and identity provenance are required') from None
        return {key:value for key,value in document.items() if key != 'finished_at'}

    def load(self, failed_run_id, computer_guid):
        pair = _pair(failed_run_id, computer_guid)
        document = private_read(self._path(**pair))
        try:
            raw = {key:base64.b64decode(item['bytes_b64'],validate=True) for key,item in document['evidence']['files'].items()}
            if (document['schema_version'] != 1 or type(document['schema_version']) is not int
                or document['pair'] != pair or evidence_document(raw) != document['evidence']
                or digest(document['evidence']) != document['identity']['evidence_sha256']
                or document['terminal'].get('evidence_sha256') != document['identity']['evidence_sha256']
                or any(document['terminal'].get(key) != value for key,value in pair.items())): raise ValueError
            run = decode_state_bytes(raw['run'])
            plan = decode_state_bytes(raw['plan'])
            binding = decode_state_bytes(raw['binding'])
            revision = 1
            if plan['payload']['existing_assignment'] is not None:
                created = _timestamp(plan['created_at'])
                if created > _timestamp(run['created_at']):
                    raise ValueError
                revision = RecoveryHistoryStore(self.settings.state_root)._prejoin_revision(
                    plan['payload'], binding, created)
            elif 'prejoin_retry' in plan['payload']:
                raise ValueError
            if (run.get('run_id') != pair['failed_run_id'] or run.get('status') != 'failed'
                    or run.get('machine_uuid') != document['identity']['machine_uuid']
                    or not re.fullmatch('[0-9a-f]{32}',str(run.get('configuration_run_id','')))
                    or not re.fullmatch('setup-[0-9a-f]{64}',str(run.get('plan_id','')))
                    or plan.get('plan_id') != run['plan_id']
                    or decode_state_bytes(raw['index']) != {'run_id':pair['failed_run_id']}
                    or binding.get('run_id') != pair['failed_run_id'] or binding.get('result') != 'failed'
                    or binding.get('machine_uuid') != run['machine_uuid']
                    or str(uuid.UUID(run['machine_uuid'])) != run['machine_uuid']
                    or binding.get('revision') != revision or type(binding.get('revision')) is not int): raise ValueError
        except (ControlError, KeyError, ValueError, TypeError):
            raise fail('recovery_resolution_invalid', 'Protected additive resolution is invalid') from None
        return document

    def _originals(self, document, *, require_binding=True):
        files = document['evidence']['files']
        raw = {key:base64.b64decode(item['bytes_b64'],validate=True) for key,item in files.items()}
        run = decode_state_bytes(raw['run'])
        root = self.settings.state_root
        paths = dict(run=root/'setup-runs'/(run['run_id']+'.json'),
            plan=root/'setup-plans'/(run['plan_id']+'.json'),
            index=root/'setup-plan-runs'/(run['plan_id']+'.json'),
            configuration_result=root/'configure-runs'/run['configuration_run_id']/'result.json')
        if require_binding:
            paths['binding'] = root/'domain-assignments'/(run['machine_uuid']+'.json')
        if any(private_read_bytes(path) != raw[key] for key,path in paths.items()):
            raise fail('recovery_history_drift', 'Original failed Setup history changed')
        return raw

    def prepare(self, failed_run_id, computer_guid):
        pair = _pair(failed_run_id, computer_guid)
        history = RecoveryHistoryStore(self.settings.state_root).load(failed_run_id)
        identity = history['identity']
        terminal = self.terminal(pair, identity, identity['evidence_sha256'])
        document = dict(schema_version=1, pair=pair, identity=identity, terminal=terminal,
            evidence=evidence_document(history['raw_files']))
        return document

    def retain(self, document):
        self._originals(document)
        path = self._path(**document['pair'])
        if path.exists() or path.is_symlink():
            if self.load(**document['pair']) != document:
                raise fail('recovery_resolution_conflict', 'Existing recovery resolution differs')
        else:
            private_create(path,document)
            _sync_directory(path.parent)
        return document

    def validate(self, reference, binding):
        if (not isinstance(reference, dict) or set(reference) != {'failed_run_id','computer_guid','resolution_sha256'}
                or not isinstance(reference.get('resolution_sha256'), str)
                or not re.fullmatch('[0-9a-f]{64}',reference['resolution_sha256'])):
            raise fail('recovery_resolution_invalid', 'Protected recovery resolution reference is invalid')
        document = self.load(reference['failed_run_id'],reference['computer_guid'])
        if digest(document) != reference['resolution_sha256']:
            raise fail('recovery_resolution_invalid', 'Recovery resolution confirmation differs')
        self._originals(document)
        if decode_state_bytes(base64.b64decode(document['evidence']['files']['binding']['bytes_b64'])) != binding:
            raise fail('recovery_resolution_invalid', 'Original failed binding differs')
        current = self.terminal(document['pair'],document['identity'],document['identity']['evidence_sha256'])
        if current != document['terminal']:
            raise fail('recovery_terminal_drift','Retained terminal provenance changed')
        return document
