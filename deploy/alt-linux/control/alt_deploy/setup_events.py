"""Allowlisted Setup events: no task names, arguments, output or result objects."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import stat

from .ad_directory import fail
from .jobs import JobRepository
from .locks import exclusive_lock
from .setup_jobs import fsync_directory, publish, timestamp, service_uid
from .setup_plans import canonical, private_directory, private_read

TYPES = {'task_start', 'task_ok', 'task_failed', 'task_unreachable', 'task_skipped', 'component_start', 'component_completed'}
CODES = {'started', 'ok', 'task_failed', 'unreachable', 'skipped', 'component_preflight_failed', 'completed'}
FIRST_JOIN_CODES = {'first_join_' + value for value in (
    'request_invalid', 'native_interface_invalid', 'local_state_conflict', 'directory_unavailable',
    'native_arguments_invalid', 'native_failed', 'native_access_denied', 'native_kerberos_failed',
    'native_name_collision', 'native_cache_unavailable', 'keytab_create_failed', 'keytab_bind_failed',
    'trust_failed', 'machine_as_failed', 'timeout', 'output_limit', 'internal_error', 'ok',
    'ad_quota_exhausted', 'ad_rights_unproven', 'ad_principal_unusable',
    'ad_identity_changed', 'ad_preflight_failed', 'native_quota_exhausted')}
CODES |= FIRST_JOIN_CODES
INPUT_FIELDS = {'schema_version', 'component_id', 'component_version', 'stage', 'task_id', 'type', 'changed', 'code'}
STAGE_PRIORITY = ('transaction', 'download', 'verify', 'preflight', 'domain_join',
                  'domain_core_verify', 'upgrade', 'identity', 'network', 'configuration', 'apply', 'complete')
STAGES = set(STAGE_PRIORITY)
MAX_EVENTS = 10000


def _diagnostic_code(result, component, expected):
    task, raw = result._task, result._result
    if (component['id'] != 'domain.ready' or 'alt_setup_first_join_diagnostic' not in getattr(task, 'tags', ())
            or getattr(task, 'no_log', False) or raw.get('_ansible_no_log') or not isinstance(expected, dict)):
        return None


    fields = {'schema_version', 'configuration_run_id', 'invocation_id', 'identity_sha256'}
    try:
        if (set(expected) != fields or type(expected['schema_version']) is not int or expected['schema_version'] != 1
                or any(not isinstance(expected[k], str) or not re.fullmatch('[0-9a-f]{'+str(n)+'}', expected[k])
                       for k, n in (('configuration_run_id', 32), ('invocation_id', 32), ('identity_sha256', 64)))):
            return None
        cmd = raw.get('cmd')
        if (not isinstance(cmd, list) or len(cmd) != 5 or cmd[:4] != ['/usr/bin/python3', '-I',
                '/usr/local/libexec/alt-first-join.py', '--read-diagnostic']
                or not isinstance(cmd[4], str) or len(cmd[4]) > 4096 or json.loads(cmd[4]) != expected):
            return None
        text = raw.get('stdout')
        if not isinstance(text, str) or len(text.encode('utf-8')) > 4096:
            return None
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value: raise ValueError
                value[key] = item
            return value
        value = json.loads(text, object_pairs_hook=unique)
        if (not isinstance(value, dict) or set(value) != fields | {'phase', 'code', 'directory_effect'}
                or any(value.get(k) != v or type(value.get(k)) is not type(v) for k, v in expected.items())
                or value.get('phase') not in ('request', 'native_interface', 'preconditions', 'directory_observation', 'admission',
                    'native_arguments', 'native_execution', 'offline_keytab', 'keytab_bind', 'trust_verify', 'machine_as')
                or value.get('directory_effect') not in ('not_dispatched', 'dispatch_entered', 'returned_success', 'returned_failure', 'uncertain')
                or value.get('code') not in FIRST_JOIN_CODES):
            return None
        return value['code']
    except (ValueError, KeyError, TypeError, UnicodeError):
        return None


def _helper_diagnostic(result,component,bindings):
    try:
        from .helper_diagnostics import CODES as HELPERS,UNAVAILABLE
        from .helper_diagnostic_target import FIELDS,OUTCOMES,_unique
        task=result._task;raw=result._result
        if (not isinstance(bindings,dict) or component['id'] not in HELPERS
                or 'alt_setup_helper_diagnostic' not in getattr(task,'tags',())
                or getattr(task,'no_log',False) or raw.get('_ansible_no_log')):return None
        expected=bindings[component['id']]
        if not isinstance(expected,dict) or set(expected)!={'scope','reader_sha256'}:return None
        scope=expected['scope'];command=raw.get('cmd');text=raw.get('stdout')
        if (not isinstance(scope,dict) or set(scope)!=FIELDS or type(scope['schema_version']) is not int
                or scope['schema_version']!=1 or scope['component_id']!=component['id']
                or not isinstance(command,list) or len(command)!=6 or command[:4]!=['/usr/bin/python3','-I','-B','-c']
                or not isinstance(command[4],str) or len(command[4].encode())>65536
                or hashlib.sha256(command[4].encode()).hexdigest()!=expected['reader_sha256']
                or not isinstance(command[5],str) or len(command[5].encode())>4096
                or json.loads(command[5],object_pairs_hook=_unique)!=scope
                or not isinstance(text,str) or len(text.encode())>4096):return None
        value=json.loads(text,object_pairs_hook=_unique)
        if (not isinstance(value,dict) or set(value)!=FIELDS|{'recorded','outcome','code'}
                or any(type(value[k]) is not type(v) or value[k]!=v for k,v in scope.items())
                or type(value['recorded']) is not bool or value['outcome'] not in OUTCOMES):return None
        if not value['recorded']:
            if value['outcome']!='outcome_unverified' or value['code']!=UNAVAILABLE:return None
        elif value['code'] is not None and value['code'] not in HELPERS[component['id']]:return None
        known=value['outcome'] in ('noop','repaired','configured','applied_verified','rolled_back_verified')
        if not known and value['code'] is None:return None
        return value['code'] or 'ok',not known
    except Exception:return None


def _allowed_codes(component,scope):
    allowed=CODES
    if 'desktop.kwallet_repair' in scope or 'network.final_dns' in scope:
        from .helper_diagnostics import CODES as HELPERS,UNAVAILABLE
        if component in HELPERS:allowed=allowed|HELPERS[component]|{UNAVAILABLE}
    return allowed
def safe_task_event(result, *, component, event_type, diagnostic_binding=None,helper_diagnostic_bindings=None):
    task = result._task
    path = task.get_path()
    task_id = 'task-'+hashlib.sha256(path.encode('utf-8')).hexdigest()[:16]
    stage = 'apply'
    for candidate in STAGE_PRIORITY:
        if 'alt_setup_'+candidate in getattr(task, 'tags', ()):
            stage = candidate
            break
    code = {'task_ok': 'ok', 'task_failed': 'task_failed', 'task_unreachable': 'unreachable',
            'task_skipped': 'skipped', 'task_start': 'started'}[event_type]
    if event_type == 'task_failed' and stage == 'preflight':
        code = 'component_preflight_failed'
    if event_type in ('task_ok', 'task_failed'):
        diagnostic = _diagnostic_code(result, component, diagnostic_binding)
        if diagnostic is not None:
            code = diagnostic
            if diagnostic != 'first_join_ok':
                event_type = 'task_failed'
        helper=_helper_diagnostic(result,component,helper_diagnostic_bindings)
        if helper is not None:
            code,failed=helper
            if failed:event_type='task_failed'
    return {'schema_version': 1, 'component_id': component['id'], 'component_version': component['version'],
            'stage': stage, 'task_id': task_id, 'type': event_type,
            'changed': result._result.get('changed') is True, 'code': code}


class SetupEventStore:
    def __init__(self, settings, *, clock=None):
        self.settings = settings
        self.jobs = JobRepository(settings)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _scope(self, job):
        if job.status.get('kind') != 'setup':
            raise fail('setup_job_not_found', 'Setup events require a typed Setup job')
        payload = job.request['plan']['payload']
        components = [payload['component']] if job.request['operation'] == 'component' else payload['components']
        return {c['id']: c['version'] for c in components}

    def _validate(self, event, scope, *, persisted=False):
        try:
            fields = INPUT_FIELDS | ({'sequence', 'job_id', 'timestamp'} if persisted else set())
            if (not isinstance(event, dict) or set(event) != fields or type(event['schema_version']) is not int
                    or event['schema_version'] != 1 or event['component_id'] not in scope
                    or type(event['component_version']) is not int
                    or event['component_version'] != scope[event['component_id']]
                    or event['stage'] not in STAGES or not isinstance(event['task_id'], str)
                    or not re.fullmatch(r'(task-[0-9a-f]{16}|component)', event['task_id'])
                    or event['type'] not in TYPES or event['code'] not in _allowed_codes(event['component_id'],scope)
                    or type(event['changed']) is not bool or len(canonical(event)) > 2048):
                raise ValueError
            if persisted:
                timestamp(event['timestamp'])
                if type(event['sequence']) is not int or not 1 <= event['sequence'] <= MAX_EVENTS:
                    raise ValueError
        except (ValueError, TypeError, KeyError) as exc:
            raise fail('setup_event_invalid', 'Setup event schema, scope or size is invalid') from exc

    def _read(self, job):
        root = job.job_dir/'events'
        if not root.exists() and not root.is_symlink():
            return []
        metadata = root.lstat()
        uid = service_uid(self.settings)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise fail('setup_event_invalid', 'Setup event directory is unsafe')
        paths = sorted(root.glob('*.json'))
        if len(paths) > MAX_EVENTS:
            raise fail('setup_event_invalid', 'Setup event limit exceeded')
        scope = self._scope(job)
        events = []
        for sequence, path in enumerate(paths, 1):
            event = private_read(path, owner_uid=uid)
            self._validate(event, scope, persisted=True)
            if (event['job_id'] != job.job_id or event['sequence'] != sequence
                    or path.name != f'{sequence:012d}.json'):
                raise fail('setup_event_invalid', 'Setup event sequence or identity is invalid')
            events.append(event)
        return events

    def append(self, job_id, event):
        job = self.jobs.get(job_id)
        self._validate(event, self._scope(job))
        root = job.job_dir/'events'
        private_directory(root)
        fsync_directory(job.job_dir)
        with exclusive_lock(job.job_dir/'events.lock'):
            previous = self._read(job)
            if len(previous) >= MAX_EVENTS:
                raise fail('setup_event_invalid', 'Setup event limit exceeded')
            sequence = len(previous)+1
            document = dict(event, sequence=sequence, job_id=job_id, timestamp=self.clock().isoformat())
            self._validate(document, self._scope(job), persisted=True)
            publish(root/f'{sequence:012d}.json', document, create=True)
            return document

    def read(self, job_id, *, after=0, limit=100):
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise fail('setup_event_query_invalid', 'Setup event pagination is invalid')
        events = self._read(self.jobs.get(job_id))
        page = events[after:after+limit]
        return {'schema_version': 1, 'job_id': job_id, 'events': page,
                'next_sequence': page[-1]['sequence'] if page else min(after, len(events)),
                'total': len(events)}
