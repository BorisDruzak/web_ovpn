"""Allowlisted Setup events: no task names, arguments, output or result objects."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re

from .ad_directory import fail
from .jobs import JobRepository
from .locks import exclusive_lock
from .setup_jobs import fsync_directory, publish, timestamp
from .setup_plans import canonical, private_directory, private_read

TYPES = {'task_start', 'task_ok', 'task_failed', 'task_unreachable', 'task_skipped', 'component_start', 'component_completed'}
CODES = {'started', 'ok', 'task_failed', 'unreachable', 'skipped', 'component_preflight_failed', 'completed'}
INPUT_FIELDS = {'schema_version', 'component_id', 'component_version', 'stage', 'task_id', 'type', 'changed', 'code'}
STAGE_PRIORITY = ('transaction', 'download', 'verify', 'preflight', 'domain_join',
                  'domain_core_verify', 'upgrade', 'identity', 'network', 'configuration', 'apply', 'complete')
STAGES = set(STAGE_PRIORITY)
MAX_EVENTS = 10000


def safe_task_event(result, *, component, event_type):
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
                    or event['type'] not in TYPES or event['code'] not in CODES
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
        private_directory(root)
        paths = sorted(root.glob('*.json'))
        if len(paths) > MAX_EVENTS:
            raise fail('setup_event_invalid', 'Setup event limit exceeded')
        scope = self._scope(job)
        events = []
        for sequence, path in enumerate(paths, 1):
            event = private_read(path)
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
