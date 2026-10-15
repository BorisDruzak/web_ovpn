"""Bounded public chronology and safe, deterministic error classifications."""
from __future__ import annotations

import base64
import json
import re
import time
import uuid

from sqlalchemy import select

from .models import DirectoryLink, SourceRun, WorkstationRequest
from .sources import SourceError, timestamp

MAX_EVENTS = 10000
PRIVATE = frozenset(('dn', 'computer_ou', 'stdout', 'stderr', 'raw', 'raw_output', 'raw_xml', 'traceback', 'request',
    'payload', 'ssh_binding', 'record_path', 'password', 'vault_password', 'secret', 'token', 'private_key', 'diagnostics'))


def public_payload(value):
    if isinstance(value, dict):
        return {key: public_payload(item) for key, item in value.items() if isinstance(key, str) and key.lower() not in PRIVATE
                and not any(word in key.lower() for word in ('password', 'secret', 'private_key', 'token'))}
    if isinstance(value, list):
        return [public_payload(item) for item in value]
    return value


def safe_code(code):
    return code if isinstance(code, str) and re.fullmatch('[a-z][a-z0-9_]{0,127}', code) else 'workstations_internal_error'


def error_details(code, *, uncertain=False):
    code = safe_code(code)
    if uncertain:
        category, action = 'uncertain_outcome', 'Проверьте исходное задание или квитанцию. Повторный запуск запрещён до штатного review.'
    elif any(value in code for value in ('permission', 'scope', 'auth_required', 'denied')):
        category, action = 'authorization', 'Проверьте права учётной записи.'
    elif any(value in code for value in ('transport', 'source_', 'observer_', 'not_configured', 'host_key', 'gateway_timeout')):
        category, action = 'source_transport', 'Проверьте состояние источника и повторите чтение после устранения ошибки.'
    elif 'verification' in code or 'verify' in code:
        category, action = 'verification', 'Изучите безопасный журнал проверки и требуемое действие оператора.'
    elif any(value in code for value in ('preflight', 'admission', 'assignment', 'previous_run')):
        category, action = 'preflight', 'Обновите план и проверьте назначения и очередь контроллера.'
    elif any(value in code for value in ('failed', 'unreachable')):
        category, action = 'execution', 'Изучите этап отказа; не повторяйте присоединение без штатной проверки.'
    else:
        category, action = 'validation', 'Обновите сравнение и проверьте выбранные значения и ревизии.'
    return {'code': code, 'category': category, 'next_action': action}


def _cursor(value):
    if value is None:
        return None
    try:
        if not isinstance(value, str) or len(value) > 1024:
            raise ValueError
        result = json.loads(base64.b64decode(value.encode(), altchars=b'-_', validate=True))
        if not isinstance(result, list) or len(result) != 2 or not all(isinstance(v, str) and len(v) <= 256 for v in result):
            raise ValueError
        return tuple(result)
    except (ValueError, UnicodeError, TypeError):
        raise SourceError('workstations_journal_cursor_invalid') from None


def _encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).decode()


def _code(value):
    return value if isinstance(value, str) and re.fullmatch('[a-zA-Z0-9_.:-]{1,160}', value) else None


class JournalService:
    def __init__(self, *, client=None):
        self.client = client

    def list(self, db, *, filters, cursor=None, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000 or not set(filters) <= {'device_key', 'job_id', 'component', 'stage', 'severity'}:
            raise SourceError('workstations_journal_query_invalid')
        events, after_cursor, deadline = [], _cursor(cursor), time.monotonic() + 50
        def emit(row):
            if time.monotonic() >= deadline:
                raise SourceError('workstations_journal_timeout')
            row['timestamp'] = timestamp(row['timestamp']).isoformat()
            if after_cursor and (row['timestamp'], row['id']) <= after_cursor:
                return
            if any(filters.get(name) and row.get(field) != filters[name]
                   for name, field in (('component', 'component_id'), ('stage', 'stage'), ('severity', 'severity'))):
                return
            events.append(row)
        job_id, device_key = filters.get('job_id'), filters.get('device_key')
        for row in db.scalars(select(WorkstationRequest).order_by(WorkstationRequest.created_at, WorkstationRequest.id).execution_options(yield_per=250)):
            data, params = row.data_json or {}, row.parameters_json
            if job_id and data.get('job_id') != job_id and params.get('job_id') != job_id:
                continue
            if device_key and params.get('device_key') != device_key and 'machine:' + str(params.get('machine_uuid')) != device_key:
                continue
            phase = row.phases_json[-1] if row.phases_json else {}
            emit({'id': 'request:' + row.id, 'request_id': row.id, 'operation_id': row.panel_operation_id,
                'job_id': _code(data.get('job_id') or params.get('job_id')), 'device_key': device_key,
                'timestamp': row.created_at.isoformat(), 'actor': row.actor, 'action': row.action,
                'stage': _code(phase.get('stage')), 'status': row.status, 'code': safe_code(row.error_code) if row.error_code else None,
                'severity': 'error' if row.status in ('unknown', 'failed') else 'info', 'source': 'panel'})
            if len(events) > limit:
                break
        if not job_id and not device_key:
            start = len(events)
            for row in db.scalars(select(SourceRun).order_by(SourceRun.started_at, SourceRun.id).execution_options(yield_per=250)):
                emit({'id': 'source:' + row.id, 'timestamp': row.started_at.isoformat(), 'source': row.source,
                    'action': 'source.collect', 'status': row.status, 'code': safe_code(row.error_code) if row.error_code else None,
                    'severity': 'error' if row.status == 'error' else 'info', 'run_id': row.batch_id})
                if len(events) - start > limit:
                    break
        if not job_id:
            statement = select(DirectoryLink).where(DirectoryLink.status.in_(('confirmed', 'ended')))
            if device_key:
                statement = statement.where(DirectoryLink.device_key == device_key)
            for state, moment in (('confirmed', DirectoryLink.confirmed_at), ('ended', DirectoryLink.ended_at)):
                start = len(events)
                for row in db.scalars(statement.where(moment.is_not(None)).order_by(moment, DirectoryLink.id).execution_options(yield_per=250)):
                    observed = row.confirmed_at if state == 'confirmed' else row.ended_at
                    emit({'id': 'link:' + row.id + ':' + state, 'timestamp': observed.isoformat(),
                        'source': 'panel', 'action': 'link.' + state, 'actor': row.created_by if state == 'confirmed' else row.ended_by,
                        'device_key': row.device_key, 'status': state, 'revision': row.revision, 'severity': 'info'})
                    if len(events) - start > limit:
                        break
        evidence = 'local_history'
        if job_id and self.client is not None:
            from .client import WorkstationsClient
            client = self.client.with_deadline(deadline) if isinstance(self.client, WorkstationsClient) else self.client
            status = client.call('jobs.status', {'job_id': job_id}, request_id=str(uuid.uuid4()))
            history = status.get('job', {}).get('history')
            if not isinstance(history, list) or len(history) > 1024:
                raise SourceError('workstations_journal_evidence_invalid')
            for sequence, item in enumerate(history, 1):
                emit({'id': 'stage:' + job_id + ':' + str(sequence), 'timestamp': item['at'], 'job_id': job_id,
                    'source': 'controller', 'action': 'job.stage', 'stage': _code(item['stage']), 'status': _code(item['state']),
                    'severity': 'error' if item['state'] in ('failed', 'unknown_requires_review') else 'info'})
            after, evidence = 0, 'complete'
            while True:
                page = client.call('jobs.events', {'job_id': job_id, 'after': after, 'limit': 1000}, request_id=str(uuid.uuid4()))
                rows, total, next_sequence = page.get('events'), page.get('total'), page.get('next_sequence')
                if (not isinstance(rows, list) or type(total) is not int or not 0 <= total <= MAX_EVENTS
                        or type(next_sequence) is not int or not after <= next_sequence <= total or not rows and next_sequence < total):
                    raise SourceError('workstations_journal_evidence_invalid')
                for item in rows:
                    if type(item.get('sequence')) is not int or item['sequence'] != after + 1:
                        raise SourceError('workstations_journal_evidence_gap')
                    after += 1
                    value = {key: item[key] for key in ('sequence', 'timestamp', 'job_id', 'component_id', 'component_version',
                        'task_id', 'stage', 'type', 'changed', 'code') if key in item}
                    value.update(id='event:' + job_id + ':' + str(after), source='controller', action='job.event',
                        severity='error' if item.get('type') in ('task_failed', 'task_unreachable') else 'info')
                    emit(value)
                if next_sequence != after:
                    raise SourceError('workstations_journal_evidence_gap')
                if after == total:
                    break
            if total == 0:
                evidence = 'no_published_events'
        events.sort(key=lambda row: (row['timestamp'], row['id']))
        page = events[:limit]
        return {'events': page, 'next_cursor': _encoded([page[-1]['timestamp'], page[-1]['id']]) if len(events) > limit else None,
                'evidence': evidence, 'limit': limit}

    def export(self, db, *, filters, cursor=None, limit=1000):
        return self.list(db, filters=filters, cursor=cursor, limit=limit)
