"""Bounded public chronology and safe, deterministic error classifications."""
from __future__ import annotations

import base64
import bisect
import json
import re
import time
import uuid

from sqlalchemy import select

from .models import DirectoryLink, SourceRun, SourceSnapshot, WorkstationRequest
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
    workflow_actions={
        'krfb_clients_connected':'Завершите подключение VNC-клиента, если требуется перенастройка KRFB. Приложения и чужой сеанс не закрываются автоматически.',
        'certificates_importer_active':'Дождитесь завершения импорта сертификатов. Контроллер повторно прочитает готовность исходного задания.',
        'graphical_session_unavailable':'Выполните настоящий графический вход выбранного сотрудника. Worker продолжит исходное задание.',
        'graphical_session_ambiguous':'Проверьте несколько графических сеансов выбранного сотрудника; нужен один однозначный сеанс.',
        'workflow_final_verification_unavailable':'Восстановите доступность ПК и сеанса для свежей проверки. Применённые этапы повторяться не будут.',
        'final_dns_rolled_back':'Подтверждён откат DNS. Проверьте доступность резолвера и журнал финализации; повтор Setup или join не требуется.'}
    if uncertain:
        category, action = 'uncertain_outcome', 'Проверьте исходное задание или квитанцию. Повторный запуск запрещён до штатного review.'
    elif code in workflow_actions:
        category,action='workflow',workflow_actions[code]
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
        events, keys, after_cursor, deadline = [], [], _cursor(cursor), time.monotonic() + 50
        def check():
            if time.monotonic() >= deadline:
                raise SourceError('workstations_journal_timeout')
        def emit(row):
            check()
            row['timestamp'] = timestamp(row['timestamp']).isoformat()
            key = (row['timestamp'], row['id'])
            if after_cursor and key <= after_cursor:
                return False
            if any(filters.get(name) and row.get(field) != filters[name]
                   for name, field in (('component', 'component_id'), ('stage', 'stage'), ('severity', 'severity'))):
                return False
            position = bisect.bisect_right(keys, key)
            keys.insert(position, key); events.insert(position, row)
            if len(events) > limit + 1:
                keys.pop(); events.pop()
            return True

        job_id, device_key, component = filters.get('job_id'), filters.get('device_key'), filters.get('component')
        aliases, machine = {device_key}, device_key[8:] if device_key and device_key.startswith('machine:') else None
        if device_key:
            from .projection import device_aliases
            snapshot = db.get(SourceSnapshot, 'reconciliation')
            matches = [row for row in snapshot.data_json.get('devices', []) if device_key in device_aliases(row)] if snapshot else []
            if len(matches) == 1:
                aliases = device_aliases(matches[0]); machine = matches[0].get('machine_uuid') or machine
        native, native_errors, native_complete, published = {}, [], self.client is not None, 0
        if self.client is not None:
            from .client import WorkstationsClient
            client = self.client.with_deadline(deadline) if isinstance(self.client, WorkstationsClient) else self.client
            def call(operation, parameters):
                check()
                return client.call(operation, parameters, request_id=str(uuid.uuid4()))
            try:
                if device_key and not machine:
                    raise SourceError('workstations_journal_device_identity_unavailable')
                identifiers = [job_id] if job_id else []
                if not job_id:
                    offset, expected_total, seen = 0, None, set()
                    while True:
                        page = call('jobs.list', dict(offset=offset, limit=100, **({'machine_uuid': machine} if machine else {})))
                        rows, total, next_offset = page.get('jobs'), page.get('total'), page.get('next_offset')
                        if (not isinstance(rows, list) or len(rows) > 100 or type(total) is not int or not 0 <= total <= MAX_EVENTS
                                or expected_total is not None and total != expected_total
                                or type(next_offset) is not int or next_offset != offset + len(rows) or next_offset > total
                                or not rows and offset < total):
                            raise SourceError('workstations_journal_evidence_invalid')
                        expected_total = total
                        for item in rows:
                            identity = item.get('job_id')
                            if not isinstance(identity, str) or not re.fullmatch(r'job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', identity) or identity in seen:
                                raise SourceError('workstations_journal_evidence_invalid')
                            seen.add(identity); identifiers.append(identity)
                        offset = next_offset
                        if offset == total:
                            break
                for identity in identifiers:
                    status = call('jobs.status', {'job_id': identity}).get('job', {})
                    if machine and status.get('machine_uuid') != machine:
                        continue
                    if component and component not in status.get('components', {}):
                        continue
                    native[identity] = status
                    history = status.get('history')
                    if not isinstance(history, list) or len(history) > 1024:
                        raise SourceError('workstations_journal_evidence_invalid')
                    for sequence, item in enumerate(history, 1):
                        emit({'id': 'stage:' + identity + ':' + str(sequence), 'timestamp': item['at'], 'job_id': identity,
                            'device_key': 'machine:' + status['machine_uuid'] if status.get('machine_uuid') else None,
                            'component_id': component, 'source': 'controller', 'action': 'job.stage',
                            'stage': _code(item['stage']), 'status': _code(item['state']),
                            'severity': 'error' if item['state'] in ('failed', 'unknown_requires_review') else 'info'})
                    after, expected_total = 0, None
                    while True:
                        page = call('jobs.events', {'job_id': identity, 'after': after, 'limit': 1000})
                        rows, total, next_sequence = page.get('events'), page.get('total'), page.get('next_sequence')
                        if (not isinstance(rows, list) or len(rows) > 1000 or type(total) is not int or not 0 <= total <= MAX_EVENTS
                                or expected_total is not None and total != expected_total
                                or type(next_sequence) is not int or not after <= next_sequence <= total
                                or not rows and next_sequence < total):
                            raise SourceError('workstations_journal_evidence_invalid')
                        expected_total = total
                        for item in rows:
                            if type(item.get('sequence')) is not int or item['sequence'] != after + 1:
                                raise SourceError('workstations_journal_evidence_gap')
                            after += 1
                            value = {key: item[key] for key in ('sequence', 'timestamp', 'component_id', 'component_version',
                                'task_id', 'stage', 'type', 'changed', 'code') if key in item}
                            value.update(id='event:' + identity + ':' + str(after), job_id=identity,
                                device_key='machine:' + status['machine_uuid'] if status.get('machine_uuid') else None,
                                source='controller', action='job.event',
                                severity='error' if item.get('type') in ('task_failed', 'task_unreachable') else 'info')
                            emit(value)
                        if next_sequence != after:
                            raise SourceError('workstations_journal_evidence_gap')
                        if after == total:
                            published += total
                            break
            except Exception as exc:
                native_complete = False
                native_errors.append({'code': safe_code(getattr(exc, 'code', 'workstations_journal_source_unavailable'))})

        def association(params, data):
            linked_job = data.get('job_id') or params.get('job_id')
            plan_id = params.get('plan_id') or data.get('plan_id')
            related = [data] + [row for key, row in native.items() if key == linked_job or plan_id and row.get('plan_id') == plan_id]
            if plan_id and (device_key or component):
                planning = db.scalar(select(WorkstationRequest).where(
                    WorkstationRequest.action.in_(('plans.create', 'component_plans.create')),
                    WorkstationRequest.status == 'succeeded', WorkstationRequest.data_json['plan_id'].as_string() == plan_id).limit(1))
                if planning:
                    related.append(planning.data_json or {})
            machines, components, related_jobs = {str(params.get('machine_uuid'))}, {params.get('component_id')}, {linked_job}
            for item in related:
                machines.add(str(item.get('machine_uuid') or (item.get('machine') or {}).get('uuid')))
                selected = item.get('components') or {}
                components.update(selected if isinstance(selected, dict) else (entry.get('id') for entry in selected if isinstance(entry, dict)))
            related_jobs.update(key for key, row in native.items() if plan_id and row.get('plan_id') == plan_id)
            return related_jobs, machines, components

        matched = 0
        for row in db.scalars(select(WorkstationRequest).order_by(WorkstationRequest.created_at, WorkstationRequest.id).execution_options(yield_per=250)):
            check()
            data, params = row.data_json or {}, row.parameters_json or {}
            related_jobs, machines, components = association(params, data)
            if job_id and job_id not in related_jobs:
                continue
            if device_key and params.get('device_key') not in aliases and machine not in machines:
                continue
            if component and component not in components:
                continue
            phase = row.phases_json[-1] if row.phases_json else {}
            matched += emit({'id': 'request:' + row.id, 'request_id': row.id, 'operation_id': row.panel_operation_id,
                'job_id': _code(data.get('job_id') or params.get('job_id')), 'device_key': device_key, 'component_id': component,
                'timestamp': row.created_at.isoformat(), 'actor': row.actor, 'action': row.action,
                'stage': _code(phase.get('stage')), 'status': row.status, 'code': safe_code(row.error_code) if row.error_code else None,
                'severity': 'error' if row.status in ('unknown', 'failed') else 'info', 'source': 'panel'})
            if matched > limit:
                break
        if not job_id and not device_key and not component:
            matched = 0
            for row in db.scalars(select(SourceRun).order_by(SourceRun.started_at, SourceRun.id).execution_options(yield_per=250)):
                matched += emit({'id': 'source:' + row.id, 'timestamp': row.started_at.isoformat(), 'source': row.source,
                    'action': 'source.collect', 'status': row.status, 'code': safe_code(row.error_code) if row.error_code else None,
                    'severity': 'error' if row.status == 'error' else 'info', 'run_id': row.batch_id})
                if matched > limit:
                    break
        if not job_id and not component:
            statement = select(DirectoryLink).where(DirectoryLink.status.in_(('confirmed', 'ended')))
            if device_key:
                statement = statement.where(DirectoryLink.device_key.in_(aliases))
            for state, moment in (('confirmed', DirectoryLink.confirmed_at), ('ended', DirectoryLink.ended_at)):
                matched = 0
                for row in db.scalars(statement.where(moment.is_not(None)).order_by(moment, DirectoryLink.id).execution_options(yield_per=250)):
                    observed = row.confirmed_at if state == 'confirmed' else row.ended_at
                    matched += emit({'id': 'link:' + row.id + ':' + state, 'timestamp': observed.isoformat(),
                        'source': 'panel', 'action': 'link.' + state, 'actor': row.created_by if state == 'confirmed' else row.ended_by,
                        'device_key': row.device_key, 'status': state, 'revision': row.revision, 'severity': 'info'})
                    if matched > limit:
                        break
        evidence = ('complete' if published else 'no_published_events') if native_complete else ('unavailable' if self.client else 'local_history')
        page = events[:limit]
        return {'events': page, 'next_cursor': _encoded([page[-1]['timestamp'], page[-1]['id']]) if len(events) > limit else None,
                'evidence': evidence, 'native_complete': native_complete, 'native_errors': native_errors, 'limit': limit}

    def export(self, db, *, filters, cursor=None, limit=1000):
        return self.list(db, filters=filters, cursor=cursor, limit=limit)
