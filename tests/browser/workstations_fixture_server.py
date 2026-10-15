"""Loopback-only workstation UI fixture. All controller/CLI calls are synthetic."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

MACHINE, USER, COMPUTER = (str(uuid.UUID(int=n)) for n in (1001, 1002, 1003))
JOB = 'job-20261015T000000Z-12345678'
MAC = '02:00:00:00:00:11'


def now():
    return datetime.now(timezone.utc)


def source(**content):
    result = dict(schema_version=1, complete=True, generated_at=now().isoformat(), **content)
    result['generation'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


class Controller:
    def __init__(self):
        self.calls, self.state, self.apply_count, self.verify_count = [], 'waiting_first_login', 0, 0
        self.users = [{'object_guid': str(uuid.UUID(int=1002 + n * 10)), 'object_sid': 'S-1-5-21-' + str(n + 1),
            'login': 'synthetic' + str(n + 1), 'upn': 'synthetic' + str(n + 1) + '@example.invalid',
            'display_name': 'Тестовый Сотрудник' + (' <img src=x onerror=alert(1)>' if n else ''),
            'department': 'Тестовый отдел ' + str(n + 1), 'state': 'enabled'} for n in range(2)]
        self.computer = {'object_guid': COMPUTER, 'object_sid': 'S-1-5-21-3', 'login': 'synthetic-pc$',
                         'dns_hostname': 'synthetic-pc.example.invalid', 'state': 'enabled'}
        self.machine = {'uuid': MACHINE, 'hostname': 'Тестовый ПК', 'mac': MAC, 'registration_state': 'ready', 'domain_assignment': None}
        self.started = now()
        self.plan_sha, self.job_plan_id = 'c' * 64, 'setup-' + 'c' * 64

    def call(self, operation, p, **kwargs):
        self.calls.append(operation)
        if operation == 'status':
            return {'execution_mode': 'sequential', 'queued_count': int(self.state == 'queued'), 'executing': [],
                'historical_unknown_count': 2, 'unresolved_legacy_count': 2, 'admission_status': 'native_worker_review_required', 'observer_configured': True}
        if operation == 'machines.list':
            return {'machines': [copy.deepcopy(self.machine)], 'total': 1, 'next_offset': 1, 'generation': 'a' * 64}
        if operation == 'machines.show':
            return {'machine': copy.deepcopy(self.machine)}
        if operation == 'directory.search':
            return {'users': copy.deepcopy(self.users), 'truncated': False}
        if operation == 'directory.identity':
            rows = self.users if p['kind'] == 'user' else [self.computer]
            return {'identity': next((copy.deepcopy(row) for row in rows if row['object_guid'] == p['object_guid']), None)}
        if operation == 'directory.snapshot':
            if p['source'] == 'ad': return source(users=copy.deepcopy(self.users), computers=[copy.deepcopy(self.computer)])
            return source(records=[{'name': self.computer['dns_hostname'], 'type': 'A', 'value': '192.0.2.17', 'zone': 'example.invalid'}], zones=['example.invalid'], findings=[])
        if operation == 'assignments.show': return {'assignment': None}
        if operation == 'catalog.list':
            return {'ous': [{'id': 'b' * 64, 'name': 'Тестовые компьютеры'}],
                'profiles': [{'id': 'office-standard-v1', 'name': 'Офисный комплект без электронной подписи'}],
                'components': [{'id': 'software.onlyoffice', 'name': 'Офисный редактор'}]}
        if operation in ('plans.create', 'component_plans.create'):
            component = operation == 'component_plans.create'
            self.plan_sha = hashlib.sha256((json.dumps(p, sort_keys=True) + now().isoformat()).encode()).hexdigest()
            return {'plan_id': ('setup-component-' if component else 'setup-') + self.plan_sha, 'sha256': self.plan_sha,
                'created_at': now().isoformat(), 'expires_at': (now() + timedelta(minutes=5)).isoformat(), 'machine': self.machine,
                'user': {} if component else next(row for row in self.users if row['object_guid'] == p['user_guid']),
                'profile': {'id': 'office-standard-v1', 'name': 'Офисный комплект'}, 'components': [{'id': 'software.onlyoffice', 'version': 1}],
                'changes': ['Установить офисный редактор по опубликованному каталогу'], 'warnings': ['Первый вход сотрудника выполняется отдельно'],
                'deferred_actions': ['Проверить запуск приложения пользователем']}
        if operation == 'plans.apply':
            self.apply_count += 1; self.state = 'queued'
            self.job_plan_id = p['plan_id']
            return {'job_id': JOB, 'state': 'queued', 'machine_uuid': MACHINE, 'plan_id': p['plan_id'], 'plan_sha256': p['sha256']}
        if operation == 'jobs.verify': self.verify_count += 1; self.state = 'successful'
        if operation == 'jobs.cancel': self.state = 'failed'
        if operation in ('jobs.list', 'jobs.status', 'jobs.verify', 'jobs.cancel'):
            job = {'job_id': JOB, 'machine_uuid': MACHINE, 'state': self.state, 'recorded_state': self.state, 'stage': 'configuration',
                'plan_id': self.job_plan_id, 'plan_sha256': self.job_plan_id[-64:], 'queue_position': 1 if self.state == 'queued' else None,
                'operator_action_required': self.state in ('waiting_first_login', 'unknown_requires_review', 'failed', 'waiting_reboot'),
                'history': [{'state': 'queued', 'stage': 'created', 'at': self.started.isoformat()},
                    {'state': self.state, 'stage': 'configuration', 'at': (self.started + timedelta(seconds=1)).isoformat()}],
                'components': {'software.onlyoffice': {'version': 1, 'changed': True, 'verification': {'version': 1, 'status': 'compliant',
                    'installation_status': 'installed_verified', 'acceptance_status': 'functional_verification_required', 'operator_action': 'functional_acceptance'}}}}
            return {'jobs': [job], 'total': 1, 'next_offset': 1} if operation == 'jobs.list' else {'job': job}
        if operation == 'jobs.events':
            events = [{'sequence': number, 'job_id': JOB, 'timestamp': (self.started + timedelta(milliseconds=number)).isoformat(),
                'component_id': 'software.onlyoffice', 'component_version': 1, 'task_id': 'component', 'type': 'task_ok',
                'stage': 'configuration', 'code': 'ok', 'changed': number % 2 == 0} for number in range(1, 206)]
            rows = events[p.get('after', 0):p.get('after', 0) + min(100, p.get('limit', 100))]
            return {'events': rows, 'total': len(events), 'next_sequence': rows[-1]['sequence'] if rows else len(events)}
        raise RuntimeError('Unexpected controller operation in isolated UI fixture')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=18881)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    database = args.output.resolve() / 'synthetic.sqlite'
    if database.exists(): raise RuntimeError('Use a fresh output directory')
    os.environ.update(DATABASE_URL='sqlite:///' + database.as_posix(), APP_ENV='development',
        APP_SECRET_KEY='synthetic-workstations-browser-session', ADMIN_USERNAME='synthetic', ADMIN_PASSWORD='synthetic-browser-only',
        ENDPOINT_PLATFORM_ENABLED='false', WORKSTATIONS_ENABLED='true', WORKSTATIONS_HOST='',
        WORKSTATIONS_RECONCILE_LOCK=str(args.output.resolve() / 'reconcile.lock'), PANEL_EXPORT_ROOT=str(args.output.resolve() / 'exports'))
    from app.db import reset_engine_cache, init_db, get_sessionmaker
    reset_engine_cache(); init_db()
    from app.inventory.models import InventoryAsset, InventoryAssetType, InventoryNetctlBinding, InventoryExternalBindingStatus
    with get_sessionmaker()() as db:
        card = InventoryAsset(asset_type=InventoryAssetType.PC, custom_name='Тестовая карточка ПК', assigned_person_name='Владелец карточки вручную')
        db.add(card); db.flush(); card_id = card.id
        db.add(InventoryNetctlBinding(asset_id=card.id, network_key='mac:' + MAC, status=InventoryExternalBindingStatus.CONFIRMED, created_by='synthetic'))
        db.commit()
    controller = Controller()
    def network(args, timeout=None):
        return {'snapshot': {'snapshot_id': 1, 'generated_at': now().isoformat(), 'stale': False},
            'hosts': [{'device_key': 'mac:' + MAC, 'mac': MAC, 'hostname': 'synthetic-pc', 'ip': '192.0.2.17'}],
            'pagination': {'page': 1, 'pages': 1, 'limit': 250, 'total': 1}}
    import app.workstations.reconcile as worker
    original = worker.reconcile_once
    def reconcile(**kwargs):
        return original(**dict(kwargs, client=controller, netctl_call=network))
    worker.reconcile_once = reconcile
    if reconcile()['status'] != 'success': raise RuntimeError('Synthetic reconciliation failed')
    import app.main as panel
    import app.workstations.api as api
    import app.workstations.client as transport
    import app.api as old_api
    def forbidden(*args, **kwargs): raise RuntimeError('External infrastructure calls forbidden in workstation UI fixture')
    transport.run_ssh = forbidden
    panel.run_vpnctl = panel.run_netctl = old_api.run_vpnctl = old_api.run_netctl = forbidden
    api.controller_client = lambda: controller
    @panel.app.get('/__fixture/state')
    def state():
        with get_sessionmaker()() as db:
            owner = db.get(InventoryAsset, card_id).assigned_person_name
        return {'calls': controller.calls, 'apply_count': controller.apply_count, 'verify_count': controller.verify_count,
                'inventory_asset_id': card_id, 'manual_owner': owner}
    @panel.app.post('/__fixture/refresh')
    def refresh(): return reconcile()
    @panel.app.post('/__fixture/job/{value}')
    def job(value: str):
        if value not in ('queued', 'running', 'waiting_first_login', 'waiting_reboot', 'successful', 'failed', 'unknown_requires_review'):
            from fastapi import HTTPException
            raise HTTPException(422)
        controller.state = value
        return {'state': value}
    import uvicorn
    uvicorn.run(panel.app, host='127.0.0.1', port=args.port)


if __name__ == '__main__': main()
