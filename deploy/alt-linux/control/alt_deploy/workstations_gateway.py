"""Fixed-operation JSON gateway invoked only by a restricted SSH forced command."""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import time
from pathlib import Path

from .ad_directory import ADDirectory, fail
from .ad_transport import DirectoryConfig, LDAPTransport
from .component_catalog import ComponentCatalog
from .component_setup import ComponentSetupService
from .directory_dns import DirectoryDNS
from .directory_observer import DirectoryObserver, DirectoryObserverConfig
from .errors import ControlError
from .jobs import JOB_ID_RE
from .registry import MachineRepository
from .setup import SetupService
from .setup_assignments import DomainAssignmentStore
from .setup_jobs import SetupJobRepository, service_uid, unresolved_legacy_reservations
from .setup_jobs_view import SetupJobsService
from .setup_plans import canonical, digest
from .workstations_projection import fields, project, public_machine
from .workstations_receipts import GatewayReceiptStore, request_uuid

MAX_REQUEST_BYTES = 32768
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
OPERATIONS = {
    'status': ((), ()), 'machines.list': ((), ('offset', 'limit')), 'machines.show': (('machine_uuid',), ()),
    'catalog.list': ((), ()), 'directory.search': (('query',), ('limit',)),
    'directory.identity': (('kind', 'object_guid'), ()),
    'directory.snapshot': (('source',), ()), 'assignments.show': (('machine_uuid',), ()),
    'plans.create': (('machine_uuid', 'user_login', 'user_guid', 'user_sid', 'ou_id', 'software_profile'), ('remote_access_profile',)),
    'component_plans.create': (('machine_uuid', 'component_id'), ()),
    'plans.apply': (('plan_id', 'sha256', 'kind'), ()), 'jobs.list': ((), ('machine_uuid', 'offset', 'limit')),
    'jobs.status': (('job_id',), ()), 'jobs.events': (('job_id',), ('after', 'limit')),
    'jobs.verify': (('job_id',), ()), 'jobs.cancel': (('job_id', 'sha256'), ()),
    'receipts.status': (('request_id',), ()),
}
CONTROL = frozenset({'plans.create', 'component_plans.create', 'plans.apply', 'jobs.verify', 'jobs.cancel'})


def decode_request(raw):
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_REQUEST_BYTES:
            raise ValueError
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError
                value[key] = item
            return value
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise fail('workstations_request_invalid', 'Invalid bounded JSON request') from exc


def validate(operation, parameters):
    required, optional = OPERATIONS[operation]
    if not isinstance(parameters, dict) or not set(required) <= set(parameters) <= set(required + optional):
        raise fail('workstations_parameters_invalid', 'Operation parameters do not match the fixed contract')
    for name, value in parameters.items():
        if name in ('offset', 'after', 'limit'):
            maximum = 1000 if name == 'limit' and operation == 'jobs.events' else 100 if name == 'limit' else 1000000
            if type(value) is not int or not (1 if name == 'limit' else 0) <= value <= maximum:
                raise fail('workstations_parameters_invalid', 'Pagination bound is invalid')
            continue
        if not isinstance(value, str) or not value or len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise fail('workstations_parameters_invalid', 'Operation value is invalid')
        if name in ('machine_uuid', 'user_guid', 'object_guid', 'request_id'):
            request_uuid(value)
        elif name == 'job_id' and not JOB_ID_RE.fullmatch(value):
            raise fail('workstations_parameters_invalid', 'Job identifier is invalid')
        elif name in ('sha256', 'ou_id') and not re.fullmatch('[0-9a-f]{64}', value):
            raise fail('workstations_parameters_invalid', 'Confirmation binding is invalid')
        elif name in ('software_profile', 'component_id') and not re.fullmatch('[a-z][a-z0-9_.-]{0,127}', value):
            raise fail('workstations_parameters_invalid', 'Published catalog identifier is invalid')
        elif name == 'user_login' and not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._@-]{0,191}', value):
            raise fail('workstations_parameters_invalid', 'Employee login is invalid')
        elif name == 'user_sid' and not re.fullmatch('S-1-[0-9]+(?:-[0-9]+)+', value):
            raise fail('workstations_parameters_invalid', 'Employee SID is invalid')
        elif name == 'remote_access_profile' and value not in ('none', 'krfb'):
            raise fail('workstations_parameters_invalid', 'Remote-access profile is invalid')
    if operation == 'directory.search' and (len(parameters['query']) > 160 or parameters.get('limit', 50) > 50):
        raise fail('workstations_parameters_invalid', 'Employee search bound is invalid')
    if operation == 'directory.snapshot' and parameters['source'] not in ('ad', 'dns'):
        raise fail('workstations_parameters_invalid', 'Directory source is invalid')
    if operation == 'directory.identity' and parameters['kind'] not in ('user', 'computer'):
        raise fail('workstations_parameters_invalid', 'Directory identity kind is invalid')
    if operation == 'plans.apply':
        prefix = {'full_setup': 'setup-', 'component': 'setup-component-'}.get(parameters['kind'])
        if prefix is None or parameters['plan_id'] != prefix + parameters['sha256']:
            raise fail('workstations_parameters_invalid', 'Plan type and exact SHA confirmation differ')


class ControllerBackend:
    def __init__(self, settings, *, observer_path=Path('/etc/alt-deploy/directory-observer.json')):
        self.settings, self.observer_path = settings, observer_path

    def _setup(self):
        observer = DirectoryObserverConfig.load(self.observer_path)
        native = DirectoryConfig.load()
        return SetupService(self.settings, directory=ADDirectory(LDAPTransport(observer.directory_config(), settings=self.settings)),
                            approved_ous=native.approved_ous)

    def _ous(self):
        return {digest(dn): dn for dn in DirectoryConfig.load().approved_ous}

    def recover(self, intent):
        if intent.get('operation') != 'plans.apply':
            return None
        parameters = intent['parameters']
        jobs = SetupJobRepository(self.settings)
        path = jobs.claims / (parameters['sha256'] + '.json')
        if not path.exists() and not path.is_symlink():
            return None
        claim = jobs._read(path)
        job = jobs.get(claim['job_id'])
        jobs._check_claim(job, claim)
        if (job.request['plan']['plan_id'] != parameters['plan_id']
                or job.request['plan']['sha256'] != parameters['sha256']
                or job.request['operation'] != parameters['kind']):
            return None
        return {'job_id': job.job_id, 'machine_uuid': job.machine_uuid, 'state': job.state,
                'plan_id': parameters['plan_id'], 'plan_sha256': parameters['sha256']}

    def call(self, operation, p):
        settings = self.settings
        if operation == 'status':
            jobs = SetupJobRepository(settings).list()
            queued = sorted((j for j in jobs if j.state == 'queued'), key=lambda j: j.status['admission_sequence'])
            unknown = [j.job_id for j in jobs if j.state == 'unknown_requires_review']
            leases = unresolved_legacy_reservations(settings)
            return {'execution_mode': 'sequential', 'queued_count': len(queued), 'queue': [j.job_id for j in queued[:100]],
                    'executing': [j.job_id for j in jobs if j.state in ('preflight', 'running', 'verifying')][:100],
                    'historical_unknown_count': len(unknown), 'unresolved_legacy_count': len(leases),
                    'admission_status': 'native_worker_review_required' if unknown or leases else 'native_worker_checks',
                    'observer_configured': self.observer_path.is_file()}
        if operation.startswith('machines.'):
            machines = MachineRepository(settings)
            assignments = DomainAssignmentStore(settings.state_root)
            def row(machine):
                return public_machine(dict(machine.to_public_dict(), domain_assignment=assignments.get(machine.uuid)))
            if operation == 'machines.show':
                return {'machine': row(machines.get(p['machine_uuid']))}
            rows = [row(machine) for machine in machines.list()]
            offset, limit = p.get('offset', 0), p.get('limit', 100)
            return {'machines': rows[offset:offset + limit], 'generation': digest(rows),
                    'total': len(rows), 'next_offset': min(len(rows), offset + limit)}
        if operation == 'catalog.list':
            catalog = ComponentCatalog.load(settings.ansible_project_dir)
            return {'catalog_version': catalog.version, 'catalog_sha256': catalog.fingerprint,
                    'components': [fields(row, ('id', 'version', 'name', 'category', 'dependencies')) for row in catalog.components()],
                    'profiles': [fields(row, ('id', 'version', 'name', 'components')) for row in catalog.profiles()],
                    'ous': [{'id': key, 'name': ', '.join(part.removeprefix('OU=') for part in dn.split(',') if part.startswith('OU='))}
                            for key, dn in self._ous().items()]}
        if operation.startswith('directory.'):
            config = DirectoryObserverConfig.load(self.observer_path)
            if operation == 'directory.search':
                return DirectoryObserver(config, settings=settings).search_users(p['query'], limit=p.get('limit', 50))
            if operation == 'directory.identity':
                return {'identity': DirectoryObserver(config, settings=settings).identity(p['kind'], p['object_guid'])}
            observer = DirectoryDNS if p['source'] == 'dns' else DirectoryObserver
            return dict(observer(config, settings=settings).collect(deadline=time.monotonic() + 120), source=p['source'])
        if operation == 'assignments.show':
            return {'assignment': DomainAssignmentStore(settings.state_root).get(p['machine_uuid'])}
        if operation == 'plans.create':
            ous = self._ous()
            if p['ou_id'] not in ous:
                raise fail('setup_ou_not_approved', 'Select a current approved OU')
            result = self._setup().plan(p['machine_uuid'], p['user_login'], ous[p['ou_id']],
                                        p['software_profile'], p.get('remote_access_profile', 'none'))
            if any(result['payload']['user'][key] != p[requested] for key, requested in
                   (('object_guid', 'user_guid'), ('object_sid', 'user_sid'))):
                raise fail('workstations_user_changed', 'Selected employee identity changed; search again')
            return result
        if operation == 'component_plans.create':
            return ComponentSetupService(settings, setup=self._setup()).plan(p['machine_uuid'], p['component_id'])
        if operation == 'plans.apply':
            return (ComponentSetupService(settings).apply(p['plan_id'], p['sha256']) if p['kind'] == 'component'
                    else SetupService(settings).apply(p['plan_id'], p['sha256'], detach=True))
        service = SetupJobsService(settings)
        if operation == 'jobs.list':
            return service.list(p.get('machine_uuid'), offset=p.get('offset', 0), limit=p.get('limit', 100))
        if operation == 'jobs.status':
            return service.status(p['job_id'])
        if operation == 'jobs.events':
            return service.events_for(p['job_id'], after=p.get('after', 0), limit=p.get('limit', 100))
        if operation == 'jobs.verify':
            return service.verify_continuation(p['job_id'])
        if operation == 'jobs.cancel':
            return service.cancel(p['job_id'], p['sha256'])
        raise fail('workstations_operation_invalid', 'Controller operation is not supported')


class Gateway:
    def __init__(self, settings, *, backend=None, receipts=None):
        self.backend = backend or ControllerBackend(settings)
        self.receipts = receipts or GatewayReceiptStore(settings.state_root, recover=self.backend.recover)

    def dispatch(self, envelope, *, scope):
        if (not isinstance(envelope, dict) or set(envelope) != {'schema_version', 'request_id', 'operation', 'parameters'}
                or type(envelope['schema_version']) is not int or envelope['schema_version'] != 1
                or len(canonical(envelope)) > MAX_REQUEST_BYTES):
            raise fail('workstations_request_invalid', 'Gateway request schema is invalid')
        request_id = request_uuid(envelope['request_id'])
        operation, parameters = envelope['operation'], envelope['parameters']
        if not isinstance(operation, str) or operation not in OPERATIONS:
            raise fail('workstations_operation_invalid', 'Controller operation is not allowed')
        if scope not in ('read', 'execute') or operation in CONTROL and scope != 'execute':
            raise fail('workstations_scope_denied', 'Gateway credential lacks the required operation scope')
        validate(operation, parameters)
        if operation == 'receipts.status':
            data = self.receipts.status(parameters['request_id'])
        elif operation in CONTROL:
            intent = {'operation': operation, 'parameters': parameters}
            receipt = self.receipts.execute(request_id, intent, lambda: project(operation, self.backend.call(operation, parameters)))
            if receipt['state'] != 'successful':
                raise fail(receipt['error_code'] or 'workstations_request_unresolved', 'Controller request outcome requires verification')
            data = receipt['data']
        else:
            data = project(operation, self.backend.call(operation, parameters))
        response = {'schema_version': 1, 'request_id': request_id, 'status': 'ok', 'data': data, 'error_code': None}
        if len(canonical(response)) > MAX_RESPONSE_BYTES:
            raise fail('workstations_response_limit', 'Controller response exceeds its bound')
        return response


def audit_event(*, request_id, scope, operation, status, error_code, elapsed, writer=None):
    try:
        request_id = request_uuid(request_id)
    except ControlError:
        request_id = None
    event = {'request_id': request_id, 'gateway_scope': scope if scope in ('read', 'execute') else None,
             'operation': operation if isinstance(operation, str) and operation in OPERATIONS else None,
             'status': 'ok' if status == 'ok' else 'error',
             'error_code': error_code if isinstance(error_code, str) and re.fullmatch('[a-z][a-z0-9_]{1,100}', error_code) else None,
             'duration_ms': max(0, int(elapsed * 1000))}
    if writer is not None:
        writer(event)
    else:
        import syslog
        syslog.openlog('alt-workstations-gateway', syslog.LOG_PID, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO if status == 'ok' else syslog.LOG_WARNING, json.dumps(event, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--scope', choices=('read', 'execute'), required=True)
    options = parser.parse_args(argv)
    request_id, operation, started = None, None, time.monotonic()
    def deadline(*_):
        raise TimeoutError
    for interrupted in (signal.SIGALRM, signal.SIGHUP, signal.SIGTERM):
        signal.signal(interrupted, deadline)
    signal.alarm(300)
    try:
        from .config import Settings
        settings = Settings.from_env()
        if os.geteuid() != service_uid(settings):
            raise fail('workstations_actor_invalid', 'Run the gateway as the configured controller service account')
        envelope = decode_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
        request_id = request_uuid(envelope.get('request_id'))
        operation = envelope.get('operation')
        response = Gateway(settings).dispatch(envelope, scope=options.scope)
    except (Exception, KeyboardInterrupt) as exc:
        code = ('workstations_gateway_timeout' if isinstance(exc, TimeoutError) else
                exc.code if isinstance(exc, ControlError) and re.fullmatch('[a-z][a-z0-9_]{1,100}', exc.code)
                else 'workstations_gateway_unavailable')
        response = {'schema_version': 1, 'request_id': request_id, 'status': 'error', 'data': None, 'error_code': code}
    finally:
        signal.alarm(0)
    try:
        audit_event(request_id=request_id, scope=options.scope, operation=operation,
                    status=response['status'], error_code=response['error_code'], elapsed=time.monotonic() - started)
    except OSError:
        response = {'schema_version': 1, 'request_id': request_id, 'status': 'error', 'data': None,
                    'error_code': 'workstations_audit_unavailable'}
    sys.stdout.write(json.dumps(response, ensure_ascii=True, allow_nan=False) + '\n')
    return 0 if response['status'] == 'ok' else 1
