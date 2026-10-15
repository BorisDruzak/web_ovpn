from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from test_component_setup import component_service
from test_component_catalog import project as catalog_project

# The existing component fixture requests its canonical project fixture by name.
project = catalog_project


def envelope(operation='status', parameters=None):
    return {'schema_version': 1, 'request_id': str(uuid.uuid4()), 'operation': operation, 'parameters': parameters or {}}


class Backend:
    def __init__(self, data=None):
        self.data, self.calls = data or {}, []
    def call(self, operation, parameters):
        self.calls.append((operation, parameters))
        return self.data
    def recover(self, intent):
        return None


def gateway(tmp_path, backend=None):
    from alt_deploy.workstations_gateway import Gateway
    return Gateway(SimpleNamespace(state_root=tmp_path), backend=backend or Backend())


@pytest.mark.parametrize('operation', ['shell', 'recovery.apply', 'users.create', 'maintenance.confirm', 'reboot', '../status'])
def test_only_fixed_operations_are_admitted(tmp_path, operation):
    backend = Backend()
    with pytest.raises(ControlError):
        gateway(tmp_path, backend).dispatch(envelope(operation), scope='execute')
    assert backend.calls == []


@pytest.mark.parametrize('operation,parameters', [('plans.create', {}), ('plans.apply', {}), ('jobs.cancel', {}), ('jobs.verify', {})])
def test_read_scope_never_executes_control_operations(tmp_path, operation, parameters):
    backend = Backend()
    with pytest.raises(ControlError) as exc:
        gateway(tmp_path, backend).dispatch(envelope(operation, parameters), scope='read')
    assert exc.value.code == 'workstations_scope_denied'
    assert backend.calls == []


@pytest.mark.parametrize('parameters', [{'command': 'id'}, {'offset': -1}, {'limit': 101}, {'limit': True}])
def test_unknown_or_unbounded_parameters_never_reach_backend(tmp_path, parameters):
    backend = Backend()
    with pytest.raises(ControlError):
        gateway(tmp_path, backend).dispatch(envelope('machines.list', parameters), scope='read')
    assert backend.calls == []


def test_machine_projection_drops_private_fields(tmp_path):
    machine_uuid = str(uuid.uuid4())
    backend = Backend({'machines': [{'uuid': machine_uuid, 'hostname': 'synthetic-pc', 'mac': '02:00:00:00:00:01',
        'registration_state': 'ready', 'raw': {'password': 'not-public'}, 'record_path': '/private/registration'}], 'total': 1})
    response = gateway(tmp_path, backend).dispatch(envelope('machines.list'), scope='read')
    raw = json.dumps(response)
    assert response['data']['machines'][0]['uuid'] == machine_uuid
    assert 'password' not in raw and 'record_path' not in raw and 'not-public' not in raw


def test_plan_projection_drops_request_paths_and_raw_observations(tmp_path):
    from alt_deploy.workstations_projection import public_plan
    plan = {'plan_id': 'setup-' + 'a' * 64, 'sha256': 'a' * 64, 'created_at': 'now', 'expires_at': 'later', 'payload': {
        'machine': {'uuid': str(uuid.uuid4()), 'hostname': 'synthetic-pc', 'registration_sha256': 'private'},
        'user': {'object_guid': str(uuid.uuid4()), 'object_sid': 'S-1-5-21-1', 'login': 'synthetic', 'dn': 'private'},
        'components': [{'id': 'system.base', 'version': 1, 'execution': {'command': 'private'}}],
        'observed': {'raw_output': 'private'}, 'request': {'vault_password': 'private'}, 'ssh_binding': '/private/key'}}
    projected = public_plan(plan)
    assert 'private' not in json.dumps(projected)
    assert projected['components'] == [{'id': 'system.base', 'version': 1}]


def test_matching_apply_requests_return_one_backend_job(tmp_path):
    backend = Backend({'job_id': 'job-20261015T000000Z-12345678', 'state': 'queued'})
    parameters = {'plan_id': 'setup-' + 'a' * 64, 'sha256': 'a' * 64, 'kind': 'full_setup'}
    request = envelope('plans.apply', parameters)
    first = gateway(tmp_path, backend).dispatch(request, scope='execute')
    second = gateway(tmp_path, backend).dispatch(request, scope='execute')
    assert first == second and len(backend.calls) == 1
    assert first['data']['job_id'] == 'job-20261015T000000Z-12345678'


def test_invalid_schema_or_typed_identity_is_rejected(tmp_path):
    for request in (dict(envelope(), schema_version=True), dict(envelope(), extra='bad'),
                    envelope('machines.show', {'machine_uuid': '192.0.2.1'}),
                    envelope('plans.apply', {'plan_id': 'setup-' + 'a' * 64, 'sha256': 'b' * 64, 'kind': 'full_setup'})):
        with pytest.raises(ControlError):
            gateway(tmp_path).dispatch(request, scope='execute')


def test_input_decoder_rejects_duplicate_fields_and_oversized_body():
    from alt_deploy.workstations_gateway import decode_request, MAX_REQUEST_BYTES
    for raw in (b'{"operation":"status","operation":"shell"}', b'x' * (MAX_REQUEST_BYTES + 1), b'[]'):
        with pytest.raises(ControlError):
            decode_request(raw)


def test_native_component_admission_recovers_after_lost_response(tmp_path, component_service, monkeypatch):
    from alt_deploy import workstations_gateway as module
    service, setup, machine, *_ = component_service
    setup.settings.jobs_dir = setup.settings.state_root / 'jobs'
    setup.settings.service_user = setup.settings.service_group = 'altserver'
    plan = service.plan(machine.uuid, 'software.onlyoffice')
    monkeypatch.setattr(module, 'ComponentSetupService', lambda settings: service)
    backend = module.ControllerBackend(setup.settings)
    native_call = backend.call
    calls = []
    def lose_response(operation, parameters):
        calls.append(operation)
        native_call(operation, parameters)
        raise ConnectionError('response lost after admission')
    backend.call = lose_response
    request = envelope('plans.apply', {'plan_id': plan['plan_id'], 'sha256': plan['sha256'], 'kind': 'component'})
    gateway = module.Gateway(setup.settings, backend=backend)
    with pytest.raises(ControlError):
        gateway.dispatch(request, scope='execute')
    result = gateway.dispatch(request, scope='execute')
    jobs = module.SetupJobRepository(setup.settings).list()
    assert len(jobs) == 1 and result['data']['job_id'] == jobs[0].job_id
    assert calls == ['plans.apply']


def test_plan_verification_cannot_expose_arbitrary_private_fields():
    from alt_deploy.workstations_projection import public_plan
    result = public_plan({'plan_id': 'setup-' + 'a' * 64, 'payload': {
        'verification': {'system.base': {'status': 'compliant', 'raw_output': 'private diagnostic'}}}})
    assert 'private diagnostic' not in json.dumps(result)
    assert result['verification']['system.base']['status'] == 'compliant'


def test_gateway_audit_never_serializes_parameters_or_invalid_identity():
    from alt_deploy.workstations_gateway import audit_event
    events = []
    audit_event(request_id='private directory identity', scope='read', operation='private command',
                status='error', error_code='workstations_request_invalid', elapsed=1, writer=events.append)
    assert len(events) == 1
    assert 'private' not in json.dumps(events[0])
    assert events[0]['request_id'] is None and events[0]['operation'] is None
    assert events[0]['duration_ms'] == 1000


def test_response_has_a_finite_size_bound(tmp_path):
    from alt_deploy.workstations_gateway import MAX_RESPONSE_BYTES
    with pytest.raises(ControlError) as exc:
        gateway(tmp_path, Backend({'unexpected': 'x' * MAX_RESPONSE_BYTES})).dispatch(envelope(), scope='read')
    assert exc.value.code == 'workstations_response_limit'


def test_gateway_deadline_returns_safe_timeout_and_cancels_alarm(monkeypatch):
    import io
    from alt_deploy import workstations_gateway as module
    alarms, events = [], []
    class TimeoutGateway:
        def dispatch(self, *args, **kwargs):
            raise TimeoutError('private transport timeout')
    monkeypatch.setattr(module, 'Gateway', lambda settings: TimeoutGateway())
    monkeypatch.setattr(module.signal, 'alarm', alarms.append)
    monkeypatch.setattr(module.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(module, 'audit_event', lambda **kw: events.append(kw))
    monkeypatch.setattr(module.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(envelope()).encode())))
    output = io.StringIO()
    monkeypatch.setattr(module.sys, 'stdout', output)
    assert module.main(['--scope', 'read']) == 1
    assert json.loads(output.getvalue())['error_code'] == 'workstations_gateway_timeout'
    assert 'private' not in output.getvalue()
    assert alarms == [300, 0] and len(events) == 1


def test_gateway_deadline_reaps_bounded_transport_child(monkeypatch):
    import io
    from alt_deploy import ad_transport
    class Process:
        stdout, stderr, killed = io.BytesIO(), io.BytesIO(), False
        def wait(self, **kwargs):
            if not self.killed:
                raise TimeoutError('gateway deadline')
        def kill(self):
            self.killed = True
    child = Process()
    monkeypatch.setattr(ad_transport.subprocess, 'Popen', lambda *a, **k: child)
    with pytest.raises(ControlError) as exc:
        ad_transport.bounded_run(['synthetic-read'], environment={})
    assert child.killed
    assert exc.value.code == 'ad_timeout'
