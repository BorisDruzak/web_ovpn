from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest


def configured(tmp_path):
    paths = [tmp_path / name for name in ('read-key', 'execute-key', 'known-hosts')]
    for path in paths:
        path.write_text('synthetic credential fixture', encoding='utf-8')
        path.chmod(0o600)
    return SimpleNamespace(workstations_enabled=True, workstations_host='controller.example.invalid',
        workstations_ssh_user='altserver', workstations_read_key=paths[0], workstations_execute_key=paths[1],
        workstations_known_hosts=paths[2])


def test_transport_uses_strict_scoped_key_and_fixed_command(tmp_path):
    from app.workstations.client import WorkstationsClient
    calls = []
    request_id = str(uuid.uuid4())
    def run(command, **options):
        calls.append((command, options))
        assert json.loads(options['input_data'])['request_id'] == request_id
        return 0, json.dumps({'schema_version': 1, 'request_id': request_id, 'status': 'ok',
                              'data': {'execution_mode': 'sequential'}, 'error_code': None}).encode(), b''
    settings = configured(tmp_path)
    assert WorkstationsClient(settings, runner=run).call('status', {}, request_id=request_id) == {'execution_mode': 'sequential'}
    command, options = calls[0]
    assert 'StrictHostKeyChecking=yes' in command and 'IdentitiesOnly=yes' in command
    assert 'PasswordAuthentication=no' in command and 'ForwardAgent=no' in command
    assert 'IdentityFile=' + str(settings.workstations_read_key) in command
    assert command[-1] == 'gateway' and command[-2] == settings.workstations_host
    assert options['timeout'] <= 20


def test_execute_credential_is_never_used_by_default(tmp_path):
    from app.workstations.client import WorkstationsClient
    calls = []
    def run(command, **options):
        calls.append(command)
        request = json.loads(options['input_data'])
        return 0, json.dumps({'schema_version': 1, 'request_id': request['request_id'], 'status': 'ok', 'data': {}, 'error_code': None}).encode(), b''
    settings = configured(tmp_path)
    WorkstationsClient(settings, runner=run).call('plans.apply', {}, request_id=str(uuid.uuid4()), scope='execute')
    assert 'IdentityFile=' + str(settings.workstations_execute_key) in calls[0]
    assert 'IdentityFile=' + str(settings.workstations_read_key) not in calls[0]


@pytest.mark.parametrize('host', ['-oProxyCommand=private', 'host;private', 'host\nprivate', '', 'a b'])
def test_invalid_config_cannot_become_shell_or_ssh_options(tmp_path, host):
    from app.workstations.client import WorkstationsClient, WorkstationsTransportError
    settings = configured(tmp_path)
    settings.workstations_host = host
    with pytest.raises(WorkstationsTransportError):
        WorkstationsClient(settings, runner=lambda *a, **kw: pytest.fail('unsafe target reached SSH')).call('status', {}, request_id=str(uuid.uuid4()))


def test_timeout_preserves_request_identity_and_uncertainty(tmp_path):
    from app.workstations.client import WorkstationsClient, WorkstationsTransportError
    request_id = str(uuid.uuid4())
    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired('private command', 30, output=b'private output', stderr=b'private key path')
    with pytest.raises(WorkstationsTransportError) as exc:
        WorkstationsClient(configured(tmp_path), runner=run).call('plans.apply', {}, request_id=request_id, scope='execute')
    assert exc.value.request_id == request_id and exc.value.uncertain is True
    assert exc.value.code == 'workstations_transport_timeout'
    assert 'private' not in str(exc.value)


@pytest.mark.parametrize('raw', [b'not json', b'[]', b'{"schema_version":1,"schema_version":2}', b'x' * (20 * 1024 * 1024 + 1)])
def test_malformed_and_unbounded_responses_are_safe_errors(tmp_path, raw):
    from app.workstations.client import WorkstationsClient, WorkstationsTransportError
    with pytest.raises(WorkstationsTransportError):
        WorkstationsClient(configured(tmp_path), runner=lambda *a, **kw: (0, raw, b'private')).call('status', {}, request_id=str(uuid.uuid4()))


def test_unconfigured_feature_does_not_attempt_connection(tmp_path):
    from app.workstations.client import WorkstationsClient, WorkstationsTransportError
    settings = configured(tmp_path)
    settings.workstations_enabled = False
    with pytest.raises(WorkstationsTransportError) as exc:
        WorkstationsClient(settings, runner=lambda *a, **kw: pytest.fail('disabled feature connected')).call('plans.apply', {}, request_id=str(uuid.uuid4()), scope='execute')
    assert exc.value.code == 'workstations_not_configured'
    assert exc.value.uncertain is False


@pytest.mark.skipif(os.name == 'nt', reason='POSIX credential mode contract')
def test_shared_or_redirected_key_is_rejected(tmp_path):
    from app.workstations.client import WorkstationsClient, WorkstationsTransportError
    settings = configured(tmp_path)
    settings.workstations_read_key.chmod(0o644)
    with pytest.raises(WorkstationsTransportError):
        WorkstationsClient(settings).call('status', {}, request_id=str(uuid.uuid4()))
    settings.workstations_read_key.chmod(0o600)
    linked = tmp_path / 'linked-key'
    linked.symlink_to(settings.workstations_read_key)
    settings.workstations_read_key = linked
    with pytest.raises(WorkstationsTransportError):
        WorkstationsClient(settings).call('status', {}, request_id=str(uuid.uuid4()))


def test_real_transport_reader_enforces_output_bound(monkeypatch):
    import sys
    from app.workstations import client
    monkeypatch.setattr(client, 'MAX_OUTPUT', 128)
    with pytest.raises(ValueError):
        client.run_ssh([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"x" * 256)'],
                       input_data=b'{}', timeout=5)


def test_real_transport_timeout_kills_the_local_ssh_process():
    import sys
    from app.workstations.client import run_ssh
    with pytest.raises(subprocess.TimeoutExpired):
        run_ssh([sys.executable, '-c', 'import time; time.sleep(20)'], input_data=b'{}', timeout=0.1)
