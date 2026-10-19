"""Independent sandbox inventory catches effects beyond the native probe."""
import os

import pytest

from test_partial_local_probe import native_fixture
from test_partial_local_target import target


def test_rehearsal_preserves_local_authentication_and_snapshot(native_fixture, monkeypatch):
    from support.partial_local_sandbox import rehearse
    protocol, root, request, calls = target(native_fixture, monkeypatch)
    checks = []
    def authenticate():
        checks.append(True)
        return {'local_admin': True, 'ansible': True}
    result = rehearse({'root': root, 'request': request, 'owner': os.getuid()},
                      {'target': protocol, 'authenticate': authenticate})
    assert result['status'] == 'passed'
    assert result['accounts_unchanged'] and result['backup_verified']
    assert result['fresh_authentication'] == {'local_admin': True, 'ansible': True}
    assert len(checks) == 2 and len(calls) == 1
    assert len(result['backup_sha256']) == 64


def test_rehearsal_refuses_unexpected_native_side_effect(native_fixture, monkeypatch):
    from support.partial_local_sandbox import rehearse
    protocol, root, request, calls = target(native_fixture, monkeypatch)
    original = protocol.subprocess.run
    def changed(argv, **kwargs):
        value = original(argv, **kwargs)
        if argv[0].endswith('/system-auth') and argv[1:] == ['write', 'local']:
            (root/'etc/unrelated-setting').write_text('unrequested change\n')
        return value
    monkeypatch.setattr(protocol.subprocess, 'run', changed)
    with pytest.raises(ValueError, match='Unexpected sandbox effect'):
        rehearse({'root': root, 'request': request, 'owner': os.getuid()},
                 {'target': protocol, 'authenticate': lambda: {'local_admin': True, 'ansible': True}})
    assert len(calls) == 1
