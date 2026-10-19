"""The target backup precedes the sole fixed writer and cannot be bypassed."""
import copy
import os
from types import SimpleNamespace

import pytest

from test_partial_local_probe import native_fixture, probe_module, REQUEST
from test_setup_partial_local_state import control


def target(native_fixture, monkeypatch, *, fault=None):
    probe, root = probe_module(native_fixture, monkeypatch)
    original = native_fixture[1]
    written = []
    def run(argv, **kwargs):
        if argv[0].endswith('/system-auth') and argv[1:] == ['write', 'local']:
            written.append(list(argv))
            for name in ('system-auth', 'system-auth-use_first_pass', 'system-policy'):
                path = root/'etc/pam.d'/name; path.unlink(); path.symlink_to(name+'-local')
            (root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nshadow: tcb files\n')
            if fault == 'extra_write': (root/'etc/sssd/sssd.conf').write_text('unexpected write\n')
            if fault == 'accounts': (root/'etc/passwd').write_text('unexpected account replacement\n')
            if fault == 'lost_reply': raise TimeoutError('Synthetic lost reply')
            return SimpleNamespace(returncode=1 if fault == 'native_failed' else 0, stdout='SENTINEL-never-export', stderr='')
        if written and argv[0].endswith('/system-auth') and argv[1:] == ['status']:
            return SimpleNamespace(returncode=0, stdout='local\n', stderr='')
        return original(argv, **kwargs)
    monkeypatch.setattr(probe.subprocess, 'run', run)
    before = probe.collect(REQUEST, root=root, owner=os.getuid())
    module = control('partial_local_target')
    monkeypatch.setattr(module, '_collect', lambda request, **kw: probe.collect(request, **kw))
    request = {'schema_version': 1, 'claim_key': 'a'*64, 'plan_sha256': 'b'*64,
               'machine': REQUEST, 'before': before}
    return module, root, request, written


def test_local_transition_preserves_accounts_and_credentials_absence(native_fixture, monkeypatch):
    module, root, request, calls = target(native_fixture, monkeypatch)
    accounts = (root/'etc/passwd').read_bytes()
    result = module.execute(request, root=root, owner=os.getuid())
    assert result['status'] == 'successful'
    assert len(calls) == 1 and calls[0][1:] == ['write', 'local']
    assert (root/'etc/passwd').read_bytes() == accounts
    assert not (root/'etc/krb5.keytab').exists()
    assert 'SENTINEL' not in str(result)
    assert module.inspect(request, root=root, owner=os.getuid()) == result
    with pytest.raises(ValueError): module.execute(request, root=root, owner=os.getuid())
    assert len(calls) == 1


def test_missing_or_tampered_backup_denies_write(native_fixture, monkeypatch):
    module, root, request, calls = target(native_fixture, monkeypatch)
    monkeypatch.setattr(module, '_verify_backup', lambda *a, **k: (_ for _ in ()).throw(ValueError('Synthetic missing backup')))
    result = module.execute(request, root=root, owner=os.getuid())
    assert result['status'] == 'unknown_requires_review' and calls == []


def test_changed_target_intent_cannot_be_verified_as_success(native_fixture, monkeypatch):
    import json
    module, root, request, calls = target(native_fixture, monkeypatch)
    assert module.execute(request, root=root, owner=os.getuid())['status'] == 'successful'
    path = root/'var/lib/alt-deploy-partial-local'/request['claim_key']/'intent.json'
    document = json.loads(path.read_text()); document['command'] = ['/usr/sbin/system-auth', 'write', 'ad']
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError): module.inspect(request, root=root, owner=os.getuid())
    assert len(calls) == 1


@pytest.mark.parametrize('fault', ['extra_write', 'accounts', 'lost_reply', 'native_failed'])
def test_unexpected_effect_or_lost_reply_never_rolls_back_or_repeats(native_fixture, monkeypatch, fault):
    module, root, request, calls = target(native_fixture, monkeypatch, fault=fault)
    result = module.execute(request, root=root, owner=os.getuid())
    assert result['status'] == 'unknown_requires_review' and len(calls) == 1
    assert (root/'etc/pam.d/system-auth').readlink().as_posix() == 'system-auth-local'
    with pytest.raises(ValueError): module.execute(request, root=root, owner=os.getuid())
    assert len(calls) == 1


@pytest.mark.parametrize('fault', ['boot', 'tool', 'nss'])
def test_snapshot_drift_dispatches_no_native_writer(native_fixture, monkeypatch, fault):
    module, root, request, calls = target(native_fixture, monkeypatch)
    path = root/({'boot': 'proc/sys/kernel/random/boot_id', 'tool': 'usr/sbin/system-auth', 'nss': 'etc/nsswitch.conf'}[fault])
    path.write_text('cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa\n' if fault == 'boot' else 'changed\n')
    with pytest.raises(ValueError): module.execute(request, root=root, owner=os.getuid())
    assert calls == []
