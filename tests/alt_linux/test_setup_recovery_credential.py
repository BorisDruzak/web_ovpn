from __future__ import annotations

import hashlib
import json
import os
import sys
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest, private_read, private_replace
from test_setup_recovery_state import GUID, RUN, scenario as reserved_scenario


def codec_fixture(root):
    from alt_deploy.setup_recovery_credential import RecoveryVaultCodec
    password_file = root / 'vault-pass'
    password_file.write_bytes(b'SYNTHETIC_VAULT_MASTER\n'); password_file.chmod(0o600)
    calls, encrypted = [], {}
    def runner(command, *, input_text, password_fd):
        assert os.pread(password_fd, 100, 0) == b'SYNTHETIC_VAULT_MASTER\n'
        with pytest.raises(OSError): os.write(password_fd, b'change')
        calls.append((command, input_text, password_fd))
        if command[1] == 'encrypt':
            ciphertext = '$ANSIBLE_VAULT;1.1;AES256\n' + hashlib.sha256(input_text.encode()).hexdigest() + '\n'
            encrypted[ciphertext] = input_text
            return ciphertext
        return encrypted[input_text]
    checker = SimpleNamespace(password_file=password_file, _service_uid=lambda: os.geteuid())
    return RecoveryVaultCodec(SimpleNamespace(), checker=checker, runner=runner), calls, encrypted


def test_codec_uses_sealed_memory_fd_and_no_password_in_command(tmp_path):
    codec, calls, _ = codec_fixture(tmp_path)
    secret = 'Aa9!' + 'a' * 64
    encrypted = codec.seal(secret)
    assert secret not in encrypted and codec.unseal(encrypted) == secret
    assert all(command[0] == '/usr/bin/ansible-vault' and secret not in str(command) for command, _, _ in calls)
    assert all('/proc/self/fd/' in command[-1] for command, _, _ in calls)
    for _, _, fd in calls:
        with pytest.raises(OSError): os.fstat(fd)


def test_vault_process_uses_private_empty_config_and_ignores_inherited_environment(monkeypatch):
    from pathlib import Path
    from alt_deploy.setup_recovery_credential import _run_vault
    monkeypatch.setenv('ANSIBLE_CONFIG', 'SYNTHETIC_SECRET_CONFIG')
    script = 'import os,json,pathlib; p=pathlib.Path(os.environ["ANSIBLE_CONFIG"]); print(json.dumps({"path":str(p),"content":p.read_text(),"mode":p.stat().st_mode & 511,"cwd":os.getcwd(),"safe_path":os.environ.get("PYTHONSAFEPATH")}))'
    fd = os.open('/dev/null', os.O_RDONLY)
    try: result = json.loads(_run_vault([sys.executable, '-I', '-B', '-c', script], input_text='', password_fd=fd))
    finally: os.close(fd)
    assert result['content'] == '[defaults]\n' and result['mode'] == 0o600
    assert result['cwd'] == str(Path(result['path']).parent) and result['safe_path'] == '1'
    assert not Path(result['path']).exists()


def test_excessive_vault_output_is_refused():
    from alt_deploy.setup_recovery_credential import _run_vault, MAX_VAULT_BYTES
    fd = os.open('/dev/null', os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            _run_vault([sys.executable, '-I', '-B', '-c', f'print("x" * {MAX_VAULT_BYTES + 1})'],
                       input_text='', password_fd=fd)
    finally: os.close(fd)


def test_stalled_child_and_stdin_writer_are_killed_within_timeout(monkeypatch):
    import time
    from alt_deploy import setup_recovery_credential as module
    original = module.subprocess.Popen
    class ShortWait(original):
        def wait(self, timeout=None): return super().wait(timeout=0.05 if timeout == 30 else timeout)
    monkeypatch.setattr(module.subprocess, 'Popen', ShortWait)
    fd = os.open('/dev/null', os.O_RDONLY); started = time.monotonic()
    try:
        with pytest.raises(ValueError):
            module._run_vault([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(60)'],
                             input_text='x' * module.MAX_VAULT_BYTES, password_fd=fd)
    finally: os.close(fd)
    assert time.monotonic() - started < 3


@pytest.mark.parametrize('unsafe', ['symlink', 'mode', 'oversize', 'owner'])
def test_codec_rejects_unprotected_master_before_subprocess(tmp_path, unsafe):
    codec, calls, _ = codec_fixture(tmp_path)
    path = codec.checker.password_file
    if unsafe == 'symlink':
        path.rename(tmp_path / 'other'); path.symlink_to(tmp_path / 'other')
    elif unsafe == 'mode': path.chmod(0o644)
    elif unsafe == 'oversize': path.write_bytes(b'x' * 4097)
    else: codec.checker._service_uid = lambda: os.geteuid() + 1
    with pytest.raises(ControlError): codec.seal('synthetic')
    assert calls == []


def store_fixture(root):
    from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
    attempts, plan, raw = reserved_scenario(root)
    claim = attempts.reserve(plan['plan_id'], plan['sha256'], raw)
    codec, calls, encrypted = codec_fixture(root)
    store = RecoveryCredentialStore(root, codec=codec)
    return store, attempts, plan, claim, calls, encrypted


def test_store_seals_durable_bound_credential_without_plaintext_on_disk(tmp_path):
    store, attempts, plan, claim, calls, _ = store_fixture(tmp_path)
    result = store.create(RUN, GUID)
    assert set(result) == {'claim_sha256', 'sealed_sha256'}
    password = store.open(RUN, GUID)
    assert len(password) == 68 and password.startswith('Aa9!')
    assert password not in str(result)
    for path in tmp_path.rglob('*'):
        if path.is_file(): assert password.encode() not in path.read_bytes()
    sealed = private_read(store.path(RUN, GUID))
    assert sealed['claim_sha256'] == result['claim_sha256']
    assert sealed['plan_sha256'] == plan['sha256']
    with pytest.raises(ControlError): store.create(RUN, GUID)


@pytest.mark.parametrize('drift', ['claim', 'evidence', 'plan', 'sealed', 'readiness', 'terminal'])
def test_changed_or_terminal_attempt_never_exposes_credential(tmp_path, drift):
    store, attempts, plan, claim, calls, encrypted = store_fixture(tmp_path)
    store.create(RUN, GUID)
    if drift == 'claim': path = attempts.claim_path(RUN, GUID); key = 'evidence_sha256'
    elif drift == 'evidence': path = attempts.evidence_path(RUN, GUID); key = 'schema_version'
    elif drift == 'plan': path = attempts.plans.root / (plan['plan_id'] + '.json'); key = 'content_sha256'
    elif drift == 'sealed': path = store.path(RUN, GUID); key = 'sealed_sha256'
    elif drift == 'readiness': path = store._ready_path(RUN, GUID); key = 'document_sha256'
    else:
        attempts.finish(RUN, GUID, status='failed', error_code='synthetic_failure')
        path = None
    if path:
        document = private_read(path); document[key] = 'changed'; private_replace(path, document)
    before = len(calls)
    with pytest.raises(ControlError): store.open(RUN, GUID)
    assert len(calls) == before


def test_roundtrip_or_storage_failure_keeps_attempt_excluded(tmp_path, monkeypatch):
    from alt_deploy import setup_recovery_credential as module
    store, attempts, plan, claim, calls, _ = store_fixture(tmp_path)
    monkeypatch.setattr(module, '_sync_directory', lambda path: (_ for _ in ()).throw(OSError('SYNTHETIC_SECRET')))
    with pytest.raises(ControlError) as caught: store.create(RUN, GUID)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    assert attempts.claim_path(RUN, GUID).exists()
    with pytest.raises(ControlError): store.open(RUN, GUID)
    with pytest.raises(ControlError): store.create(RUN, GUID)


def test_ciphertext_substitution_is_bound_inside_encryption(tmp_path):
    store, attempts, plan, claim, calls, encrypted = store_fixture(tmp_path)
    store.create(RUN, GUID)
    path = store.path(RUN, GUID); document = private_read(path)
    original = json.loads(encrypted[document['ciphertext']]); original['computer_guid'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    replacement = store.codec.seal(json.dumps(original))
    document['ciphertext'] = replacement
    document['sealed_sha256'] = hashlib.sha256(replacement.encode()).hexdigest()
    private_replace(path, document)
    ready_path = store._ready_path(RUN, GUID)
    ready = private_read(ready_path); ready['sealed_sha256'] = document['sealed_sha256']; ready['document_sha256'] = digest(document)
    private_replace(ready_path, ready)
    with pytest.raises(ControlError): store.open(RUN, GUID)


@pytest.mark.parametrize('stage', ['marker_write', 'marker_sync', 'roundtrip'])
def test_failed_preparation_closes_attempt_even_if_ready_marker_is_visible(tmp_path, monkeypatch, stage):
    from alt_deploy import setup_recovery_credential as module
    store, attempts, plan, claim, calls, encrypted = store_fixture(tmp_path)
    if stage == 'marker_write':
        original = module.private_create
        def fail_ready(path, document):
            if path == store._ready_path(RUN, GUID): raise OSError('SYNTHETIC_SECRET')
            return original(path, document)
        monkeypatch.setattr(module, 'private_create', fail_ready)
    elif stage == 'marker_sync':
        original = module._sync_directory
        def fail_ready_sync(path):
            if store._ready_path(RUN, GUID).exists(): raise OSError('SYNTHETIC_SECRET')
            return original(path)
        monkeypatch.setattr(module, '_sync_directory', fail_ready_sync)
    else:
        monkeypatch.setattr(store.codec, 'unseal', lambda value: 'SYNTHETIC_SECRET')
    with pytest.raises(ControlError) as caught: store.create(RUN, GUID)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    if stage == 'marker_sync': assert store._ready_path(RUN, GUID).exists()
    terminal = private_read(attempts._path(RUN, GUID, '.receipt.json'))
    assert terminal['status'] == 'failed' and terminal['error_code'] == 'recovery_credential_failed'
    before = len(calls)
    with pytest.raises(ControlError): store.open(RUN, GUID)
    assert len(calls) == before


def test_reservation_drift_during_decryption_refuses_password(tmp_path, monkeypatch):
    store, attempts, plan, claim, calls, encrypted = store_fixture(tmp_path)
    store.create(RUN, GUID)
    original = store.codec.unseal
    def changed(ciphertext):
        plaintext = original(ciphertext)
        path = attempts.claim_path(RUN, GUID); document = private_read(path)
        document['evidence_sha256'] = 'f' * 64; private_replace(path, document)
        return plaintext
    monkeypatch.setattr(store.codec, 'unseal', changed)
    with pytest.raises(ControlError): store.open(RUN, GUID)
