"""A verification receipt skips tests only; it never authorizes installation."""
import importlib.util
import json
import os
import fcntl
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT/'deploy/alt-linux/verification_checkpoint.py'


def helper():
    spec = importlib.util.spec_from_file_location('verification_checkpoint', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def setup(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    (source/'code.py').write_text('value=1\n')
    cache = tmp_path/'cache'
    env = {'python': '3.12', 'dependencies': 'inspected'}
    return helper(), source, cache, env


def test_pass_then_resume_skips_only_the_verification_execution(setup):
    m, source, cache, env = setup
    calls = []
    m.verify(source, cache, env, lambda: calls.append('tests') or 0, owner=os.getuid(), now=1000)
    assert calls == ['tests']
    result = m.verify(source, cache, env, lambda: pytest.fail('already verified'),
                      resume=True, owner=os.getuid(), now=1001)
    assert result == 'reused'


@pytest.mark.parametrize('fault', ['source', 'new_source', 'mode', 'environment', 'expired', 'future', 'tampered', 'symlink', 'writable'])
def test_drift_and_untrusted_receipts_never_skip_tests(setup, fault):
    m, source, cache, env = setup
    m.verify(source, cache, env, lambda: 0, owner=os.getuid(), now=1000)
    receipt = next(cache.glob('*.json'))
    now = 1001
    if fault == 'source': (source/'code.py').write_text('value=2\n')
    if fault == 'new_source': (source/'new.py').write_text('value=2\n')
    if fault == 'mode': (source/'code.py').chmod(0o600)
    if fault == 'environment': env['dependencies'] = 'changed'
    if fault == 'expired': now = 1000 + m.MAX_AGE + 1
    if fault == 'future': now = 999
    if fault == 'tampered': receipt.write_text('{}')
    if fault == 'symlink':
        data = receipt.read_text();receipt.unlink();other = source/'forged';other.write_text(data);receipt.symlink_to(other)
    if fault == 'writable': receipt.chmod(0o666)
    with pytest.raises((ValueError, OSError)):
        m.verify(source, cache, env, lambda: pytest.fail('resume must refuse'), resume=True, owner=os.getuid(), now=now)


def test_failed_tests_and_changes_during_tests_create_no_receipt(setup):
    m, source, cache, env = setup
    with pytest.raises(ValueError, match='verification_failed'):
        m.verify(source, cache, env, lambda: 23, owner=os.getuid(), now=1000)
    assert not list(cache.glob('*.json'))
    def mutate():
        (source/'code.py').write_text('changed')
        return 0
    with pytest.raises(ValueError, match='verification_inputs_changed'):
        m.verify(source, cache, env, mutate, owner=os.getuid(), now=1001)
    assert not list(cache.glob('*.json'))


def test_source_symlinks_and_writable_files_are_denied_before_tests(setup):
    m, source, cache, env = setup
    (source/'code.py').chmod(0o666)
    with pytest.raises(ValueError):
        m.verify(source, cache, env, lambda: pytest.fail('unsafe source'), owner=os.getuid(), now=1000)
    (source/'code.py').unlink(); (source/'code.py').symlink_to('/etc/passwd')
    with pytest.raises(ValueError):
        m.verify(source, cache, env, lambda: pytest.fail('unsafe source'), owner=os.getuid(), now=1000)


def test_existing_good_receipt_is_invalidated_before_fresh_failed_run(setup):
    m, source, cache, env = setup
    m.verify(source, cache, env, lambda: 0, owner=os.getuid(), now=1000)
    with pytest.raises(ValueError):
        m.verify(source, cache, env, lambda: 1, owner=os.getuid(), now=1001)
    with pytest.raises(ValueError):
        m.verify(source, cache, env, lambda: pytest.fail('must not run'), resume=True, owner=os.getuid(), now=1002)


def test_worker_command_always_uses_service_account_and_full_runner():
    command = helper().worker_command(ROOT, '/usr/bin/python3')
    assert command == ['/usr/bin/sudo', '-n', '-H', '-u', 'altserver', '--',
                       '/usr/bin/python3', '-E', str(ROOT/'deploy/alt-linux/verify_repository.py')]


def test_environment_change_during_tests_does_not_create_receipt(setup):
    m, source, cache, env = setup
    def change():
        env['dependencies'] = 'new'
        return 0
    with pytest.raises(ValueError, match='verification_inputs_changed'):
        m.verify(source, cache, lambda: env, change, owner=os.getuid(), now=1000)
    assert not list(cache.glob('*.json'))


def test_native_lock_excludes_another_verifier(setup):
    m, source, cache, env = setup
    cache.mkdir(mode=0o700)
    fd = os.open(cache/'.lock', os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            m.verify(source, cache, env, lambda: pytest.fail('concurrent verification'), owner=os.getuid(), now=1000)
        assert not list(cache.glob('*.json'))
    finally:
        os.close(fd)
