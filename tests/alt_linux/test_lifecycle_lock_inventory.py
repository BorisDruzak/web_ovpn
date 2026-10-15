"""Idle lock polling must not invalidate a real, quiescent backup capture."""
import fcntl
import multiprocessing
import stat
import sys

import pytest

from alt_deploy.locks import exclusive_lock
from alt_deploy_backup.fs import source_inventory
from support.backup_repository_sandbox import BackupSandbox


def waiting_contender(path, ready):
    announced = False

    def observe(frame, event, function):
        nonlocal announced
        if event == 'c_call' and function is fcntl.flock and not announced:
            announced = True
            ready.send(True)

    # Observe the real flock entry after all native preparation. No lock or
    # validator is replaced, and the caller keeps the real lifecycle lock.
    sys.setprofile(observe)
    try:
        with exclusive_lock(path):
            pass
    finally:
        sys.setprofile(None)


def test_repeated_idle_lock_poll_preserves_backup_inventory(tmp_path):
    path = tmp_path/'state'/'workstationctl.lock'
    with exclusive_lock(path):
        pass
    before = source_inventory([path.parent])
    with exclusive_lock(path):
        pass
    assert source_inventory([path.parent]) == before


def test_backup_with_waiting_idle_contender_publishes_once(tmp_path, monkeypatch):
    sandbox = BackupSandbox.create(tmp_path)
    sandbox.seed_complete_controller()
    sandbox.settings.controller_state_root.chmod(0o700)
    repo = sandbox.repository()
    original = repo.archive_engine.capture
    context = multiprocessing.get_context('fork')
    ready_recv, ready_send = context.Pipe(False)
    children = []

    def capture(spec, destination):
        if not children:
            child = context.Process(target=waiting_contender,
                                    args=(sandbox.settings.lifecycle_lock, ready_send))
            children.append(child)
            child.start()
            assert ready_recv.poll(5) and ready_recv.recv()
        return original(spec, destination)

    monkeypatch.setattr(repo.archive_engine, 'capture', capture)
    try:
        result = repo.create()
    finally:
        for child in children:
            child.join(5)
            if child.is_alive():
                child.terminate()
                child.join(5)
    assert children[0].exitcode == 0
    assert result.component_count == 6
    assert result.services_restored is True
    assert len(sandbox.published_backups()) == 1
    assert not list(sandbox.settings.backup_root.glob('.creating-*'))


@pytest.mark.parametrize('directory_mode,lock_mode', [
    (0o700, 0o600), (0o755, 0o644), (0o1700, 0o1600),
])
def test_lifecycle_lock_still_enforces_private_modes(tmp_path, directory_mode, lock_mode):
    root = tmp_path/'state'
    root.mkdir()
    root.chmod(directory_mode)
    path = root/'workstationctl.lock'
    path.write_bytes(b'')
    path.chmod(lock_mode)
    with exclusive_lock(path):
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_lifecycle_lock_creates_missing_private_state(tmp_path):
    path = tmp_path/'state'/'workstationctl.lock'
    with exclusive_lock(path):
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
