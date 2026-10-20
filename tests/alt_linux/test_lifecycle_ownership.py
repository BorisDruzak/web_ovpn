"""A phase may reuse the actual native lifecycle flock, never a boolean flag."""
import multiprocessing
import os
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy import locks


def test_only_current_owned_kernel_flock_is_accepted_and_release_revokes_it(tmp_path):
    path=tmp_path/'private/lifecycle.lock'
    with pytest.raises(ControlError):locks.assert_owned(path)
    with locks.exclusive_lock(path):
        locks.assert_owned(path)
        with pytest.raises(ControlError):locks.assert_owned(path.with_name('other.lock'))
    with pytest.raises(ControlError):locks.assert_owned(path)


def test_inherited_context_cannot_assert_its_parent_process_flock(tmp_path):
    path=tmp_path/'private/lifecycle.lock';ctx=multiprocessing.get_context('fork')
    read,write=ctx.Pipe(duplex=False)
    def child():
        try:locks.assert_owned(path)
        except ControlError:write.send('blocked')
        else:write.send('unsafe')
    with locks.exclusive_lock(path):
        process=ctx.Process(target=child);process.start();process.join(5)
        assert process.exitcode==0 and read.recv()=='blocked'
        locks.assert_owned(path)


def test_descriptor_identity_or_lost_kernel_lock_is_not_hidden_by_context(tmp_path):
    import fcntl
    path=tmp_path/'private/lifecycle.lock'
    with locks.exclusive_lock(path):
        lease=locks._HELD.get()[-1]
        fcntl.flock(lease[1],fcntl.LOCK_UN)
        with pytest.raises(ControlError):locks.assert_owned(path)
        fcntl.flock(lease[1],fcntl.LOCK_EX)
        locks.assert_owned(path)
        path.rename(path.with_suffix('.old'))
        path.write_text('foreign replacement');path.chmod(0o600)
        with pytest.raises(ControlError):locks.assert_owned(path)
