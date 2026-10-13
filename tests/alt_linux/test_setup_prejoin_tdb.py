"""Native read-only TDB ABI verification using synthetic credentials only."""
import ctypes
import ctypes.util
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip('fcntl')
if ctypes.util.find_library('tdb') is None:
    pytest.skip('Native libtdb ABI tests require the ALT/Samba runtime library', allow_module_level=True)
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'deploy/alt-linux/control'))


def reader():
    from alt_deploy.setup_runtime import READONLY_TDB_KEYS_SCRIPT
    ns = {}
    exec(READONLY_TDB_KEYS_SCRIPT, ns)
    return ns['readonly_tdb_keys'], ns


@pytest.mark.parametrize('key', [b'SECRETS/SID/SYNTHETIC\0', b'SECRETS/MACHINE_PASSWORD/SYNTHETIC\0'])
def test_native_reader_returns_only_keys_and_never_changes_database(tmp_path, key):
    read, ns = reader()
    lib = ctypes.CDLL('libtdb.so.1')
    data = ns['TdbData']
    lib.tdb_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    lib.tdb_open.restype = ctypes.c_void_p
    lib.tdb_store.argtypes = [ctypes.c_void_p, data, data, ctypes.c_int]
    lib.tdb_close.argtypes = [ctypes.c_void_p]
    p = tmp_path/'synthetic.tdb'
    handle = lib.tdb_open(os.fsencode(p), 0, 0, os.O_CREAT|os.O_RDWR, 0o600)
    assert handle
    key_buf = ctypes.create_string_buffer(key)
    value = b'SYNTHETIC_VALUE_MUST_NOT_BE_RETURNED'
    val_buf = ctypes.create_string_buffer(value)
    assert lib.tdb_store(handle, data(ctypes.cast(key_buf, ctypes.c_void_p), len(key)), data(ctypes.cast(val_buf, ctypes.c_void_p), len(value)), 1) == 0
    assert lib.tdb_close(handle) == 0
    before = p.read_bytes()
    assert read(p) == [key.rstrip(b'\0').decode('ascii')]
    assert p.read_bytes() == before
    assert value not in repr(read(p)).encode()


def test_native_reader_rejects_missing_corrupt_and_symlinked_database(tmp_path):
    read, _ = reader()
    with pytest.raises(RuntimeError): read(tmp_path/'missing.tdb')
    p = tmp_path/'broken.tdb'; p.write_bytes(b'not a database')
    with pytest.raises(RuntimeError): read(p)
    link = tmp_path/'link.tdb'; link.symlink_to(p)
    with pytest.raises(RuntimeError): read(link)


def empty_database(path):
    lib = ctypes.CDLL('libtdb.so.1')
    lib.tdb_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    lib.tdb_open.restype = ctypes.c_void_p
    lib.tdb_close.argtypes = [ctypes.c_void_p]
    handle = lib.tdb_open(os.fsencode(path), 0, 0, os.O_CREAT|os.O_RDWR, 0o600)
    assert handle and lib.tdb_close(handle) == 0
    return lib


def test_reader_refuses_uncertain_iteration_error(tmp_path, monkeypatch):
    read, _ = reader()
    path = tmp_path/'empty.tdb'
    lib = empty_database(path)
    original = ctypes.CDLL
    lib.tdb_error = lambda _: 8
    monkeypatch.setattr(ctypes, 'CDLL', lambda name: lib if name == 'libtdb.so.1' else original(name))
    with pytest.raises(RuntimeError): read(path)


def test_reader_refuses_mutex_database_instead_of_disabling_locks(tmp_path):
    read, _ = reader()
    lib = ctypes.CDLL('libtdb.so.1')
    lib.tdb_runtime_check_for_robust_mutexes.restype = ctypes.c_bool
    if not lib.tdb_runtime_check_for_robust_mutexes(): pytest.skip('Native robust mutex TDB support unavailable')
    lib.tdb_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    lib.tdb_open.restype = ctypes.c_void_p
    lib.tdb_close.argtypes = [ctypes.c_void_p]
    path = tmp_path/'mutex.tdb'
    handle = lib.tdb_open(os.fsencode(path), 0, 4096|1, os.O_CREAT|os.O_RDWR, 0o600)
    assert handle and lib.tdb_close(handle) == 0
    with pytest.raises(RuntimeError): read(path)


def test_reader_refuses_concurrent_writer_without_waiting(tmp_path):
    import threading
    read, _ = reader()
    path = tmp_path/'empty.tdb'
    lib = empty_database(path)
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_read); os.close(release_write)
            handle = lib.tdb_open(os.fsencode(path), 0, 0, os.O_RDWR, 0)
            lib.tdb_lockall.argtypes = [ctypes.c_void_p]
            lib.tdb_unlockall.argtypes = [ctypes.c_void_p]
            assert lib.tdb_lockall(handle) == 0
            os.write(ready_write, b'R'); os.read(release_read, 1)
            lib.tdb_unlockall(handle); lib.tdb_close(handle)
            os._exit(0)
        except BaseException: os._exit(1)
    os.close(ready_write); os.close(release_read)
    timer = None
    try:
        assert os.read(ready_read, 1) == b'R'
        timer = threading.Timer(0.25, lambda: os.write(release_write, b'R'))
        timer.start()
        with pytest.raises(RuntimeError): read(path)
        timer.join()
    finally:
        if timer is not None: timer.join()
        os.close(ready_read); os.close(release_write)
        _, status = os.waitpid(pid, 0)
        assert status == 0
