from datetime import datetime,timezone,timedelta
import os

import pytest


def test_export_storage_is_private_bounded_and_cleans_expired_only(tmp_path,monkeypatch):
    monkeypatch.setenv('PANEL_EXPORT_ROOT',str(tmp_path/'private-exports'))
    from app.config import reset_settings_cache
    reset_settings_cache()
    import app.export_artifacts as storage
    path = storage.store_export(b'synthetic')
    assert path.read_bytes() == b'synthetic'
    assert storage.assert_export_file(path) == path.resolve()
    if os.name != 'nt':
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
    foreign = path.parent/'preserve.txt'
    foreign.write_text('keep')
    old = (datetime.now(timezone.utc)-timedelta(days=1)).timestamp()
    os.utime(path,(old,old))
    new = storage.store_export(b'new')
    assert new.is_file() and not path.exists() and foreign.exists()
    monkeypatch.setattr(storage,'MAX_STORED_BYTES',3)
    with pytest.raises(storage.ExportLimit):
        storage.store_export(b'exceeds')


def test_export_path_does_not_expand_vpn_download_roots(tmp_path,monkeypatch):
    monkeypatch.setenv('PANEL_EXPORT_ROOT',str(tmp_path/'private-exports'))
    from app.config import reset_settings_cache
    reset_settings_cache()
    from app.export_artifacts import store_export,assert_export_file
    from app.download_tokens import assert_allowed_file
    path = store_export(b'synthetic')
    with pytest.raises(ValueError):
        assert_allowed_file(path)
    outside = tmp_path/'outside.xlsx'
    outside.write_bytes(b'synthetic')
    with pytest.raises(ValueError):
        assert_export_file(outside)


def test_cleanup_worker_removes_expired_artifacts_without_another_export(tmp_path,monkeypatch):
    import time
    from types import SimpleNamespace
    monkeypatch.setenv('PANEL_EXPORT_ROOT',str(tmp_path/'private-exports'))
    from app.config import reset_settings_cache
    reset_settings_cache()
    import app.export_artifacts as storage
    path = storage.store_export(b'synthetic')
    old = time.time()-86400
    os.utime(path,(old,old))
    app = SimpleNamespace(state=SimpleNamespace())
    storage.start_cleanup(app)
    try:
        deadline = time.monotonic()+3
        while path.exists() and time.monotonic()<deadline:
            app.state.export_cleanup[0].wait(.02)
        assert not path.exists()
    finally:
        storage.stop_cleanup(app)
    assert not app.state.export_cleanup[1].is_alive()


def test_export_quota_is_shared_between_processes(tmp_path,monkeypatch):
    import subprocess
    import sys
    monkeypatch.setenv('PANEL_EXPORT_ROOT',str(tmp_path/'private-exports'))
    code = '''
import app.export_artifacts as storage
storage.MAX_STORED_FILES = 2
try:
    storage.store_export(b'synthetic')
    print('ok')
except storage.ExportLimit:
    print('limit')
'''
    processes = [subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(4)]
    outcomes = []
    for process in processes:
        stdout,stderr = process.communicate(timeout=20)
        assert process.returncode == 0,stderr
        outcomes.append(stdout.strip())
    assert sorted(outcomes) == ['limit','limit','ok','ok']
    assert len(list((tmp_path/'private-exports').glob('export-*.xlsx'))) == 2
