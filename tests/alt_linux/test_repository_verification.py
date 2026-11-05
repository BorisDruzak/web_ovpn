"""The shared ALT runner must not inherit operator-specific test settings."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT/'deploy/alt-linux/verify_repository.py'


def runner():
    spec = importlib.util.spec_from_file_location('repository_verification', RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_inherited_python_pytest_and_display_settings_do_not_leak(monkeypatch, tmp_path):
    monkeypatch.setenv('PYTHONPATH', '/wrong/modules')
    monkeypatch.setenv('PYTEST_ADDOPTS', '-n 8')
    monkeypatch.setenv('PYTEST_PLUGINS', 'untrusted_plugin')
    monkeypatch.setenv('DISPLAY', ':999')
    monkeypatch.setenv('ALT_DEPLOY_STATE_ROOT', '/production/state')
    env = runner().test_environment(tmp_path, '/home/altserver')
    assert env['PYTEST_ADDOPTS'] == '' and env['QT_QPA_PLATFORM'] == 'offscreen'
    assert not {'PYTHONPATH', 'PYTEST_PLUGINS', 'DISPLAY', 'ALT_DEPLOY_STATE_ROOT'} & env.keys()
    assert env['PYTHONPYCACHEPREFIX'].startswith(str(tmp_path))
    assert env['TMPDIR'].startswith(str(tmp_path))


def test_full_and_focused_runs_share_environment_and_short_private_temp(monkeypatch, tmp_path):
    m = runner()
    seen = []
    def run(argv, **kwargs):
        env = kwargs['env']
        cache = Path(env['PYTHONPYCACHEPREFIX'])
        temp = Path(env['TMPDIR'])
        assert cache.is_dir() and temp.is_dir()
        assert cache.stat().st_mode & 0o077 == 0
        assert temp.stat().st_mode & 0o077 == 0
        assert kwargs['cwd'] == ROOT
        if 'pytest' in argv:
            seen.append((argv, env.copy()))
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(m, 'smoke_check', lambda: None)
    assert m.verify(ROOT, [], run=run) == 0
    assert m.verify(ROOT, ['tests/alt_linux/test_prejoin_upgrade_compat.py'], run=run) == 0
    assert seen[0][0][-1] == 'tests/alt_linux'
    assert seen[1][0][-1] == 'tests/alt_linux/test_prejoin_upgrade_compat.py'
    assert all('-n' not in c for c, _ in seen)
    assert not Path(seen[0][1]['TMPDIR']).exists()


def test_smoke_failure_stops_before_test_execution(monkeypatch):
    m = runner()
    monkeypatch.setattr(m, 'smoke_check', lambda: (_ for _ in ()).throw(ValueError('wrong_worker')))
    with pytest.raises(ValueError, match='wrong_worker'):
        m.verify(ROOT, [], run=lambda *a, **k: pytest.fail('must stop before execution'))


def test_syntax_failure_prevents_full_test_run(monkeypatch):
    m = runner()
    monkeypatch.setattr(m, 'smoke_check', lambda: None)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1)
    assert m.verify(ROOT, [], run=run) == 1
    assert not any('pytest' in c for c in calls)


def test_installer_and_developer_use_the_same_runner():
    library = (ROOT/'deploy/alt-linux/install-control-plane-lib.sh').read_text()
    wrapper = (ROOT/'deploy/alt-linux/run-tests.sh').read_text()
    assert 'verification_checkpoint.py' in library and 'verify_repository.py' in wrapper
    assert 'TemporaryDirectory' not in library


@pytest.mark.parametrize('exit_code', [0, 23])
def test_nested_compiler_preserves_readonly_source_and_cleans_cache(monkeypatch, tmp_path, exit_code):
    if os.geteuid() == 0:
        pytest.skip('read-only filesystem proof needs unprivileged account')
    m = runner()
    monkeypatch.setattr(m, 'smoke_check', lambda: None)
    source = tmp_path/'published'
    source.mkdir()
    module = source/'payload.py'
    module.write_text('VALUE = 42\n')
    module.chmod(0o444)
    source.chmod(0o555)
    observed = []
    def run(argv, **kwargs):
        if 'pytest' not in argv:
            return subprocess.CompletedProcess(argv, 0)
        observed.append(kwargs['env'])
        script = 'import py_compile,sys; print(py_compile.compile(sys.argv[1], doraise=True)); sys.exit(int(sys.argv[2]))'
        result = subprocess.run([sys.executable, '-c', script, str(module), str(exit_code)],
                                capture_output=True, text=True, env=kwargs['env'])
        assert Path(result.stdout.strip()).is_relative_to(Path(kwargs['env']['PYTHONPYCACHEPREFIX']))
        return result
    try:
        assert m.verify(ROOT, [], run=run) == exit_code
        assert not Path(observed[0]['PYTHONPYCACHEPREFIX']).exists()
        assert not (source/'__pycache__').exists()
        assert module.read_text() == 'VALUE = 42\n'
    finally:
        source.chmod(0o700)


def test_runtime_fingerprint_detects_unrecorded_startup_code_and_preserved_metadata(tmp_path):
    m = runner()
    site = tmp_path/'site-packages'
    site.mkdir()
    before = m.runtime_digest([site])
    custom = site/'sitecustomize.py'
    custom.write_text('value=1\n')
    added = m.runtime_digest([site])
    assert added != before
    info = custom.stat()
    custom.write_text('value=2\n')
    os.utime(custom, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert m.runtime_digest([site]) != added
    pth = site/'custom.pth'; pth.write_text('import custom\n')
    assert m.runtime_digest([site]) != added


def test_runtime_fingerprint_ignores_only_generated_cache(tmp_path):
    m = runner()
    before = m.runtime_digest([tmp_path])
    cache = tmp_path/'__pycache__'; cache.mkdir(); (cache/'generated.pyc').write_bytes(b'cache')
    assert m.runtime_digest([tmp_path]) == before


def test_venv_import_tree_is_bound_even_though_source_receipt_excludes_it(monkeypatch, tmp_path):
    m = runner()
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    site = tmp_path/'.venv/lib/python3.12/site-packages'
    site.mkdir(parents=True)
    before = m.runtime_digest([site])
    (site/'startup.pth').write_text('import startup\n')
    assert m.runtime_digest([site]) != before
