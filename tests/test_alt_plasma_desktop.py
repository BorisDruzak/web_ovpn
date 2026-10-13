from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest

HELPER = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible/roles/plasma_baseline/files/apply_desktop_defaults.py'


def helper():
    assert HELPER.exists(), 'The desktop baseline must cover existing and future profiles'
    spec = spec_from_file_location('desktop_defaults', HELPER)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_merge_preserves_unrelated_settings_and_is_idempotent(tmp_path):
    module = helper()
    values = {('kdeglobals', 'KDE', 'SingleClick'): 'true',
              ('kdeglobals', 'General', 'UnrelatedSetting'): 'keep',
              ('mimeapps.list', 'Added Associations', 'application/pdf'): 'vendor-viewer.desktop;'}
    writes = []

    def run(argv, **kwargs):
        if 'kbuildsycoca6' in argv or 'busctl' in argv:
            return SimpleNamespace(returncode=0, stdout='')
        key = (Path(argv[argv.index('--file')+1]).name,
               argv[argv.index('--group')+1], argv[argv.index('--key')+1])
        if 'kwriteconfig6' in argv:
            values[key] = argv[-1]
            writes.append(key)
            return SimpleNamespace(returncode=0, stdout='')
        return SimpleNamespace(returncode=0, stdout=values.get(key, '__ALT_MISSING__'))

    result = module.apply_settings(tmp_path, [], run)
    assert result['changed'] is True
    assert values[('kdeglobals', 'General', 'UnrelatedSetting')] == 'keep'
    assert values[('mimeapps.list', 'Added Associations', 'application/pdf')] == 'onlyoffice-desktopeditors.desktop;vendor-viewer.desktop;'
    docx = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    assert values[('mimeapps.list', 'Default Applications', docx)] == 'onlyoffice-desktopeditors.desktop;'
    assert values[('kdeglobals', 'KDE', 'SingleClick')] == 'false'
    count = len(writes)
    assert module.apply_settings(tmp_path, [], run)['changed'] is False
    assert len(writes) == count


def test_keyboard_uses_published_template_and_preserves_other_keys(tmp_path):
    module = helper()
    template = HELPER.parent.parent/'templates/kxkbrc.j2'
    settings = module.keyboard_settings(template.read_text())
    assert settings == [('kxkbrc', 'Layout', 'SwitchMode', 'Global')]
    values = {('kxkbrc', 'Layout', 'SwitchMode'): 'WinClass', ('kxkbrc', 'Layout', 'LayoutList'): 'us,ru'}
    calls = []
    def run(argv, **kwargs):
        key = (Path(argv[argv.index('--file')+1]).name, argv[argv.index('--group')+1], argv[argv.index('--key')+1])
        if 'kwriteconfig6' in argv:
            values[key] = argv[-1]
            calls.append(key)
        return SimpleNamespace(returncode=0, stdout=values.get(key, '__ALT_MISSING__'))
    assert module.apply_settings(tmp_path, [], run, settings=settings)['changed'] is True
    assert values[('kxkbrc', 'Layout', 'LayoutList')] == 'us,ru'
    assert module.apply_settings(tmp_path, [], run, settings=settings)['changed'] is False
    assert calls == [('kxkbrc', 'Layout', 'SwitchMode')]


def test_symlinked_target_is_rejected_before_any_write(tmp_path):
    module = helper()
    outside = tmp_path.parent/'outside-desktop-config'
    outside.write_text('do not change')
    (tmp_path/'mimeapps.list').symlink_to(outside)
    calls = []
    with pytest.raises(ValueError, match='Symlink'):
        module.apply_settings(tmp_path, [], lambda argv, **kwargs: calls.append(argv))
    assert calls == []
    assert outside.read_text() == 'do not change'


def test_missing_profile_is_not_created(monkeypatch):
    module = helper()
    monkeypatch.setattr(module, 'resolve_profile', lambda username: (None, [], 12345))
    assert module.apply('employee') == {'changed': False, 'profile_exists': False}


@pytest.mark.parametrize('username', ['root', 'ansible', 'osn-admin'])
def test_administrative_profile_is_rejected(monkeypatch, username):
    module = helper()
    monkeypatch.setattr(module, 'run', lambda argv, **kwargs: SimpleNamespace(
        returncode=0, stdout=f'{username}:x:12345:12345::/home/{username}:/bin/bash\n'))
    with pytest.raises(ValueError, match='Administrative'):
        module.resolve_profile(username)


def test_cache_refresh_is_retried_after_partial_apply(tmp_path):
    module = helper()
    values = {}
    cache_calls = []

    def run(argv, **kwargs):
        if 'kbuildsycoca6' in argv:
            cache_calls.append(argv)
            return SimpleNamespace(returncode=0, stdout='')
        key = (Path(argv[argv.index('--file')+1]).name,
               argv[argv.index('--group')+1], argv[argv.index('--key')+1])
        if 'kwriteconfig6' in argv:
            values[key] = argv[-1]
        return SimpleNamespace(returncode=0, stdout=values.get(key, '__ALT_MISSING__'))

    module.apply_settings(tmp_path, ['runuser', '-u', 'employee', '--'], run)
    assert module.apply_settings(tmp_path, ['runuser', '-u', 'employee', '--'], run)['changed'] is False
    assert len(cache_calls) == 2


def test_user_commands_drop_sudo_identity_and_use_profile_locale(monkeypatch):
    module = helper()
    def run(argv, **kwargs):
        if argv[0] == 'getent':
            return SimpleNamespace(returncode=0, stdout='employee:x:12345:12345::/home/domain/employee:/bin/bash\n')
        return SimpleNamespace(returncode=0, stdout='ru_RU.UTF-8')
    monkeypatch.setattr(module, 'run', run)
    monkeypatch.setattr(Path, 'is_absolute', lambda p: True)
    monkeypatch.setattr(Path, 'is_relative_to', lambda p, parent: True)
    monkeypatch.setattr(Path, 'is_symlink', lambda p: False)
    monkeypatch.setattr(Path, 'exists', lambda p: True)
    monkeypatch.setattr(Path, 'is_dir', lambda p: True)
    monkeypatch.setattr(Path, 'stat', lambda p: SimpleNamespace(st_uid=12345))
    _, prefix, _ = module.resolve_profile('employee')
    assert prefix[prefix.index('env')+1:prefix.index('env')+9] == [
        '-u', 'SUDO_UID', '-u', 'SUDO_GID', '-u', 'SUDO_USER', '-u', 'SUDO_COMMAND']
    assert 'LANG=ru_RU.UTF-8' in prefix
    assert '-u' in prefix and 'LC_ALL' in prefix
