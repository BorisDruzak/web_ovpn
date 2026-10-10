from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest

HELPER = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible/roles/plasma_baseline/files/apply_existing_power.py'
spec = spec_from_file_location('existing_power', HELPER)
power = module_from_spec(spec)
spec.loader.exec_module(power)


def test_missing_domain_home_is_not_created(monkeypatch):
    monkeypatch.setattr(power, 'run', lambda argv, **kw: SimpleNamespace(
        returncode=0, stdout='employee:x:12345:12345::/home/domain/employee:/bin/bash\n'))
    monkeypatch.setattr(Path, 'is_absolute', lambda p: True)
    monkeypatch.setattr(Path, 'is_relative_to', lambda p, parent: True)
    monkeypatch.setattr(Path, 'is_symlink', lambda p: False)
    monkeypatch.setattr(Path, 'exists', lambda p: False)
    assert power.apply('employee') == {'changed': False, 'profile_exists': False}


@pytest.mark.parametrize('account', ['root', 'ansible', 'osn-admin'])
def test_administrative_profiles_are_rejected(monkeypatch, account):
    monkeypatch.setattr(power, 'run', lambda argv, **kw: SimpleNamespace(
        returncode=0, stdout=f'{account}:x:12345:12345::/home/{account}:/bin/bash\n'))
    with pytest.raises(ValueError, match='Administrative'):
        power.apply(account)


def test_only_different_power_keys_are_written_and_repeat_is_unchanged(monkeypatch):
    home = '/home/domain/employee'
    values = {(profile, section, key): value for profile in ('AC', 'Battery', 'LowBattery')
              for section, key, value in power.SETTINGS}
    values[('AC', 'Display', 'TurnOffDisplayWhenIdle')] = 'true'
    values[('AC', 'Performance', 'PowerProfile')] = 'balanced'
    writes = []

    def fake_run(argv, **kwargs):
        if argv[0] == 'getent':
            return SimpleNamespace(returncode=0, stdout=f'employee:x:12345:12345::{home}:/bin/bash\n')
        group_indexes = [i for i, arg in enumerate(argv) if arg == '--group']
        key = (argv[group_indexes[0]+1], argv[group_indexes[1]+1], argv[argv.index('--key')+1])
        if 'kwriteconfig6' in argv:
            writes.append(key)
            values[key] = argv[-1]
            return SimpleNamespace(returncode=0, stdout='')
        assert 'kreadconfig6' in argv
        return SimpleNamespace(returncode=0, stdout=values[key])

    monkeypatch.setattr(power, 'run', fake_run)
    monkeypatch.setattr(Path, 'is_absolute', lambda p: True)
    monkeypatch.setattr(Path, 'is_relative_to', lambda p, parent: True)
    monkeypatch.setattr(Path, 'is_symlink', lambda p: False)
    monkeypatch.setattr(Path, 'exists', lambda p: p.name != 'bus')
    monkeypatch.setattr(Path, 'is_dir', lambda p: True)
    monkeypatch.setattr(Path, 'stat', lambda p, **kw: SimpleNamespace(
        st_uid=12345, st_mode=0o40700))
    assert power.apply('employee')['changed'] is True
    assert writes == [('AC', 'Display', 'TurnOffDisplayWhenIdle')]
    assert values[('AC', 'Performance', 'PowerProfile')] == 'balanced'
    assert power.apply('employee')['changed'] is False
    assert len(writes) == 1
