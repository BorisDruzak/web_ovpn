"""Resolve future APT policy-client versions before the first real upgrade."""
import subprocess
from pathlib import Path

import pytest
import yaml

from test_gpupdate_compat import helper


def resolver(installed=None, upgrade='', install='', *, fail=None):
    installed = installed if installed is not None else {'gpupdate': '0.16.1-alt1', 'gpoa-lib': '0.16.1-alt1'}
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == '/usr/bin/rpm':
            name = argv[-1]
            value = installed.get(name)
            return subprocess.CompletedProcess(argv, 0 if value else 1,
                f'{name}|{value}\n' if value else f'package {name} is not installed\n', '')
        assert '--simulate' in argv and 'Debug::NoLocking=true' in argv
        assert kwargs['timeout'] <= 120 and kwargs['env']['LC_ALL'] == 'C'
        if fail == 'timeout':
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
        return subprocess.CompletedProcess(argv, 100 if fail else 0,
            upgrade if 'dist-upgrade' in argv else install, '')
    return run, calls


def test_future_version_is_checked_instead_of_current_supported_version():
    run, _ = resolver(upgrade='Inst gpupdate [0.16.1-alt1] (0.17.0-alt1:p11+123@456 ALT)\n'
                              'Inst gpoa-lib [0.16.1-alt1] (0.17.0-alt1:p11+123@456 ALT)\n')
    with pytest.raises(ValueError, match='upgrade_version_unsupported'):
        helper().check_upgrade(run=run)


def test_inspected_upgrade_pair_accepts_alt_disttags_without_installing():
    run, calls = resolver(upgrade='Inst gpupdate [0.16.1-alt1] (0.16.4-alt1:p11+123.1@456 ALT)\n'
                                  'Inst gpoa-lib [0.16.1-alt1] (0.16.4-alt1:p11+123.1@456 ALT)\n')
    result = helper().check_upgrade(run=run)
    assert result['packages'] == {'gpupdate': '0.16.4-alt1', 'gpoa-lib': '0.16.4-alt1'}
    assert result['changed'] is False
    assert len([c for c in calls if 'dist-upgrade' in c]) == 1


def test_missing_dependency_is_resolved_before_accepting_upgrade():
    run, calls = resolver(installed={'gpupdate': '0.16.4-alt1'},
                         install='Inst gpoa-lib (0.16.4-alt1:p11+123@456 ALT)\n')
    assert helper().check_upgrade(run=run)['packages']['gpoa-lib'] == '0.16.4-alt1'
    assert any(c[-2:] == ['install', 'gpoa-lib'] for c in calls)


@pytest.mark.parametrize('output', [
    'Remv gpupdate [0.16.1-alt1]\n',
    'Inst gpupdate (0.16.4-alt1 ALT)\nInst gpupdate (0.17.0-alt1 ALT)\n',
    'Inst gpupdate malformed\n',
    'Inst gpupdate:32bit (0.16.4-alt1 ALT)\n',
    'Inst gpupdate (1:0.16.4-alt1 ALT)\n',
])
def test_unsafe_or_ambiguous_resolution_is_denied(output):
    run, _ = resolver(upgrade=output)
    with pytest.raises(ValueError):
        helper().check_upgrade(run=run)


@pytest.mark.parametrize('fault', ['timeout', 'failure'])
def test_unavailable_resolver_never_reports_compatibility(fault):
    run, _ = resolver(fail=fault)
    with pytest.raises(ValueError, match='upgrade_resolution_unavailable'):
        helper().check_upgrade(run=run)


def test_mixed_pair_and_unresolved_missing_package_are_denied():
    for installed in ({'gpupdate': '0.16.4-alt1', 'gpoa-lib': '0.16.1-alt1'}, {}):
        run, _ = resolver(installed=installed)
        with pytest.raises(ValueError):
            helper().check_upgrade(run=run)


def test_prejoin_checks_after_metadata_before_upgrade_without_retrying_transaction():
    path = Path(__file__).resolve().parents[2]/'deploy/alt-linux/ansible/roles/prejoin_upgrade/tasks/main.yml'
    tasks = yaml.safe_load(path.read_text())
    gate = next((t for t in tasks if '--upgrade-check' in t.get('ansible.builtin.script', '')), None)
    assert gate is not None, 'missing future-version compatibility gate'
    upgrade = next(t for t in tasks if t.get('ansible.builtin.command', {}).get('argv') == ['apt-get', '-y', 'dist-upgrade'])
    metadata = next(t for t in tasks if t.get('ansible.builtin.command', {}).get('argv') == ['apt-get', 'update'])
    assert tasks.index(metadata) < tasks.index(gate) < tasks.index(upgrade)
    assert gate['changed_when'] is False and gate['check_mode'] is False
    assert gate['when'] == upgrade['when']
    assert not {'until', 'retries', 'delay'} & set(upgrade)
