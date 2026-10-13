"""Keep bootstrap and ordinary first-install package sources consistent."""
from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1] / 'deploy/alt-linux'


def mirror_rule():
    tasks = yaml.safe_load((ROOT / 'ansible/roles/prejoin_upgrade/tasks/main.yml').read_text())
    task = next(t for t in tasks if t['name'] == 'Select the approved p11 package mirror before first join')
    return task, task['ansible.builtin.replace']


@pytest.mark.parametrize('scheme', ['http', 'https'])
@pytest.mark.parametrize('arch', ['x86_64', 'x86_64-i586', 'noarch'])
def test_only_default_p11_origin_changes_preserving_branch_components_and_signature(scheme, arch):
    _, rule = mirror_rule()
    line = f'rpm [p11] {scheme}://ftp.altlinux.org/pub/distributions/ALTLinux p11/branch/{arch} classic debuginfo\n'
    expected = line.replace(f'{scheme}://ftp.altlinux.org', 'https://download.basealt.ru')
    assert re.sub(rule['regexp'], rule['replace'], line, flags=re.M) == expected
    assert rule.get('backup', False) is False


@pytest.mark.parametrize('line', [
    '#rpm [p11] http://ftp.altlinux.org/pub/distributions/ALTLinux p11/branch/x86_64 classic',
    'rpm [p10] http://ftp.altlinux.org/pub/distributions/ALTLinux p10/branch/x86_64 classic',
    'rpm [p11] http://ftp.altlinux.org/pub/distributions/ALTLinux Sisyphus/x86_64 classic',
    'rpm [vendor] https://example.org/packages p11/branch/x86_64 classic',
    'rpm [p11] https://download.basealt.ru/pub/distributions/ALTLinux p11/branch/noarch classic',
])
def test_comments_other_branches_and_custom_repositories_are_unchanged(line):
    _, rule = mirror_rule()
    assert re.sub(rule['regexp'], rule['replace'], line, flags=re.M) == line


def test_bootstrap_uses_same_rule_before_apt_and_role_excludes_joined_machines():
    source = (ROOT / 'bootstrap/bootstrap.sh').read_text()
    _, rule = mirror_rule()
    pattern = re.search(r"P11_MIRROR_PATTERN='([^']+)'", source).group(1)
    replacement = re.search(r"P11_MIRROR_REPLACEMENT='([^']+)'", source).group(1)
    assert pattern == rule['regexp']
    assert replacement == rule['replace']
    assert source.index('select_p11_mirror\n') < source.index('apt-get update')
    assert '[[ -L "${source_file}" ]]' in source
    task, _ = mirror_rule()
    assert 'not prejoin_upgrade_already_joined' in task['when']
    from jinja2.nativetypes import NativeEnvironment
    env = NativeEnvironment()
    assert env.from_string(task['loop']).render(prejoin_upgrade_sources={'skipped': True}) == []
