"""A release cannot claim a narrow scope from an unknown or shared change."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT/'deploy/alt-linux/verification_policy.py'
ROLE = 'deploy/alt-linux/ansible/roles/'


def module():
    spec = importlib.util.spec_from_file_location('verification_policy', MODULE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def rows(**items):
    return [[p, 0o644, h*64] for p, h in sorted(items.items())]


def test_signing_helper_and_owned_test_select_all_coupled_contracts():
    m = module()
    paths = {ROLE+'software_gosuslugi_plugin/files/cryptopro_browser_policy.py': 'a',
             'tests/alt_linux/test_cryptopro_browser_policy.py': 'a'}
    plan = m.select(rows(**paths), rows(**{p: 'b' for p in paths}))
    assert plan['mode'] == 'selective' and plan['components'] == ['browser-signing']
    assert 'tests/test_alt_yandex_gpo_handoff.py' in plan['targets']
    assert 'tests/alt_linux/test_yandex_gpo_policy_runtime.py' in plan['targets']
    assert set(m.MANDATORY) <= set(plan['targets'])
    assert 'tests/alt_linux' not in plan['targets']


@pytest.mark.parametrize('path', [
    'deploy/alt-linux/control/alt_deploy/setup.py', 'deploy/alt-linux/install-control-plane-lib.sh',
    'deploy/alt-linux/backup/alt_deploy_backup/guard.py', 'deploy/alt-linux/verification_policy.py',
    'deploy/alt-linux/ansible/group_vars/software_catalog.yml', 'requirements.txt',
    'tests/alt_linux/conftest.py', 'tests/alt_linux/support/installer_sandbox.py',
    'tests/alt_linux/test_unmapped_new_case.py', ROLE+'new_unknown_role/tasks/main.yml',
])
def test_shared_or_unknown_paths_require_full(path):
    assert module().select(rows(**{path: 'a'}), rows(**{path: 'b'}))['mode'] == 'full'


@pytest.mark.parametrize('change', ['delete', 'rename', 'mode'])
def test_removal_and_permissions_require_full_even_inside_one_component(change):
    path = ROLE+'software_directum/tasks/main.yml'
    before = rows(**{path: 'a'})
    after = [] if change == 'delete' else rows(**{path+'/renamed': 'a'}) if change == 'rename' else [[path, 0o600, 'a'*64]]
    assert module().select(before, after)['mode'] == 'full'


def test_two_components_select_their_union_and_static_docs_do_not_force_full():
    m = module()
    paths = {ROLE+'software_directum/tasks/main.yml': 'a', ROLE+'software_vkworkspace/tasks/main.yml': 'a',
             'docs/WORKSTATIONS_WEB_GUIDE.md': 'a'}
    plan = m.select(rows(**paths), rows(**{p: 'b' for p in paths}))
    assert plan['mode'] == 'selective'
    assert set(plan['components']) == {'directum', 'vkworkspace'}
    assert 'tests/test_alt_directum_ansible.py' in plan['targets']
    assert 'tests/alt_linux/test_software_vkworkspace.py' in plan['targets']


def test_added_component_helper_is_scoped_but_unknown_new_test_is_not():
    m = module()
    assert m.select([], rows(**{ROLE+'software_onlyoffice/files/new-helper.py': 'a'}))['mode'] == 'selective'
    assert m.select([], rows(**{'tests/alt_linux/test_unknown_office.py': 'a'}))['mode'] == 'full'


def test_no_change_still_runs_mandatory_checks_and_full_can_be_forced():
    m = module()
    assert m.select([], [])['targets'] == list(m.MANDATORY)
    assert m.select([], [], full=True)['mode'] == 'full'


@pytest.mark.parametrize('subpath', ['meta/main.yml', 'handlers/main.yml', 'library/global.py', 'filter_plugins/global.py'])
def test_role_orchestration_and_plugins_are_not_component_helpers(subpath):
    assert module().select([], rows(**{ROLE+'software_onlyoffice/'+subpath: 'a'}))['mode'] == 'full'


@pytest.mark.parametrize('task_yaml', [
    '- ansible.builtin.include_role:\n    name: domain_join\n',
    '- action: include_role name=domain_join\n',
    '- local_action:\n    module: import_role\n    name: domain_join\n',
])
def test_cross_role_import_in_task_file_requires_full(tmp_path, task_yaml):
    m = module()
    path = ROLE+'software_onlyoffice/tasks/main.yml'
    task = tmp_path/path;task.parent.mkdir(parents=True)
    task.write_text(task_yaml)
    assert m.select(rows(**{path: 'a'}), rows(**{path: 'b'}), source=tmp_path)['mode'] == 'full'


def test_full_suite_covers_every_component_target_including_standalone_tests():
    m = module()
    full = m.full_targets()
    for group in m.GROUPS.values():
        for target in (*m.MANDATORY, *group['tests']):
            assert (ROOT/target).is_file(), target
            assert target.startswith('tests/alt_linux/') or target in full
    assert 'tests/alt_linux' in full


def test_every_test_referencing_a_scoped_role_is_in_its_impact_group():
    m = module()
    missing = []
    for name, group in m.GROUPS.items():
        targets = set(m.MANDATORY)
        for impacted in m.affected([name]):
            targets.update(m.GROUPS[impacted]['tests'])
        for path in (ROOT/'tests').rglob('test*.py'):
            if any(role in path.read_text(encoding='utf-8') for role in group['roles']):
                relative = path.relative_to(ROOT).as_posix()
                if relative not in targets:
                    missing.append((name, relative))
    assert not missing, missing


def test_declared_catalog_dependencies_are_covered_by_reverse_impact():
    import yaml
    m = module()
    catalog = yaml.safe_load((ROOT/'deploy/alt-linux/ansible/group_vars/software_catalog.yml').read_text())['setup_catalog']
    components = {entry['id']: entry for entry in catalog['components']}
    by_role = {role: name for name, group in m.GROUPS.items() for role in group['roles']}
    for component in components.values():
        consumer = by_role.get(component['execution'].get('role'))
        if consumer is None: continue
        for identity in component['dependencies']:
            provider = by_role.get(components[identity]['execution'].get('role'))
            if provider is not None:
                assert consumer in m.affected([provider]), (provider, consumer)
