"""Published catalog validation; portable without controller account modules."""
from __future__ import annotations

import copy
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/alt-linux/control'))

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.errors import ControlError

SOURCE = ROOT / 'deploy/alt-linux/ansible'
SOFTWARE = ['software.browser', 'software.onlyoffice', 'software.nextcloud',
            'software.directum', 'software.cryptopro', 'software.cades', 'software.gosplugin']


@pytest.fixture
def project(tmp_path):
    # Never copy local Vault, inventory or private controller artifacts.
    target = tmp_path / 'ansible'
    (target / 'group_vars').mkdir(parents=True)
    shutil.copyfile(SOURCE / 'group_vars/software_catalog.yml',
                    target / 'group_vars/software_catalog.yml')
    shutil.copytree(SOURCE / 'roles', target / 'roles')
    return target


def edit(project, change):
    path = project / 'group_vars/software_catalog.yml'
    document = yaml.safe_load(path.read_text(encoding='utf-8'))
    change(document['setup_catalog'])
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding='utf-8')


def test_catalog_initial_profiles():
    catalog = ComponentCatalog.load(SOURCE)
    assert len(catalog.components()) == 17
    assert catalog.version == 1
    assert len(catalog.fingerprint) == 64
    core = catalog.profile('core-apps')
    assert core['version'] == 1
    assert [c for c in core['components'] if c.startswith('software.')] == SOFTWARE
    assert 'remote.krfb' not in core['components']
    assert 'remote.krfb' in core['optional_components']
    assert not any(c.startswith('software.') for c in catalog.profile('base')['components'])
    standard = catalog.profile('office-standard-v1')
    assert [c for c in standard['components'] if c.startswith('software.')] == SOFTWARE[:4]
    assert catalog.profile('office-signature-v1')['components'] == core['components']
    assert catalog.component('domain.ready')['execution']['adapter'] == 'legacy_domain_critical'
    assert catalog.component('software.onlyoffice')['preflight']['artifact_key'] == 'onlyoffice'
    assert catalog.component('software.cryptopro')['verification']['services'] == ['pcscd.socket']


@pytest.mark.parametrize('bad', [
    'duplicate', 'version_bool', 'unknown_key', 'unknown_role', 'unknown_artifact',
    'unknown_dependency', 'cycle', 'os', 'profile_order', 'no_preflight',
    'no_verification', 'command', 'expression', 'protected_role', 'empty_catalog',
    'duplicate_profile', 'profile_version', 'unknown_recipe', 'duplicate_dependency',
    'home_scope', 'retry_policy', 'missing_domain_dependency', 'unknown_profile_component',
])
def test_catalog_rejects_entire_invalid_document(project, bad):
    def change(catalog):
        components = catalog['components']
        component = next(c for c in components if c['id'] == 'software.onlyoffice')
        if bad == 'duplicate': components.append(copy.deepcopy(component))
        elif bad == 'version_bool': component['version'] = True
        elif bad == 'unknown_key': component['script'] = 'echo forbidden'
        elif bad == 'unknown_role': component['execution']['role'] = 'unpublished_role'
        elif bad == 'unknown_artifact': component['preflight']['artifact_key'] = 'unpublished'
        elif bad == 'unknown_dependency': component['dependencies'].append('software.absent')
        elif bad == 'cycle': components[0]['dependencies'] = [component['id']]
        elif bad == 'os': component['supported_os'] = ['unapproved-os']
        elif bad == 'profile_order': catalog['profiles'][1]['components'].reverse()
        elif bad == 'no_preflight': del component['preflight']
        elif bad == 'no_verification': del component['verification']
        elif bad == 'command': component['execution']['command'] = 'whoami'
        elif bad == 'expression': component['execution']['role'] = '{{ arbitrary_role }}'
        elif bad == 'protected_role': component['execution']['role'] = 'domain_join'
        elif bad == 'empty_catalog': catalog['components'] = []
        elif bad == 'duplicate_profile': catalog['profiles'].append(copy.deepcopy(catalog['profiles'][0]))
        elif bad == 'profile_version': catalog['profiles'][0]['version'] = 0
        elif bad == 'unknown_recipe': component['verification']['recipe'] = 'run_shell'
        elif bad == 'duplicate_dependency': component['dependencies'] *= 2
        elif bad == 'home_scope': component['execution']['requires_user_home'] = 'yes'
        elif bad == 'retry_policy': component['execution']['retry_policy'] = 'always'
        elif bad == 'missing_domain_dependency': component['dependencies'].remove('domain.ready')
        elif bad == 'unknown_profile_component': catalog['profiles'][0]['components'].append('missing')
    edit(project, change)
    with pytest.raises(ControlError) as caught:
        ComponentCatalog.load(project)
    assert caught.value.code == 'component_catalog_invalid'
    assert 'echo forbidden' not in str(caught.value)


def test_duplicate_yaml_key_and_unsafe_tag_rejected(project):
    path = project / 'group_vars/software_catalog.yml'
    for raw in ('setup_catalog: {}\nsetup_catalog: {}\n',
                'setup_catalog: !!python/object/apply:os.system ["echo forbidden"]\n'):
        path.write_text(raw, encoding='utf-8')
        with pytest.raises(ControlError, match='catalog'):
            ComponentCatalog.load(project)


def test_symlinked_role_and_catalog_are_rejected(project):
    role = project / 'roles/software_onlyoffice'
    moved = project / 'outside-role'
    role.rename(moved)
    try:
        role.symlink_to(moved, target_is_directory=True)
    except OSError:
        pytest.skip('Creating symlinks unavailable on this test runner')
    with pytest.raises(ControlError):
        ComponentCatalog.load(project)
    role.unlink()
    moved.rename(role)
    path = project / 'group_vars/software_catalog.yml'
    other = project / 'outside-catalog.yml'
    path.rename(other)
    path.symlink_to(other)
    with pytest.raises(ControlError):
        ComponentCatalog.load(project)


def test_add_published_component_without_orchestrator_change(project):
    original = ComponentCatalog.load(project)
    role = project / 'roles/software_example/tasks'
    role.mkdir(parents=True)
    (role / 'main.yml').write_text('---\n- ansible.builtin.debug: {msg: approved}\n', encoding='utf-8')
    def change(catalog):
        component = copy.deepcopy(next(c for c in catalog['components'] if c['id'] == 'software.onlyoffice'))
        component.update(id='software.example', name='Approved example')
        component['execution']['role'] = 'software_example'
        catalog['components'].append(component)
    edit(project, change)
    updated = ComponentCatalog.load(project)
    assert updated.component('software.example')['execution']['role'] == 'software_example'
    order = [c['id'] for c in updated.ordered(['software.example'], os_id='alt-kworkstation-11')]
    assert order.index('system.base') < order.index('domain.ready') < order.index('software.example')
    assert updated.fingerprint != original.fingerprint
    with pytest.raises(ControlError):
        original.component('software.example')


def test_catalog_version_change_preserves_snapshot_and_defensive_copies(project):
    original = ComponentCatalog.load(project)
    snapshot = original.profile('core-apps')
    edit(project, lambda c: c['profiles'][1].update(version=2))
    updated = ComponentCatalog.load(project)
    assert updated.fingerprint != original.fingerprint
    assert snapshot['version'] == original.profile('core-apps')['version'] == 1
    assert updated.profile('core-apps')['version'] == 2
    snapshot['components'].clear()
    component = original.component('software.onlyoffice')
    component['execution']['role'] = 'not_approved'
    assert original.profile('core-apps')['components']
    assert original.component('software.onlyoffice')['execution']['role'] == 'software_onlyoffice'
    with pytest.raises(ControlError):
        original.ordered(['software.onlyoffice'], os_id='other-os')
