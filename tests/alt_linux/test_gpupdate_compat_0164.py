"""Compatibility against inspected 0.16.4 vendor bytes, including native fixes."""
from enum import Enum
from pathlib import Path
import ast
import os
import types
import xml.etree.ElementTree as ET

import pytest

from test_gpupdate_compat import helper, fixture, functions, run, tree


FIXTURES = Path(__file__).with_name('fixtures')/'gpupdate-0.16.4'
MODULES = {
    'services': ('gpupdate', '/usr/lib/python3/site-packages/gpoa/gpt/services.py'),
    'kde': ('gpoa-lib', '/usr/lib/python3/site-packages/gpoa_lib/frontend/kde_applier.py'),
    'shortcuts': ('gpupdate', '/usr/lib/python3/site-packages/gpoa/frontend/shortcut_applier.py'),
    'shortcut_model': ('gpupdate', '/usr/lib/python3/site-packages/gpoa/gpt/shortcuts.py'),
}


def vendor_bytes(name):
    # The inspected 0.16.4 services module is identical to 0.16.1.
    source=FIXTURES.with_name('gpupdate-0.16.1') if name=='services' else FIXTURES
    return (source/(name+'.py.txt')).read_bytes()


def vendor_fixture(root):
    for name, (_, path) in MODULES.items():
        dest = root/path.lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(vendor_bytes(name))
        dest.chmod(0o644)
    def packages(path):
        package = next(package for package, suffix in MODULES.values() if str(path).endswith(suffix))
        return package, '0.16.4-alt1'
    return helper(), packages


def test_0164_check_preserves_all_vendor_bytes_and_only_predicts_service_repair(tmp_path):
    m, packages = vendor_fixture(tmp_path)
    before = tree(tmp_path)
    result = run(m, tmp_path, packages)
    assert result['changed'] is True and result['backup_id'] is None
    states = {entry['id']: entry['state'] for entry in result['fixes']}
    assert states == {'services': 'would_patch', 'kde': 'already_fixed',
                      'shortcuts': 'already_fixed', 'shortcut_model': 'already_fixed'}
    assert tree(tmp_path) == before


def test_0164_apply_fixes_xml_without_rewriting_native_fixes_and_repeats_as_noop(tmp_path):
    m, packages = vendor_fixture(tmp_path)
    before = tree(tmp_path)
    result = run(m, tmp_path, packages, True)
    assert result['changed'] is True and result['backup_id']
    for name in ('kde', 'shortcuts', 'shortcut_model'):
        key = MODULES[name][1].lstrip('/')
        assert tree(tmp_path)[key] == before[key]
    source = (tmp_path/MODULES['services'][1].lstrip('/')).read_text()
    xml = '<Services><Service name="example"><Properties serviceName="example" serviceAction="START"/></Service></Services>'
    namespace = functions(source, {'service', 'read_services'}, {
        'DynamicAttributes': object, 'get_xml_root': lambda unused: ET.fromstring(xml),
        'parse_filters': lambda unused: []})
    assert namespace['read_services']('fixture')[0].serviceaction == 'START'
    after = tree(tmp_path)
    assert run(m, tmp_path, packages, True)['changed'] is False
    assert tree(tmp_path) == after


def test_0164_backup_can_restore_only_service_original(tmp_path, monkeypatch):
    m, packages = vendor_fixture(tmp_path)
    result = run(m, tmp_path, packages, True)
    monkeypatch.setattr(m, 'busy_client', lambda: False)
    restored = m.rollback(result['backup_id'], root=tmp_path, owner=os.getuid(), package_query=packages)
    assert restored['changed'] is True
    for name, (_, path) in MODULES.items():
        assert (tmp_path/path.lstrip('/')).read_bytes() == vendor_bytes(name)


@pytest.mark.parametrize('fault', ['kde', 'shortcuts', 'shortcut_model', 'mixed_version'])
def test_0164_unverified_native_fix_blocks_all_writes(tmp_path, fault):
    m, packages = vendor_fixture(tmp_path)
    if fault == 'mixed_version':
        original = packages
        packages = lambda path: ('gpoa-lib', '0.16.1-alt1') if str(path).endswith(MODULES['kde'][1]) else original(path)
    else:
        p = tmp_path/MODULES[fault][1].lstrip('/')
        p.write_bytes(p.read_bytes()+b'\n# unrelated modification\n')
    before = tree(tmp_path)
    with pytest.raises(ValueError):
        run(m, tmp_path, packages, True)
    assert tree(tmp_path) == before and not (tmp_path/'var').exists()


def test_0164_backup_rejects_a_later_package_version_before_restore(tmp_path, monkeypatch):
    m, packages = vendor_fixture(tmp_path)
    result = run(m, tmp_path, packages, True)
    monkeypatch.setattr(m, 'busy_client', lambda: False)
    before = tree(tmp_path)
    with pytest.raises(ValueError):
        m.rollback(result['backup_id'], root=tmp_path, owner=os.getuid(),
                   package_query=lambda path: (packages(path)[0], '0.16.5-alt1'))
    assert tree(tmp_path) == before


def test_legacy_backup_does_not_authorize_restore_after_upgrade(tmp_path, monkeypatch):
    m, packages = fixture(tmp_path)
    result = run(m, tmp_path, packages, True)
    # A retained schema-1 manifest has no package identity. Its interpretation
    # remains the inspected 0.16.1 recipe even with the newer rollback helper.
    import json
    manifest = tmp_path/'var/backups/alt-gpupdate-compat'/result['backup_id']/'manifest.json'
    value = json.loads(manifest.read_text())
    value['schema'] = 1
    for row in value['modules']:
        row.pop('package', None)
        row.pop('evr', None)
    manifest.write_text(json.dumps(value))
    monkeypatch.setattr(m, 'busy_client', lambda: False)
    before = tree(tmp_path)
    with pytest.raises(ValueError):
        m.rollback(result['backup_id'], root=tmp_path, owner=os.getuid(),
                   package_query=lambda path: (packages(path)[0], '0.16.4-alt1'))
    assert tree(tmp_path) == before


def test_legacy_schema_one_backup_still_restores_its_original_package(tmp_path, monkeypatch):
    import json
    m, packages = fixture(tmp_path)
    result = run(m, tmp_path, packages, True)
    manifest = tmp_path/'var/backups/alt-gpupdate-compat'/result['backup_id']/'manifest.json'
    value = json.loads(manifest.read_text())
    value['schema'] = 1
    for row in value['modules']:
        row.pop('package', None)
        row.pop('evr', None)
    manifest.write_text(json.dumps(value))
    monkeypatch.setattr(m, 'busy_client', lambda: False)
    assert m.rollback(result['backup_id'], root=tmp_path, owner=os.getuid(),
                      package_query=packages)['changed'] is True
    original = FIXTURES.with_name('gpupdate-0.16.1')
    for patch in m.PATCHES:
        assert (tmp_path/patch['path'].lstrip('/')).read_bytes() == (original/(patch['id']+'.py.txt')).read_bytes()


def test_0164_native_kde_probe_is_headless_and_rejects_ambiguous_writers():
    calls = []
    def output(argv, **kwargs):
        calls.append(kwargs)
        assert kwargs['env']['QT_QPA_PLATFORM'] == 'offscreen'
        assert kwargs['env']['LC_ALL'] == 'C'
        return 'KDE Frameworks Version: 6.30.0\n'
    source = (FIXTURES/'kde.py.txt').read_text()
    ns = functions(source, {'get_kde_version'}, {
        'os': os, 'KDE_TOOL_PATH': '/usr/lib/kf5/bin:/usr/lib/kf6/bin:/usr/bin',
        'shutil': types.SimpleNamespace(which=lambda name, **kwargs: '/usr/bin/'+name),
        'subprocess': types.SimpleNamespace(check_output=output), 'log': lambda *args: None})
    assert ns['get_kde_version']() == 6 and calls
    ns['shutil'].which = lambda name, **kwargs: None if name == 'kinfo' else '/usr/bin/'+name
    assert ns['get_kde_version']() is None
    ns['shutil'].which = lambda name, **kwargs: '/usr/bin/'+name if name == 'kwriteconfig6' else None
    assert ns['get_kde_version']() == 6


def test_0164_native_shortcut_frontend_uses_model_to_preserve_machine_values():
    model = functions((FIXTURES/'shortcut_model.py.txt').read_text(),
                      {'TargetType', 'get_ttype', 'shortcut'}, {'Enum': Enum, 'DynamicAttributes': object})
    row = {'dest': '%DesktopDir%/Folder', 'path': 'file://%HOME%', 'arguments': '',
           'name': 'Folder', 'action': 'U', 'type': 'URL', 'icon': 'folder-home',
           'comment': 'Folder', 'disabled': True, 'uid': '11111111-2222-3333-4444-555555555555',
           'remove_policy': True, 'bypass_errors': True, 'apply_once': True,
           'policy_guid': '22222222-2222-3333-4444-555555555555', 'filters': []}
    namespace = {'applier_frontend': object, 'shortcut': model['shortcut'],
                 'string_to_literal_eval': ast.literal_eval, 'log': lambda *args: None,
                 '_filter_objects': lambda values, username: values}
    cls = functions((FIXTURES/'shortcuts.py.txt').read_text(),
                    {'shortcut_applier_user'}, namespace)['shortcut_applier_user']
    obj = object.__new__(cls)
    obj.username = 'synthetic'
    obj.storage = types.SimpleNamespace(get_dictionary_from_dconf_file_db=lambda: {
        'Software/BaseALT/Policies/Preferences/Machine': {'Shortcuts': repr([row])}})
    sc = obj.get_machine_shortcuts()[0]
    assert sc.type.value == 'URL' and sc.is_usercontext() and sc.merged_machine
    for key in ('dest', 'icon', 'comment', 'disabled', 'uid', 'remove_policy',
                'bypass_errors', 'apply_once', 'policy_guid'):
        assert getattr(sc, key) == row[key]
