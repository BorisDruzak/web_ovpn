"""Behavioral checks for explicitly migrated browser policy ownership."""
import importlib.util
from pathlib import Path

import pytest
import json
import stat
from types import SimpleNamespace

HELPER = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible/roles/software_gosuslugi_plugin/files/browser_policy_source.py'


def module():
    spec = importlib.util.spec_from_file_location('browser_policy_source', HELPER)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixture():
    m = module()
    receipt = {'schema': 1, 'machine_uuid': '53b03180-5d78-11f0-bd95-f027db877a00',
               'gpo_id': 'bb7f77b5-33f1-467d-8844-4c1ba172dc9f', 'gpo_name': 'Browser policy'}
    policy = {'ExtensionInstallForcelist': [m.EXTENSION]}
    cache = '''[Software/BaseALT/Policies/GpoPriority/Machine/1]
display_name = "Browser policy"
name = "{BB7F77B5-33F1-467D-8844-4C1BA172DC9F}"
[Source/Software/Policies/YandexBrowser/ExtensionInstallForcelist]
1 = "{'policy_name': 'Browser policy', 'type': 1}"
[Software/Policies/YandexBrowser/ExtensionInstallForcelist]
1 = "''' + m.EXTENSION + '''"
'''
    return m, receipt, policy, cache


def test_unmigrated_machine_keeps_legacy_ownership():
    m = module()
    assert m.select_source(None, {}, '', 'any', None)['source'] == 'ansible'


def test_migrated_machine_accepts_matching_gpo_and_legacy():
    m, receipt, policy, cache = fixture()
    assert m.select_source(receipt, policy, cache, receipt['machine_uuid'], policy)['source'] == 'gpo'


@pytest.mark.parametrize('problem', ['wrong_machine', 'missing_extension', 'missing_gpo', 'wrong_source', 'custom_legacy', 'invalid_schema'])
def test_migrated_machine_refuses_unsafe_fallback(problem):
    m, receipt, policy, cache = fixture()
    legacy = dict(policy)
    machine = receipt['machine_uuid']
    if problem == 'wrong_machine':
        machine = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    elif problem == 'missing_extension':
        policy = {}
    elif problem == 'missing_gpo':
        cache = cache.replace('BB7F77B5-33F1-467D-8844-4C1BA172DC9F', 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')
    elif problem == 'wrong_source':
        cache = cache.replace("'policy_name': 'Browser policy'", "'policy_name': 'Local Policy'")
    elif problem == 'custom_legacy':
        legacy['HomepageLocation'] = 'https://example.org'
    else:
        receipt['schema'] = 2
    with pytest.raises(ValueError):
        m.select_source(receipt, policy, cache, machine, legacy)


def test_gpo_can_preserve_other_extensions_without_policy_loss():
    m, receipt, policy, cache = fixture()
    policy['ExtensionInstallForcelist'].append('another-extension;https://example.org/update')
    assert m.select_source(receipt, policy, cache, receipt['machine_uuid'], None)['source'] == 'gpo'


def test_generated_file_alone_is_not_gpo_provenance():
    m, receipt, policy, cache = fixture()
    with pytest.raises(ValueError):
        m.select_source(receipt, policy, '', receipt['machine_uuid'], None)


def test_existing_null_receipt_is_not_treated_as_unmigrated(tmp_path, monkeypatch):
    m = module()
    receipt = tmp_path / 'receipt.json'
    receipt.write_text('null')
    monkeypatch.setattr(m, 'RECEIPT', receipt)
    for name, content in [('GENERATED', '{}'), ('CACHE', '')]:
        path = tmp_path / name
        path.write_text(content)
        monkeypatch.setattr(m, name, path)
    dmi = tmp_path / 'dmi'
    dmi.write_text('53b03180-5d78-11f0-bd95-f027db877a00')
    monkeypatch.setattr(m, 'Path', lambda unused: dmi)
    monkeypatch.setattr(m, 'LEGACY', tmp_path / 'absent')
    monkeypatch.setattr(m, 'protected_file', lambda path: None)
    with pytest.raises(ValueError, match='receipt'):
        m.main()


@pytest.mark.parametrize('generated', [None, [], 'not-an-object'])
def test_non_object_generated_policy_is_rejected(generated):
    m, receipt, policy, cache = fixture()
    with pytest.raises(ValueError):
        m.select_source(receipt, generated, cache, receipt['machine_uuid'], None)


def test_duplicate_gpo_display_names_are_ambiguous():
    m, receipt, policy, cache = fixture()
    cache += '''
[Software/BaseALT/Policies/GpoPriority/Machine/2]
display_name = "Browser policy"
name = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
'''
    with pytest.raises(ValueError, match='ambiguous'):
        m.select_source(receipt, policy, cache, receipt['machine_uuid'], None)


def test_existing_null_legacy_file_is_not_silently_removed(tmp_path, monkeypatch):
    m, receipt, policy, cache = fixture()
    for name, content in [('RECEIPT', json.dumps(receipt)), ('GENERATED', json.dumps(policy)),
                           ('CACHE', cache), ('LEGACY', 'null')]:
        path = tmp_path / name
        path.write_text(content)
        monkeypatch.setattr(m, name, path)
    dmi = tmp_path / 'dmi'
    dmi.write_text(receipt['machine_uuid'])
    monkeypatch.setattr(m, 'Path', lambda unused: dmi)
    monkeypatch.setattr(m, 'protected_file', lambda path: None)
    with pytest.raises(ValueError, match='legacy'):
        m.main()


@pytest.mark.parametrize('mode,owner', [(stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o666, 0), (stat.S_IFREG | 0o644, 1000)])
def test_untrusted_evidence_files_are_rejected(mode, owner):
    m = module()
    path = SimpleNamespace(lstat=lambda: SimpleNamespace(st_mode=mode, st_uid=owner))
    with pytest.raises(ValueError, match='unsafe'):
        m.protected_file(path)
