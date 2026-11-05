"""CryptoPro policy ownership and safe coexistence with the GosPlugin list."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'deploy/alt-linux/ansible/roles/software_gosuslugi_plugin/files/cryptopro_browser_policy.py'
ID = 'epebfcehmdedogndhlcacafjaacknbcm'
URL = 'https://extension-updates.opera.com/api/omaha/update/'
POLICY = {'ExtensionSettings': {ID: {'installation_mode': 'force_installed', 'update_url': URL}}}


def module():
    spec = importlib.util.spec_from_file_location('cryptopro_browser_policy', HELPER)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def inspect(root):
    return module().inspect_directory(root, expected_uid=os.geteuid())


def test_new_and_repeated_policy_preserve_gosplugin_and_unrelated_files(tmp_path):
    gos = tmp_path / 'policies.json'
    gos.write_text(json.dumps({'ExtensionInstallForcelist': ['jabjbhgjaidecageckilhonbggakppme;https://clients2.google.com/service/update2/crx'], 'HomepageLocation': 'https://example.org'}))
    before = gos.read_bytes()
    assert inspect(tmp_path)['policy'] == POLICY
    (tmp_path / 'alt-cryptopro-cades.json').write_text(json.dumps(POLICY))
    assert inspect(tmp_path)['policy'] == POLICY
    assert gos.read_bytes() == before


@pytest.mark.parametrize('content', ['null', '[]', '{', '{"HomepageLocation":"https://example.org"}', '{"ExtensionSettings":{},"ExtensionSettings":{}}'])
def test_custom_or_invalid_owned_policy_is_never_replaced(tmp_path, content):
    own = tmp_path / 'alt-cryptopro-cades.json'
    own.write_text(content)
    with pytest.raises(ValueError):
        inspect(tmp_path)
    assert own.read_text() == content


@pytest.mark.parametrize('setting', [{ID: {'installation_mode': 'blocked'}}, {'*': {'installation_mode': 'allowed'}}, {'another': {'installation_mode': 'allowed'}}])
def test_competing_extension_settings_are_not_silently_overwritten(tmp_path, setting):
    path = tmp_path / 'policies.json'
    path.write_text(json.dumps({'ExtensionSettings': setting}))
    before = path.read_bytes()
    with pytest.raises(ValueError, match='ExtensionSettings'):
        inspect(tmp_path)
    assert path.read_bytes() == before


def test_conflicting_same_extension_update_source_is_rejected(tmp_path):
    (tmp_path / 'policies.json').write_text(json.dumps({'ExtensionInstallForcelist': [ID+';https://example.org/update']}))
    with pytest.raises(ValueError):
        inspect(tmp_path)


@pytest.mark.parametrize('problem', ['symlink', 'writable', 'directory'])
def test_unsafe_policy_entries_are_rejected(tmp_path, problem):
    path = tmp_path / 'policies.json'
    if problem == 'symlink':
        target = tmp_path / 'target'
        target.write_text('{}')
        path.symlink_to(target)
    elif problem == 'directory':
        path.mkdir()
    else:
        path.write_text('{}')
        path.chmod(0o666)
    with pytest.raises(ValueError):
        inspect(tmp_path)


def test_missing_directory_is_read_only(tmp_path):
    path = tmp_path / 'absent'
    assert inspect(path)['policy'] == POLICY
    assert not path.exists()


@pytest.mark.parametrize('problem', ['owner', 'directory_mode', 'root_symlink', 'force_list'])
def test_directory_ownership_and_policy_shape_fail_closed(tmp_path, problem):
    m = module()
    root = tmp_path / 'managed'
    root.mkdir()
    if problem == 'root_symlink':
        link = tmp_path / 'link'
        link.symlink_to(root)
        root = link
    elif problem == 'directory_mode':
        root.chmod(0o777)
    elif problem == 'force_list':
        (root / 'policies.json').write_text('{"ExtensionInstallForcelist":null}')
    uid = os.geteuid() + 1 if problem == 'owner' else os.geteuid()
    with pytest.raises(ValueError):
        m.inspect_directory(root, expected_uid=uid)
