"""VK identity and installation budget; never touch a real package manager."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys

import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.errors import ControlError
from test_component_catalog import SOURCE, project
from test_component_setup import component_service
from test_component_verification import UUID

DOWNLOAD = 377133320
INSTALLED = 1164975020
RESERVE = 536870912


def storage(opt_free=10**10, staging_free=10**10, *, shared=True):
    return {'opt': {'device': 11, 'available_bytes': opt_free},
            'staging': {'device': 11 if shared else 12, 'available_bytes': staging_free}}


def test_vk_manifest_and_legacy_profiles_are_preserved():
    catalog = ComponentCatalog.load(SOURCE)
    component = catalog.component('software.vkworkspace')
    assert component['execution']['role'] == 'software_vkworkspace'
    assert component['execution']['retry_policy'] == 'idempotent'
    assert component['verification']['functional_verification_required'] is True
    artifact = catalog.artifact('software.vkworkspace')
    assert artifact == {
        'enabled': True, 'source': 'rpm',
        'artifact_path': '/opt/alt-deploy-control/artifacts/vkworkspace/vkworkspace.rpm',
        'sha256': '386b314d8a31ec06330e60ea842268304c98e39be343fb95ea5907a8d896cdc9',
        'package_name': 'vkworkspace', 'package_evr': '26.4.0.141207-1.el8',
        'architecture': 'x86_64', 'executable': '/opt/vkworkspace/vkworkspace',
        'desktop_entry': '/usr/share/applications/vkworkspace.desktop',
        'download_size_bytes': DOWNLOAD, 'installed_size_bytes': INSTALLED}
    # All four published legacy declarations remain byte-equivalent as JSON.
    original = yaml.safe_load(SOURCE.joinpath('group_vars/software_catalog.yml').read_text())
    legacy = [p for p in original['setup_catalog']['profiles'] if p['id'] != 'workstation-full-v1']
    assert len(legacy) == 4
    assert hashlib.sha256(json.dumps(legacy, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == \
        '6dd71b909ed4b17939b488a4e63340118b822340592d1d7cfc82ae49d761044f'
    assert all('software.vkworkspace' not in p['components'] for p in legacy)
    defaults = yaml.safe_load(SOURCE.joinpath('roles/desktop_shortcuts/defaults/main.yml').read_text())
    assert defaults['desktop_shortcuts_component_entries']['software.vkworkspace'] == 'vkworkspace.desktop'


@pytest.mark.parametrize('shared', [True, False])
@pytest.mark.parametrize('short', [False, True])
def test_space_budget_checks_each_filesystem(shared, short):
    from alt_deploy.component_storage import installation_budget
    artifact = ComponentCatalog.load(SOURCE).artifact('software.vkworkspace')
    opt = INSTALLED + RESERVE + (DOWNLOAD if shared else 0)
    stage = opt if shared else DOWNLOAD + RESERVE
    result = installation_budget(artifact, storage(opt-int(short), stage, shared=shared))
    assert result['ready'] is (not short)
    assert result.get('error_code') == ('component_install_space_insufficient' if short else None)
    if not shared:
        assert installation_budget(artifact, storage(opt, stage-1, shared=False))['ready'] is False


@pytest.mark.parametrize('bad', [None, {}, True, {'opt': {}},
    {'opt': {'device': True, 'available_bytes': 10**10}, 'staging': {'device': 11, 'available_bytes': 10**10}},
    {'opt': {'device': 11, 'available_bytes': -1}, 'staging': {'device': 11, 'available_bytes': 10**10}}])
def test_missing_or_ambiguous_storage_does_not_admit_install(bad):
    from alt_deploy.component_storage import installation_budget
    artifact = ComponentCatalog.load(SOURCE).artifact('software.vkworkspace')
    assert installation_budget(artifact, bad) == {'ready': False, 'error_code': 'component_install_space_unverified'}


@pytest.mark.parametrize('value', [True, 0, -1, 2**63, '377133320', 1.5])
def test_catalog_rejects_invalid_artifact_sizes(project, value):
    path = project/'group_vars/software_catalog.yml'
    document = yaml.safe_load(path.read_text())
    document['software_catalog']['vkworkspace']['download_size_bytes'] = value
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    with pytest.raises(ControlError):
        ComponentCatalog.load(project)


def test_component_plan_blocks_missing_disk_evidence_but_noop_ignores_it(component_service):
    service, _, _, _, observed, _, _ = component_service
    fact = observed['components']['software.vkworkspace']
    preflight_calls = []
    service.preflight = lambda c: preflight_calls.append(c['id']) or {'ready': True}
    assert service.plan(UUID, 'software.vkworkspace')['payload']['action'] == 'noop'
    assert preflight_calls == []
    fact.update(packages=[], executable=False)
    plan = service.plan(UUID, 'software.vkworkspace')['payload']
    assert plan['action'] == 'blocked'
    assert plan['preflight']['error_code'] == 'component_install_space_unverified'
    fact['storage'] = storage()
    assert service.plan(UUID, 'software.vkworkspace')['payload']['action'] == 'install'
    fact['storage'] = storage(0, 0)
    assert service.plan(UUID, 'software.vkworkspace')['payload']['action'] == 'blocked'


def test_space_fluctuation_above_budget_is_not_plan_drift_but_loss_or_remount_is(component_service):
    service, _, _, _, observed, _, _ = component_service
    fact = observed['components']['software.vkworkspace']
    fact.update(packages=[], executable=False, storage=storage())
    plan = service.plan(UUID, 'software.vkworkspace')
    fact['storage'] = storage(10**10-4096, 10**10-8192)
    assert service.validate(plan['plan_id'], plan['sha256'])['action'] == 'install'
    fact['storage'] = storage(0, 0)
    with pytest.raises(ControlError):
        service.validate(plan['plan_id'], plan['sha256'])
    fact['storage'] = storage(shared=False)
    with pytest.raises(ControlError):
        service.validate(plan['plan_id'], plan['sha256'])


@pytest.mark.parametrize('identifier', ['software.vkworkspace', 'software.onlyoffice'])
def test_unknown_package_fact_blocks_without_changing_legacy_projection(component_service, identifier):
    service, _, _, _, observed, _, _ = component_service
    observed['components'][identifier] = None
    payload = service.plan(UUID, identifier)['payload']
    assert payload['action'] == 'blocked'
    assert payload['observed']['components'][identifier] is None


def test_native_collector_carries_space_separately_from_installed_readiness(tmp_path):
    from alt_deploy.component_probe_script import inspect_component
    catalog = ComponentCatalog.load(SOURCE)
    artifact = catalog.artifact('software.vkworkspace')
    for name in ('opt/vkworkspace/vkworkspace', 'usr/share/applications/vkworkspace.desktop'):
        p = tmp_path/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('synthetic package file')
        p.chmod(0o755)
    (tmp_path/'var/tmp').mkdir(parents=True)
    calls = []
    def call(args):
        calls.append(args)
        if args[:2] == ['rpm', '-qf']:
            return 0, 'vkworkspace'
        return 0, 'vkworkspace|26.4.0.141207-1.el8|x86_64|(none)'
    result = inspect_component(tmp_path, {'id': 'software.vkworkspace', 'recipe': 'package',
        'artifact': artifact, 'services': []}, {}, '', '', call)
    assert result['checks']['ready'] is True
    assert result['storage']['opt']['device'] == result['storage']['staging']['device']
    assert type(result['storage']['opt']['available_bytes']) is int
    assert ['rpm', '-qf', '--queryformat', '%{NAME}', str(tmp_path/'usr/share/applications/vkworkspace.desktop')] in calls
    shutil.rmtree(tmp_path/'var')
    again = inspect_component(tmp_path, {'id':'software.vkworkspace', 'recipe':'package',
        'artifact':artifact, 'services':[]}, {}, '', '', call)
    assert again['checks']['ready'] is True and again['storage'] is None
    (tmp_path/'usr/share/applications/vkworkspace.desktop').unlink()
    assert inspect_component(tmp_path, {'id':'software.vkworkspace', 'recipe':'package',
        'artifact':artifact, 'services':[]}, {}, '', '', call)['checks']['ready'] is False


@pytest.mark.parametrize('case', ['install', 'noop', 'corrupt', 'symlink', 'metadata', 'space', 'failure'])
def test_real_ansible_vk_role_preserves_data_and_never_reinstalls_noop(tmp_path, case):
    executable = Path(sys.executable).with_name('ansible-playbook')
    if not executable.exists():
        pytest.skip('Pinned real Ansible is unavailable')
    root = tmp_path/'target'
    for folder in ('opt/vkworkspace', 'usr/share/applications', 'var/tmp', 'home/employee/.config/vkworkspace'):
        (root/folder).mkdir(parents=True, exist_ok=True)
    data = root/'home/employee/.config/vkworkspace/session'
    data.write_bytes(b'USER-DATA-MUST-SURVIVE')
    sentinel = 'PRIVATE-RUNTIME-SENTINEL'
    package = tmp_path/'approved.rpm'
    package.write_bytes(b'synthetic-approved-rpm')
    sha = hashlib.sha256(package.read_bytes()).hexdigest()
    state = tmp_path/'installed'
    transaction_log = tmp_path/'transactions'
    binary = root/'opt/vkworkspace/vkworkspace'
    launcher = root/'usr/share/applications/vkworkspace.desktop'
    if case == 'noop':
        state.touch()
        binary.write_text('package executable'); binary.chmod(0o755)
        launcher.write_text('package launcher')
    bindir = tmp_path/'bin'; bindir.mkdir()
    rpm = bindir/'rpm'
    rpm.write_text('#!'+sys.executable+'\n'+
        'import pathlib,sys\n'+
        'args=sys.argv[1:]\n'+
        'installed=pathlib.Path('+repr(str(state))+').exists()\n'+
        "if '-qp' not in args and not installed: raise SystemExit(1)\n"+
        "if '-qf' in args: print('vkworkspace'); raise SystemExit(0)\n"+
        "print('vkworkspace|"+('99-invalid' if case == 'metadata' else '26.4.0.141207-1.el8')+"|x86_64|(none)')\n")
    rpm.chmod(0o700)
    apt = bindir/'apt-get'
    apt.write_text('#!'+sys.executable+'\nimport pathlib,sys\n'+
        'print('+repr(sentinel)+')\n'+
        'pathlib.Path('+repr(str(transaction_log))+').write_text("install")\n'+
        ('raise SystemExit(7)\n' if case == 'failure' else '')+
        'pathlib.Path('+repr(str(state))+').touch()\n'+
        'p=pathlib.Path('+repr(str(binary))+');p.write_text("package executable");p.chmod(0o755)\n'+
        'pathlib.Path('+repr(str(launcher))+').write_text("package launcher")\n')
    apt.chmod(0o700)
    role = tmp_path/'roles/software_vkworkspace/tasks'; role.mkdir(parents=True)
    source = SOURCE.joinpath('roles/software_vkworkspace/tasks/main.yml').read_text()
    # Rewrite fixed destinations solely in the isolated copied role. No real
    # inventory, package manager, workstation home, Vault or system path is used.
    original_artifact = '/opt/alt-deploy-control/artifacts/vkworkspace/vkworkspace.rpm'
    source = source.replace(original_artifact, str(package))
    source = source.replace('386b314d8a31ec06330e60ea842268304c98e39be343fb95ea5907a8d896cdc9', sha)
    source = source.replace('/usr/share/applications/vkworkspace.desktop', str(launcher))
    source = source.replace('/opt/vkworkspace/vkworkspace', str(binary))
    source = source.replace('/var/tmp', str(root/'var/tmp'))
    # Preserve real live free-space measurement, but permit a reproducible low
    # space injection before the transaction on the fixture filesystem only.
    source = source.replace("'/opt'", repr(str(root/'opt')))
    tasks = yaml.safe_load(source)
    def patch(tasks):
        for task in tasks:
            if 'ansible.builtin.copy' in task:
                task['ansible.builtin.copy']['owner'] = pwd.getpwuid(os.getuid()).pw_name
                task['ansible.builtin.copy'].pop('group', None)
            command = task.get('ansible.builtin.command', {}).get('argv')
            if command and command[0] == '/usr/bin/python3':
                command[0] = sys.executable
                if case == 'space':
                    command[2] = 'print(\'[{"device":11,"free":0},{"device":11,"free":0}]\')'
            for key in ('block', 'always', 'rescue'):
                patch(task.get(key, []))
    patch(tasks)
    (role/'main.yml').write_text(yaml.safe_dump(tasks, sort_keys=False))
    artifact = ComponentCatalog.load(SOURCE).artifact('software.vkworkspace')
    artifact.update(artifact_path=str(package), sha256=sha, executable=str(binary), desktop_entry=str(launcher))
    if case == 'corrupt': package.write_bytes(b'corrupt-after-review')
    if case == 'symlink':
        actual = tmp_path/'real.rpm'; package.rename(actual); package.symlink_to(actual)
    play = tmp_path/'play.yml'
    play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':{
        'software_catalog':{'vkworkspace':artifact}, 'selected_software_components':['vkworkspace'],
        'configure_component_preflight_passed':True,
        'configure_result':{'components':{},'verification':{}},
        'ansible_connection':'local','ansible_become':False,
        'ansible_python_interpreter':sys.executable,'private_sentinel':sentinel},
        'roles':['software_vkworkspace']}], sort_keys=False))
    env = dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'])
    env['ANSIBLE_CONFIG'] = str(tmp_path/'ansible.cfg')
    Path(env['ANSIBLE_CONFIG']).write_text('[defaults]\nretry_files_enabled=False\n')
    result = subprocess.run([str(executable),'-i','localhost,',str(play)], cwd=tmp_path,
                            env=env,text=True,capture_output=True,timeout=60)
    successful = case in ('install', 'noop')
    assert (result.returncode == 0) is successful, result.stdout+result.stderr
    assert transaction_log.exists() is (case in ('install', 'failure'))
    assert data.read_bytes() == b'USER-DATA-MUST-SURVIVE'
    assert list(root.joinpath('var/tmp').iterdir()) == []
    assert sentinel not in result.stdout+result.stderr
    if case == 'noop': assert 'changed=0' in result.stdout
    if case == 'install':
        before_transaction = transaction_log.stat().st_mtime_ns
        again = subprocess.run([str(executable), '-i', 'localhost,', str(play)], cwd=tmp_path,
                               env=env, text=True, capture_output=True, timeout=60)
        assert again.returncode == 0, again.stdout+again.stderr
        assert 'changed=0' in again.stdout
        assert transaction_log.stat().st_mtime_ns == before_transaction
        assert data.read_bytes() == b'USER-DATA-MUST-SURVIVE'


@pytest.mark.parametrize('state', ['valid', 'corrupt', 'symlink', 'parent_symlink'])
def test_component_artifact_preflight_rejects_corruption_and_links(component_service, tmp_path, state):
    from types import SimpleNamespace
    service, *_ = component_service
    component = ComponentCatalog.load(SOURCE).component('software.vkworkspace')
    parent = tmp_path/'artifacts'; parent.mkdir()
    payload = parent/'vkworkspace.rpm'; payload.write_bytes(b'pinned-synthetic')
    artifact = ComponentCatalog.load(SOURCE).artifact('software.vkworkspace')
    artifact.update(artifact_path=str(payload), sha256=hashlib.sha256(payload.read_bytes()).hexdigest())
    if state == 'corrupt': payload.write_bytes(b'different')
    elif state == 'symlink':
        actual = parent/'other.rpm'; payload.rename(actual); payload.symlink_to(actual)
    elif state == 'parent_symlink':
        real = tmp_path/'actual'; parent.rename(real); parent.symlink_to(real, target_is_directory=True)
    service.catalog = SimpleNamespace(artifact=lambda *a: artifact)
    result = service._preflight(component)
    assert result == ({'ready': True} if state == 'valid' else
                      {'ready': False, 'error_code': 'component_artifact_unverified'})


def test_full_setup_checks_install_space_and_binds_only_budget(component_service, monkeypatch):
    from test_component_catalog import edit
    from test_setup_detach import full_fixture
    from test_setup_service import OU
    service, setup, _, user, observed, _, _ = component_service
    # A synthetic profile selection exercises the future full-preset boundary
    # without changing any published legacy profile declaration.
    def select(catalog):
        next(p for p in catalog['profiles'] if p['id']=='core-apps')['components'].append('software.vkworkspace')
    edit(setup.settings.ansible_project_dir, select)
    setup, *_ = full_fixture(component_service, monkeypatch)
    fact = observed['components']['software.vkworkspace']
    plan = setup.plan(UUID, user['login'], OU, 'core-apps')
    assert 'storage' not in plan['payload']['component_observed']['components']['software.vkworkspace']
    fact.update(packages=[], executable=False)
    with pytest.raises(ControlError) as caught:
        setup.plan(UUID, user['login'], OU, 'core-apps')
    assert caught.value.code == 'component_install_space_unverified'
    fact['storage'] = storage(0, 0)
    with pytest.raises(ControlError) as caught:
        setup.plan(UUID, user['login'], OU, 'core-apps')
    assert caught.value.code == 'component_install_space_insufficient'
    fact['storage'] = storage()
    before = setup.plan(UUID, user['login'], OU, 'core-apps')['payload']
    fact['storage'] = storage(10**10-4096, 10**10-8192)
    after = setup.plan(UUID, user['login'], OU, 'core-apps')['payload']
    assert before == after
