"""Run the shipped target collector against fixture files and read-command stubs."""
import json
import os
import sys
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'deploy/alt-linux/control'))
from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_probe import desired_queries
from alt_deploy.component_probe_script import collect
from test_component_verification import UUID, CATALOG


def fixture(root, identifier='software.onlyoffice'):
    catalog = ComponentCatalog.load(CATALOG)
    files = {
        'sys/devices/virtual/dmi/id/product_uuid': UUID,
        'proc/sys/kernel/random/boot_id': 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee',
        'etc/os-release': 'ID=altlinux\nVERSION_ID=11.1\nPRETTY_NAME="ALT Workstation K 11.1"\n',
        'usr/bin/onlyoffice-desktopeditors': 'synthetic executable',
    }
    for name, contents in files.items():
        target = root/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents)
        if name.startswith('usr/bin/'):
            target.chmod(0o755)
    query = {'schema_version': 1, 'machine_uuid': UUID, 'hostname': 'alt-a1-pc3',
             'login': 'synthetic.user', 'upn': 'synthetic.user@sosnadmin.local',
             'components': desired_queries(CATALOG, catalog, [catalog.component(identifier)])}
    calls = []
    def call(command):
        calls.append(command)
        if command[0] == 'hostname': return 0, 'alt-a1-pc3'
        if command[0] == 'getent':
            return 0, f"synthetic.user:x:{max(1, os.getuid())}:{max(1, os.getgid())}:Synthetic:/home/synthetic.user:/bin/bash"
        if command[0] == 'ps': return 0, 'COMMAND\npython3' if command[-1] == 'comm' else 'PID COMMAND\n9999 /usr/bin/sshd'
        if command[:2] == ['rpm', '-qa']: return 0, 'rpm\napt'
        if command[0] == 'rpm': return 0, 'onlyoffice-desktopeditors|9.4.0-epm1.repacked.130|x86_64|100'
        if command[0] == 'apt-get': return 0, ''
        raise AssertionError('Unexpected mutation or command')
    return query, call, calls


def tree(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_shipped_package_collector_is_readonly_and_does_not_create_home(tmp_path):
    query, call, calls = fixture(tmp_path)
    before = tree(tmp_path)
    result = collect(query, root=tmp_path, call=call)
    assert result['machine']['os_id'] == 'alt-kworkstation-11'
    assert result['user']['home_exists'] is False
    assert result['user']['home_safe'] is True
    assert result['components']['software.onlyoffice']['packages'] == [{
        'name': 'onlyoffice-desktopeditors', 'evr': '9.4.0-epm1.repacked.130', 'architecture': 'x86_64', 'epoch': 100}]
    assert result['components']['software.onlyoffice']['executable'] is True
    assert before == tree(tmp_path)
    assert not (tmp_path/'home').exists()
    assert all(c[0] in ('hostname', 'getent', 'rpm', 'ps', 'apt-get') for c in calls)
    assert all(c[1] in ('-q', '-qa') for c in calls if c[0] == 'rpm')
    assert all('--simulate' in c and 'Debug::NoLocking=true' in c for c in calls if c[0] == 'apt-get')


def test_normal_linux_dmi_class_symlink_does_not_break_identity(tmp_path):
    query, call, _ = fixture(tmp_path)
    original = tmp_path/'sys/class/dmi/id'
    physical = tmp_path/'sys/devices/virtual/dmi/id'
    original.parent.mkdir(parents=True)
    original.symlink_to('../../devices/virtual/dmi/id', target_is_directory=True)
    assert collect(query, root=tmp_path, call=call)['machine']['uuid'] == UUID


def test_unknown_package_probe_and_process_state_remain_unknown(tmp_path):
    query, original, _ = fixture(tmp_path)
    def call(command):
        if command[0] == 'rpm': raise subprocess.TimeoutExpired(command, 10)
        if command[0] == 'ps': return 1, 'private output not public'
        return original(command)
    result = collect(query, root=tmp_path, call=call)
    fact = result['components']['software.onlyoffice']
    assert fact['error_code'] == 'probe_unavailable'
    assert fact['checks']['ready'] is None
    assert result['package_manager']['processes_absent'] is None
    assert 'private output' not in json.dumps(result)


def test_domain_probe_checks_current_gpo_without_running_gpupdate(tmp_path):
    query, original, calls = fixture(tmp_path, 'domain.ready')
    def call(command):
        calls.append(command)
        if command[0] == 'net': return 0, 'Join is OK'
        if command[0] == 'gpupdate-setup':
            return 0, 'samba' if command[1] == 'active-backend' else 'workstation'
        if command[:2] == ['systemctl', 'is-active']: return 0, 'active'
        if command[:2] == ['systemctl', 'show']:
            return 0, 'Result=success\nExecMainStatus=0\nExecMainStartTimestampMonotonic=10000000'
        return original(command)
    result = collect(query, root=tmp_path, call=call)
    assert result['components']['domain.ready']['checks']['ready'] is True
    assert not any(c[0] in ('gpupdate', 'gpoa', 'reboot') for c in calls)
    assert all(c[1] in ('status', 'active-backend', 'active-policy') for c in calls if c[0] == 'gpupdate-setup')
    assert all(c[-1] == 'testjoin' for c in calls if c[0] == 'net')


def test_wrong_home_ownership_and_symlink_cannot_be_accepted(tmp_path):
    query, call, _ = fixture(tmp_path)
    home = tmp_path/'home/synthetic.user'
    home.parent.mkdir()
    home.symlink_to(tmp_path, target_is_directory=True)
    result = collect(query, root=tmp_path, call=call)
    assert result['user']['home_safe'] is False


def test_current_desktop_keyboard_drift_is_detected(tmp_path):
    from alt_deploy.component_probe_script import desktop_ready
    home = '/home/synthetic'
    query = {'skel': '/etc/skel/.config', 'skel_power': [], 'power': [],
             'desktop': [], 'keyboard': [[['Layout'], 'SwitchMode', 'Global']]}
    skel = tmp_path/'etc/skel/.config'
    user = tmp_path/'home/synthetic/.config'
    skel.mkdir(parents=True)
    user.mkdir(parents=True)
    (skel/'kxkbrc').write_text('[Layout]\nSwitchMode=Global\n')
    (user/'kxkbrc').write_text('[Layout]\nSwitchMode=WinClass\n')
    assert desktop_ready(tmp_path, query, home, os.getuid()) is False


def test_shortcuts_compare_autostart_and_launchers_for_selected_office_profile(tmp_path):
    query, call, _ = fixture(tmp_path, 'desktop.shortcuts')
    catalog = ComponentCatalog.load(CATALOG)
    query['components'] = desired_queries(CATALOG, catalog, [catalog.component('desktop.shortcuts')], profile_id='office-standard-v1')
    recipe = query['components'][0]
    defaults = recipe['defaults']
    home = tmp_path/'home/synthetic.user'
    desktop = home/defaults['desktop_shortcuts_user_desktop_name']
    desktop.mkdir(parents=True)
    applications = tmp_path/defaults['desktop_shortcuts_applications_dir'].lstrip('/')
    applications.mkdir(parents=True)
    for entry in recipe['entries']:
        payload = '[Desktop Entry]\nType=Application\nName='+entry+'\n'
        (applications/entry).write_text(payload)
        target = desktop/entry
        target.write_text(payload)
        target.chmod(0o755)
    autostart = home/'.config/autostart'/defaults['desktop_shortcuts_nextcloud_entry']
    autostart.parent.mkdir(parents=True)
    autostart.write_bytes((applications/defaults['desktop_shortcuts_nextcloud_entry']).read_bytes())
    autostart.chmod(0o644)
    for link in defaults['desktop_shortcuts_relative_links']:
        (desktop/link['name']).symlink_to(link['src'])
    # Match the positive synthetic SSS identity when pytest runs as root.
    if os.getuid() == 0:
        for target in (home, *home.rglob('*')):
            os.chown(target, max(1, os.getuid()), max(1, os.getgid()), follow_symlinks=False)
    assert collect(query, root=tmp_path, call=call)['components']['desktop.shortcuts']['checks']['ready'] is True
    autostart.write_text('[Desktop Entry]\nExec=false\n')
    assert collect(query, root=tmp_path, call=call)['components']['desktop.shortcuts']['checks']['ready'] is False
    assert not (desktop/'cptools.desktop').exists()
