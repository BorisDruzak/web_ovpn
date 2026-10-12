"""Regression gates for the ordinary clean-VM Setup path."""
from pathlib import Path
import shlex

import yaml

ROOT = Path(__file__).resolve().parents[1] / 'deploy/alt-linux'


def test_bootstrap_checks_elevation_as_the_ansible_user():
    source = (ROOT / 'bootstrap/bootstrap.sh').read_text(encoding='utf-8')
    command = next(line for line in source.splitlines()
                   if line.startswith('if ! ') and ' true; then' in line)
    args = shlex.split(command.removeprefix('if ! ').removesuffix('; then'))
    assert args == ['runuser', '-u', '${ANSIBLE_USER}', '--', 'sudo', '-n', 'true']


def test_core_apps_includes_shortcuts_after_software_before_final_verification():
    phase = yaml.safe_load((ROOT / 'ansible/playbooks/tasks/configure_critical_phase.yml').read_text())
    block = phase[1]['block']
    roles = [t['ansible.builtin.include_role']['name'] for t in block
             if 'ansible.builtin.include_role' in t]
    assert roles.index('standard_software') < roles.index('desktop_shortcuts') < roles.index('domain_verify')
    shortcuts = next(t for t in block if t.get('ansible.builtin.include_role', {}).get('name') == 'desktop_shortcuts')
    assert shortcuts['when'] == "software_profile == 'core-apps'"


def test_shortcuts_report_verified_and_deferred_home_separately():
    tasks = yaml.safe_load((ROOT / 'ansible/roles/desktop_shortcuts/tasks/main.yml').read_text())
    final = tasks[-1]['ansible.builtin.set_fact']
    assert final['desktop_shortcuts_verified'] is True
    assert 'desktop_shortcuts_home_deferred' in final
    assert "'desktop_shortcuts'" in final['configure_result']


def test_signature_suite_configures_browser_extension_and_native_host():
    tasks = yaml.safe_load((ROOT / 'ansible/roles/software_gosuslugi_plugin/tasks/main.yml').read_text(encoding='utf-8'))
    copies = [t['ansible.builtin.copy'] for t in tasks if 'ansible.builtin.copy' in t]
    policy = next(item for item in copies if item.get('dest') == '/etc/opt/yandex/browser/policies/managed/alt-signature-suite.json')
    import json
    settings = json.loads(policy['content'])
    assert settings['ExtensionInstallForcelist'] == [
        'jabjbhgjaidecageckilhonbggakppme;https://clients2.google.com/service/update2/crx',
        'iifchhfnnmpdbibifmljnfjhpififfog;https://clients2.google.com/service/update2/crx']
    hosts = next(item for item in copies if item.get('dest') == '/etc/chromium/native-messaging-hosts/{{ item }}')
    assert hosts['remote_src'] is True


def test_manifest_check_parses_json_and_checks_exact_launcher():
    tasks = yaml.safe_load((ROOT / 'ansible/roles/software_gosuslugi_plugin/tasks/main.yml').read_text(encoding='utf-8'))
    gate = next(t for t in tasks if t['name'] == 'Require ГосПлагин browser integration')
    assert any('from_json).path ==' in expression for expression in gate['ansible.builtin.assert']['that'])


def test_missing_or_non_executable_native_launcher_cannot_be_verified():
    import base64
    import json
    from jinja2.nativetypes import NativeEnvironment
    tasks = yaml.safe_load((ROOT / 'ansible/roles/software_gosuslugi_plugin/tasks/main.yml').read_text(encoding='utf-8'))
    gate = next(t for t in tasks if t['name'] == 'Require ГосПлагин browser integration')
    env = NativeEnvironment()
    env.filters['b64decode'] = lambda value: base64.b64decode(value).decode()
    env.filters['from_json'] = json.loads
    host = '/opt/iitrust/gosuslugi_plugin/bin/gosuslugi_plugin'
    manifest = {'name': 'chrome.gosuslugi.plugin', 'type': 'stdio', 'path': host+'.sh',
                'allowed_origins': ['chrome-extension://jabjbhgjaidecageckilhonbggakppme/']}
    for launcher, expected in [({'exists': False, 'isreg': False, 'executable': False}, False),
                               ({'exists': True, 'isreg': True, 'executable': False}, False),
                               ({'exists': True, 'isreg': True, 'executable': True}, True)]:
        values = {'software_gosuslugi_plugin_native_host': host,
                  'software_gosuslugi_plugin_native_host_stat': {'stat': {'exists': True, 'isreg': True, 'executable': True}},
                  'software_gosuslugi_plugin_launcher_stat': {'stat': launcher},
                  'software_gosuslugi_plugin_manifest': {'content': base64.b64encode(json.dumps(manifest).encode()).decode()}}
        result = all(env.from_string('{{ '+expression+' }}').render(**values) is True
                     for expression in gate['ansible.builtin.assert']['that'])
        assert result is expected


def test_all_existing_desktop_destinations_are_inspected_before_copy():
    import re
    from jinja2.nativetypes import NativeEnvironment
    tasks = yaml.safe_load((ROOT / 'ansible/roles/desktop_shortcuts/tasks/main.yml').read_text(encoding='utf-8'))
    inspection = next(t for t in tasks if t['name'] == 'Inspect existing profile destinations before the first home write')
    env = NativeEnvironment()
    env.filters['regex_replace'] = lambda value, pattern, replacement: re.sub(pattern, replacement, value)
    result = env.from_string(inspection['loop']).render(desktop_shortcuts_user_desktop_name='Desktop',
                desktop_shortcuts_nextcloud_entry='nextcloud.desktop', desktop_shortcuts_application_entries=['office.desktop', 'browser.desktop'])
    assert result == ['Desktop', '.config', '.config/autostart', '.config/autostart/nextcloud.desktop',
                      'Desktop/office.desktop', 'Desktop/browser.desktop']
    assert inspection['ansible.builtin.stat']['follow'] is False
    names = [t['name'] for t in tasks]
    assert names.index('Refuse symlinked or foreign-owned profile destinations') < names.index('Copy application launchers into existing domain test user desktop')
