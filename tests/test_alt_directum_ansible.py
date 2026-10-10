from pathlib import Path

import pytest
import yaml
from jinja2.nativetypes import NativeEnvironment

from test_alt_component_preflight_contract import preflight

ROOT = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible'


def test_directum_catalog_pins_approved_rpm():
    catalog = yaml.safe_load((ROOT / 'group_vars/software_catalog.yml').read_text())['software_catalog']
    assert catalog['directum'] == {
        'enabled': True, 'source': 'rpm',
        'artifact_path': '/opt/alt-deploy-control/artifacts/directum/WebAccessAgent-6.0.3-1010.x86_64.rpm',
        'sha256': 'f028c1390e2277def97352a19cd610e13933fe0be569755909c7f512f738bec3',
        'package_name': 'WebAccessAgent', 'package_evr': '6.0.3-1010',
        'architecture': 'x86_64', 'executable': '/usr/webaccessagent/Launcher',
    }


@pytest.mark.parametrize('metadata', [
    'WebAccessAgent|6.0.3-1010|x86_64|1',
    'WebAccessAgent|6.0.3-1010|aarch64|(none)',
    'WebAccessAgent|other|x86_64|(none)',
    'other|6.0.3-1010|x86_64|(none)',
])
def test_bad_directum_rpm_stops_aggregate_preflight(metadata):
    catalog = yaml.safe_load((ROOT / 'group_vars/software_catalog.yml').read_text())['software_catalog']
    with pytest.raises(AssertionError):
        preflight(catalog, metadata={'directum': metadata})


@pytest.mark.parametrize('field,value', [
    ('enabled', False), ('package_name', 'other'), ('package_evr', 'other'),
    ('architecture', 'aarch64'), ('artifact_path', '/tmp/unapproved.rpm'),
    ('executable', '/bin/sh'), ('package_epoch', 1),
])
def test_bad_directum_catalog_stops_aggregate_preflight(field, value):
    catalog = yaml.safe_load((ROOT / 'group_vars/software_catalog.yml').read_text())['software_catalog']
    catalog['directum'][field] = value
    with pytest.raises(AssertionError):
        preflight(catalog)


@pytest.mark.parametrize('rc,identity,needed', [
    (0, 'WebAccessAgent|6.0.3-1010|x86_64|(none)', False),
    (0, 'WebAccessAgent|6.0.2-1000|x86_64|(none)', True),
    (1, '', True),
])
def test_matching_installed_directum_skips_transfer_and_install(rc, identity, needed):
    tasks = yaml.safe_load((ROOT / 'roles/software_directum/tasks/main.yml').read_text())
    block = tasks[1]['block']
    decision = next(t for t in block if t['name'] == 'Decide whether Directum installation is needed')
    context = {
        'software_directum_current_metadata': {'rc': rc, 'stdout': identity},
        'software_directum_controller_metadata': {'stdout': 'WebAccessAgent|6.0.3-1010|x86_64|(none)'},
    }
    expression = decision['ansible.builtin.set_fact']['software_directum_install_needed']
    assert NativeEnvironment().from_string(expression).render(**context) is needed
    for task in block:
        if any(k in task for k in ('ansible.builtin.tempfile', 'ansible.builtin.copy')) or task.get(
                'ansible.builtin.command', {}).get('argv', [])[:3] == ['apt-get', '-y', 'install']:
            assert task['when'] == 'software_directum_install_needed'
    assert any(t.get('ansible.builtin.stat', {}).get('path') == '/etc/xdg/autostart/WebAccessAgent.desktop'
               for t in block)
