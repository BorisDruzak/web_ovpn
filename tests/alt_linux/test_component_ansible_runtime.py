"""Real Ansible against synthetic localhost inputs; never workstation inventory."""
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
from alt_deploy.setup_execution import ComponentExecutor
from alt_deploy.setup_events import SetupEventStore
from test_component_catalog import project, SOURCE
from test_component_setup import component_service
from test_setup_jobs import jobs_fixture


@pytest.fixture
def ansible_runtime(project):
    executable = Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():
        found = shutil.which('ansible-playbook')
        if not found: pytest.skip('Real Ansible runtime is unavailable')
        executable = Path(found)
    # Match checkout layout so a pre-install fixture cannot import old runtime.
    shutil.copytree(SOURCE.parent/'control', project.parent/'control')
    for name in ('playbooks', 'filter_plugins', 'callback_plugins'):
        shutil.copytree(SOURCE/name, project/name)
    shutil.copyfile(SOURCE/'group_vars/all.yml', project/'group_vars/all.yml')
    (project/'group_vars/vault.yml').write_text('vault_cryptopro_license: synthetic-test-license\n')
    # Exercise the published plugin paths without a real Vault credential path.
    config = SOURCE.joinpath('ansible.cfg').read_text()
    (project/'ansible.cfg').write_text('\n'.join(
        line for line in config.splitlines() if not line.startswith('vault_password_file')) + '\n')
    document = yaml.safe_load((project/'group_vars/software_catalog.yml').read_text())
    metadata = {}
    for key, entry in document['software_catalog'].items():
        if entry['source'] == 'alt-repository': continue
        artifact = project/(key+'.synthetic')
        artifact.write_bytes(b'synthetic-artifact-'+key.encode())
        entry['artifact_path'] = str(artifact)
        entry['sha256'] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if entry['source'] == 'rpm':
            metadata[str(artifact)] = '|'.join([entry['package_name'], entry['package_evr'], entry['architecture'], str(entry.get('package_epoch', '(none)'))])
    (project/'group_vars/software_catalog.yml').write_text(yaml.safe_dump(document, sort_keys=False))
    bin_dir = project/'synthetic-bin'
    bin_dir.mkdir()
    rpm = bin_dir/'rpm'
    rpm.write_text('#!'+sys.executable+'\nimport sys\nm='+repr(metadata)+'\nprint(m[sys.argv[-1]])\n')
    rpm.chmod(0o700)
    env = os.environ.copy()
    env['PATH'] = str(bin_dir)+os.pathsep+str(executable.parent)+os.pathsep+env['PATH']
    env['ANSIBLE_CONFIG'] = str(project/'ansible.cfg')
    env['PYTHONPATH'] = str(SOURCE.parent/'control')
    env['ANSIBLE_FILTER_PLUGINS'] = str(project/'filter_plugins')
    return executable, project, env


@pytest.mark.parametrize('playbook', ['03-configure-domain-workstation.yml', '04-setup-component.yml'])
def test_real_ansible_syntax(ansible_runtime, playbook):
    executable, project, env = ansible_runtime
    result = subprocess.run([str(executable), '-i', 'localhost,', '--syntax-check',
        str(project/'playbooks'/playbook)], cwd=project, env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout+result.stderr


@pytest.mark.parametrize('profile,component,failure', [('base', '', ''), ('core-apps', '', ''),
    ('core-apps', 'software.onlyoffice', ''), ('core-apps', 'software.onlyoffice', 'unselected_blank_license'),
    ('core-apps', '', 'missing_artifact'), ('core-apps', '', 'blank_license')])
def test_real_ansible_nonmutating_selected_preflight(ansible_runtime, profile, component, failure):
    executable, project, env = ansible_runtime
    if failure == 'missing_artifact': (project/'gosuslugi_plugin.synthetic').unlink()
    if failure in ('blank_license', 'unselected_blank_license'): (project/'group_vars/vault.yml').write_text('vault_cryptopro_license: ""\n')
    variables = {'software_profile': profile, 'remote_access_profile': 'none', 'setup_component_id': component,
                 'ansible_python_interpreter': sys.executable}
    result = subprocess.run([str(executable), '-i', 'localhost,', '-e', json.dumps(variables),
        str(project/'playbooks/03-setup-controller-preflight.yml')], cwd=project, env=env,
        text=True, capture_output=True, timeout=45)
    assert (result.returncode != 0) == (failure in ('missing_artifact', 'blank_license')), result.stdout+result.stderr
    assert 'changed=0' in result.stdout
    assert 'synthetic-test-license' not in result.stdout+result.stderr


def test_published_filter_loads_from_unrelated_operator_directory(ansible_runtime, tmp_path):
    executable, project, env = ansible_runtime
    env = env.copy()
    env.pop('ANSIBLE_FILTER_PLUGINS', None)
    operator_home = tmp_path / 'operator-home'
    operator_home.mkdir()
    variables = {'software_profile': 'office-standard-v1', 'remote_access_profile': 'none',
                 'ansible_python_interpreter': sys.executable}
    result = subprocess.run([str(executable), '-i', 'localhost,', '-e', json.dumps(variables),
        str(project/'playbooks/03-setup-controller-preflight.yml')], cwd=operator_home, env=env,
        text=True, capture_output=True, timeout=45)
    assert result.returncode == 0, result.stdout+result.stderr
    assert 'changed=0' in result.stdout
    assert 'synthetic-test-license' not in result.stdout+result.stderr


def test_real_callback_never_displays_task_name_or_secret_output(ansible_runtime, component_service):
    executable, project, env = ansible_runtime
    sentinel = 'SENTINEL-NEVER-PUBLIC-TASK-SECRET'
    (project/'roles/software_onlyoffice/tasks/main.yml').write_text(yaml.safe_dump([
        {'name': sentinel, 'ansible.builtin.debug': {'msg': sentinel}, 'no_log': True}]))
    service, setup, *_ = component_service
    # The plan includes the synthetic fixture catalog/source from the outset.
    setup.settings.ansible_project_dir = project
    setup.settings.ansible_playbook_path = executable
    setup.settings.service_user = pwd.getpwuid(os.getuid()).pw_name
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, plan, settings = jobs_fixture(component_service)
    settings.service_user = pwd.getpwuid(os.getuid()).pw_name
    job = jobs.submit(plan, operation='component')
    def local_runner(command, **options):
        command = list(command)
        command[command.index('-i')+1] = 'localhost,'
        command[-1:-1] = ['-e', json.dumps({'ansible_connection': 'local', 'ansible_become': False,
                                          'ansible_python_interpreter': sys.executable})]
        options['env'].update({k: env[k] for k in ('PATH', 'ANSIBLE_FILTER_PLUGINS')})
        return subprocess.run(command, **options)
    result = ComponentExecutor(settings, ComponentCatalog.load(project), runner=local_runner).run(plan, job)
    assert result['status'] == 'applied'
    events = SetupEventStore(settings).read(job.job_id, limit=1000)
    assert events['events'][-1]['type'] == 'component_completed'
    assert sentinel not in json.dumps(events)
    assert sentinel not in (job.job_dir/'ansible.log').read_text()


def test_real_full_callback_attributes_changes_to_catalog_role(ansible_runtime, component_service, monkeypatch):
    from test_setup_detach import full_fixture
    executable, project, env = ansible_runtime
    service, setup, *_ = component_service
    setup.settings.ansible_project_dir = project
    setup.settings.service_user = pwd.getpwuid(os.getuid()).pw_name
    setup, jobs, _, _, _ = full_fixture(component_service, monkeypatch)
    setup.settings.service_user = pwd.getpwuid(os.getuid()).pw_name
    plan = setup.plan(component_service[2].uuid, component_service[3]['login'],
                      setup.approved_ous[0], 'core-apps')
    job = jobs.submit(plan, operation='full_setup')
    sentinel = 'SENTINEL-PRIVATE-FULL-TASK'
    (project/'roles/software_onlyoffice/tasks/main.yml').write_text(yaml.safe_dump([
        {'name': sentinel, 'ansible.builtin.debug': {'msg': sentinel}, 'changed_when': True, 'no_log': True}]))
    play = project/'synthetic-full-callback.yml'
    play.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False,
        'tasks': [{'ansible.builtin.include_role': {'name': 'software_onlyoffice'}}]}]))
    env.update(ANSIBLE_STDOUT_CALLBACK='alt_setup_events',
        ANSIBLE_CALLBACK_PLUGINS=str(project/'callback_plugins'), ALT_DEPLOY_STATE_ROOT=str(setup.settings.state_root),
        ALT_DEPLOY_SERVICE_USER=setup.settings.service_user, ALT_SETUP_JOB_ID=job.job_id,
        ALT_SETUP_COMPONENT_ID='domain.ready', ALT_SETUP_COMPONENT_VERSION='1', ALT_SETUP_FULL_SETUP='true')
    result = subprocess.run([str(executable), '-i', 'localhost,', '-e', 'ansible_connection=local',
        str(play)], cwd=project, env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout+result.stderr
    events = SetupEventStore(setup.settings).read(job.job_id, limit=1000)['events']
    assert any(e['component_id'] == 'software.onlyoffice' and e['changed'] for e in events)
    assert events[-1]['type'] == 'component_completed'
    assert sentinel not in result.stdout+result.stderr+json.dumps(events)
