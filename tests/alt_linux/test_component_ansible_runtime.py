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


@pytest.mark.parametrize('profile, selected', [
    ('base', False), ('core-apps', True),
    ('office-standard-v1', True), ('office-signature-v1', True),
])
def test_full_setup_shortcuts_use_preflight_catalog_selection(ansible_runtime, profile, selected):
    executable, project, env = ansible_runtime
    preflight = yaml.safe_load((project/'playbooks/tasks/configure_component_preflight.yml').read_text())
    critical = yaml.safe_load((project/'playbooks/tasks/configure_critical_phase.yml').read_text())
    block = next(task['block'] for task in critical if 'block' in task)
    shortcuts = next(task for task in block
                     if task.get('ansible.builtin.include_role', {}).get('name') == 'desktop_shortcuts')
    marker = 'SYNTHETIC-SHORTCUTS-ROLE-SELECTED'
    (project/'roles/desktop_shortcuts/tasks/main.yml').write_text(yaml.safe_dump([
        {'ansible.builtin.debug': {'msg': marker}}]))
    play = project/'playbooks/synthetic-shortcuts-selection.yml'
    play.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False,
        'tasks': preflight[:2] + [shortcuts]}]))
    variables = {'software_profile': profile, 'ansible_connection': 'local',
                 'ansible_become': False, 'ansible_python_interpreter': sys.executable}
    result = subprocess.run([str(executable), '-i', 'localhost,', '-e', json.dumps(variables),
        str(play)], cwd=project, env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout+result.stderr
    assert (marker in result.stdout) is selected
    assert 'changed=0' in result.stdout


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


def test_real_callback_exports_bound_diagnostic_outside_secret_block(ansible_runtime, component_service, monkeypatch):
    from test_setup_detach import full_fixture
    executable, project, env = ansible_runtime
    _, setup, *_ = component_service
    setup.settings.ansible_project_dir = project
    setup.settings.service_user = pwd.getpwuid(os.getuid()).pw_name
    setup, jobs, _, _, _ = full_fixture(component_service, monkeypatch)
    plan = setup.plan(component_service[2].uuid, component_service[3]['login'], setup.approved_ous[0], 'core-apps')
    job = jobs.submit(plan, operation='full_setup')
    binding = {'schema_version': 1, 'configuration_run_id': 'a'*32,
               'invocation_id': 'b'*32, 'identity_sha256': 'c'*64}
    public = {**binding, 'phase': 'native_execution', 'code': 'first_join_native_access_denied',
              'directory_effect': 'returned_failure'}
    argv = ['/usr/bin/python3', '-I', '/usr/local/libexec/alt-first-join.py', '--read-diagnostic', json.dumps(binding)]
    library = project/'library'
    library.mkdir()
    # Model only the remote reader result; run the real Ansible callback/store.
    (library/'fixture_diagnostic.py').write_text(
        'from ansible.module_utils.basic import AnsibleModule\n'
        'm=AnsibleModule(argument_spec={})\n'
        'm.exit_json(changed=False, stdout='+repr(json.dumps(public))+', cmd='+repr(argv)+')\n')
    sentinel = 'SENTINEL-SECRET-NATIVE-FAILURE'
    (project/'roles/domain_join/tasks/main.yml').write_text(yaml.safe_dump([{
        'block': [{'ansible.builtin.fail': {'msg': sentinel}}],
        'always': [{'fixture_diagnostic': {}, 'no_log': False,
                    'tags': ['alt_setup_domain_join', 'alt_setup_first_join_diagnostic']}],
        'no_log': True}]))
    play = project/'synthetic-first-join-callback.yml'
    play.write_text(yaml.safe_dump([{'hosts': 'localhost', 'gather_facts': False,
        'tasks': [{'ansible.builtin.include_role': {'name': 'domain_join'}}]}]))
    env.update(ANSIBLE_STDOUT_CALLBACK='alt_setup_events', ANSIBLE_LIBRARY=str(library),
        ANSIBLE_CALLBACK_PLUGINS=str(project/'callback_plugins'), ALT_DEPLOY_STATE_ROOT=str(setup.settings.state_root),
        ALT_DEPLOY_SERVICE_USER=setup.settings.service_user, ALT_SETUP_JOB_ID=job.job_id,
        ALT_SETUP_COMPONENT_ID='domain.ready', ALT_SETUP_COMPONENT_VERSION='1', ALT_SETUP_FULL_SETUP='true',
        ALT_SETUP_FIRST_JOIN_BINDING=json.dumps(binding))
    result = subprocess.run([str(executable), '-i', 'localhost,', '-e', json.dumps({
        'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable}), str(play)],
        cwd=project, env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 2, result.stdout+result.stderr
    events = SetupEventStore(setup.settings).read(job.job_id, limit=1000)['events']
    specific = [e for e in events if e['code'] == 'first_join_native_access_denied']
    assert len(specific) == 1 and specific[0]['type'] == 'task_failed'
    assert specific[0]['component_id'] == 'domain.ready'
    assert sentinel not in result.stdout+result.stderr+json.dumps(events)
