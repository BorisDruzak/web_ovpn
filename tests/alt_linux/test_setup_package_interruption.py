"""Package retries require fresh target health and a newly confirmed plan."""
import copy
import json
from pathlib import Path

import pytest
import yaml

from alt_deploy.component_probe_script import package_health
from alt_deploy.errors import ControlError
from alt_deploy.setup_execution import SetupExecutionEngine
from alt_deploy.setup_events import SetupEventStore, safe_task_event
from alt_deploy.setup_plans import private_read
from test_component_setup import component_service
from test_component_catalog import project, SOURCE
from test_setup_execution import claimed, engine_for


@pytest.mark.parametrize('components', ['classic', 'classic gostcrypto'])
def test_package_source_simulation_and_budget_are_readonly(tmp_path, components):
    sources = tmp_path/'etc/apt/sources.list'
    sources.parent.mkdir(parents=True)
    sources.write_text('rpm [p11] https://download.basealt.ru/pub/distributions/ALTLinux p11/branch/x86_64 '+components+'\n')
    sources.chmod(0o644)
    calls = []
    def call(command):
        calls.append(command)
        if command[0] == 'ps':
            return 0, 'COMMAND\npython3' if command[-1] == 'comm' else 'PID COMMAND\n9999 /usr/bin/sshd'
        if command[0] == 'rpm': return 0, 'rpm\napt'
        if command[-1] == 'check': return 0, 'Reading Package Lists... Done'
        return 0, 'Inst nextcloud-client (3.17-alt1 p11)\nRemv obsolete-package [1.0-alt1]'
    before = sources.read_bytes()
    result = package_health(tmp_path, [{'id': 'software.nextcloud', 'recipe': 'package',
                            'artifact': {'source': 'alt-repository', 'packages': ['nextcloud-client']}}], call)
    assert all(result[k] is True for k in ('processes_absent', 'remote_execution_absent',
                                         'locks_clear', 'database_readable', 'dependencies_healthy'))
    assert result['source']['status'] == 'approved_p11'
    assert result['simulation']['software.nextcloud'] == {'status': 'available',
        'install': ['nextcloud-client'], 'remove': ['obsolete-package']}
    assert sources.read_bytes() == before
    assert all('--simulate' in c and 'Debug::NoLocking=true' in c for c in calls if c[0] == 'apt-get')


@pytest.mark.parametrize('fault', ['process', 'remote', 'database', 'dependency', 'source', 'simulation'])
def test_package_unknown_or_busy_is_never_invented_healthy(tmp_path, fault):
    sources = tmp_path/'etc/apt/sources.list'
    sources.parent.mkdir(parents=True)
    sources.write_text('rpm [p11] https://download.basealt.ru/pub/distributions/ALTLinux p11/branch/x86_64 classic\n')
    sources.chmod(0o644)
    def call(command):
        if command[0] == 'ps':
            if command[-1] == 'comm': return 0, 'COMMAND\n'+('apt-get' if fault == 'process' else 'sshd')
            return 0, 'PID COMMAND\n9999 '+('/usr/bin/python3 /tmp/AnsiballZ_command.py' if fault == 'remote' else '/usr/bin/sshd')
        if command[0] == 'rpm': return (1, '') if fault == 'database' else (0, 'rpm')
        if command[-1] == 'check': return (1, '') if fault == 'dependency' else (0, 'healthy')
        return (1, '') if fault == 'simulation' else (0, 'Inst nextcloud-client (3.17-alt1)')
    if fault == 'source': sources.write_text('rpm https://user:SENTINEL@unknown.invalid p11/branch/x86_64 classic\n')
    result = package_health(tmp_path, [{'id': 'software.nextcloud', 'recipe': 'package',
                            'artifact': {'source': 'alt-repository', 'packages': ['nextcloud-client']}}], call)
    key = {'process': 'processes_absent', 'remote': 'remote_execution_absent',
           'database': 'database_readable', 'dependency': 'dependencies_healthy'}.get(fault)
    if key: assert result[key] is not True
    if fault == 'source': assert result['source']['status'] == 'unknown'
    if fault == 'simulation': assert result['simulation']['software.nextcloud']['status'] == 'unavailable'
    assert 'SENTINEL' not in json.dumps(result)


@pytest.mark.parametrize('branch,components', [
    ('x86_64', 'classic gostcrypto untrusted'), ('x86_64', 'classic debuginfo'),
    ('x86_64', 'gostcrypto'), ('noarch', 'classic gostcrypto'),
    ('x86_64-i586', 'classic gostcrypto'), ('x86_64', 'classic classic'),
])
def test_additional_source_components_do_not_bypass_p11_policy(tmp_path, branch, components):
    source = tmp_path/'etc/apt/sources.list'
    source.parent.mkdir(parents=True)
    source.write_text('rpm [p11] https://download.basealt.ru/pub/distributions/ALTLinux p11/branch/'+branch+' '+components+'\n')
    source.chmod(0o644)
    original = source.read_bytes()
    result = package_health(tmp_path, [], lambda command: (1, ''))
    assert result['source']['status'] == 'unknown'
    assert source.read_bytes() == original


def unknown_job(component_service):
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, plan, settings, job = claimed(component_service)
    engine, _ = engine_for(component_service, jobs, settings,
        lambda *a: (_ for _ in ()).throw(ControlError('setup_component_timeout', 'Safe timeout', 7)))
    assert engine.execute(job.job_id)['state'] == 'unknown_requires_review'
    component_service[2].active_job = dict(jobs.get(job.job_id).status)
    return jobs, plan, settings, job


@pytest.mark.parametrize('fault', ['healthy', 'remote', 'lock', 'database', 'dependencies', 'process'])
def test_package_transaction_interruption_requires_fresh_plan(component_service, fault):
    service = component_service[0]
    jobs, plan, settings, old = unknown_job(component_service)
    old_status = (old.job_dir/'status.json').read_bytes()
    old_plan = copy.deepcopy(old.request['plan'])
    if fault != 'healthy':
        key = {'remote': 'remote_execution_absent', 'lock': 'locks_clear', 'database': 'database_readable',
               'dependencies': 'dependencies_healthy', 'process': 'processes_absent'}[fault]
        component_service[4]['package_manager'][key] = False
        with pytest.raises(ControlError): service.plan(old.machine_uuid, 'software.onlyoffice', after_job=old.job_id)
    else:
        fresh = service.plan(old.machine_uuid, 'software.onlyoffice', after_job=old.job_id)
        assert fresh['sha256'] != plan['sha256']
        assert fresh['payload']['predecessor_job']['job_id'] == old.job_id
        submitted = service.apply(fresh['plan_id'], fresh['sha256'])
        assert jobs.get(submitted['job_id']).state == 'queued'
        assert jobs.submit(fresh, operation='component').job_id == submitted['job_id']
    assert old_status == (old.job_dir/'status.json').read_bytes()
    assert old.request['plan'] == old_plan


def test_prejoin_transaction_has_no_automatic_retry():
    tasks = yaml.safe_load((SOURCE/'roles/prejoin_upgrade/tasks/main.yml').read_text())
    upgrade = next(t for t in tasks if t.get('ansible.builtin.command', {}).get('argv') == ['apt-get', '-y', 'dist-upgrade'])
    assert not {'until', 'retries', 'delay'} & set(upgrade)
    assert 'alt_setup_transaction' in upgrade['tags']


def test_real_manager_lock_blocks_health_without_modifying_lock(tmp_path):
    import fcntl
    import multiprocessing
    lock = tmp_path/'var/lib/rpm/.rpm.lock'
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b'')
    context = multiprocessing.get_context('fork')
    ready_recv, ready_send = context.Pipe(False)
    release_recv, release_send = context.Pipe(False)
    def hold():
        with lock.open('r+b') as stream:
            fcntl.lockf(stream, fcntl.LOCK_EX)
            ready_send.send(True)
            release_recv.recv()
    child = context.Process(target=hold)
    child.start()
    try:
        assert ready_recv.poll(5) and ready_recv.recv()
        assert package_health(tmp_path, [], lambda *a: (1, ''))['locks_clear'] is False
        assert lock.read_bytes() == b''
    finally:
        release_send.send(True)
        child.join(5)
        if child.is_alive(): child.terminate()
    assert child.exitcode == 0


def test_retry_successor_runs_once_and_releases_only_reviewed_identity(component_service):
    from types import SimpleNamespace
    from alt_deploy.setup_worker import SetupWorker
    from alt_deploy.jobs import JobRepository
    service = component_service[0]
    good = copy.deepcopy(component_service[4]['components']['software.onlyoffice'])
    jobs, old_plan, settings, old = unknown_job(component_service)
    fresh = service.plan(old.machine_uuid, 'software.onlyoffice', after_job=old.job_id)
    job_id = service.apply(fresh['plan_id'], fresh['sha256'])['job_id']
    component_service[2].active_job = None
    assert JobRepository(settings).active_for_machine(old.machine_uuid).job_id == job_id
    calls = []
    def run(plan, job):
        calls.append(job.job_id)
        component_service[4]['components']['software.onlyoffice'] = good
        return {'status': 'applied', 'changed': True, 'reboot_required': False}
    engine = SetupExecutionEngine(settings, components=service, jobs=jobs, component_executor=SimpleNamespace(run=run))
    worker = SetupWorker(settings, engine=engine, clock=service.clock)
    assert worker.run_once()['status'] == 'successful'
    assert jobs.get(old.job_id).state == 'unknown_requires_review'
    assert JobRepository(settings).active_for_machine(old.machine_uuid) is None
    assert worker.run_once()['status'] == 'idle' and calls == [job_id]


@pytest.mark.parametrize('fault', ['component', 'status_changed', 'review_missing'])
def test_retry_never_bypasses_changed_or_partial_review(component_service, fault):
    from alt_deploy.setup_plans import private_replace
    service = component_service[0]
    jobs, _, settings, old = unknown_job(component_service)
    if fault == 'component':
        with pytest.raises(ControlError): service.plan(old.machine_uuid, 'software.browser', after_job=old.job_id)
        return
    fresh = service.plan(old.machine_uuid, 'software.onlyoffice', after_job=old.job_id)
    if fault == 'status_changed':
        status = private_read(old.job_dir/'status.json')
        status['updated_at'] = '2026-10-13T12:01:00+00:00'
        private_replace(old.job_dir/'status.json', status)
        with pytest.raises(ControlError): service.apply(fresh['plan_id'], fresh['sha256'])
    else:
        service.apply(fresh['plan_id'], fresh['sha256'])
        (settings.state_root/'setup-job-reviews'/(old.job_id+'.json')).unlink()
        with pytest.raises(ControlError) as caught: jobs._check_admissions()
        assert caught.value.code == 'setup_job_admission_requires_review'


def test_timeout_retains_transaction_stage_changed_and_fresh_manager_state(component_service):
    service = component_service[0]
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, _, settings, job = claimed(component_service)
    def action(plan, job):
        SetupEventStore(settings).append(job.job_id, {'schema_version': 1, 'component_id': 'software.onlyoffice',
            'component_version': 1, 'stage': 'transaction', 'task_id': 'task-'+'a'*16,
            'type': 'task_start', 'changed': False, 'code': 'started'})
        component_service[4]['package_manager']['processes_absent'] = False
        raise ControlError('setup_component_timeout', 'Safe timeout', 7)
    engine, _ = engine_for(component_service, jobs, settings, action)
    result = engine.execute(job.job_id)
    assert result['state'] == 'unknown_requires_review'
    assert result['stage'] == 'software.onlyoffice.transaction'
    assert result['post_error_package_manager']['processes_absent'] is False
    assert result['components']['software.onlyoffice']['changed'] is None
    assert job.request['plan']['payload']['execution_budget_seconds'] == 5400


def test_production_apt_probe_drops_all_privileges(monkeypatch):
    from types import SimpleNamespace
    from alt_deploy import component_probe_script
    calls = []
    monkeypatch.setattr(component_probe_script.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=65534, pw_gid=65534))
    # This unit test supplies cache metadata instead of inspecting its host.
    monkeypatch.setattr(component_probe_script, 'Path', lambda value: SimpleNamespace(
        exists=lambda: True, is_symlink=lambda: False,
        lstat=lambda: SimpleNamespace(st_uid=0, st_mode=0o755)))
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout='healthy', stderr='')
    monkeypatch.setattr(component_probe_script.subprocess, 'run', run)
    assert component_probe_script.run(['apt-get', '--simulate', 'check']) == (0, 'healthy')
    options = calls[0][1]
    assert options['user'] == options['group'] == 65534 and options['extra_groups'] == []


def test_installed_versions_do_not_hide_an_active_post_transaction(component_service):
    good = copy.deepcopy(component_service[4]['components']['software.onlyoffice'])
    component_service[4]['components']['software.onlyoffice'].update(packages=[], executable=False)
    jobs, _, settings, job = claimed(component_service)
    def action(plan, job):
        component_service[4]['components']['software.onlyoffice'] = good
        component_service[4]['package_manager']['processes_absent'] = False
        return {'status': 'applied', 'changed': True, 'reboot_required': False}
    engine, _ = engine_for(component_service, jobs, settings, action)
    assert engine.execute(job.job_id)['state'] == 'unknown_requires_review'
