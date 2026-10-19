"""A closed first-join failure is evidence, never permission to replay it."""
import copy
import hashlib
import importlib
from pathlib import Path

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_jobs import legacy_setup_execution
from alt_deploy.setup_plans import private_create, private_read, private_replace
from test_component_catalog import project
from test_component_setup import component_service
from test_setup_detach import full_fixture
from test_setup_service import UUID, OU


def backend(name):
    path = Path(__file__).resolve().parents[2]/'deploy/alt-linux/backup/alt_deploy_backup'/(name+'.py')
    assert path.exists(), 'Missing read-only partial-state contract: '+name
    return importlib.import_module('alt_deploy_backup.'+name)


@pytest.fixture
def partial_failure(component_service, monkeypatch):
    return make_partial_failure(component_service, monkeypatch)


def make_partial_failure(component_service, monkeypatch, *, configuration_id='f'*32):
    _, setup, machine, user, state, date, calls = component_service
    (setup.assignments.root/(UUID+'.json')).unlink()
    current = {'uuid': UUID, 'hostname': machine.hostname, 'domain': '', 'trust': False,
        'sssd': False, 'user_lookup': False, 'local_duplicate': False, 'home_exists': False, 'computer_identity': None}
    setup.probe = lambda *a: copy.deepcopy(current)
    setup.directory.computer = lambda hostname: {'hostname': hostname, 'exists': False, 'objects': []}
    setup.prerequisites = lambda request: {'ready': True, 'directory_uri': 'ldap://dc.sosnadmin.local'}
    state['user'].update(uid=None, gid=None, home_exists=False, home_safe=False)
    state['components']['domain.ready']['checks']['ready'] = False
    setup, jobs, engine, worker, _ = full_fixture(component_service, monkeypatch)
    def fail_configure(identifier, request, **kwargs):
        from alt_deploy.setup_events import SetupEventStore
        run_id = configuration_id
        with legacy_setup_execution(setup.settings, UUID, machine.hostname, operation='configure', run_id=run_id):
            private_create(setup.settings.state_root/'configure-runs'/run_id/'request.json', request.to_dict())
            private_create(setup.settings.state_root/'configure-runs'/run_id/'result.json', {
                'schema_version': 1, 'machine_uuid': UUID, 'hostname': machine.hostname,
                'profile': request.profile, 'status': 'failed', 'phase': 'domain_join',
                'retryable': False, 'recovered': False, 'reboot_required': True,
                'error': {'code': 'configure_critical_phase_failed', 'class': 'fatal-invariant',
                          'safe_message': 'Synthetic partial join failure'},
                'components': {}, 'verification': {'group_policy_flag_preserved': True}})
            job = next(j for j in jobs.list() if j.machine_uuid == UUID)
            store = SetupEventStore(setup.settings, clock=setup.clock)
            for kind, code in [('task_start', 'started'), ('task_failed', 'task_failed')]:
                store.append(job.job_id, {'schema_version': 1, 'component_id': 'domain.ready',
                    'component_version': 1, 'stage': 'domain_join', 'task_id': 'task-'+'0'*16,
                    'type': kind, 'changed': False, 'code': code})
            current['domain'] = 'sosnadmin.local'
            raise ControlError('domain_join_failed', 'Synthetic failure', 7, {'run_id': run_id, 'phase': 'domain_join'})
    setup.planner.start = fail_configure
    plan = setup.plan(UUID, user['login'], OU, 'office-standard-v1')
    submitted = setup.apply(plan['plan_id'], plan['sha256'], detach=True)
    assert worker.run_once()['status'] == 'unknown_requires_review'
    return setup, jobs.get(submitted['job_id']), machine, user, state, current, date


def retained(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_original_closed_join_is_sealed_without_guid(partial_failure):
    setup, job, machine, user, state, current, date = partial_failure
    before = retained(setup.settings.state_root)
    value = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)
    assert value['job_id'] == job.job_id and len(value['lease_ids']) == 2
    assert value['configuration_run_id'] == 'f'*32
    assert value['original']['computer']['objects'] == []
    assert value['original']['observed']['domain'] == ''
    assert 'computer_guid' not in value
    assert value['binding']['result'] == 'failed'
    assert value['files']['jobs/'+job.job_id+'/status.json'] == before['jobs/'+job.job_id+'/status.json']
    assert retained(setup.settings.state_root) == before


@pytest.mark.parametrize('fault', ['result', 'event_gap', 'binding', 'foreign_lease', 'unfinished', 'mode'])
def test_missing_result_or_event_gap_denies_history(partial_failure, fault):
    setup, job, *_ = partial_failure
    root = setup.settings.state_root
    if fault == 'result':
        (root/'configure-runs'/('f'*32)/'result.json').unlink()
    elif fault == 'event_gap':
        sorted((job.job_dir/'events').glob('*.json'))[0].unlink()
    elif fault == 'binding':
        path = root/'domain-assignments'/(UUID+'.json')
        private_replace(path, dict(private_read(path), login='other.user'))
    elif fault == 'foreign_lease':
        path = next((root/'legacy-setup-reservations').glob('*.json'))
        record = dict(private_read(path), reservation_id='e'*32, run_id='e'*32)
        private_create(path.parent/('e'*32+'.json'), record)
    elif fault == 'unfinished':
        path = job.job_dir/'execution.json'
        record = private_read(path); record.pop('finished_at')
        private_replace(path, record)
    else:
        (root/'configure-runs'/('f'*32)/'result.json').chmod(0o644)
    with pytest.raises(ControlError):
        backend('setup_closed_failure').ClosedFailureEvidence(setup.settings).load(job.job_id)


def test_history_digest_changes_when_even_safe_event_bytes_change(partial_failure):
    setup, job, *_ = partial_failure
    service = backend('setup_closed_failure').ClosedFailureEvidence(setup.settings)
    before = service.load(job.job_id)
    path = sorted((job.job_dir/'events').glob('*.json'))[-1]
    path.write_bytes(path.read_bytes()+b' ')
    after = service.load(job.job_id)
    assert before['history_sha256'] != after['history_sha256']
