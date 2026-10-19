"""Public events are allowlisted facts, never captured Ansible result objects."""
import json
from types import SimpleNamespace

import pytest

from alt_deploy.setup_events import SetupEventStore, safe_task_event
from alt_deploy.errors import ControlError
from test_setup_jobs import jobs_fixture
from test_component_setup import component_service
from test_component_catalog import project


def test_events_never_serialize_secret_results(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    store = SetupEventStore(settings, clock=jobs.clock)
    sentinel = 'SENTINEL-private-password-ticket-key-stderr'
    task = SimpleNamespace(get_path=lambda: '/approved/roles/software_onlyoffice/tasks/main.yml:7',
                           tags=[], no_log=True, get_name=lambda: sentinel)
    result = SimpleNamespace(_task=task, _result={'changed': True, 'stdout': sentinel, 'stderr': sentinel,
        'msg': sentinel, 'invocation': {'password': sentinel}, '_ansible_no_log': True})
    event = safe_task_event(result, component=plan['payload']['component'], event_type='task_failed')
    written = store.append(job.job_id, event)
    assert written['sequence'] == 1
    assert sentinel not in json.dumps(store.read(job.job_id))
    assert written['code'] == 'task_failed' and written['changed'] is True
    assert written['task_id'].startswith('task-')


@pytest.mark.parametrize('field,value', [('sequence', 9), ('stdout', 'raw'), ('code', 'free-form-secret'),
    ('changed', 1), ('schema_version', 2), ('component_id', 'domain.ready'), ('task_id', 'x'*3000)])
def test_event_schema_sequence_and_scope_are_strict(component_service, field, value):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    store = SetupEventStore(settings, clock=jobs.clock)
    event = {'schema_version': 1, 'component_id': 'software.onlyoffice', 'component_version': 1,
             'stage': 'apply', 'task_id': 'task-'+'a'*16, 'type': 'task_ok', 'changed': False, 'code': 'ok'}
    event[field] = value
    with pytest.raises(ControlError): store.append(job.job_id, event)
    assert store.read(job.job_id)['events'] == []


def test_event_pagination_corruption_and_missing_completion(component_service):
    jobs, plan, settings = jobs_fixture(component_service)
    job = jobs.submit(plan, operation='component')
    store = SetupEventStore(settings, clock=jobs.clock)
    event = {'schema_version': 1, 'component_id': 'software.onlyoffice', 'component_version': 1,
             'stage': 'apply', 'task_id': 'task-'+'a'*16, 'type': 'task_ok', 'changed': False, 'code': 'ok'}
    store.append(job.job_id, event)
    store.append(job.job_id, event)
    page = store.read(job.job_id, after=1, limit=1)
    assert page['events'][0]['sequence'] == 2
    assert jobs.get(job.job_id).state == 'queued'
    path = job.job_dir/'events'/'000000000002.json'
    path.write_text('{}')
    with pytest.raises(ControlError): store.read(job.job_id)


@pytest.mark.parametrize('no_log,foreign,tagged,expected', [
    (False, False, True, 'first_join_native_access_denied'),
    (True, False, True, 'task_failed'),
    (False, True, True, 'task_failed'),
    (False, False, False, 'task_failed'),
])
def test_foreign_binding_and_no_log_never_export(no_log, foreign, tagged, expected):
    binding = {'schema_version': 1, 'configuration_run_id': 'a'*32,
               'invocation_id': 'b'*32, 'identity_sha256': 'c'*64}
    value = {**binding, 'phase': 'native_execution',
             'code': 'first_join_native_access_denied', 'directory_effect': 'returned_failure'}
    if foreign:
        value['invocation_id'] = 'd'*32
    task = SimpleNamespace(get_path=lambda: '/approved/roles/domain_join/tasks/main.yml:1',
        tags=['alt_setup_domain_join', 'alt_setup_first_join_diagnostic'] if tagged else [],
        no_log=no_log, args={'argv': ['/usr/bin/python3', '-I', '/usr/local/libexec/alt-first-join.py',
                                  '--read-diagnostic', json.dumps(binding, sort_keys=True)]})
    event = safe_task_event(SimpleNamespace(_task=task, _result={
        'stdout': json.dumps(value), 'cmd': task.args['argv'],
        'stderr': 'SENTINEL-private', '_ansible_no_log': no_log}),
        component={'id': 'domain.ready', 'version': 1}, event_type='task_failed',
        diagnostic_binding=binding)
    assert event['code'] == expected
    assert 'SENTINEL' not in json.dumps(event)
