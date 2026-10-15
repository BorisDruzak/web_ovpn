import json
import uuid

import pytest

from test_workstations_reconcile import database, NOW


def test_journal_exports_only_reviewed_fields_with_matching_cursor(database):
    from app.workstations.journal import JournalService
    from app.workstations.models import WorkstationRequest
    with database() as db:
        for number in range(3):
            db.add(WorkstationRequest(id=str(uuid.uuid4()), actor='user:synthetic', action='plans.apply', permission='workstations:apply',
                intent_sha256='a' * 64, status='unknown', parameters_json={'query': 'private-marker'},
                data_json={'job_id': 'job-20261015T000000Z-12345678', 'stdout': 'private-marker'},
                phases_json=[{'stage': 'apply', 'status': 'unknown', 'stderr': 'private-marker'}], created_at=NOW))
        db.commit()
        journal = JournalService()
        first = journal.list(db, filters={}, cursor=None, limit=2)
        assert len(first['events']) == 2 and first['next_cursor']
        last = journal.list(db, filters={}, cursor=first['next_cursor'], limit=2)
        assert len(last['events']) == 1
        exported = journal.export(db, filters={}, cursor=None, limit=100)
        assert len(exported['events']) == 3 and 'private-marker' not in json.dumps(exported)
        assert {row['id'] for row in first['events']}.isdisjoint({row['id'] for row in last['events']})


def test_native_event_cursor_and_error_classification_are_safe(database):
    from app.workstations.journal import JournalService, error_details
    class Client:
        def call(self, operation, parameters, **kwargs):
            if operation == 'jobs.status':
                return {'job': {'history': [{'state': 'queued', 'stage': 'created', 'at': NOW.isoformat(), 'raw': 'private-marker'}]}}
            assert operation == 'jobs.events'
            return {'events': [{'sequence': 1, 'timestamp': NOW.isoformat(), 'job_id': parameters['job_id'],
                'component_id': 'system.base', 'task_id': 'component', 'stage': 'apply', 'type': 'task_failed', 'code': 'task_failed', 'stdout': 'private-marker'}],
                'next_sequence': 1, 'total': 1}
    with database() as db:
        value = JournalService(client=Client()).list(db, filters={'job_id': 'job-20261015T000000Z-12345678'}, cursor=None, limit=100)
        assert value['events'][0]['code'] == 'task_failed' and 'private-marker' not in json.dumps(value)
        assert len(value['events']) == 2 and any(row.get('stage') == 'created' for row in value['events'])
    assert error_details('workstations_transport_timeout', uncertain=True)['category'] == 'uncertain_outcome'
    assert error_details('ad_user_disabled')['category'] == 'validation'


def test_large_run_history_still_pages_from_oldest_without_hidden_truncation(database):
    from datetime import timedelta
    from sqlalchemy import insert
    from app.workstations.models import SourceRun
    from app.workstations.journal import JournalService
    with database() as db:
        db.execute(insert(SourceRun), [{'id': str(uuid.uuid4()), 'batch_id': str(uuid.uuid4()), 'source': 'ad',
            'status': 'success', 'started_at': NOW + timedelta(seconds=number)} for number in range(10002)])
        db.commit()
        first = JournalService().list(db, filters={}, cursor=None, limit=2)
        assert len(first['events']) == 2 and first['events'][0]['timestamp'] == NOW.isoformat()
        assert first['next_cursor']


def test_ended_link_keeps_both_confirmation_and_ending_events(database):
    from datetime import timedelta
    from app.workstations.models import DirectoryLink
    from app.workstations.journal import JournalService
    with database() as db:
        db.add(DirectoryLink(device_key='machine:' + str(uuid.uuid4()), user_guid=str(uuid.uuid4()), user_sid='S-1-5-21-1',
            user_login='synthetic', source_revision='a' * 64, status='ended', created_at=NOW,
            confirmed_at=NOW, ended_at=NOW + timedelta(seconds=1), created_by='synthetic', ended_by='synthetic'))
        db.commit()
        rows = JournalService().list(db, filters={}, cursor=None, limit=100)['events']
        assert [row['action'] for row in rows] == ['link.confirmed', 'link.ended']


@pytest.mark.parametrize('filter_name', ['device_key', 'component'])
def test_filtered_journal_includes_native_history_and_apply_plan_association(database, filter_name):
    from app.workstations.journal import JournalService
    from app.workstations.models import WorkstationRequest
    machine, other = str(uuid.uuid4()), str(uuid.uuid4())
    jobs = ['job-20261015T000000Z-12345678', 'job-20261015T000001Z-12345679']
    plan_id = 'setup-component-' + 'a' * 64
    class Client:
        def __init__(self): self.calls = []
        def call(self, operation, parameters, **kwargs):
            self.calls.append((operation, parameters))
            if operation == 'jobs.list':
                offset = parameters.get('offset', 0)
                return {'jobs': [{'job_id': jobs[offset], 'machine_uuid': machine if offset == 0 else other}],
                    'total': 2, 'next_offset': offset + 1}
            if operation == 'jobs.status':
                first = parameters['job_id'] == jobs[0]
                return {'job': {'job_id': parameters['job_id'], 'machine_uuid': machine if first else other,
                    'plan_id': plan_id if first else 'setup-component-' + 'b' * 64,
                    'components': {'software.onlyoffice' if first else 'system.base': {}},
                    'history': [{'state': 'running', 'stage': 'apply', 'at': NOW.isoformat()}]}}
            assert operation == 'jobs.events'
            assert parameters['job_id'] == jobs[0]
            return {'events': [{'sequence': 1, 'timestamp': NOW.isoformat(), 'stage': 'apply',
                'component_id': 'software.onlyoffice', 'type': 'task_failed', 'code': 'task_failed'}], 'total': 1, 'next_sequence': 1}
    client = Client()
    with database() as db:
        receipt = WorkstationRequest(actor='synthetic', action='plans.apply', permission='workstations:apply',
            intent_sha256='a' * 64, status='unknown', parameters_json={'plan_id': plan_id}, created_at=NOW)
        db.add(receipt); db.commit()
        filters = {filter_name: 'machine:' + machine if filter_name == 'device_key' else 'software.onlyoffice'}
        value = JournalService(client=client).list(db, filters=filters, limit=100)
        assert {row['action'] for row in value['events']} == {'plans.apply', 'job.stage', 'job.event'}
        assert any(row.get('request_id') == receipt.id for row in value['events'])
        assert value['evidence'] == 'complete' and value['native_complete'] is True
        assert len([call for call in client.calls if call[0] == 'jobs.list']) == 2
        assert all(row.get('job_id') in (None, jobs[0]) for row in value['events'])


def test_native_list_failure_is_explicit_in_filtered_journal(database):
    from app.workstations.journal import JournalService
    from app.workstations.sources import SourceError
    class Client:
        def call(self, *args, **kwargs): raise SourceError('workstations_transport_timeout')
    with database() as db:
        value = JournalService(client=Client()).list(db, filters={'component': 'software.onlyoffice'}, limit=2)
        assert value['native_complete'] is False and value['evidence'] == 'unavailable'
        assert value['native_errors'] == [{'code': 'workstations_transport_timeout'}]


def test_component_stages_are_not_attributed_to_unproven_component(database):
    from app.workstations.journal import JournalService
    class Client:
        def call(self, operation, parameters, **kwargs):
            if operation == 'jobs.list':
                return {'jobs': [{'job_id': 'job-20261015T000000Z-12345678'}], 'total': 1, 'next_offset': 1}
            if operation == 'jobs.status': return {'job': {'components': {'system.base': {}}, 'history': []}}
            raise AssertionError('Unrelated job events must not be read')
    with database() as db:
        value = JournalService(client=Client()).list(db, filters={'component': 'software.onlyoffice'})
        assert value['events'] == [] and value['native_complete'] is True
