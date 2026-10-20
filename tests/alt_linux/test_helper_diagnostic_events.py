"""Only the pinned reader command and its matching native scope emit codes."""
import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from alt_deploy.setup_events import safe_task_event


@pytest.mark.parametrize('fault',['none','command','reader','scope','stdout','not_tagged','private','unavailable','rollback'])
def test_bound_helper_diagnostic_cannot_be_forged_from_another_task_output(fault):
    component={'id':'network.final_dns','version':1};program='published fixed read-only diagnostic'
    scope={'schema_version':1,'component_id':component['id'],'job_id':'job-20261020T000000Z-12345678',
        'machine_uuid':'11111111-2222-3333-4444-555555555555','plan_sha256':'1'*64,
        'operation_sha256':'2'*64,'context_sha256':'3'*64,'helper_sha256':'4'*64}
    expected={component['id']:{'scope':copy.deepcopy(scope),'reader_sha256':hashlib.sha256(program.encode()).hexdigest()}}
    value=dict(scope,recorded=True,outcome='outcome_unverified',code='final_dns_rollback_unverified')
    command=['/usr/bin/python3','-I','-B','-c',program,json.dumps(scope)]
    task=SimpleNamespace(get_path=lambda:'fixed-role:1',tags=['alt_setup_helper_diagnostic'],no_log=False)
    raw={'cmd':command,'stdout':json.dumps(value),'changed':False}
    if fault=='command':command[0]='/bin/echo'
    elif fault=='reader':command[4]+='PRIVATE-SENTINEL'
    elif fault=='scope':value['job_id']='job-20261020T000000Z-87654321'
    elif fault=='stdout':value['code']='PRIVATE-SENTINEL'
    elif fault=='not_tagged':task.tags=[]
    elif fault=='private':raw['_ansible_no_log']=True
    elif fault=='unavailable':value.update(recorded=False,code='workflow_helper_diagnostic_unavailable')
    elif fault=='rollback':value.update(outcome='rolled_back_verified',code='final_dns_lookup_failed')
    raw['stdout']=json.dumps(value)
    event=safe_task_event(SimpleNamespace(_task=task,_result=raw),component=component,event_type='task_ok',helper_diagnostic_bindings=expected)
    if fault in ('none','unavailable','rollback'):
        assert event['code']==value['code']
        assert event['type']==('task_ok' if fault=='rollback' else 'task_failed')
    else:assert event['code']=='ok' and event['type']=='task_ok'
    assert 'SENTINEL' not in json.dumps(event)
