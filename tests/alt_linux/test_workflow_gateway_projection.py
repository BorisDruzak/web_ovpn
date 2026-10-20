"""Public workflow projections reject private additions at every nesting level."""
import copy
import json

import pytest

from alt_deploy.workstations_projection import public_plan,project


def workflow():
    return {'schema_version':1,'kind':'complete_workstation','profile_id':'workstation-full-v1',
        'policy_sha256':'a'*64,'policy':{'vnc':{'port':5900,'scope':'direct','authentication':'password_required'},
        'final_dns':{'servers':['192.0.2.53']}},'phases':[
            {'id':name,'component_ids':[component],'budget_seconds':seconds}
            for name,component,seconds in [('system','network.vnc_policy',21600),('user','remote.krfb',5400),
                                          ('final_dns','network.final_dns',300)]]}


def test_plan_only_exposes_declared_workflow_policy_and_phases():
    native=workflow();native['private_path']='PRIVATE-SENTINEL'
    plan={'payload':{'workflow':native},'plan_id':'setup-'+'a'*64,'sha256':'a'*64}
    result=public_plan(plan)
    assert result['workflow']=={k:workflow()[k] for k in ('kind','phases','policy')}
    assert 'PRIVATE-SENTINEL' not in json.dumps(result)


@pytest.mark.parametrize('mutation',[lambda w:w['policy']['vnc'].update(password='PRIVATE-SENTINEL'),
    lambda w:w['policy'].update(raw='PRIVATE-SENTINEL'),
    lambda w:w['phases'][0].update(command='PRIVATE-SENTINEL'),
    lambda w:w['policy']['final_dns'].update(image='PRIVATE-SENTINEL'),
    lambda w:w['policy']['final_dns'].update(servers=['PRIVATE-SENTINEL']),
    lambda w:w['phases'][0].update(budget_seconds=True)])
def test_invalid_nested_workflow_fails_closed(mutation):
    value=workflow();mutation(value)
    with pytest.raises(Exception):public_plan({'payload':{'workflow':value}})


def test_safe_job_workflow_is_retained_without_native_private_refs():
    value={'schema_version':1,'kind':'complete_workstation','phase':'user','waiting_reason':'krfb_clients_connected',
        'phases':{name:{'state':'pending','component_ids':[row['component_ids'][0]],'budget_seconds':row['budget_seconds'],
                       'error_code':None,'admission_sequence':None} for name,row in zip(('system','user','final_dns'),workflow()['phases'])}}
    data={'job':{'job_id':'synthetic','workflow':value,'raw':'PRIVATE-SENTINEL'}}
    result=project('jobs.status',data)
    assert result['job']['workflow']==value
    assert 'PRIVATE-SENTINEL' not in json.dumps(result)
    unsafe=copy.deepcopy(data);unsafe['job']['workflow']['phases']['user']['private_key']='PRIVATE-SENTINEL'
    with pytest.raises(Exception):project('jobs.status',unsafe)
