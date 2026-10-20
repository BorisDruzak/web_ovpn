"""One registry-derived complete preset, with no request-side policy choices."""
import copy
import hashlib
import json

import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.errors import ControlError
from test_component_catalog import SOURCE,project


def test_complete_profile_preserves_all_four_legacy_declarations():
    document=yaml.safe_load((SOURCE/'group_vars/software_catalog.yml').read_text())
    profiles=document['setup_catalog']['profiles']
    old=[p for p in profiles if p['id']!='workstation-full-v1']
    assert hashlib.sha256(json.dumps(old,sort_keys=True,separators=(',',':')).encode()).hexdigest()=='6dd71b909ed4b17939b488a4e63340118b822340592d1d7cfc82ae49d761044f'
    profile=ComponentCatalog.load(SOURCE).profile('workstation-full-v1')
    assert profile['workflow']=='complete_workstation_v1' and profile['version']==1
    assert profile['optional_components']==[] and len(profile['components'])==17


def test_full_plan_is_an_exact_registry_partition_with_direct_vnc_first_and_dns_last():
    from alt_deploy.full_workflow import build_workflow_plan,validate_workflow_plan
    catalog=ComponentCatalog.load(SOURCE);workflow=build_workflow_plan(catalog,{'servers':['192.0.2.53']})
    assert workflow['kind']=='complete_workstation' and workflow['profile_id']=='workstation-full-v1'
    assert workflow['policy']=={'final_dns':{'servers':['192.0.2.53']},
        'vnc':{'port':5900,'scope':'direct','authentication':'password_required'}}
    phases=workflow['phases']
    assert [(p['id'],p['budget_seconds']) for p in phases]==[('system',21600),('user',5400),('final_dns',300)]
    assert phases[0]['component_ids'][0]=='remote.vnc_policy'
    assert phases[-1]['component_ids']==['network.final_dns']
    assert set(phases[1]['component_ids'])=={'desktop.shortcuts','desktop.kwallet_repair','remote.krfb'}
    flattened=[v for p in phases for v in p['component_ids']]
    assert len(flattened)==len(set(flattened))==17
    assert set(flattened)=={c['id'] for c in catalog.components()}
    assert all('adapter' not in catalog.component(v)['execution'] for p in phases[1:] for v in p['component_ids'])
    assert validate_workflow_plan(workflow,catalog)==workflow
    assert workflow['policy_sha256']==hashlib.sha256(json.dumps(workflow['policy'],sort_keys=True,separators=(',',':')).encode()).hexdigest()


@pytest.mark.parametrize('fault',['extra','missing','duplicate','order','budget','bool','policy','hash','adapter','profile'])
def test_workflow_cannot_replace_phases_commands_policy_or_budgets(fault):
    from alt_deploy.full_workflow import build_workflow_plan,validate_workflow_plan
    catalog=ComponentCatalog.load(SOURCE);workflow=build_workflow_plan(catalog,{'servers':['192.0.2.53']})
    if fault=='extra':workflow['command']='PRIVATE-SECRET-SENTINEL'
    elif fault=='missing':workflow['phases'][1]['component_ids'].pop()
    elif fault=='duplicate':workflow['phases'][1]['component_ids'].append('desktop.shortcuts')
    elif fault=='order':workflow['phases'].reverse()
    elif fault=='budget':workflow['phases'][0]['budget_seconds']=99999999
    elif fault=='bool':workflow['schema_version']=True
    elif fault=='policy':workflow['policy']['vnc']['authentication']='none'
    elif fault=='hash':workflow['policy_sha256']='0'*64
    elif fault=='adapter':workflow['phases'][1]['component_ids'].append('domain.ready')
    elif fault=='profile':workflow['profile_id']='core-apps'
    with pytest.raises(ControlError) as caught:validate_workflow_plan(workflow,catalog)
    assert caught.value.code=='full_workflow_plan_invalid' and 'SENTINEL' not in str(caught.value)


@pytest.mark.parametrize('fault',['unknown_marker','legacy_marker','optional','missing_registry_component'])
def test_complete_profile_marker_cannot_weaken_the_declared_complete_partition(project,fault):
    from alt_deploy.full_workflow import build_workflow_plan
    path=project/'group_vars/software_catalog.yml';document=yaml.safe_load(path.read_text())
    profiles=document['setup_catalog']['profiles'];profile=next(p for p in profiles if p['id']=='workstation-full-v1')
    if fault=='unknown_marker':profile['workflow']='arbitrary'
    elif fault=='legacy_marker':profiles[0]['workflow']='complete_workstation_v1'
    elif fault=='optional':profile['optional_components']=['remote.krfb'];profile['components'].remove('remote.krfb')
    else:profile['components'].remove('software.vkworkspace')
    path.write_text(yaml.safe_dump(document,sort_keys=False))
    with pytest.raises(ControlError):build_workflow_plan(ComponentCatalog.load(project),{'servers':['192.0.2.53']})


def test_deferred_system_result_is_typed_and_never_implies_later_phase_success():
    from alt_deploy.full_workflow import build_workflow_plan,deferred_system_result,validate_system_result
    workflow=build_workflow_plan(ComponentCatalog.load(SOURCE),{'servers':['192.0.2.53']})
    marker=deferred_system_result(workflow)
    validate_system_result({'status':'successful','components':{'workflow_deferred':marker}},workflow)
    marker['schema_version']=True
    with pytest.raises(ValueError):validate_system_result({'status':'successful','components':{'workflow_deferred':marker}},workflow)


def test_complete_krfb_configuration_probe_uses_the_direct_fixed_port_template():
    from alt_deploy.component_probe import desired_queries
    catalog=ComponentCatalog.load(SOURCE);component=catalog.component('remote.krfb')
    legacy=desired_queries(SOURCE,catalog,[component],profile_id='core-apps')[0]
    managed=desired_queries(SOURCE,catalog,[component],profile_id='workstation-full-v1')[0]
    assert [['TCP'],'port','5900'] in managed['settings']
    assert [['TCP'],'useDefaultPort','true'] in managed['settings']
    assert [['TCP'],'port','5900'] not in legacy['settings']
    assert all(v[1] not in ('desktopPassword','unattendedPassword') for v in managed['settings'])
