"""The final DNS component is observable and reserved for the full workflow."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_probe import ComponentProbe,desired_queries
from alt_deploy.component_verification import VerificationEngine
from alt_deploy.errors import ControlError
from test_component_catalog import SOURCE,project
from test_component_setup import component_service
from test_component_verification import evidence,UUID


def test_final_dns_recipe_is_fixed_and_existing_profiles_do_not_select_it():
    catalog=ComponentCatalog.load(SOURCE);component=catalog.component('network.final_dns')
    assert component['execution']['role']=='workstation_final_dns'
    assert component['execution']['requires_domain'] is True and component['execution']['requires_user_home'] is False
    query=desired_queries(SOURCE,catalog,[component])[0]
    assert query['recipe']=='final_dns' and len(query['helper_sha256'])==64
    assert 'program' not in json.dumps(query) and 'servers' not in query
    for name in ('base','core-apps','office-standard-v1','office-signature-v1'):
        assert 'network.final_dns' not in catalog.profile(name)['components']


@pytest.mark.parametrize('case',['correct','different','blocked','private'])
def test_dns_enrichment_uses_protected_policy_and_fixed_readonly_observer(tmp_path,monkeypatch,case):
    from alt_deploy import final_dns_runtime
    from alt_deploy.vault import VaultHealthChecker
    catalog=ComponentCatalog.load(SOURCE);component=catalog.component('network.final_dns');baseline=evidence(catalog)
    settings=SimpleNamespace(ansible_project_dir=SOURCE,known_hosts_file=tmp_path/'known',private_key_file=tmp_path/'key')
    machine=SimpleNamespace(uuid=UUID,hostname=baseline['machine']['hostname'],ip='192.0.2.10')
    monkeypatch.setattr(VaultHealthChecker,'full_workflow_policy',lambda self:{'servers':['192.0.2.53']})
    def observe(settings,machine,policy,**options):
        assert policy=={'servers':['192.0.2.53']} and options['expected_boot_id']==baseline['machine']['boot_id']
        if case=='blocked':return {'status':'blocked','code':'final_dns_backend_unverified'}
        value=baseline['components']['network.final_dns']['final_dns']
        if case=='different':
            value['observation']['servers']=['192.0.2.11']
            value['observation']['snapshot_sha256']=hashlib.sha256(final_dns_runtime.canonical({k:v for k,v in value['observation'].items() if k!='snapshot_sha256'})).hexdigest()
        if case=='private':value['observation']['environment']='PRIVATE-SECRET-SENTINEL'
        return value
    monkeypatch.setattr(final_dns_runtime,'observe',observe)
    probe=ComponentProbe(settings,runner=lambda *a,**k:(0,json.dumps(baseline),''))
    if case=='private':
        with pytest.raises(ControlError):probe.observe(machine,{'login':'synthetic.user','upn':'synthetic.user@sosnadmin.local'},[component])
    else:
        value=probe.observe(machine,{'login':'synthetic.user','upn':'synthetic.user@sosnadmin.local'},[component])
        fact=value['components']['network.final_dns']
        assert fact['checks']['ready'] is (case=='correct')
        if case=='blocked':assert fact['error_code']=='final_dns_backend_unverified'
        else:assert fact['policy']=={'servers':['192.0.2.53']}
        assert 'SENTINEL' not in json.dumps(value)


def test_dns_verification_cannot_accept_a_ready_boolean_without_bound_evidence():
    catalog=ComponentCatalog.load(SOURCE);value=evidence(catalog)
    value['components']['network.final_dns'].pop('final_dns',None)
    assert VerificationEngine(catalog).evaluate(value,['network.final_dns'])['components']['network.final_dns']['status']=='unknown'


def test_final_dns_cannot_be_dispatched_as_an_ordinary_component(component_service):
    service,_,machine,*_=component_service
    with pytest.raises(ControlError) as caught:service.plan(machine.uuid,'network.final_dns')
    assert caught.value.code=='full_workflow_required'
