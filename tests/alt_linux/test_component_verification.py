"""Current facts, rather than a previous run, control component compliance."""
import copy
import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/alt-linux/control'))
from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_verification import VerificationEngine

UUID = '11111111-2222-3333-4444-555555555555'
CATALOG = ROOT / 'deploy/alt-linux/ansible'


def evidence(catalog):
    result = {'schema_version': 1, 'observed_at': '2026-10-13T12:00:00+00:00',
              'machine': {'uuid': UUID, 'hostname': 'alt-a1-pc3', 'os_id': 'alt-kworkstation-11',
                          'boot_id': 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'},
              'user': {'login': 'synthetic.user', 'uid': 10001, 'gid': 10001,
                       'home_exists': True, 'home_safe': True},
              'package_manager': {'processes_absent': True, 'remote_execution_absent': True,
                                  'locks_clear': True, 'database_readable': True, 'dependencies_healthy': True,
                                  'source': {'status': 'approved_p11'}, 'simulation': {}}, 'components': {}}
    for component in catalog.components():
        fact = {'schema_version': 1, 'checks': {'ready': True}, 'error_code': None}
        if component['verification']['recipe']=='vnc_policy':
            fact['checks'].update(backend_verified=True,external_policy_clear=True)
        artifact = catalog.artifact(component['id'])
        if artifact:
            if artifact['source'] == 'alt-repository':
                packages = [{'name': p, 'evr': '1.0-alt1', 'architecture': 'x86_64', 'epoch': 0}
                            for p in artifact['packages']]
            elif artifact['source'] == 'archive':
                packages = [{'name': p['package_name'], 'evr': p['package_evr'],
                             'architecture': p['architecture'], 'epoch': p.get('package_epoch', 0)}
                            for p in artifact['packages']]
            else:
                packages = [{'name': artifact['package_name'], 'evr': artifact['package_evr'],
                             'architecture': artifact['architecture'], 'epoch': artifact.get('package_epoch', 0)}]
            fact.update(packages=packages, executable=True)
        if component['verification']['recipe']=='kwallet':
            from alt_deploy.kwallet_runtime import specification,canonical
            spec=specification(catalog._project)
            value=dict(spec,schema_version=1,machine_uuid=UUID,hostname=result['machine']['hostname'],
                boot_id=result['machine']['boot_id'],login=result['user']['login'],uid=result['user']['uid'],gid=result['user']['gid'],
                installed_helper_sha256=spec['helper_sha256'],helper_installed=True,disposition='noop',readiness_sha256='a'*64)
            value.pop('previous_helper_sha256')
            value['snapshot_sha256']=hashlib.sha256(canonical(value)).hexdigest()
            fact['wallet_readiness']=value
        if component['verification']['recipe']=='final_dns':
            from alt_deploy.final_dns_program import target_program
            from alt_deploy.final_dns_runtime import canonical
            policy={'servers':['192.0.2.53']}
            value={'schema_version':1,'machine_uuid':UUID,'hostname':result['machine']['hostname'],
                'boot_id':result['machine']['boot_id'],'backend':'nm_etcnet','interface':'eth0',
                'connection_uuid':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','servers':policy['servers'],
                'persistent_servers':policy['servers'],'configuration_sha256':'a'*64,'network_sha256':'b'*64}
            value['snapshot_sha256']=hashlib.sha256(canonical(value)).hexdigest()
            fact.update(policy=policy,policy_sha256=hashlib.sha256(canonical(policy)).hexdigest(),final_dns={
                'schema_version':1,'status':'ok','helper_sha256':hashlib.sha256(target_program(catalog._project).encode()).hexdigest(),
                'observation':value})
        result['components'][component['id']] = fact
    return result


@pytest.mark.parametrize('alter,status', [
    ('healthy', 'compliant'), ('absent', 'missing'), ('version', 'drifted'),
    ('epoch', 'drifted'), ('architecture', 'drifted'), ('executable', 'drifted'),
    ('invalid', 'unknown'), ('unavailable', 'unknown'),
])
def test_real_package_identity_drives_status(alter, status):
    catalog = ComponentCatalog.load(CATALOG)
    state = evidence(catalog)
    fact = state['components']['software.onlyoffice']
    if alter == 'absent': fact.update(packages=[], executable=False)
    elif alter == 'version': fact['packages'][0]['evr'] = '0.0-alt1'
    elif alter == 'epoch': fact['packages'][0]['epoch'] = 0
    elif alter == 'architecture': fact['packages'][0]['architecture'] = 'noarch'
    elif alter == 'executable': fact['executable'] = False
    elif alter == 'invalid': fact['executable'] = 'true'
    elif alter == 'unavailable': fact['error_code'] = 'probe_unavailable'
    result = VerificationEngine(catalog).evaluate(state, ['software.onlyoffice'])
    assert result['components']['software.onlyoffice']['status'] == status
    assert result['components']['remote.krfb']['status'] == 'not_selected'
    assert result['machine_uuid'] == UUID
    assert result['schema_version'] == 2


def test_missing_dependency_unknown_identity_and_user_profile_block():
    catalog = ComponentCatalog.load(CATALOG)
    for kind in ('dependency', 'identity', 'profile'):
        state = evidence(catalog)
        if kind == 'dependency': state['components']['domain.ready']['checks']['ready'] = False
        elif kind == 'identity': state['machine']['os_id'] = 'other-os'
        else: state['user']['home_safe'] = False
        result = VerificationEngine(catalog).evaluate(state, ['desktop.shortcuts'])
        assert result['components']['desktop.shortcuts']['status'] == 'blocked'
        assert result['operator_action_required'] is True
        assert result['overall_status'] != 'successful'


def test_home_deferral_and_functional_acceptance_are_distinct():
    catalog = ComponentCatalog.load(CATALOG)
    state = evidence(catalog)
    state['user']['home_exists'] = False
    result = VerificationEngine(catalog).evaluate(state, ['desktop.shortcuts'])
    assert result['components']['desktop.shortcuts']['operator_action'] == 'first_domain_login'
    state['user']['home_exists'] = True
    result = VerificationEngine(catalog).evaluate(state, ['software.directum', 'software.cryptopro'])
    for identifier in ('software.directum', 'software.cryptopro'):
        assert result['components'][identifier]['status'] == 'compliant'
        assert result['components'][identifier]['installation_status'] == 'installed_verified'
        assert result['components'][identifier]['acceptance_status'] == 'functional_verification_required'


def test_unknown_never_becomes_success_and_every_recipe_uses_actual_checks():
    catalog = ComponentCatalog.load(CATALOG)
    engine = VerificationEngine(catalog)
    state = evidence(catalog)
    selected = [c['id'] for c in catalog.components()]
    assert engine.evaluate(state, selected)['overall_status'] == 'successful'
    for identifier in selected:
        changed = copy.deepcopy(state)
        changed['components'][identifier]['checks']['ready'] = None
        result = engine.evaluate(changed, selected)
        assert result['components'][identifier]['status'] == 'unknown'
        assert result['overall_status'] != 'successful'
    malformed = engine.evaluate({'schema_version': True}, selected)
    assert malformed['overall_status'] == 'unknown_requires_review'
    assert all(c['status'] == 'unknown' for c in malformed['components'].values())


def test_system_and_user_component_preserves_first_login_deferral():
    catalog = ComponentCatalog.load(CATALOG)
    state = evidence(catalog)
    state['user']['home_exists'] = False
    state['components']['desktop.plasma']['checks']['ready'] = False
    state['components']['desktop.plasma']['deferred'] = True
    result = VerificationEngine(catalog).evaluate(state, ['desktop.plasma'])
    assert result['components']['desktop.plasma']['status'] == 'blocked'
    assert result['components']['desktop.plasma']['operator_action'] == 'first_domain_login'
