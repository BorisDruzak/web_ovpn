import copy,json
import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from alt_deploy import setup_recovery_policy_baseline as baseline,setup_recovery_policy_effects as effects
from alt_deploy import setup_recovery_original_policy as original,setup_recovery_sssd_policy as policy,setup_recovery_native as native
from test_setup_recovery_policy_baseline_runtime import scenario as baseline_fixture,planning_scenario


def reply(bound,values):
    receipt=dict(schema_version=1,status='original_sssd_policy_baseline',request_sha256=digest(bound),
        original_sha256=digest(bound['backup_request']['facts']['files']['/etc/sssd/sssd.conf']),tools_sha256='a'*64,
        configured_values=copy.deepcopy(values),defaults_verified=False,running_policy_verified=False,trust_verified=False)
    projection=baseline.projection(receipt,original=original,policy=policy,native=native,meta=bound['metadata'])
    request=dict(schema_version=1,baseline_request=bound,baseline_receipt=receipt,source_sha256=bound['source_sha256'])
    configured={key:dict(present=bool(values.get(key,'')),value=values.get(key,'')) for key in effects.KEYS}
    domain='cn='+bound['metadata']['realm'].upper()+',cn=domain,cn=config'
    value=dict(schema_version=1,status='original_policy_effect_inventory',request_sha256=digest(request),
        baseline_projection_sha256=digest(projection),source_sha256=bound['source_sha256'],
        runtime_dependencies={path:dict(present=True,sha256='b'*64,size=100,uid=0,gid=0,mode=0o755,package=package)
                              for path,package in effects.DEPENDENCIES.items()},
        configured=configured,key_inventory={domain:sorted(key for key,record in configured.items() if record['present']),
                                            'cn=sssd,cn=config':['domains']},
        unreviewed_keys=[],defaults_reviewed=False,effects_reviewed=False,execution_authorized=False)
    return dict(baseline_receipt=receipt,effect_receipt=value)


def scenario(root):
    from alt_deploy.setup_recovery_policy_effects_runtime import RecoveryPolicyEffectsRuntime
    old,machine,snapshot,metadata,_=baseline_fixture(root);calls=[]
    values=old.runner([],input_text=json.dumps({'request':dict(backup_request={'facts':snapshot['workstation_facts']['snapshot']})}))[1]
    values=json.loads(values)['configured_values']
    def runner(command,**options):
        calls.append((command,options));bound=json.loads(options['input_text'])['request']
        return 0,json.dumps(reply(bound,values)),'SYNTHETIC_PRIVATE_OUTPUT'
    runtime=RecoveryPolicyEffectsRuntime(old.settings,runner=runner)
    return runtime,machine,snapshot,metadata,calls


def test_effect_runtime_pins_sources_target_and_false_claims(tmp_path):
    runtime,machine,snapshot,metadata,calls=scenario(tmp_path)
    result=runtime.capture(machine,snapshot,metadata)
    assert result['receipt']['effect_receipt']['effects_reviewed'] is False
    command,options=calls[0];bound=json.loads(options['input_text'])['request']
    assert len(json.loads(options['input_text'])['sources'])==8
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null'] and command[-2]=='ansible@192.0.2.10'
    assert len(command[-1].encode())<8192 and options['timeout']==210
    assert all(value in command for value in ('StrictHostKeyChecking=yes','ProxyJump=none','ProxyCommand=none','PermitLocalCommand=no'))
    assert bound['backup_request']['claim_sha256']==digest(dict(schema_version=1,scope='original_policy_effect_inventory_only',recovery_snapshot_sha256=digest(snapshot)))


@pytest.mark.parametrize('change',['uuid','hostname','address','registration','facts','metadata'])
def test_effect_runtime_refuses_pre_transport_drift(tmp_path,change):
    runtime,machine,snapshot,metadata,calls=scenario(tmp_path)
    if change=='uuid':machine.uuid='bad'
    elif change=='hostname':machine.hostname='alt-a1-pc99'
    elif change=='address':machine.ip='192.0.2.99'
    elif change=='registration':machine.raw['revision']=2
    elif change=='facts':snapshot['workstation_facts']['snapshot_sha256']='0'*64
    else:metadata['hostname']='alt-a1-pc99'
    with pytest.raises(ControlError):runtime.capture(machine,snapshot,metadata)
    assert calls==[]


@pytest.mark.parametrize('change',['rc','extra','duplicate','oversize','effect_request','baseline_projection','source','claim','claim_type','helper_owner','helper_package','configured','unknown','source_after','target_after'])
def test_effect_runtime_refuses_forged_receipt_or_post_transport_drift(tmp_path,change,monkeypatch):
    runtime,machine,snapshot,metadata,calls=scenario(tmp_path);previous=runtime.runner
    def runner(command,**options):
        rc,out,err=previous(command,**options)
        if change=='rc':rc=1
        elif change=='duplicate':out=out[:-1]+',"effect_receipt":{}}'
        elif change=='oversize':out=' '*(16384+1)
        elif change=='source_after':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*8)
        elif change=='target_after':machine.raw['revision']=2
        else:
            pair=json.loads(out);value=pair['effect_receipt']
            if change=='extra':pair['command']='start'
            elif change=='effect_request':value['request_sha256']='0'*64
            elif change=='baseline_projection':value['baseline_projection_sha256']='0'*64
            elif change=='source':value['source_sha256']='0'*64
            elif change=='claim':value['effects_reviewed']=True
            elif change=='claim_type':value['effects_reviewed']=0
            elif change=='helper_owner':next(iter(value['runtime_dependencies'].values()))['uid']=1000
            elif change=='helper_package':next(iter(value['runtime_dependencies'].values()))['package']='wrong'
            elif change=='configured':value['configured']['id_provider']['value']='ldap'
            else:value['unreviewed_keys']=['forged']
            out=json.dumps(pair)
        return rc,out,err
    runtime.runner=runner
    with pytest.raises(ControlError) as caught:runtime.capture(machine,snapshot,metadata)
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(caught.value)


def service_scenario(root):
    from alt_deploy.setup_recovery_policy_effects_runtime import RecoveryPolicyEffectsRuntime,RecoveryPolicyEffectsService
    old,paths,machine,user,computer,facts=planning_scenario(root)
    def runner(command,**options):
        rc,out,err=old.runtime.runner(command,**options)
        values=json.loads(out)['configured_values'];bound=json.loads(options['input_text'])['request']
        return 0,json.dumps(reply(bound,values)),''
    runtime=RecoveryPolicyEffectsRuntime(old.runtime.settings,runner=runner)
    service=RecoveryPolicyEffectsService(old.planning,runtime=runtime,resolver=old.resolver)
    return service,paths,machine,user,computer,facts


def test_effect_plan_preserves_history_and_has_no_reservation(tmp_path):
    from test_setup_recovery_planning import RUN,COMPUTER_GUID
    service,paths,*_=service_scenario(tmp_path);before={key:path.read_bytes() for key,path in paths.items()}
    plan=service.plan(RUN,COMPUTER_GUID)
    assert plan['plan_id'].startswith('recovery-policy-effects-')
    assert plan['payload']['execution_available'] is False
    assert plan['payload']['effects_reviewed'] is plan['payload']['defaults_reviewed'] is False
    assert {key:path.read_bytes() for key,path in paths.items()}==before
    assert not (service.planning.settings.state_root/'setup-recovery-attempts').exists()


@pytest.mark.parametrize('change',['employee','registration','facts','dc'])
def test_effect_service_refuses_live_snapshot_drift(tmp_path,change):
    from test_setup_recovery_planning import RUN,COMPUTER_GUID
    service,paths,machine,user,computer,facts=service_scenario(tmp_path);previous=service.runtime.runner
    def runner(command,**options):
        result=previous(command,**options)
        if change=='employee':user['state']='disabled'
        elif change=='registration':machine.raw['revision']=99
        elif change=='facts':facts['snapshot']['clock_synchronized']=False
        else:computer['dc']['dns_hostname']='other.sosnadmin.local'
        return result
    service.runtime.runner=runner
    with pytest.raises(ControlError):service.plan(RUN,COMPUTER_GUID)


def test_effect_service_rechecks_sources_after_final_snapshot(tmp_path,monkeypatch):
    from test_setup_recovery_planning import RUN,COMPUTER_GUID
    service,*_=service_scenario(tmp_path);original_snapshot=service.planning.snapshot;count=0
    def snapshot(*args):
        nonlocal count
        value=original_snapshot(*args);count+=1
        if count==4:monkeypatch.setattr(service.runtime,'_sources',lambda:['changed']*8)
        return value
    monkeypatch.setattr(service.planning,'snapshot',snapshot)
    with pytest.raises(ControlError):service.plan(RUN,COMPUTER_GUID)
