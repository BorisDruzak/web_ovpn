from __future__ import annotations

import copy,json
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from test_setup_recovery_policy_baseline import scenario as baseline_fixture


def scenario(root):
    from alt_deploy.setup_recovery_policy_baseline_runtime import RecoveryPolicyBaselineRuntime
    request,args,_,values=baseline_fixture(root)
    frame=request['backup_request'];facts=frame['facts']
    machine=SimpleNamespace(uuid=frame['machine_uuid'],hostname=frame['hostname'],ip='192.0.2.10',raw={'revision':1})
    snapshot=dict(failed_run_id=frame['failed_run_id'],computer_guid=frame['computer_guid'],machine_uuid=machine.uuid,
        machine=dict(uuid=machine.uuid,hostname=machine.hostname,ip=machine.ip,registration_sha256=digest(machine.raw)),
        workstation_facts=dict(snapshot=copy.deepcopy(facts),snapshot_sha256=digest(facts)))
    calls=[]
    def runner(command,**options):
        wire=json.loads(options['input_text']);calls.append((command,options));bound=wire['request']
        result=dict(schema_version=1,status='original_sssd_policy_baseline',request_sha256=digest(bound),
            original_sha256=digest(bound['backup_request']['facts']['files']['/etc/sssd/sssd.conf']),
            tools_sha256='a'*64,configured_values=copy.deepcopy(values),defaults_verified=False,
            running_policy_verified=False,trust_verified=False)
        return 0,json.dumps(result),'SYNTHETIC_PRIVATE_OUTPUT'
    runtime=RecoveryPolicyBaselineRuntime(SimpleNamespace(known_hosts_file=root/'known_hosts',private_key_file=root/'key'),runner=runner)
    return runtime,machine,snapshot,request['metadata'],calls


def test_fixed_baseline_runtime_binds_registered_target_request_and_sources(tmp_path):
    runtime,machine,snapshot,metadata,calls=scenario(tmp_path)
    result=runtime.capture(machine,snapshot,metadata)
    assert result['projection']['running_policy_verified'] is False
    command,options=calls[0];request=json.loads(options['input_text'])['request']
    assert result['request_sha256']==digest(request)==result['receipt']['request_sha256']
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null']
    assert all(value in command for value in ('StrictHostKeyChecking=yes','ProxyJump=none','ProxyCommand=none','PermitLocalCommand=no','IdentitiesOnly=yes'))
    assert command[-2]=='ansible@192.0.2.10' and len(command[-1].encode())<8192 and options['timeout']==150
    assert request['backup_request']['claim_sha256']==digest(dict(schema_version=1,scope='original_policy_baseline_only',recovery_snapshot_sha256=digest(snapshot)))


@pytest.mark.parametrize('change',['uuid','hostname','address','registration','facts','metadata'])
def test_changed_target_or_request_refuses_before_ssh(tmp_path,change):
    runtime,machine,snapshot,metadata,calls=scenario(tmp_path)
    if change=='uuid':machine.uuid='changed'
    elif change=='hostname':machine.hostname='alt-a1-pc99'
    elif change=='address':machine.ip='192.0.2.99'
    elif change=='registration':machine.raw['revision']=2
    elif change=='facts':snapshot['workstation_facts']['snapshot_sha256']='0'*64
    else:metadata['hostname']='alt-a1-pc99'
    with pytest.raises(ControlError):runtime.capture(machine,snapshot,metadata)
    assert calls==[]


@pytest.mark.parametrize('change',['rc','extra','duplicate','oversize','request','original','claim','source_after','target_after'])
def test_baseline_runtime_refuses_malformed_reply_or_transport_drift(tmp_path,change,monkeypatch):
    runtime,machine,snapshot,metadata,calls=scenario(tmp_path);previous=runtime.runner
    def runner(command,**options):
        rc,out,err=previous(command,**options)
        if change=='rc':rc=1
        elif change=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif change=='oversize':out=' '*(16384+1)
        elif change=='source_after':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*7)
        elif change=='target_after':machine.raw['revision']=2
        else:
            value=json.loads(out)
            if change=='extra':value['command']='restart'
            elif change=='claim':value['defaults_verified']=True
            else:value['request_sha256' if change=='request' else 'original_sha256']='0'*64
            out=json.dumps(value)
        return rc,out,err
    runtime.runner=runner
    with pytest.raises(ControlError) as caught:runtime.capture(machine,snapshot,metadata)
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(caught.value)


def planning_scenario(root):
    from test_setup_recovery_planning import scenario as planning_fixture
    from alt_deploy.setup_recovery_policy_baseline_runtime import RecoveryPolicyBaselineService,RecoveryPolicyBaselineRuntime
    request,args,_,values=baseline_fixture(root/'workstation')
    build,paths,machine,user,computer,ou,observed,facts,ready,calls=planning_fixture(root/'controller')
    facts['snapshot']=copy.deepcopy(request['backup_request']['facts']);facts['snapshot_sha256']=digest(facts['snapshot'])
    computer['dc'].update({key:request['metadata'][source] for key,source in
        (('domain_guid','domain_guid'),('domain_sid','domain_sid'),('dns_hostname','dc_hostname'))})
    planning=build();planning.settings.lock_file=root/'controller'/'workstationctl.lock'
    def runner(command,**options):
        bound=json.loads(options['input_text'])['request']
        value=dict(schema_version=1,status='original_sssd_policy_baseline',request_sha256=digest(bound),
            original_sha256=digest(bound['backup_request']['facts']['files']['/etc/sssd/sssd.conf']),tools_sha256='a'*64,
            configured_values=copy.deepcopy(values),defaults_verified=False,running_policy_verified=False,trust_verified=False)
        return 0,json.dumps(value),''
    runtime=RecoveryPolicyBaselineRuntime(SimpleNamespace(known_hosts_file=root/'known_hosts',private_key_file=root/'key'),runner=runner)
    service=RecoveryPolicyBaselineService(planning,runtime=runtime,resolver=lambda name:request['metadata']['dc_address'])
    return service,paths,machine,user,computer,facts


def test_baseline_plan_preserves_history_and_does_not_reserve_attempt(tmp_path):
    from test_setup_recovery_planning import RUN,COMPUTER_GUID
    service,paths,*_=planning_scenario(tmp_path);before={key:path.read_bytes() for key,path in paths.items()}
    result=service.plan(RUN,COMPUTER_GUID)
    assert result['plan_id'].startswith('recovery-policy-baseline-') and result['payload']['execution_available'] is False
    assert result['payload']['projection']['defaults_verified'] is False
    assert not service.planning.attempts.root.exists()
    assert {key:path.read_bytes() for key,path in paths.items()}==before
    assert service.plans.load(result['plan_id'],result['sha256'])==result


def test_invalid_dc_hostname_is_rejected_before_resolver_callback(tmp_path):
    from test_setup_recovery_planning import RUN,COMPUTER_GUID
    service,paths,machine,user,computer,facts=planning_scenario(tmp_path);called=[]
    computer['dc']['dns_hostname']='other.example'
    service.resolver=lambda hostname:called.append(hostname) or '192.0.2.20'
    with pytest.raises(ControlError):service.plan(RUN,COMPUTER_GUID)
    assert called==[]


def test_baseline_service_rechecks_sources_after_final_directory_snapshot(tmp_path,monkeypatch):
    from test_setup_recovery_planning import RUN,COMPUTER_GUID
    service,*_=planning_scenario(tmp_path);previous=service.planning.snapshot;observed=[]
    def snapshot(*args):
        value=previous(*args);observed.append(True)
        if len(observed)==3:monkeypatch.setattr(service.runtime,'_sources',lambda:['changed']*7)
        return value
    service.planning.snapshot=snapshot
    with pytest.raises(ControlError):service.plan(RUN,COMPUTER_GUID)
    assert not service.plans.root.exists()


@pytest.mark.parametrize('change',['employee','registration','facts','dc'])
def test_baseline_service_refuses_drift_during_readonly_capture(tmp_path,change):
    from test_setup_recovery_planning import RUN,COMPUTER_GUID
    service,paths,machine,user,computer,facts=planning_scenario(tmp_path);previous=service.runtime.runner
    def runner(command,**options):
        result=previous(command,**options)
        if change=='employee':user['state']='disabled'
        elif change=='registration':machine.raw['revision']=2
        elif change=='facts':facts['snapshot']['clock_synchronized']=False;facts['snapshot_sha256']=digest(facts['snapshot'])
        else:computer['dc']['domain_guid']='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        return result
    service.runtime.runner=runner
    with pytest.raises(ControlError):service.plan(RUN,COMPUTER_GUID)
    assert not service.plans.root.exists() and not service.planning.attempts.root.exists()
