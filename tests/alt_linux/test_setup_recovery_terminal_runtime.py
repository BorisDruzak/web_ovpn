import copy,json,subprocess,sys
import pytest
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest

def scenario(root):
    from test_setup_recovery_user_runtime import scenario as user_fixture
    from alt_deploy.setup_recovery_terminal_runtime import RecoveryTerminalRuntime
    user,startup,calls,native,receipt,parent,employee,scope=user_fixture(root)
    user.check_once(startup['plan_id'],startup['plan_sha256']);sent=[];identity={'kvno':receipt['kvno'],'employee':employee};approval=['a'*64]
    def authority(plan_id,sha,source):
        return dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=source,approval_sha256=approval[0],effects_sha256='b'*64,
            baseline=dict(schema_version=1,original_sha256='c'*64,tools_sha256='d'*64,configured_values={},defaults_verified=False,running_policy_verified=False,trust_verified=False),terminal_units={'smb.service':{},'nmb.service':{}},runtime_dependencies={path:{'present':True} for path in __import__('alt_deploy.setup_recovery_terminal',fromlist=['DEPENDENCIES']).DEPENDENCIES},environment_files={'/etc/sysconfig/sssd':{'present':False},'/etc/sysconfig/samba':{'present':False}},credential_cache={'present':False},daemon_links={path:dict(uid=0,gid=0,mode=0o777,size=len(target),target=target) for path,target in __import__('alt_deploy.setup_recovery_terminal',fromlist=['DAEMON_LINKS']).DAEMON_LINKS.items()})
    def runner(command,**options):
        sent.append((command,options));request=json.loads(options['input_text'])['request'];old=request['user_request']['startup_request']['policy_request']['kerberos_request']['import_request']['directory_result']
        result=dict({k:old[k] for k in ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno')},schema_version=1,status='normal_policy_handoff_succeeded',request_sha256=digest(request),identity_sha256=request['identity_sha256'],invocation_id='b'*32,main_pid=321,n_restarts=0,services_sha256='e'*64,unit_sha256='e'*64,trust_tools_sha256='e'*64,nss_tools_sha256='e'*64,local_passwd_sha256='e'*64,employee=employee,uid=100100,gid=100100,native_trust_verified=True,native_peer_pinning_verified=False,credential_continuity='unchanged',temporary_policy_retained=False,login_verified=False,online_user_authentication_verified=False)
        return 0,json.dumps(result),'PRIVATE'
    runtime=RecoveryTerminalRuntime(user_runtime=user,authorization=authority,identity=lambda *args:copy.deepcopy(identity),runner=runner)
    return runtime,startup,sent,identity,approval

def test_terminal_transport_once_retained_verify_and_strict_ssh(tmp_path):
    runtime,startup,sent,identity,approval=scenario(tmp_path);plan=startup['plan_id'];sha=startup['plan_sha256']
    result=runtime.handoff_once(plan,sha)
    command,options=sent[0]
    assert len(command[-1].encode())<8192 and 'StrictHostKeyChecking=yes' in command and 'PermitLocalCommand=no' in command
    assert runtime.verify(plan,sha)==result
    with pytest.raises(ControlError):runtime.handoff_once(plan,sha)
    assert len(sent)==2

@pytest.mark.parametrize('change',['rc','renewal','identity','authority','invocation','extra','duplicate'])
def test_terminal_controller_ambiguity_permanently_excludes_attempt(tmp_path,change):
    runtime,startup,sent,identity,approval=scenario(tmp_path);previous=runtime.runner
    def changed(command,**options):
        rc,out,err=previous(command,**options);value=json.loads(out)
        if change=='rc':rc=1
        elif change=='renewal':value['kvno']+=1
        elif change=='identity':identity['kvno']+=1
        elif change=='authority':approval[0]='f'*64
        elif change=='invocation':value['invocation_id']=startup.get('invocation_id','a'*32)
        elif change=='extra':value['password']='PRIVATE'
        else:return rc,out[:-1]+',"schema_version":1}',err
        return rc,json.dumps(value),err
    runtime.runner=changed
    with pytest.raises(ControlError):runtime.handoff_once(startup['plan_id'],startup['plan_sha256'])
    with pytest.raises(ControlError):runtime.handoff_once(startup['plan_id'],startup['plan_sha256'])
    assert len(sent)==1

def test_real_bootstrap_rejects_tampered_source_before_execution(tmp_path):
    from alt_deploy import setup_recovery_terminal_wire as wire
    runtime,startup,sent,identity,approval=scenario(tmp_path);context=runtime._context(startup['plan_id'],startup['plan_sha256'])
    script,encoded=wire.build('handoff',context['sources'],context['request'])
    value=json.loads(encoded);value['sources']['terminal']='raise RuntimeError("PRIVATE")'
    result=subprocess.run([sys.executable,'-I','-B','-c',script],input=json.dumps(value),text=True,capture_output=True)
    assert result.returncode==1 and 'PRIVATE' not in result.stdout+result.stderr

def test_failed_fresh_terminal_verify_excludes_all_subsequent_transport(tmp_path):
    runtime,startup,sent,identity,approval=scenario(tmp_path)
    runtime.handoff_once(startup['plan_id'],startup['plan_sha256'])
    previous=runtime.runner
    def failing(command,**options):
        previous(command,**options);return 1,'{}','PRIVATE'
    runtime.runner=failing
    with pytest.raises(ControlError):runtime.verify(startup['plan_id'],startup['plan_sha256'])
    with pytest.raises(ControlError):runtime.verify(startup['plan_id'],startup['plan_sha256'])
    assert len(sent)==2

def test_final_upstream_context_cannot_revoke_terminal_authority_before_ssh(tmp_path):
    runtime,startup,sent,identity,approval=scenario(tmp_path);previous=runtime.user_runtime._context;observations=[]
    def changed(*args):
        value=previous(*args);observations.append(True)
        if len(observations)==2:approval[0]='f'*64
        return value
    runtime.user_runtime._context=changed
    with pytest.raises(ControlError):runtime.handoff_once(startup['plan_id'],startup['plan_sha256'])
    assert sent==[]
