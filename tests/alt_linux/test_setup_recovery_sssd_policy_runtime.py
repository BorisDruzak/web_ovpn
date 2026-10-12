from __future__ import annotations

import json
import shlex

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_replace
from test_setup_recovery_kerberos_runtime import scenario as kerberos_fixture


def scenario(root):
    from alt_deploy.setup_recovery_sssd_policy_runtime import RecoverySSSDPolicyRuntime
    previous,imported,context,calls=kerberos_fixture(root)
    previous.prove_once('plan','a'*64);calls.clear()
    runtime=RecoverySSSDPolicyRuntime(kerberos_runtime=previous)
    def runner(command,**options):
        calls.append((command,options))
        from alt_deploy import setup_recovery_sssd_policy as policy,setup_recovery_backup as backup
        request=json.loads(options['input_text'])['request']
        meta=request['kerberos_request']['import_request']['rehearsal_request']['metadata']
        return 0,json.dumps(policy._receipt(request,{},policy._snippet(meta),backup)),'SYNTHETIC_DIAGNOSTICS'
    runtime.runner=runner
    return runtime,previous,context,calls


def test_once_only_policy_transport_and_retained_verify(tmp_path):
    runtime,previous,context,calls=scenario(tmp_path)
    receipt=runtime.install_once('plan','a'*64)
    assert receipt['status']=='sssd_policy_prepared' and receipt['trust_verified'] is False
    command,options=calls[0]
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null'] and command[-2]=='ansible@192.0.2.10'
    for option in ('StrictHostKeyChecking=yes','BatchMode=yes','IdentitiesOnly=yes','ProxyJump=none','ProxyCommand=none'):
        assert option in command
    wire=json.loads(options['input_text']);request=wire['request']
    assert set(wire)=={'request','service_request','service_receipt','_worker'}
    assert request['source_sha256']==digest(runtime._sources())
    assert request['kerberos_request']['source_sha256']==digest(previous._sources())
    assert request['kerberos_request']['import_request']['source_sha256']==digest(previous.import_runtime._sources())
    compile(shlex.split(command[-1])[-1],'<fixed-policy-worker>','exec')
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert len(calls)==1
    assert runtime.verify('plan','a'*64)==receipt


@pytest.mark.parametrize('change',['proof_intent','proof_result','missing_proof','dc','nonzero','duplicate','guid','kvno',
    'snippet','trust','tools','extra','history_after','sources_after','dc_after','intent_after','proof_after'])
def test_changed_or_failed_policy_transport_is_never_success_or_replayed(tmp_path,monkeypatch,change):
    runtime,previous,context,calls=scenario(tmp_path)
    pair={key:context['payload'][key] for key in ('failed_run_id','computer_guid')}
    path=lambda suffix:runtime.attempts._path(**pair,suffix=suffix)
    if change=='proof_intent':private_replace(path('.kerberos-intent.json'),{'schema_version':1})
    elif change=='proof_result':private_replace(path('.kerberos-result.json'),{'schema_version':1})
    elif change=='missing_proof':path('.kerberos-result.json').unlink()
    elif change=='dc':previous.resolver=lambda hostname:'203.0.113.9'
    original=runtime.runner
    def changed(*args,**options):
        rc,out,err=original(*args,**options)
        if change=='nonzero':rc=1
        elif change=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif change in ('guid','kvno','snippet','trust','tools','extra'):
            result=json.loads(out)
            if change=='guid':result['computer_guid']='ffffffff-ffff-ffff-ffff-ffffffffffff'
            elif change=='kvno':result['kvno']+=1
            elif change=='snippet':result['snippet_sha256']='f'*64
            elif change=='trust':result['trust_verified']=True
            elif change=='tools':result['tools_sha256']='bad'
            else:result['command']='reset'
            out=json.dumps(result)
        elif change=='history_after':context['preparation']['local_rehearsal']['request_sha256']='f'*64
        elif change=='sources_after':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*10)
        elif change=='dc_after':previous.resolver=lambda hostname:'203.0.113.9'
        elif change=='intent_after':private_replace(path('.sssd-policy-intent.json'),{'schema_version':1})
        elif change=='proof_after':private_replace(path('.kerberos-result.json'),{'schema_version':1})
        return rc,out,err
    runtime.runner=changed
    with pytest.raises(ControlError) as caught:runtime.install_once('plan','a'*64)
    assert 'SYNTHETIC_DIAGNOSTICS' not in str(caught.value)
    count=len(calls)
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert len(calls)==count


def test_lock_spans_install_and_retained_verification(tmp_path):
    import fcntl,os
    runtime,previous,context,calls=scenario(tmp_path);original=runtime.runner
    def checked(*args,**options):
        fd=os.open(runtime.settings.lock_file,os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(fd)
        return original(*args,**options)
    runtime.runner=checked
    runtime.install_once('plan','a'*64);runtime.verify('plan','a'*64)


def test_directory_drift_during_receipt_persistence_is_terminal(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    runtime,previous,context,calls=scenario(tmp_path)
    terminal=[];runtime.attempts.finish=lambda **options:terminal.append(options)
    original=RecoveryControllerBackup._persist
    def changed(path,value):
        original(path,value)
        if str(path).endswith('.sssd-policy-result.json'):context['directory_result']['kvno']+=1
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',changed)
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert len(calls)==1 and len(terminal)==1 and terminal[0]['error_code']=='recovery_sssd_policy_failed'
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert len(calls)==1


@pytest.mark.parametrize('change',['history','expiry','proof'])
def test_final_source_read_drift_refuses_remote_policy_install(tmp_path,change):
    runtime,previous,context,calls=scenario(tmp_path)
    pair={key:context['payload'][key] for key in ('failed_run_id','computer_guid')}
    original_load=previous.import_runtime.postwrite.load;expired=False;reads=0
    def load(*args):
        if expired:raise ValueError('expired plan')
        return original_load(*args)
    previous.import_runtime.postwrite.load=load
    original=runtime._sources
    def sources():
        nonlocal expired,reads
        result=original();reads+=1
        if reads==4:
            if change=='history':context['preparation']['local_rehearsal']['request_sha256']='f'*64
            elif change=='expiry':expired=True
            else:private_replace(runtime.attempts._path(**pair,suffix='.kerberos-result.json'),{'schema_version':1})
        return result
    runtime._sources=sources
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert reads==4 and calls==[]


@pytest.mark.parametrize('change',[None,'wire','units'])
def test_generated_worker_uses_real_policy_evidence_without_auth_or_service_actions(tmp_path,monkeypatch,change):
    import contextlib,copy,io,os,sys
    from test_setup_recovery_sssd_policy import scenario as worker_fixture
    from alt_deploy import setup_recovery_services as services
    if os.geteuid()!=0:pytest.skip('fixed worker integration requires root-owned evidence')
    runtime,previous,context,calls=scenario(tmp_path/'controller')
    policy,request,args,native_calls=worker_fixture(tmp_path/'worker')
    sources=runtime._sources();request['source_sha256']=digest(sources)
    snapshot=copy.deepcopy(context['services_preparation']['services'])
    bound=previous._context('plan','a'*64)
    wire=dict(request=request,service_request=bound['service_request'],service_receipt=bound['service_receipt'])
    hashes={key:digest(value) for key,value in wire.items()}
    if change=='wire':wire['request']['kerberos_receipt']['kvno']+=1
    elif change=='units':snapshot['units'][services.UNITS[0]]['properties']['ActiveState']='active'
    def execute(action):
        program=runtime._script(action,sources,request['source_sha256'],hashes)
        injection='''probe.collect = fixture_collect
process.bounded_recovery_run = fixture_runner
services.snapshot = lambda **kw: fixture_snapshot
original_install = policy.install_once
policy.install_once = lambda request,**kw: original_install(request,root=fixture_root,owner=0,**kw)
original_verify = policy.verify
policy.verify = lambda request,**kw: original_verify(request,root=fixture_root,owner=0,**kw)
'''
        program=program.replace('try:\n    raw = sys.stdin.buffer.read',injection+'try:\n    raw = sys.stdin.buffer.read',1)
        from alt_deploy.setup_recovery_source_stdin import build_source_stdin
        program,encoded=build_source_stdin(program,wire)
        output=io.StringIO()
        with monkeypatch.context() as patched,contextlib.redirect_stdout(output):
            patched.setattr(sys,'stdin',type('Input',(),{'buffer':io.BytesIO(encoded.encode())})())
            try:
                exec(compile(program,'<fixed-policy-worker>','exec'),dict(fixture_collect=args['collect'],
                    fixture_runner=args['runner'],fixture_root=args['root'],fixture_snapshot=snapshot))
                rc=0
            except SystemExit as stopped:rc=stopped.code
        return rc,json.loads(output.getvalue())
    rc,result=execute('install')
    if change is None:
        assert rc==0 and result['status']=='sssd_policy_prepared' and result['trust_verified'] is False
        assert execute('verify')==(0,result)
    else:
        assert rc==1 and result=={'schema_version':1,'error_code':'recovery_sssd_policy_failed'}
        assert not (args['root']/policy.SNIPPET.lstrip('/')).exists()
    assert not any(command[0]=='/usr/bin/kinit' or 'start' in command or 'stop' in command for command,options in native_calls)
