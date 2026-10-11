from __future__ import annotations

import json
import shlex
from unittest.mock import patch

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_replace
from test_setup_recovery_import_runtime import scenario as import_fixture


def scenario(root):
    from alt_deploy.setup_recovery_kerberos_runtime import RecoveryKerberosRuntime
    import test_setup_recovery_backup as facts
    original=facts.scenario
    def reviewed(directory):
        probe,calls,values,runner=original(directory)
        (directory/'usr/bin/klist').chmod(0o755)
        def read(command):
            if command[:3]==['/usr/bin/rpm','-qf','/usr/bin/klist']:return 'krb5-kinit 1.21.3-alt2.1'
            return runner(command)
        return probe,calls,values,read
    with patch.object(facts,'scenario',reviewed):imported,context,calls,files,data=import_fixture(root)
    from types import SimpleNamespace
    context['payload']['snapshot']['prerequisites']={'source_sha256':'b'*64}
    imported.postwrite.fingerprint=lambda:'b'*64
    imported.postwrite.service_gate.preparation.plans=SimpleNamespace(
        load=lambda *args:{'payload':imported.postwrite.load(*args)['payload']})
    imported.install_once('plan','a'*64)
    calls.clear()
    imported.credentials.open=lambda **kw:pytest.fail('Kerberos transport opened Vault')
    runtime=RecoveryKerberosRuntime(import_runtime=imported,resolver=lambda hostname:context['preparation']['rehearsal_metadata']['dc_address'])
    def runner(command,**options):
        calls.append((command,options))
        from alt_deploy import setup_recovery_kerberos as kerberos,setup_recovery_backup as backup
        request=json.loads(options['input_text'])['request']
        result=kerberos._receipt(request,{},request['import_request']['rehearsal_request']['metadata'],backup)
        return 0,json.dumps(result),'SYNTHETIC_DIAGNOSTICS'
    runtime.runner=runner
    return runtime,imported,context,calls


def test_once_only_bound_proof_and_readonly_retained_verification(tmp_path):
    runtime,imported,context,calls=scenario(tmp_path)
    receipt=runtime.prove_once('plan','a'*64)
    assert receipt['trust_verified'] is False and receipt['status']=='machine_keytab_authenticated'
    command,options=calls[0]
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null'] and command[-2]=='ansible@192.0.2.10'
    assert set(json.loads(options['input_text']))=={'request','service_request','service_receipt'}
    request=json.loads(options['input_text'])['request']
    assert request['import_request']['source_sha256']==digest(imported._sources())
    assert request['source_sha256']==digest(runtime._sources())
    compile(shlex.split(command[-1])[-1],'<fixed-kerberos-worker>','exec')
    with pytest.raises(ControlError):runtime.prove_once('plan','a'*64)
    assert len(calls)==1
    assert runtime.verify('plan','a'*64)==receipt


@pytest.mark.parametrize('change',['import_intent','import_result','missing_result','dc','nonzero','duplicate',
    'principal','trust','tool_hash','extra','history_after','source_after','dc_after','intent_after','result_after'])
def test_unbound_changed_or_failed_proof_never_succeeds_or_replays(tmp_path,monkeypatch,change):
    runtime,imported,context,calls=scenario(tmp_path)
    pair={key:context['payload'][key] for key in ('failed_run_id','computer_guid')}
    path=lambda suffix:runtime.attempts._path(**pair,suffix=suffix)
    if change=='import_intent':private_replace(path('.local-import-intent.json'),{'schema_version':1})
    elif change=='import_result':private_replace(path('.local-import-result.json'),{'schema_version':1})
    elif change=='missing_result':path('.local-import-result.json').unlink()
    elif change=='dc':runtime.resolver=lambda hostname:'203.0.113.9'
    original=runtime.runner
    def changed(*a,**kw):
        rc,out,err=original(*a,**kw)
        if change=='nonzero':rc=1
        elif change=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif change in ('principal','trust','tool_hash','extra'):
            result=json.loads(out)
            if change=='principal':result['principal']='OTHER$@SOSNADMIN.LOCAL'
            elif change=='trust':result['trust_verified']=True
            elif change=='tool_hash':result['tools_sha256']='bad'
            else:result['command']='reset'
            out=json.dumps(result)
        elif change=='history_after':context['preparation']['local_rehearsal']['request_sha256']='f'*64
        elif change=='source_after':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*9)
        elif change=='dc_after':runtime.resolver=lambda hostname:'203.0.113.9'
        elif change=='intent_after':private_replace(path('.kerberos-intent.json'),{'schema_version':1})
        elif change=='result_after':private_replace(path('.local-import-result.json'),{'schema_version':1})
        return rc,out,err
    runtime.runner=changed
    with pytest.raises(ControlError) as caught:runtime.prove_once('plan','a'*64)
    assert 'SYNTHETIC_DIAGNOSTICS' not in str(caught.value)
    count=len(calls)
    with pytest.raises(ControlError):runtime.prove_once('plan','a'*64)
    assert len(calls)==count


def test_lifecycle_lock_spans_remote_proof_and_retained_verification(tmp_path):
    import fcntl
    import os
    runtime,imported,context,calls=scenario(tmp_path)
    original=runtime.runner
    def checked(*a,**kw):
        fd=os.open(runtime.settings.lock_file,os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(fd)
        return original(*a,**kw)
    runtime.runner=checked
    runtime.prove_once('plan','a'*64)
    runtime.verify('plan','a'*64)


def test_context_drift_during_receipt_persistence_is_terminal(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    runtime,imported,context,calls=scenario(tmp_path)
    terminal=[];runtime.attempts.finish=lambda **kw:terminal.append(kw)
    original=RecoveryControllerBackup._persist
    def changed(path,value):
        original(path,value)
        if str(path).endswith('.kerberos-result.json'):
            context['directory_result']['kvno']+=1
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',changed)
    with pytest.raises(ControlError):runtime.prove_once('plan','a'*64)
    assert len(calls)==1 and len(terminal)==1
    assert terminal[0]['status']=='failed' and terminal[0]['error_code']=='recovery_kerberos_failed'
    with pytest.raises(ControlError):runtime.prove_once('plan','a'*64)
    assert len(calls)==1


@pytest.mark.parametrize('change',[None,'wire','units'])
def test_generated_program_runs_real_isolated_machine_proof_and_retained_verifier(tmp_path,monkeypatch,change):
    import contextlib
    import copy
    import io
    import os
    import sys
    from test_setup_recovery_kerberos import scenario as worker_fixture,NOW
    from alt_deploy.setup_recovery_kerberos_runtime import RecoveryKerberosRuntime
    from alt_deploy import setup_recovery_services as services
    if os.geteuid()!=0:pytest.skip('fixed worker integration requires root-owned evidence')
    runtime,imported,context,calls=scenario(tmp_path/'controller')
    data,request,native_runner,native_calls=worker_fixture(tmp_path/'worker')
    sources=runtime._sources();request['source_sha256']=digest(sources)
    snapshot=copy.deepcopy(context['services_preparation']['services'])
    wire=dict(request=request,service_request=imported._context('plan','a'*64)['service_request'],
        service_receipt=context['services_receipt'])
    hashes={key:digest(value) for key,value in wire.items()}
    if change=='wire':wire['request']['import_receipt']['kvno']+=1
    elif change=='units':snapshot['units'][services.UNITS[0]]['properties']['ActiveState']='active'
    def execute(action):
        program=RecoveryKerberosRuntime._script(action,sources,request['source_sha256'],hashes)
        injection='''probe.collect = fixture_collect
process.bounded_recovery_run = fixture_runner
services.snapshot = lambda **kw: fixture_snapshot
original_prove = kerberos.prove_once
kerberos.prove_once = lambda request,**kw: original_prove(request,root=fixture_root,owner=0,clock=lambda:fixture_now,**kw)
original_verify = kerberos.verify
kerberos.verify = lambda request,**kw: original_verify(request,root=fixture_root,owner=0,**kw)
'''
        program=program.replace('try:\n    raw = sys.stdin.buffer.read',injection+'try:\n    raw = sys.stdin.buffer.read',1)
        output=io.StringIO()
        with monkeypatch.context() as patched,contextlib.redirect_stdout(output):
            patched.setattr(sys,'stdin',type('Input',(),{'buffer':io.BytesIO(json.dumps(wire).encode())})())
            try:
                exec(compile(program,'<fixed-kerberos-worker>','exec'),dict(fixture_collect=data['collect'],
                    fixture_runner=native_runner,fixture_root=data['root'],fixture_now=NOW,fixture_snapshot=snapshot))
                rc=0
            except SystemExit as stopped:rc=stopped.code
        return rc,json.loads(output.getvalue())
    rc,result=execute('prove')
    if change is None:
        assert rc==0 and result['status']=='machine_keytab_authenticated' and result['trust_verified'] is False
        before=sum(command[0]=='/usr/bin/kinit' for command,options in native_calls)
        assert execute('verify')==(0,result)
        assert sum(command[0]=='/usr/bin/kinit' for command,options in native_calls)==before==1
    else:
        assert rc==1 and result=={'schema_version':1,'error_code':'recovery_kerberos_failed'}
        assert not any(command[0]=='/usr/bin/kinit' for command,options in native_calls)
    assert not list((data['root']/'var/lib/alt-deploy-recovery').glob('kerberos-*/cache-*'))


@pytest.mark.parametrize('change',['history','expiry'])
def test_final_resolver_drift_refuses_remote_authentication(tmp_path,change):
    runtime,imported,context,calls=scenario(tmp_path)
    original_load=imported.postwrite.load;expired=False;resolutions=0
    def load(*args):
        if expired:raise ValueError('expired plan')
        return original_load(*args)
    imported.postwrite.load=load
    original_resolver=runtime.resolver
    def resolver(hostname):
        nonlocal expired,resolutions
        resolutions+=1
        if resolutions==2:
            if change=='history':context['preparation']['local_rehearsal']['request_sha256']='f'*64
            else:expired=True
        return original_resolver(hostname)
    runtime.resolver=resolver
    with pytest.raises(ControlError):runtime.prove_once('plan','a'*64)
    assert resolutions==2 and calls==[]
