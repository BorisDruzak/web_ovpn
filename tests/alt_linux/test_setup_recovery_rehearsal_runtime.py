from __future__ import annotations

import json
import shlex
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_create
from test_setup_recovery_rehearsal import scenario as fixture
from test_setup_recovery_native import PASSWORD
from test_setup_recovery_state import RUN, GUID


def scenario(root):
    from alt_deploy.setup_recovery_rehearsal_runtime import RecoveryRehearsalRuntime
    backup, _, request, collector, native_runner, _ = fixture(root)
    identity = {'claim_sha256': request['backup_request']['claim_sha256'],
                'machine_uuid': request['backup_request']['machine_uuid']}
    sealed = {'sealed_sha256': 'd'*64, 'ciphertext': '$ANSIBLE_VAULT;1.1;AES256\n'}
    path = root/'sealed.json'; private_create(path, sealed)
    credentials = SimpleNamespace(_reservation=lambda **pair: dict(identity), path=lambda **pair: path,
                                  open=lambda **pair: PASSWORD)
    settings = SimpleNamespace(state_root=root, known_hosts_file=root/'known_hosts', private_key_file=root/'key')
    calls=[]
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        wire=json.loads(kwargs['input_text']); document=wire['request']
        from alt_deploy import setup_recovery_rehearsal as rehearsal
        return 0,json.dumps(rehearsal._receipt(document,backup=backup)),'SYNTHETIC_SECRET_STDERR'
    runtime = RecoveryRehearsalRuntime(settings, credentials=credentials, runner=runner)
    runtime._fixture_collector, runtime._fixture_native_runner = collector, native_runner
    machine = SimpleNamespace(uuid=identity['machine_uuid'],hostname=request['metadata']['hostname'],ip='192.0.2.10')
    return runtime,machine,request,calls,identity,path


@pytest.mark.parametrize('method', ['create_rehearsal', 'verify_rehearsal'])
def test_fixed_rehearsal_transport_binds_sealed_credential_backup_and_sources(tmp_path, method):
    runtime,machine,request,calls,_,_=scenario(tmp_path)
    receipt=getattr(runtime,method)(machine,RUN,GUID,request['backup_request'],request['backup_receipt'],request['metadata'])
    command,options=calls[0]
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null']
    assert 'StrictHostKeyChecking=yes' in command and '-I -B -c' in command[-1]
    assert PASSWORD not in str(command) and PASSWORD not in str(receipt)
    wire=json.loads(options['input_text'])
    assert wire.get('password')==PASSWORD if method=='create_rehearsal' else 'password' not in wire
    assert receipt['credential_sha256']=='d'*64
    compile(shlex.split(command[-1])[-1],'<fixed-rehearsal-wire>','exec')


@pytest.mark.parametrize('failure',['target','backup','cipher_before','claim_before','cipher_after','password_after','claim_after',
                                     'claim_final_open','nonzero','diagnostic','duplicate','receipt'])
def test_drift_or_unsafe_rehearsal_never_returns_success(tmp_path,failure):
    runtime,machine,request,calls,identity,path=scenario(tmp_path)
    original=runtime.runner
    if failure=='target':machine.uuid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    if failure=='backup':request['backup_receipt']['manifest_sha256']='f'*64
    if failure=='cipher_before':
        original_open=runtime.credentials.open
        def replaced(**pair):
            path.write_text(json.dumps({'sealed_sha256':'f'*64,'ciphertext':'changed'}))
            return original_open(**pair)
        runtime.credentials.open=replaced
    if failure=='claim_before':
        def replaced_claim(**pair):
            identity['claim_sha256']='f'*64
            return PASSWORD
        runtime.credentials.open=replaced_claim
    if failure=='claim_final_open':
        opened=[0]
        def replaced_final_claim(**pair):
            opened[0]+=1
            if opened[0]>1:identity['claim_sha256']='f'*64
            return PASSWORD
        runtime.credentials.open=replaced_final_claim
    def changed(*args,**kwargs):
        rc,stdout,stderr=original(*args,**kwargs)
        if failure=='cipher_after':path.write_text(json.dumps({'sealed_sha256':'f'*64,'ciphertext':'changed'}))
        if failure=='password_after':runtime.credentials.open=lambda **pair:'Aa9!'+'c'*64
        if failure=='claim_after':identity['claim_sha256']='f'*64
        if failure=='nonzero':rc=1
        if failure=='diagnostic':raise RuntimeError(PASSWORD)
        if failure=='duplicate':stdout=stdout[:-1]+',"schema_version":1}'
        if failure=='receipt':stdout='{}'
        return rc,stdout,stderr
    runtime.runner=changed
    with pytest.raises(ControlError) as caught:
        runtime.create_rehearsal(machine,RUN,GUID,request['backup_request'],request['backup_receipt'],request['metadata'])
    assert PASSWORD not in str(caught.value)
    if failure in ('target','backup','cipher_before','claim_before'):assert calls==[]


def test_generated_worker_executes_create_and_verify_in_isolated_fixture(tmp_path,monkeypatch):
    import contextlib
    import io
    import os
    import sys
    runtime,machine,request,calls,_,_=scenario(tmp_path)
    collector,native_runner=runtime._fixture_collector,runtime._fixture_native_runner
    def execute(command,**kwargs):
        program=shlex.split(command[-1])[-1]
        inject='''probe.collect = fixture_collect
original_create = rehearsal.create
original_verify = rehearsal.verify
rehearsal.create = lambda request,password,**kw: original_create(request,password,backup=backup,native=native,collect=fixture_collect,runner=fixture_runner,root=fixture_root,owner=fixture_owner)
rehearsal.verify = lambda request,**kw: original_verify(request,backup=backup,collect=fixture_collect,root=fixture_root,owner=fixture_owner)
'''
        program=program.replace('try:\n    raw = sys.stdin.buffer.read',inject+'try:\n    raw = sys.stdin.buffer.read',1)
        scope={'__name__':'fixture_worker','fixture_collect':collector,'fixture_runner':native_runner,
               'fixture_root':tmp_path,'fixture_owner':os.geteuid()}
        captured=io.StringIO()
        with monkeypatch.context() as patch,contextlib.redirect_stdout(captured):
            patch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(kwargs['input_text'].encode())))
            exec(compile(program,'<fixed-rehearsal-worker>','exec'),scope)
        return 0,captured.getvalue(),''
    runtime.runner=execute
    args=(machine,RUN,GUID,request['backup_request'],request['backup_receipt'],request['metadata'])
    created=runtime.create_rehearsal(*args)
    assert runtime.verify_rehearsal(*args)==created
    assert 'sandbox-' not in ''.join(str(path) for path in (tmp_path/'var/lib/alt-deploy-recovery').rglob('*'))
