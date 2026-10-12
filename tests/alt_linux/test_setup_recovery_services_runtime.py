from __future__ import annotations

import json
import shlex
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from test_setup_recovery_services import scenario as fixture
from test_setup_recovery_state import RUN, GUID


def scenario(root):
    from alt_deploy.setup_recovery_services_runtime import RecoveryServicesRuntime
    data, request, states, native_calls = fixture(root)
    identity = {key: request['backup_request'][key] for key in ('machine_uuid', 'claim_sha256')}
    calls = []
    def runner(command, **options):
        calls.append((command, options))
        wire = json.loads(options['input_text'])
        if 'request' in wire:
            from alt_deploy import setup_recovery_services as services
            result = services._receipt(wire['request'], backup=data['backup'])
        else:
            result = request['services']
        return 0, json.dumps(result), 'SYNTHETIC_SECRET_STDERR'
    settings = SimpleNamespace(state_root=root, known_hosts_file=root/'known_hosts', private_key_file=root/'key')
    runtime = RecoveryServicesRuntime(settings, runner=runner,
        credentials=SimpleNamespace(_reservation=lambda **pair: dict(identity)))
    machine = SimpleNamespace(uuid=identity['machine_uuid'], hostname=request['backup_request']['hostname'], ip='192.0.2.10')
    # Build the fixture's backup using the same protected source-derived request.
    facts = request['backup_request']['facts']
    bound = runtime.backup_request(machine, RUN, GUID, facts)
    pair = {'failed_run_id': RUN, 'computer_guid': GUID}
    from alt_deploy.setup_plans import digest
    receipt = {key: bound[key] for key in ('schema_version','failed_run_id','computer_guid','claim_sha256','machine_uuid','snapshot_sha256','source_sha256')}
    receipt['backup_id'] = 'backup-' + digest(pair)
    receipt['manifest_sha256'] = digest({'schema_version':1,'request':bound,'backup_id':receipt['backup_id']})
    return runtime, machine, bound, receipt, request['services'], calls, identity, data, states


@pytest.mark.parametrize('action', ['capture_services','quiesce_services','verify_services'])
def test_fixed_service_transport_has_no_operator_command_or_secret(tmp_path, action):
    runtime,machine,bound,receipt,snapshot,calls,_,_,_=scenario(tmp_path)
    args=(machine,RUN,GUID,bound,receipt)
    result=getattr(runtime,action)(*args,*(() if action=='capture_services' else (snapshot,)))
    command,options=calls[0]
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null']
    for value in ('StrictHostKeyChecking=yes','BatchMode=yes','IdentitiesOnly=yes','ProxyCommand=none','ProxyJump=none'):
        assert value in command
    assert command[-2]=='ansible@192.0.2.10' and '-I -B -c' in command[-1]
    assert options['timeout']==360 and 'SYNTHETIC_SECRET' not in str(result)
    wire=json.loads(options['input_text'])
    assert set(wire)==(({'backup_request','backup_receipt','source_sha256'} if action=='capture_services' else {'request'})|{'_worker'})
    assert 'SYNTHETIC_SECRET' not in options['input_text']
    compile(shlex.split(command[-1])[-1],'<fixed-services-wire>','exec')
    assert result==snapshot if action=='capture_services' else result['status']=='services_quiesced'


@pytest.mark.parametrize('failure',['ip','uuid','hostname','claim','backup','snapshot','schema','receipt','duplicate','nonzero','diagnostic','claim_after','source_after'])
def test_changed_or_failed_service_transport_never_returns_success(tmp_path,monkeypatch,failure):
    runtime,machine,bound,receipt,snapshot,calls,identity,_,_=scenario(tmp_path)
    if failure=='ip':machine.ip='--ProxyCommand=bad'
    elif failure=='uuid':machine.uuid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    elif failure=='hostname':machine.hostname='other-host'
    elif failure=='claim':identity['claim_sha256']='f'*64
    elif failure=='backup':receipt['manifest_sha256']='f'*64
    elif failure=='snapshot':snapshot['machine_uuid']='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    elif failure=='schema':snapshot['schema_version']=True
    original=runtime.runner
    def changed(*args,**kwargs):
        rc,out,err=original(*args,**kwargs)
        if failure=='receipt':out='{}'
        elif failure=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif failure=='nonzero':rc=1
        elif failure=='diagnostic':raise RuntimeError('SYNTHETIC_SECRET')
        elif failure=='claim_after':identity['claim_sha256']='f'*64
        elif failure=='source_after':
            import alt_deploy.setup_recovery_services_runtime as module
            monkeypatch.setattr(module,'_read_source',lambda *a,**k:'changed')
        return rc,out,err
    runtime.runner=changed
    with pytest.raises(ControlError) as caught:
        runtime.quiesce_services(machine,RUN,GUID,bound,receipt,snapshot)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    if failure in ('ip','uuid','hostname','claim','backup','snapshot','schema'):assert calls==[]


def test_generated_stop_and_verify_workers_use_real_isolated_producers(tmp_path,monkeypatch):
    import contextlib
    import io
    import os
    import sys
    runtime,machine,bound,receipt,snapshot,calls,_,data,states=scenario(tmp_path)
    # The fixture's backup uses a different source hash; create the actual bound
    # backup in a separate private root rather than alter an existing receipt.
    from test_setup_recovery_backup import fixture as backup_fixture
    root=tmp_path/'worker-root';root.mkdir()
    backup,original,collect=backup_fixture(root)
    backup.create(bound,collect=collect,root=root,owner=os.geteuid())
    # Copy only synthetic fixture executables/units to the isolated worker root.
    import shutil
    shutil.copytree(tmp_path/'usr',root/'usr',dirs_exist_ok=True)
    service_runner=data['runner']
    def execute(command,**options):
        frame=json.loads(options['input_text']);program=frame.pop('_worker')
        injection='''probe.collect = fixture_collect
original_snapshot = services.snapshot
original_quiesce = services.quiesce_once
original_verify = services.verify
services.snapshot = lambda **kw: original_snapshot(backup=backup,probe=probe,collect=fixture_collect,runner=fixture_runner,root=fixture_root,owner=fixture_owner)
services.quiesce_once = lambda request,**kw: original_quiesce(request,backup=backup,probe=probe,importer=importer,collect=fixture_collect,runner=fixture_runner,root=fixture_root,owner=fixture_owner)
services.verify = lambda request,**kw: original_verify(request,backup=backup,probe=probe,collect=fixture_collect,runner=fixture_runner,root=fixture_root,owner=fixture_owner)
original_backup_verify = backup.verify
backup.verify = lambda request,**kw: original_backup_verify(request,root=fixture_root,owner=fixture_owner)
'''
        program=program.replace('try:\n    raw = sys.stdin.buffer.read',injection+'try:\n    raw = sys.stdin.buffer.read',1)
        from alt_deploy.setup_recovery_source_stdin import build_source_stdin
        program,encoded=build_source_stdin(program,frame)
        output=io.StringIO()
        with monkeypatch.context() as patch,contextlib.redirect_stdout(output):
            patch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(encoded.encode())))
            exec(compile(program,'<fixed-services-worker>','exec'),{'fixture_collect':collect,
                'fixture_runner':service_runner,'fixture_root':root,'fixture_owner':os.geteuid()})
        return 0,output.getvalue(),''
    runtime.runner=execute
    args=(machine,RUN,GUID,bound,receipt)
    captured=runtime.capture_services(*args)
    stopped=runtime.quiesce_services(*args,captured)
    assert runtime.verify_services(*args,captured)==stopped
    assert states['smb.service']['ActiveState']=='inactive'
    assert states['nmb.service']['ActiveState']=='inactive'
