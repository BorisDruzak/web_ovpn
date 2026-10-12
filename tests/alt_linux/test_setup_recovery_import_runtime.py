from __future__ import annotations

import copy
import json
import shlex
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from test_setup_recovery_import import scenario as local_fixture
from test_setup_recovery_native import PASSWORD


def scenario(root):
    from alt_deploy.setup_recovery_import_runtime import RecoveryImportRuntime
    data,_=local_fixture(root)
    request=data['request'];bound=request['rehearsal_request']['backup_request']
    identity={key:bound[key] for key in ('machine_uuid','claim_sha256')}
    credentials=SimpleNamespace(_reservation=lambda **kw:dict(identity),open=lambda **kw:PASSWORD)
    settings=SimpleNamespace(state_root=root,lock_file=root/'controller.lock',known_hosts_file=root/'known_hosts',private_key_file=root/'key')
    gate=SimpleNamespace(preparation=SimpleNamespace(credentials=credentials))
    postwrite=SimpleNamespace(service_gate=gate)
    runtime=RecoveryImportRuntime(settings,postwrite=postwrite)
    # Complete the synthetic context with the exact source-derived receipts.
    machine=SimpleNamespace(uuid=bound['machine_uuid'],hostname=bound['hostname'],ip='192.0.2.10')
    bound=runtime.backup_request(machine,bound['failed_run_id'],bound['computer_guid'],bound['facts'])
    from alt_deploy import setup_recovery_services as services
    snapshot=dict(schema_version=1,machine_uuid=machine.uuid,hostname=machine.hostname,systemctl={},
        systemd_package='systemd 258.9-alt1',dependencies={},units={unit:dict(unit_file={},
            properties={key:('inactive' if key=='ActiveState' else '') for key in services.PROPERTIES}) for unit in services.UNITS})
    sources=runtime._sources()
    backup_receipt=runtime._backup_receipt(bound)
    meta=request['rehearsal_request']['metadata']
    rehearsal_request=dict(schema_version=1,backup_request=bound,backup_receipt=backup_receipt,
        metadata=meta,credential_sha256=request['directory_result']['sealed_sha256'],source_sha256=digest(sources[:5]))
    from alt_deploy import setup_recovery_rehearsal as rehearsal, setup_recovery_backup as backup
    service_request=dict(schema_version=1,backup_request=bound,backup_receipt=backup_receipt,
        services=snapshot,services_sha256=digest(snapshot),source_sha256=digest([sources[i] for i in (0,1,3,6,7)]))
    context=dict(machine=machine,payload=dict(failed_run_id=bound['failed_run_id'],computer_guid=bound['computer_guid'],
        machine_uuid=machine.uuid,snapshot=dict(workstation_facts=dict(snapshot=bound['facts']),computer=dict(dc=dict(
            domain_guid=meta['domain_guid'],domain_sid=meta['domain_sid'],dns_hostname=meta['dc_hostname'])))),
        preparation=dict(backup_request=bound,workstation_backup=backup_receipt,rehearsal_metadata=meta,
            local_rehearsal=rehearsal._receipt(rehearsal_request,backup=backup)),
        credential_document=dict(sealed_sha256=request['directory_result']['sealed_sha256']),
        services_preparation=dict(services=snapshot,services_sha256=digest(snapshot)),
        services_receipt=services._receipt(service_request,backup=backup),directory_result=request['directory_result'])
    postwrite.load=lambda *a:copy.deepcopy(context)
    calls=[]
    files={path:dict(present=True,sha256='a'*64,size=100,uid=0,gid=bound['facts']['files'][path].get('gid',0),mode=0o600)
        for path in ('/var/lib/samba/private/secrets.tdb','/etc/krb5.keytab')}
    def runner(command,**options):
        calls.append((command,options))
        wire=json.loads(options['input_text'])
        from alt_deploy import setup_recovery_import as importer
        return 0,json.dumps(importer._receipt(wire['request'],files,backup=backup)),'SYNTHETIC_SECRET'
    runtime.runner=runner
    return runtime,context,calls,files,data


def test_once_only_fixed_import_and_readonly_verify(tmp_path):
    runtime,context,calls,files,data=scenario(tmp_path)
    receipt=runtime.install_once('plan','a'*64)
    assert receipt['trust_verified'] is False
    command,options=calls[0]
    assert command[:3]==['/usr/bin/ssh','-F','/dev/null']
    assert command[-2]=='ansible@192.0.2.10'
    for option in ('StrictHostKeyChecking=yes','BatchMode=yes','IdentitiesOnly=yes','ProxyJump=none','ProxyCommand=none'):
        assert option in command
    assert PASSWORD not in str(command) and PASSWORD not in str(receipt)
    assert set(json.loads(options['input_text']))=={'request','service_request','service_receipt','password','_worker'}
    compile(shlex.split(command[-1])[-1],'<fixed-import-worker>','exec')
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert len(calls)==1
    runtime.credentials.open=lambda **kw:pytest.fail('verify opened Vault')
    assert runtime.verify('plan','a'*64)==receipt
    assert 'password' not in json.loads(calls[-1][1]['input_text'])


@pytest.mark.parametrize('change',['backup','rehearsal','services','sid','ip','nonzero','duplicate','files','trust','history_after','source_after'])
def test_unbound_or_failed_import_is_never_success_or_replayed(tmp_path,monkeypatch,change):
    runtime,context,calls,files,data=scenario(tmp_path)
    if change=='backup':context['preparation']['workstation_backup']['manifest_sha256']='f'*64
    elif change=='rehearsal':context['preparation']['local_rehearsal']['request_sha256']='f'*64
    elif change=='services':context['services_receipt']['request_sha256']='f'*64
    elif change=='sid':context['directory_result']['computer_sid']='S-1-5-21-9-9-9-999'
    elif change=='ip':context['machine'].ip='--ProxyCommand=bad'
    original=runtime.runner
    def changed(*a,**kw):
        rc,out,err=original(*a,**kw)
        if change=='nonzero':rc=1
        elif change=='duplicate':out=out[:-1]+',"schema_version":1}'
        elif change in ('files','trust'):
            value=json.loads(out)
            if change=='files':value['files']['/etc/krb5.keytab']['mode']=0o644
            else:value['trust_verified']=True
            out=json.dumps(value)
        elif change=='history_after':context['preparation']['local_rehearsal']['request_sha256']='f'*64
        elif change=='source_after':monkeypatch.setattr(runtime,'_sources',lambda:['changed']*8)
        return rc,out,err
    runtime.runner=changed
    with pytest.raises(ControlError) as caught:runtime.install_once('plan','a'*64)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    count=len(calls)
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert len(calls)==count


def test_intent_changed_during_vault_open_is_terminal_before_ssh(tmp_path):
    from alt_deploy.setup_plans import private_replace
    runtime,context,calls,files,data=scenario(tmp_path)
    pair={key:context['payload'][key] for key in ('failed_run_id','computer_guid')}
    terminal=[]
    runtime.attempts.finish=lambda **kw:terminal.append(kw)
    def changed(**kw):
        private_replace(runtime.attempts._path(**pair,suffix='.local-import-intent.json'),{'schema_version':1})
        return PASSWORD
    runtime.credentials.open=changed
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert calls==[]
    assert terminal==[dict(pair,status='failed',error_code='recovery_local_import_failed')]
    with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
    assert calls==[]


def test_transport_holds_lifecycle_lock_until_result_is_persisted(tmp_path):
    import fcntl
    import os
    runtime,context,calls,files,data=scenario(tmp_path)
    original=runtime.runner
    def checked(*a,**kw):
        fd=os.open(runtime.settings.lock_file,os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(fd)
        return original(*a,**kw)
    runtime.runner=checked
    runtime.install_once('plan','a'*64)
    runtime.verify('plan','a'*64)


@pytest.mark.parametrize('drift',[False,True,'wire'])
def test_generated_worker_uses_real_isolated_importer_and_checks_units_between_writes(tmp_path,monkeypatch,drift):
    import contextlib
    import io
    import os
    import shutil
    import sys
    if os.geteuid()!=0:pytest.skip('fixed root-worker receipt requires root-owned fixture files')
    from alt_deploy import setup_recovery_services as services, setup_recovery_rehearsal as rehearsal
    from test_setup_recovery_backup import fixture as backup_fixture
    from test_setup_recovery_services import scenario as service_fixture
    runtime,context,calls,files,data=scenario(tmp_path/'controller')
    worker_root=tmp_path/'worker';worker_root.mkdir()
    backup,_,collect=backup_fixture(worker_root)
    transport=runtime._context('plan','a'*64)
    request=transport['request'];backup.create(request['rehearsal_request']['backup_request'],collect=collect,root=worker_root,owner=os.geteuid())
    rehearsal.create(request['rehearsal_request'],PASSWORD,backup=backup,native=data['native'],collect=collect,
        runner=data['runner'],root=worker_root,owner=os.geteuid())
    service_root=tmp_path/'services';service_root.mkdir()
    service_data,_,states,_=service_fixture(service_root)
    shutil.copytree(service_root/'usr',worker_root/'usr',dirs_exist_ok=True)
    service_runner=service_data['runner']
    snapshot=services.snapshot(backup=backup,probe=data['probe'],collect=collect,runner=service_runner,root=worker_root,owner=os.geteuid())
    context['services_preparation']=dict(services=snapshot,services_sha256=digest(snapshot))
    service_request=dict(transport['service_request'],services=snapshot,services_sha256=digest(snapshot))
    context['services_receipt']=services.quiesce_once(service_request,backup=backup,probe=data['probe'],importer=service_data['importer'],
        collect=collect,runner=service_runner,root=worker_root,owner=os.geteuid())
    def worker_runner(command,**options):
        if command[0] in ('/usr/bin/rpm','/usr/bin/systemctl') and 'is-active' not in command:
            return service_runner(command,**options)
        return data['runner'](command,**options)
    def execute(command,**options):
        frame=json.loads(options['input_text'])
        program=frame.pop('_worker')
        injection='''probe.collect = fixture_collect
process.bounded_recovery_run = fixture_runner
original_snapshot = services.snapshot
services.snapshot = lambda **kw: original_snapshot(backup=backup,probe=probe,collect=fixture_collect,runner=fixture_runner,root=fixture_root,owner=fixture_owner)
original_services_verify = services.verify
services.verify = lambda request,**kw: original_services_verify(request,backup=backup,probe=probe,collect=fixture_collect,runner=fixture_runner,root=fixture_root,owner=fixture_owner)
original_install = importer.install_once
importer.install_once = lambda request,password,**kw: original_install(request,password,root=fixture_root,owner=fixture_owner,**kw)
original_verify = importer.verify
importer.verify = lambda request,**kw: original_verify(request,root=fixture_root,owner=fixture_owner,**kw)
'''
        program=program.replace('try:\n    raw = sys.stdin.buffer.read',injection+'try:\n    raw = sys.stdin.buffer.read',1)
        output=io.StringIO()
        from alt_deploy.setup_recovery_source_stdin import build_source_stdin
        program,wire=build_source_stdin(program,frame)
        if drift=='wire':
            value=json.loads(wire);value['request']['directory_result']['computer_guid']='ffffffff-ffff-ffff-ffff-ffffffffffff'
            wire=json.dumps(value)
        with monkeypatch.context() as patch,contextlib.redirect_stdout(output):
            patch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(wire.encode())))
            try:
                exec(compile(program,'<fixed-import-worker>','exec'),dict(fixture_collect=collect,fixture_runner=worker_runner,
                    fixture_root=worker_root,fixture_owner=os.geteuid()))
                rc=0
            except SystemExit as stopped:rc=stopped.code
        return rc,output.getvalue(),''
    runtime.runner=execute
    if drift is True:
        original_replace=os.replace
        def changed(src,dest):
            original_replace(src,dest)
            if str(dest)==str(worker_root/'var/lib/samba/private/secrets.tdb'):
                (worker_root/'usr/lib/systemd/system/sssd.service').write_bytes(b'CHANGED_UNIT')
        monkeypatch.setattr(os,'replace',changed)
        with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
        assert (worker_root/'etc/krb5.keytab').read_bytes()==b'SYNTHETIC_SECRET_CONTENT'
    elif drift=='wire':
        with pytest.raises(ControlError):runtime.install_once('plan','a'*64)
        assert (worker_root/'var/lib/samba/private/secrets.tdb').read_bytes()==b'SYNTHETIC_SECRET_CONTENT'
    else:
        receipt=runtime.install_once('plan','a'*64)
        assert runtime.verify('plan','a'*64)==receipt
        assert receipt['trust_verified'] is False
