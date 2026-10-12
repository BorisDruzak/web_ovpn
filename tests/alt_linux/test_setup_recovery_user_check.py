from __future__ import annotations

import copy,os
from pathlib import Path
from unittest.mock import patch

import pytest

EMPLOYEE=dict(object_guid='11111111-2222-3333-4444-555555555555',object_sid='S-1-5-21-1-2-3-1101',
    login='test.user',upn='test.user@sosnadmin.local')
PACKAGE='glibc-utils 2.38.0.223.f053ff-alt1.p11.1'


def api():
    from alt_deploy import setup_recovery_user_check
    return setup_recovery_user_check


def scenario(root,*,nss_mode=0o755,getent_mode=0o755):
    import test_setup_recovery_backup as fixture
    from test_setup_recovery_native_testjoin import scenario as native_fixture
    from alt_deploy import setup_recovery_native_testjoin as checker
    original=fixture.scenario
    def tools(directory):
        probe,calls,values,read=original(directory)
        (directory/'usr/bin/getent').chmod(getent_mode)
        (directory/'usr/lib64/libnss_sss.so.2').chmod(nss_mode)
        def wrapped(command):
            if command[:3]==['/usr/bin/rpm','-qf','/usr/bin/getent']:return PACKAGE
            if command[:3]==['/usr/bin/rpm','-qf','/usr/lib64/libnss_sss.so.2']:return 'sssd-client 2.9.8-alt3'
            return read(command)
        return probe,calls,values,wrapped
    with patch.object(fixture,'scenario',tools):request,started,args,native,states=native_fixture(root)
    native_receipt=checker.testjoin_once(request,started,**args)
    passwd=root/'etc/passwd';passwd.write_text('root:x:0:0:root:/root:/bin/bash\n');passwd.chmod(0o644)
    wrapped=dict(schema_version=1,startup_request=request,startup_receipt=started,native_receipt=native_receipt,
        employee=copy.deepcopy(EMPLOYEE),source_sha256='a'*64,approval_sha256=request['approval_sha256'])
    calls=[];previous=args['runner']
    def runner(command,**options):
        if command[:3]==['/usr/bin/rpm','-qf','/usr/bin/getent']:return 0,PACKAGE+'\n',''
        if command[:3]==['/usr/bin/rpm','-qf','/usr/lib64/libnss_sss.so.2']:return 0,'sssd-client 2.9.8-alt3\n',''
        if command[0]=='/usr/bin/getent':
            calls.append((command,options))
            return 0,'test.user@sosnadmin.local:x:100100:100100:Test:/home/test.user@sosnadmin.local:/bin/bash\n',''
        return previous(command,**options)
    args.update(checker=checker,runner=runner)
    return wrapped,args,calls,states


def test_fixed_sss_lookup_is_bound_and_retained_verification_never_reauthenticates(tmp_path):
    module=api();request,args,calls,states=scenario(tmp_path)
    result=module.check_once(request,**args)
    assert len(calls)==1 and calls[0][0]==['/usr/bin/getent','-s','sss','passwd',EMPLOYEE['upn']]
    assert result['status']=='selected_user_resolved' and result['user_lookup'] is True
    assert result['login_verified'] is False and result['online_user_authentication_verified'] is False
    assert result['local_duplicate'] is False and result['uid']==100100
    assert result['employee']==EMPLOYEE and result['request_sha256']==args['backup'].digest(request)
    assert module.verify(request,result,**args)==result and len(calls)==1
    with pytest.raises(ValueError):module.check_once(request,**args)
    assert len(calls)==1


@pytest.mark.parametrize('change',['extra','user_guid','user_sid','login','upn','approval','source','native_receipt','local_duplicate','nss_module'])
def test_unbound_inputs_do_not_enter_user_lookup(tmp_path,change):
    module=api();request,args,calls,states=scenario(tmp_path)
    if change=='extra':request['command']='arbitrary'
    elif change in ('user_guid','user_sid'):request['employee'][{'user_guid':'object_guid','user_sid':'object_sid'}[change]]='invalid'
    elif change=='login':request['employee']['login']='--option'
    elif change=='upn':request['employee']['upn']='other@sosnadmin.local'
    elif change=='approval':request['approval_sha256']='b'*64
    elif change=='source':request['source_sha256']='invalid'
    elif change=='native_receipt':request['native_receipt']['kvno']+=1
    elif change=='nss_module':(tmp_path/'usr/lib64/libnss_sss.so.2').write_bytes(b'changed')
    else:(tmp_path/'etc/passwd').write_text('test.user:x:1001:1001::/home/test.user:/bin/bash\n')
    with pytest.raises(ValueError):module.check_once(request,**args)
    assert calls==[]


@pytest.mark.parametrize('change',['failure','wrong_user','multiple','numeric','password','pid','restart','tool','passwd','intent','nss_module'])
def test_entered_user_check_failure_retains_permanent_exclusion(tmp_path,change):
    module=api();request,args,calls,states=scenario(tmp_path);previous=args['runner']
    def changed(command,**options):
        rc,out,err=previous(command,**options)
        if command[0]=='/usr/bin/getent':
            if change=='failure':rc=2;err='SYNTHETIC_SECRET'
            elif change=='wrong_user':out=out.replace('test.user','other')
            elif change=='multiple':out+=out
            elif change=='numeric':out=out.replace(':100100:',':0:')
            elif change=='password':out=out.replace(':x:',':SYNTHETIC_SECRET:')
            elif change=='pid':states['sssd.service']['MainPID']='124'
            elif change=='restart':states['sssd.service']['NRestarts']='1'
            elif change=='tool':(tmp_path/'usr/bin/getent').write_bytes(b'changed')
            elif change=='nss_module':(tmp_path/'usr/lib64/libnss_sss.so.2').write_bytes(b'changed')
            elif change=='passwd':(tmp_path/'etc/passwd').write_text('other:x:1:1::/:/bin/bash\n')
            else:(module.path_for(request,backup=args['backup'],root=tmp_path)/'intent.json').write_text('{}')
        return rc,out,err
    args['runner']=changed
    with pytest.raises(ValueError) as caught:module.check_once(request,**args)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    leaf=module.path_for(request,backup=args['backup'],root=tmp_path)
    assert (leaf/'failed.json').exists() and not (leaf/'verified.json').exists()
    with pytest.raises(ValueError):module.check_once(request,**args)
    assert len(calls)==1

def test_stock_readonly_nss_library_does_not_require_executable_bits(tmp_path):
    module=api();request,args,calls,states=scenario(tmp_path,nss_mode=0o644)
    result=module.check_once(request,**args)
    assert result['status']=='selected_user_resolved' and len(calls)==1
    assert module.verify(request,result,**args)==result

def test_worker_still_requires_executable_getent_before_lookup(tmp_path):
    module=api();request,args,calls,states=scenario(tmp_path,getent_mode=0o644,nss_mode=0o644)
    with pytest.raises(ValueError):module.check_once(request,**args)
    assert calls==[]
