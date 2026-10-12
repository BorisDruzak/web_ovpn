from __future__ import annotations

import hashlib,json,shlex
from pathlib import Path

import pytest

from alt_deploy.setup_plans import canonical,digest
from test_setup_recovery_native_wire import fixture as native_fixture
from test_setup_recovery_start_wire import run
from test_setup_recovery_user_check import EMPLOYEE


def fixture(root):
    from alt_deploy import setup_recovery_user_wire as wire
    _,startup,started,sources=native_fixture(root)
    original=startup['policy_request']['kerberos_request']['import_request']['directory_result']
    started.update({key:original[key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno')})
    sources.append('''def check_once(request, **options):
    assert 'checker' in options and 'start' in options
    return {'schema_version':1,'status':'synthetic_user','login_verified':False}
def verify(request, receipt, **options):
    return receipt
''')
    native=dict(schema_version=1,status='native_testjoin_succeeded',request_sha256=digest(startup),
        startup_receipt_sha256=digest(started),trust_verified=False,native_testjoin_peer_pinning_verified=False,
        temporary_policy_retained=True)
    request=dict(schema_version=1,startup_request=startup,startup_receipt=started,native_receipt=native,
        employee=dict(EMPLOYEE),source_sha256=digest(sources),approval_sha256=startup['approval_sha256'])
    return wire,request,sources


def test_fixed_user_bootstrap_preserves_native_and_startup_bindings(tmp_path):
    wire,request,sources=fixture(tmp_path)
    assert request['startup_request']['source_sha256']==digest(sources[:12])
    script,encoded=wire.build('check',sources,request)
    assert len(script.encode())<8192 and 'SYNTHETIC_MODULE' not in script
    assert len(('sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)).encode())<8192
    assert json.loads(encoded)['sources']==dict(zip(wire.NAMES,sources))
    result=run(script,encoded)
    assert result.returncode==0 and result.stderr==''
    receipt=json.loads(result.stdout.splitlines()[-1])
    assert receipt==dict(schema_version=1,status='synthetic_user',login_verified=False)
    script,encoded=wire.build('verify',sources,request,receipt=receipt)
    assert run(script,encoded).returncode==0


@pytest.mark.parametrize('change',['action','extra','count','type','size','sources','startup_sources',
    'startup_receipt','native_status','native_request','native_startup','native_claim','employee','approval','check_receipt','verify_receipt'])
def test_invalid_builder_cannot_form_user_transport(tmp_path,change):
    wire,request,sources=fixture(tmp_path);action='check';receipt=None
    if change=='action':action='login'
    elif change=='extra':request['command']='arbitrary'
    elif change=='count':sources.pop()
    elif change=='type':sources[-1]={}
    elif change=='size':sources[-1]='x'*(wire.MAX_SOURCE_BYTES+1)
    elif change=='sources':request['source_sha256']='0'*64
    elif change=='startup_sources':request['startup_request']['source_sha256']='0'*64
    elif change=='startup_receipt':request['startup_receipt']['request_sha256']='0'*64
    elif change=='native_status':request['native_receipt']['status']='failed'
    elif change=='native_request':request['native_receipt']['request_sha256']='0'*64
    elif change=='native_startup':request['native_receipt']['startup_receipt_sha256']='0'*64
    elif change=='native_claim':request['native_receipt']['trust_verified']=True
    elif change=='employee':request['employee']['upn']='other@sosnadmin.local'
    elif change=='approval':request['approval_sha256']='0'*64
    elif change=='check_receipt':receipt={}
    else:action='verify'
    with pytest.raises(ValueError):wire.build(action,sources,request,receipt=receipt)


@pytest.mark.parametrize('change',['wire_hash','duplicate','nonfinite','module','module_hash','all_sources',
    'startup_sources','native_request','native_status','employee','approval','action','schema','extra','oversized'])
def test_parser_rejects_before_any_source_execution(tmp_path,change):
    wire,request,sources=fixture(tmp_path);script,encoded=wire.build('check',sources,request)
    value=json.loads(encoded);hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(wire.NAMES,sources)}
    if change=='duplicate':encoded=encoded[:-1]+',"schema_version":1}'
    elif change=='nonfinite':encoded=encoded[:-1]+',"extra":NaN}'
    elif change=='oversized':encoded=' '*(wire.MAX_WIRE_BYTES+1)
    else:
        if change=='wire_hash':value['action']='changed'
        elif change=='module':value['sources']['arbitrary']='print("MUST_NOT_RUN")'
        elif change=='module_hash':value['sources']['user_check']='print("MUST_NOT_RUN")'
        elif change=='all_sources':value['request']['source_sha256']='0'*64
        elif change=='startup_sources':value['request']['startup_request']['source_sha256']='0'*64
        elif change=='native_request':value['request']['native_receipt']['request_sha256']='0'*64
        elif change=='native_status':value['request']['native_receipt']['status']='failed'
        elif change=='employee':value['request']['employee']['upn']='other@sosnadmin.local'
        elif change=='approval':value['request']['approval_sha256']='0'*64
        elif change=='action':value['action']='login'
        elif change=='schema':value['request']['schema_version']=True
        else:value['request']['command']='arbitrary'
        encoded=canonical(value).decode()
    if change!='wire_hash':script=wire._script('check',hashlib.sha256(encoded.encode()).hexdigest(),hashes)
    result=run(script,encoded)
    assert result.returncode==1 and result.stderr==''
    assert json.loads(result.stdout)==dict(schema_version=1,error_code='recovery_user_wire_invalid')
    assert 'MODULE_EXECUTED' not in result.stdout and 'MUST_NOT_RUN' not in result.stdout


def test_real_fourteen_source_bundle_fits_fixed_transport(tmp_path):
    wire,request,_=fixture(tmp_path)
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
    request['source_sha256']=digest(sources)
    request['startup_request']['source_sha256']=digest(sources[:12])
    request['startup_receipt']['request_sha256']=digest(request['startup_request'])
    request['native_receipt'].update(request_sha256=digest(request['startup_request']),startup_receipt_sha256=digest(request['startup_receipt']))
    script,encoded=wire.build('check',sources,request)
    assert len(encoded.encode())<wire.MAX_WIRE_BYTES and len(script.encode())<8192
    assert len(('sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)).encode())<8192
