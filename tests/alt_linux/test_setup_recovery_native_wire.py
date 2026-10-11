from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from alt_deploy.setup_plans import canonical,digest
from test_setup_recovery_start_wire import fixture as startup_fixture,run


def fixture(root):
    from alt_deploy import setup_recovery_native_wire as wire
    _,request,sources=startup_fixture(root)
    sources.append('''def testjoin_once(request, started, **options):
    assert 'start' in options
    return {'status':'synthetic_native', 'trust_verified':False}
def verify(request, started, receipt, **options):
    return receipt
''')
    started={'status':'sssd_started','request_sha256':digest(request)}
    return wire,request,started,sources


def test_fixed_native_bootstrap_preserves_startup_source_binding_and_stdin_only(tmp_path):
    wire,request,started,sources=fixture(tmp_path)
    original=request['source_sha256']
    script,encoded=wire.build('testjoin',sources,request,started)
    assert request['source_sha256']==original==digest(sources[:-1])
    assert len(script.encode())<8192 and 'SYNTHETIC_MODULE' not in script
    result=run(script,encoded)
    assert result.returncode==0 and result.stderr==''
    receipt=json.loads(result.stdout.splitlines()[-1])
    assert receipt=={'status':'synthetic_native','trust_verified':False}
    script,encoded=wire.build('verify',sources,request,started,receipt=receipt)
    assert run(script,encoded).returncode==0


@pytest.mark.parametrize('change',['action','extra','startup_hash','startup_status','all_source_hash',
    'source_count','source_type','source_size','receipt_testjoin','receipt_verify'])
def test_invalid_native_builder_cannot_form_executable_transport(tmp_path,change):
    wire,request,started,sources=fixture(tmp_path);action='testjoin';receipt=None
    if change=='action':action='join'
    elif change=='extra':request['command']='join'
    elif change=='startup_hash':started['request_sha256']='0'*64
    elif change=='startup_status':started['status']='failed'
    elif change=='all_source_hash':request['source_sha256']=digest(sources);started['request_sha256']=digest(request)
    elif change=='source_count':sources.pop()
    elif change=='source_type':sources[-1]={}
    elif change=='source_size':sources[-1]='x'*(wire.MAX_SOURCE_BYTES+1)
    elif change=='receipt_testjoin':receipt={}
    else:action='verify'
    with pytest.raises(ValueError):wire.build(action,sources,request,started,receipt=receipt)


@pytest.mark.parametrize('change',['wire_hash','duplicate','nonfinite','unknown_module','source_hash',
    'startup_hash','startup_status','extra','action','oversized'])
def test_native_wire_parser_refuses_before_module_execution(tmp_path,change):
    wire,request,started,sources=fixture(tmp_path)
    script,encoded=wire.build('testjoin',sources,request,started)
    value=json.loads(encoded);hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(wire.NAMES,sources)}
    if change=='duplicate':encoded=encoded[:-1]+',"schema_version":1}'
    elif change=='nonfinite':encoded=encoded[:-1]+',"extra":NaN}'
    elif change=='oversized':encoded=' '*(wire.MAX_WIRE_BYTES+1)
    else:
        if change=='wire_hash':value['started']['status']='changed'
        elif change=='unknown_module':value['sources']['operator_module']='print("MUST_NOT_RUN")'
        elif change=='source_hash':value['sources']['native_testjoin']='print("MUST_NOT_RUN")'
        elif change=='startup_hash':value['started']['request_sha256']='0'*64
        elif change=='startup_status':value['started']['status']='failed'
        elif change=='extra':value['request']['command']='join'
        else:value['action']='join'
        encoded=canonical(value).decode()
    if change!='wire_hash':script=wire._script('testjoin',hashlib.sha256(encoded.encode()).hexdigest(),hashes)
    result=run(script,encoded)
    assert result.returncode==1 and result.stderr==''
    assert json.loads(result.stdout)=={'schema_version':1,'error_code':'recovery_native_wire_invalid'}
    assert 'MODULE_EXECUTED' not in result.stdout and 'MUST_NOT_RUN' not in result.stdout


def test_genuine_native_bundle_fits_transport_without_rebinding_startup(tmp_path):
    wire,request,started,_=fixture(tmp_path)
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
    request['source_sha256']=digest(sources[:-1]);started['request_sha256']=digest(request)
    script,encoded=wire.build('testjoin',sources,request,started)
    assert len(encoded.encode())<wire.MAX_WIRE_BYTES and len(script.encode())<8192


def test_genuine_native_bootstrap_uses_retained_startup_without_service_actions(tmp_path):
    import subprocess,sys
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control'
    root=tmp_path/'root';root.mkdir(mode=0o700)
    harness=tmp_path/'harness.py'
    harness.write_text('''import io, json, os, sys, types
from pathlib import Path
sys.path[:0] = '''+repr([str(Path(__file__).parent),str(directory)])+'''
import test_setup_recovery_native_testjoin as fixture
from alt_deploy import setup_recovery_native_wire as wire
from alt_deploy.setup_plans import digest
directory = Path('''+repr(str(directory/'alt_deploy'))+''')
root = Path('''+repr(str(root))+''')
sources = [(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
original = fixture.startup_fixture
service_calls = []
def bound_startup(path):
    global service_calls
    result = original(path)
    service_calls = result[3]
    result[1]['source_sha256'] = digest(sources[:-1])
    return result
fixture.startup_fixture = bound_startup
request, started, args, native_calls, states = fixture.scenario(root)
service_calls.clear()
factory = types.SimpleNamespace
def private_modules(**scope):
    name = scope.get('__name__')
    if name == 'fixed_recovery_probe': scope['collect'] = args['collect']
    if name == 'fixed_recovery_process': scope['bounded_recovery_run'] = args['runner']
    if name == 'fixed_recovery_native_testjoin':
        original = scope['testjoin_once']; verify = scope['verify']
        scope['testjoin_once'] = lambda request, started, **options: original(request, started, root=root, owner=os.geteuid(), **options)
        scope['verify'] = lambda request, started, receipt, **options: verify(request, started, receipt, root=root, owner=os.geteuid(), **options)
    return factory(**scope)
types.SimpleNamespace = private_modules
script, encoded = wire.build('testjoin', sources, request, started)
sys.stdin = io.TextIOWrapper(io.BytesIO(encoded.encode()))
executed = {}; exec(compile(script, '<genuine-native-bootstrap>', 'exec'), executed)
script, encoded = wire.build('verify', sources, request, started, receipt=executed['result'])
sys.stdin = io.TextIOWrapper(io.BytesIO(encoded.encode()))
exec(compile(script, '<genuine-native-verification>', 'exec'), {})
print(json.dumps({'native_invocations':len(native_calls), 'scratch_removed':not native_calls[0][2].exists(),
    'startup_request_unchanged':started['request_sha256']==digest(request),
    'service_actions':sum(command[1] in ('start','stop','restart','reload','reset-failed') for command in service_calls)}))
''')
    result=subprocess.run([sys.executable,'-I','-B',str(harness)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    lines=result.stdout.splitlines();assert len(lines)==3
    receipt=json.loads(lines[0]);assert receipt['status']=='native_testjoin_succeeded'
    assert receipt['trust_verified'] is False and json.loads(lines[1])==receipt
    assert json.loads(lines[2])==dict(native_invocations=1,scratch_removed=True,startup_request_unchanged=True,service_actions=0)
