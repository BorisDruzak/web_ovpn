from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest

from alt_deploy.setup_plans import canonical,digest
from test_setup_recovery_sssd_start import scenario


def fixture(root):
    from alt_deploy import setup_recovery_start_wire as wire
    _,request,_,_,_=scenario(root)
    sources=['SYNTHETIC_MODULE = True\n' for _ in wire.NAMES]
    sources[0]='print("SYNTHETIC_MODULE_EXECUTED")\n'
    sources[-1]='''def start_once(request, **options):
    return {'schema_version': 1, 'status': 'synthetic_start', 'trust_verified': False}
def verify_started(request, receipt, **options):
    return receipt
'''
    # The real transport carries genuine collector/process modules; these
    # isolated bootstrap fixtures must never inspect or mutate the host.
    sources[0]+='def collect(): return {}\n'
    sources[3]+='def bounded_recovery_run(*args, **options): raise AssertionError("No native operation")\n'
    request['source_sha256']=digest(sources)
    return wire,request,sources


def run(script,encoded):
    return subprocess.run([sys.executable,'-I','-B','-c',script],input=encoded,text=True,capture_output=True,timeout=10)


def test_short_bootstrap_carries_sources_only_on_stdin_and_dispatches_fixed_action(tmp_path):
    wire,request,sources=fixture(tmp_path)
    script,encoded=wire.build('start',sources,request)
    assert len(script.encode())<8192 and 'SYNTHETIC_MODULE' not in script
    assert json.loads(encoded)['sources']==dict(zip(wire.NAMES,sources))
    result=run(script,encoded)
    assert result.returncode==0 and result.stderr==''
    assert result.stdout.splitlines()==['SYNTHETIC_MODULE_EXECUTED',json.dumps(
        {'schema_version':1,'status':'synthetic_start','trust_verified':False},sort_keys=True)]
    receipt={'schema_version':1,'status':'synthetic_start','trust_verified':False}
    script,encoded=wire.build('verify',sources,request,receipt=receipt)
    assert run(script,encoded).returncode==0


@pytest.mark.parametrize('change',['extra','action','schema','request_extra','request_schema','request_source',
    'source_name','source_type','source_bytes','receipt_start','missing_receipt_verify'])
def test_invalid_bound_builder_inputs_fail_without_transport(tmp_path,change):
    wire,request,sources=fixture(tmp_path);action='start';receipt=None
    if change=='extra':request['command']='restart'
    elif change=='action':action='restart'
    elif change=='schema':request['schema_version']=True
    elif change=='request_extra':request['inventory']={}
    elif change=='request_schema':request['policy_request']['schema_version']=True
    elif change=='request_source':request['source_sha256']='0'*64
    elif change=='source_name':sources=sources[:-1]
    elif change=='source_type':sources[1]={}
    elif change=='source_bytes':sources[1]='x'*(wire.MAX_SOURCE_BYTES+1);request['source_sha256']=digest(sources)
    elif change=='receipt_start':receipt={}
    else:action='verify'
    with pytest.raises(ValueError):wire.build(action,sources,request,receipt=receipt)


@pytest.mark.parametrize('change',['wire_hash','duplicate','unknown_module','source_hash','request_extra',
    'schema','action','oversized','nonfinite','receipt'])
def test_malformed_wire_is_rejected_before_any_module_execution(tmp_path,change):
    wire,request,sources=fixture(tmp_path);script,encoded=wire.build('start',sources,request)
    value=json.loads(encoded);hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(wire.NAMES,sources)}
    if change=='duplicate':encoded=encoded[:-1]+',"schema_version":1}'
    elif change=='oversized':encoded=' '*(wire.MAX_WIRE_BYTES+1)
    elif change=='nonfinite':encoded=encoded[:-1]+',"extra":NaN}'
    else:
        if change=='wire_hash':value['request']['approval_sha256']='4'*64
        elif change=='unknown_module':value['sources']['operator_module']='print("MUST_NOT_RUN")'
        elif change=='source_hash':value['sources']['backup']='print("MUST_NOT_RUN")'
        elif change=='request_extra':value['request']['command']='restart'
        elif change=='schema':value['schema_version']=True
        elif change=='action':value['action']='restart'
        else:value['receipt']={}
        encoded=canonical(value).decode()
    if change!='wire_hash':
        # Bind deliberately malformed fixture bytes to exercise the parser's
        # own checks, independently of the complete envelope hash.
        script=wire._script('start',hashlib.sha256(encoded.encode()).hexdigest(),hashes)
    result=run(script,encoded)
    assert result.returncode==1 and result.stderr==''
    assert json.loads(result.stdout)=={'schema_version':1,'error_code':'recovery_start_wire_invalid'}
    assert 'MODULE_EXECUTED' not in result.stdout and 'MUST_NOT_RUN' not in result.stdout


def test_genuine_fixed_bundle_builds_below_wire_bound(tmp_path):
    from pathlib import Path
    wire,request,_=fixture(tmp_path)
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
    request['source_sha256']=digest(sources)
    script,encoded=wire.build('start',sources,request)
    assert len(encoded.encode())<wire.MAX_WIRE_BYTES
    assert len(script.encode())<8192


def test_genuine_bootstrap_and_all_workers_execute_only_in_private_fixture(tmp_path):
    from pathlib import Path
    test_directory=Path(__file__).parent;control=Path(__file__).parents[2]/'deploy/alt-linux/control'
    root=tmp_path/'root';root.mkdir(mode=0o700)
    harness=tmp_path/'harness.py'
    harness.write_text('''import io, json, os, sys, types
from pathlib import Path
sys.path[:0] = '''+repr([str(test_directory),str(control)])+'''
from test_setup_recovery_sssd_start import scenario
from alt_deploy import setup_recovery_start_wire as wire
from alt_deploy.setup_plans import digest
root = Path('''+repr(str(root))+''')
_, request, args, calls, states = scenario(root)
directory = Path('''+repr(str(control/'alt_deploy'))+''')
sources = [(directory / ('setup_recovery_' + name + '.py')).read_text() for name in wire.NAMES]
request['source_sha256'] = digest(sources)
script, encoded = wire.build('start', sources, request)
factory = types.SimpleNamespace
def private_modules(**scope):
    name = scope.get('__name__')
    if name == 'fixed_recovery_probe': scope['collect'] = args['collect']
    if name == 'fixed_recovery_process': scope['bounded_recovery_run'] = args['runner']
    if name == 'fixed_recovery_sssd_start':
        original = scope['start_once']
        scope['start_once'] = lambda request, **options: original(request, root=root, owner=os.geteuid(), **options)
        verify = scope['verify_started']
        scope['verify_started'] = lambda request, receipt, **options: verify(request, receipt, root=root, owner=os.geteuid(), **options)
    return factory(**scope)
types.SimpleNamespace = private_modules
sys.stdin = io.TextIOWrapper(io.BytesIO(encoded.encode()))
executed = {}
exec(compile(script, '<genuine-startup-bootstrap>', 'exec'), executed)
starts = sum(command[1] == 'start' for command in calls)
calls.clear()
script, encoded = wire.build('verify', sources, request, receipt=executed['result'])
sys.stdin = io.TextIOWrapper(io.BytesIO(encoded.encode()))
exec(compile(script, '<genuine-startup-verification-bootstrap>', 'exec'), {})
print(json.dumps({'starts': starts,
    'verification_actions': sum(command[1] in ('start', 'stop', 'restart', 'reload', 'reset-failed') for command in calls)}))
''')
    result=subprocess.run([sys.executable,'-I','-B',str(harness)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    lines=result.stdout.splitlines();assert len(lines)==3
    receipt=json.loads(lines[0]);assert receipt['status']=='sssd_started' and receipt['trust_verified'] is False
    assert json.loads(lines[1])==receipt
    assert json.loads(lines[2])=={'starts':1,'verification_actions':0}
