import hashlib,json,os,shlex
from pathlib import Path

import pytest

from alt_deploy.setup_plans import canonical,digest
from test_setup_recovery_policy_baseline_wire import fixture as baseline_fixture
from test_setup_recovery_start_wire import run


def fixture(root):
    from alt_deploy import setup_recovery_policy_effects_wire as wire
    _,request,sources=baseline_fixture(root)
    sources.append('''def observe(request, **options):
    assert request['baseline_receipt']['status']=='synthetic_baseline'
    assert 'baseline' in options and 'original' in options
    return {'schema_version':1,'status':'synthetic_effects','effects_reviewed':False}
''')
    request['source_sha256']=request['backup_request']['source_sha256']=digest(sources)
    return wire,request,sources


def test_effect_wire_has_only_fixed_baseline_then_inventory_dispatch(tmp_path):
    wire,request,sources=fixture(tmp_path);script,payload=wire.build(sources,request)
    assert len(('sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)).encode())<8192
    assert 'SYNTHETIC_MODULE' not in script
    result=run(script,payload)
    assert result.returncode==0 and result.stderr==''
    value=json.loads(result.stdout)
    assert set(value)=={'baseline_receipt','effect_receipt'}
    assert value['effect_receipt']['status']=='synthetic_effects'


@pytest.mark.parametrize('change',['count','source_type','source_size','source_hash','frame_source','extra','metadata','facts'])
def test_effect_builder_refuses_invalid_envelope(tmp_path,change):
    wire,request,sources=fixture(tmp_path)
    if change=='count':sources.pop()
    elif change=='source_type':sources[0]={}
    elif change=='source_size':sources[0]='x'*(wire.MAX_SOURCE_BYTES+1)
    elif change=='source_hash':request['source_sha256']='0'*64
    elif change=='frame_source':request['backup_request']['source_sha256']='0'*64
    elif change=='extra':request['action']='start'
    elif change=='metadata':request['metadata']['realm']='other.local'
    else:request['backup_request']['snapshot_sha256']='0'*64
    with pytest.raises(ValueError):wire.build(sources,request)


@pytest.mark.parametrize('change',['duplicate','nonfinite','module','source_hash','frame_source','extra','metadata','schema','oversize'])
def test_effect_bootstrap_refuses_before_any_source_execution(tmp_path,change):
    wire,request,sources=fixture(tmp_path);script,payload=wire.build(sources,request)
    value=json.loads(payload);hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(wire.NAMES,sources)}
    if change=='duplicate':payload=payload[:-1]+',"schema_version":1}'
    elif change=='nonfinite':payload=payload[:-1]+',"bad":NaN}'
    elif change=='oversize':payload=' '*(wire.MAX_WIRE_BYTES+1)
    else:
        if change=='module':value['sources']['policy_effects']='print("SOURCE_EXECUTED")'
        elif change=='source_hash':value['request']['source_sha256']='0'*64
        elif change=='frame_source':value['request']['backup_request']['source_sha256']='0'*64
        elif change=='extra':value['action']='start'
        elif change=='metadata':value['request']['metadata']['hostname']='alt-a1-pc99'
        else:value['request']['schema_version']=True
        payload=canonical(value).decode()
    script=wire._script(hashlib.sha256(payload.encode()).hexdigest(),hashes)
    result=run(script,payload)
    assert result.returncode==1 and result.stderr==''
    assert json.loads(result.stdout)==dict(schema_version=1,error_code='recovery_policy_effects_wire_invalid')
    assert 'SOURCE_EXECUTED' not in result.stdout


def test_genuine_eight_module_source_set_is_package_free(tmp_path):
    wire,request,_=fixture(tmp_path);directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
    request['source_sha256']=request['backup_request']['source_sha256']=digest(sources)
    script,payload=wire.build(sources,request)
    assert len(('sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)).encode())<8192
    for name,source in zip(wire.NAMES,sources):
        scope={'__name__':'fixed_'+name,'__package__':None};exec(compile(source,name,'exec'),scope)
    assert len(payload.encode())<wire.MAX_WIRE_BYTES


def test_genuine_baseline_and_effect_worker_pipeline_runs_through_bootstrap(tmp_path):
    from alt_deploy import setup_recovery_policy_effects_wire as wire
    from test_setup_recovery_policy_effects import scenario
    effects,bound,args,_,data=scenario(tmp_path)
    request=bound['baseline_request'];values=bound['baseline_receipt']['configured_values']
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
    sources[0]+='\ndef collect(**kwargs): return '+repr(request['backup_request']['facts'])+'\n'
    sources[3]+='\nPACKAGES='+repr({**args['policy'].TOOLS,**effects.DEPENDENCIES})+'\nVALUES='+repr(values)+'\nEFFECT_DATA='+repr(data)+'\n'+'''
def bounded_recovery_run(command,**options):
    if command[0]=='/usr/bin/rpm':
        if command[1]=='-q':return 0,'libini_config 1.3.1-alt6\\n',''
        if command[2] in PACKAGES:return 0,PACKAGES[command[2]]+'\\n',''
        if command[2].startswith('/usr/lib64/samba/ldb.mit/'):
            return 0,'libldb-modules-ldap 4.21.9-alt4.p11.1\\n',''
    if command[0]=='/usr/bin/bwrap':
        if '/usr/sbin/sssd' in command:
            from pathlib import Path
            path=Path(command[command.index('--bind')+1])/'sss/db/config.ldb'
            path.write_bytes(b'SYNTHETIC_CONFIGURATION_DATABASE');path.chmod(0o600)
        if '/usr/bin/python3.12' in command:
            import json
            return 0,json.dumps(EFFECT_DATA if 'key_inventory' in command[-1] else VALUES),''
        return 0,'',''
    raise ValueError('Unexpected synthetic native command')
'''
    for name in ('policy_baseline','policy_effects'):
        index=wire.NAMES.index(name)
        sources[index]+=('\nfixed_observe=observe\ndef observe(request,**options):\n'
            '    options.update(root=Path('+repr(str(tmp_path))+'),owner='+str(os.geteuid())+')\n'
            '    return fixed_observe(request,**options)\n')
    request['source_sha256']=request['backup_request']['source_sha256']=digest(sources)
    before={str(path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    script,payload=wire.build(sources,request);result=run(script,payload)
    assert result.returncode==0 and result.stderr==''
    receipts=json.loads(result.stdout)
    assert receipts['baseline_receipt']['request_sha256']==digest(request)
    assert receipts['effect_receipt']['configured']==data['configured']
    assert receipts['effect_receipt']['effects_reviewed'] is False
    assert {str(path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}==before
