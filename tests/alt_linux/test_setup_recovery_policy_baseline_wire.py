from __future__ import annotations

import hashlib,json,os,shlex
from pathlib import Path

import pytest

from alt_deploy.setup_plans import canonical,digest
from test_setup_recovery_policy_baseline import scenario
from test_setup_recovery_start_wire import run


def fixture(root):
    from alt_deploy import setup_recovery_policy_baseline_wire as wire
    request,_,_,_=scenario(root)
    sources=['SYNTHETIC_MODULE = True\n' for _ in wire.NAMES]
    sources[0]+='def collect(**options): return {}\n'
    sources[3]+='def bounded_recovery_run(*args, **options): raise AssertionError("No native operation")\n'
    sources[-1]='''def observe(request, **options):
    assert 'original' in options and 'policy' in options
    return {'schema_version':1,'status':'synthetic_baseline','defaults_verified':False}
'''
    request['source_sha256']=digest(sources)
    return wire,request,sources


@pytest.mark.parametrize('hostname', ['alt-a1-pc3', 'alt-arh1-pc1'])
def test_baseline_bootstrap_dispatches_only_fixed_read_only_worker(tmp_path, hostname):
    wire,request,sources=fixture(tmp_path)
    bound=request['backup_request']
    bound['hostname']=bound['facts']['hostname']=request['metadata']['hostname']=hostname
    bound['snapshot_sha256']=digest(bound['facts'])
    script,encoded=wire.build(sources,request)
    assert len(('sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)).encode())<8192
    assert 'SYNTHETIC_MODULE' not in script
    result=run(script,encoded)
    assert result.returncode==0 and result.stderr==''
    assert json.loads(result.stdout)==dict(schema_version=1,status='synthetic_baseline',defaults_verified=False)


@pytest.mark.parametrize('change',['count','source_type','source_size','source_hash','request_extra','request_size','metadata','facts'])
def test_invalid_baseline_builder_refuses_without_transport(tmp_path,change):
    wire,request,sources=fixture(tmp_path)
    if change=='count':sources.pop()
    elif change=='source_type':sources[0]={}
    elif change=='source_size':sources[0]='x'*(wire.MAX_SOURCE_BYTES+1)
    elif change=='source_hash':request['source_sha256']='0'*64
    elif change=='request_extra':request['command']='restart'
    elif change=='request_size':request['backup_request']['facts']['extra']='x'*wire.MAX_REQUEST_BYTES
    elif change=='metadata':request['metadata']['realm']='other.local'
    else:request['backup_request']['snapshot_sha256']='0'*64
    with pytest.raises(ValueError):wire.build(sources,request)


@pytest.mark.parametrize('change',['hash','duplicate','nonfinite','module','module_hash','source_hash','request_extra','metadata',
    'facts','hostname','schema','extra','oversize'])
def test_baseline_parser_refuses_before_source_execution(tmp_path,change):
    wire,request,sources=fixture(tmp_path);script,encoded=wire.build(sources,request)
    value=json.loads(encoded);hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(wire.NAMES,sources)}
    if change=='hash':encoded=encoded.replace('synthetic_baseline','MUST_NOT_RUN')
    elif change=='duplicate':encoded=encoded[:-1]+',"schema_version":1}'
    elif change=='nonfinite':encoded=encoded[:-1]+',"extra":NaN}'
    elif change=='oversize':encoded=' '*(wire.MAX_WIRE_BYTES+1)
    else:
        if change=='module':value['sources']['policy_baseline']='print("SOURCE_EXECUTED")'
        elif change=='module_hash':hashes['policy_baseline']='0'*64
        elif change=='source_hash':value['request']['source_sha256']='0'*64
        elif change=='request_extra':value['request']['command']='restart'
        elif change=='metadata':value['request']['metadata']['realm']='other.local'
        elif change=='facts':value['request']['backup_request']['snapshot_sha256']='0'*64
        elif change=='hostname':value['request']['metadata']['hostname']='alt-a1-pc99'
        elif change=='schema':value['request']['schema_version']=True
        else:value['action']='restart'
        encoded=canonical(value).decode()
    if change!='hash':script=wire._script(hashlib.sha256(encoded.encode()).hexdigest(),hashes)
    result=run(script,encoded)
    assert result.returncode==1 and result.stderr==''
    assert json.loads(result.stdout)==dict(schema_version=1,error_code='recovery_policy_baseline_wire_invalid')
    assert 'SOURCE_EXECUTED' not in result.stdout and 'MUST_NOT_RUN' not in result.stdout


def test_genuine_baseline_source_set_loads_without_package_context(tmp_path):
    wire,request,_=fixture(tmp_path)
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
    request['source_sha256']=digest(sources)
    script,encoded=wire.build(sources,request)
    assert len(('sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)).encode())<8192
    modules={}
    for name,source in zip(wire.NAMES,sources):
        scope={'__name__':'fixed_baseline_'+name,'__package__':None}
        exec(compile(source,'fixed_baseline_'+name,'exec'),scope);modules[name]=scope
    assert callable(modules['policy_baseline']['observe'])


def test_genuine_baseline_worker_pipeline_runs_through_bootstrap_with_synthetic_native_parser(tmp_path):
    from alt_deploy import setup_recovery_policy_baseline_wire as wire
    request,args,calls,values=scenario(tmp_path)
    directory=Path(__file__).parents[2]/'deploy/alt-linux/control/alt_deploy'
    sources=[(directory/('setup_recovery_'+name+'.py')).read_text() for name in wire.NAMES]
    sources[0]+='\ndef collect(**kwargs): return '+repr(request['backup_request']['facts'])+'\n'
    sources[3]+='\nPACKAGES='+repr(args['policy'].TOOLS)+'\nVALUES='+repr(values)+'\n'+'''
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
            return 0,json.dumps(VALUES),''
        return 0,'',''
    raise ValueError('Unexpected synthetic native command')
'''
    sources[-1]+=('\nfixed_observe=observe\ndef observe(request,**options):\n'
        '    options.update(root=Path('+repr(str(tmp_path))+'),owner='+str(os.geteuid())+')\n'
        '    return fixed_observe(request,**options)\n')
    request['source_sha256']=digest(sources)
    before={str(path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    script,encoded=wire.build(sources,request);result=run(script,encoded)
    assert result.returncode==0 and result.stderr==''
    receipt=json.loads(result.stdout)
    assert receipt['status']=='original_sssd_policy_baseline' and receipt['configured_values']==values
    assert receipt['request_sha256']==digest(request) and receipt['defaults_verified'] is False
    assert {str(path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}==before
