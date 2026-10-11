from __future__ import annotations

import copy,json,os,subprocess,sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import canonical,digest,private_read


def api():
    from alt_deploy import setup_recovery_startup_inventory
    return setup_recovery_startup_inventory


def inventory(root):
    from test_setup_recovery_start_graph import scenario
    from alt_deploy import setup_recovery_start_graph as graph
    args,states,calls,facts=scenario(root)
    facts.clear();facts.update(uuid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',hostname='alt-a1-pc3')
    return graph.capture(**args)


def test_large_inventory_has_private_immutable_chunks_and_exact_manifest(tmp_path):
    module=api();store=module.InventoryStore(tmp_path)
    value={'metadata':'x'*880000,'escaped':'\\"'*200000}
    reference=store.create(value)
    assert reference['sha256']==digest(value) and reference['bytes']==len(canonical(value))
    assert store.load(reference)==value and store.create(value)==reference
    leaf=store.path(reference['sha256'])
    assert all(path.stat().st_mode & 0o777==0o600 for path in leaf.iterdir())
    assert leaf.stat().st_mode & 0o777==0o700
    manifest=private_read(leaf/'manifest.json')
    part=leaf/manifest['parts'][0]['name'];part.write_text('{}');part.chmod(0o600)
    with pytest.raises(ControlError):store.load(reference)
    with pytest.raises(ControlError):store.create(value)


def test_read_of_missing_inventory_does_not_create_directories(tmp_path):
    store=api().InventoryStore(tmp_path)
    with pytest.raises(ControlError):store.load({'schema_version':1,'sha256':'a'*64,'bytes':2})
    assert not store.root.exists()


def test_manifest_schema_boolean_is_not_an_integer(tmp_path):
    from alt_deploy.setup_plans import private_replace
    store=api().InventoryStore(tmp_path);reference=store.create({'safe':True});leaf=store.path(reference['sha256'])
    manifest=private_read(leaf/'manifest.json');manifest['schema_version']=True
    private_replace(leaf/'manifest.json',manifest)
    with pytest.raises(ControlError):store.load(reference)


def test_inventory_read_never_recreates_a_disappearing_leaf(tmp_path,monkeypatch):
    store=api().InventoryStore(tmp_path);reference=store.create({'safe':True});leaf=store.path(reference['sha256'])
    original=Path.lstat;removed=[]
    def race(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        if path==leaf and not removed:
            for child in leaf.iterdir():child.unlink()
            leaf.rmdir();removed.append(True)
        return value
    monkeypatch.setattr(Path,'lstat',race)
    with pytest.raises(ControlError):store.load(reference)
    assert removed and not leaf.exists()


@pytest.mark.parametrize('change',['extra','manifest','symlink','reference'])
def test_partial_or_substituted_inventory_is_refused(tmp_path,change):
    module=api();store=module.InventoryStore(tmp_path);reference=store.create({'safe':True});leaf=store.path(reference['sha256'])
    if change=='extra':(leaf/'unknown').write_text('x')
    elif change=='manifest':(leaf/'manifest.json').unlink()
    elif change=='symlink':
        original=leaf/'part-000.json';original.rename(leaf/'original');original.symlink_to(leaf/'original')
    else:reference['bytes']+=1
    with pytest.raises(ControlError):store.load(reference)


def test_wire_validates_all_sources_before_execution_and_handles_large_metadata():
    module=api()
    sources=['def collect(): return {}','def bounded_inventory_command_run(*a,**k): return (0,"","")',
        'def capture(**kwargs): return {"safe":"x"*880000}']
    script,payload=module.bootstrap(sources)
    result=subprocess.run([sys.executable,'-I','-B','-c',script],input=payload,capture_output=True,text=True,timeout=5)
    assert result.returncode==0 and len(json.loads(result.stdout)['safe'])==880000
    wire=json.loads(payload);wire['sources']['start_graph']='raise Exception("SYNTHETIC_SECRET")'
    result=subprocess.run([sys.executable,'-I','-B','-c',script],input=json.dumps(wire),capture_output=True,text=True,timeout=5)
    assert result.returncode!=0 and 'SYNTHETIC_SECRET' not in result.stdout+result.stderr


def test_genuine_three_module_bootstrap_collects_fixture_graph_without_file_mutations(tmp_path):
    from alt_deploy import setup_recovery_probe as probe,setup_recovery_process as process,setup_recovery_start_graph as graph
    from test_setup_recovery_start_graph import scenario
    args,states,calls,facts=scenario(tmp_path);expected=graph.capture(**args)
    responses={tuple(command):args['runner'](command) for command in list(calls)}
    sources=[Path(probe.__file__).read_text()+'\ndef collect(): return '+repr(facts)+'\n',
        Path(process.__file__).read_text()+'\nFIXTURE='+repr(responses)+'\ndef bounded_inventory_command_run(command,**kwargs): return FIXTURE[tuple(command)]\n',
        Path(graph.__file__).read_text()+'\nfixed_capture=capture\ndef capture(**kwargs): return fixed_capture(**kwargs,root=Path('+repr(str(tmp_path))+'),owner='+str(os.geteuid())+')\n']
    before={str(path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    script,payload=api().bootstrap(sources)
    result=subprocess.run([sys.executable,'-I','-B','-c',script],input=payload,capture_output=True,text=True,timeout=5)
    assert result.returncode==0 and json.loads(result.stdout)==expected
    assert {str(path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}==before


@pytest.mark.parametrize('change',['schema','authority','facts','status','extra','overflow'])
def test_runtime_rejects_unbound_or_executable_inventory(tmp_path,change):
    module=api();value=inventory(tmp_path/'machine');expected=copy.deepcopy(value['facts'])
    if change=='schema':value['schema_version']=True
    elif change=='authority':value['execution_authorized']=True
    elif change=='facts':value['facts']['uuid']='other'
    elif change=='status':value['status']='trust_recovered'
    elif change=='extra':value['unreviewed']='x'
    else:value['unresolved']=['x'*4194304]
    runtime=module.RecoveryStartupInventoryRuntime(SimpleNamespace(known_hosts_file='/safe/known',private_key_file='/safe/key'),
        runner=lambda *a,**k:(0,json.dumps(value),''))
    runtime._sources=lambda:['fixed']*3
    machine=SimpleNamespace(uuid=expected['uuid'],hostname=expected['hostname'],ip='192.0.2.10')
    with pytest.raises(ControlError):runtime.capture(machine,expected)


def test_runtime_uses_strict_fixed_stdin_ssh_and_rechecks_source_bundle(tmp_path):
    module=api();value=inventory(tmp_path/'machine');calls=[];sources=['fixed']*3
    def runner(command,**options):calls.append((command,options));return 0,json.dumps(value),''
    runtime=module.RecoveryStartupInventoryRuntime(SimpleNamespace(known_hosts_file='/safe/known',private_key_file='/safe/key'),runner=runner)
    runtime._sources=lambda:copy.deepcopy(sources)
    machine=SimpleNamespace(uuid=value['facts']['uuid'],hostname=value['facts']['hostname'],ip='192.0.2.10')
    assert runtime.capture(machine,value['facts'])['inventory']==value
    command,options=calls[0]
    assert 'StrictHostKeyChecking=yes' in command and command[-2]=='ansible@192.0.2.10'
    assert command[1:3]==['-F','/dev/null'] and 'ProxyJump=none' in command
    assert 'PermitLocalCommand=no' in command
    assert 'sudo -n /usr/bin/python3 -I -B -c ' in command[-1]
    assert len(command[-1])<8192 and options['timeout']==60 and options['input_text']
    def drift(*a,**kw):sources[0]='changed';return 0,json.dumps(value),''
    runtime.runner=drift
    with pytest.raises(ControlError):runtime.capture(machine,value['facts'])


def test_service_retains_snapshot_bound_inventory_without_reserving_or_changing_history(tmp_path):
    from test_setup_recovery_planning import scenario,COMPUTER_GUID,RUN
    module=api();build,paths,machine,*_=scenario(tmp_path/'controller');planning=build()
    planning.settings.lock_file=tmp_path/'controller'/'workstationctl.lock'
    snapshot=planning.snapshot(RUN,COMPUTER_GUID);before={key:path.read_bytes() for key,path in paths.items()}
    value=inventory(tmp_path/'workstation');value['facts']=snapshot['workstation_facts']['snapshot']
    runtime=SimpleNamespace(capture=lambda m,f:dict(source_sha256='a'*64,inventory=value))
    service=module.RecoveryStartupInventoryService(planning,runtime=runtime)
    result=service.plan(RUN,COMPUTER_GUID)
    assert result['payload']['execution_available'] is False
    assert service.store.load(result['payload']['inventory'])==value
    assert {key:path.read_bytes() for key,path in paths.items()}==before
    assert not planning.attempts.root.exists()
    assert result['payload']['recovery_snapshot_sha256']==digest(snapshot)
