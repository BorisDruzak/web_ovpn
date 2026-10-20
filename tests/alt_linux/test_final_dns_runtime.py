"""Controller final-DNS observation cannot select a mutating entry point."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from test_component_catalog import SOURCE
from test_workstation_final_dns import UUID,CONNECTION


@pytest.mark.parametrize('fault',[None,'source','identity','hash','private_output','blocked','timeout'])
def test_fixed_readonly_transport_validates_bounded_source_and_network_reply(tmp_path,fault):
    from alt_deploy.final_dns_runtime import observe
    settings=SimpleNamespace(ansible_project_dir=SOURCE,known_hosts_file=tmp_path/'known',private_key_file=tmp_path/'key')
    machine=SimpleNamespace(uuid=UUID,hostname='alt-test-pc1',ip='192.0.2.10');calls=[]
    def runner(args,**options):
        calls.append((args,options))
        if fault=='timeout':raise TimeoutError('PRIVATE-SECRET-SENTINEL')
        assert json.loads(options['input_text'])=={'schema_version':1,'machine_uuid':UUID,
            'hostname':'alt-test-pc1','servers':['192.0.2.53']}
        if fault=='blocked':return 4,json.dumps({'schema_version':1,'status':'blocked','code':'final_dns_backend_unverified'}),'PRIVATE-SECRET-SENTINEL'
        from alt_deploy.final_dns_program import target_program
        value={'schema_version':1,'machine_uuid':UUID,'hostname':machine.hostname,'boot_id':CONNECTION,
            'backend':'nm_etcnet','interface':'eth0','connection_uuid':CONNECTION,'servers':['192.0.2.11'],
            'persistent_servers':['192.0.2.11'],'configuration_sha256':'a'*64,'network_sha256':'b'*64}
        value['snapshot_sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        reply={'schema_version':1,'status':'ok','helper_sha256':hashlib.sha256(target_program(SOURCE).encode()).hexdigest(),'observation':value}
        if fault=='source':reply['helper_sha256']='0'*64
        if fault=='identity':value['machine_uuid']='99999999-2222-3333-4444-555555555555'
        if fault=='hash':value['snapshot_sha256']='0'*64
        if fault=='private_output':value['configuration']='PRIVATE-SECRET-SENTINEL'
        return 0,json.dumps(reply),'PRIVATE-SECRET-SENTINEL'
    if fault and fault!='blocked':
        with pytest.raises(ControlError) as caught:observe(settings,machine,{'servers':['192.0.2.53']},runner=runner)
        assert 'SENTINEL' not in str(caught.value)
    else:
        result=observe(settings,machine,{'servers':['192.0.2.53']},runner=runner)
        assert result['status']==('blocked' if fault=='blocked' else 'ok')
        assert 'SENTINEL' not in json.dumps(result)
    assert len(calls)==1
    args,options=calls[0]
    assert args[:4]==['/usr/bin/ssh','-F','/dev/null','-T']
    assert 'StrictHostKeyChecking=yes' in args and 'ForwardAgent=no' in args
    assert options['timeout']<=60 and options['max_bytes']<=65536


@pytest.mark.parametrize('observer',[False,True])
def test_fixed_dns_program_masks_private_invalid_input_and_compiles(observer):
    from alt_deploy.final_dns_program import target_program
    program=target_program(SOURCE,observer=observer)
    assert len(program.encode())<120000
    result=subprocess.run([sys.executable,'-I','-B','-c',program,'--arbitrary'],
        input='PRIVATE-SECRET-SENTINEL',capture_output=True,text=True,timeout=5)
    assert result.returncode==4 and result.stderr=='' and 'SENTINEL' not in result.stdout
    reply=json.loads(result.stdout)
    assert set(reply)=={'schema_version','status','code'} and reply['status']=='blocked'
