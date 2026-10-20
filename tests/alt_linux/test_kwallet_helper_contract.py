"""The fixed wallet helper binds identity/source and has no public command selector."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_component_catalog import SOURCE
from test_user_session import graphical
from test_kwallet_empty_name_repair import wallet,helper,files
from test_krfb_managed_runtime import runtime_request


UUID='11111111-2222-3333-4444-555555555555'
BOOT='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


@pytest.fixture
def target(wallet):
    f=wallet
    for name,value in [('sys/class/dmi/id/product_uuid',UUID),('proc/sys/kernel/random/boot_id',BOOT)]:
        path=f['root']/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value+'\n')
    executable=f['root']/'usr/local/libexec/alt-kwallet-empty-name-repair'
    executable.parent.mkdir(parents=True);executable.write_text('published-fixed-helper\n');executable.chmod(0o700)
    request={'schema_version':1,'machine_uuid':UUID,'hostname':'alt-test-pc1','login':'synthetic.user',
        'wallet_name':'recovered-wallet','helper_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
        'previous_helper_sha256':[]}
    original=f['call']
    def call(args):
        if args==['hostname','-s']:return 0,'alt-test-pc1\n'
        if args==['getent','-s','sss','passwd','synthetic.user@sosnadmin.local']:
            return 0,f'synthetic.user:x:{f["uid"]}:{f["gid"]}:Employee:{f["home"]}:/bin/bash\n'
        return original(args)
    return dict(f,executable=executable,request=request,probe_call=call)


@pytest.mark.parametrize('case',['current','absent','approved_old','foreign','symlink','wrong_uuid','local_shadow'])
def test_candidate_readiness_is_readonly_before_installing_any_helper(target,monkeypatch,case):
    m=helper();f=target;request=dict(f['request'])
    def forbidden(*args,**kwargs):raise AssertionError('A read-only probe attempted mutation')
    for name in ('repair_wallet','run_writer','stop_daemons','apply_wallet_files','verify_wallet_bus'):
        monkeypatch.setattr(m,name,forbidden)
    if case=='absent':f['executable'].unlink()
    elif case in ('approved_old','foreign'):
        old=request['helper_sha256'];request['helper_sha256']='f'*64
        if case=='approved_old':request['previous_helper_sha256']=[old]
    elif case=='symlink':
        saved=f['executable'].with_suffix('.foreign');f['executable'].rename(saved);f['executable'].symlink_to(saved)
    elif case=='wrong_uuid':request['machine_uuid']='99999999-2222-3333-4444-555555555555'
    elif case=='local_shadow':
        original=f['probe_call'];f['probe_call']=lambda args:(0,'root:x:0:0:Root:/root:/bin/bash') if args[0]=='getent' else original(args)
    before=files(f['root'])
    if case in ('foreign','symlink','wrong_uuid','local_shadow'):
        with pytest.raises(m.WalletError):m.observe_candidate(request,root=f['root'],call=f['probe_call'],limits_reader=f['limits_reader'])
    else:
        observation=m.observe_candidate(request,root=f['root'],call=f['probe_call'],limits_reader=f['limits_reader'])
        assert observation['machine_uuid']==UUID and observation['boot_id']==BOOT
        assert observation['disposition']=='repair' and len(observation['readiness_sha256'])==64
        assert observation['helper_installed'] is (case!='absent')
        assert observation['installed_helper_sha256']==(None if case=='absent' else f['request']['helper_sha256'])
        assert 'SENTINEL' not in json.dumps(observation)
        assert not {'configuration','files','environment','wallets'} & set(observation)
    assert files(f['root'])==before


@pytest.mark.parametrize('kind',['complete_workstation','component_wallet_repair'])
@pytest.mark.parametrize('fault',[None,'extra_secret','wrong_machine','wrong_phase','wrong_operation','bad_source','bad_job'])
def test_only_exact_native_full_or_component_context_is_accepted(target,kind,fault):
    m=helper();observation=dict(target['request'],boot_id=BOOT)
    if kind=='complete_workstation':
        context=runtime_request()['context'];operation=context['claim_sha256']
    else:
        operation='a'*64
        context={'schema_version':1,'kind':kind,'job_id':'job-20261020T010000Z-12345678',
            'component_id':'desktop.kwallet_repair','plan_sha256':'1'*64,'machine_uuid':UUID,
            'source_sha256':'2'*64,'operation_sha256':operation}
    if fault=='extra_secret':context['credential']='PRIVATE-SECRET-SENTINEL'
    elif fault=='wrong_machine':context['machine_uuid']='99999999-2222-3333-4444-555555555555'
    elif fault=='wrong_phase':context['phase']='system'
    elif fault=='wrong_operation':operation='0'*64
    elif fault=='bad_source':context['source_sha256']='PRIVATE-SECRET-SENTINEL'
    elif fault=='bad_job':context['job_id']='PRIVATE-SECRET-SENTINEL'
    if fault is None:assert m.validate_invocation(context,observation,operation)==context
    else:
        with pytest.raises(m.WalletError) as caught:m.validate_invocation(context,observation,operation)
        assert 'SENTINEL' not in str(caught.value)


@pytest.mark.parametrize('observer',[False,True])
def test_published_program_has_only_fixed_entrypoints_and_masks_invalid_private_input(observer):
    from alt_deploy.kwallet_program import target_program
    program=target_program(SOURCE,observer=observer)
    assert len(program.encode())<120000
    compile(program,'<fixed-wallet-program>','exec')
    result=subprocess.run([sys.executable,'-I','-B','-c',program,'--invalid-private-argument'],
        input='PRIVATE-SECRET-SENTINEL',capture_output=True,text=True,timeout=5)
    assert result.returncode==4 and result.stderr==''
    document=json.loads(result.stdout)
    assert document['status']=='blocked' and 'SENTINEL' not in result.stdout
    assert set(document)=={'schema_version','status','code'}
    with pytest.raises(ValueError):target_program(SOURCE,observer='arbitrary')
