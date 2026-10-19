"""Protected configuration is prepared before any listener or reload action."""
import pytest
import hashlib
import stat
import os
import json

from test_krfb_user_session import desktop
from test_user_session import graphical,discover


def runtime_request():
    value={'schema_version':1,'machine_uuid':'11111111-2222-3333-4444-555555555555','hostname':'alt-test-pc1',
        'login':'synthetic.user','source_sha256':'a'*64,'policy_sha256':'b'*64,'expected_snapshot_sha256':'c'*64,
        'policy_helper_sha256':'d'*64,'expected_policy_snapshot_sha256':'e'*64,
        'configuration':desired_configuration().decode(),'autostart':'[Desktop Entry]\nType=Application\nExec=/usr/bin/krfb\n',
        'context':{'schema_version':1,'kind':'complete_workstation','phase':'user','job_id':'job-20261020T010000Z-12345678',
            'claim_sha256':'f'*64,'plan_sha256':'1'*64,'workflow_policy_sha256':'2'*64,
            'machine_uuid':'11111111-2222-3333-4444-555555555555','source_sha256':'a'*64,'policy_sha256':'b'*64}}
    value['configuration_template_sha256']=hashlib.sha256(value['configuration'].encode()).hexdigest()
    value['autostart_template_sha256']=hashlib.sha256(value['autostart'].encode()).hexdigest()
    return value


@pytest.mark.parametrize('case',['valid','extra','bool','phase','source','machine','claim','plan','policy','worker_kind','configuration_size',
                                'configuration_changed','autostart_changed'])
def test_only_the_exact_claimed_user_phase_context_is_accepted(case):
    from alt_deploy.krfb_managed_runtime import validate_runtime_request
    from alt_deploy.krfb_user_session import KRFBSessionError
    request=runtime_request()
    if case=='extra':request['command']='PRIVATE-SECRET-SENTINEL'
    elif case=='bool':request['schema_version']=True
    elif case=='phase':request['context']['phase']='system'
    elif case=='source':request['context']['source_sha256']='0'*64
    elif case=='machine':request['context']['machine_uuid']='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    elif case=='claim':request['context']['claim_sha256']='PRIVATE-SECRET-SENTINEL'
    elif case=='plan':request['context']['plan_sha256']='PRIVATE-SECRET-SENTINEL'
    elif case=='policy':request['context']['policy_sha256']='0'*64
    elif case=='worker_kind':request['context']['kind']='manual'
    elif case=='configuration_size':request['configuration']='PRIVATE-SECRET-SENTINEL'*4000
    elif case=='configuration_changed':request['configuration']+='\n# changed after claim\n'
    elif case=='autostart_changed':request['autostart']+='\n# changed after claim\n'
    if case=='valid':assert validate_runtime_request(request) is True
    else:
        with pytest.raises(KRFBSessionError) as caught:validate_runtime_request(request)
        assert 'SENTINEL' not in str(caught.value)


def desired_configuration():
    obscure=lambda value:''.join(ch if ord(ch)<=0x21 else chr((0x1001f-ord(ch))&0xffff) for ch in value)
    return ('[MainWindow]\nstartMinimized=true\n[FrameBuffer]\npreferredFrameBufferPlugin=xcb\n'
        '[Security]\nallowDesktopControl=true\nallowUnattendedAccess=true\nnoWallet=true\n'
        'desktopPassword='+obscure('fixture-desktop')+'\nunattendedPassword='+obscure('fixture-unattended')+'\n').encode()


def test_configuration_merge_preserves_unmanaged_bytes_and_is_idempotent(desktop):
    from alt_deploy.krfb_managed_runtime import prepare_configuration
    context=discover(desktop);desired=desired_configuration()
    existing=(b'# employee comment\n[Unrelated][Nested]\nPosition=42,73\n\n'+desired
              .replace(b'allowUnattendedAccess=true',b'allowUnattendedAccess=false'))
    before=bytes(existing)
    result=prepare_configuration(existing,desired,context)
    assert b'# employee comment\n[Unrelated][Nested]\nPosition=42,73\n\n' in result
    assert b'allowUnattendedAccess=true' in result and b'allowUnattendedAccess=false' not in result
    assert existing==before
    assert prepare_configuration(result,desired,context)==result


@pytest.mark.parametrize('existing',[None,b'# existing private note',b'[MainWindow]\nstartMinimized=false'])
def test_missing_managed_groups_are_completed_without_touching_files(desktop,existing):
    from alt_deploy.krfb_managed_runtime import prepare_configuration
    from alt_deploy.krfb_user_session import _configuration_ready
    context=discover(desktop);result=prepare_configuration(existing,desired_configuration(),context)
    assert _configuration_ready(result,context)
    if existing and existing.startswith(b'#'):assert b'# existing private note\n' in result


@pytest.mark.parametrize('fault',['extra_group','extra_key','duplicate_key','plaintext_password','wrong_framebuffer','wrong_port','nul'])
def test_unapproved_desired_configuration_is_rejected_before_effects(desktop,fault):
    from alt_deploy.krfb_managed_runtime import prepare_configuration
    from alt_deploy.krfb_user_session import KRFBSessionError
    desired=desired_configuration()
    if fault=='extra_group':desired+=b'[Command]\nExec=/bin/sh\n'
    elif fault=='extra_key':desired+=b'passwordFile=/tmp/arbitrary-file\n'
    elif fault=='duplicate_key':desired+=b'noWallet=false\n'
    elif fault=='plaintext_password':desired=desired.replace(desired.split(b'desktopPassword=')[1].splitlines()[0],b'PRIVATE-PLAINTEXT-SENTINEL')
    elif fault=='wrong_framebuffer':desired=desired.replace(b'=xcb',b'=pw')
    elif fault=='wrong_port':desired+=b'[TCP]\nport=5901\n'
    elif fault=='nul':desired+=b'\0'
    original=desktop['config'].read_bytes()
    with pytest.raises(KRFBSessionError) as caught:prepare_configuration(original,desired,discover(desktop))
    assert 'SENTINEL' not in str(caught.value)
    assert desktop['config'].read_bytes()==original


@pytest.mark.parametrize('entry,valid',[
    (b'[Desktop Entry]\nType=Application\nExec=/usr/bin/krfb\nOnlyShowIn=KDE;\n',True),
    (b'[Desktop Entry]\nType=Application\nExec=/bin/sh -c arbitrary\n',False),
    (b'[Desktop Entry]\nType=Application\nExec=/usr/bin/krfb\nHidden=true\n',False),
    (b'[Desktop Entry]\nType=Application\nExec=/usr/bin/krfb\nX-Arbitrary-Command=arbitrary\n',False),
])
def test_autostart_is_only_the_fixed_package_launcher(entry,valid):
    from alt_deploy.krfb_managed_runtime import validate_autostart
    from alt_deploy.krfb_user_session import KRFBSessionError
    if valid:assert validate_autostart(entry)==entry
    else:
        with pytest.raises(KRFBSessionError):validate_autostart(entry)


@pytest.mark.parametrize('case',['update','stale','symlink'])
def test_real_unprivileged_writer_is_fixed_scoped_and_checks_current_bytes(desktop,case):
    from alt_deploy.krfb_managed_runtime import prepare_configuration,write_user_configuration
    from alt_deploy.krfb_user_session import KRFBSessionError
    f=desktop;context=discover(f);original=f['config'].read_bytes();other=f['config'].parent/'unrelated.ini'
    other.write_bytes(b'UNRELATED-USER-DATA')
    expected={'krfbrc':hashlib.sha256(original).hexdigest(),
              'org.sosn.krfb.desktop':hashlib.sha256(f['autostart'].read_bytes()).hexdigest()}
    contents={'krfbrc':prepare_configuration(original,desired_configuration(),context),
              'org.sosn.krfb.desktop':f['autostart'].read_bytes()}
    if case=='stale':expected['krfbrc']='0'*64
    elif case=='symlink':
        saved=f['config'].with_suffix('.original');f['config'].rename(saved);f['config'].symlink_to(saved)
    if case=='update':
        registered=[]
        write_user_configuration(context,contents,expected,root=f['root'],register_child=lambda value:registered.append(value) or True)
        assert len(registered)==1 and registered[0]['uid']==f['uid'] and registered[0]['gid']==f['gid']
        assert registered[0]['parent_pid']==os.getpid() and registered[0]['pid']>0 and registered[0]['start_ticks']>0
        assert f['config'].read_bytes()==contents['krfbrc']
        assert f['config'].stat().st_uid==f['uid'] and stat.S_IMODE(f['config'].stat().st_mode)==0o600
        assert f['autostart'].stat().st_uid==f['uid'] and stat.S_IMODE(f['autostart'].stat().st_mode)==0o644
    else:
        with pytest.raises(KRFBSessionError) as caught:write_user_configuration(context,contents,expected,root=f['root'],register_child=lambda value:True)
        assert 'SENTINEL' not in str(caught.value)
        assert f['config'].read_bytes()==original
    assert other.read_bytes()==b'UNRELATED-USER-DATA'


def test_writer_cannot_mutate_before_child_identity_is_durably_acknowledged(desktop):
    from alt_deploy.krfb_managed_runtime import prepare_configuration,write_user_configuration
    from alt_deploy.krfb_user_session import KRFBSessionError
    f=desktop;context=discover(f);before=f['config'].read_bytes();registered=[]
    expected={'krfbrc':hashlib.sha256(before).hexdigest(),
              'org.sosn.krfb.desktop':hashlib.sha256(f['autostart'].read_bytes()).hexdigest()}
    contents={'krfbrc':prepare_configuration(before,desired_configuration(),context),
              'org.sosn.krfb.desktop':f['autostart'].read_bytes()}
    with pytest.raises(KRFBSessionError):
        write_user_configuration(context,contents,expected,root=f['root'],register_child=lambda value:registered.append(value) or False)
    assert len(registered)==1 and f['config'].read_bytes()==before


@pytest.mark.parametrize('case',['noop','reload','clients_wait','no_server','policy_unready'])
def test_readiness_predicts_reload_without_a_claim_or_any_mutation(desktop,monkeypatch,case):
    from alt_deploy import krfb_managed_runtime as module
    from alt_deploy.krfb_user_session import KRFBSessionError
    f=desktop;request=runtime_request()
    # Readiness is a separate read-only contract and cannot carry a dispatch
    # claim or choose an executable. Applying it will require the strict claim.
    request={key:value for key,value in request.items() if key not in
             ('context','expected_snapshot_sha256','expected_policy_snapshot_sha256','configuration_template_sha256','autostart_template_sha256')}
    f['config'].write_bytes(desired_configuration() if case=='noop' else f['config'].read_bytes())
    request['autostart']=f['autostart'].read_text()
    if case=='clients_wait':
        (f['krfb']/'fd/8').symlink_to('socket:[2000]')
        (f['root']/'proc/net/tcp').write_text('header\n'+f['row']()+f['row'](inode=2000,state='01'))
    elif case=='no_server':(f['krfb']/'exe').unlink();(f['root']/'proc/net/tcp').write_text('header\n')
    policy={'ready':case!='policy_unready','machine_uuid':request['machine_uuid'],'hostname':request['hostname'],
            'source_sha256':request['source_sha256'],'policy_sha256':request['policy_sha256'],
            'boot_id':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','snapshot_sha256':'3'*64}
    monkeypatch.setattr(module,'read_direct_policy',lambda *a,**k:policy,raising=False)
    before={str(p):p.read_bytes() for p in f['root'].rglob('*') if p.is_file() and not p.is_symlink()}
    if case=='policy_unready':
        with pytest.raises(KRFBSessionError):module.assess_runtime(request,root=f['root'],call=f['probe_call'],limits_reader=f['limits_reader'])
    else:
        result=module.assess_runtime(request,root=f['root'],call=f['probe_call'],limits_reader=f['limits_reader'])
        assert result.disposition==('noop' if case=='noop' else 'waiting_vnc_clients' if case=='clients_wait' else 'apply')
        assert result.needs_reload is (case in ('reload','clients_wait'))
        assert 'SENTINEL' not in repr(result)
    assert before=={str(p):p.read_bytes() for p in f['root'].rglob('*') if p.is_file() and not p.is_symlink()}


@pytest.mark.parametrize('case',['ready','unprepared','source_changed','helper_changed','symlink','external_blocker'])
def test_readiness_uses_only_the_pinned_installed_policy_and_current_rules(tmp_path,case):
    from alt_deploy.krfb_managed_runtime import read_direct_policy
    from alt_deploy.krfb_user_session import KRFBSessionError
    from test_remote_access_policy import helper,runtime,observe,request as policy_request
    from test_component_catalog import SOURCE
    module=helper();state,run=runtime(tmp_path,legacy=False)
    installed=tmp_path/'usr/local/libexec/alt-vnc-access-policy';installed.parent.mkdir(parents=True)
    installed.write_bytes((SOURCE/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2').read_bytes());installed.chmod(0o700)
    if case!='unprepared':module.apply_policy(tmp_path,policy_request(observe(module,tmp_path,run)),run=run)
    request=runtime_request();request['policy_helper_sha256']=hashlib.sha256(installed.read_bytes()).hexdigest()
    request['policy_sha256']=module.POLICY_SHA256
    marker=tmp_path/'untrusted-code-must-not-run'
    if case=='helper_changed':installed.write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n')
    elif case=='symlink':
        actual=installed.with_suffix('.original');installed.rename(actual);installed.symlink_to(actual)
    elif case=='source_changed':request['source_sha256']='0'*64
    elif case=='external_blocker':state['nft']['nftables']=[
        {'table':{'family':'inet','name':'external'}},
        {'chain':{'family':'inet','table':'external','name':'input','hook':'input','type':'filter','prio':0,'policy':'drop'}}]
    if case=='ready':assert read_direct_policy(request,root=tmp_path,run=run)['ready'] is True
    else:
        with pytest.raises(KRFBSessionError):read_direct_policy(request,root=tmp_path,run=run)
    assert not marker.exists()


def prepared_assessment(f,monkeypatch):
    from alt_deploy import krfb_managed_runtime as module
    request=runtime_request();request['autostart']=f['autostart'].read_text()
    request['autostart_template_sha256']=hashlib.sha256(request['autostart'].encode()).hexdigest()
    readonly={key:value for key,value in request.items() if key not in ('context','expected_snapshot_sha256',
        'expected_policy_snapshot_sha256','configuration_template_sha256','autostart_template_sha256')}
    policy={'ready':True,'machine_uuid':request['machine_uuid'],'hostname':request['hostname'],
        'source_sha256':request['source_sha256'],'policy_sha256':request['policy_sha256'],
        'boot_id':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','snapshot_sha256':'3'*64}
    monkeypatch.setattr(module,'read_direct_policy',lambda *a,**k:policy)
    assessment=module.assess_runtime(readonly,root=f['root'],call=f['probe_call'],limits_reader=f['limits_reader'])
    request['expected_snapshot_sha256']=assessment.snapshot['snapshot_sha256']
    request['expected_policy_snapshot_sha256']=policy['snapshot_sha256']
    (f['root']/'var/lib').mkdir(parents=True,exist_ok=True)
    return request,assessment


@pytest.mark.parametrize('case',['normal','repeat_claim','changed_config','namespace_symlink'])
def test_closed_runtime_backup_precedes_effects_and_never_reuses_a_claim(desktop,monkeypatch,case):
    from alt_deploy import krfb_managed_runtime as module
    from alt_deploy.krfb_user_session import KRFBSessionError
    f=desktop;request,assessment=prepared_assessment(f,monkeypatch)
    original=f['config'].read_bytes();autostart=f['autostart'].read_bytes()
    namespace=f['root']/'var/lib/alt-krfb-user-runtime'
    if case=='changed_config':f['config'].write_bytes(original+b'\n# raced change\n')
    elif case=='namespace_symlink':
        other=f['root']/'unrelated';other.mkdir();namespace.symlink_to(other,target_is_directory=True)
    if case in ('changed_config','namespace_symlink'):
        with pytest.raises(KRFBSessionError):module.create_runtime_backup(request,assessment,root=f['root'])
    else:
        directory=module.create_runtime_backup(request,assessment,root=f['root'])
        assert stat.S_IMODE(directory.stat().st_mode)==0o700
        manifest=json.loads((directory/'manifest.json').read_text())
        assert manifest['context']==request['context'] and manifest['helper']['pid']==os.getpid()
        assert manifest['helper']['start_ticks']>0
        assert (directory/'krfbrc').read_bytes()==original
        assert (directory/'autostart.desktop').read_bytes()==autostart
        for filename,digest in manifest['files'].items():
            target=directory/filename
            assert stat.S_IMODE(target.stat().st_mode)==0o600
            assert hashlib.sha256(target.read_bytes()).hexdigest()==digest
        if case=='repeat_claim':
            before={p.name:p.read_bytes() for p in directory.iterdir()}
            with pytest.raises(KRFBSessionError):module.create_runtime_backup(request,assessment,root=f['root'])
            assert before=={p.name:p.read_bytes() for p in directory.iterdir()}
    assert f['config'].read_bytes()==(original+b'\n# raced change\n' if case=='changed_config' else original)
    assert f['autostart'].read_bytes()==autostart
