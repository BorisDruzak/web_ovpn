"""Controller wallet observations remain fixed, source-bound and read-only."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from test_component_catalog import SOURCE,project


UUID='11111111-2222-3333-4444-555555555555'
BOOT='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def fixture(tmp_path):
    return (SimpleNamespace(ansible_project_dir=SOURCE,known_hosts_file=tmp_path/'known',private_key_file=tmp_path/'key'),
        SimpleNamespace(uuid=UUID,hostname='alt-test-pc1',ip='192.0.2.10'),
        {'login':'synthetic.user','upn':'synthetic.user@sosnadmin.local'})


def observation(request,*,installed=True,disposition='noop'):
    value={k:request[k] for k in ('schema_version','machine_uuid','hostname','login','wallet_name','helper_sha256')}
    value.update(boot_id=BOOT,uid=10001,gid=10001,installed_helper_sha256=request['helper_sha256'] if installed else None,
                 helper_installed=installed,disposition=disposition,readiness_sha256='a'*64)
    value['snapshot_sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return value


@pytest.mark.parametrize('case',['compliant','defect','missing_helper','no_session','extra_secret','wrong_uuid','wrong_boot','wrong_sha','bad_hash'])
def test_fixed_candidate_observer_never_dispatches_repair_or_echoes_private_output(tmp_path,case):
    from alt_deploy.kwallet_runtime import observe
    settings,machine,user=fixture(tmp_path);calls=[]
    def runner(command,**options):
        calls.append((command,options));request=json.loads(options['input_text'])
        assert '--apply' not in command[-1].splitlines()[-1:]
        if case=='no_session':return 4,json.dumps({'schema_version':1,'status':'blocked','code':'graphical_session_unavailable'}),'PRIVATE-SECRET-SENTINEL'
        value=observation(request,installed=case!='missing_helper',disposition='repair' if case=='defect' else 'noop')
        if case=='extra_secret':value['environment']='PRIVATE-SECRET-SENTINEL'
        elif case=='wrong_uuid':value['machine_uuid']='99999999-2222-3333-4444-555555555555'
        elif case=='wrong_boot':value['boot_id']='99999999-2222-3333-4444-555555555555'
        elif case=='wrong_sha':value['helper_sha256']='0'*64
        elif case=='bad_hash':value['snapshot_sha256']='0'*64
        return 0,json.dumps({'schema_version':1,'status':'ok','observation':value}),'PRIVATE-SECRET-SENTINEL'
    if case in ('extra_secret','wrong_uuid','wrong_boot','wrong_sha','bad_hash'):
        with pytest.raises(ControlError) as caught:observe(settings,machine,user,expected_boot_id=BOOT,runner=runner)
        assert 'SENTINEL' not in str(caught.value)
    else:
        result=observe(settings,machine,user,expected_boot_id=BOOT,runner=runner)
        assert 'SENTINEL' not in json.dumps(result)
        if case=='no_session':assert result=={'status':'blocked','code':'graphical_session_unavailable'}
        else:
            assert result['status']=='ok'
            assert result['observation']['disposition']==('repair' if case=='defect' else 'noop')
    assert len(calls)==1
    command,options=calls[0]
    assert command[:4]==['/usr/bin/ssh','-F','/dev/null','-T']
    assert 'StrictHostKeyChecking=yes' in command and 'ForwardAgent=no' in command
    assert 'ControlMaster=no' in command and 'ProxyJump=none' in command
    assert options['timeout']<=60 and options['max_bytes']<=65536


def test_published_wallet_defaults_define_only_fixed_repair_parameters():
    from alt_deploy.kwallet_runtime import specification
    # The actual source defaults define the ordinary complete-preset parameter.
    value=specification(SOURCE)
    assert value['wallet_name']=='recovered-wallet' and value['previous_helper_sha256']==[]
    assert len(value['helper_sha256'])==64
    assert set(value)=={'wallet_name','helper_sha256','previous_helper_sha256'}


@pytest.mark.parametrize('bad',[{'kwallet_repair_new_name':'../escape'},
    {'kwallet_repair_new_name':''},{'kwallet_repair_previous_helper_sha256':['0'*64,'0'*64]},
    {'kwallet_repair_previous_helper_sha256':['PRIVATE-SECRET-SENTINEL']},
    {'kwallet_repair_previous_helper_sha256':'not-a-list'},
    {'kwallet_repair_previous_helper_sha256':[{}]}])
def test_published_wallet_settings_reject_arbitrary_names_and_migration_hashes(project,bad):
    import yaml
    from alt_deploy.kwallet_runtime import specification
    path=project/'roles/kwallet_empty_name_repair/defaults/main.yml'
    document=yaml.safe_load(path.read_text());document.update(bad);path.write_text(yaml.safe_dump(document))
    with pytest.raises(ControlError) as caught:specification(project)
    assert caught.value.code=='kwallet_specification_unverified' and 'SENTINEL' not in str(caught.value)
