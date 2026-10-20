"""Only a proven owned legacy VNC guard can be retired."""
import copy
import importlib.machinery
import importlib.util
import os
import json
import hashlib
import io
import subprocess
import sys
from pathlib import Path

import pytest

from test_component_catalog import SOURCE

UNIT = '''[Unit]
Description=Restrict VNC to the workstation loopback interface
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target display-manager.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/alt-vnc-network-restrict
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
'''
LEGACY_HELPER = '''#!/bin/sh
set -eu
umask 077
exec 9>/run/alt-vnc-network-restrict.lock
flock -x 9
rules=$(mktemp /run/alt-vnc-network-restrict.XXXXXX)
trap 'rm -f "$rules"' EXIT HUP INT TERM
if /sbin/nft list table inet alt_vnc_restrict >/dev/null 2>&1; then
  printf 'delete table inet alt_vnc_restrict\\n' >> "$rules"
fi
cat >> "$rules" <<'NFT'
table inet alt_vnc_restrict {
 chain input {
  type filter hook input priority -10; policy accept;
  iifname != "lo" tcp dport 5900 counter reject with tcp reset comment "VNC only through local SSH tunnel"
 }
}
NFT
/sbin/nft --check -f "$rules"
/sbin/nft -f "$rules"
'''


def helper():
    path=SOURCE/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2'
    loader=importlib.machinery.SourceFileLoader('vnc_access_policy_test',str(path))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    return module


def legacy_rules():
    return {'nftables':[
        {'metainfo':{'json_schema_version':1}},
        {'table':{'family':'inet','name':'alt_vnc_restrict','handle':3}},
        {'chain':{'family':'inet','table':'alt_vnc_restrict','name':'input','handle':1,
                  'type':'filter','hook':'input','prio':-10,'policy':'accept'}},
        {'rule':{'family':'inet','table':'alt_vnc_restrict','chain':'input','handle':2,
                 'comment':'VNC only through local SSH tunnel','expr':[
            {'match':{'op':'!=','left':{'meta':{'key':'iifname'}},'right':'lo'}},
            {'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':5900}},
            {'counter':{'packets':8,'bytes':416}}, {'reject':{'type':'tcp reset'}}]}}]}


def files(root):
    unit=root/'etc/systemd/system/alt-vnc-network-restrict.service';unit.parent.mkdir(parents=True)
    script=root/'usr/local/libexec/alt-vnc-network-restrict';script.parent.mkdir(parents=True)
    unit.write_text(UNIT);unit.chmod(0o644)
    script.write_text(LEGACY_HELPER);script.chmod(0o700)
    return unit,script


def service(*, enabled=False, absent=False):
    return {'load_state':'not-found' if absent else 'loaded','active_state':'inactive',
            'sub_state':'dead','unit_file_state':'' if absent else 'enabled' if enabled else 'disabled',
            'main_pid':0,'drop_ins':[], 'fragment_path':'' if absent else '/etc/systemd/system/alt-vnc-network-restrict.service'}


def test_clean_pc_has_no_obsolete_restriction_to_install(tmp_path):
    result=helper().inspect_legacy(tmp_path,{'nftables':[]},service(absent=True))
    assert result=={'owned_legacy':False,'legacy_table_present':False,'retirement_required':False,
                    'service_disabled':True,'external_policy_clear':True}


@pytest.mark.parametrize('enabled,table', [(False,False),(True,False),(True,True),(False,True)])
def test_owned_legacy_guard_is_identified_without_mutation(tmp_path,enabled,table):
    unit,script=files(tmp_path)
    before=(unit.read_bytes(),script.read_bytes())
    nft=legacy_rules() if table else {'nftables':[]}
    saved=copy.deepcopy(nft)
    result=helper().inspect_legacy(tmp_path,nft,service(enabled=enabled))
    assert result['owned_legacy'] is True
    assert result['legacy_table_present'] is table
    assert result['retirement_required'] is (table or enabled)
    assert (unit.read_bytes(),script.read_bytes())==before and nft==saved


@pytest.mark.parametrize('case', ['unit_bytes','helper_bytes','helper_mode','symlink','missing_helper',
    'dropin','active_process','wrong_fragment','extra_rule','wrong_port','wrong_family','extra_chain','table_only'])
def test_name_collision_or_unproven_rule_never_admits_retirement(tmp_path,case):
    module=helper();unit,script=files(tmp_path);nft=legacy_rules();state=service(enabled=True)
    if case=='unit_bytes': unit.write_text(UNIT+'ExecStop=/bin/false\n')
    elif case=='helper_bytes': script.write_text(LEGACY_HELPER+'echo unknown\n')
    elif case=='helper_mode': script.chmod(0o777)
    elif case=='symlink':
        actual=tmp_path/'other';script.rename(actual);script.symlink_to(actual)
    elif case=='missing_helper': script.unlink()
    elif case=='dropin': state['drop_ins']=['/etc/systemd/system/alt-vnc-network-restrict.service.d/override.conf']
    elif case=='active_process': state.update(main_pid=123,active_state='activating',sub_state='start')
    elif case=='wrong_fragment': state['fragment_path']='/run/systemd/system/alt-vnc-network-restrict.service'
    elif case=='extra_rule': nft['nftables'].append(copy.deepcopy(nft['nftables'][-1]))
    elif case=='wrong_port': nft['nftables'][-1]['rule']['expr'][1]['match']['right']=22
    elif case=='wrong_family': nft['nftables'][1]['table']['family']='ip'
    elif case=='extra_chain': nft['nftables'].append({'chain':{'family':'inet','table':'alt_vnc_restrict','name':'unknown'}})
    elif case=='table_only': unit.unlink();script.unlink()
    with pytest.raises(module.PolicyError) as caught: module.inspect_legacy(tmp_path,nft,state)
    assert str(caught.value)=='vnc_policy_ownership_unverified'


@pytest.mark.parametrize('blocked', [False, True])
def test_unrelated_policy_is_preserved_and_conflicting_input_is_diagnosed(tmp_path,blocked):
    module=helper();files(tmp_path);nft=legacy_rules()
    external=[{'table':{'family':'inet','name':'unrelated'}},
        {'chain':{'family':'inet','table':'unrelated','name':'input','type':'filter',
                  'hook':'input','prio':0,'policy':'drop' if blocked else 'accept'}},
        {'rule':{'family':'inet','table':'unrelated','chain':'input','expr':[
            {'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':22}}, {'drop':None}]}}]
    nft['nftables'].extend(external);before=copy.deepcopy(nft)
    result=module.inspect_legacy(tmp_path,nft,service(enabled=True))
    assert result['external_policy_clear'] is (not blocked)
    assert nft==before


def runtime(root, *, legacy=True, listener=False):
    if legacy:files(root)
    for name,value in [('sys/class/dmi/id/product_uuid','11111111-2222-3333-4444-555555555555'),
                       ('proc/sys/kernel/random/boot_id','aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')]:
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n')
    (root/'var/lib').mkdir(parents=True,exist_ok=True)
    (root/'run').mkdir(exist_ok=True)
    state={'service':service(enabled=legacy,absent=not legacy),
           'nft':legacy_rules() if legacy else {'nftables':[]},'listener':listener,
           'mutations':[],'fail_delete':False}
    def run(argv):
        if argv==['hostname','-s']:return 0,'alt-test-pc1'
        if argv[:4]==['/sbin/nft','-j','list','ruleset']:return 0,json.dumps(state['nft'])
        if argv[:2]==['systemctl','show']:
            mapping={'LoadState':'load_state','ActiveState':'active_state','SubState':'sub_state',
                     'UnitFileState':'unit_file_state','MainPID':'main_pid',
                     'DropInPaths':'drop_ins','FragmentPath':'fragment_path'}
            return 0,'\n'.join(k+'='+(' '.join(state['service'][v]) if isinstance(state['service'][v],list)
                                      else str(state['service'][v])) for k,v in mapping.items())
        if argv[0]=='ss':return 0,'LISTEN 0 5 0.0.0.0:5900 0.0.0.0:*' if state['listener'] else ''
        if argv==['systemctl','disable','--now','alt-vnc-network-restrict.service']:
            state['mutations'].append(argv);state['service'].update(unit_file_state='disabled',active_state='inactive',sub_state='dead')
            return 0,''
        if argv==['/sbin/nft','delete','table','inet','alt_vnc_restrict']:
            state['mutations'].append(argv)
            if state['fail_delete']:return 1,'PRIVATE-ERROR-SENTINEL'
            state['nft']['nftables']=[item for item in state['nft']['nftables']
                if not any(isinstance(v,dict) and (v.get('table')==TABLE_NAME or k=='table' and v.get('name')==TABLE_NAME)
                           for k,v in item.items())]
            return 0,''
        raise AssertionError('Unexpected command: '+repr(argv))
    return state,run


TABLE_NAME='alt_vnc_restrict'


def request(snapshot, *, authenticated=False):
    return {'machine_uuid':'11111111-2222-3333-4444-555555555555','hostname':'alt-test-pc1',
            'source_sha256':'a'*64,'expected_snapshot_sha256':snapshot['snapshot_sha256'],
            'listener_authenticated':authenticated,'context':{
                'schema_version':1,'kind':'complete_workstation','phase':'system',
                'job_id':'job-20261020T010000Z-12345678','claim_sha256':'b'*64,
                'plan_sha256':'d'*64,'workflow_policy_sha256':'e'*64,
                'machine_uuid':'11111111-2222-3333-4444-555555555555','source_sha256':'a'*64,
                'policy_sha256':snapshot['policy_sha256']}}


def observe(module,root,run):
    return module.observe_policy(root,'11111111-2222-3333-4444-555555555555','alt-test-pc1','a'*64,run=run)


@pytest.mark.parametrize('legacy', [False,True])
def test_policy_apply_is_bound_backed_up_verified_and_then_unchanged(tmp_path,legacy):
    module=helper();state,run=runtime(tmp_path,legacy=legacy)
    before=observe(module,tmp_path,run)
    assert before['ready'] is False
    result=module.apply_policy(tmp_path,request(before),run=run)
    assert result['ready'] is True and result['changed'] is True
    if legacy:
        assert state['mutations']==[['systemctl','disable','--now','alt-vnc-network-restrict.service'],
                                    ['/sbin/nft','delete','table','inet','alt_vnc_restrict']]
        backups=list((tmp_path/'var/lib/alt-vnc-access-policy').glob('backup-*'))
        assert len(backups)==1
        assert backups[0].stat().st_mode & 0o777==0o700
        assert all(p.stat().st_mode & 0o777==0o600 for p in backups[0].iterdir())
    else:assert state['mutations']==[]
    marker=tmp_path/'var/lib/alt-vnc-access-policy/prepared.json'
    assert marker.stat().st_mode & 0o777==0o600
    snapshot=observe(module,tmp_path,run);assert snapshot['ready'] is True
    original=marker.read_bytes();original_mtime=marker.stat().st_mtime_ns
    assert module.apply_policy(tmp_path,request(snapshot),run=run)['changed'] is False
    assert marker.read_bytes()==original and marker.stat().st_mtime_ns==original_mtime


@pytest.mark.parametrize('case', ['uuid','boot','nft','context','source','listener','environment'])
def test_policy_migration_rechecks_every_binding_before_mutation(tmp_path,monkeypatch,case):
    module=helper();state,run=runtime(tmp_path,listener=case in ('listener','environment'))
    before=observe(module,tmp_path,run);plan=request(before)
    if case=='uuid':(tmp_path/'sys/class/dmi/id/product_uuid').write_text('99999999-2222-3333-4444-555555555555')
    elif case=='boot':(tmp_path/'proc/sys/kernel/random/boot_id').write_text('99999999-bbbb-cccc-dddd-eeeeeeeeeeee')
    elif case=='nft':state['nft']['nftables'].append({'chain':{'family':'inet','table':TABLE_NAME,'name':'unexpected'}})
    elif case=='context':plan['context']['kind']='manual'
    elif case=='source':plan['context']['source_sha256']='c'*64
    elif case=='environment':monkeypatch.setenv('ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED','true')
    with pytest.raises(module.PolicyError):module.apply_policy(tmp_path,plan,run=run)
    assert state['mutations']==[]


def test_post_dispatch_uncertainty_never_claims_success_or_deletes_another_table(tmp_path):
    module=helper();state,run=runtime(tmp_path);state['fail_delete']=True
    before=observe(module,tmp_path,run)
    with pytest.raises(module.PolicyError) as caught:module.apply_policy(tmp_path,request(before),run=run)
    assert str(caught.value)=='vnc_policy_outcome_unverified'
    assert state['mutations'][-1]==['/sbin/nft','delete','table','inet','alt_vnc_restrict']
    assert list((tmp_path/'var/lib/alt-vnc-access-policy').glob('backup-*'))
    assert not (tmp_path/'var/lib/alt-vnc-access-policy/prepared.json').exists()


def test_corrupt_backup_blocks_before_any_firewall_or_service_change(tmp_path,monkeypatch):
    module=helper();state,run=runtime(tmp_path)
    snapshot=observe(module,tmp_path,run);write=module._write_private
    def corrupt(path,data):
        write(path,data)
        if path.name=='helper.sh':path.write_bytes(b'CORRUPTED-BACKUP')
    monkeypatch.setattr(module,'_write_private',corrupt)
    with pytest.raises(module.PolicyError):module.apply_policy(tmp_path,request(snapshot),run=run)
    assert state['mutations']==[]


def test_marker_schema_is_strict_and_unknown_owned_state_is_not_overwritten(tmp_path):
    module=helper();state,run=runtime(tmp_path,legacy=False)
    module.apply_policy(tmp_path,request(observe(module,tmp_path,run)),run=run)
    marker=tmp_path/'var/lib/alt-vnc-access-policy/prepared.json'
    value=json.loads(marker.read_bytes());value['schema_version']=True
    marker.write_text(json.dumps(value));before=marker.read_bytes()
    with pytest.raises(module.PolicyError):observe(module,tmp_path,run)
    assert marker.read_bytes()==before


def test_new_source_policy_marker_keeps_its_previous_private_copy(tmp_path):
    module=helper();state,run=runtime(tmp_path,legacy=False)
    module.apply_policy(tmp_path,request(observe(module,tmp_path,run)),run=run)
    marker=tmp_path/'var/lib/alt-vnc-access-policy/prepared.json';before=marker.read_bytes()
    snapshot=module.observe_policy(tmp_path,'11111111-2222-3333-4444-555555555555','alt-test-pc1','c'*64,run=run)
    plan=request(snapshot);plan['source_sha256']='c'*64;plan['context']['source_sha256']='c'*64
    assert module.apply_policy(tmp_path,plan,run=run)['ready'] is True
    backups=list((tmp_path/'var/lib/alt-vnc-access-policy').glob('backup-*/marker-before.json'))
    assert len(backups)==1 and backups[0].read_bytes()==before


def test_unrelated_policy_drift_after_marker_write_remains_uncertain(tmp_path,monkeypatch):
    module=helper();state,run=runtime(tmp_path,legacy=False)
    snapshot=observe(module,tmp_path,run);save=module._save_marker
    def drift(root,before):
        save(root,before)
        state['nft']['nftables'].append({'table':{'family':'inet','name':'external-change'}})
    monkeypatch.setattr(module,'_save_marker',drift)
    with pytest.raises(module.PolicyError) as caught:module.apply_policy(tmp_path,request(snapshot),run=run)
    assert str(caught.value)=='vnc_policy_outcome_unverified'
    assert state['nft']['nftables']==[{'table':{'family':'inet','name':'external-change'}}]


def cli_request():
    return {'schema_version':1,'machine_uuid':'11111111-2222-3333-4444-555555555555',
            'hostname':'alt-test-pc1','source_sha256':'a'*64,'helper_sha256':'f'*64}


def test_embedded_readonly_cli_needs_no_installed_helper_or_user_profile(tmp_path,monkeypatch,capsys):
    module=helper();monkeypatch.setattr(module,'ROOT',tmp_path)
    monkeypatch.setattr(module,'__file__',None)
    monkeypatch.setattr(module,'observe_policy',lambda *a,**k:{'ready':False,'snapshot_sha256':'b'*64})
    monkeypatch.setattr(module.sys,'stdin',io.StringIO(json.dumps(cli_request())))
    assert module.main(['--observe'])==0
    result=json.loads(capsys.readouterr().out)
    assert result['status']=='ok' and result['operation']=='observe'
    assert result['helper_sha256']=='f'*64 and result['observation']['ready'] is False


@pytest.mark.parametrize('case', ['extra','duplicate','oversized','version','argv','unknown_error'])
def test_cli_rejects_unsafe_input_without_echoing_it(tmp_path,monkeypatch,capsys,case):
    module=helper();monkeypatch.setattr(module,'ROOT',tmp_path)
    monkeypatch.setattr(module,'__file__',None)
    payload=cli_request();args=['--observe']
    if case=='extra':payload['password']='PRIVATE-SECRET-SENTINEL'
    elif case=='version':payload['schema_version']=True
    elif case=='argv':args=['--observe','--command=PRIVATE-SECRET-SENTINEL']
    raw=json.dumps(payload)
    if case=='duplicate':raw=raw[:-1]+',"source_sha256":"PRIVATE-SECRET-SENTINEL"}'
    elif case=='oversized':raw='PRIVATE-SECRET-SENTINEL'*4000
    elif case=='unknown_error':
        def fail(*a,**k):raise module.PolicyError('PRIVATE-SECRET-SENTINEL')
        monkeypatch.setattr(module,'observe_policy',fail)
    monkeypatch.setattr(module.sys,'stdin',io.StringIO(raw))
    assert module.main(args)==4
    output=capsys.readouterr().out
    assert 'SENTINEL' not in output and json.loads(output)['status']=='blocked'


def test_apply_cli_requires_the_exact_installed_owned_helper(tmp_path,monkeypatch,capsys):
    module=helper();monkeypatch.setattr(module,'ROOT',tmp_path)
    path=tmp_path/'usr/local/libexec/alt-vnc-access-policy';path.parent.mkdir(parents=True)
    path.write_bytes(b'synthetic-published-helper');path.chmod(0o700)
    monkeypatch.setattr(module,'__file__',str(path))
    snapshot={'snapshot_sha256':'b'*64,'policy_sha256':'c'*64}
    payload=dict(request(snapshot),schema_version=1,helper_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    called=[]
    monkeypatch.setattr(module,'apply_policy',lambda *a,**k:called.append(a) or {'ready':True,'changed':False})
    monkeypatch.setattr(module.sys,'stdin',io.StringIO(json.dumps(payload)))
    assert module.main(['--apply'])==0 and len(called)==1
    assert json.loads(capsys.readouterr().out)['result']['ready'] is True
    payload['helper_sha256']='d'*64
    monkeypatch.setattr(module.sys,'stdin',io.StringIO(json.dumps(payload)))
    assert module.main(['--apply'])==4 and len(called)==1
    assert json.loads(capsys.readouterr().out)['status']=='blocked'


def test_registry_policy_recipe_is_independent_and_preserves_legacy_profiles(tmp_path):
    from alt_deploy.component_catalog import ComponentCatalog
    from alt_deploy.component_probe import desired_queries
    import yaml
    project=SOURCE
    catalog=ComponentCatalog.load(project)
    component=catalog.component('remote.vnc_policy')
    assert component['dependencies']==[]
    assert component['execution']['requires_domain'] is False
    assert component['execution']['requires_user_home'] is False
    query=desired_queries(project,catalog,[component])[0]
    assert query['recipe']=='vnc_policy' and query['helper_source']==(SOURCE/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2').read_text()
    assert len(query['source_sha256'])==64
    profiles=yaml.safe_load((project/'group_vars/software_catalog.yml').read_text())['setup_catalog']['profiles']
    profiles=[p for p in profiles if p['id']!='workstation-full-v1']
    assert hashlib.sha256(json.dumps(profiles,sort_keys=True,separators=(',',':')).encode()).hexdigest()=='6dd71b909ed4b17939b488a4e63340118b822340592d1d7cfc82ae49d761044f'


def test_component_policy_observation_requires_preparation_not_application_readiness(tmp_path):
    from alt_deploy.component_probe_script import inspect_component
    module=helper();state,run=runtime(tmp_path,legacy=False)
    query={'id':'remote.vnc_policy','recipe':'vnc_policy','helper_source':(SOURCE/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2').read_text(),'source_sha256':'a'*64}
    # The common collector already binds identity, while this recipe also
    # observes it afresh and cannot equate an open port with authenticated KRFB.
    fact=inspect_component(tmp_path,query,{},None,None,run)
    assert fact['checks']=={'ready':False,'backend_verified':True,'external_policy_clear':True}
    module.apply_policy(tmp_path,request(observe(module,tmp_path,run)),run=run)
    fact=inspect_component(tmp_path,query,{},None,None,run)
    assert fact['checks']=={'ready':True,'backend_verified':True,'external_policy_clear':True}
    assert 'authenticated' not in fact['checks']


@pytest.mark.parametrize('case',['clean','absent_parent','missing_context','wrong_phase','helper_collision','parent_symlink'])
def test_real_ansible_policy_protocol_and_noop(tmp_path,case):
    import yaml
    executable=Path(sys.executable).with_name('ansible-playbook')
    if not executable.is_file():pytest.skip('Pinned real Ansible is unavailable')
    root=tmp_path/'node';root.mkdir()
    module=helper();state,run=runtime(root,legacy=False)
    before=observe(module,root,run);plan=request(before)
    destination=root/'usr/local/libexec/alt-vnc-access-policy';destination.parent.mkdir(parents=True)
    for p in (root/'usr',root/'usr/local',destination.parent):p.chmod(0o755)
    fixed=SOURCE/'roles/remote_access_policy/templates/alt-vnc-access-policy.py.j2'
    evidence={'schema_version':1,'helper_sha256':hashlib.sha256(fixed.read_bytes()).hexdigest(),
              'observation':before,'listener_authenticated':False}
    launcher=tmp_path/'fixture-launcher.py'
    launcher.write_text('import sys\nfrom pathlib import Path\n'+
        'sys.path.insert(0,'+repr(str(Path(__file__).parent))+')\n'+
        'from test_remote_access_policy import helper,runtime\n'+
        'module=helper();module.ROOT=Path('+repr(str(root))+')\n'+
        'module.__file__='+repr(str(destination))+'\n'+
        'state,run=runtime(module.ROOT,legacy=False)\n'+
        'original=module.apply_policy\n'+
        'module.apply_policy=lambda root,request:original(root,request,run=run)\n'+
        'raise SystemExit(module.main(["--apply"]))\n')
    tasks=yaml.safe_load((SOURCE/'roles/remote_access_policy/tasks/main.yml').read_text())
    for task in tasks:
        for key in ('ansible.builtin.stat','ansible.builtin.template','ansible.builtin.file'):
            if key in task:
                for pathkey in ('path','dest'):
                    if pathkey in task[key] and task[key][pathkey].startswith('/usr/'):
                        task[key][pathkey]=str(root)+task[key][pathkey]
        if task.get('name')=='Inspect fixed policy helper parent directories':
            task['loop']=[str(root)+p for p in task['loop']]
        if 'ansible.builtin.assert' in task:
            task['ansible.builtin.assert']['that']=[s.replace('.uid == 0','.uid == '+str(os.getuid())).replace("item.item == '/usr/local/libexec'",'item.item == '+repr(str(destination.parent)))
                                                    for s in task['ansible.builtin.assert']['that']]
        if 'ansible.builtin.file' in task:task['ansible.builtin.file'].update(owner=str(os.getuid()),group=str(os.getgid()))
        if 'ansible.builtin.template' in task:
            task['ansible.builtin.template'].update(src=str(fixed),owner=str(os.getuid()),group=str(os.getgid()))
        if 'ansible.builtin.command' in task:
            task['ansible.builtin.command']['argv']=[sys.executable,str(launcher)]
    variables={'ansible_connection':'local','ansible_become':False,'ansible_python_interpreter':sys.executable,
               'alt_setup_workflow_context':plan['context'],'alt_setup_vnc_policy_evidence':evidence}
    if case=='missing_context':variables.pop('alt_setup_workflow_context')
    if case=='wrong_phase':variables['alt_setup_workflow_context']['phase']='user'
    if case=='helper_collision':destination.write_bytes(b'UNOWNED-HELPER-SENTINEL');destination.chmod(0o700)
    if case=='absent_parent':destination.parent.rmdir()
    if case=='parent_symlink':
        destination.parent.rmdir();elsewhere=tmp_path/'external';elsewhere.mkdir()
        destination.parent.symlink_to(elsewhere,target_is_directory=True)
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,
        'vars':variables,'tasks':tasks}],sort_keys=False))
    cfg=tmp_path/'ansible.cfg';cfg.write_text('[defaults]\nretry_files_enabled=False\n')
    env=dict(os.environ,ANSIBLE_CONFIG=str(cfg),ALT_DEPLOY_KRFB_ALLOW_UNRESTRICTED='1')
    for iteration in range(2 if case in ('clean','absent_parent') else 1):
        result=subprocess.run([str(executable),'-i','localhost,',str(play)],env=env,cwd=tmp_path,
                               capture_output=True,text=True,timeout=40)
        assert (result.returncode==0) is (case in ('clean','absent_parent')),result.stdout+result.stderr
        assert 'UNOWNED-HELPER-SENTINEL' not in result.stdout+result.stderr
        if case in ('clean','absent_parent'):
            assert (root/'var/lib/alt-vnc-access-policy/prepared.json').is_file()
            if iteration:assert 'changed=0' in result.stdout
            else:
                # Each native invocation observes afresh; consumed evidence
                # is intentionally unsuitable for blind transport replay.
                evidence['observation']=observe(module,root,run)
                play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,
                    'vars':variables,'tasks':tasks}],sort_keys=False))
        else:
            assert not (root/'var/lib/alt-vnc-access-policy/prepared.json').exists()
            if case=='helper_collision':assert destination.read_bytes()==b'UNOWNED-HELPER-SENTINEL'
