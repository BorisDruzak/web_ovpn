"""Exercise the exact inspected vendor modules and transactional client repair."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import types

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT/'deploy/alt-linux/ansible/roles/alt_group_policy_compat'
FIXTURES = Path(__file__).with_name('fixtures')/'gpupdate-0.16.1'


def helper():
    spec = importlib.util.spec_from_file_location('gpupdate_compat', ROLE/'files/gpupdate_compat.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(tmp_path, fixed=False):
    m = helper()
    for p in m.PATCHES:
        dest = tmp_path/p['path'].lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = (FIXTURES/(p['id']+'.py.txt')).read_bytes()
        assert hashlib.sha256(data).hexdigest() == p['before_sha256']
        dest.write_bytes(m.patched(data, p) if fixed else data)
        dest.chmod(0o644)
    packages = lambda path: next((p['package'], p['evr']) for p in m.PATCHES if str(path).endswith(p['path']))
    return m, packages


def tree(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


def run(m, root, packages, apply=False, **kwargs):
    return m.repair(root=root, owner=os.getuid(), package_query=packages,
                    busy=lambda: False, apply=apply, **kwargs)


def test_check_predicts_all_repairs_without_writes(tmp_path):
    m, packages = fixture(tmp_path)
    before = tree(tmp_path)
    result = run(m, tmp_path, packages)
    assert result['changed'] is True and result['backup_id'] is None
    assert [v['state'] for v in result['fixes']] == ['would_patch']*3
    assert tree(tmp_path) == before
    assert not (tmp_path/'var').exists() and not (tmp_path/'run').exists()


def test_apply_backups_exact_originals_and_second_run_is_noop(tmp_path):
    m, packages = fixture(tmp_path)
    before = tree(tmp_path)
    result = run(m, tmp_path, packages, True)
    assert result['changed'] is True and result['backup_id']
    backup = tmp_path/'var/backups/alt-gpupdate-compat'/result['backup_id']
    manifest = json.loads((backup/'manifest.json').read_text())
    assert manifest['state'] == 'applied'
    assert (backup/'rollback.py').is_file()
    for p in m.PATCHES:
        current = tmp_path/p['path'].lstrip('/')
        assert hashlib.sha256(current.read_bytes()).hexdigest() == p['after_sha256']
        assert (backup/(p['id']+'.original')).read_bytes() == before[p['path'].lstrip('/')][0]
        assert current.stat().st_mode & 0o777 == 0o644
    after = tree(tmp_path)
    assert run(m, tmp_path, packages, True)['changed'] is False
    assert tree(tmp_path) == after


def test_existing_pilot_fixes_are_readonly_noop(tmp_path):
    m, packages = fixture(tmp_path, fixed=True)
    before = tree(tmp_path)
    assert run(m, tmp_path, packages, True)['changed'] is False
    assert tree(tmp_path) == before and not (tmp_path/'var').exists()


@pytest.mark.parametrize('fault', ['modified', 'symlink', 'writable', 'parent_symlink', 'new_package', 'missing'])
def test_any_unverified_module_rejects_whole_plan_before_mutation(tmp_path, fault):
    m, packages = fixture(tmp_path)
    p = tmp_path/m.PATCHES[-1]['path'].lstrip('/')
    if fault == 'modified': p.write_text(p.read_text()+'\n# unknown administrator change\n')
    elif fault == 'symlink':
        p.rename(p.with_suffix('.saved'));p.symlink_to(p.with_suffix('.saved'))
    elif fault == 'writable': p.chmod(0o666)
    elif fault == 'missing': p.unlink()
    elif fault == 'parent_symlink':
        parent = p.parent;parent.rename(parent.with_name(parent.name+'.saved'))
        parent.symlink_to(parent.with_name(parent.name+'.saved'), target_is_directory=True)
    else: packages = lambda path: ('gpupdate', '0.99.0-alt1')
    before = tree(tmp_path)
    with pytest.raises(ValueError): run(m, tmp_path, packages, True)
    assert tree(tmp_path) == before
    assert not (tmp_path/'var').exists()


def test_busy_client_is_not_modified(tmp_path):
    m, packages = fixture(tmp_path)
    before = tree(tmp_path)
    with pytest.raises(ValueError, match='client_busy'):
        m.repair(root=tmp_path, owner=os.getuid(), package_query=packages, busy=lambda: True, apply=True)
    assert tree(tmp_path) == before


def test_failed_second_write_rolls_back_first_write(tmp_path, monkeypatch):
    m, packages = fixture(tmp_path)
    originals = {p['id']: (tmp_path/p['path'].lstrip('/')).read_bytes() for p in m.PATCHES}
    write = m.replace_module
    calls = []
    def fail_second(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2: raise OSError('synthetic write failure')
        return write(*args, **kwargs)
    monkeypatch.setattr(m, 'replace_module', fail_second)
    with pytest.raises(ValueError, match='apply_failed_rolled_back'):
        run(m, tmp_path, packages, True)
    for p in m.PATCHES: assert (tmp_path/p['path'].lstrip('/')).read_bytes() == originals[p['id']]


def test_guarded_rollback_restores_originals_and_rejects_newer_edits(tmp_path):
    m, packages = fixture(tmp_path)
    result = run(m, tmp_path, packages, True)
    p = tmp_path/m.PATCHES[-1]['path'].lstrip('/')
    expected = p.read_bytes();p.write_bytes(expected+b'\n# newer work\n')
    before = tree(tmp_path)
    with pytest.raises(ValueError): m.rollback(result['backup_id'], root=tmp_path, owner=os.getuid(), package_query=packages)
    assert tree(tmp_path) == before
    p.write_bytes(expected)
    assert m.rollback(result['backup_id'], root=tmp_path, owner=os.getuid(), package_query=packages)['changed'] is True
    for patch in m.PATCHES:
        assert (tmp_path/patch['path'].lstrip('/')).read_bytes() == (FIXTURES/(patch['id']+'.py.txt')).read_bytes()


def functions(source, names, namespace):
    nodes = [n for n in ast.parse(source).body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<vendor>', 'exec'), namespace)
    return namespace


def test_qt_detection_is_headless_and_does_not_guess_mixed_versions(tmp_path):
    m, _ = fixture(tmp_path)
    p = next(v for v in m.PATCHES if v['id']=='kde')
    source = m.patched((FIXTURES/'kde.py.txt').read_bytes(), p).decode()
    calls = []
    def output(argv, **kwargs):
        calls.append(kwargs)
        assert kwargs['env']['QT_QPA_PLATFORM']=='offscreen'
        assert kwargs['env']['LC_ALL']=='C'
        return 'KDE Frameworks Version: 6.30.0\n'
    which = lambda name, **kwargs: '/usr/bin/'+name
    ns = functions(source, {'get_kde_version'}, {'os':os,'KDE_TOOL_PATH':'/usr/lib/kf5/bin:/usr/lib/kf6/bin:/usr/bin',
        'shutil':types.SimpleNamespace(which=which),'subprocess':types.SimpleNamespace(check_output=output),'log':lambda *a:None})
    assert ns['get_kde_version']()==6 and calls
    ns['shutil'].which=lambda name,**kwargs: None if name=='kinfo' else '/usr/bin/'+name
    assert ns['get_kde_version']() is None
    ns['shutil'].which=lambda name,**kwargs: '/usr/bin/'+name if name=='kwriteconfig6' else None
    assert ns['get_kde_version']()==6


def test_service_xml_uses_the_real_model_setter(tmp_path):
    import xml.etree.ElementTree as ET
    m, _ = fixture(tmp_path)
    p=next(v for v in m.PATCHES if v['id']=='services')
    source=(FIXTURES/'services.py.txt').read_bytes()
    xml='<Services><Service name="example"><Properties serviceName="example" serviceAction="START"/></Service></Services>'
    namespace={'DynamicAttributes':object,'get_xml_root':lambda unused:ET.fromstring(xml),'parse_filters':lambda unused:[]}
    old=functions(source.decode(),{'service','read_services'},dict(namespace))
    with pytest.raises(AttributeError):old['read_services']('fixture')
    fixed=functions(m.patched(source,p).decode(),{'service','read_services'},dict(namespace))
    assert fixed['read_services']('fixture')[0].serviceaction=='START'


@pytest.mark.parametrize('key,value', [('type','URL'),('icon','folder-home'),('comment','Folder'),
    ('disabled',True),('uid','11111111-2222-3333-4444-555555555555'),
    ('remove_policy',True),('bypass_errors',True),('apply_once',True)])
def test_machine_shortcut_merge_preserves_serialized_values(tmp_path,key,value):
    m,_=fixture(tmp_path)
    patch=next(p for p in m.PATCHES if p['id']=='shortcuts')
    source=(FIXTURES/'shortcuts.py.txt').read_bytes()
    row={'dest':'%DesktopDir%/Folder','path':'file://%HOME%','arguments':'','name':'Folder','action':'U',
         'type':'URL','icon':'folder-home','comment':'Folder','disabled':True,
         'uid':'11111111-2222-3333-4444-555555555555','remove_policy':True,'bypass_errors':True,'apply_once':True}
    class Shortcut:
        def __init__(self,dest,path,args,name,action,kind):self.type=kind
        def __getattr__(self,name):
            if name.startswith('set_'):return lambda v:setattr(self,name[4:],v)
            return None
    namespace={'applier_frontend':object,'shortcut':Shortcut,'get_ttype':lambda v:v,
        'string_to_literal_eval':ast.literal_eval,'log':lambda *a:None}
    def merged(text):
        cls=functions(text,{'shortcut_applier_user'},dict(namespace))['shortcut_applier_user']
        obj=object.__new__(cls)
        obj.storage=types.SimpleNamespace(get_dictionary_from_dconf_file_db=lambda:{
            'Software/BaseALT/Policies/Preferences/Machine':{'Shortcuts':repr([row])}})
        return obj.get_machine_shortcuts()[0]
    assert getattr(merged(source.decode()),key)!=value
    assert getattr(merged(m.patched(source,patch).decode()),key)==value


def test_failure_after_atomic_replace_is_also_rolled_back(tmp_path,monkeypatch):
    m,packages=fixture(tmp_path)
    write=m.replace_module;calls=[]
    def committed_then_failed(*args,**kwargs):
        write(*args,**kwargs);calls.append(1)
        if len(calls)==1:raise OSError('synthetic fsync failure after rename')
    monkeypatch.setattr(m,'replace_module',committed_then_failed)
    with pytest.raises(ValueError,match='apply_failed_rolled_back'):run(m,tmp_path,packages,True)
    for p in m.PATCHES:assert (tmp_path/p['path'].lstrip('/')).read_bytes()==(FIXTURES/(p['id']+'.py.txt')).read_bytes()


@pytest.mark.parametrize('fault',['bad_mode','bad_metadata','backup_bytes'])
def test_rollback_preflights_every_entry_before_restore(tmp_path,fault):
    m,packages=fixture(tmp_path)
    result=run(m,tmp_path,packages,True)
    backup=tmp_path/'var/backups/alt-gpupdate-compat'/result['backup_id']
    if fault=='backup_bytes':(backup/'shortcuts.original').write_bytes(b'changed')
    elif fault=='bad_mode':(tmp_path/m.PATCHES[-1]['path'].lstrip('/')).chmod(0o600)
    else:
        p=backup/'manifest.json';v=json.loads(p.read_text());v['modules'][-1]['metadata']['gid']='invalid';p.write_text(json.dumps(v))
    before=tree(tmp_path)
    with pytest.raises(ValueError):m.rollback(result['backup_id'],root=tmp_path,owner=os.getuid(),package_query=packages)
    assert tree(tmp_path)==before


def test_standalone_and_normal_setup_share_the_protected_role():
    play = yaml.safe_load((ROOT/'deploy/alt-linux/ansible/playbooks/08-gpupdate-client-fixes.yml').read_text())[0]
    assert play['serial']==1 and play['gather_facts'] is False
    assert play['roles']==['alt_group_policy_prerequisites']
    assert 'ansible_play_hosts_all | length == 1' in str(play['pre_tasks'])
    for role in ('alt_group_policy_prerequisites','alt_group_policy_client'):
        tasks=yaml.safe_load((ROOT/'deploy/alt-linux/ansible/roles'/role/'tasks/main.yml').read_text())
        assert any(t.get('ansible.builtin.include_role',{}).get('name')=='alt_group_policy_compat' for t in tasks)
    from alt_deploy.component_catalog import PROTECTED_ROLES
    assert 'alt_group_policy_compat' in PROTECTED_ROLES
