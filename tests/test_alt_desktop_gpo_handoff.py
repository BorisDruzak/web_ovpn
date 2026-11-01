"""Behavioral gates for desktop ownership transferred to a machine-filtered GPO."""
import importlib.util
import json
from pathlib import Path
import os

import pytest

HELPER = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible/roles/desktop_shortcuts/files/desktop_policy_source.py'
UUID = '53b03180-5d78-11f0-bd95-f027db877a00'
GPO = 'bb7f77b5-33f1-467d-8844-4c1ba172dc9f'


def module():
    spec = importlib.util.spec_from_file_location('desktop_policy_source', HELPER)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixture():
    receipt = dict(schema=1, machine_uuid=UUID, gpo_id=GPO, gpo_name='Desktop policy')
    rows = [dict(dest=r'%DesktopDir%\office', path='/usr/bin/office', arguments='%U',
                 name='Office', icon='office', type='FILESYSTEM', action='U', disabled=False),
            dict(dest=r'%HOME%\.config\autostart\nextcloud-client', path='/usr/bin/nextcloud', arguments='',
                 name='Nextcloud', icon='Nextcloud', type='FILESYSTEM', action='U', disabled=False),
            dict(dest=r'%DesktopDir%\Домашняя папка', path='file://%HOME%', arguments='',
                 name='Домашняя папка', icon='folder-home', type='URL', action='U', disabled=False)]
    for i, row in enumerate(rows):
        row.update(uid='00000000-0000-0000-0000-'+str(i + 1).zfill(12),
                   policy_guid='{'+GPO+'}', policy_name='Desktop policy')
    return receipt, rows


def cache(rows, *, merge='1'):
    return ('[Software/BaseALT/Policies/GpoPriority/Machine/1]\n'
            'display_name = "Desktop policy"\nname = "{'+GPO+'}"\n'
            '[Software/BaseALT/Policies/GPUpdate]\nShortcutsMerge = '+merge+'\n'
            'ShortcutsApplier = 1\nShortcutsApplierUser = 1\n'
            '[Source/Software/BaseALT/Policies/GPUpdate]\n'
            + ''.join(k+' = '+json.dumps(repr({'policy_name': 'Desktop policy'}))+'\n'
                      for k in ('ShortcutsMerge', 'ShortcutsApplier', 'ShortcutsApplierUser'))
            + '[Software/BaseALT/Policies/Preferences/Machine]\nShortcuts = '+json.dumps(repr(rows))+'\n')


def test_unmigrated_computer_keeps_ansible_ownership():
    assert module().select_policy(None, '', '', [])['source'] == 'ansible'


@pytest.mark.parametrize('output', ['', 'different:x:2000:2000::/home/different:/bin/bash',
    'employee:x:0:2000::/home/employee:/bin/bash',
    'employee:x:2000:2000::/home/employee:/bin/bash\nemployee:x:2001:2001::/home/other:/bin/bash'])
def test_ambiguous_or_wrong_sss_identity_is_rejected(output):
    with pytest.raises(ValueError): module().parse_sss_account('employee', output)


def test_sss_identity_keeps_its_domain_uid_and_home():
    value = module().parse_sss_account('employee', 'employee:x:2000:2001::/home/REALM/employee:/bin/bash')
    assert value == {'name':'employee','uid':2000,'gid':2001,'home':'/home/REALM/employee'}


def test_current_machine_gpo_owns_selected_launchers_and_autostart():
    receipt, rows = fixture()
    result = module().select_policy(receipt, UUID, cache(rows), ['office.desktop'])
    assert result['source'] == 'gpo'
    assert len(result['shortcuts']) == 3


@pytest.mark.parametrize('fault', ['wrong_machine', 'missing_gpo', 'missing_item', 'foreign_source',
                                  'duplicate_path', 'disabled', 'no_merge', 'invalid_receipt'])
def test_invalid_migration_never_falls_back_or_verifies(fault):
    receipt, rows = fixture()
    machine = UUID
    if fault == 'wrong_machine': machine = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    elif fault == 'missing_gpo': receipt['gpo_id'] = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    elif fault == 'missing_item': rows.pop(0)
    elif fault == 'foreign_source': rows[0]['policy_guid'] = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    elif fault == 'duplicate_path': rows.append(dict(rows[0]))
    elif fault == 'disabled': rows[0]['disabled'] = True
    elif fault == 'invalid_receipt': receipt = []
    with pytest.raises(ValueError):
        module().select_policy(receipt, machine, cache(rows, merge='0' if fault == 'no_merge' else '1'), ['office.desktop'])


def write_profile(root, rows, *, skel=False):
    desktop = root/'Рабочий стол'
    desktop.mkdir(parents=True)
    for row in rows:
        if 'autostart' in row['dest']:
            path = root/'.config/autostart/nextcloud-client.desktop'
        else:
            path = desktop/(row['dest'].split('\\')[-1]+'.desktop')
        path.parent.mkdir(parents=True, exist_ok=True)
        content = '[Desktop Entry]\nType='+('Link' if row['type']=='URL' else 'Application')+'\n'
        content += 'Name='+row['name']+'\nIcon='+row['icon']+'\n'
        if row['type']=='URL': content += 'URL=file://'+('%HOME%' if skel else str(root)+'/')+'\n'
        else: content += 'Exec='+row['path']+' '+row['arguments']+'\n'
        path.write_text(content, encoding='utf-8')
        path.chmod(0o755)
    return desktop


@pytest.mark.skipif(os.name != 'posix', reason='POSIX profile metadata required')
def test_verifier_accepts_gpo_edits_without_requiring_distro_file_bytes(tmp_path):
    m = module()
    receipt, rows = fixture()
    rows[0]['name'] = 'Office from GPO'
    rows[0]['arguments'] = '--new-window %U'
    policy = m.select_policy(receipt, UUID, cache(rows), ['office.desktop'])
    write_profile(tmp_path, rows)
    assert m.verify_profile(policy, tmp_path, os.getuid(), 'Рабочий стол') == []


@pytest.mark.skipif(os.name != 'posix', reason='POSIX profile metadata required')
@pytest.mark.parametrize('fault', ['missing', 'wrong_exec', 'symlink', 'unsafe_mode', 'wrong_icon'])
def test_verifier_detects_missing_or_modified_policy_outputs(tmp_path, fault):
    m = module()
    receipt, rows = fixture()
    policy = m.select_policy(receipt, UUID, cache(rows), ['office.desktop'])
    desktop = write_profile(tmp_path, rows)
    p = desktop/'office.desktop'
    if fault == 'missing': p.unlink()
    elif fault == 'symlink':
        p.rename(desktop/'preserved.desktop')
        p.symlink_to('preserved.desktop')
    elif fault == 'unsafe_mode': p.chmod(0o777)
    else: p.write_text(p.read_text().replace('Exec=/usr/bin/office', 'Exec=/bin/false') if fault == 'wrong_exec'
                       else p.read_text().replace('Icon=office', 'Icon=wrong'))
    with pytest.raises(ValueError): m.verify_profile(policy, tmp_path, os.getuid(), 'Рабочий стол')


@pytest.mark.skipif(os.name != 'posix', reason='POSIX profile metadata required')
def test_only_exact_legacy_home_symlink_is_eligible_for_cleanup(tmp_path):
    m = module()
    receipt, rows = fixture()
    policy = m.select_policy(receipt, UUID, cache(rows), ['office.desktop'])
    desktop = write_profile(tmp_path, rows)
    old = desktop/'Домашняя папка'
    old.symlink_to('..')
    assert m.verify_profile(policy, tmp_path, os.getuid(), 'Рабочий стол') == [str(old)]
    old.unlink();old.symlink_to('/tmp')
    with pytest.raises(ValueError): m.verify_profile(policy, tmp_path, os.getuid(), 'Рабочий стол')


@pytest.mark.skipif(os.name != 'posix', reason='POSIX profile metadata required')
@pytest.mark.parametrize('setting', ['OnlyShowIn=GNOME;', 'NotShowIn=KDE;',
    'TryExec=/not/a/real/program', 'X-GNOME-Autostart-enabled=false',
    'X-systemd-skip=true', 'AutostartCondition=GSettings missing setting'])
def test_suppressed_nextcloud_autostart_is_not_verified(tmp_path, setting):
    m = module()
    receipt, rows = fixture()
    policy = m.select_policy(receipt, UUID, cache(rows), ['office.desktop'])
    write_profile(tmp_path, rows)
    autostart = tmp_path/'.config/autostart/nextcloud-client.desktop'
    autostart.write_text(autostart.read_text()+setting+'\n')
    with pytest.raises(ValueError): m.verify_profile(policy, tmp_path, os.getuid(), 'Рабочий стол')


@pytest.mark.skipif(os.name != 'posix', reason='POSIX profile metadata required')
@pytest.mark.parametrize('fault', ['writable', 'file', 'symlink'])
def test_missing_profile_parent_defers_but_unsafe_existing_parent_does_not(tmp_path, fault):
    m = module()
    home = tmp_path/'REALM/new-user'
    assert m.profile_deferred(home, owner=os.getuid(), root=tmp_path) is True
    if fault == 'file': home.parent.write_text('not a directory')
    elif fault == 'symlink': home.parent.symlink_to(tmp_path)
    else:
        home.parent.mkdir()
        home.parent.chmod(0o777)
    with pytest.raises(ValueError): m.profile_deferred(home, owner=os.getuid(), root=tmp_path)
