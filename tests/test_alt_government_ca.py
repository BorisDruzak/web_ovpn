import base64
import hashlib
import importlib.util
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1] / 'deploy/alt-linux/ansible'


def helper():
    spec = importlib.util.spec_from_file_location('government_import', ROOT / 'roles/government_ca/files/import_user_certificates.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bundle():
    return yaml.safe_load((ROOT / 'roles/government_ca/defaults/main.yml').read_text())['government_ca_certificates']


def test_user_import_preserves_unrelated_certificates_and_is_idempotent(tmp_path, monkeypatch):
    module = helper()
    db = tmp_path / 'nssdb'
    db.mkdir()
    (db / 'cert9.db').touch()
    state = {'Unrelated Vendor CA': {'pem': '', 'trust': 'C,C,C'}}
    mutations = []
    monkeypatch.setattr(module, 'nss_identity', lambda db, name:
                        module.fingerprint(state[name]['pem']) if name in state else None)

    def run(argv):
        assert argv[0] == 'certutil'
        name = argv[argv.index('-n')+1] if '-n' in argv else None
        if '-A' in argv:
            state[name] = {'pem': Path(argv[argv.index('-i')+1]).read_text(), 'trust': argv[argv.index('-t')+1]}
            mutations.append(name)
        elif '-M' in argv:
            state[name]['trust'] = argv[argv.index('-t')+1]
            mutations.append(name)
        elif name:
            return SimpleNamespace(returncode=0 if name in state else 255, stdout=state.get(name, {}).get('pem', ''))
        else:
            return SimpleNamespace(returncode=0, stdout='\n'.join(f'{name}    {entry["trust"]}' for name, entry in state.items()))
        return SimpleNamespace(returncode=0, stdout='')

    entries = bundle()
    source = ROOT / 'files/government_ca'
    assert module.import_certificates(source, entries, db, run)['changed'] is True
    assert len(mutations) == 4
    assert state['Unrelated Vendor CA'] == {'pem': '', 'trust': 'C,C,C'}
    for entry in entries:
        if entry['gost']:
            assert 'ALT Government CA '+entry['filename'] not in state
            continue
        assert state['ALT Government CA '+entry['filename']]['trust'] == ('C,,' if entry['kind']=='root' else ',,')
    assert module.import_certificates(source, entries, db, run)['changed'] is False
    assert len(mutations) == 4


def test_nss_exact_record_identity_distinguishes_old_and_new_sub_ca(tmp_path):
    module = helper()
    db = tmp_path / 'nssdb'
    db.mkdir()
    entries = [e for e in bundle() if e['kind'] == 'intermediate' and not e['gost']]
    with sqlite3.connect(db/'cert9.db') as connection:
        connection.execute('CREATE TABLE nssPublic (a3 BLOB, a11 BLOB)')
        for entry in entries:
            pem = (ROOT/'files/government_ca'/entry['filename']).read_bytes()
            der = base64.b64decode(b''.join(pem.splitlines()[1:-1]))
            connection.execute('INSERT INTO nssPublic VALUES (?, ?)',
                               (('ALT Government CA '+entry['filename']).encode(), der))
    before = (db/'cert9.db').read_bytes()
    for entry in entries:
        assert module.nss_identity(db, 'ALT Government CA '+entry['filename']) == entry['fingerprint_sha256']
    assert (db/'cert9.db').read_bytes() == before



def test_altered_bundle_is_rejected_before_store_operations(tmp_path):
    module = helper()
    entries = bundle()
    source = tmp_path / 'certificates'
    source.mkdir()
    for entry in entries:
        (source/entry['filename']).write_bytes((ROOT/'files/government_ca'/entry['filename']).read_bytes())
    (source/entries[-1]['filename']).write_text('altered')
    operations = []
    with pytest.raises(ValueError, match='payload mismatch'):
        module.import_certificates(source, entries, tmp_path/'nssdb', lambda argv: operations.append(argv))
    assert operations == []


def test_government_bundle_contains_only_pinned_public_ca_certificates():
    settings = yaml.safe_load((ROOT / 'roles/government_ca/defaults/main.yml').read_text())
    entries = settings['government_ca_certificates']
    assert len(entries) == 7
    assert sum(e['kind'] == 'root' for e in entries) == 4
    assert sum(e['kind'] == 'intermediate' for e in entries) == 3
    for entry in entries:
        payload = (ROOT / 'files/government_ca' / entry['filename']).read_bytes()
        assert payload.count(b'-----BEGIN CERTIFICATE-----') == 1
        assert b'PRIVATE KEY' not in payload
        assert hashlib.sha256(payload).hexdigest() == entry['sha256']
        der = base64.b64decode(b''.join(payload.splitlines()[1:-1]))
        assert hashlib.sha256(der).hexdigest() == entry['fingerprint_sha256']
        assert hashlib.sha1(der).hexdigest() == entry['thumbprint_sha1']


def test_root_and_intermediate_certificates_keep_distinct_trust():
    source = (ROOT / 'roles/government_ca/tasks/main.yml').read_text()
    assert '/etc/pki/ca-trust/source/anchors/{{ government_cert.filename }}' in source
    assert "government_cert.kind == 'root'" in source
    assert "'mRoot' if government_cert.kind == 'root' else 'mCA'" in source
    helper = (ROOT / 'roles/government_ca/files/import_user_certificates.py').read_text()
    assert "'C,,' if entry['kind'] == 'root' else ',,'" in helper
    assert "'uRoot' if entry['kind'] == 'root' else 'uCA'" in helper


def test_intermediate_cleanup_targets_only_verified_managed_anchor_files():
    tasks = yaml.safe_load((ROOT/'roles/government_ca/tasks/main.yml').read_text())
    cleanup = next(t for t in tasks if t.get('name') == 'Keep managed intermediate certificates outside system trust anchors')
    assert cleanup['ansible.builtin.file']['path'] == '/etc/pki/ca-trust/source/anchors/{{ government_cert.filename }}'
    assert cleanup['when'] == "government_cert.kind == 'intermediate'"
    assert cleanup['ansible.builtin.file']['state'] == 'absent'
    index = tasks.index(cleanup)
    assert any(t.get('ansible.builtin.stat', {}).get('path') == cleanup['ansible.builtin.file']['path']
               and t['ansible.builtin.stat']['follow'] is False
               and t['ansible.builtin.stat']['checksum_algorithm'] == 'sha256' for t in tasks[:index])
    guard = next(t for t in tasks[:index] if t.get('name') == 'Require exact ownership and bytes before intermediate anchor cleanup')
    guard_text = str(guard['ansible.builtin.assert'])
    assert 'checksum' in guard_text and 'sha256' in guard_text and 'uid' in guard_text and 'isreg' in guard_text
    assert '/usr/share/pki' not in str(tasks)


def test_future_and_existing_users_receive_browser_certificates():
    source = (ROOT / 'roles/government_ca/tasks/main.yml').read_text()
    assert '/etc/xdg/autostart/alt-government-ca.desktop' in source
    assert 'runuser' in source
    assert 'government_ca_user_import' in source
    desktop = (ROOT / 'roles/government_ca/files/alt-government-ca.desktop').read_text()
    assert 'Exec=/usr/bin/python3 /usr/local/libexec/alt-government-ca-user-import.py' in desktop
    assert 'Terminal=false' in desktop


def test_esia_gost_issuer_is_in_the_standard_bundle():
    entries = bundle()
    matches = [entry for entry in entries if entry['filename'] == 'guc2022_pem.crt']
    assert len(matches) == 1
    assert matches[0]['kind'] == 'root'
    assert matches[0]['gost'] is True
    assert matches[0]['fingerprint_sha256'] == '4bb37cc7c0ff4bf2aa893e95076ebb3565c69237ee1b61635beee4c1966495c7'


def test_required_cryptopro_is_checked_before_any_user_store_write(tmp_path,monkeypatch):
    module=helper();operations=[]
    monkeypatch.setattr(module,'CRYPTOPRO_CERTMGR',tmp_path/'missing-certmgr',raising=False)
    with pytest.raises(RuntimeError,match='CryptoPro certificate manager is required'):
        module.import_certificates(ROOT/'files/government_ca',bundle(),tmp_path/'nssdb',
                                   lambda argv:operations.append(argv),require_cryptopro=True)
    assert operations==[] and not (tmp_path/'nssdb').exists()


def test_user_import_does_not_accept_an_unapplied_nss_trust_change(tmp_path,monkeypatch):
    module=helper();entries=[e for e in bundle() if not e['gost']];operations=[]
    db=tmp_path/'nssdb';db.mkdir();(db/'cert9.db').touch()
    monkeypatch.setattr(module,'nss_identity',lambda db,name:next(
        e['fingerprint_sha256'] for e in entries if name.endswith(e['filename'])))
    def run(argv):
        operations.append(argv)
        return SimpleNamespace(returncode=0,stdout='\n'.join(
            'ALT Government CA '+e['filename']+' u,,' for e in entries))
    with pytest.raises(RuntimeError,match='Browser CA trust verification failed'):
        module.import_certificates(ROOT/'files/government_ca',entries,db,run)
    assert any('-M' in argv for argv in operations)


def test_certificate_subprocess_has_a_finite_deadline(monkeypatch):
    module=helper();options=[]
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**kw:options.append(kw))
    module.call(['certutil','-L'])
    assert options[0]['timeout']==30


def test_provider_disappearing_during_import_cannot_report_success(tmp_path,monkeypatch):
    module=helper();db=tmp_path/'nssdb';db.mkdir();(db/'cert9.db').touch()
    class VanishingManager:
        checks=0
        def is_file(self):
            self.checks+=1
            return self.checks==1
        def exists(self):return False
        def __str__(self):return '/fixed/certmgr'
    monkeypatch.setattr(module,'CRYPTOPRO_CERTMGR',VanishingManager())
    entries=[e for e in bundle() if e['gost']]
    with pytest.raises(RuntimeError,match='CryptoPro'):
        module.import_certificates(ROOT/'files/government_ca',entries,db,
            lambda argv:SimpleNamespace(returncode=0,stdout=argv[-1]),require_cryptopro=True)


def test_all_user_roots_are_installed_before_intermediates_and_second_run_is_noop(tmp_path,monkeypatch):
    module=helper();entries=bundle();db=tmp_path/'nssdb';db.mkdir();(db/'cert9.db').touch()
    manager=tmp_path/'certmgr';manager.touch()
    monkeypatch.setattr(module,'CRYPTOPRO_CERTMGR',manager)
    state={'vendor':True};nss={};imports=[]
    monkeypatch.setattr(module,'nss_identity',lambda db,nickname:nss.get(nickname))
    def run(argv):
        if argv[0]=='certutil':
            if '-A' in argv:
                filename=Path(argv[argv.index('-i')+1]).name
                entry=next(e for e in entries if e['filename']==filename)
                nss[argv[argv.index('-n')+1]]=entry['fingerprint_sha256']
            return SimpleNamespace(returncode=0,stdout='\n'.join('ALT Government CA '+e['filename']+' '+
                ('C,,' if e['kind']=='root' else ',,') for e in entries if not e['gost']))
        store=argv[argv.index('-store')+1]
        if '-install' in argv:
            filename=Path(argv[argv.index('-file')+1]).name
            entry=next(e for e in entries if e['filename']==filename)
            state[(store,entry['thumbprint_sha1'])]=True;imports.append((store,entry['kind'],filename))
            return SimpleNamespace(returncode=0,stdout='')
        thumbprint=argv[argv.index('-thumbprint')+1]
        return SimpleNamespace(returncode=0 if (store,thumbprint) in state else 44,stdout=thumbprint)
    assert module.import_certificates(ROOT/'files/government_ca',entries,db,run,require_cryptopro=True)['changed'] is True
    assert [kind for store,kind,name in imports]==['root']*4+['intermediate']*3
    assert all(store==('uRoot' if kind=='root' else 'uCA') for store,kind,name in imports)
    assert module.import_certificates(ROOT/'files/government_ca',entries,db,run,require_cryptopro=True)['changed'] is False
    assert len(imports)==7 and state['vendor'] is True
