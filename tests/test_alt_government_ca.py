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
    assert len(mutations) == 3
    assert state['Unrelated Vendor CA'] == {'pem': '', 'trust': 'C,C,C'}
    for entry in entries:
        if entry['gost']:
            assert 'ALT Government CA '+entry['filename'] not in state
            continue
        assert state['ALT Government CA '+entry['filename']]['trust'] == ('C,,' if entry['kind']=='root' else ',,')
    assert module.import_certificates(source, entries, db, run)['changed'] is False
    assert len(mutations) == 3


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
    assert len(entries) == 5
    assert sum(e['kind'] == 'root' for e in entries) == 2
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


def test_future_and_existing_users_receive_browser_certificates():
    source = (ROOT / 'roles/government_ca/tasks/main.yml').read_text()
    assert '/etc/xdg/autostart/alt-government-ca.desktop' in source
    assert 'runuser' in source
    assert 'government_ca_user_import' in source
    desktop = (ROOT / 'roles/government_ca/files/alt-government-ca.desktop').read_text()
    assert 'Exec=/usr/bin/python3 /usr/local/libexec/alt-government-ca-user-import.py' in desktop
    assert 'Terminal=false' in desktop
