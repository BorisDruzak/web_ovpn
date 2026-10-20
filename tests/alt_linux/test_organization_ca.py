"""The full trust component includes the verified organization CA, never a leaf."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import ssl
from types import SimpleNamespace

from cryptography import x509
import pytest
import yaml

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.component_probe import desired_queries
from alt_deploy.component_probe_script import certificates_ready
from test_component_catalog import SOURCE


FINGERPRINT = '5525eccf01536b7f0436d96500c663f7a58edac463f00f0fb34a59dd8b3250be'


def entry():
    entries = yaml.safe_load((SOURCE/'roles/government_ca/defaults/main.yml').read_text())['government_ca_certificates']
    matches = [e for e in entries if e['fingerprint_sha256'] == FINGERPRINT]
    assert len(matches) == 1, 'The verified organization root must be in the automatic trust bundle'
    return matches[0]


def test_organization_root_is_pinned_ca_not_cloud_leaf():
    approved = entry()
    assert approved['kind'] == 'root' and approved['gost'] is False
    payload = (SOURCE/'files/government_ca'/approved['filename']).read_bytes()
    assert b'PRIVATE KEY' not in payload
    cert = x509.load_pem_x509_certificate(payload)
    assert cert.subject == cert.issuer
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True
    assert hashlib.sha256(ssl.PEM_cert_to_DER_cert(payload.decode())).hexdigest() == FINGERPRINT
    assert hashlib.sha256(payload).hexdigest() == approved['sha256']
    assert cert.not_valid_after_utc.year == 2036
    cert.verify_directly_issued_by(cert)


def test_organization_root_is_required_by_fresh_certificate_verification():
    approved = entry()
    catalog = ComponentCatalog.load(SOURCE)
    query = desired_queries(SOURCE,catalog,[catalog.component('certificates.government')],profile_id='core-apps')[0]
    assert approved in query['certificates']
    assert query['require_cryptopro'] is True


@pytest.mark.parametrize('missing', [None, 'system', 'browser', 'trust'])
def test_readonly_probe_requires_organization_ca_in_system_and_employee_nss(tmp_path, missing):
    approved = entry()
    payload = (SOURCE/'files/government_ca'/approved['filename']).read_text()
    public = tmp_path/'usr/local/share/alt-government-ca'/approved['filename']
    public.parent.mkdir(parents=True); public.write_text(payload)
    bundle = tmp_path/'etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    bundle.parent.mkdir(parents=True); bundle.write_text('' if missing == 'system' else payload)
    home = '/home/synthetic.user'
    database = tmp_path/(home.lstrip('/')+'/.pki/nssdb/cert9.db')
    database.parent.mkdir(parents=True)
    nickname = 'ALT Government CA '+approved['filename']
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE nssPublic (a3 BLOB, a11 BLOB)')
        if missing != 'browser':
            connection.execute('INSERT INTO nssPublic VALUES (?, ?)',
                               (nickname.encode(),ssl.PEM_cert_to_DER_cert(payload)))
    def call(args):
        if args[0] == 'openssl': return 0, ''
        assert args[:4] == ['runuser','-u','synthetic.user','--']
        return 0, nickname+' '+('u,,' if missing == 'trust' else 'C,,')+'\n'
    before = database.read_bytes()
    assert certificates_ready(tmp_path,{'certificates':[approved],'installed_files':{}},home,
                              'synthetic.user',os.getuid(),call) is (missing is None)
    assert database.read_bytes() == before


def test_existing_organization_ca_nickname_collision_is_not_overwritten(tmp_path, monkeypatch):
    approved = entry()
    spec = importlib.util.spec_from_file_location('organization_ca_import',SOURCE/'roles/government_ca/files/import_user_certificates.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    monkeypatch.setattr(module,'CRYPTOPRO_CERTMGR',tmp_path/'missing-manager')
    db = tmp_path/'nssdb'; db.mkdir(); (db/'cert9.db').touch()
    monkeypatch.setattr(module,'nss_identity',lambda *_:'f'*64)
    calls = []
    with pytest.raises(ValueError,match='different certificate'):
        module.import_certificates(SOURCE/'files/government_ca',[approved],db,
                                   lambda args:calls.append(args) or SimpleNamespace(returncode=0,stdout=''))
    assert calls == []
