"""Import only the approved public CA bundle into a graphical user's stores."""
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sqlite3
import subprocess
import sys


CRYPTOPRO_CERTMGR = Path('/opt/cprocsp/bin/amd64/certmgr')


def call(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def nss_identity(db, nickname):
    # certutil's nickname lookup may return the newest CA with the same subject.
    # Read CKA_LABEL (a3) / CKA_VALUE (a11) from cert9.db to verify the exact record.
    # Never open key4.db or modify NSS directly; all writes go through certutil.
    with sqlite3.connect((db / 'cert9.db').as_uri() + '?mode=ro', uri=True) as connection:
        records = connection.execute('SELECT a11 FROM nssPublic WHERE a3 = ? AND a11 IS NOT NULL',
                                     (nickname.encode(),)).fetchall()
    if not records:
        return None
    if len(records) != 1:
        raise ValueError('Ambiguous managed browser CA nickname')
    return hashlib.sha256(records[0][0]).hexdigest()


def import_certificates(directory, entries, db, run=call, *, require_cryptopro=False):
    # Validate the whole bundle before touching any certificate store.
    for entry in entries:
        path = directory / entry['filename']
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('Government certificate payload mismatch')
        if fingerprint(path.read_text()) != entry['fingerprint_sha256']:
            raise ValueError('Government certificate identity mismatch')
    manager = CRYPTOPRO_CERTMGR
    manager_present = manager.is_file()
    if require_cryptopro and not manager_present:
        raise RuntimeError('CryptoPro certificate manager is required')
    entries = [entry for entry in entries if entry['kind']=='root'] + [
        entry for entry in entries if entry['kind']!='root']
    changed = False
    if not (db / 'cert9.db').exists():
        db.mkdir(mode=0o700, parents=True, exist_ok=True)
        result = run(['certutil', '-N', '-d', 'sql:' + str(db), '--empty-password'])
        if result.returncode:
            raise RuntimeError('Cannot initialize browser certificate database')
        changed = True
    for entry in entries:
        # NSS cannot import the GOST public-key algorithm. Yandex GOST TLS uses CSP.
        if entry['gost']:
            continue
        nickname = 'ALT Government CA ' + entry['filename']
        trust = 'C,,' if entry['kind'] == 'root' else ',,'
        args = ['certutil', '-d', 'sql:' + str(db)]
        existing = nss_identity(db, nickname)
        if existing is None:
            result = run(args + ['-A', '-n', nickname, '-t', trust, '-i', str(directory / entry['filename'])])
            if result.returncode:
                raise RuntimeError('Cannot import approved browser CA certificate')
            changed = True
        elif existing != entry['fingerprint_sha256']:
            raise ValueError('Managed browser CA nickname has a different certificate')
        listing = run(args + ['-L'])
        if listing.returncode:
            raise RuntimeError('Cannot read browser certificate trust')
        match = re.search(r'^' + re.escape(nickname) + r'\s+(\S+)\s*$', listing.stdout, re.MULTILINE)
        if not match:
            raise RuntimeError('Imported browser CA certificate is missing')
        if match.group(1) != trust:
            result = run(args + ['-M', '-n', nickname, '-t', trust])
            if result.returncode:
                raise RuntimeError('Cannot set approved browser CA trust')
            changed = True
            verified = run(args + ['-L'])
            match = re.search(r'^' + re.escape(nickname) + r'\s+(\S+)\s*$', verified.stdout, re.MULTILINE)
            if verified.returncode or not match or match.group(1) != trust:
                raise RuntimeError('Browser CA trust verification failed')
        if nss_identity(db, nickname) != entry['fingerprint_sha256']:
            raise RuntimeError('Browser CA certificate verification failed')
    if manager_present:
        for entry in entries:
            store = 'uRoot' if entry['kind'] == 'root' else 'uCA'
            args = [str(manager), '-list', '-store', store, '-thumbprint', entry['thumbprint_sha1']]
            existing = run(args)
            if existing.returncode == 44:
                result = run([str(manager), '-install', '-store', store, '-file', str(directory / entry['filename'])])
                if result.returncode:
                    raise RuntimeError('Cannot import government CA into CryptoPro user store')
                changed = True
                existing = run(args)
            compact = re.sub('[^0-9a-f]', '', existing.stdout.lower())
            if existing.returncode or entry['thumbprint_sha1'] not in compact:
                raise RuntimeError('CryptoPro user CA verification failed')
        if not manager.is_file():
            raise RuntimeError('CryptoPro certificate manager disappeared during verification')
    return {'changed': changed, 'nss_certificates_verified': sum(not e['gost'] for e in entries),
            'cryptopro_certificates_verified': len(entries) if manager_present else 0,
            'gost_browser_ready': manager_present}


def main():
    import pwd
    if sys.argv[1:] not in ([], ['--require-cryptopro']):
        raise ValueError('Unsupported certificate import arguments')
    if os.getuid() == 0:
        raise ValueError('Run certificate import as the graphical user')
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    db = home / '.pki' / 'nssdb'
    for path in (home, home / '.pki', db, db / 'cert9.db', db / 'key4.db'):
        if path.is_symlink():
            raise ValueError('Symlinked browser certificate database is unsafe')
        if path.exists() and path.stat().st_uid != os.getuid():
            raise ValueError('Browser certificate database ownership mismatch')
    directory = Path('/usr/local/share/alt-government-ca')
    entries = json.loads((directory / 'catalog.json').read_text())
    print(json.dumps(import_certificates(directory, entries, db,
                                       require_cryptopro=sys.argv[1:]==['--require-cryptopro'])))


if __name__ == '__main__':
    main()
