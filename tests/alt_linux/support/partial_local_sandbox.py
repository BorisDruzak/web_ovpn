"""Test-only inventory oracle; this never authorizes production recovery."""
import hashlib
from pathlib import Path
import stat

from alt_deploy.setup_plans import digest


def inventory(root):
    records = {}
    for path in root.rglob('*'):
        name = '/'+path.relative_to(root).as_posix()
        if name == '/var' or name == '/var/lib' or name.startswith('/var/lib/alt-deploy-partial-local'):
            continue
        info = path.lstat()
        value = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        if stat.S_ISLNK(info.st_mode): value.update(kind='link', target=path.readlink().as_posix())
        elif stat.S_ISREG(info.st_mode): value.update(kind='file', sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISDIR(info.st_mode): value.update(kind='directory')
        else: raise ValueError('Unsupported sandbox object')
        records[name] = value
    return records


def rehearse(snapshot, native_tools):
    root = Path(snapshot['root']).resolve()
    if root == Path('/') or root.is_symlink() or not root.is_dir(): raise ValueError('Synthetic root required')
    protocol = native_tools['target']
    authenticate = native_tools['authenticate']
    expected_auth = {'local_admin': True, 'ansible': True}
    if authenticate() != expected_auth: raise ValueError('Fresh authentication failed')
    before = inventory(root)
    result = protocol.execute(snapshot['request'], root=root, owner=snapshot['owner'])
    after = inventory(root)
    allowed = {'/etc/nsswitch.conf', '/etc/pam.d/system-auth',
               '/etc/pam.d/system-auth-use_first_pass', '/etc/pam.d/system-policy'}
    changes = {name for name in set(before) | set(after) if before.get(name) != after.get(name)}
    if changes != allowed: raise ValueError('Unexpected sandbox effect')
    for name in allowed - {'/etc/nsswitch.conf'}:
        if after[name] != dict(before[name], target=Path(name).name+'-local'):
            raise ValueError('Unexpected PAM transition')
    if result['status'] != 'successful': raise ValueError('Native rehearsal not successful')
    backup = root/'var/lib/alt-deploy-partial-local'/snapshot['request']['claim_key']
    backup_before = digest({str(p.relative_to(backup)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in backup.rglob('*') if p.is_file()})
    if protocol.inspect(snapshot['request'], root=root, owner=snapshot['owner']) != result:
        raise ValueError('Forensic backup not verified')
    backup_after = digest({str(p.relative_to(backup)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in backup.rglob('*') if p.is_file()})
    if backup_before != backup_after: raise ValueError('Forensic backup changed')
    if authenticate() != expected_auth: raise ValueError('Fresh authentication failed')
    return {'status': 'passed', 'accounts_unchanged': True, 'backup_verified': True,
            'fresh_authentication': expected_auth, 'backup_sha256': result['backup_sha256'],
            'before_sha256': digest(before), 'after_sha256': digest(after)}
