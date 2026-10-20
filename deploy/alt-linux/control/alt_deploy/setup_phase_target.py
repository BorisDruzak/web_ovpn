"""Fixed target-side read-only checks; never serialize a GUI environment."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def _regular(path,owner,*,private=False,limit=16777216):
    for parent in path.parents:
        if not stat.S_ISDIR(parent.lstat().st_mode):raise ValueError
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_nlink!=1
                or info.st_mode&0o022 or private and stat.S_IMODE(info.st_mode)!=0o600):raise ValueError
        data=stream.read(limit+1)
        if len(data)>limit:raise ValueError
        return data


def _directory(path,owner):
    for parent in (path,*path.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):raise ValueError
    info=path.lstat()
    if info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError


def _alive(identity,boot,root):
    if identity.get('boot_id',boot)!=(root/'proc/sys/kernel/random/boot_id').read_text().strip():return False
    pid=identity['pid'];ticks=int(identity['start_ticks'])
    if type(pid) is not int or not 0<pid<=2147483647 or ticks<=0:raise ValueError
    try:raw=(root/'proc'/str(pid)/'stat').read_text()
    except FileNotFoundError:return False
    fields=raw.rsplit(')',1)[1].split()
    return int(fields[19])==ticks and fields[0] not in ('Z','X')


def mutators_quiet(*,root=Path('/')):
    """A live acknowledged writer blocks even after reparenting or UID change."""
    root=Path(root);owner=0 if root==Path('/') else os.getuid()
    current_boot=(root/'proc/sys/kernel/random/boot_id').read_text().strip()
    # A selected-user import may lose its Python parent while a bounded NSS
    # or CSP writer still exists. Read-only certificate queries and ordinary
    # desktop applications are not outstanding installation writers.
    for process in (root/'proc').iterdir():
        if not process.name.isdecimal():continue
        try:
            fd=os.open(process/'cmdline',os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:raw=stream.read(262145)
            if len(raw)>262144:raise ValueError
        except FileNotFoundError:continue
        argv=raw.split(b'\0')
        if not argv or not argv[0]:continue
        name=argv[0].rsplit(b'/',1)[-1]
        if (b'/usr/local/libexec/alt-government-ca-user-import.py' in argv
                or name==b'certutil' and any(v in argv for v in (b'-A',b'-M',b'-D',b'-N',b'-F'))
                or name==b'certmgr' and any(v in argv for v in (b'-install',b'-delete',b'-renew'))):return False
    for name,lock,first in (('alt-kwallet-empty-name-repair','repair.lock','manifest.json'),
                           ('alt-krfb-user-runtime','runtime.lock','manifest.json'),
                           ('alt-workstation-final-dns','lock','invocation.json')):
        namespace=root/'var/lib'/name
        if not namespace.exists() and not namespace.is_symlink():continue
        _directory(namespace,owner);paths=list(namespace.iterdir())
        if len(paths)>4096:raise ValueError
        for path in paths:
            if path.name==lock:
                _regular(path,owner,private=True,limit=0)
                continue
            if not re.fullmatch('[0-9a-f]{64}',path.name):raise ValueError
            _directory(path,owner)
            value=json.loads(_regular(path/first,owner,private=True))
            boot=value.get('boot_id')
            if not isinstance(boot,str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):raise ValueError
            if boot!=current_boot:continue
            helper=value if first=='invocation.json' else value['helper']
            if helper['pid']!=os.getpid() and _alive(helper,boot,root):return False
            writer=path/'writer.json'
            if writer.exists() or writer.is_symlink():
                record=json.loads(_regular(writer,owner,private=True))
                if record.get('boot_id')!=boot:raise ValueError
                if _alive(record['child'],boot,root):return False
    return True


def user_state(context,*,root=Path('/')):
    root=Path(root);owner=0 if root==Path('/') else os.getuid()
    helper=root/'usr/local/libexec/alt-government-ca-user-import.py'
    helper_sha=hashlib.sha256(_regular(helper,owner,limit=262144)).hexdigest()
    directory=root/'usr/local/share/alt-government-ca'
    catalog=_regular(directory/'catalog.json',owner,limit=65536)
    quiet=True
    for process in (root/'proc').iterdir():
        if not process.name.isdecimal():continue
        try:
            if process.stat().st_uid!=context.uid:continue
            argv=(process/'cmdline').read_bytes().split(b'\0')
            if b'/usr/local/libexec/alt-government-ca-user-import.py' in argv:quiet=False
        except FileNotFoundError:continue
    home=root/context.home.lstrip('/');lock=home/'.local/state/alt-government-ca/import.lock'
    if lock.exists() or lock.is_symlink():
        _directory(lock.parent,context.uid);_regular(lock,context.uid,private=True,limit=0)
        descriptor=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:quiet=False
        finally:os.close(descriptor)
    files={}
    # Public trust only: key4.db and its journal are never opened.
    for name in ('cert9.db','pkcs11.txt','cert9.db-wal'):
        path=home/'.pki/nssdb'/name
        if path.exists() or path.is_symlink():files[name]=hashlib.sha256(_regular(path,context.uid)).hexdigest()
    encoded=json.dumps({'helper':helper_sha,'catalog':hashlib.sha256(catalog).hexdigest(),'files':files},sort_keys=True).encode()
    return {'home_sha256':hashlib.sha256(context.home.encode()).hexdigest(),'certificates_quiet':quiet,
            'target_mutators_quiet':mutators_quiet(root=root),'certificates_sha256':hashlib.sha256(encoded).hexdigest(),
            'certificate_helper_sha256':helper_sha}
