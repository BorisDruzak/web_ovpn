"""Fixed read-only identity, process and never-entered workstation proof."""
from __future__ import annotations
import hashlib,json,os,re,stat,uuid
from pathlib import Path

PREFIXES=('backup-','rehearsal-','services-','import-','kerberos-','sssd-policy-','sssd-start-','native-testjoin-','user-check-','terminal-')

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()

def no_active_recovery(*,root=Path('/')):
    for index,process in enumerate((root/'proc').iterdir()):
        if index>=16384:raise ValueError('Unbounded process inventory')
        if not process.name.isdigit() or int(process.name)==os.getpid():continue
        try:
            with (process/'cmdline').open('rb') as stream:raw=stream.read(32769)
        except FileNotFoundError:continue
        if len(raw)>32768:raise ValueError('Unknown process arguments')
        args=raw.decode('utf-8',errors='replace').split('\0')
        if (any(arg.startswith('/usr/bin/python') for arg in args[:1]) and any('fixed_recovery_worker' in arg for arg in args[1:])):raise ValueError('Active recovery worker')
        if '/usr/local/sbin/workstationctl' in args and any(args[i:i+2]==['recovery','apply'] for i in range(len(args)-1)):raise ValueError('Active recovery apply')
        if '/usr/local/sbin/alt-deploy-backup' in args:
            index=args.index('/usr/local/sbin/alt-deploy-backup')
            if index+1>=len(args) or args[index+1] not in ('guard','list','verify','rehearse-status'):raise ValueError('Active native backup operation')
    return True

def _parents(path,root,owner):
    current=path
    while True:
        info=current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:raise ValueError('Unsafe evidence ancestry')
        if current==root:return
        if current.parent==current:raise ValueError('Path escaped root')
        current=current.parent

def _identity_file(path,owner):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:raise ValueError('Unsafe kernel identity')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:raw=stream.read(257)
    if len(raw)>256:raise ValueError('Oversized kernel identity')
    return raw.decode('ascii').strip().lower()

def inspect(request,*,root=Path('/'),owner=0):
    if (not isinstance(request,dict) or set(request)!={'schema_version','pair','machine_uuid','hostname'}
            or type(request['schema_version']) is not int or request['schema_version']!=1):raise ValueError('Invalid fixed request')
    pair=request['pair']
    if (not isinstance(pair,dict) or set(pair)!={'failed_run_id','computer_guid'}
            or not isinstance(pair['failed_run_id'],str) or not re.fullmatch('setup-run-[0-9a-f]{32}',pair['failed_run_id'])):raise ValueError
    for value in (pair['computer_guid'],request['machine_uuid']):
        if str(uuid.UUID(value))!=value or uuid.UUID(value).int==0:raise ValueError
    if not isinstance(request['hostname'],str) or not re.fullmatch(r'(?:lin|alt|win|deb)-[a-z][0-9]?-(?:pc[1-9][0-9]*)',request['hostname']):raise ValueError
    if (_identity_file(root/'sys/class/dmi/id/product_uuid',owner)!=request['machine_uuid']
            or _identity_file(root/'proc/sys/kernel/hostname',owner) not in (request['hostname'],request['hostname']+'.sosnadmin.local')):raise ValueError('Wrong machine')
    parent=root/'var/lib/alt-deploy-recovery';_parents(parent.parent,root,owner)
    if parent.exists() or parent.is_symlink():
        _parents(parent,root,owner)
        token=hashlib.sha256(encoded(pair)).hexdigest()
        for prefix in PREFIXES:
            target=parent/(prefix+token)
            try:target.lstat()
            except FileNotFoundError:continue
            raise ValueError('Workstation attempt already entered')
    no_active_recovery(root=root)
    return dict(request,footprints_absent=True,no_active_recovery=True)

if __name__=='__main__':
    import sys
    try:
        wire=json.loads(sys.stdin.read(131073));result=inspect(wire['request'])
        print(json.dumps(result,sort_keys=True))
    except Exception:
        print(json.dumps(dict(schema_version=1,error_code='recovery_successor_inspection_refused')));sys.exit(1)
