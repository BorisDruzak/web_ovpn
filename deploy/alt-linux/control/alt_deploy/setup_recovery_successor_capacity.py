"""Root-only fixed read-only controller capacity and archival audit observation."""
from __future__ import annotations
import hashlib,json,os,stat,sys,shutil
import fcntl
from contextlib import contextmanager
from datetime import datetime,timezone
from pathlib import Path

def _encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()

@contextmanager
def readonly_operation_lock(path,*,owner=0,group=0):
    for parent in path.parents:
        if not stat.S_ISDIR(parent.lstat().st_mode):raise ValueError('Unsafe lock ancestry')
    parent=path.parent.lstat();before=path.lstat()
    if (parent.st_uid!=owner or parent.st_gid!=group or parent.st_mode&0o002
            or not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_gid!=group
            or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1):raise ValueError('Unsafe native operation lock')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):raise ValueError
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if (path.lstat().st_dev,path.lstat().st_ino)!=(opened.st_dev,opened.st_ino):raise ValueError
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def audit_preflight_failed(path,approved_at,finished_at,*,owner=0):
    start=datetime.fromisoformat(approved_at);finish=datetime.fromisoformat(finished_at)
    if start.tzinfo is None or finish.tzinfo is None or not start<=finish<=datetime.now(timezone.utc):raise ValueError('Invalid predecessor interval')
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>134217728):raise ValueError('Unsafe backup audit')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    events=[];selected=[]
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):raise ValueError
        remaining=info.st_size;count=0
        while remaining:
            offset=stream.tell();line=stream.readline(min(8193,remaining));remaining-=len(line);count+=1
            if not line or len(line)>8192 or not line.endswith(b'\n') or count>524288:raise ValueError('Unbounded or incomplete audit record')
            row=json.loads(line);when=datetime.fromisoformat(row['timestamp'])
            if when.tzinfo is None:raise ValueError
            if row['command']=='create' and start<=when<=finish:
                events.append(row);selected.append((offset,line))
                if len(events)>2:raise ValueError('Ambiguous backup operation')
        after=path.lstat()
        if ((info.st_ino,info.st_dev)!=(after.st_ino,after.st_dev) or after.st_size<info.st_size
                or after.st_uid!=owner or after.st_nlink!=1 or after.st_mode&0o022):raise ValueError
        # Native guard checks may append newer rows while we read. The bounded
        # historical prefix and both selected records must remain unchanged.
        for offset,line in selected:
            stream.seek(offset)
            if stream.read(len(line))!=line:raise ValueError('Historical audit proof changed')
    if (len(events)!=2 or events[0]['event']!='command_started' or events[0]['status']!='started'
            or events[1]['event']!='command_failed' or events[1]['status']!='error'
            or events[1].get('error_code')!='backup_preflight_failed'
            or events[0]['operation_id']!=events[1]['operation_id'] or any(row.get('backup_id') is not None for row in events)):raise ValueError('Incomplete native failure proof')
    return dict(preflight_failed=True,operation_sha256=hashlib.sha256(_encoded(events)).hexdigest())

def inspect_capacity(request):
    if os.geteuid()!=0 or not isinstance(request,dict) or set(request)!={'approved_at','finished_at'}:raise ValueError
    sys.path.insert(0,'/opt/alt-deploy-backup');sys.path.insert(0,'/opt/alt-deploy-control')
    from alt_deploy_backup.settings import BackupSettings
    from alt_deploy_backup.repository import BackupRepository
    from alt_deploy_backup.components import component_specs
    from alt_deploy_backup.fs import source_inventory
    from alt_deploy_backup.guard import GuardState
    from alt_deploy.setup_recovery_successor_probe import no_active_recovery
    settings=BackupSettings.from_env();repo=BackupRepository(settings)
    with readonly_operation_lock(settings.operation_lock,owner=settings.expected_root_uid,group=settings.expected_root_gid):
        repo._validate_roots();repo._validate_commands()
        paths=repo._source_paths(component_specs(settings));repo._check_disk_space(paths)
        repo.quiescence.assert_quiescent();GuardState(settings).assert_control_plane_allowed()
        no_active_recovery()
        size=sum(entry.size for entry in source_inventory(paths) if entry.kind=='regular')
        capacity=dict(required_free_bytes=max(64*1024*1024,size*2),actual_free_bytes=shutil.disk_usage(settings.backup_root).free)
        if capacity['actual_free_bytes']<capacity['required_free_bytes']:raise ValueError('Capacity changed')
        audit=audit_preflight_failed(settings.log_file,request['approved_at'],request['finished_at'])
        return dict(schema_version=1,native_guard=True,no_active_recovery=True,capacity=capacity,backup_audit=audit)

if __name__=='__main__':
    try:
        wire=json.loads(sys.stdin.read(131073));result=inspect_capacity(wire['request'])
        print(json.dumps(result,sort_keys=True))
    except Exception:
        print(json.dumps(dict(schema_version=1,error_code='recovery_successor_capacity_refused')));sys.exit(1)
