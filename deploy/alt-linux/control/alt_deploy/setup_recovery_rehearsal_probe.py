"""Fixed bounded read-only proof for the exact closed locale rehearsal failure."""
from __future__ import annotations
import hashlib,json,os,re,stat,tarfile
from pathlib import PurePosixPath
from datetime import datetime,timezone

def _encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()

def audit_rehearsal_failed(path,approved_at,finished_at,*,owner=0):
    start=datetime.fromisoformat(approved_at);finish=datetime.fromisoformat(finished_at)
    if start.tzinfo is None or finish.tzinfo is None or not start<=finish<=datetime.now(timezone.utc):raise ValueError
    before=path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_nlink!=1
            or before.st_mode&0o022 or before.st_size>134217728):raise ValueError
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);events=[];selected=[]
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):raise ValueError
        remaining=before.st_size;count=0
        while remaining:
            offset=stream.tell();line=stream.readline(min(8193,remaining));remaining-=len(line);count+=1
            if not line or len(line)>8192 or not line.endswith(b'\n') or count>524288:raise ValueError
            row=json.loads(line);when=datetime.fromisoformat(row['timestamp'])
            if when.tzinfo is None:raise ValueError
            if row['command'] in ('create','verify','rehearse','restore','recover','delete') and start<=when<=finish:
                events.append(row);selected.append((offset,line))
                if len(events)>6:raise ValueError('Ambiguous native history')
        after=path.lstat()
        if ((after.st_dev,after.st_ino)!=(before.st_dev,before.st_ino) or after.st_size<before.st_size
                or after.st_uid!=owner or after.st_nlink!=1 or after.st_mode&0o022):raise ValueError
        for offset,line in selected:
            stream.seek(offset)
            if stream.read(len(line))!=line:raise ValueError('Historical audit changed')
    if len(events)!=6:raise ValueError('Incomplete closed native history')
    bid=events[2].get('backup_id')
    if not isinstance(bid,str) or not re.fullmatch('backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',bid):raise ValueError
    operations=set();previous=start
    for i,command in enumerate(('create','verify','rehearse')):
        begin,end=events[2*i:2*i+2]
        operation=begin.get('operation_id')
        if (not isinstance(operation,str) or not 1<=len(operation)<=128 or operation in operations
                or end.get('operation_id')!=operation or begin['command']!=command or end['command']!=command
                or begin['event']!='command_started' or begin['status']!='started'
                or begin.get('backup_id')!=(None if command=='create' else bid)
                or end.get('backup_id')!=(None if command=='create' else bid)):raise ValueError
        operations.add(operation)
        for row in (begin,end):
            when=datetime.fromisoformat(row['timestamp'])
            if when<previous:raise ValueError
            previous=when
        if command=='rehearse':
            if end['event']!='command_failed' or end['status']!='error' or end.get('error_code')!='backup_rehearsal_failed':raise ValueError
        elif (end['event']!='command_completed' or end['status']!='ok'
                or end.get('result')!=('backup_created' if command=='create' else 'backup_verified')):raise ValueError
    return dict(backup_id=bid,rehearsal_failed=True,operation_sha256=hashlib.sha256(_encoded(events)).hexdigest())

def _safe_parents(path,root):
    current=path.parent
    while True:
        if not stat.S_ISDIR(current.lstat().st_mode):raise ValueError('Unsafe retained ancestry')
        if current==root:return
        if current.parent==current:raise ValueError
        current=current.parent

def retained_tree_projection(repo,verified,selected):
    from alt_deploy_backup.components import component_specs
    expected=set();parents=set();records=[];total=0
    engine=repo.archive_engine
    for spec,component in zip(component_specs(repo.settings),verified.manifest.components,strict=True):
        _,process=engine._open_decompressor(verified.path/component.filename)
        try:
            with tarfile.open(fileobj=process.stdout,mode='r|') as archive:
                for raw in archive:
                    member=engine._validated_member(spec,raw)
                    if member.name in expected or len(expected)>=200000:raise ValueError
                    expected.add(member.name)
                    parents.update(str(p) for p in PurePosixPath(member.name).parents if str(p)!='.')
                    path=selected.joinpath(*PurePosixPath(member.name).parts);_safe_parents(path,selected)
                    info=path.lstat();kind='directory' if stat.S_ISDIR(info.st_mode) else 'regular' if stat.S_ISREG(info.st_mode) else 'symlink' if stat.S_ISLNK(info.st_mode) else 'special'
                    if (kind!=('regular' if member.kind=='hardlink' else member.kind)
                            or info.st_uid!=member.uid or info.st_gid!=member.gid
                            or stat.S_IMODE(info.st_mode)!=member.mode&0o1777):raise ValueError('Retained metadata changed')
                    content=None
                    if member.kind=='regular':
                        total+=member.size
                        if member.size>8589934592 or total>34359738368 or info.st_size!=member.size:raise ValueError
                        stream=archive.extractfile(raw);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                        with os.fdopen(fd,'rb') as restored:
                            opened=os.fstat(restored.fileno())
                            if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):raise ValueError
                            left=hashlib.sha256();right=hashlib.sha256();remaining=member.size
                            while remaining:
                                chunk=stream.read(min(1048576,remaining));other=restored.read(len(chunk))
                                if not chunk or chunk!=other:raise ValueError('Retained bytes changed')
                                left.update(chunk);right.update(other);remaining-=len(chunk)
                            content=left.hexdigest()
                    elif member.kind=='symlink':
                        content=os.readlink(path)
                        if content!=member.link_name:raise ValueError
                    elif member.kind=='hardlink':
                        target=selected/engine._resolve_link_target(member.name,member.link_name,spec.namespace)
                        _safe_parents(target,selected);linked=target.lstat()
                        if not stat.S_ISREG(linked.st_mode) or (linked.st_dev,linked.st_ino)!=(info.st_dev,info.st_ino):raise ValueError
                        content=member.link_name
                    after=path.lstat()
                    if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)!=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns):raise ValueError
                    records.append((member.name,kind,stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid,content))
        except BaseException:
            engine._finish_decompressor(process);raise
        if engine._finish_decompressor(process)!=0:raise ValueError
    allowed=expected|parents;actual=set();pending=[selected]
    while pending:
        directory=pending.pop()
        for path in directory.iterdir():
            name=path.relative_to(selected).as_posix()
            if len(actual)>=200000 or name not in allowed:raise ValueError('Unknown retained entry')
            actual.add(name)
            metadata=path.lstat()
            if name not in expected:
                if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=repo.settings.expected_root_uid
                        or metadata.st_gid!=repo.settings.expected_root_gid or stat.S_IMODE(metadata.st_mode)!=0o700):raise ValueError('Unsafe implicit retained parent')
                records.append((name,'directory',stat.S_IMODE(metadata.st_mode),metadata.st_uid,metadata.st_gid,None))
            if stat.S_ISDIR(metadata.st_mode):pending.append(path)
    if actual!=allowed:raise ValueError('Missing retained entry')
    return hashlib.sha256(_encoded(sorted(records))).hexdigest()

def _tool_paths(settings):
    paths={'cli':settings.ansible_playbook_path,'systemd-analyze':settings.systemd_analyze_path,
        'zstd':settings.zstd_path}
    if not settings.test_mode:
        import importlib.util,sys
        from pathlib import Path
        paths.update({'bash':Path('/bin/bash').resolve(strict=True),'python':Path(sys.executable).resolve(strict=True)})
        for name in ('ansible','alt_deploy_backup'):
            spec=importlib.util.find_spec(name)
            if spec is None or spec.origin is None:raise ValueError
            package=Path(spec.origin).parent
            for path in sorted(package.rglob('*.py')):
                if len(paths)>=4096:raise ValueError
                paths[name+'/'+path.relative_to(package).as_posix()]=path
    return paths

def _protected_tool_hash(settings,path):
    from alt_deploy_backup.fs import read_regular_bytes
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=settings.expected_root_uid
            or info.st_gid!=settings.expected_root_gid or info.st_nlink!=1 or info.st_mode&0o022):raise ValueError
    return hashlib.sha256(read_regular_bytes(path,max_bytes=16777216)).hexdigest()

def retained_metadata(repo,bid):
    if not isinstance(bid,str) or not re.fullmatch('backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',bid):raise ValueError
    records=[];settings=repo.settings
    def record(label,path):
        info=path.lstat()
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):raise ValueError
        records.append((label,info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns))
        return info
    for label,root in (('backup',settings.backup_root/bid),('tree',settings.rehearsal_root/bid)):
        info=record(label,root)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=settings.expected_root_uid
                or info.st_gid!=settings.expected_root_gid or stat.S_IMODE(info.st_mode)!=0o700):raise ValueError
        pending=[root]
        while pending:
            directory=pending.pop()
            for path in directory.iterdir():
                if len(records)>=200000:raise ValueError
                info=record(label+'/'+path.relative_to(root).as_posix(),path)
                if stat.S_ISDIR(info.st_mode):pending.append(path)
    for name,path in _tool_paths(settings).items():
        record('tool/'+name,path)
        records.append(('tool-source/'+name,_protected_tool_hash(settings,path)))
    return hashlib.sha256(_encoded(sorted(records))).hexdigest()

def locale_proof(settings,selected):
    from alt_deploy.setup_recovery_process import bounded_recovery_run
    root=selected/'ansible/home/altserver/ansible';playbooks=sorted((root/'playbooks').glob('*.yml'))
    if not 1<=len(playbooks)<=64:raise ValueError
    tools=_tool_paths(settings);hashes={name:_protected_tool_hash(settings,path) for name,path in tools.items()}
    def run(arguments,locale):
        import sys
        # Native rehearsal resolves roles relative to this retained Ansible root.
        # Fixed internal exec wrapper preserves the bounded runner's pipe contract.
        command=[sys.executable,'-I','-B','-c',
            'import os,sys; os.chdir(sys.argv[1]); os.execv(sys.argv[2],sys.argv[2:])',str(root),*arguments]
        return bounded_recovery_run(command,
            environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':locale,'ANSIBLE_CONFIG':str(root/'ansible.cfg')},
            input_text='',timeout=120)
    def command(playbook):
        _safe_parents(playbook,selected)
        if not stat.S_ISREG(playbook.lstat().st_mode):raise ValueError
        return [str(settings.ansible_playbook_path),'--syntax-check','--inventory','localhost,',
            '--vault-password-file',str(settings.vault_password_file),'--extra-vars','@'+str(settings.vault_file),str(playbook)]
    rc,out,error=run(command(playbooks[0]),'C')
    if rc!=1 or 'locale encoding to be UTF-8' not in out+error:raise ValueError('Different historical failure')
    for playbook in playbooks:
        rc,_,_=run(command(playbook),'C.UTF-8')
        if rc:raise ValueError('Corrected syntax refused')
    rc,out,_=run([str(settings.ansible_playbook_path),'--version'],'C.UTF-8')
    version=out.splitlines()[0] if out.splitlines() else ''
    if rc or not re.fullmatch(r'ansible-playbook \[core [0-9]+\.[0-9]+\.[0-9]+\]',version):raise ValueError
    hashes['version']=hashlib.sha256(version.encode('ascii')).hexdigest()
    if any(hashes[name]!=_protected_tool_hash(settings,path) for name,path in tools.items()):raise ValueError
    return dict(old_locale_refused=True,corrected_locale_passed=True,tool_sources_sha256=hashlib.sha256(_encoded(hashes)).hexdigest())

def retained_rehearsal_proof(repo,bid):
    from alt_deploy_backup.bundle_management import BundleManager
    from alt_deploy_backup.fs import read_regular_bytes
    from alt_deploy_backup.rehearsal import RehearsalService
    if not isinstance(bid,str) or not re.fullmatch('backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',bid):raise ValueError
    selected=repo.settings.rehearsal_root/bid;info=selected.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=repo.settings.expected_root_uid
            or info.st_gid!=repo.settings.expected_root_gid or stat.S_IMODE(info.st_mode)!=0o700):raise ValueError
    _safe_parents(selected,repo.settings.rehearsal_root)
    manager=BundleManager(repo);verified=manager._verify_bundle(bid)
    if manager._evidence_state(verified)!=(True,False) or (verified.path/'rehearsal.json').exists() or (verified.path/'rehearsal.json').is_symlink():raise ValueError
    verification=read_regular_bytes(verified.path/'verification.json',max_bytes=4194304)
    metadata=retained_metadata(repo,bid)
    tree=retained_tree_projection(repo,verified,selected)
    service=RehearsalService(repo)
    service._validate_manifest_paths(selected,verified.manifest);service._compile_python(selected)
    service._validate_shell(selected);service._validate_systemd(selected)
    service.state_validator.validate_tree(selected,verified.manifest);service._scan_secrets(selected)
    locale=locale_proof(repo.settings,selected)
    if (set(locale)!={'old_locale_refused','corrected_locale_passed','tool_sources_sha256'}
            or locale['old_locale_refused'] is not True or locale['corrected_locale_passed'] is not True
            or not re.fullmatch('[0-9a-f]{64}',locale['tool_sources_sha256'])):raise ValueError
    if (tree!=retained_tree_projection(repo,verified,selected)
            or retained_metadata(repo,bid)!=metadata
            or read_regular_bytes(verified.path/'verification.json',max_bytes=4194304)!=verification
            or manager._evidence_state(verified)!=(True,False)):raise ValueError
    return dict(backup_id=bid,manifest_sha256=verified.manifest_sha256,
        verification_sha256=hashlib.sha256(verification).hexdigest(),tree_sha256=tree,locale=locale,protected_metadata_sha256=metadata)

def bound_retained_proof(repo,expected):
    from alt_deploy_backup.fs import read_regular_bytes
    from alt_deploy_backup.manifest import parse_manifest,parse_verification_evidence
    fields={'backup_id','manifest_sha256','verification_sha256','tree_sha256','locale','protected_metadata_sha256'}
    if (not isinstance(expected,dict) or set(expected)!=fields
            or any(not isinstance(expected[key],str) or not re.fullmatch('[0-9a-f]{64}',expected[key]) for key in fields-{'backup_id','locale'})):raise ValueError
    bid=expected['backup_id'];metadata=retained_metadata(repo,bid)
    if metadata!=expected['protected_metadata_sha256']:raise ValueError('Retained evidence metadata changed')
    root=repo.settings.backup_root/bid
    manifest_raw=read_regular_bytes(root/'manifest.json',max_bytes=16777216)
    verification_raw=read_regular_bytes(root/'verification.json',max_bytes=4194304)
    manifest=parse_manifest(manifest_raw);verification=parse_verification_evidence(verification_raw)
    if (hashlib.sha256(manifest_raw).hexdigest()!=expected['manifest_sha256']
            or hashlib.sha256(verification_raw).hexdigest()!=expected['verification_sha256']
            or manifest.backup_id!=bid or verification.backup_id!=bid or verification.status!='ok'
            or verification.manifest_sha256!=expected['manifest_sha256']
            or (root/'rehearsal.json').exists() or (root/'rehearsal.json').is_symlink()):raise ValueError
    repo.secrets.assert_matches(manifest.secret_identities)
    if retained_metadata(repo,bid)!=metadata:raise ValueError
    return dict(schema_version=1,retained_evidence_unchanged=True,protected_metadata_sha256=metadata)

def inspect_controller(request):
    import sys,shutil
    if os.geteuid()!=0 or not isinstance(request,dict):raise ValueError
    sys.path.insert(0,'/opt/alt-deploy-backup');sys.path.insert(0,'/opt/alt-deploy-control')
    from alt_deploy_backup.settings import BackupSettings
    from alt_deploy_backup.repository import BackupRepository
    from alt_deploy_backup.components import component_specs
    from alt_deploy_backup.fs import source_inventory
    from alt_deploy_backup.guard import GuardState
    from alt_deploy.setup_recovery_successor_probe import no_active_recovery
    from alt_deploy.setup_recovery_successor_capacity import readonly_operation_lock
    settings=BackupSettings.from_env()
    if settings.test_mode:raise ValueError
    repo=BackupRepository(settings)
    with readonly_operation_lock(settings.operation_lock):
        repo._validate_roots();repo._validate_commands();GuardState(settings).assert_control_plane_allowed()
        if set(request)=={'kind','retained','approved_at','finished_at','operation_sha256'} and request['kind']=='bound':
            audit=audit_rehearsal_failed(settings.log_file,request['approved_at'],request['finished_at'])
            if audit['operation_sha256']!=request['operation_sha256'] or audit['backup_id']!=request['retained']['backup_id']:raise ValueError
            return bound_retained_proof(repo,request['retained'])
        if set(request)!={'kind','approved_at','finished_at'} or request['kind']!='inspect':raise ValueError
        paths=repo._source_paths(component_specs(settings));repo._check_disk_space(paths)
        repo.quiescence.assert_quiescent();no_active_recovery()
        size=sum(entry.size for entry in source_inventory(paths) if entry.kind=='regular')
        capacity=dict(required_free_bytes=max(67108864,size*2),actual_free_bytes=shutil.disk_usage(settings.backup_root).free)
        if capacity['actual_free_bytes']<capacity['required_free_bytes']:raise ValueError
        audit=audit_rehearsal_failed(settings.log_file,request['approved_at'],request['finished_at'])
        retained=retained_rehearsal_proof(repo,audit['backup_id'])
        return dict(schema_version=1,native_guard=True,no_active_recovery=True,capacity=capacity,backup_audit=audit,retained=retained)

if __name__=='__main__':
    import sys
    try:
        frame=json.loads(sys.stdin.read(131073));result=inspect_controller(frame['request'])
        print(json.dumps(result,sort_keys=True))
    except Exception:
        print(json.dumps(dict(schema_version=1,error_code='recovery_rehearsal_controller_refused')));sys.exit(1)
