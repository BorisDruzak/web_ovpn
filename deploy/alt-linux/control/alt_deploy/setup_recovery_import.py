"""Fixed, nonretryable local credentials installation after one verified reset.

Only the existing Samba secrets database and fixed system keytab are replaced.
No online join, service start, directory write, rollback or trust claim occurs.
This internal producer requires trusted source dependencies and is not a CLI.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

FILES=('/var/lib/samba/private/secrets.tdb','/etc/krb5.keytab')


@contextmanager
def _lock(root,owner,backup):
    path=root/'var/lib/alt-deploy-recovery/.import.lock'
    backup._ancestry(path,root,owner);backup._directory(path.parent,owner)
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_size!=0
                or stat.S_IMODE(info.st_mode)!=0o600 or backup._signature(path.lstat())!=backup._signature(info)):
            raise ValueError('Unsafe local import lock')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Local credential installation is already running') from None
        yield
    finally:os.close(fd)


def _request(request,*,backup,rehearsal=None,native=None):
    fields={'schema_version','rehearsal_request','rehearsal_receipt','directory_result','source_sha256'}
    if (not isinstance(request,dict) or set(request)!=fields
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or not isinstance(request['source_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',request['source_sha256'])):
        raise ValueError('Invalid fixed import request')
    original=request['rehearsal_request']
    if rehearsal is not None:rehearsal._request(original,backup=backup,native=native)
    backup._request(original['backup_request'])
    result=request['directory_result'];bound=original['backup_request']
    fields={'schema_version','failed_run_id','computer_guid','status','machine_uuid','computer_sid',
            'claim_sha256','intent_sha256','sealed_sha256','kvno','pwd_last_set'}
    if (not isinstance(result,dict) or set(result)!=fields
            or type(result['schema_version']) is not int or result['schema_version']!=1
            or result['status']!='directory_password_written'
            or any(result[name]!=bound[name] for name in ('failed_run_id','computer_guid','machine_uuid','claim_sha256'))
            or result['sealed_sha256']!=original['credential_sha256']
            or not isinstance(result['intent_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',result['intent_sha256'])
            or not isinstance(result['computer_sid'],str)
            or not re.fullmatch(re.escape(original['metadata']['domain_sid'])+r'-[1-9][0-9]*',result['computer_sid'])
            or int(result['computer_sid'].rsplit('-',1)[1])>0xffffffff
            or type(result['kvno']) is not int or not 1<=result['kvno']<=2147483647
            or type(result['pwd_last_set']) is not int or not 0<result['pwd_last_set']<2**63):
        raise ValueError('Unbound directory write result')


def path_for(request,*,backup,root=Path('/')):
    _request(request,backup=backup)
    pair={key:request['directory_result'][key] for key in ('failed_run_id','computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('import-'+backup.digest(pair))


def _sync_all(path,root,backup):
    for directory in (path,*path.parents):
        backup._sync(directory)
        if directory==root:return
    raise ValueError('Import outside root')


def _guard(request,*,backup,collect,root,owner):
    original=request['rehearsal_request']
    if (collect()!=original['backup_request']['facts']
            or backup.verify(original['backup_request'],root=root,owner=owner)!=original['backup_receipt']):
        raise ValueError('Changed import snapshot or backup')


def _inactive(runner):
    rc,out,_=runner(['/usr/bin/systemctl','is-active','sssd','smb','nmb','winbind'],
        environment={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=15)
    if type(rc) is not int or rc not in (3,4) or out.splitlines()!=['inactive']*4:
        raise ValueError('Authentication services must be inactive')


def _build(request,password,*,backup,native,keytab,probe,runner,root,owner,leaf):
    original=request['rehearsal_request'];meta=original['metadata'];bound=original['backup_request']
    metadata=bound['facts']['files'][FILES[0]]
    if metadata.get('present') is not True:raise ValueError('Original secrets required')
    seed=backup._read(backup.path_for(bound,root=root)/'files'/str(backup.AUTH_FILES.index(FILES[0])),
        metadata,root=root,owner=owner)
    with tempfile.TemporaryDirectory(prefix='sandbox-',dir=leaf) as directory:
        work=Path(directory);work.chmod(0o700)
        for name in ('private','state','cache','lock','pid','logs','ncalrpc','winbind'):
            (work/name).mkdir(mode=0o700)
        backup._write(work/'private/secrets.tdb',seed,gid=metadata['gid'])
        backup._write(work/'smb.conf',native.sandbox_config(meta).encode())
        def run(operation,input_text=None):
            rc,out,_=runner(native.sandbox_command(work,meta,operation,owner=owner),
                environment={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8'},input_text=input_text,timeout=20)
            if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>16384:
                raise ValueError('Native local import failed')
            return out
        blob=run('compose',f"username = {meta['hostname'].upper()}$\npassword = {password}\ndomain = {meta['workgroup']}\n")
        if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}\n?',blob):raise ValueError('Invalid native blob')
        run('import',blob);native.validate_native_metadata(run('metadata'),meta)
        run('password',password)
        if run('password_check',password)!='true\n':raise ValueError('Native password mismatch')
        native.validate_native_metadata(run('metadata'),meta);run('keytab')
        native.validate_rehearsal_keytab(run('keytab_list'),meta)
        path=work/'krb5.keytab';info=probe._file(work,'/krb5.keytab',private=True,owner=owner)
        raw=backup._read(path,info,root=work,owner=owner,maximum=keytab.MAX_BYTES)
        bound_keys=keytab.bind_offline_keytab(raw,meta,request['directory_result']['kvno'],native=native)
        # The scratch file is private, isolated and checked again by native Samba.
        replacement=work/'bound.keytab';backup._write(replacement,bound_keys);os.replace(replacement,path)
        native.validate_domain_keytab(run('keytab_list'),meta,request['directory_result']['kvno'])
        secret_info=probe._file(work,'/private/secrets.tdb',private=True,owner=owner)
        secret=backup._read(work/'private/secrets.tdb',secret_info,root=work,owner=owner)
        backup._write(leaf/'secrets.tdb',secret);backup._write(leaf/'krb5.keytab',bound_keys)
        backup._sync(leaf)


def _expected(request,files):
    facts=copy.deepcopy(request['rehearsal_request']['backup_request']['facts'])
    facts['files'].update(files);facts['keytab_present']=True
    return facts


def _receipt(request,files,*,backup):
    result=request['directory_result']
    return dict(schema_version=1,status='local_credentials_installed',trust_verified=False,
        failed_run_id=result['failed_run_id'],computer_guid=result['computer_guid'],
        machine_uuid=result['machine_uuid'],computer_sid=result['computer_sid'],kvno=result['kvno'],
        request_sha256=backup.digest(request),directory_result_sha256=backup.digest(result),files=files)


def verify(request,*,backup,probe,collect,root=Path('/'),owner=0):
    receipt=verify_artifacts(request,backup=backup,probe=probe,collect=collect,root=root,owner=owner)
    if collect()!=_expected(request,receipt['files']):raise ValueError('Changed local import snapshot')
    return receipt


def verify_artifacts(request,*,backup,probe,collect,root=Path('/'),owner=0):
    """Verify retained import and all static facts, without asserting stopped services.

    Process observations alone are excluded. The startup worker must independently
    check service/process state; this result is neither fresh authentication nor trust.
    """
    if os.geteuid()!=owner or collect is None or not root.is_absolute():raise ValueError('Fixed root import required')
    leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner)
    backup._directory(leaf.parent,owner);backup._directory(leaf,owner)
    expected={'request.json','secrets.tdb','krb5.keytab','install-intent.json',
              'installed-secret.json','installed-keytab.json','installed.json'}
    if {p.name for p in leaf.iterdir()}!=expected or backup._json(leaf/'request.json',root=root,owner=owner)!=request:
        raise ValueError('Incomplete or failed local import')
    files={path:probe._file(root,path,private=True,owner=owner) for path in FILES}
    for index,path in enumerate(FILES):
        raw=backup._read(leaf/('secrets.tdb' if index==0 else 'krb5.keytab'),
            dict(files[path],gid=(leaf/('secrets.tdb' if index==0 else 'krb5.keytab')).lstat().st_gid),root=root,owner=owner)
        if hashlib.sha256(raw).hexdigest()!=files[path]['sha256']:raise ValueError('Changed installed credentials')
        marker={'schema_version':1,'path':path,'file_sha256':files[path]['sha256']}
        if backup._json(leaf/('installed-secret.json' if index==0 else 'installed-keytab.json'),root=root,owner=owner)!=marker:
            raise ValueError('Changed install progress')
    intent={'schema_version':1,'request_sha256':backup.digest(request),'files':files}
    receipt=_receipt(request,files,backup=backup)
    current=collect();expected_facts=_expected(request,files)
    processes=current.get('incompatible_processes') if isinstance(current,dict) else None
    if (not isinstance(processes,list) or any(not isinstance(item,str) for item in processes)
            or set(current)!=set(expected_facts)
            or {key:value for key,value in current.items() if key!='incompatible_processes'}
                !={key:value for key,value in expected_facts.items() if key!='incompatible_processes'}):
        raise ValueError('Changed local import static facts')
    if (backup._json(leaf/'install-intent.json',root=root,owner=owner)!=intent
            or backup._json(leaf/'installed.json',root=root,owner=owner)!=receipt
            or backup.verify(request['rehearsal_request']['backup_request'],root=root,owner=owner)!=request['rehearsal_request']['backup_receipt']):
        raise ValueError('Changed local import evidence')
    # The genuine collector runs native commands after reading file metadata.
    # Close that interval with protected reads, without another command cycle.
    for path,private in probe.AUTH_FILES.items():
        if probe._file(root,path,private=private,owner=owner)!=expected_facts['files'][path]:
            raise ValueError('Changed authentication file during artifact collection')
    for name,path in probe.TOOLS.items():
        metadata={key:value for key,value in expected_facts['tools'][name].items() if key!='package'}
        if probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)!=metadata:
            raise ValueError('Changed native executable during artifact collection')
    backup._sync(leaf);return receipt


def install_once(request,password,*,backup,native,keytab,rehearsal,probe,collect,runner,root=Path('/'),owner=0):
    if (os.geteuid()!=owner or collect is None or runner is None or not root.is_absolute()
            or not isinstance(password,str) or not re.fullmatch(r'Aa9![A-Za-z0-9_-]{64}',password)):
        raise ValueError('Fixed root import required')
    _request(request,backup=backup,rehearsal=rehearsal,native=native)
    with _lock(root,owner,backup):
        return _install(request,password,backup=backup,native=native,keytab=keytab,rehearsal=rehearsal,
            probe=probe,collect=collect,runner=runner,root=root,owner=owner)


def _install(request,password,*,backup,native,keytab,rehearsal,probe,collect,runner,root,owner):
    _guard(request,backup=backup,collect=collect,root=root,owner=owner)
    if rehearsal.verify(request['rehearsal_request'],backup=backup,collect=collect,root=root,owner=owner)!=request['rehearsal_receipt']:
        raise ValueError('Changed rehearsal evidence')
    leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner)
    try:leaf.mkdir(mode=0o700)
    except FileExistsError:raise ValueError('Local import already attempted') from None
    try:
        backup._write(leaf/'request.json',backup.encoded(request));_sync_all(leaf,root,backup)
        _inactive(runner)
        _build(request,password,backup=backup,native=native,keytab=keytab,probe=probe,
            runner=runner,root=root,owner=owner,leaf=leaf)
        _guard(request,backup=backup,collect=collect,root=root,owner=owner);_inactive(runner)
        staged={};files={}
        suffix='.alt-recovery-'+leaf.name.removeprefix('import-')+'.tmp'
        for path in FILES:
            target=root/path.lstrip('/');backup._ancestry(target,root,owner)
            raw=(leaf/('secrets.tdb' if path==FILES[0] else 'krb5.keytab')).read_bytes()
            temp=target.with_name(target.name+suffix);original=request['rehearsal_request']['backup_request']['facts']['files'][path]
            backup._write(temp,raw,gid=original.get('gid',os.getgid()));backup._sync(target.parent)
            staged[path]=temp;files[path]=probe._file(root,'/'+temp.relative_to(root).as_posix(),private=True,owner=owner)
        _guard(request,backup=backup,collect=collect,root=root,owner=owner)
        backup._write(leaf/'install-intent.json',backup.encoded({'schema_version':1,'request_sha256':backup.digest(request),'files':files}))
        _sync_all(leaf,root,backup)
        expected=copy.deepcopy(request['rehearsal_request']['backup_request']['facts'])
        for index,path in enumerate(FILES):
            if collect()!=expected:raise ValueError('Workstation changed before replacement')
            _inactive(runner)
            backup._read(staged[path],files[path],root=root,owner=owner)
            os.replace(staged[path],root/path.lstrip('/'));backup._sync((root/path.lstrip('/')).parent)
            expected['files'][path]=files[path]
            if path==FILES[1]:expected['keytab_present']=True
            backup._write(leaf/('installed-secret.json' if index==0 else 'installed-keytab.json'),
                backup.encoded({'schema_version':1,'path':path,'file_sha256':files[path]['sha256']}));backup._sync(leaf)
        receipt=_receipt(request,files,backup=backup)
        _inactive(runner)
        backup._write(leaf/'installed.json',backup.encoded(receipt));backup._sync(leaf)
        return verify(request,backup=backup,probe=probe,collect=collect,root=root,owner=owner)
    except Exception:
        try:
            backup._write(leaf/'failed.json',backup.encoded({'schema_version':1,'error_code':'recovery_local_import_failed'}));backup._sync(leaf)
        except Exception:pass
        raise ValueError('Local recovery import failed; replay and automatic rollback are prohibited') from None
