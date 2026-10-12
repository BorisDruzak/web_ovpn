"""One selected-user NSS observation under retained suppression/native proof.

No password authentication, cache flushing, service action or home creation.
Fresh employee AD identity/state is a separate mandatory controller guard.
NSS may use SSSD cache; this receipt never asserts online user authentication.
"""
from __future__ import annotations

import os,re,time,uuid
from pathlib import Path

TOOL='/usr/bin/getent'
PACKAGE='glibc-utils 2.38.0.223.f053ff-alt1.p11.1'
NSS_MODULE='/usr/lib64/libnss_sss.so.2'
NSS_PACKAGE='sssd-client 2.9.8-alt3'
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


def employee(value):
    if (not isinstance(value,dict) or set(value)!={'object_guid','object_sid','login','upn'}
            or any(not isinstance(field,str) for field in value.values())
            or str(uuid.UUID(value['object_guid']))!=value['object_guid']
            or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',value['object_sid'])
            or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}',value['login'])
            or value['upn']!=value['login']+'@sosnadmin.local'):raise ValueError('Invalid selected employee')
    return value


def _request(request):
    if (not isinstance(request,dict) or set(request)!={'schema_version','startup_request','startup_receipt',
            'native_receipt','employee','source_sha256','approval_sha256'}
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or any(not isinstance(request[key],str) or not re.fullmatch('[0-9a-f]{64}',request[key])
                for key in ('source_sha256','approval_sha256'))
            or request['approval_sha256']!=request['startup_request']['approval_sha256']):raise ValueError('Invalid selected-user request')
    employee(request['employee'])


def path_for(request,*,backup,root=Path('/')):
    original=request['startup_request']['policy_request']['kerberos_request']['import_request']['directory_result']
    return root/'var/lib/alt-deploy-recovery'/('user-check-'+backup.digest({key:original[key]
        for key in ('failed_run_id','computer_guid')}))


def _local(request,*,backup,probe,root,owner):
    metadata=probe._file(root,'/etc/passwd',owner=owner)
    if metadata.get('present') is not True:raise ValueError('Local user database unavailable')
    raw=backup._read(root/'etc/passwd',metadata,root=root,owner=owner)
    names=[]
    for line in raw.decode('utf-8').splitlines():
        fields=line.split(':')
        if len(fields)!=7 or not fields[0] or len(fields[0])>255:raise ValueError('Invalid local user database')
        names.append(fields[0].lower())
    if any(value in names for value in (request['employee']['login'],request['employee']['upn'])):
        raise ValueError('Local duplicate of selected domain employee')
    return metadata


def _dependency(request,key,path,package,*,probe,runner,root,owner):
    metadata=probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)
    facts=request['startup_request']['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
    expected=dict(facts['tools'][key]);expected.pop('package')
    if (metadata!=expected or metadata.get('present') is not True
            or (key=='getent' and metadata['mode'] & 0o111==0)
            or (key=='nss_sss' and metadata['mode'] & 0o400==0)):
        raise ValueError('Changed planned NSS dependency')
    rc,out,_=runner(['/usr/bin/rpm','-qf',path,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n'],
        environment=dict(ENVIRONMENT),timeout=10)
    if type(rc) is not int or rc or out!=package+'\n':raise ValueError('Unreviewed NSS package')
    if probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)!=metadata:raise ValueError('Changed NSS dependency')
    return dict(metadata,package=package)


def _tool(request,*,probe,runner,root,owner):
    return {key:_dependency(request,key,path,package,probe=probe,runner=runner,root=root,owner=owner)
        for key,path,package in (('getent',TOOL,PACKAGE),('nss_sss',NSS_MODULE,NSS_PACKAGE))}


def _unchanged(tool,*,probe,root,owner):
    return all(probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)==
        {key:value for key,value in tool[name].items() if key!='package'}
        for name,path in (('getent',TOOL),('nss_sss',NSS_MODULE)))


def _lookup(output,value):
    if (not isinstance(output,str) or len(output.encode())>16384 or not output.endswith('\n')
            or '\n' in output[:-1] or any(ord(char)<32 or ord(char)==127 for char in output[:-1])):
        raise ValueError('Invalid selected-user NSS response')
    fields=output[:-1].split(':')
    if (len(fields)!=7 or fields[0].lower() not in (value['login'],value['upn']) or fields[1]!='x'
            or any(not re.fullmatch('[1-9][0-9]{0,9}',fields[index]) or int(fields[index])>4294967294 for index in (2,3))
            or not fields[5].startswith('/') or '..' in fields[5].split('/') or len(fields[5])>4096
            or not fields[6].startswith('/') or '..' in fields[6].split('/') or len(fields[6])>4096):
        raise ValueError('Selected-user NSS identity did not match')
    return dict(uid=int(fields[2]),gid=int(fields[3]))


def _receipt(request,ids,tool,local,backup):
    original=request['native_receipt']
    result={key:original[key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno')}
    return dict(result,**ids,schema_version=1,status='selected_user_resolved',employee=request['employee'],
        request_sha256=backup.digest(request),native_receipt_sha256=backup.digest(original),
        getent_sha256=backup.digest(tool),local_passwd_sha256=backup.digest(local),
        user_lookup=True,local_duplicate=False,login_verified=False,online_user_authentication_verified=False,
        temporary_policy_retained=True)


def _records(request,result,tool,local,*,backup,root,owner):
    leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner);backup._directory(leaf,owner)
    records={'request.json':request,'intent.json':dict(schema_version=1,request_sha256=backup.digest(request),
        getent_sha256=backup.digest(tool),local_passwd_sha256=backup.digest(local))}
    if result is not None:records['verified.json']=result
    if {path.name for path in leaf.iterdir()}!=set(records):raise ValueError('Incomplete or failed selected-user observation')
    if any(backup.encoded(backup._json(leaf/name,root=root,owner=owner))!=backup.encoded(value)
            for name,value in records.items()):raise ValueError('Changed selected-user evidence')


def verify(request,result,*,checker,start,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root user verification required')
    _request(request);runner=start._runner(runner,time.monotonic()+120,request['startup_request'])
    args=dict(start=start,backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,
        policy=policy,services=services,graph=graph,collect=collect,runner=runner,root=root,owner=owner)
    checker.verify(request['startup_request'],request['startup_receipt'],request['native_receipt'],**args)
    tool=_tool(request,probe=probe,runner=runner,root=root,owner=owner);local=_local(request,backup=backup,probe=probe,root=root,owner=owner)
    if (not isinstance(result,dict) or any(type(result.get(key)) is not int or not 1<=result[key]<=4294967294 for key in ('uid','gid'))
            or backup.encoded(result)!=backup.encoded(_receipt(request,{key:result[key] for key in ('uid','gid')},tool,local,backup))):
        raise ValueError('Unbound selected-user receipt')
    checker.verify(request['startup_request'],request['startup_receipt'],request['native_receipt'],**args)
    # End all native callbacks with protected tool/passwd/evidence rereads.
    if (not _unchanged(tool,probe=probe,root=root,owner=owner)
            or _local(request,backup=backup,probe=probe,root=root,owner=owner)!=local):raise ValueError('Changed selected-user dependencies')
    _records(request,result,tool,local,backup=backup,root=root,owner=owner)
    return result


def check_once(request,*,checker,start,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root user observation required')
    _request(request);runner=start._runner(runner,time.monotonic()+120,request['startup_request'])
    args=dict(start=start,backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,
        policy=policy,services=services,graph=graph,collect=collect,runner=runner,root=root,owner=owner)
    leaf=path_for(request,backup=backup,root=root)
    with importer._lock(root,owner,backup):
        backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner)
        if leaf.exists() or leaf.is_symlink():raise ValueError('Selected-user check already attempted')
        checker.verify(request['startup_request'],request['startup_receipt'],request['native_receipt'],**args)
        tool=_tool(request,probe=probe,runner=runner,root=root,owner=owner);local=_local(request,backup=backup,probe=probe,root=root,owner=owner)
        leaf.mkdir(mode=0o700)
        try:
            backup._write(leaf/'request.json',backup.encoded(request))
            backup._write(leaf/'intent.json',backup.encoded(dict(schema_version=1,request_sha256=backup.digest(request),
                getent_sha256=backup.digest(tool),local_passwd_sha256=backup.digest(local))))
            importer._sync_all(leaf,root,backup)
            checker.verify(request['startup_request'],request['startup_receipt'],request['native_receipt'],**args)
            if (not _unchanged(tool,probe=probe,root=root,owner=owner)
                    or _local(request,backup=backup,probe=probe,root=root,owner=owner)!=local):raise ValueError('Changed prelookup dependencies')
            _records(request,None,tool,local,backup=backup,root=root,owner=owner)
            rc,out,_=runner([TOOL,'-s','sss','passwd',request['employee']['upn']],environment=dict(ENVIRONMENT),input_text='',timeout=15)
            if type(rc) is not int or rc:raise ValueError('Selected-user NSS resolution failed')
            ids=_lookup(out,request['employee']);del out
            checker.verify(request['startup_request'],request['startup_receipt'],request['native_receipt'],**args)
            if (_tool(request,probe=probe,runner=runner,root=root,owner=owner)!=tool
                    or _local(request,backup=backup,probe=probe,root=root,owner=owner)!=local):raise ValueError('Changed postlookup dependencies')
            _records(request,None,tool,local,backup=backup,root=root,owner=owner)
            result=_receipt(request,ids,tool,local,backup)
            backup._write(leaf/'verified.json',backup.encoded(result));backup._sync(leaf)
            return verify(request,result,checker=checker,**args)
        except Exception:
            try:backup._write(leaf/'failed.json',backup.encoded({'schema_version':1,'error_code':'recovery_user_check_failed'}));backup._sync(leaf)
            except Exception:pass
            raise ValueError('Selected-user observation did not verify; replay and automatic cleanup are prohibited') from None
