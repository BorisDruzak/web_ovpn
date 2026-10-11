"""Fixed temporary SSSD policy; no service start, directory write or reauth.

The future transport must bind current AD and stopped unit policy separately.
An explicit terminal restoration remains required after fresh Setup acceptance.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import tempfile

SNIPPET='/etc/sssd/conf.d/99-alt-deploy-recovery.conf'
TOOLS={'/usr/sbin/sssd':'sssd 2.9.8-alt3','/usr/sbin/sssctl':'sssd-tools 2.9.8-alt3',
    '/usr/bin/bwrap':'bubblewrap 0.13.0-alt1','/usr/bin/python3.12':'python3 3.12.13-alt1',
    '/usr/lib64/python3/site-packages/ldb.cpython-312.so':'python3-module-pyldb 4.21.9-alt4.p11.1'}
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}
# Configuration generation only: map the service identity into the single-UID
# namespace. These files never become host NSS configuration or start a daemon.
SANDBOX_NSS={'/passwd':b'root:x:0:0:root:/root:/bin/false\n_sssd:x:0:0:SSSD:/:/bin/false\n',
    '/group':b'root:x:0:\n_sssd:x:0:\n'}
MODULE_DIRECTORY='/usr/lib64/samba/ldb.mit'
MODULE_PACKAGES=frozenset(('libldb-modules-ldap 4.21.9-alt4.p11.1','samba-dc-libs 4.21.9-alt4.p11.1','sssd 2.9.8-alt3'))


def _request(request,*,backup,kerberos):
    if (not isinstance(request,dict) or set(request)!={'schema_version','kerberos_request','kerberos_receipt','source_sha256'}
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or not isinstance(request['source_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',request['source_sha256'])):
        raise ValueError('Invalid fixed SSSD policy request')
    kerberos._request(request['kerberos_request'],backup=backup)


def _values(meta):
    return {'ad_maximum_machine_account_password_age':'0','dyndns_update':'false','ad_server':meta['dc_hostname'],
        'ad_backup_server':'','ad_enabled_domains':meta['realm'],'ad_enable_dns_sites':'false',
        'id_provider':'ad','auth_provider':'ad','access_provider':'ad','domains':meta['realm'].upper()}


def _snippet(meta):
    values=_values(meta)
    return ('[domain/'+meta['realm'].upper()+']\n'+''.join(key+' = '+values[key]+'\n' for key in
        ('ad_maximum_machine_account_password_age','dyndns_update','ad_server','ad_enabled_domains','ad_enable_dns_sites'))).encode('ascii')


def _run(runner,command):
    rc,out,_=runner(command,environment=dict(ENVIRONMENT),timeout=30)
    if type(rc) is not int or rc!=0 or not isinstance(out,str) or len(out.encode())>16384:raise ValueError('Fixed policy command failed')
    return out


def _tools(*,probe,runner,root,owner):
    result={}
    for path,package in TOOLS.items():
        info=probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)
        if not info['present'] or (not path.endswith('.so') and info['mode']!=0o755):raise ValueError('Unsafe policy executable')
        if _run(runner,['/usr/bin/rpm','-qf',path,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n']).strip()!=package:
            raise ValueError('Unreviewed policy executable')
        result[path]=dict(info,package=package)
    if _run(runner,['/usr/bin/rpm','-q','libini_config','--qf','%{NAME} %{VERSION}-%{RELEASE}\n']).strip()!='libini_config 1.3.1-alt6':
        raise ValueError('Unreviewed configuration parser')
    result['ldb_modules']=_modules(probe=probe,runner=runner,root=root,owner=owner)
    return result


def _modules(*,probe,runner,root,owner):
    directory=root/MODULE_DIRECTORY.lstrip('/');info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:raise ValueError('Unsafe LDB module directory')
    lookup=directory.parent/'ldb';before=lookup.lstat()
    target='/etc/alternatives/links/|usr|lib64|samba|ldb'
    if (not stat.S_ISLNK(before.st_mode) or before.st_uid!=owner or os.readlink(lookup)!=target
            or probe._signature(lookup.lstat())!=probe._signature(before)):
        raise ValueError('Unreviewed LDB lookup link')
    names=sorted(path.name for path in directory.iterdir())
    if not 1<=len(names)<=128 or any(not re.fullmatch('[a-z0-9_]+\\.so',name) for name in names):
        raise ValueError('Unexpected LDB modules')
    result={'lookup_link':{'target':target,'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode)}}
    for name in names:
        path=MODULE_DIRECTORY+'/'+name;metadata=probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)
        package=_run(runner,['/usr/bin/rpm','-qf',path,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n']).strip()
        if not metadata['present'] or package not in MODULE_PACKAGES:raise ValueError('Unreviewed LDB module')
        result[name]=dict(metadata,package=package)
    if (sorted(path.name for path in directory.iterdir())!=names
            or probe._signature(lookup.lstat())!=probe._signature(before)):
        raise ValueError('Changed LDB module set or lookup link')
    return result


def _directory(root,owner,names):
    directory=root/'etc/sssd/conf.d'
    for path in (directory,directory.parent):
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:raise ValueError('Unsafe snippet directory')
    if {path.name for path in directory.iterdir()}!=names:raise ValueError('Unexpected SSSD snippets')


def _current(request,*,backup,probe,native,kerberos,importer,collect,runner,root,owner):
    bound=request['kerberos_request']
    if kerberos.verify(bound,backup=backup,probe=probe,native=native,importer=importer,collect=collect,
            runner=runner,root=root,owner=owner)!=request['kerberos_receipt']:raise ValueError('Changed retained machine proof')
    tools=_tools(probe=probe,runner=runner,root=root,owner=owner)
    planned=bound['import_request']['rehearsal_request']['backup_request']['facts']['tools']
    if any(tools[path]!=planned[name] for name,path in (('sssd','/usr/sbin/sssd'),('bwrap','/usr/bin/bwrap'))):
        raise ValueError('Changed planned policy executable')
    return tools


def _commands(work,meta,*,native,owner):
    command=native.sandbox_command(work,meta,'password_check',owner=owner)
    prefix=command[:command.index('--')]
    prefix+=['--ro-bind',str(work/'config'),'/etc/sssd','--dir','/var','--dir','/var/lib',
        '--bind',str(work/'sss'),'/var/lib/sss','--dir','/var/log','--dir','/var/log/sssd','--tmpfs','/run',
        '--ro-bind',str(work/'passwd'),'/etc/passwd','--ro-bind',str(work/'group'),'/etc/group',
        '--dir','/etc/alternatives','--dir','/etc/alternatives/links',
        '--symlink','/usr/lib64/samba/ldb.mit','/etc/alternatives/links/|usr|lib64|samba|ldb','--']
    values=_values(meta);attributes=[key for key in values if key!='domains']
    # Only fixed local database and allowlisted non-secret attributes are read.
    code=('import json,ldb; db=ldb.Ldb("/var/lib/sss/db/config.ldb",flags=ldb.FLG_RDONLY); '
        'rows=db.search(base='+repr('cn='+meta['realm'].upper()+',cn=domain,cn=config')+',scope=ldb.SCOPE_BASE,attrs='+repr(attributes)+'); '
        'assert len(rows)==1; row=rows[0]; '
        'assert all(len(row[key])==1 for key in '+repr(attributes)+' if key in row); '
        'result={key:bytes(row[key][0]).decode("ascii") if key in row else "" for key in '+repr(attributes)+'}; '
        'sssd=db.search(base="cn=sssd,cn=config",scope=ldb.SCOPE_BASE,attrs=["domains"]); '
        'assert len(sssd)==1 and len(sssd[0]["domains"])==1; '
        'result["domains"]=bytes(sssd[0]["domains"][0]).decode("ascii"); print(json.dumps(result,sort_keys=True))')
    return [prefix+['/usr/sbin/sssctl','config-check'],prefix+['/usr/sbin/sssd','--genconf','--logger=stderr','-d','0'],
        prefix+['/usr/bin/python3.12','-I','-B','-c',code]]


def _offline(main,snippet,meta,*,leaf,backup,probe,native,runner,owner,root=Path('/')):
    modules=_modules(probe=probe,runner=runner,root=root,owner=owner)
    with tempfile.TemporaryDirectory(prefix='scratch-',dir=leaf) as temporary:
        work=Path(temporary)
        for path in ('config','config/conf.d','sss','sss/db','sss/pubconf','sss/pipes'):(work/path).mkdir(mode=0o700)
        backup._write(work/'config/sssd.conf',main)
        backup._write(work/'config/conf.d'/Path(SNIPPET).name,snippet)
        files={'/config/sssd.conf':main,'/config/conf.d/'+Path(SNIPPET).name:snippet}
        for path,content in SANDBOX_NSS.items():backup._write(work/path.lstrip('/'),content)
        files.update(SANDBOX_NSS)
        metadata={path:probe._file(work,path,private=True,owner=owner) for path in files}
        def guard():
            for path,content in files.items():
                if (probe._file(work,path,private=True,owner=owner)!=metadata[path]
                        or backup._read(work/path.lstrip('/'),metadata[path],root=work,owner=owner)!=content):
                    raise ValueError('Changed isolated configuration')
        outputs=[];database=None
        for index,command in enumerate(_commands(work,meta,native=native,owner=owner)):
            guard()
            if _modules(probe=probe,runner=runner,root=root,owner=owner)!=modules:
                raise ValueError('Changed LDB modules')
            if database is not None and probe._file(work,'/sss/db/config.ldb',private=True,owner=owner)!=database:
                raise ValueError('Changed isolated configuration database')
            outputs.append(_run(runner,command));guard()
            if _modules(probe=probe,runner=runner,root=root,owner=owner)!=modules:
                raise ValueError('Changed LDB modules during parsing')
            if index==1:
                database=probe._file(work,'/sss/db/config.ldb',private=True,owner=owner)
                if not database['present'] or not database['size']:raise ValueError('Configuration database missing')
            elif index==2 and probe._file(work,'/sss/db/config.ldb',private=True,owner=owner)!=database:
                raise ValueError('Changed configuration database during read')
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('Duplicate effective policy')
                result[key]=value
            return result
        if json.loads(outputs[-1],object_pairs_hook=unique)!=_values(meta):raise ValueError('Effective SSSD policy did not verify')


def path_for(request,*,backup,root=Path('/')):
    pair={key:request['kerberos_request']['import_request']['directory_result'][key] for key in ('failed_run_id','computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('sssd-policy-'+backup.digest(pair))


def _receipt(request,tools,snippet,backup):
    pair={key:request['kerberos_request']['import_request']['directory_result'][key] for key in
        ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno')}
    return dict(pair,schema_version=1,status='sssd_policy_prepared',trust_verified=False,
        request_sha256=backup.digest(request),tools_sha256=backup.digest(tools),snippet_sha256=backup.digest(snippet.decode('ascii')))


def verify(request,*,backup,probe,native,kerberos,importer,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root policy verification required')
    _request(request,backup=backup,kerberos=kerberos);leaf=path_for(request,backup=backup,root=root)
    backup._ancestry(leaf,root,owner);backup._directory(leaf,owner)
    if {path.name for path in leaf.iterdir()}!={'request.json','intent.json','original.json','original.conf','verified.json'}:
        raise ValueError('Incomplete or failed SSSD policy')
    tools=_current(request,backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,
        collect=collect,runner=runner,root=root,owner=owner)
    meta=native.validate_metadata(request['kerberos_request']['import_request']['rehearsal_request']['metadata']);snippet=_snippet(meta)
    _directory(root,owner,{Path(SNIPPET).name})
    info=probe._file(root,SNIPPET,private=True,owner=owner)
    if info.get('gid')!=owner or backup._read(root/SNIPPET.lstrip('/'),info,root=root,owner=owner)!=snippet:raise ValueError('Changed SSSD policy')
    main=probe._file(root,'/etc/sssd/sssd.conf',private=True,owner=owner)
    stored=backup._json(leaf/'original.json',root=root,owner=owner)
    if main!=stored:raise ValueError('Changed main SSSD configuration')
    original=probe._file(leaf,'/original.conf',private=True,owner=owner)
    if backup._read(leaf/'original.conf',original,root=leaf,owner=owner)!=backup._read(root/'etc/sssd/sssd.conf',main,root=root,owner=owner):
        raise ValueError('Changed retained main configuration')
    result=_receipt(request,tools,snippet,backup)
    intent=dict(schema_version=1,request_sha256=backup.digest(request),tools_sha256=backup.digest(tools),
        original_sha256=backup.digest(stored),snippet_sha256=result['snippet_sha256'])
    for name,value in (('request.json',request),('intent.json',intent),('verified.json',result)):
        if backup._json(leaf/name,root=root,owner=owner)!=value:raise ValueError('Changed SSSD policy evidence')
    return result


def install_once(request,*,backup,probe,native,kerberos,importer,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root policy preparation required')
    _request(request,backup=backup,kerberos=kerberos)
    with importer._lock(root,owner,backup):
        args=dict(backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,collect=collect,runner=runner,root=root,owner=owner)
        tools=_current(request,**args);_directory(root,owner,set())
        meta=native.validate_metadata(request['kerberos_request']['import_request']['rehearsal_request']['metadata']);snippet=_snippet(meta)
        main=probe._file(root,'/etc/sssd/sssd.conf',private=True,owner=owner)
        content=backup._read(root/'etc/sssd/sssd.conf',main,root=root,owner=owner)
        leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner)
        try:leaf.mkdir(mode=0o700)
        except FileExistsError:raise ValueError('SSSD policy already attempted') from None
        try:
            result=_receipt(request,tools,snippet,backup)
            intent=dict(schema_version=1,request_sha256=backup.digest(request),tools_sha256=backup.digest(tools),
                original_sha256=backup.digest(main),snippet_sha256=result['snippet_sha256'])
            for name,value in (('request.json',request),('intent.json',intent),('original.json',main)):backup._write(leaf/name,backup.encoded(value))
            backup._write(leaf/'original.conf',content);importer._sync_all(leaf,root,backup)
            _offline(content,snippet,meta,leaf=leaf,backup=backup,probe=probe,native=native,runner=runner,owner=owner,root=root)
            if _current(request,**args)!=tools:raise ValueError('Changed preinstallation state')
            _directory(root,owner,set())
            if (probe._file(root,'/etc/sssd/sssd.conf',private=True,owner=owner)!=main
                    or backup._json(leaf/'intent.json',root=root,owner=owner)!=intent
                    or backup._json(leaf/'request.json',root=root,owner=owner)!=request):raise ValueError('Changed policy intent')
            backup._write(root/SNIPPET.lstrip('/'),snippet);importer._sync_all(root/'etc/sssd/conf.d',root,backup)
            if _current(request,**args)!=tools:raise ValueError('Changed postinstallation state')
            backup._write(leaf/'verified.json',backup.encoded(result));backup._sync(leaf)
            return verify(request,**args)
        except Exception:
            try:backup._write(leaf/'failed.json',backup.encoded({'schema_version':1,'error_code':'recovery_sssd_policy_failed'}));backup._sync(leaf)
            except Exception:pass
            raise ValueError('SSSD policy did not verify; replay and diagnostics are prohibited') from None
