"""One native Samba check using private copied credentials and retained startup.

Internal worker only: no CLI, AD writer, service action or user authentication.
Native discovery is not an enforced-peer proof. Pinned directory/Kerberos
continuity and employee NSS resolution remain separate controller obligations.
"""
from __future__ import annotations

import os
import hashlib
from pathlib import Path
import tempfile
import time

TOOLS={'/usr/bin/net':'samba-common-tools 4.21.9-alt4.p11.1',
    '/usr/bin/testparm':'samba-common-tools 4.21.9-alt4.p11.1',
    '/usr/bin/bwrap':'bubblewrap 0.13.0-alt1'}
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


def sandbox_config(meta,*,native):
    return (native.sandbox_config(meta)+'create krb5 conf = no\ninclude system krb5 conf = no\n'
        'client ldap sasl wrapping = seal\nidmap config * : backend = tdb\n'
        'idmap config * : range = 100000-199999\n')


def sandbox_command(work,meta,*,native,owner=0):
    command=native.sandbox_command(work,meta,'metadata',owner=owner)
    command.remove('--unshare-net')
    # The only changed isolation boundary is deliberate native networking.
    # Fixed private NSS/DNS/Kerberos inputs replace inherited host inputs.
    position=command.index('/etc/nsswitch.conf');command[position]=str(work/'nsswitch.conf')
    end=command.index('--')
    for name,target in [('hosts','/etc/hosts'),('resolv.conf','/etc/resolv.conf'),
            ('krb5.conf','/etc/krb5.conf'),('smb.conf','/work/smb.conf')]:
        command[end:end]=['--ro-bind',str(work/name),target];end+=3
    command[end:end]=['--setenv','KRB5_CONFIG','/etc/krb5.conf','--setenv','KRB5CCNAME','FILE:/work/ccache']
    end=command.index('--')
    command[end+1:]=['/usr/bin/net','-s','/work/smb.conf','-d','0','--use-kerberos=required',
        '-S',meta['dc_hostname'],'-I',meta['dc_address'],'ads','testjoin']
    return command


def path_for(request,*,backup,root=Path('/')):
    original=request['policy_request']['kerberos_request']['import_request']['directory_result']
    pair={key:original[key] for key in ('failed_run_id','computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('native-testjoin-'+backup.digest(pair))


def _tools(request,*,backup,probe,runner,root,owner):
    facts=request['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
    result={}
    for path,package in TOOLS.items():
        info=probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)
        name=path.rsplit('/',1)[1];expected={key:value for key,value in facts['tools'][name].items() if key!='package'}
        if not info.get('present') or info['mode']!=0o755 or info!=expected:raise ValueError('Changed native executable')
        rc,out,_=runner(['/usr/bin/rpm','-qf',path,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n'],
            environment=dict(ENVIRONMENT),timeout=15)
        if type(rc) is not int or rc!=0 or not isinstance(out,str) or out.strip()!=package:raise ValueError('Unreviewed native package')
        result[path]=dict(info,package=package)
    return result


def _request(request,started,*,start,backup,policy,kerberos,services,native):
    start._request(request,backup=backup,policy=policy,kerberos=kerberos,services=services)
    meta=request['policy_request']['kerberos_request']['import_request']['rehearsal_request']['metadata']
    native.validate_metadata(meta)
    if started.get('request_sha256')!=backup.digest(request) or started.get('status')!='sssd_started':
        raise ValueError('Unbound native check startup')
    return meta


def _receipt(request,started,tools,backup):
    result={key:started[key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno')}
    return dict(result,schema_version=1,status='native_testjoin_succeeded',trust_verified=False,
        request_sha256=backup.digest(request),startup_receipt_sha256=backup.digest(started),
        tools_sha256=backup.digest(tools),native_testjoin_peer_pinning_verified=False,
        temporary_policy_retained=True)


def _records(request,started,result,tools,*,backup,root,owner):
    leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner);backup._directory(leaf,owner)
    records={'request.json':dict(startup_request=request,startup_receipt=started),
        'intent.json':dict(schema_version=1,request_sha256=backup.digest(request),
            startup_receipt_sha256=backup.digest(started),tools_sha256=backup.digest(tools))}
    if result is not None:records['verified.json']=result
    if {path.name for path in leaf.iterdir()}!=set(records):raise ValueError('Incomplete or failed native check')
    if any(backup.encoded(backup._json(leaf/name,root=root,owner=owner))!=backup.encoded(value)
            for name,value in records.items()):raise ValueError('Changed native check evidence')


def _scratch(work,pinned,*,backup,root,owner,preinvoke):
    backup._ancestry(work/'smb.conf',root,owner);backup._directory(work,owner)
    for name in ('private','state','cache','lock','pid','logs','ncalrpc','winbind'):
        backup._directory(work/name,owner)
    for name,(metadata,signature) in pinned.items():
        if name=='private/secrets.tdb' and not preinvoke:continue
        path=work/name
        if backup._signature(path.lstat())!=signature:raise ValueError('Changed scratch input')
        backup._read(path,metadata,root=root,owner=owner)


def verify(request,started,result,*,start,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root native check required')
    _request(request,started,start=start,backup=backup,policy=policy,kerberos=kerberos,services=services,native=native)
    runner=start._runner(runner,time.monotonic()+120,request)
    args=dict(backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,
        policy=policy,services=services,graph=graph,collect=collect,runner=runner,root=root,owner=owner)
    start.verify_started(request,started,**args)
    tools=_tools(request,backup=backup,probe=probe,runner=runner,root=root,owner=owner)
    if backup.encoded(result)!=backup.encoded(_receipt(request,started,tools,backup)):raise ValueError('Unbound native result')
    _records(request,started,result,tools,backup=backup,root=root,owner=owner)
    if _tools(request,backup=backup,probe=probe,runner=runner,root=root,owner=owner)!=tools:raise ValueError('Changed native tool')
    start.verify_started(request,started,**args)
    _records(request,started,result,tools,backup=backup,root=root,owner=owner)
    return result


def testjoin_once(request,started,*,start,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root native check required')
    meta=_request(request,started,start=start,backup=backup,policy=policy,kerberos=kerberos,services=services,native=native)
    runner=start._runner(runner,time.monotonic()+min(120,start._remaining(request)),request)
    args=dict(backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,
        policy=policy,services=services,graph=graph,collect=collect,runner=runner,root=root,owner=owner)
    leaf=path_for(request,backup=backup,root=root)
    with importer._lock(root,owner,backup):
        backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner)
        if leaf.exists() or leaf.is_symlink():raise ValueError('Native check already attempted')
        start.verify_started(request,started,**args)
        tools=_tools(request,backup=backup,probe=probe,runner=runner,root=root,owner=owner)
        leaf.mkdir(mode=0o700)
        try:
            backup._write(leaf/'request.json',backup.encoded(dict(startup_request=request,startup_receipt=started)))
            backup._write(leaf/'intent.json',backup.encoded(dict(schema_version=1,request_sha256=backup.digest(request),
                startup_receipt_sha256=backup.digest(started),tools_sha256=backup.digest(tools))))
            importer._sync_all(leaf,root,backup)
            start.verify_started(request,started,**args)
            imported=request['policy_request']['kerberos_request']['import_receipt']
            with tempfile.TemporaryDirectory(prefix='scratch-',dir=leaf) as directory:
                work=Path(directory);work.chmod(0o700)
                for name in ('private','state','cache','lock','pid','logs','ncalrpc','winbind'):(work/name).mkdir(mode=0o700)
                raw=backup._read(root/'var/lib/samba/private/secrets.tdb',imported['files']['/var/lib/samba/private/secrets.tdb'],root=root,owner=owner)
                backup._write(work/'private/secrets.tdb',raw);del raw
                files={'smb.conf':sandbox_config(meta,native=native),'krb5.conf':kerberos._config(meta),
                    'nsswitch.conf':'hosts: files dns\npasswd: files\ngroup: files\n',
                    'hosts':'127.0.0.1 localhost\n'+meta['dc_address']+' '+meta['dc_hostname']+'\n',
                    'resolv.conf':'nameserver '+meta['dc_address']+'\noptions timeout:2 attempts:1\n'}
                for name,value in files.items():backup._write(work/name,value.encode())
                pinned={}
                expected={name:hashlib.sha256(value.encode()).hexdigest() for name,value in files.items()}
                expected['private/secrets.tdb']=imported['files']['/var/lib/samba/private/secrets.tdb']['sha256']
                for name,sha in expected.items():
                    metadata=probe._file(work,'/'+name,private=True,owner=owner)
                    if not metadata.get('present') or metadata['mode']!=0o600 or metadata['sha256']!=sha:raise ValueError
                    pinned[name]=(metadata,backup._signature((work/name).lstat()))
                command=sandbox_command(work,meta,native=native,owner=owner)
                if _tools(request,backup=backup,probe=probe,runner=runner,root=root,owner=owner)!=tools:raise ValueError
                start.verify_started(request,started,**args)
                # The durable intent is checked while scratch exists; scratch
                # names are deliberately excluded from the retained record set.
                for name,value in (('request.json',dict(startup_request=request,startup_receipt=started)),
                        ('intent.json',dict(schema_version=1,request_sha256=backup.digest(request),
                            startup_receipt_sha256=backup.digest(started),tools_sha256=backup.digest(tools)))):
                    if backup.encoded(backup._json(leaf/name,root=root,owner=owner))!=backup.encoded(value):raise ValueError
                _scratch(work,pinned,backup=backup,root=root,owner=owner,preinvoke=True)
                rc,out,_=runner(command,environment=dict(ENVIRONMENT),input_text='',timeout=30)
                if type(rc) is not int or rc!=0 or out!='Join is OK\n':raise ValueError('Native Samba authentication did not verify')
                _scratch(work,pinned,backup=backup,root=root,owner=owner,preinvoke=False)
            # No copied secrets or ticket caches may remain at receipt commit.
            _records(request,started,None,tools,backup=backup,root=root,owner=owner)
            start.verify_started(request,started,**args)
            if _tools(request,backup=backup,probe=probe,runner=runner,root=root,owner=owner)!=tools:raise ValueError
            result=_receipt(request,started,tools,backup)
            backup._write(leaf/'verified.json',backup.encoded(result));backup._sync(leaf)
            return verify(request,started,result,start=start,**args)
        except Exception:
            try:backup._write(leaf/'failed.json',backup.encoded({'schema_version':1,'error_code':'recovery_native_testjoin_failed'}));backup._sync(leaf)
            except Exception:pass
            raise ValueError('Native Samba check did not verify; replay and automatic cleanup are prohibited') from None
