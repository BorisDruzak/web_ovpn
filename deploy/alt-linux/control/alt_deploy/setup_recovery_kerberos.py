"""Fixed local machine-keytab proof with a private, destroyed ticket cache.

This internal worker authenticates only the installed machine keytab. It cannot
reset passwords, join AD, start services, test a user's password or claim SSSD
or Samba trust. Its future transport must separately bind the actual AD identity
and current service/unit policy to the protected controller post-write state.
"""
from __future__ import annotations

from datetime import datetime,timezone
import os
from pathlib import Path
import re
import tempfile

TOOLS=('/usr/bin/kinit','/usr/bin/klist','/usr/bin/kdestroy')
PACKAGE='krb5-kinit 1.21.3-alt2.1'


def _request(request,*,backup):
    if (not isinstance(request,dict) or set(request)!={'schema_version','import_request','import_receipt','source_sha256'}
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or not isinstance(request['source_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',request['source_sha256'])):
        raise ValueError('Invalid fixed Kerberos proof request')
    original=request['import_request']['rehearsal_request']['backup_request'];backup._request(original)
    if original['facts']['tools']['klist']['package']!=PACKAGE:raise ValueError('Unreviewed Kerberos package')


def _run(runner,command,environment):
    rc,out,_=runner(command,environment=environment,timeout=30)
    if type(rc) is not int or rc!=0 or not isinstance(out,str) or len(out.encode('utf-8'))>16384:
        raise ValueError('Kerberos command failed')
    return out


def _tools(*,probe,runner,root,owner):
    result={}
    for path in TOOLS:
        info=probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)
        if not info['present'] or info['mode']!=0o755:raise ValueError('Unsafe Kerberos executable')
        package=_run(runner,['/usr/bin/rpm','-qf',path,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n'],
            {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}).strip()
        if package!=PACKAGE:raise ValueError('Unreviewed Kerberos executable')
        result[path]=dict(info,package=package)
    return result


def _config(meta):
    realm=meta['realm'].upper()
    return ('[libdefaults]\n default_realm = '+realm+'\n canonicalize = false\n'
        ' dns_canonicalize_hostname = false\n rdns = false\n dns_lookup_kdc = false\n dns_uri_lookup = false\n'
        ' forwardable = false\n proxiable = false\n renew_lifetime = 0\n kdc_default_options = 0\n'
        ' ticket_lifetime = 5m\n udp_preference_limit = 1\n[realms]\n '+realm+' = {\n'
        '  kdc = '+meta['dc_address']+':88\n }\n')


def _ticket(output,cache,principal,realm,now):
    lines=[line.strip() for line in output.splitlines() if line.strip()]
    if (len(lines) not in (4,5) or lines[0]!='Ticket cache: '+cache
            or lines[1]!='Default principal: '+principal
            or not re.fullmatch(r'Valid starting\s+Expires\s+Service principal',lines[2])):
        raise ValueError('Unexpected machine ticket identity')
    date=r'[0-9]{2}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}'
    match=re.fullmatch('('+date+r')\s+('+date+r')\s+krbtgt/'+re.escape(realm)+'@'+re.escape(realm),lines[3])
    if match is None or (len(lines)==5 and not re.fullmatch('renew until '+date,lines[4])):
        raise ValueError('Unexpected machine ticket service')
    start,end=[datetime.strptime(value,'%m/%d/%y %H:%M:%S').replace(tzinfo=timezone.utc) for value in match.groups()]
    if now.utcoffset() is None or not start.timestamp()<=now.timestamp()+300 or not end>now or not 0<(end-start).total_seconds()<=600:
        raise ValueError('Machine ticket is not current and bounded')


def path_for(request,*,backup,root=Path('/')):
    _request(request,backup=backup)
    pair={key:request['import_request']['directory_result'][key] for key in ('failed_run_id','computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('kerberos-'+backup.digest(pair))


def _current(request,*,backup,importer,probe,collect,runner,root,owner):
    if importer.verify(request['import_request'],backup=backup,probe=probe,collect=collect,root=root,owner=owner)!=request['import_receipt']:
        raise ValueError('Changed local import')
    importer._inactive(runner)
    tools=_tools(probe=probe,runner=runner,root=root,owner=owner)
    if tools['/usr/bin/klist']!=request['import_request']['rehearsal_request']['backup_request']['facts']['tools']['klist']:
        raise ValueError('Changed planned Kerberos executable')
    return tools


def _intent(request,tools,meta,backup):
    return dict(schema_version=1,request_sha256=backup.digest(request),tools_sha256=backup.digest(tools),
        configuration_sha256=backup.digest(_config(meta)))


def _receipt(request,tools,meta,backup):
    result={key:request['import_request']['directory_result'][key] for key in ('failed_run_id','computer_guid','machine_uuid','computer_sid','kvno')}
    return dict(result,schema_version=1,status='machine_keytab_authenticated',trust_verified=False,
        principal=meta['hostname'].upper()+'$@'+meta['realm'].upper(),dc_hostname=meta['dc_hostname'],
        dc_address=meta['dc_address'],request_sha256=backup.digest(request),tools_sha256=backup.digest(tools))


def verify(request,*,backup,importer,probe,native,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root verification required')
    _request(request,backup=backup)
    _current(request,backup=backup,importer=importer,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
    result=verify_artifacts(request,backup=backup,importer=importer,probe=probe,native=native,
        collect=collect,runner=runner,root=root,owner=owner)
    if importer.verify(request['import_request'],backup=backup,probe=probe,collect=collect,
            root=root,owner=owner)!=request['import_receipt']:raise ValueError('Changed final local import')
    importer._inactive(runner)
    return result


def verify_artifacts(request,*,backup,importer,probe,native,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root verification required')
    _request(request,backup=backup)
    if importer.verify_artifacts(request['import_request'],backup=backup,probe=probe,collect=collect,
            root=root,owner=owner)!=request['import_receipt']:raise ValueError('Changed retained import')
    tools=_tools(probe=probe,runner=runner,root=root,owner=owner)
    result=_verify_artifacts(request,backup=backup,importer=importer,probe=probe,native=native,
        collect=collect,root=root,owner=owner)
    if backup.digest(tools)!=result['tools_sha256']:raise ValueError('Changed Kerberos tools during read')
    return result


def _verify_artifacts(request,*,backup,importer,probe,native,collect,root,owner):
    # This verifies retained evidence and current files/tools only. It does not
    # repeat authentication or assert that a historical TGT remains valid.
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root verification required')
    _request(request,backup=backup);leaf=path_for(request,backup=backup,root=root)
    backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner);backup._directory(leaf,owner)
    if {path.name for path in leaf.iterdir()}!={'request.json','intent.json','verified.json'}:
        raise ValueError('Incomplete or failed Kerberos proof')
    meta=native.validate_metadata(request['import_request']['rehearsal_request']['metadata'])
    if importer.verify_artifacts(request['import_request'],backup=backup,probe=probe,collect=collect,
            root=root,owner=owner)!=request['import_receipt']:raise ValueError('Changed retained import')
    # No commands here: the retained receipt binds the originally verified RPM
    # identity, while protected metadata binds the same executable bytes now.
    tools={path:dict(probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner),package=PACKAGE) for path in TOOLS}
    if tools['/usr/bin/klist']!=request['import_request']['rehearsal_request']['backup_request']['facts']['tools']['klist']:
        raise ValueError('Changed planned Kerberos executable')
    result=_receipt(request,tools,meta,backup)
    for name,value in (('request.json',request),('intent.json',_intent(request,tools,meta,backup)),('verified.json',result)):
        if backup._json(leaf/name,root=root,owner=owner)!=value:raise ValueError('Changed Kerberos evidence')
    return result


def prove_once(request,*,backup,importer,probe,native,collect,runner,root=Path('/'),owner=0,clock=None):
    if os.geteuid()!=owner or not root.is_absolute() or collect is None or runner is None:raise ValueError('Fixed root proof required')
    _request(request,backup=backup)
    clock=clock or (lambda:datetime.now(timezone.utc))
    meta=native.validate_metadata(request['import_request']['rehearsal_request']['metadata'])
    principal=meta['hostname'].upper()+'$@'+meta['realm'].upper()
    with importer._lock(root,owner,backup):
        def guard():
            return _current(request,backup=backup,importer=importer,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
        tools=guard();leaf=path_for(request,backup=backup,root=root)
        backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner)
        try:leaf.mkdir(mode=0o700)
        except FileExistsError:raise ValueError('Kerberos proof already attempted') from None
        try:
            backup._write(leaf/'request.json',backup.encoded(request))
            configuration=_config(meta)
            intent=_intent(request,tools,meta,backup)
            backup._write(leaf/'intent.json',backup.encoded(intent));importer._sync_all(leaf,root,backup)
            def artifact_guard():
                if (backup._json(leaf/'request.json',root=root,owner=owner)!=request
                        or backup._json(leaf/'intent.json',root=root,owner=owner)!=intent):raise ValueError('Changed proof intent')
            with tempfile.TemporaryDirectory(prefix='cache-',dir=leaf) as temporary:
                scratch=Path(temporary);config=scratch/'krb5.conf';cache='FILE:'+str(scratch/'ccache')
                backup._write(config,configuration.encode('ascii'))
                config_info=probe._file(scratch,'/krb5.conf',private=True,owner=owner)
                def configuration_guard():
                    if (probe._file(scratch,'/krb5.conf',private=True,owner=owner)!=config_info
                            or backup._read(config,config_info,root=scratch,owner=owner)!=configuration.encode('ascii')):
                        raise ValueError('Changed private Kerberos configuration')
                environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','TZ':'UTC',
                    'KRB5_CONFIG':str(config),'KRB5CCNAME':cache}
                if guard()!=tools:raise ValueError('Changed preauthentication state')
                artifact_guard()
                configuration_guard()
                _run(runner,['/usr/bin/kinit','-k','-t',str(root/'etc/krb5.keytab'),'-c',cache,'-l','5m','-F','-P',principal],environment)
                configuration_guard()
                _run(runner,['/usr/bin/klist','-s','-c',cache],environment)
                _ticket(_run(runner,['/usr/bin/klist','-c',cache],environment),cache,principal,meta['realm'].upper(),clock())
                configuration_guard()
                info=probe._file(scratch,'/ccache',private=True,owner=owner)
                if not info['present'] or info['size']==0:raise ValueError('Machine cache missing')
                if guard()!=tools:raise ValueError('Changed postauthentication state')
                artifact_guard()
                configuration_guard()
                _run(runner,['/usr/bin/kdestroy','-c',cache],environment)
                configuration_guard()
                if (scratch/'ccache').exists() or (scratch/'ccache').is_symlink():raise ValueError('Machine cache not destroyed')
            if guard()!=tools:raise ValueError('Changed final authentication state')
            artifact_guard()
            result=_receipt(request,tools,meta,backup)
            backup._write(leaf/'verified.json',backup.encoded(result));backup._sync(leaf)
            return verify(request,backup=backup,importer=importer,probe=probe,native=native,collect=collect,runner=runner,root=root,owner=owner)
        except Exception:
            try:
                backup._write(leaf/'failed.json',backup.encoded({'schema_version':1,'error_code':'recovery_kerberos_failed'}));backup._sync(leaf)
            except Exception:pass
            raise ValueError('Machine Kerberos proof failed; replay and diagnostics are prohibited') from None
