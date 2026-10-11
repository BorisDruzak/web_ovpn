"""Bound root-private service quiescence before any recovery password write.

Read-only snapshot plus a fixed stop-only worker. Never start/restart a service,
change a unit, reset failed state, write AD/authentication files or claim trust.
Controller approval, fresh sealed-plan/result binding and restoration remain
requirements for the future execution coordinator and strict transport.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import re

UNITS=('sssd.service','winbind.service','smb.service','nmb.service')
EDGES=('RequiredBy','RequisiteOf','BoundBy','ConsistsOf','PropagatesStopTo','TriggeredBy','UpheldBy','OnFailure','OnSuccess')
OUTBOUND=('Requires','Wants','Requisite','BindsTo','Upholds')
PROPERTIES=('Id','LoadState','ActiveState','SubState','MainPID','ControlPID','KillMode',
            'FragmentPath','DropInPaths','NeedDaemonReload','Job','SuccessAction','FailureAction','StopWhenUnneeded',*EDGES,*OUTBOUND)
DEPENDENCY_PROPERTIES=('Id','LoadState','StopWhenUnneeded','FragmentPath','DropInPaths','NeedDaemonReload','Job')
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


def _run(runner,command,timeout=15):
    rc,out,_=runner(command,environment=dict(ENVIRONMENT),timeout=timeout)
    if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>16384 or '\x00' in out:
        raise ValueError('Fixed service operation failed')
    return out


def _show(runner,unit,properties):
    output=_run(runner,['/usr/bin/systemctl','show',unit,'--no-pager','--property='+','.join(properties)])
    values={}
    for line in output.splitlines():
        key,sep,value=line.partition('=')
        if not sep or key in values or key not in properties:raise ValueError('Invalid fixed service state')
        values[key]=value
    if set(values)!=set(properties):raise ValueError('Incomplete fixed service state')
    return values


def _dependency(unit,*,runner,probe,root,owner):
    values=_show(runner,unit,DEPENDENCY_PROPERTIES)
    if (values['Id']!=unit or values['LoadState']!='loaded' or values['StopWhenUnneeded']!='no'
            or values['NeedDaemonReload']!='no' or values['Job']):
        raise ValueError('Unsafe stop dependency')
    paths=[];fragment=values['FragmentPath']
    if fragment:
        if fragment!='/usr/lib/systemd/system/'+unit:raise ValueError('Unsupported dependency source')
        paths.append(fragment)
    elif unit not in ('system.slice','-.slice'):
        raise ValueError('Unsupported implicit dependency')
    drops=values['DropInPaths'].split()
    if len(drops)>8 or len(set(drops))!=len(drops):raise ValueError('Unsupported dependency overrides')
    for path in drops:
        if not re.fullmatch(r'/(?:usr/lib|etc)/systemd/system/'+re.escape(unit)+r'\.d/[A-Za-z0-9_.-]{1,128}\.conf',path):
            raise ValueError('Unsupported dependency overrides')
    paths.extend(drops);sources={path:probe._file(root,path,owner=owner) for path in paths}
    if any(value.get('present') is not True for value in sources.values()):raise ValueError('Missing dependency source')
    values['DropInPaths']=' '.join(sorted(drops))
    return {'properties':values,'sources':sources}


def snapshot(*,backup,probe,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or collect is None or runner is None or not root.is_absolute():
        raise ValueError('Fixed root service snapshot required')
    before=collect()
    tool=probe._file(root,'/usr/bin/systemctl',maximum=probe.MAX_TOOL_BYTES,owner=owner)
    package=_run(runner,['/usr/bin/rpm','-qf','/usr/bin/systemctl','--qf','%{NAME} %{VERSION}-%{RELEASE}\n']).strip()
    if tool.get('present') is not True or package!='systemd 258.9-alt1':
        raise ValueError('Unreviewed service manager')
    units={};dependencies=set()
    for unit in UNITS:
        values=_show(runner,unit,PROPERTIES)
        if (set(values)!=set(PROPERTIES) or values['Id']!=unit or values['LoadState']!='loaded'
                or values['FragmentPath']!='/usr/lib/systemd/system/'+unit
                or values['DropInPaths'] or values['NeedDaemonReload']!='no' or values['Job']
                or any(values[name] for name in EDGES) or values['ControlPID']!='0'
                or values['KillMode']!='control-group' or not re.fullmatch(r'0|[1-9][0-9]{0,9}',values['MainPID'])
                or values['SuccessAction']!='none' or values['FailureAction']!='none' or values['StopWhenUnneeded']!='no'
                or int(values['MainPID'])>2147483647
                or (values['ActiveState'],values['SubState']) not in (('active','running'),('inactive','dead'))
                or (values['MainPID']=='0')!=(values['ActiveState']=='inactive')):
            raise ValueError('Unsafe or unsupported service state')
        for field in OUTBOUND:
            names=values[field].split()
            if len(names)>64 or len(set(names))!=len(names) or any(not re.fullmatch(r'[A-Za-z0-9_.@:-]{1,128}\.(?:service|target|slice|socket|mount|path|timer)',name) for name in names):
                raise ValueError('Unsupported service dependency names')
            dependencies.update(names);values[field]=' '.join(sorted(names))
        if len(dependencies)>64:raise ValueError('Service dependency graph exceeds bound')
        metadata=probe._file(root,'/usr/lib/systemd/system/'+unit,owner=owner)
        if metadata.get('present') is not True:raise ValueError('Missing fixed service unit')
        units[unit]={'properties':values,'unit_file':metadata}
    related={unit:_dependency(unit,runner=runner,probe=probe,root=root,owner=owner)
             for unit in sorted(dependencies-set(UNITS))}
    if collect()!=before or probe._file(root,'/usr/bin/systemctl',maximum=probe.MAX_TOOL_BYTES,owner=owner)!=tool:
        raise ValueError('Workstation changed during service snapshot')
    return {'schema_version':1,'machine_uuid':before['uuid'],'hostname':before['hostname'],
            'systemctl':tool,'systemd_package':package,'units':units,'dependencies':related}


def _request(request,*,backup):
    fields={'schema_version','backup_request','backup_receipt','services','services_sha256','source_sha256'}
    if (not isinstance(request,dict) or set(request)!=fields
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or any(not isinstance(request[key],str) or not re.fullmatch('[0-9a-f]{64}',request[key])
                for key in ('services_sha256','source_sha256'))):
        raise ValueError('Invalid bound service request')
    backup._request(request['backup_request']);bound=request['backup_request'];document=request['services']
    if (not isinstance(document,dict) or set(document)!={'schema_version','machine_uuid','hostname','systemctl','systemd_package','units','dependencies'}
            or type(document['schema_version']) is not int or document['schema_version']!=1
            or document['machine_uuid']!=bound['machine_uuid'] or document['hostname']!=bound['hostname']
            or not isinstance(document['units'],dict) or set(document['units'])!=set(UNITS)
            or backup.digest(document)!=request['services_sha256']):
        raise ValueError('Invalid service identity')
    for unit in UNITS:
        value=document['units'][unit]
        if (not isinstance(value,dict) or set(value)!={'properties','unit_file'}
                or not isinstance(value['properties'],dict) or set(value['properties'])!=set(PROPERTIES)
                or value['properties']['ActiveState'] not in ('active','inactive')):
            raise ValueError('Invalid service schema')


def path_for(request,*,backup,root=Path('/')):
    _request(request,backup=backup)
    pair={key:request['backup_request'][key] for key in ('failed_run_id','computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('services-'+backup.digest(pair))


def _stopped(document,unit):
    result=copy.deepcopy(document)
    result['units'][unit]['properties'].update(ActiveState='inactive',SubState='dead',MainPID='0')
    return result


def _guard(request,expected,*,backup,probe,collect,runner,root,owner):
    if (collect()!=request['backup_request']['facts']
            or backup.verify(request['backup_request'],root=root,owner=owner)!=request['backup_receipt']
            or snapshot(backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)!=expected):
        raise ValueError('Changed service snapshot or backup')


def _active(request):
    return [unit for unit in UNITS if request['services']['units'][unit]['properties']['ActiveState']=='active']


def _receipt(request,*,backup):
    result={key:request['backup_request'][key] for key in ('failed_run_id','computer_guid','machine_uuid','claim_sha256')}
    return dict(result,schema_version=1,status='services_quiesced',request_sha256=backup.digest(request),
        services_sha256=request['services_sha256'],active_services=_active(request))


def verify(request,*,backup,probe,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root service verification required')
    leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner)
    backup._directory(leaf.parent,owner);backup._directory(leaf,owner)
    expected=copy.deepcopy(request['services']);names={'request.json','verified.json'}
    names.update(prefix+unit+'.json' for unit in _active(request) for prefix in ('stopping-','stopped-'))
    if {p.name for p in leaf.iterdir()}!=names:raise ValueError('Incomplete or failed service quiescence')
    if backup._json(leaf/'request.json',root=root,owner=owner)!=request:raise ValueError('Changed service request')
    for unit in _active(request):
        before=expected;expected=_stopped(expected,unit)
        intent={'schema_version':1,'request_sha256':backup.digest(request),'unit':unit,'before_sha256':backup.digest(before)}
        result={'schema_version':1,'unit':unit,'after_sha256':backup.digest(expected)}
        for name,document in (('stopping-'+unit+'.json',intent),('stopped-'+unit+'.json',result)):
            names.add(name)
            if backup._json(leaf/name,root=root,owner=owner)!=document:raise ValueError('Changed service progress')
    receipt=_receipt(request,backup=backup)
    if {p.name for p in leaf.iterdir()}!=names or backup._json(leaf/'verified.json',root=root,owner=owner)!=receipt:
        raise ValueError('Incomplete or failed service quiescence')
    _guard(request,expected,backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
    backup._sync(leaf);return receipt


def quiesce_once(request,*,backup,probe,importer,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root service worker required')
    _request(request,backup=backup)
    with importer._lock(root,owner,backup):
        expected=copy.deepcopy(request['services'])
        _guard(request,expected,backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
        leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner)
        try:leaf.mkdir(mode=0o700)
        except FileExistsError:raise ValueError('Service quiescence already attempted') from None
        try:
            backup._write(leaf/'request.json',backup.encoded(request));importer._sync_all(leaf,root,backup)
            for unit in _active(request):
                _guard(request,expected,backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
                intent={'schema_version':1,'request_sha256':backup.digest(request),'unit':unit,'before_sha256':backup.digest(expected)}
                backup._write(leaf/('stopping-'+unit+'.json'),backup.encoded(intent));importer._sync_all(leaf,root,backup)
                _guard(request,expected,backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
                _run(runner,['/usr/bin/systemctl','stop',unit,'--job-mode=fail'],timeout=30)
                expected=_stopped(expected,unit)
                _guard(request,expected,backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
                backup._write(leaf/('stopped-'+unit+'.json'),backup.encoded({'schema_version':1,'unit':unit,'after_sha256':backup.digest(expected)}));backup._sync(leaf)
            receipt=_receipt(request,backup=backup)
            backup._write(leaf/'verified.json',backup.encoded(receipt));backup._sync(leaf)
            return verify(request,backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
        except Exception:
            try:
                backup._write(leaf/'failed.json',backup.encoded({'schema_version':1,'error_code':'recovery_service_quiescence_failed'}));backup._sync(leaf)
            except Exception:pass
            raise ValueError('Recovery service quiescence failed; automatic restart and replay are prohibited') from None
