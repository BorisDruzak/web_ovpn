"""One fixed SSSD start under retained recovery guards; never a trust proof.

No CLI route or approval authority. The future controller transport must verify
the actual exact approval, AD identity/history/TTL and reviewed effects ledger.
Local service observations are bounded checks, not an exclusive manager lease.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import time

MAX_SECONDS=120
START=['/usr/bin/systemctl','start','sssd.service','--job-mode=ignore-requirements']
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


def _request(request,*,backup,policy,kerberos,services):
    fields={'schema_version','policy_request','policy_receipt','service_request','service_receipt','sssd_unit',
        'source_sha256','effects_ledger_sha256','plan_id','plan_sha256','approval_sha256',
        'plan_created_at','plan_expires_at'}
    if (not isinstance(request,dict) or set(request)!=fields or type(request['schema_version']) is not int
            or request['schema_version']!=1 or not isinstance(request['plan_id'],str)
            or request['plan_id']!='recovery-'+str(request['plan_sha256'])
            or any(not isinstance(request[key],str) or not re.fullmatch('[0-9a-f]{64}',request[key]) for key in
                ('source_sha256','effects_ledger_sha256','plan_sha256','approval_sha256'))):
        raise ValueError('Invalid fixed startup request')
    _times(request)
    policy._request(request['policy_request'],backup=backup,kerberos=kerberos)
    services._request(request['service_request'],backup=backup)
    bound=request['policy_request']['kerberos_request']['import_request']['rehearsal_request']
    if (request['service_request']['backup_request']!=bound['backup_request']
            or request['service_request']['backup_receipt']!=bound['backup_receipt']):
        raise ValueError('Startup service and import histories differ')
    validate_unit(request['sssd_unit'])


def validate_unit(unit):
    """Shared unchanged stopped-unit policy for pre-reservation approval."""
    if (not isinstance(unit,dict) or set(unit)!={'properties','sources','opaque_sha256','source_resolution','lookup_absence'}
            or not isinstance(unit['properties'],dict)):raise ValueError('Invalid fixed startup unit')
    values=unit['properties']
    required=dict(Id='sssd.service',Names=['sssd.service'],LoadState='loaded',ActiveState='inactive',SubState='dead',
        FragmentPath='/usr/lib/systemd/system/sssd.service',DropInPaths=[],NeedDaemonReload='no',Job='',
        MainPID='0',ControlPID='0',Restart='on-abnormal',RestartMode='normal',Type='notify',
        SuccessAction='none',FailureAction='none',StartLimitAction='none',StopWhenUnneeded='no',
        RefuseManualStart='no',RefuseManualStop='no',NRestarts='0')
    if (any(values.get(key)!=value for key,value in required.items())
            or not isinstance(values.get('NRestarts'),str) or not re.fullmatch('0|[1-9][0-9]{0,9}',values['NRestarts'])
            or int(values['NRestarts'])>2147483647
            or not isinstance(values.get('InvocationID'),str)
            or (values['InvocationID'] and not re.fullmatch('[0-9a-f]{32}',values['InvocationID']))
            or set(unit['sources'])!={'/usr/lib/systemd/system/sssd.service'} or unit['lookup_absence']):
        raise ValueError('Unsupported fixed startup policy')


def path_for(request,*,backup,root=Path('/')):
    original=request['policy_request']['kerberos_request']['import_request']['directory_result']
    pair={key:original[key] for key in ('failed_run_id','computer_guid')}
    return root/'var/lib/alt-deploy-recovery'/('sssd-start-'+backup.digest(pair))


def _times(request):
    try:
        if any(not isinstance(request[key],str) for key in ('plan_created_at','plan_expires_at')):raise ValueError
        created=datetime.fromisoformat(request['plan_created_at']);expires=datetime.fromisoformat(request['plan_expires_at'])
        if created.tzinfo is None or expires.tzinfo is None or expires-created!=timedelta(minutes=30):raise ValueError
        return created,expires
    except (ValueError,TypeError,KeyError):raise ValueError('Invalid startup plan lifetime') from None


def _remaining(request):
    created,expires=_times(request);now=datetime.now(timezone.utc)
    if now<created or now>=expires:raise ValueError('Startup plan is not currently valid')
    return (expires-now).total_seconds()


def _runner(runner,deadline,request=None):
    def bounded(command,**options):
        remaining=deadline-time.monotonic()
        if request is not None:remaining=min(remaining,_remaining(request))
        if remaining<=0:raise ValueError('Fixed startup deadline exceeded')
        options['timeout']=min(options.get('timeout',15),remaining)
        result=runner(command,**options)
        if request is not None:_remaining(request)
        if time.monotonic()>deadline:raise ValueError('Fixed startup deadline exceeded')
        return result
    return bounded


def _jobs(runner):
    rc,out,_=runner(['/usr/bin/systemctl','list-jobs','--no-legend','--no-pager'],environment=dict(ENVIRONMENT),timeout=15)
    if type(rc) is not int or rc!=0 or out!='':raise ValueError('Pending or unknown manager jobs')


def _stopped(request,services):
    expected=copy.deepcopy(request['service_request']['services'])
    for unit in services._active(request['service_request']):expected=services._stopped(expected,unit)
    if any(value['properties']['ActiveState']!='inactive' for value in expected['units'].values()):
        raise ValueError('Authentication services were not quiesced')
    return expected


def _protected(request,*,backup,probe,kerberos,importer,policy,services,root,owner):
    """Fixed local files only; no command or alternate request path is accepted."""
    paths=dict(probe.AUTH_FILES)
    paths.update({path:False for path in (*probe.TOOLS.values(),*kerberos.TOOLS,*policy.TOOLS,'/usr/bin/systemctl')})
    paths[policy.SNIPPET]=True
    paths['/etc/sysconfig/sssd']=True
    paths.update({'/usr/lib/systemd/system/'+unit:False for unit in services.UNITS})
    result={path:probe._file(root,path,private=private,maximum=probe.MAX_TOOL_BYTES if path.startswith('/usr/') else probe.MAX_AUTH_BYTES,
        owner=owner) for path,private in paths.items()}
    if result['/etc/sysconfig/sssd'].get('present') is not False:
        raise ValueError('Unreviewed SSSD environment file')
    bound=request['policy_request']['kerberos_request']
    leaves=(importer.path_for(bound['import_request'],backup=backup,root=root),
        kerberos.path_for(bound,backup=backup,root=root),policy.path_for(request['policy_request'],backup=backup,root=root),
        services.path_for(request['service_request'],backup=backup,root=root))
    for leaf in leaves:
        backup._ancestry(leaf,root,owner);backup._directory(leaf,owner)
        names=sorted(path.name for path in leaf.iterdir())
        if len(names)>32 or any(not re.fullmatch('[a-z0-9_.-]{1,128}',name) for name in names):
            raise ValueError('Unbounded retained startup dependencies')
        result[str(leaf.relative_to(root))]={name:probe._file(leaf,'/'+name,private=True,owner=owner) for name in names}
    return result


def _end(request,guard,*,backup,probe,kerberos,importer,policy,services,root,owner):
    files,tools=guard
    if _protected(request,backup=backup,probe=probe,kerberos=kerberos,importer=importer,policy=policy,
            services=services,root=root,owner=owner)!=files:raise ValueError('Changed protected startup dependencies')
    policy._unchanged_tools(tools,probe=probe,root=root,owner=owner)
    if services.verify_artifacts(request['service_request'],backup=backup,root=root,owner=owner)!=request['service_receipt']:
        raise ValueError('Changed retained quiescence after native observation')


def _proof(request,*,backup,probe,native,kerberos,importer,policy,services,collect,runner,root,owner,pre_start):
    protected_args=dict(backup=backup,probe=probe,kerberos=kerberos,importer=importer,policy=policy,services=services,root=root,owner=owner)
    guard=(_protected(request,**protected_args),policy._tools(probe=probe,runner=runner,root=root,owner=owner))
    if backup.digest(guard[1])!=request['policy_receipt']['tools_sha256']:raise ValueError('Changed startup policy tools')
    function=policy.verify if pre_start else policy.verify_artifacts
    if function(request['policy_request'],backup=backup,probe=probe,native=native,kerberos=kerberos,
            importer=importer,collect=collect,runner=runner,root=root,owner=owner)!=request['policy_receipt']:
        raise ValueError('Changed prepared policy')
    if services.verify_artifacts(request['service_request'],backup=backup,root=root,owner=owner)!=request['service_receipt']:
        raise ValueError('Changed retained service quiescence')
    if collect()['incompatible_processes']:raise ValueError('Incompatible recovery process')
    _end(request,guard,**protected_args)
    return guard


def _state(request,*,backup,probe,services,graph,collect,runner,root,owner,deadline,started=None):
    _jobs(runner)
    paths=graph._run(runner,['/usr/bin/systemctl','show','--all','--no-pager','--property=UnitPath'],deadline)
    if paths.strip()!='UnitPath='+' '.join(graph.UNIT_PATHS):raise ValueError('Changed manager unit lookup paths')
    current=graph._unit('sssd.service',runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
    expected=copy.deepcopy(request['sssd_unit']);stopped=_stopped(request,services)
    if started is not None:
        values=current['properties'];invocation=values['InvocationID'];pid=values['MainPID']
        if (not re.fullmatch('[0-9a-f]{32}',invocation) or int(invocation,16)==0
                or invocation==request['sssd_unit']['properties']['InvocationID']
                or not re.fullmatch('[1-9][0-9]{0,9}',pid) or int(pid)>2147483647):
            raise ValueError('No fresh running SSSD invocation')
        if started and (invocation!=started['invocation_id'] or int(pid)!=started['main_pid']):
            raise ValueError('SSSD invocation changed')
        expected['properties'].update(ActiveState='active',SubState='running',MainPID=pid,InvocationID=invocation)
        stopped['units']['sssd.service']['properties'].update(ActiveState='active',SubState='running',MainPID=pid)
    if current!=expected:raise ValueError('Changed SSSD unit, restart count or invocation state')
    if services.snapshot(backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)!=stopped:
        raise ValueError('Changed authentication service state')
    _jobs(runner)
    return current


def _intent(request,backup):
    return dict(schema_version=1,request_sha256=backup.digest(request),policy_receipt_sha256=backup.digest(request['policy_receipt']),
        services_receipt_sha256=backup.digest(request['service_receipt']),sssd_unit_sha256=backup.digest(request['sssd_unit']))


def _receipt(request,state,backup):
    original=request['policy_request']['kerberos_request']['import_request']['directory_result']
    pair={key:original[key] for key in ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno')}
    return dict(pair,schema_version=1,status='sssd_started',trust_verified=False,request_sha256=backup.digest(request),
        invocation_id=state['properties']['InvocationID'],main_pid=int(state['properties']['MainPID']),
        n_restarts=int(state['properties']['NRestarts']),state_sha256=backup.digest(state),
        effects_ledger_sha256=request['effects_ledger_sha256'],approval_sha256=request['approval_sha256'])


def _records(request,receipt,*,backup,root,owner):
    leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner)
    backup._directory(leaf.parent,owner);backup._directory(leaf,owner)
    if {path.name for path in leaf.iterdir()}!={'request.json','start-intent.json','started.json'}:
        raise ValueError('Incomplete or failed SSSD start')
    for name,value in (('request.json',request),('start-intent.json',_intent(request,backup)),('started.json',receipt)):
        if backup.encoded(backup._json(leaf/name,root=root,owner=owner))!=backup.encoded(value):
            raise ValueError('Changed retained startup evidence')


def verify_started(request,receipt,*,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root startup verification required')
    _request(request,backup=backup,policy=policy,kerberos=kerberos,services=services)
    if (not isinstance(receipt,dict) or any(type(receipt.get(key)) is not int for key in
            ('schema_version','main_pid','n_restarts','kvno')) or receipt.get('trust_verified') is not False):
        raise ValueError('Invalid typed startup receipt')
    deadline=time.monotonic()+MAX_SECONDS;runner=_runner(runner,deadline)
    args=dict(backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,policy=policy,
        services=services,collect=collect,runner=runner,root=root,owner=owner)
    state_args={key:value for key,value in args.items() if key not in ('native','kerberos','importer','policy')}
    _records(request,receipt,backup=backup,root=root,owner=owner)
    guard=_proof(request,**args,pre_start=False)
    state=_state(request,**state_args,graph=graph,deadline=deadline,started=receipt)
    if _receipt(request,state,backup)!=receipt:raise ValueError('Unbound SSSD startup receipt')
    _end(request,guard,**{key:value for key,value in args.items() if key not in ('native','collect','runner')})
    _records(request,receipt,backup=backup,root=root,owner=owner)
    return receipt


def start_once(request,*,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root SSSD start required')
    _request(request,backup=backup,policy=policy,kerberos=kerberos,services=services)
    deadline=time.monotonic()+min(MAX_SECONDS,_remaining(request));runner=_runner(runner,deadline,request)
    args=dict(backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,policy=policy,
        services=services,collect=collect,runner=runner,root=root,owner=owner)
    state_args={key:value for key,value in args.items() if key not in ('native','kerberos','importer','policy')}
    with importer._lock(root,owner,backup):
        leaf=path_for(request,backup=backup,root=root);backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner)
        if leaf.exists() or leaf.is_symlink():raise ValueError('SSSD start already attempted')
        guard=_proof(request,**args,pre_start=True)
        _state(request,**state_args,graph=graph,deadline=deadline)
        _end(request,guard,**{key:value for key,value in args.items() if key not in ('native','collect','runner')})
        leaf.mkdir(mode=0o700)
        try:
            backup._write(leaf/'request.json',backup.encoded(request));backup._write(leaf/'start-intent.json',backup.encoded(_intent(request,backup)))
            importer._sync_all(leaf,root,backup)
            guard=_proof(request,**args,pre_start=True)
            _state(request,**state_args,graph=graph,deadline=deadline)
            _end(request,guard,**{key:value for key,value in args.items() if key not in ('native','collect','runner')})
            if (backup.encoded(backup._json(leaf/'request.json',root=root,owner=owner))!=backup.encoded(request)
                    or backup.encoded(backup._json(leaf/'start-intent.json',root=root,owner=owner))!=backup.encoded(_intent(request,backup))
                    or {path.name for path in leaf.iterdir()}!={'request.json','start-intent.json'}):
                raise ValueError('Changed immediate startup intent')
            rc,out,_=runner(list(START),environment=dict(ENVIRONMENT),timeout=30)
            if type(rc) is not int or rc!=0 or out!='':raise ValueError('Fixed SSSD start failed')
            state=_state(request,**state_args,graph=graph,deadline=deadline,started={})
            result=_receipt(request,state,backup)
            time.sleep(0.2)
            guard=_proof(request,**args,pre_start=False)
            if _state(request,**state_args,graph=graph,deadline=deadline,started=result)!=state:
                raise ValueError('Unstable SSSD startup invocation')
            _end(request,guard,**{key:value for key,value in args.items() if key not in ('native','collect','runner')})
            if (backup.encoded(backup._json(leaf/'request.json',root=root,owner=owner))!=backup.encoded(request)
                    or backup.encoded(backup._json(leaf/'start-intent.json',root=root,owner=owner))!=backup.encoded(_intent(request,backup))):
                raise ValueError('Changed startup intent during start')
            backup._write(leaf/'started.json',backup.encoded(result));backup._sync(leaf)
            return verify_started(request,result,**args,graph=graph)
        except Exception:
            try:backup._write(leaf/'failed.json',backup.encoded({'schema_version':1,'error_code':'recovery_sssd_start_failed'}));backup._sync(leaf)
            except Exception:pass
            raise ValueError('SSSD start did not verify; replay and automatic cleanup are prohibited') from None
