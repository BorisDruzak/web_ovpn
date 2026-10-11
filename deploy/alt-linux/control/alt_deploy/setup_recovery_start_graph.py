"""Read-only, conservative systemd 258.9 startup-effect inventory.

This is not a transaction simulator, execution approval or trust proof. No
active-state pruning is attempted. Event-triggered effects remain separately
labelled; the future execution gate must review sources and consequences.
"""
from __future__ import annotations

from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import time

SEEDS=('sssd.service','smb.service','nmb.service')
START=('Requires','Wants','BindsTo','Upholds')
STOP=('RequiredBy','RequisiteOf','BoundBy','ConsistsOf','PropagatesStopTo')
EVENTS=('OnFailure','OnSuccess','Triggers','TriggeredBy','UpheldBy')
GRAPH=(*START,'Requisite','Conflicts','ConflictedBy',*STOP,*EVENTS)
OPAQUE=('ExecStart','ExecStartPre','ExecStartPost','ExecCondition','ExecStop','ExecStopPost',
        'ExecReload','Environment','EnvironmentFiles','PassEnvironment','UnsetEnvironment')
LIFECYCLE=('Restart','RestartMode','RestartUSec','RestartForceExitStatus','RestartPreventExitStatus',
           'NRestarts','InvocationID','MainPID','ControlPID','Type','WatchdogUSec',
           'TimeoutStartUSec','TimeoutStopUSec','StartLimitIntervalUSec','StartLimitBurst',
           'RefuseManualStart','RefuseManualStop')
PROPERTIES=('Id','Names','Following','LoadState','ActiveState','SubState','FragmentPath','DropInPaths',
            'NeedDaemonReload','Job','SuccessAction','FailureAction','StartLimitAction','StopWhenUnneeded',*GRAPH,*OPAQUE,*LIFECYCLE)
MAX_UNITS=512
MAX_PAIRS=2048
MAX_EDGES=16384
MAX_SECONDS=30
MAX_INVENTORY_BYTES=4194304
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}
UNIT_PATHS=('/etc/systemd/system.control','/run/systemd/system.control','/run/systemd/transient',
    '/run/systemd/generator.early','/etc/systemd/system','/etc/systemd/system.attached',
    '/run/systemd/system','/run/systemd/system.attached','/run/systemd/generator',
    '/usr/local/lib/systemd/system','/usr/lib/systemd/system','/run/systemd/generator.late')
_NAME=re.compile(r'(?:[A-Za-z0-9_.@:-]|\\x[0-9a-fA-F]{2})+\.(?:service|target|slice|socket|mount|automount|path|timer|device|swap|scope)')


def _names(value):
    if not isinstance(value,str) or len(value.encode())>65536 or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('Invalid native unit list')
    result=[];position=0;decoder=json.JSONDecoder()
    while position<len(value):
        if value[position]==' ':position+=1;continue
        if value[position]=='"':
            try:name,end=decoder.raw_decode(value,position)
            except ValueError:raise ValueError('Unknown native unit quoting') from None
        else:
            end=value.find(' ',position)
            if end<0:end=len(value)
            name=value[position:end]
        if (not isinstance(name,str) or not _NAME.fullmatch(name) or len(name.encode())>255
                or (name.startswith('-') and name not in ('-.slice','-.mount')) or name in result
                or (end<len(value) and value[end]!=' ') or len(result)>=512):
            raise ValueError('Unknown or ambiguous native unit name')
        result.append(name);position=end
    return result


def _run(runner,command,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise ValueError('Startup graph capture deadline exceeded')
    rc,out,_=runner(command,environment=dict(ENVIRONMENT),timeout=min(10,remaining))
    if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>65536 or '\x00' in out:
        raise ValueError('Fixed startup graph read failed')
    if time.monotonic()>deadline:raise ValueError('Startup graph capture deadline exceeded')
    return out


def _unit(name,*,runner,probe,root,owner,deadline):
    values={};commands={key:[] for key in OPAQUE if key.startswith('Exec')}
    output=_run(runner,['/usr/bin/systemctl','show','--all','--no-pager','--property='+','.join(PROPERTIES),'--',name],deadline)
    for line in output.splitlines():
        key,sep,value=line.partition('=')
        if not sep or key not in PROPERTIES:raise ValueError('Invalid native startup properties')
        if key in commands:
            if value:commands[key].append(value)
            if len(commands[key])>32:raise ValueError('Startup execution array exceeds bound')
            values[key]='';continue
        if key in values:raise ValueError('Invalid native startup properties')
        values[key]=value
    # Native systemctl omits empty execution/environment arrays even with --all.
    for key in (*OPAQUE,*LIFECYCLE):values.setdefault(key,'')
    if (set(values)!=set(PROPERTIES) or values['LoadState'] not in ('loaded','not-found')
            or values['NeedDaemonReload']!='no' or values['Job']
            or values['ActiveState'] not in ('active','inactive')
            or _names(values['Id'])!=[values['Id']] or name not in _names(values['Names'])):
        raise ValueError('Incomplete or unstable startup unit')
    if (name.endswith('.service') and values['LoadState']=='loaded'
            and (values['Restart'] not in ('no','on-success','on-failure','on-abnormal','on-watchdog','on-abort','always')
                 or values['RestartMode'] not in ('normal','direct','debug'))):
        raise ValueError('Unknown native restart policy')
    following=_names(values['Following'])
    if following and (len(following)!=1 or not name.endswith('.device') or not following[0].endswith('.device')):
        raise ValueError('Unsupported startup following relationship')
    values['Following']=following
    for key in GRAPH:values[key]=sorted(_names(values[key]))
    values['Names']=sorted(_names(values['Names']))
    opaque={key:hashlib.sha256(json.dumps(commands[key] if key in commands else values[key],
            ensure_ascii=True,separators=(',',':')).encode()).hexdigest() for key in OPAQUE}
    for key in OPAQUE:values.pop(key)
    if values['LoadState']=='not-found':
        if (values['ActiveState']!='inactive' or values['SubState']!='dead' or values['FragmentPath']
                or values['DropInPaths'] or following):
            raise ValueError('Unstable missing startup endpoint')
        candidates=[name]
        if '@' in name:candidates.append(name.split('@',1)[0]+'@.'+name.rsplit('.',1)[1])
        absence={directory+'/'+candidate:probe._file(root,directory+'/'+candidate,owner=owner)
                 for directory in UNIT_PATHS for candidate in candidates}
        if any(value.get('present') is not False for value in absence.values()):
            raise ValueError('Missing startup endpoint has an unreviewed source')
        values['DropInPaths']=[]
        return {'properties':values,'sources':{},'opaque_sha256':opaque,
                'source_resolution':'unresolved','lookup_absence':absence}
    sources={}
    paths=([values['FragmentPath']] if values['FragmentPath'] else [])+values['DropInPaths'].split()
    if len(paths)>17 or len(set(paths))!=len(paths):raise ValueError('Unsupported startup unit sources')
    for path in paths:
        if (not any(path.startswith(directory+'/') for directory in UNIT_PATHS)
                or not re.fullmatch(r'/[A-Za-z0-9_.@:/\\-]{1,512}',path) or '..' in path.split('/')):
            raise ValueError('Unsupported startup source path')
        metadata=probe._file(root,path,owner=owner)
        if metadata.get('present') is not True:raise ValueError('Missing startup unit source')
        if path.startswith('/usr/lib/systemd/system/'):
            package=_run(runner,['/usr/bin/rpm','-qf',path,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n'],deadline).strip()
            if not re.fullmatch(r'[A-Za-z0-9+_.-]{1,80} [A-Za-z0-9+_.:~%-]{1,100}',package):
                raise ValueError('Unknown startup source package')
            metadata=dict(metadata,origin='packaged',package=package)
        else:metadata=dict(metadata,origin='local_or_generated_requires_review',package=None)
        sources[path]=metadata
    if not paths and not name.endswith(('.device','.slice','.scope')):
        raise ValueError('Unknown implicit startup unit')
    values['DropInPaths']=sorted(values['DropInPaths'].split())
    return {'properties':values,'sources':sources,'opaque_sha256':opaque,
            'source_resolution':'metadata_captured_requires_semantic_review','lookup_absence':{}}


def _families(**data):
    output=_run(data['runner'],['/usr/bin/systemctl','list-units','--all','--type=device','--no-pager','--output=json'],data['deadline'])
    try:rows=json.loads(output)
    except ValueError:raise ValueError('Invalid native device enumeration') from None
    if not isinstance(rows,list) or len(rows)>MAX_UNITS:raise ValueError('Device family enumeration exceeds bound')
    devices={}
    for row in rows:
        if (not isinstance(row,dict) or set(row)!={'unit','load','active','sub','description'}
                or not isinstance(row['unit'],str) or _names(row['unit'])!=[row['unit']]
                or not row['unit'].endswith('.device') or row['unit'] in devices):
            raise ValueError('Unknown native device family entry')
        value=_unit(row['unit'],**data);properties=value['properties']
        if (properties['Id']!=row['unit'] or any(properties[key]!=row[field]
                for key,field in (('LoadState','load'),('ActiveState','active'),('SubState','sub')))):
            raise ValueError('Changed native device enumeration')
        devices[row['unit']]=value
    families={};leaders={}
    for name in devices:
        leader=name;visited=set()
        while devices[leader]['properties']['Following']:
            if leader in visited:raise ValueError('Cyclic device following family')
            visited.add(leader);leader=devices[leader]['properties']['Following'][0]
            if leader not in devices:raise ValueError('Uninspected device following family')
        leaders[name]=leader;families.setdefault(leader,[]).append(name)
    return devices,{name:sorted(families[leader]) for name,leader in leaders.items()}


def _capture(*,runner,probe,root,owner,deadline):
    data=dict(runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
    paths=_run(runner,['/usr/bin/systemctl','show','--all','--no-pager','--property=UnitPath'],deadline)
    if paths.strip()!='UnitPath='+' '.join(UNIT_PATHS):raise ValueError('Unreviewed native unit lookup paths')
    devices,families=_families(**data)
    queue=deque((unit,'start') for unit in SEEDS);queue.append(('sssd.service','restart'))
    pairs=set();units={};aliases={};edges=set()
    while queue:
        requested,job=queue.popleft()
        if requested not in aliases:
            if len(units)>=MAX_UNITS:raise ValueError('Startup graph exceeds unit bound')
            value=devices[requested] if requested in devices else _unit(requested,**data)
            name=value['properties']['Id'];aliases[requested]=name
            if name in units and units[name]!=value:raise ValueError('Changed startup alias identity')
            units[name]=value
        name=aliases[requested]
        if (name,job) in pairs:continue
        if len(pairs)>=MAX_PAIRS:raise ValueError('Startup graph exceeds job bound')
        pairs.add((name,job));values=units[name]['properties']
        if (name.endswith('.service') and values['LoadState']=='loaded' and job!='restart'
                and (values['Restart']!='no' or values['RestartForceExitStatus'])):
            edges.add((name,job,name,'restart','Restart:automatic:event'));queue.append((name,'restart'))
            if len(edges)>MAX_EDGES:raise ValueError('Startup graph exceeds edge bound')
        def add(field,label,reason=None):
            for destination in values[field]:
                edges.add((name,job,destination,label,reason or field))
                if len(edges)>MAX_EDGES:raise ValueError('Startup graph exceeds edge bound')
                queue.append((destination,label))
        add('Following',job,'Following:device')
        if name.endswith('.device'):
            if name not in families:raise ValueError('Uninspected device following family')
            for sibling in families[name]:
                if sibling!=name:
                    edges.add((name,job,sibling,job,'Following:family'));queue.append((sibling,job))
                    if len(edges)>MAX_EDGES:raise ValueError('Startup graph exceeds edge bound')
        if job in ('start','restart','try-restart'):
            for field in START:add(field,'start')
            add('Requisite','verify-active')
            for field in ('Conflicts','ConflictedBy'):add(field,'stop')
            add('Upholds','start','Upholds:event')
        if job in ('stop','restart','try-restart'):
            for field in STOP:add(field,'stop' if job=='stop' else 'try-restart')
        # Events are conservative possible effects, not immediate transaction jobs.
        if job!='verify-active':
            for field in EVENTS:add(field,'start',field+':event')
    unresolved=[{'unit':name,'reason':'unit_not_found'} for name in sorted(units)
                if units[name]['properties']['LoadState']=='not-found']
    return {'units':units,'aliases':aliases,'device_inventory':devices,'unresolved':unresolved,
        'unit_lookup_paths':list(UNIT_PATHS),
        'possibilities':[{'unit':name,'job':job} for name,job in sorted(pairs)],
        'edges':[dict(zip(('source','source_job','destination','job','reason'),edge))
                 for edge in sorted({(s,j,aliases[d],k,r) for s,j,d,k,r in edges})]}


def capture(*,probe,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root startup inventory required')
    deadline=time.monotonic()+MAX_SECONDS;facts=collect()
    tool=probe._file(root,'/usr/bin/systemctl',maximum=probe.MAX_TOOL_BYTES,owner=owner)
    package=_run(runner,['/usr/bin/rpm','-qf','/usr/bin/systemctl','--qf','%{NAME} %{VERSION}-%{RELEASE}\n'],deadline).strip()
    if tool.get('present') is not True or package!='systemd 258.9-alt1':raise ValueError('Unreviewed startup manager')
    data=dict(runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
    first=_capture(**data);second=_capture(**data)
    if first!=second or collect()!=facts:
        raise ValueError('Startup inventory changed during capture')
    for value in (*second['units'].values(),*second['device_inventory'].values()):
        for path,metadata in value['sources'].items():
            expected={key:field for key,field in metadata.items() if key not in ('origin','package')}
            if probe._file(root,path,owner=owner)!=expected:raise ValueError('Startup source changed after capture')
        for path,metadata in value['lookup_absence'].items():
            if probe._file(root,path,owner=owner)!=metadata:raise ValueError('Unresolved startup source appeared')
    if (probe._file(root,'/usr/bin/systemctl',maximum=probe.MAX_TOOL_BYTES,owner=owner)!=tool
            or time.monotonic()>deadline):raise ValueError('Startup inventory changed during capture')
    result=dict(first,schema_version=1,status='startup_inventory_only',execution_authorized=False,
        semantics='conservative_effect_inventory_without_pruning',
        review_requirements=['hook_and_environment_effects','manager_actions','trigger_specific_behavior',
            'conservative_try_restart_and_graceful_propagation','local_and_generated_source_origins','unresolved_destinations'],
        facts=facts,systemctl=tool,systemd_package=package)
    if (len(json.dumps(result,ensure_ascii=True,separators=(',',':')).encode())>MAX_INVENTORY_BYTES
            or time.monotonic()>deadline):raise ValueError('Startup inventory exceeds encoded or time bound')
    return result
