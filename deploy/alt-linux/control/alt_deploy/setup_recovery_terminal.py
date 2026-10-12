"""Single normal-policy handoff. Renewal is deliberately UNKNOWN, never retried."""
from __future__ import annotations
import copy, json, os, re, stat, tempfile, time
from pathlib import Path

STOP=['/usr/bin/systemctl','stop','sssd.service','--job-mode=fail']
START=['/usr/bin/systemctl','start','sssd.service','--job-mode=ignore-requirements']
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}
DEPENDENCIES={'/usr/libexec/sssd/sssd_be','/usr/lib64/sssd/libsss_ad.so','/usr/sbin/adcli','/usr/bin/nsupdate','/usr/libexec/sssd/sssd_pac',
    '/usr/lib64/samba/sbin/smbd','/usr/lib64/samba/sbin/nmbd'}
DAEMON_LINKS={path:target for name in ('smbd','nmbd') for path,target in (
    ('/usr/sbin/'+name,'/etc/alternatives/links/|usr|sbin|'+name),
    ('/etc/alternatives/links/|usr|sbin|'+name,'/usr/lib64/samba/sbin/'+name))}
FIELDS={'schema_version','user_request','user_receipt','baseline','effects_sha256','source_sha256','approval_sha256','identity_sha256','terminal_units','runtime_dependencies','environment_files','credential_cache','daemon_links'}

def _same(left,right):
    def encoded(value):return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False)
    return encoded(left)==encoded(right)

def _request(request):
    if (not isinstance(request,dict) or set(request)!=FIELDS or type(request['schema_version']) is not int or request['schema_version']!=1
        or any(not isinstance(request[k],str) or not re.fullmatch('[0-9a-f]{64}',request[k]) for k in FIELDS if k.endswith('_sha256'))
        or not isinstance(request['baseline'],dict) or set(request['baseline'])!={'schema_version','original_sha256','tools_sha256','configured_values','defaults_verified','running_policy_verified','trust_verified'}
        or type(request['baseline']['schema_version']) is not int or request['baseline']['schema_version']!=1
        or any(not isinstance(request['baseline'][k],str) or not re.fullmatch('[0-9a-f]{64}',request['baseline'][k]) for k in ('original_sha256','tools_sha256'))
        or not isinstance(request['baseline']['configured_values'],dict)
        or any(request['baseline'][k] is not False for k in ('defaults_verified','running_policy_verified','trust_verified'))
        or not isinstance(request['terminal_units'],dict) or set(request['terminal_units'])!={'smb.service','nmb.service'}
        or not isinstance(request['runtime_dependencies'],dict) or not DEPENDENCIES<=set(request['runtime_dependencies']) or len(request['runtime_dependencies'])>16
        or not isinstance(request['environment_files'],dict) or set(request['environment_files'])!={'/etc/sysconfig/sssd','/etc/sysconfig/samba'}
        or not isinstance(request['credential_cache'],dict) or set(request['credential_cache'])!={'present'} or request['credential_cache']['present'] is not False
        or not isinstance(request['daemon_links'],dict) or set(request['daemon_links'])!=set(DAEMON_LINKS)):
        raise ValueError('Invalid fixed terminal request')

def path_for(request,*,backup,root=Path('/')):
    result=request['user_request']['startup_request']['policy_request']['kerberos_request']['import_request']['directory_result']
    return root/'var/lib/alt-deploy-recovery'/('terminal-'+backup.digest({k:result[k] for k in ('failed_run_id','computer_guid')}))

def _observation(request,*,original,baseline,policy,backup,probe,native,kerberos,importer,collect,runner,root,owner,restored):
    startup=request['user_request']['startup_request']
    bound=dict(schema_version=1,policy_request=startup['policy_request'],policy_receipt=startup['policy_receipt'],source_sha256=request['source_sha256'])
    receipt=original._observe(bound,policy=policy,backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,collect=collect,runner=runner,root=root,owner=owner,restored=restored)
    meta=bound['policy_request']['kerberos_request']['import_request']['rehearsal_request']['metadata']
    if not _same(baseline.projection(receipt,original=original,policy=policy,native=native,meta=meta),request['baseline']):
        raise ValueError('Original policy differs from pre-reservation baseline')
    return receipt

def _history(request,*,user,checker,start,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root,owner):
    user.verify(request['user_request'],request['user_receipt'],checker=checker,start=start,backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,policy=policy,services=services,graph=graph,collect=collect,runner=runner,root=root,owner=owner)

def _files(request,*,start,backup,probe,kerberos,importer,policy,services,root,owner):
    startup=request['user_request']['startup_request']
    result=start._protected(startup,backup=backup,probe=probe,kerberos=kerberos,importer=importer,policy=policy,services=services,root=root,owner=owner)
    pair=backup.digest({k:startup['policy_request']['kerberos_request']['import_request']['directory_result'][k] for k in ('failed_run_id','computer_guid')})
    for prefix in ('sssd-start-','native-testjoin-','user-check-'):
        leaf=root/'var/lib/alt-deploy-recovery'/(prefix+pair);backup._ancestry(leaf,root,owner);backup._directory(leaf,owner)
        names=sorted(p.name for p in leaf.iterdir())
        if len(names)>8 or any(not re.fullmatch('[a-z0-9_.-]{1,128}',n) for n in names):raise ValueError('Changed retained terminal history')
        result[str(leaf.relative_to(root))]={n:probe._file(leaf,'/'+n,private=True,owner=owner) for n in names}
    for path,metadata in request['runtime_dependencies'].items():
        if (not isinstance(path,str) or not re.fullmatch(r'/usr/(?:lib64|libexec|bin|sbin)/[A-Za-z0-9_./-]{1,160}',path) or '..' in path.split('/')):raise ValueError('Invalid fixed effect dependency')
        current=probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)
        if not _same(current,{k:v for k,v in metadata.items() if k not in ('package','origin')}):raise ValueError('Changed reviewed effect dependency')
        result[path]=current
    for path,metadata in request['environment_files'].items():
        current=probe._file(root,path,owner=owner)
        if backup.encoded(current)!=backup.encoded(metadata):raise ValueError('Changed reviewed service environment file')
        result[path]=current
    result['fixed_daemon_links']=_links(request['daemon_links'],backup=backup,root=root,owner=owner)
    return result

def _links(approved,*,backup,root,owner):
    """Observe only the four reviewed ALT alternatives; never follow links."""
    result={}
    for absolute,target in DAEMON_LINKS.items():
        record=approved[absolute]
        if (not isinstance(record,dict) or set(record)!={'uid','gid','mode','size','target'}
            or any(type(record[k]) is not int for k in ('uid','gid','mode','size')) or record['target']!=target):raise ValueError('Invalid approved daemon link')
        path=root/absolute.lstrip('/');backup._ancestry(path,root,owner)
        before=path.lstat()
        if not stat.S_ISLNK(before.st_mode) or before.st_uid!=owner or before.st_gid!=owner or before.st_nlink!=1:raise ValueError('Unsafe fixed daemon link')
        observed=os.readlink(path)
        after=path.lstat()
        if observed!=target or backup._signature(before)!=backup._signature(after) or after.st_nlink!=1:raise ValueError('Changed fixed daemon link')
        current=dict(uid=before.st_uid,gid=before.st_gid,mode=stat.S_IMODE(before.st_mode),size=before.st_size,target=observed)
        if not _same(current,record):raise ValueError('Changed reviewed daemon alias metadata')
        backup._ancestry(path,root,owner);result[absolute]=current
    return result

def _no_sssd(root):
    for index,path in enumerate((root/'proc').iterdir()):
        if index>=16384:raise ValueError('Unbounded process observation')
        if not path.name.isdigit():continue
        try:
            with (path/'comm').open('rb') as stream:raw=stream.read(65)
        except FileNotFoundError:continue
        name=raw.decode('ascii',errors='strict').strip()
        if name=='sssd' or name.startswith('sssd_'):raise ValueError('SSSD process remains after stop')

def _cache(*,root,owner,backup,absent):
    """Metadata only: approved mutable Samba cache is never an auth proof."""
    path=root/'run/samba/krb5cc_samba'
    backup._ancestry(path,root,owner)
    for parent in (root/'run',root/'run/samba'):
        try:info=parent.lstat()
        except FileNotFoundError:continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_gid!=owner or stat.S_IMODE(info.st_mode)&0o022:raise ValueError('Unsafe cache ancestry')
    try:before=path.lstat()
    except FileNotFoundError:return
    if absent:raise ValueError('Credential cache must be absent before normal service actions')
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_gid!=owner or before.st_nlink!=1
        or stat.S_IMODE(before.st_mode)&0o077):raise ValueError('Unsafe mutable service credential cache')
    after=path.lstat()
    if backup._signature(before)!=backup._signature(after) or after.st_nlink!=1:raise ValueError('Unstable mutable service credential cache')
    backup._ancestry(path,root,owner)

def _approved_restore(unit,current,approved):
    expected=copy.deepcopy(approved)
    if (not isinstance(expected,dict) or expected.get('properties',{}).get('Id')!=unit
        or current['properties']['NRestarts']!='0'):raise ValueError('Unreviewed restoration unit')
    for field in ('ActiveState','SubState','MainPID','InvocationID'):
        expected['properties'][field]=current['properties'][field]
    if not _same(current,expected):raise ValueError('Changed approved restoration behavior')

def _unit(unit,*,graph,runner,probe,root,owner,deadline):
    return graph._unit(unit,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)

def _state(request,expected,sssd,*,start,graph,services,backup,probe,collect,runner,root,owner,deadline):
    start._jobs(runner)
    paths=graph._run(runner,['/usr/bin/systemctl','show','--all','--no-pager','--property=UnitPath'],deadline)
    if paths.strip()!='UnitPath='+' '.join(graph.UNIT_PATHS):raise ValueError('Changed manager lookup')
    if not _same(_unit('sssd.service',graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline),sssd):raise ValueError('Changed exact SSSD invocation/unit')
    for unit in ('smb.service','nmb.service'):
        value=_unit(unit,graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
        _approved_restore(unit,value,request['terminal_units'][unit])
    current=services.snapshot(backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
    if not _same(current,expected):raise ValueError('Changed authentication service state')
    start._jobs(runner)
    return current

def _command(command,runner):
    rc,out,_=runner(command,environment=dict(ENVIRONMENT),input_text='',timeout=30)
    if type(rc) is not int or rc or out!='':raise ValueError('Fixed terminal service action failed')

def _trust(request,leaf,*,checker,native,kerberos,backup,probe,runner,root,owner):
    startup=request['user_request']['startup_request'];imported=startup['policy_request']['kerberos_request']['import_receipt']
    meta=startup['policy_request']['kerberos_request']['import_request']['rehearsal_request']['metadata']
    tools=checker._tools(startup,backup=backup,probe=probe,runner=runner,root=root,owner=owner)
    with tempfile.TemporaryDirectory(prefix='ordinary-trust-',dir=leaf) as directory:
        work=Path(directory);work.chmod(0o700)
        for name in ('private','state','cache','lock','pid','logs','ncalrpc','winbind'):(work/name).mkdir(mode=0o700)
        raw=backup._read(root/'var/lib/samba/private/secrets.tdb',imported['files']['/var/lib/samba/private/secrets.tdb'],root=root,owner=owner)
        backup._write(work/'private/secrets.tdb',raw);del raw
        files={'smb.conf':checker.sandbox_config(meta,native=native),'krb5.conf':kerberos._config(meta),
            'nsswitch.conf':'hosts: files dns\npasswd: files\ngroup: files\n','hosts':'127.0.0.1 localhost\n'+meta['dc_address']+' '+meta['dc_hostname']+'\n',
            'resolv.conf':'nameserver '+meta['dc_address']+'\noptions timeout:2 attempts:1\n'}
        for name,value in files.items():backup._write(work/name,value.encode())
        pinned={name:(probe._file(work,'/'+name,private=True,owner=owner),backup._signature((work/name).lstat())) for name in (*files,'private/secrets.tdb')}
        checker._scratch(work,pinned,backup=backup,root=root,owner=owner,preinvoke=True)
        rc,out,_=runner(checker.sandbox_command(work,meta,native=native,owner=owner),environment=dict(ENVIRONMENT),input_text='',timeout=30)
        if type(rc) is not int or rc or out!='Join is OK\n':raise ValueError('Ordinary native trust UNKNOWN')
        checker._scratch(work,pinned,backup=backup,root=root,owner=owner,preinvoke=False)
    if checker._tools(startup,backup=backup,probe=probe,runner=runner,root=root,owner=owner)!=tools:raise ValueError('Changed ordinary trust tools')
    return backup.digest(tools)

def _normal_unit(current,suppressed):
    expected=copy.deepcopy(suppressed);p=current['properties'];old=suppressed['properties']
    if (not re.fullmatch('[0-9a-f]{32}',p['InvocationID']) or int(p['InvocationID'],16)==0 or p['InvocationID']==old['InvocationID']
        or not re.fullmatch('[1-9][0-9]{0,9}',p['MainPID']) or int(p['MainPID'])>2147483647):raise ValueError('No fresh ordinary invocation')
    expected['properties'].update(ActiveState='active',SubState='running',MainPID=p['MainPID'],InvocationID=p['InvocationID'])
    if not _same(current,expected):raise ValueError('Ordinary invocation source/restart drift')
    return current

def verify(request,result,**args):
    with args['importer']._lock(args.get('root',Path('/')),args.get('owner',0),args['backup']):
        return _verify(request,result,**args)

def _verify(request,result,*,user,checker,start,original,baseline,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    """Fresh ordinary acceptance; retained suppressed checks are historical only."""
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root terminal required')
    _request(request);bound=copy.deepcopy(request);approved=copy.deepcopy(result)
    startup=bound['user_request']['startup_request'];deadline=time.monotonic()+min(120,start._remaining(startup));runner=start._runner(runner,deadline,startup)
    leaf=path_for(bound,backup=backup,root=root);backup._ancestry(leaf,root,owner);backup._directory(leaf,owner)
    if (leaf/'failed.json').exists() or (leaf/'failed.json').is_symlink():raise ValueError('Failed terminal excluded')
    intent=backup._json(leaf/'intent.json',root=root,owner=owner)
    if (not isinstance(intent,dict) or set(intent)!={'schema_version','request_sha256','observation_sha256','protected_sha256','suppressed_sha256'}
        or type(intent['schema_version']) is not int or intent['schema_version']!=1 or intent['request_sha256']!=backup.digest(bound)
        or any(not isinstance(intent[k],str) or not re.fullmatch('[0-9a-f]{64}',intent[k]) for k in intent if k.endswith('_sha256'))):raise ValueError('Invalid retained terminal intent')
    names={'request.json','intent.json','normal-start-intent.json','verified.json'}
    for unit in ('smb.service','nmb.service'):
        if startup['service_request']['services']['units'][unit]['properties']['ActiveState']=='active':
            names.update({'starting-'+unit+'.json','started-'+unit+'.json'})
    def retained_files():
        if {p.name for p in leaf.iterdir()}!=names:raise ValueError('Incomplete or failed terminal records')
        return {name:probe._file(leaf,'/'+name,private=True,owner=owner) for name in sorted(names)}
    retained=retained_files()
    _cache(root=root,owner=owner,backup=backup,absent=False)
    if (not _same(backup._json(leaf/'request.json',root=root,owner=owner),bound) or not _same(backup._json(leaf/'verified.json',root=root,owner=owner),approved)
        or approved.get('request_sha256')!=backup.digest(bound) or approved.get('status')!='normal_policy_handoff_succeeded'
        or approved.get('credential_continuity')!='unchanged' or approved.get('n_restarts')!=0 or type(approved.get('n_restarts')) is not int
        or approved.get('identity_sha256')!=bound['identity_sha256']):raise ValueError('Invalid retained terminal')
    args=dict(start=start,backup=backup,probe=probe,kerberos=kerberos,importer=importer,policy=policy,services=services,root=root,owner=owner)
    protected=_files(bound,**args)
    observations=dict(original=original,baseline=baseline,policy=policy,backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,collect=collect,runner=runner,root=root,owner=owner)
    _observation(bound,**observations,restored=True)
    current=_unit('sssd.service',graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
    suppressed=copy.deepcopy(startup['sssd_unit']);old=bound['user_request']['startup_receipt'];suppressed['properties'].update(ActiveState='active',SubState='running',MainPID=str(old['main_pid']),InvocationID=old['invocation_id'])
    _normal_unit(current,suppressed)
    if (backup.digest(current)!=approved['unit_sha256'] or int(current['properties']['MainPID'])!=approved['main_pid'] or current['properties']['InvocationID']!=approved['invocation_id']):raise ValueError('Ordinary invocation changed')
    start._jobs(runner);state=services.snapshot(backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner)
    if backup.digest(state)!=approved['services_sha256']:raise ValueError('Ordinary services changed')
    trust=_trust(bound,leaf,checker=checker,native=native,kerberos=kerberos,backup=backup,probe=probe,runner=runner,root=root,owner=owner)
    tools=user._tool(bound['user_request'],probe=probe,runner=runner,root=root,owner=owner);local=user._local(bound['user_request'],backup=backup,probe=probe,root=root,owner=owner)
    rc,out,_=runner([user.TOOL,'-s','sss','passwd',bound['user_request']['employee']['upn']],environment=dict(ENVIRONMENT),input_text='',timeout=15)
    if type(rc) is not int or rc:raise ValueError('Fresh ordinary NSS UNKNOWN')
    ids=user._lookup(out,bound['user_request']['employee']);del out
    if (ids!={k:approved[k] for k in ('uid','gid')} or trust!=approved['trust_tools_sha256'] or backup.digest(tools)!=approved['nss_tools_sha256'] or backup.digest(local)!=approved['local_passwd_sha256']):raise ValueError('Fresh ordinary proof changed')
    _observation(bound,**observations,restored=True)
    _state(bound,state,current,start=start,graph=graph,services=services,backup=backup,probe=probe,collect=collect,runner=runner,root=root,owner=owner,deadline=deadline)
    # Finish native RPM callbacks before the final protected local rereads.
    if not _same(user._tool(bound['user_request'],probe=probe,runner=runner,root=root,owner=owner),tools):raise ValueError('Final ordinary NSS tools drift')
    if (not _same(user._local(bound['user_request'],backup=backup,probe=probe,root=root,owner=owner),local)
        or not _same(_files(bound,**args),protected) or not _same(request,bound) or not _same(result,approved)
        or not _same(backup._json(leaf/'request.json',root=root,owner=owner),bound)
        or not _same(backup._json(leaf/'intent.json',root=root,owner=owner),intent)
        or not _same(backup._json(leaf/'verified.json',root=root,owner=owner),approved)
        or not _same(retained_files(),retained)
        or (leaf/'failed.json').exists() or (leaf/'failed.json').is_symlink()):raise ValueError('Final ordinary proof drift')
    _cache(root=root,owner=owner,backup=backup,absent=False)
    return approved

def handoff_once(request,*,user,checker,start,original,baseline,backup,probe,native,kerberos,importer,policy,services,graph,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root terminal required')
    _request(request);bound=copy.deepcopy(request);startup=bound['user_request']['startup_request']
    deadline=time.monotonic()+min(120,start._remaining(startup));runner=start._runner(runner,deadline,startup)
    allargs=dict(user=user,checker=checker,start=start,backup=backup,probe=probe,native=native,kerberos=kerberos,importer=importer,policy=policy,services=services,graph=graph,collect=collect,runner=runner,root=root,owner=owner)
    obsargs={k:v for k,v in allargs.items() if k not in ('user','checker','start','services','graph')};obsargs.update(original=original,baseline=baseline)
    fileargs={k:v for k,v in allargs.items() if k in ('start','backup','probe','kerberos','importer','policy','services','root','owner')}
    stateargs={k:v for k,v in allargs.items() if k in ('start','graph','services','backup','probe','collect','runner','root','owner')};stateargs['deadline']=deadline
    with importer._lock(root,owner,backup):
        leaf=path_for(bound,backup=backup,root=root);backup._ancestry(leaf,root,owner);backup._directory(leaf.parent,owner)
        if leaf.exists() or leaf.is_symlink():raise ValueError('Terminal already attempted')
        _cache(root=root,owner=owner,backup=backup,absent=True)
        _history(bound,**allargs);observation=_observation(bound,**obsargs,restored=False)
        protected=_files(bound,**fileargs);suppressed=_unit('sssd.service',graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
        expected=start._stopped(startup,services);expected['units']['sssd.service']['properties'].update(ActiveState='active',SubState='running',MainPID=suppressed['properties']['MainPID'])
        _state(bound,expected,suppressed,**stateargs)
        leaf.mkdir(mode=0o700);phase='intent';cache_mutable=False
        try:
            intent=dict(schema_version=1,request_sha256=backup.digest(bound),observation_sha256=backup.digest(observation),protected_sha256=backup.digest(protected),suppressed_sha256=backup.digest(suppressed))
            backup._write(leaf/'request.json',backup.encoded(bound));backup._write(leaf/'intent.json',backup.encoded(intent));importer._sync_all(leaf,root,backup)
            def records():
                if not _same(backup._json(leaf/'request.json',root=root,owner=owner),bound) or not _same(backup._json(leaf/'intent.json',root=root,owner=owner),intent) or not _same(request,bound):raise ValueError('Changed permanent terminal intent')
            def guard():
                records()
                if not _same(_files(bound,**fileargs),protected):raise ValueError('Terminal protected dependency drift')
                _cache(root=root,owner=owner,backup=backup,absent=not cache_mutable)
            _history(bound,**allargs)
            if _observation(bound,**obsargs,restored=False)!=observation:raise ValueError('Changed original baseline')
            guard();_state(bound,expected,suppressed,**stateargs);guard()
            _command(list(STOP),runner);phase='sssd_stop_entered'
            stopped=copy.deepcopy(suppressed);current=_unit('sssd.service',graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
            stopped['properties'].update(ActiveState='inactive',SubState='dead',MainPID='0',InvocationID=current['properties']['InvocationID'])
            expected=services._stopped(expected,'sssd.service');_state(bound,expected,stopped,**stateargs);guard()
            _no_sssd(root)
            if collect()['incompatible_processes']:raise ValueError('Authentication process remains after stop')
            _state(bound,expected,stopped,**stateargs);guard();_no_sssd(root)
            phase='stopped_verified'
            snippet=root/policy.SNIPPET.lstrip('/');metadata=protected[policy.SNIPPET]
            if probe._file(root,policy.SNIPPET,private=True,owner=owner)!=metadata:raise ValueError('Changed owned snippet')
            backup._read(snippet,metadata,root=root,owner=owner);guard();snippet.unlink();backup._sync(snippet.parent);phase='snippet_removed'
            protected[policy.SNIPPET]=probe._file(root,policy.SNIPPET,private=True,owner=owner)
            if protected[policy.SNIPPET].get('present') is not False:raise ValueError('Suppression snippet remains')
            if _observation(bound,**obsargs,restored=True)!=observation:raise ValueError('Restored policy differs')
            for unit in ('smb.service','nmb.service'):
                if startup['service_request']['services']['units'][unit]['properties']['ActiveState']!='active':continue
                unit_before=_unit(unit,graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline)
                _approved_restore(unit,unit_before,bound['terminal_units'][unit])
                # Explicit reviewed fixed starts exclude new automatic dependency jobs.
                backup._write(leaf/('starting-'+unit+'.json'),backup.encoded(dict(unit=unit,before_sha256=backup.digest(unit_before))));importer._sync_all(leaf,root,backup)
                guard();_state(bound,expected,stopped,**stateargs);guard()
                cache_mutable=True
                _command(['/usr/bin/systemctl','start',unit,'--job-mode=ignore-requirements'],runner);phase=unit+'_start_entered'
                current=_unit(unit,graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline);target=copy.deepcopy(unit_before)
                p=current['properties']
                if (p['ActiveState'],p['SubState'],p['ControlPID'],p['NRestarts'])!=('active','running','0','0') or not re.fullmatch('[1-9][0-9]{0,9}',p['MainPID']) or not re.fullmatch('[0-9a-f]{32}',p['InvocationID']) or int(p['InvocationID'],16)==0 or p['InvocationID']==unit_before['properties']['InvocationID']:raise ValueError('Unsafe restored service start')
                target['properties'].update(ActiveState='active',SubState='running',MainPID=p['MainPID'],InvocationID=p['InvocationID'])
                if not _same(current,target):raise ValueError('Restored service unit drift')
                expected['units'][unit]['properties'].update(ActiveState='active',SubState='running',MainPID=p['MainPID']);_state(bound,expected,stopped,**stateargs);guard()
                backup._write(leaf/('started-'+unit+'.json'),backup.encoded(dict(unit=unit,state_sha256=backup.digest(current))));backup._sync(leaf)
            backup._write(leaf/'normal-start-intent.json',backup.encoded(dict(request_sha256=backup.digest(bound),stopped_sha256=backup.digest(stopped))));importer._sync_all(leaf,root,backup)
            guard();_state(bound,expected,stopped,**stateargs);guard();cache_mutable=True;_command(list(START),runner);phase='normal_start_entered'
            normal=_normal_unit(_unit('sssd.service',graph=graph,runner=runner,probe=probe,root=root,owner=owner,deadline=deadline),suppressed)
            expected['units']['sssd.service']['properties'].update(ActiveState='active',SubState='running',MainPID=normal['properties']['MainPID'])
            _state(bound,expected,normal,**stateargs);guard();time.sleep(0.2);_state(bound,expected,normal,**stateargs);guard();phase='normal_running'
            # Historical suppressed verifiers are never used beyond the stop.
            _observation(bound,**obsargs,restored=True)
            trust=_trust(bound,leaf,checker=checker,native=native,kerberos=kerberos,backup=backup,probe=probe,runner=runner,root=root,owner=owner)
            tools=user._tool(bound['user_request'],probe=probe,runner=runner,root=root,owner=owner);local=user._local(bound['user_request'],backup=backup,probe=probe,root=root,owner=owner)
            rc,out,_=runner([user.TOOL,'-s','sss','passwd',bound['user_request']['employee']['upn']],environment=dict(ENVIRONMENT),input_text='',timeout=15)
            if type(rc) is not int or rc:raise ValueError('Ordinary NSS UNKNOWN')
            ids=user._lookup(out,bound['user_request']['employee']);del out
            if (user._tool(bound['user_request'],probe=probe,runner=runner,root=root,owner=owner)!=tools or user._local(bound['user_request'],backup=backup,probe=probe,root=root,owner=owner)!=local):raise ValueError('Ordinary NSS drift')
            _observation(bound,**obsargs,restored=True);_state(bound,expected,normal,**stateargs);guard()
            original_result=startup['policy_request']['kerberos_request']['import_request']['directory_result']
            result=dict({k:original_result[k] for k in ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno')},schema_version=1,status='normal_policy_handoff_succeeded',request_sha256=backup.digest(bound),identity_sha256=bound['identity_sha256'],
                invocation_id=normal['properties']['InvocationID'],main_pid=int(normal['properties']['MainPID']),n_restarts=0,services_sha256=backup.digest(expected),unit_sha256=backup.digest(normal),trust_tools_sha256=trust,nss_tools_sha256=backup.digest(tools),local_passwd_sha256=backup.digest(local),employee=bound['user_request']['employee'],**ids,
                native_trust_verified=True,native_peer_pinning_verified=False,credential_continuity='unchanged',temporary_policy_retained=False,login_verified=False,online_user_authentication_verified=False)
            backup._write(leaf/'verified.json',backup.encoded(result));backup._sync(leaf);return result
        except Exception:
            try:backup._write(leaf/'failed.json',backup.encoded(dict(schema_version=1,status='UNKNOWN',last_verified_phase=phase,error_code='recovery_terminal_failed')));backup._sync(leaf)
            except Exception:pass
            raise ValueError('Terminal UNKNOWN; permanent exclusion; no retry or automatic rollback') from None
