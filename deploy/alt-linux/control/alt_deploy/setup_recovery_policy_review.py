"""Fixed supplementary raw configuration and protected PAC reads; no authority."""
from __future__ import annotations
import configparser,json,os,shlex,stat
from pathlib import Path

KEYS={'domain':('ad_gpo_access_control','ad_gpo_ignore_unreadable','chpass_provider','debug_level','default_shell','fallback_homedir','krb5_renew_interval'),
      'sssd':('config_file_version','services','user')}
PAC='/usr/libexec/sssd/sssd_pac'
PACKAGE='sssd-pac 2.9.8-alt3'
CACHE='/run/samba/krb5cc_samba'
CACHE_ENV='FILE:'+CACHE
DAEMON_LINKS={path:target for name in ('smbd','nmbd') for path,target in (
    ('/usr/sbin/'+name,'/etc/alternatives/links/|usr|sbin|'+name),
    ('/etc/alternatives/links/|usr|sbin|'+name,'/usr/lib64/samba/sbin/'+name))}

def daemon_links(*,root,owner):
    records={}
    for absolute,target in DAEMON_LINKS.items():
        path=root/absolute.lstrip('/')
        for parent in (path.parent,*path.parent.parents):
            info=parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_gid!=owner or info.st_mode&0o022:raise ValueError('Unsafe daemon link ancestry')
            if parent==root:break
        before=path.lstat()
        if not stat.S_ISLNK(before.st_mode) or before.st_uid!=owner or before.st_gid!=owner or before.st_nlink!=1:raise ValueError('Unsafe daemon alias')
        observed=os.readlink(path);after=path.lstat()
        signature=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink)
        if observed!=target or signature(before)!=signature(after):raise ValueError('Changed daemon alias')
        records[absolute]=dict(uid=before.st_uid,gid=before.st_gid,mode=stat.S_IMODE(before.st_mode),size=before.st_size,target=observed)
    return records


def absent_cache(*,root,owner):
    path=root/CACHE.lstrip('/')
    for parent in (path.parent,*path.parent.parents):
        try:info=parent.lstat()
        except FileNotFoundError:continue
        import stat
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:raise ValueError('Unsafe service cache ancestry')
        if parent==root:break
    try:path.lstat()
    except FileNotFoundError:return {'present':False}
    raise ValueError('Existing service credential cache requires separate review')

def environment(*,probe,root,owner):
    paths=('/etc/sysconfig/sssd','/etc/sysconfig/samba')
    records={path:probe._file(root,path,maximum=65536,owner=owner) for path in paths}
    if records[paths[0]]!={'present':False}:raise ValueError('Unreviewed SSSD environment override')
    values={}
    if records[paths[1]].get('present'):
        path=root/paths[1].lstrip('/')
        with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:raw=stream.read(65537)
        import hashlib
        if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=records[paths[1]]['sha256']:raise ValueError('Changed environment file')
        try:
            for line in raw.decode('ascii').splitlines():
                line=line.strip()
                if not line or line.startswith('#'):continue
                key,sep,rhs=line.partition('=')
                if not sep or key not in ('SAMBAOPTIONS','SMBDOPTIONS','NMBDOPTIONS','WINBINDOPTIONS','KRB5CCNAME') or key in values:raise ValueError
                parts=shlex.split(rhs,comments=True,posix=True)
                if key=='KRB5CCNAME':
                    if parts!=[CACHE_ENV]:raise ValueError
                    values[key]=CACHE_ENV
                else:
                    if parts not in ([],['']):raise ValueError
                    values[key]=''
        except (ValueError,UnicodeError):raise ValueError('Unreviewed Samba environment options') from None
    return records,values

def observe(request,*,probe,runner,root=Path('/'),owner=0):
    if (os.geteuid()!=owner or not isinstance(request,dict) or set(request)!={'schema_version','configuration','domain'}
            or type(request['schema_version']) is not int or request['schema_version']!=1 or request['domain']!='SOSNADMIN.LOCAL'):
        raise ValueError('Invalid fixed supplementary request')
    path='/etc/sssd/sssd.conf';before=probe._file(root,path,private=True,owner=owner)
    if not before.get('present') or json.dumps(before,sort_keys=True)!=json.dumps(request['configuration'],sort_keys=True,allow_nan=False):
        raise ValueError('Changed protected configuration')
    with os.fdopen(os.open(root/path.lstrip('/'),os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        opened=os.fstat(stream.fileno());raw=stream.read(probe.MAX_AUTH_BYTES+1)
        if len(raw)>probe.MAX_AUTH_BYTES or probe._signature(opened)!=probe._signature(os.fstat(stream.fileno())):
            raise ValueError('Changed configuration read')
    import hashlib
    if hashlib.sha256(raw).hexdigest()!=before['sha256']:raise ValueError('Changed configuration bytes')
    parser=configparser.ConfigParser(interpolation=None,strict=True)
    try:parser.read_string(raw.decode('utf-8'))
    except (configparser.Error,UnicodeError):raise ValueError('Invalid supplementary configuration') from None
    if parser.defaults():raise ValueError('Unreviewed inherited configuration')
    values={}
    for label,keys in KEYS.items():
        section='sssd' if label=='sssd' else 'domain/'+request['domain']
        if not parser.has_section(section):raise ValueError('Missing fixed section')
        values[label]={}
        for key in keys:
            present=parser.has_option(section,key);value=parser.get(section,key,raw=True) if present else ''
            if len(value)>1024 or any(not 32<=ord(char)<=126 for char in value):raise ValueError('Unbounded configured value')
            values[label][key]=dict(present=present,value=value)
    env_files,env_values=environment(probe=probe,root=root,owner=owner)
    cache=absent_cache(root=root,owner=owner)
    pac=probe._file(root,PAC,maximum=probe.MAX_TOOL_BYTES,owner=owner)
    if not pac.get('present') or pac['gid']!=owner or pac['mode']!=0o755:raise ValueError('Unsafe PAC helper')
    rc,out,_=runner(['/usr/bin/rpm','-qf',PAC,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n'],
                    environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=15)
    if type(rc) is not int or rc or out!=PACKAGE+'\n':raise ValueError('Unreviewed PAC package')
    links=daemon_links(root=root,owner=owner)
    daemons={}
    for helper in ('/usr/lib64/samba/sbin/smbd','/usr/lib64/samba/sbin/nmbd'):
        info=probe._file(root,helper,maximum=probe.MAX_TOOL_BYTES,owner=owner)
        if not info.get('present') or info['gid']!=owner or info['mode']!=0o755:raise ValueError('Unsafe restoration daemon')
        rc,out,_=runner(['/usr/bin/rpm','-qf',helper,'--qf','%{NAME} %{VERSION}-%{RELEASE}\n'],environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=15)
        if type(rc) is not int or rc or out!='samba 4.21.9-alt4.p11.1\n':raise ValueError('Unreviewed restoration daemon package')
        daemons[helper]=dict(info,package='samba 4.21.9-alt4.p11.1')
    if any(probe._file(root,helper,maximum=probe.MAX_TOOL_BYTES,owner=owner)!={key:value for key,value in info.items() if key!='package'} for helper,info in daemons.items()):raise ValueError('Changed restoration daemon')
    if (probe._file(root,path,private=True,owner=owner)!=before
            or probe._file(root,PAC,maximum=probe.MAX_TOOL_BYTES,owner=owner)!=pac
            or environment(probe=probe,root=root,owner=owner)!=(env_files,env_values)
            or absent_cache(root=root,owner=owner)!=cache
            or daemon_links(root=root,owner=owner)!=links):raise ValueError('Changed supplementary inputs')
    return dict(schema_version=1,semantics='raw_configured_values_only',configuration=before,values=values,
                pac=dict(pac,package=PACKAGE),daemon_dependencies=daemons,daemon_links=links,environment_files=env_files,environment_values=env_values,credential_cache=cache,execution_authorized=False)
