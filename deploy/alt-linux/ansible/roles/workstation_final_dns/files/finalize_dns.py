"""Bounded DNS-only finalization. No interface restart or identity operation."""
from __future__ import annotations

import configparser
import ctypes
from dataclasses import dataclass,field
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import tempfile
import time
import uuid

from alt_deploy.final_dns_policy import validate,CODES


class DnsError(Exception):pass


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(value).hexdigest()


def unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError
        value[key]=item
    return value


def run(args,*,input_text=None,timeout=15):
    try:
        p=subprocess.run(args,input=input_text,text=True,capture_output=True,timeout=timeout,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','KRB5_CONFIG':'/etc/krb5.conf'})
        if len(p.stdout.encode())>262144:raise ValueError
        return p.returncode,p.stdout
    except Exception:raise DnsError('final_dns_outcome_unverified') from None


def inside(root,path):
    relative=Path(path)
    if not relative.is_absolute() or '..' in relative.parts:raise DnsError('final_dns_ownership_unverified')
    result=root/relative.relative_to('/')
    current=result
    while current!=root:
        if current.is_symlink():raise DnsError('final_dns_ownership_unverified')
        current=current.parent
    return result


def file_identity(info):
    return tuple(getattr(info,name) for name in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink',
                                                 'st_size','st_mtime_ns','st_ctime_ns'))


def read(path,root,*,private=False,allow_hardlinks=False):
    """Keep all contents private; protect every ancestor and the read descriptor."""
    owner=0 if root==Path('/') else os.getuid()
    current=path.parent
    while current!=root:
        info=current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:
            raise DnsError('final_dns_ownership_unverified')
        current=current.parent
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_nlink<1 or not allow_hardlinks and info.st_nlink!=1
                or info.st_mode&0o022 or private and info.st_mode&0o077):
            raise DnsError('final_dns_ownership_unverified')
        value=os.read(fd,262145)
        if len(value)>262144 or file_identity(info)!=file_identity(os.fstat(fd)):
            raise DnsError('final_dns_configuration_changed')
        return value,info
    finally:os.close(fd)


def resolvers(data):
    result=[]
    for line in data.decode('utf-8').splitlines():
        parts=line.split('#',1)[0].split()
        if parts and parts[0]=='nameserver':
            if len(parts)!=2:raise DnsError('final_dns_backend_unverified')
            try:address=str(ipaddress.ip_address(parts[1]))
            except ValueError:raise DnsError('final_dns_backend_unverified') from None
            if address in result:raise DnsError('final_dns_backend_unverified')
            result.append(address)
    if not result:raise DnsError('final_dns_backend_unverified')
    return result


def shell_options(data):
    result={}
    for line in data.decode('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([A-Z][A-Z0-9_]*)=(?:"([^"\n]*)"|\x27([^\x27\n]*)\x27|([A-Za-z0-9_.:-]+))',line)
        if not match or match[1] in result:raise DnsError('final_dns_backend_unverified')
        result[match[1]]=next(v for v in match.groups()[1:] if v is not None)
    return result


def keyfile(data):
    cfg=configparser.ConfigParser(interpolation=None,strict=True)
    try:cfg.read_string(data.decode('utf-8'))
    except Exception:raise DnsError('final_dns_backend_unverified') from None
    return cfg


def attributes(path):
    values={key:os.getxattr(path,key,follow_symlinks=False) for key in os.listxattr(path,follow_symlinks=False)}
    if len(values)>64 or sum(len(k.encode())+len(v) for k,v in values.items())>65536:
        raise DnsError('final_dns_ownership_unverified')
    return values


def command(call,args):
    rc,text=call(args)
    if rc:raise DnsError('final_dns_backend_unverified')
    return text


def network_identity(call,interface):
    result={}
    for family in ('-4','-6'):
        routes=json.loads(command(call,['ip','-j',family,'route','show','dev',interface]))
        addresses=json.loads(command(call,['ip','-j',family,'address','show','dev',interface]))
        # Kernel lease clocks count down during a safe reapply. Identity is the
        # address/prefix, routing and interface, never the transient countdown.
        normalized=[]
        for entry in addresses:
            normalized.append({k:v for k,v in entry.items() if k in ('ifname','address','mtu','master')}|
                {'addr_info':[{k:v for k,v in a.items() if k not in ('valid_life_time','preferred_life_time')}
                              for a in entry.get('addr_info',[])]})
        result[family]={'routes':routes,'addresses':normalized}
    return digest(canonical(result))


@dataclass(frozen=True)
class Snapshot:
    public:dict
    path:Path=field(repr=False)
    content:bytes=field(repr=False)
    info:object=field(repr=False)
    files:dict=field(repr=False)
    attributes:dict=field(repr=False)
    resolver_source:Path|None=field(default=None,repr=False)
    persistent_exists:bool=True


def _observe(request,*,root=Path('/'),call=run,_owned_rollback=None):
    try:
        root=Path(root)
        if (not isinstance(request,dict) or set(request)!={'schema_version','machine_uuid','hostname','servers'}
                or type(request['schema_version']) is not int or request['schema_version']!=1
                or str(uuid.UUID(request['machine_uuid']))!=request['machine_uuid'] or not uuid.UUID(request['machine_uuid']).int
                or not re.fullmatch('[a-z][a-z0-9-]{0,62}',request['hostname'])):raise ValueError
        if validate(request['servers'])['servers']!=request['servers']:raise ValueError
        identity='/sys/devices/virtual/dmi/id/product_uuid' if root==Path('/') else '/sys/class/dmi/id/product_uuid'
        machine=read(inside(root,identity),root)[0].decode().strip().lower()
        boot=read(inside(root,'/proc/sys/kernel/random/boot_id'),root)[0].decode().strip()
        if (machine!=request['machine_uuid'] or command(call,['hostname','-s']).strip()!=request['hostname']
                or str(uuid.UUID(boot))!=boot):raise DnsError('final_dns_identity_unverified')
        routes=json.loads(command(call,['ip','-j','-4','route','show','default']))
        if not isinstance(routes,list) or len(routes)!=1:raise DnsError('final_dns_backend_unverified')
        interface=routes[0]['dev']
        if not isinstance(interface,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',interface):raise ValueError
        rc,active=call(['nmcli','-t','-e','no','-f','UUID,DEVICE','connection','show','--active'])
        connection=None;filename=None
        if rc==0:
            candidates=[line.split(':') for line in active.splitlines() if line.endswith(':'+interface)]
            if len(candidates)!=1 or len(candidates[0])!=2:raise DnsError('final_dns_backend_unverified')
            connection=candidates[0][0]
            if str(uuid.UUID(connection))!=connection:raise ValueError
            profiles=command(call,['nmcli','-t','-e','no','-f','UUID,FILENAME','connection','show'])
            matches=[line.partition(':')[2] for line in profiles.splitlines() if line.partition(':')[0]==connection]
            if len(matches)!=1:raise DnsError('final_dns_backend_unverified')
            filename=matches[0]
        elif rc!=10:raise DnsError('final_dns_backend_unverified')
        records={};source=None;persistent_exists=True
        if connection and filename not in ('','--'):
            if not re.fullmatch('/etc/NetworkManager/system-connections/[A-Za-z0-9_. -]+[.]nmconnection',filename):raise ValueError
            path=inside(root,filename);data,info=read(path,root,private=True);cfg=keyfile(data)
            if cfg.get('connection','uuid')!=connection or cfg.get('connection','interface-name',fallback=interface)!=interface:
                raise DnsError('final_dns_backend_unverified')
            persistent=[]
            for section in ('ipv4','ipv6'):
                if not cfg.has_section(section):raise DnsError('final_dns_backend_unverified')
                for value in cfg.get(section,'dns',fallback='').split(';'):
                    if value:persistent.append(str(ipaddress.ip_address(value)))
            backend='nm_keyfile'
        else:
            options_path=inside(root,'/etc/net/ifaces/'+interface+'/options')
            options,oinfo=read(options_path,root);settings=shell_options(options)
            if settings.get('TYPE') not in ('eth','vlan','bond','bri'):raise DnsError('final_dns_backend_unverified')
            controlled=settings.get('NM_CONTROLLED','').lower()
            if controlled!=('yes' if connection else 'no') or settings.get('SYSTEMD_CONTROLLED','no').lower()!='no':
                raise DnsError('final_dns_backend_unverified')
            records[str(options_path.relative_to(root))]=(options,oinfo)
            path=inside(root,'/etc/net/ifaces/'+interface+'/resolv.conf')
            try:data,info=read(path,root)
            except FileNotFoundError:
                # NM/Etcnet DHCP profiles need not have a static resolver input.
                # Absence is a bound preimage, never permission to overwrite.
                if not connection or settings.get('BOOTPROTO') not in ('dhcp','dhcp4'):
                    raise DnsError('final_dns_backend_unverified') from None
                data=b'';info=path.parent.stat();persistent_exists=False
            persistent=resolvers(data) if persistent_exists else [];backend='nm_etcnet' if connection else 'etcnet'
            if not connection:
                # Adopt only the already registered exact interface source.
                source=inside(root,'/run/resolvconf/interfaces/'+interface)
                sdata,sinfo=read(source,root)
                if sdata!=data:
                    # A failed resolvconf activation can leave the original
                    # registered source intact after our persistent exchange.
                    # Only the exact retained replacement and original source
                    # may be observed in this internal rollback transition.
                    if _owned_rollback is None:raise DnsError('final_dns_backend_unverified')
                    original,replacement,replacement_info=_owned_rollback
                    prior=original.files.get(str(source.relative_to(root)))
                    if (original.public['backend']!='etcnet' or original.path!=path or original.resolver_source!=source
                            or data!=replacement or file_identity(info)!=file_identity(replacement_info)
                            or attributes(path)!=original.attributes or prior is None or sdata!=prior[0]
                            or file_identity(sinfo)!=file_identity(prior[1])):
                        raise DnsError('final_dns_configuration_changed')
                records[str(source.relative_to(root))]=(sdata,sinfo)
        records[str(path.relative_to(root))]=(data,info if persistent_exists else None)
        # ALT resolvconf intentionally hardlinks its generated active file.
        # This exception is observation-only; no operation writes this file.
        active_path=inside(root,'/etc/resolv.conf');dns=resolvers(read(active_path,root,allow_hardlinks=True)[0])
        config_hash=digest(canonical({k:({'absent':True,'parent_inode':info.st_ino,'parent_device':info.st_dev,
            'parent_uid':info.st_uid,'parent_gid':info.st_gid,'parent_mode':info.st_mode} if i is None else
            {'sha256':digest(d),'uid':i.st_uid,'gid':i.st_gid,'mode':stat.S_IMODE(i.st_mode),
            'inode':i.st_ino,'device':i.st_dev,'mtime_ns':i.st_mtime_ns,'ctime_ns':i.st_ctime_ns,
            'attributes':{a:digest(b) for a,b in attributes(root/k).items()}})
            for k,(d,i) in records.items()}))
        public={'schema_version':1,'machine_uuid':machine,'hostname':request['hostname'],'boot_id':boot,
            'backend':backend,'interface':interface,'connection_uuid':connection,'servers':dns,
            'persistent_servers':persistent,'configuration_sha256':config_hash,
            'network_sha256':network_identity(call,interface)}
        public['snapshot_sha256']=digest(canonical(public))
        return Snapshot(public,path,data,info,records,attributes(path) if persistent_exists else {},source,persistent_exists)
    except DnsError:raise
    except Exception:raise DnsError('final_dns_backend_unverified') from None


def observe(request,*,root=Path('/'),call=run):
    """Ordinary read-only observations always require source convergence."""
    return _observe(request,root=root,call=call)


def rewrite(snapshot,servers):
    servers=validate(servers)['servers'];text=snapshot.content.decode('utf-8')
    if not snapshot.persistent_exists:
        return ''.join('nameserver '+s+'\n' for s in servers).encode()
    newline='\r\n' if '\r\n' in text else '\n'
    if snapshot.public['backend']!='nm_keyfile':
        output=[];inserted=False
        for line in text.splitlines(keepends=True):
            if re.match(r'^\s*nameserver\s',line):
                if not inserted:output.extend('nameserver '+s+newline for s in servers);inserted=True
            else:output.append(line)
        if not inserted:raise DnsError('final_dns_backend_unverified')
        return ''.join(output).encode()
    desired={section:{'dns':';'.join(s for s in servers if ipaddress.ip_address(s).version==version),
                       'ignore-auto-dns':'true'} for section,version in [('ipv4',4),('ipv6',6)]}
    for values in desired.values():
        if values['dns']:values['dns']+=';'
    output=[];section=None;seen=set()
    def finish():
        if section in desired:
            output.extend(k+'='+v+newline for k,v in desired[section].items() if k not in seen and (k!='dns' or v))
    for line in text.splitlines(keepends=True):
        match=re.fullmatch(r'\s*\[([^\]]+)\]\s*',line.strip())
        if match:finish();section=match[1];seen=set();output.append(line);continue
        key=line.partition('=')[0].strip()
        if section in desired and key in desired[section]:
            output.append(key+'='+desired[section][key]+newline);seen.add(key)
        else:output.append(line)
    finish()
    return ''.join(output).encode()


def record(directory,name,value):
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        data=canonical(value) if not isinstance(value,bytes) else value
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def exchange(path,old,new,info,root,expected_attributes,*,journal=None,stage='apply'):
    """Exchange first, then prove the displaced inode; never overwrite a race."""
    current,observed=read(path,root)
    if current!=old or attributes(path)!=expected_attributes or file_identity(observed)!=file_identity(info):
        raise DnsError('final_dns_configuration_changed')
    fd,name=tempfile.mkstemp(prefix='.alt-dns-',dir=path.parent);temporary=Path(name)
    try:
        os.fchmod(fd,stat.S_IMODE(info.st_mode))
        if os.geteuid()==0:os.fchown(fd,info.st_uid,info.st_gid)
        for key in os.listxattr(fd):
            if key not in expected_attributes:os.removexattr(fd,key)
        for key,value in expected_attributes.items():os.setxattr(fd,key,value)
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(new);stream.flush();os.fsync(fd)
        if journal:
            record(journal,stage+'-exchange.json',{'schema_version':1,'path':str(path.relative_to(root)),
                'displaced_slot':str(temporary.relative_to(root)),'prior_sha256':digest(old),
                'replacement_sha256':digest(new),'prior_inode':info.st_ino,'replacement_inode':os.fstat(fd).st_ino})
        libc=ctypes.CDLL(None,use_errno=True);rename=getattr(libc,'renameat2',None)
        if rename is None or rename(-100,os.fsencode(temporary),-100,os.fsencode(path),2):
            raise DnsError('final_dns_apply_failed')
        moved,moved_info=read(temporary,root)
        unchanged=('st_ino','st_dev','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns')
        if (moved!=old or attributes(temporary)!=expected_attributes
                or any(getattr(moved_info,key)!=getattr(info,key) for key in unchanged)):
            # Preserve both files if another editor raced the exchange. The
            # displaced employee bytes stay in this private sibling, never lost.
            raise DnsError('final_dns_configuration_changed')
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
        return os.fstat(fd)
    finally:os.close(fd)


def publish_absent(snapshot,data,root,journal):
    """Publish one owned DHCP resolver input with kernel no-replace semantics."""
    path=snapshot.path;parent=path.parent.stat();prior=snapshot.info
    keys=('st_dev','st_ino','st_mode','st_uid','st_gid')
    if any(getattr(parent,k)!=getattr(prior,k) for k in keys):
        raise DnsError('final_dns_configuration_changed')
    fd,name=tempfile.mkstemp(prefix='.alt-dns-',dir=path.parent);temporary=Path(name)
    try:
        os.fchmod(fd,0o644)
        if os.geteuid()==0:os.fchown(fd,prior.st_uid,prior.st_gid)
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(data);stream.flush();os.fsync(fd)
        record(journal,'apply-create.json',{'schema_version':1,'path':str(path.relative_to(root)),
            'prior_absent':True,'replacement_sha256':digest(data),'replacement_inode':os.fstat(fd).st_ino})
        rename=getattr(ctypes.CDLL(None,use_errno=True),'renameat2',None)
        if rename is None or rename(-100,os.fsencode(temporary),-100,os.fsencode(path),1):
            raise DnsError('final_dns_configuration_changed')
        parentfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parentfd)
        finally:os.close(parentfd)
        return os.fstat(fd)
    finally:os.close(fd)


def restore_absent(path,data,info,root,journal):
    """Retain the exact created input in an exclusive rollback slot; unlink nothing."""
    current,observed=read(path,root)
    if current!=data or file_identity(observed)!=file_identity(info) or attributes(path):
        raise DnsError('final_dns_configuration_changed')
    slot=path.parent/('.alt-dns-rollback-'+uuid.uuid4().hex)
    record(journal,'rollback-remove.json',{'schema_version':1,'path':str(path.relative_to(root)),
        'retained_slot':str(slot.relative_to(root)),'replacement_inode':info.st_ino,'replacement_sha256':digest(data)})
    rename=getattr(ctypes.CDLL(None,use_errno=True),'renameat2',None)
    if rename is None or rename(-100,os.fsencode(path),-100,os.fsencode(slot),1):
        raise DnsError('final_dns_configuration_changed')
    moved,moved_info=read(slot,root)
    keys=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns')
    if moved!=data or attributes(slot) or any(getattr(moved_info,k)!=getattr(info,k) for k in keys):
        # A racing editor's data is preserved and restored without overwriting.
        rename(-100,os.fsencode(slot),-100,os.fsencode(path),1)
        raise DnsError('final_dns_configuration_changed')
    parentfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parentfd)
    finally:os.close(parentfd)


def activate(snapshot,data,call):
    public=snapshot.public
    if public['backend']=='nm_etcnet':args=['nmcli','connection','reload']
    elif public['backend']=='nm_keyfile':args=['nmcli','connection','load','/etc/NetworkManager/system-connections/'+snapshot.path.name]
    else:
        rc,_=call(['resolvconf','-a',public['interface']],input_text=data.decode('utf-8'))
        if rc:raise DnsError('final_dns_apply_failed')
        return
    rc,_=call(args)
    if rc:raise DnsError('final_dns_apply_failed')
    rc,_=call(['nmcli','device','reapply',public['interface']])
    if rc:raise DnsError('final_dns_apply_failed')


def native_context(context,request):
    keys={'schema_version','kind','phase','job_id','claim_sha256','plan_sha256','workflow_policy_sha256',
          'machine_uuid','source_sha256','policy_sha256'}
    if (not isinstance(context,dict) or set(context)!=keys or type(context['schema_version']) is not int
            or context['schema_version']!=1 or context['kind']!='complete_workstation' or context['phase']!='final_dns'
            or context['machine_uuid']!=request['machine_uuid']
            or context['policy_sha256']!=digest(canonical(validate(request['servers'])))
            or not re.fullmatch('job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',context['job_id'])
            or any(not isinstance(context[k],str) or not re.fullmatch('[0-9a-f]{64}',context[k]) for k in
                ('claim_sha256','plan_sha256','workflow_policy_sha256','source_sha256','policy_sha256'))):
        raise DnsError('final_dns_context_unverified')


def same_connection(before,after):
    for key in ('machine_uuid','hostname','boot_id','backend','interface','connection_uuid','network_sha256'):
        if after.public[key]!=before.public[key]:raise DnsError('final_dns_network_changed')
    if after.path!=before.path or after.resolver_source!=before.resolver_source:
        raise DnsError('final_dns_configuration_changed')
    if set(before.files)!=set(after.files):raise DnsError('final_dns_configuration_changed')
    for path,(data,info) in before.files.items():
        # This supported Etcnet input is observed but never edited. The full
        # keyfile is independently compared to the exact DNS-only output.
        if not path.endswith('/options'):continue
        current=after.files.get(path)
        if current is None or current[0]!=data or (current[1].st_ino,current[1].st_dev,current[1].st_mode,
                current[1].st_uid,current[1].st_gid)!=(info.st_ino,info.st_dev,info.st_mode,info.st_uid,info.st_gid):
            raise DnsError('final_dns_configuration_changed')


def apply(request,expected,context,*,root=Path('/'),call=run,verify=None):
    directory=None;changed=False
    try:
        root=Path(root);native_context(context,request)
        if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):raise DnsError('final_dns_request_unverified')
        namespace=inside(root,'/var/lib/alt-workstation-final-dns')
        directory=namespace/context['claim_sha256']
        if directory.exists():raise DnsError('final_dns_claim_consumed')
        before=observe(request,root=root,call=call)
        if before.public['snapshot_sha256']!=expected:raise DnsError('final_dns_configuration_changed')
        namespace.mkdir(mode=0o700,parents=True,exist_ok=True)
        _,ninfo=read_directory(namespace,root)
        lock=os.open(namespace/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            linfo=os.fstat(lock)
            if (not stat.S_ISREG(linfo.st_mode) or linfo.st_uid!=ninfo.st_uid
                    or stat.S_IMODE(linfo.st_mode)!=0o600 or linfo.st_nlink!=1):raise DnsError('final_dns_ownership_unverified')
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise DnsError('final_dns_busy') from None
            if directory.exists():raise DnsError('final_dns_claim_consumed')
            directory.mkdir(mode=0o700)
            record(directory,'invocation.json',{'schema_version':1,'context':context,'readiness':before.public,
                'pid':os.getpid(),'uid':os.getuid(),'boot_id':before.public['boot_id'],
                'start_ticks':Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]})
            record(directory,'resolver.before',before.content)
            if read(directory/'resolver.before',root,private=True)[0]!=before.content:
                raise DnsError('final_dns_backup_unverified')
            record(directory,'manifest.json',{'schema_version':1,'path':'/'+str(before.path.relative_to(root)),
                'sha256':digest(before.content),'uid':before.info.st_uid,'gid':before.info.st_gid,
                'mode':stat.S_IMODE(before.info.st_mode),'configuration_sha256':before.public['configuration_sha256'],
                'persistent_exists':before.persistent_exists,
                'attributes':{k:v.hex() for k,v in before.attributes.items()}})
            check=verify or verify_dns
            check(before,phase='before',request=request,root=root,call=call)
            fresh=observe(request,root=root,call=call)
            if fresh.public!=before.public:raise DnsError('final_dns_configuration_changed')
            new=rewrite(before,request['servers'])
            try:
                file_changed=new!=before.content
                changed=file_changed or before.public['servers']!=request['servers']
                if file_changed:
                    new_info=(exchange(before.path,before.content,new,before.info,root,before.attributes,journal=directory)
                        if before.persistent_exists else publish_absent(before,new,root,directory))
                else:new_info=before.info
                if changed:activate(before,new,call)
                after=observe(request,root=root,call=call)
                same_connection(before,after)
                if (after.content!=new or after.attributes!=before.attributes
                        or (after.info.st_ino,after.info.st_dev)!=(new_info.st_ino,new_info.st_dev)):
                    raise DnsError('final_dns_configuration_changed')
                if after.public['servers']!=request['servers'] or after.public['persistent_servers']!=request['servers']:
                    raise DnsError('final_dns_active_unverified')
                check(after,phase='after',request=request,root=root,call=call)
                result={'status':'applied_verified','changed':changed,'code':'final_dns_applied'}
            except Exception as error:
                code=str(error) if isinstance(error,DnsError) and str(error) in CODES else 'final_dns_outcome_unverified'
                try:
                    if changed:
                        current=_observe(request,root=root,call=call,_owned_rollback=(before,new,new_info))
                        same_connection(before,current)
                        if current.content!=new or current.attributes!=before.attributes:raise ValueError
                        # Only our exact replacement inode may be rolled back.
                        if file_changed:
                            if before.persistent_exists:exchange(before.path,new,before.content,new_info,root,before.attributes,journal=directory,stage='rollback')
                            else:restore_absent(before.path,new,new_info,root,directory)
                        activate(before,before.content,call)
                    restored=observe(request,root=root,call=call)
                    if (restored.persistent_exists!=before.persistent_exists
                            or restored.content!=before.content or restored.public['servers']!=before.public['servers']
                            or restored.public['network_sha256']!=before.public['network_sha256']):raise ValueError
                    check(restored,phase='rollback',request=request,root=root,call=call)
                    result={'status':'rolled_back_verified','changed':False,'code':code}
                except Exception:result={'status':'outcome_unverified','changed':None,'code':'final_dns_rollback_unverified'}
            record(directory,'result.json',result)
            return result
        finally:os.close(lock)
    except Exception as error:
        code=str(error) if isinstance(error,DnsError) and str(error) in CODES else 'final_dns_outcome_unverified'
        return {'status':'outcome_unverified','changed':None if changed else False,'code':code}


def read_directory(path,root):
    owner=0 if root==Path('/') else os.getuid();info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700:
        raise DnsError('final_dns_ownership_unverified')
    current=path.parent
    while current!=root:
        info2=current.lstat()
        if not stat.S_ISDIR(info2.st_mode) or info2.st_uid!=owner or info2.st_mode&0o022:raise DnsError('final_dns_ownership_unverified')
        current=current.parent
    return path,info


def dns_name(data,offset):
    labels=[];seen=set();end=None
    for _ in range(128):
        if offset in seen or offset>=len(data):raise ValueError
        seen.add(offset);size=data[offset]
        if size&0xc0==0xc0:
            if offset+1>=len(data):raise ValueError
            if end is None:end=offset+2
            offset=((size&0x3f)<<8)|data[offset+1];continue
        if size&0xc0 or size>63:raise ValueError
        offset+=1
        if not size:
            value='.'.join(labels).lower()
            if len(value)>253:raise ValueError
            return value,end or offset
        label=data[offset:offset+size].decode('ascii')
        if len(label)!=size or not re.fullmatch('[A-Za-z0-9_-]+',label):raise ValueError
        labels.append(label);offset+=size
    raise ValueError


def query_dns(server,name,type_):
    """Connected UDP, one bounded transaction, exact echoed question/type."""
    try:
        address=ipaddress.ip_address(server)
        if type_ not in (1,28,33) or not re.fullmatch('[a-z0-9_.-]{1,253}',name):raise ValueError
        question=b''.join(bytes([len(v)])+v.encode() for v in name.split('.'))+b'\0'+struct.pack('!HH',type_,1)
        transaction=os.urandom(2)
        query=transaction+struct.pack('!HHHHH',0x0100,1,0,0,0)+question
        with socket.socket(socket.AF_INET if address.version==4 else socket.AF_INET6,socket.SOCK_DGRAM) as stream:
            stream.settimeout(2);stream.connect((str(address),53));stream.send(query);data=stream.recv(65536)
        if len(data)<12 or data[:2]!=transaction:raise ValueError
        flags,questions,answers,authority,additional=struct.unpack('!HHHHH',data[2:12])
        if flags&0x8000==0 or flags&0x7a0f or questions!=1 or answers>128 or authority+additional>256:raise ValueError
        echoed,offset=dns_name(data,12)
        if echoed!=name or data[offset:offset+4]!=struct.pack('!HH',type_,1):raise ValueError
        offset+=4;result=[];aliases={name}
        for _ in range(answers):
            owner,offset=dns_name(data,offset)
            if offset+10>len(data):raise ValueError
            kind,cls,ttl,size=struct.unpack('!HHIH',data[offset:offset+10]);offset+=10;end=offset+size
            if end>len(data) or cls!=1 or owner not in aliases:raise ValueError
            if kind==5:
                alias,consumed=dns_name(data,offset)
                if consumed!=end:raise ValueError
                aliases.add(alias)
            elif kind==type_:
                if kind in (1,28):
                    if size!=(4 if kind==1 else 16):raise ValueError
                    result.append(str(ipaddress.ip_address(data[offset:end])))
                else:
                    if size<7:raise ValueError
                    priority,weight,port=struct.unpack('!HHH',data[offset:offset+6]);target,consumed=dns_name(data,offset+6)
                    if consumed!=end or not target:raise ValueError
                    result.append((port,target))
            else:raise ValueError
            offset=end
        return list(dict.fromkeys(result))
    except Exception:raise DnsError('final_dns_lookup_failed') from None


def verify_dns(snapshot,*,phase,request,root=Path('/'),call=run):
    """No keytab/ticket bytes or arbitrary command output escape this function."""
    root=Path(root);deadline=time.monotonic()+35;controllers=set()
    try:
        servers=request['servers'] if phase=='before' else snapshot.public['servers']
        def query(server,name,type_):
            if time.monotonic()>=deadline:raise DnsError('final_dns_lookup_failed')
            return query_dns(server,name,type_)
        for server in servers:
            targets=set()
            for name,port in [('_ldap._tcp.dc._msdcs.sosnadmin.local',389),('_kerberos._tcp.sosnadmin.local',88)]:
                entries=query(server,name,33)
                if not entries or any(p!=port or not host.endswith('.sosnadmin.local') for p,host in entries):
                    raise DnsError('final_dns_lookup_failed')
                targets.update(host for p,host in entries)
            for name in sorted(targets):
                addresses=query(server,name,1) or query(server,name,28)
                if not addresses:raise DnsError('final_dns_lookup_failed')
                controllers.add(name)
            for name in ('download.basealt.ru','ftp.altlinux.org'):
                if not (query(server,name,1) or query(server,name,28)):raise DnsError('final_dns_lookup_failed')
        # Exercise libc/NSS through a bounded child, keeping normal process
        # limits. Direct SRV checks above alone do not establish active DNS.
        for name in [*sorted(controllers),'download.basealt.ru']:
            rc,text=call(['getent','ahosts',name],timeout=5)
            if rc or not text.strip():raise DnsError('final_dns_lookup_failed')
    except DnsError:raise
    except Exception:raise DnsError('final_dns_lookup_failed') from None
    try:
        keytab=inside(root,'/etc/krb5.keytab');read(keytab,root,private=True)
        rc,text=call(['klist','-k',str(keytab)],timeout=5)
        if rc:raise ValueError
        expected=request['hostname'].upper()+'$@SOSNADMIN.LOCAL'
        principals=[line.split()[-1] for line in text.splitlines() if line.split() and line.split()[-1]==expected]
        if not principals:raise ValueError
        run_path=inside(root,'/run')
        if root!=Path('/'):run_path.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='alt-final-dns-',dir=run_path) as temporary:
            cache='FILE:'+str(Path(temporary)/'machine.ccache')
            try:
                rc,_=call(['kinit','-k','-t',str(keytab),'-c',cache,expected],timeout=15)
                if rc:raise ValueError
            finally:call(['kdestroy','-c',cache],timeout=5)
        return {'discovery':True,'external':True,'machine_ticket':True}
    except Exception:raise DnsError('final_dns_kerberos_failed') from None


def main():
    try:
        import sys
        if (os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in ('--observe','--apply')
                or sys.argv[0]!='/usr/local/libexec/alt-workstation-final-dns'):raise ValueError
        raw=sys.stdin.read(8193)
        if len(raw.encode())>8192:raise ValueError
        document=json.loads(raw,object_pairs_hook=unique)
        keys={'request','helper_sha256'}|({'expected_snapshot_sha256','context'} if sys.argv[1]=='--apply' else set())
        if not isinstance(document,dict) or set(document)!=keys:raise ValueError
        root=Path('/');source,info=read(inside(root,sys.argv[0]),root,private=True)
        if stat.S_IMODE(info.st_mode)!=0o700 or digest(source)!=document['helper_sha256']:
            raise DnsError('final_dns_source_unverified')
        if sys.argv[1]=='--observe':
            print(json.dumps({'schema_version':1,'status':'ok','helper_sha256':document['helper_sha256'],
                'observation':observe(document['request']).public}));return 0
        result=apply(document['request'],document['expected_snapshot_sha256'],document['context'])
        known=result['status'] in ('applied_verified','rolled_back_verified')
        print(json.dumps({'schema_version':1,'status':'ok' if known else 'blocked',
            'helper_sha256':document['helper_sha256'],'claim_sha256':document['context']['claim_sha256'],'result':result}))
        return 0 if known else 4
    except Exception as error:
        code=str(error) if isinstance(error,DnsError) and str(error) in CODES else 'final_dns_request_unverified'
        print(json.dumps({'schema_version':1,'status':'blocked','code':code}));return 4
