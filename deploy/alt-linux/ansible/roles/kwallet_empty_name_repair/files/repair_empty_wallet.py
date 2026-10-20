"""Repair only a confirmed empty-name KDE wallet through the fixed native helper."""
from __future__ import annotations

from dataclasses import dataclass,field
from contextlib import contextmanager
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import sys
import threading
import time
import uuid

from alt_deploy.user_session import SessionContext,SessionError,_inside,_process,_read,_revalidate,_trusted_program,run_session_command,discover_session,_call
from alt_deploy.wallet_codes import WALLET_CODES


class WalletError(Exception):
    pass


SOURCES=('.kwl','.salt','_attributes.json')


@dataclass(frozen=True)
class WalletEvidence:
    disposition: str
    wallet_name: str
    snapshot_sha256: str
    configuration: bytes | None = field(repr=False)
    configuration_state: dict | None = field(repr=False)
    files: dict = field(repr=False)
    context: SessionContext = field(repr=False)


def validate_wallet_name(name):
    if not isinstance(name,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}',name):
        raise WalletError('kwallet_name_unverified')
    return name


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _user_directory(path,context,*,closed=False):
    info=path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=context.uid or info.st_gid!=context.gid
            or info.st_mode & 0o022 or closed and stat.S_IMODE(info.st_mode)!=0o700):
        raise WalletError('kwallet_ownership_unverified')


def _file(path,context,*,limit=67108864,dir_fd=None):
    try:
        before=os.stat(path,dir_fd=dir_fd,follow_symlinks=False)
    except FileNotFoundError:return None
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=context.uid or before.st_gid!=context.gid
            or stat.S_IMODE(before.st_mode) not in (0o400,0o600) or before.st_nlink!=1
            or before.st_size>limit):raise WalletError('kwallet_ownership_unverified')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=dir_fd)
    try:
        opened=os.fstat(descriptor)
        chunks=[];size=0
        while True:
            block=os.read(descriptor,min(1048576,limit+1-size))
            if not block:break
            chunks.append(block);size+=len(block)
            if size>limit:raise WalletError('kwallet_evidence_unverified')
        after=os.fstat(descriptor)
    finally:os.close(descriptor)
    if not _identity(before)==_identity(opened)==_identity(after)==_identity(os.stat(path,dir_fd=dir_fd,follow_symlinks=False)):
        raise WalletError('kwallet_evidence_changed')
    data=b''.join(chunks)
    if len(data)!=after.st_size:raise WalletError('kwallet_evidence_changed')
    return {'data':data,'sha256':hashlib.sha256(data).hexdigest(),
            'identity':_identity(after),'mode':stat.S_IMODE(after.st_mode)}


def _configuration(data):
    if data is None:return None
    if b'\0' in data:raise ValueError
    parser=configparser.ConfigParser(interpolation=None,strict=True,default_section='\0')
    parser.optionxform=str
    parser.read_string(data.decode('utf-8'))
    return parser


def _confirmed(parser):
    return (parser is not None and parser.has_section('Wallet')
        and parser.get('Wallet','Default Wallet',fallback=None)==''
        and parser.get('Wallet','First Use',fallback=None)=='false')


def repair_configuration(data,name):
    """Change only the empty default in the real Wallet group, preserving bytes."""
    try:
        validate_wallet_name(name)
        if not _confirmed(_configuration(data)):raise ValueError
        lines=[];active=None;changed=0
        for line in data.decode('utf-8').splitlines(keepends=True):
            core=line.rstrip('\r\n');ending=line[len(core):]
            header=re.fullmatch(r'\[(.+)\]\s*',core.strip())
            if header:active=header[1]
            key,separator,_=core.partition('=')
            if active=='Wallet' and separator and key.strip()=='Default Wallet':
                line=key+'='+name+ending;changed+=1
            lines.append(line)
        result=''.join(lines).encode('utf-8')
        if changed!=1 or _configuration(result).get('Wallet','Default Wallet')!=name:raise ValueError
        return result
    except (ValueError,TypeError,AttributeError,UnicodeError,configparser.Error):
        raise WalletError('kwallet_configuration_unverified') from None


def _evidence(context,name,configuration,files,disposition):
    # Bind the real session privately, including its complete inherited context.
    # Never serialize this dataclass or its files; expose only explicit hashes.
    private={'uid':context.uid,'gid':context.gid,'home':context.home,'session':context.session_id,
        'pid':context.pid,'start':context.start_ticks,'launcher':context.launcher_pid,
        'launcher_start':context.launcher_start_ticks,'environment':context.environment,
        'limits':context.limits,'groups':context.groups}
    proof={'wallet_name':name,'session':private,'configuration':None if configuration is None else
        {key:value for key,value in configuration.items() if key!='data'},
        'files':{key:{k:v for k,v in value.items() if k!='data'} for key,value in files.items()}}
    digest=hashlib.sha256(json.dumps(proof,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    return WalletEvidence(disposition,name,digest,configuration['data'] if configuration else None,
                          configuration,files,context)


def inspect_wallet(context,wallet_name='recovered-wallet',*,root=Path('/')):
    """Read-only conditional evidence; healthy users need no backup or file write."""
    try:
        validate_wallet_name(wallet_name)
        if not isinstance(context,SessionContext) or context.uid<=0 or context.gid<=0:raise ValueError
        root=Path(root)
        home=_inside(root,context.home);_user_directory(home,context)
        configuration_path=_inside(root,context.home+'/.config/kwalletrc')
        configuration=_file(configuration_path,context,limit=131072)
        if configuration_path.parent.exists():_user_directory(configuration_path.parent,context)
        parser=_configuration(configuration['data'] if configuration else None)
        directory=_inside(root,context.home+'/.local/share/kwalletd')
        if not directory.exists():return _evidence(context,wallet_name,configuration,{},'noop')
        # Reject links even when they point to an otherwise owned wallet.
        candidates=[_inside(root,context.home+'/.local/share/kwalletd/'+name) for name in SOURCES]
        present=[p.exists() for p in candidates]
        if not any(present):
            if _confirmed(parser) and any(_inside(root,context.home+'/.local/share/kwalletd/'+wallet_name+suffix).exists()
                                          for suffix in ('.kwl','.salt','_attributes.json')):
                raise WalletError('kwallet_partial_repair_unverified')
            return _evidence(context,wallet_name,configuration,{},'noop')
        if not all(present) or not _confirmed(parser):raise WalletError('kwallet_empty_name_evidence_incomplete')
        _user_directory(directory,context,closed=True)
        for parent in (directory.parent,directory.parent.parent):_user_directory(parent,context)
        for suffix in ('.kwl','.salt','_attributes.json'):
            target=_inside(root,context.home+'/.local/share/kwalletd/'+wallet_name+suffix)
            if target.exists():raise WalletError('kwallet_target_collision')
        paths=list(directory.iterdir())
        if len(paths)>1024:raise ValueError
        files={};size=0
        for path in sorted(paths):
            value=_file(_inside(root,context.home+'/.local/share/kwalletd/'+path.name),context)
            if value is None:raise WalletError('kwallet_evidence_changed')
            size+=len(value['data'])
            if size>268435456:raise ValueError
            files[path.name]=value
        if {p.name for p in directory.iterdir()}!=set(files):raise WalletError('kwallet_evidence_changed')
        for name,value in files.items():
            if _identity((directory/name).lstat())!=value['identity']:raise WalletError('kwallet_evidence_changed')
        if _identity(configuration_path.lstat())!=configuration['identity']:raise WalletError('kwallet_evidence_changed')
        repair_configuration(configuration['data'],wallet_name)
        return _evidence(context,wallet_name,configuration,files,'repair')
    except WalletError:raise
    except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,configparser.Error,SessionError):
        raise WalletError('kwallet_evidence_unverified') from None


def _private_directory(root,absolute,*,create=False):
    path=_inside(root,absolute)
    if create:
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
    info=path.stat();owner=0 if root==Path('/') else os.getuid()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700:
        raise WalletError('kwallet_backup_unverified')
    return path


def _private_file(path,data):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        os.fchmod(stream.fileno(),0o600)
        stream.write(data);stream.flush();os.fsync(stream.fileno())


def _sync(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def create_backup(evidence,operation_sha256,*,root=Path('/')):
    """Seal the entire owned wallet directory and config before any signal."""
    try:
        if (not isinstance(evidence,WalletEvidence) or evidence.disposition!='repair'
                or not isinstance(operation_sha256,str) or not re.fullmatch('[0-9a-f]{64}',operation_sha256)):
            raise ValueError
        root=Path(root)
        current=inspect_wallet(evidence.context,evidence.wallet_name,root=root)
        if current.snapshot_sha256!=evidence.snapshot_sha256:raise WalletError('kwallet_evidence_changed')
        namespace=_private_directory(root,'/var/lib/alt-kwallet-empty-name-repair',create=True)
        directory=namespace/operation_sha256
        try:directory.mkdir(mode=0o700)
        except FileExistsError:raise WalletError('kwallet_claim_consumed') from None
        _private_directory(root,'/var/lib/alt-kwallet-empty-name-repair/'+operation_sha256)
        wallets=directory/'wallets';wallets.mkdir(mode=0o700)
        _private_file(directory/'kwalletrc',evidence.configuration)
        for name,value in evidence.files.items():_private_file(wallets/name,value['data'])
        process=Path('/proc')/str(os.getpid())
        ticks=int(_read(process/'stat',4096).decode().rsplit(')',1)[1].split()[19])
        if ticks<=0:raise ValueError
        manifest={'schema_version':1,'kind':'confirmed_empty_wallet_backup','operation_sha256':operation_sha256,
            'boot_id':_boot_id(),
            'snapshot_sha256':evidence.snapshot_sha256,'wallet_name':evidence.wallet_name,
            'uid':evidence.context.uid,'gid':evidence.context.gid,'home':evidence.context.home,
            'helper':{'pid':os.getpid(),'start_ticks':ticks,'uid':os.geteuid(),'gid':os.getegid(),
                      'command_sha256':hashlib.sha256(_read(process/'cmdline',131072)).hexdigest()},
            'configuration':{key:value for key,value in evidence.configuration_state.items() if key!='data'},
            'files':{name:{key:item for key,item in value.items() if key!='data'} for name,value in evidence.files.items()}}
        encoded=json.dumps(manifest,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        _private_file(directory/'manifest.json',encoded)
        for path,data in [(directory/'kwalletrc',evidence.configuration),(directory/'manifest.json',encoded),
                          *[(wallets/name,value['data']) for name,value in evidence.files.items()]]:
            info=path.stat();owner=0 if root==Path('/') else os.getuid()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o600
                    or info.st_nlink!=1 or path.read_bytes()!=data):raise ValueError
        for path in (wallets,directory,namespace,namespace.parent):_sync(path)
        return directory
    except WalletError:raise
    except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,SessionError):
        raise WalletError('kwallet_backup_unverified') from None


@dataclass(frozen=True)
class DaemonEvidence:
    snapshot_sha256: str
    records: tuple = field(repr=False)


DAEMONS=frozenset({'/usr/bin/kwalletd6','/usr/bin/ksecretd'})


def observe_daemons(context,*,root=Path('/')):
    """Keep process environments private; only exact selected-user daemons qualify."""
    try:
        if not isinstance(context,SessionContext):raise ValueError
        root=Path(root);records=[];counts={}
        directories=[p for p in _inside(root,'/proc').iterdir() if p.name.isdigit()]
        if len(directories)>65536:raise ValueError
        for directory in directories:
            try:
                if directory.stat().st_uid!=context.uid:continue
            except FileNotFoundError:continue
            value=_process(root,directory,context.uid,context.gid,DAEMONS)
            if value is None:continue
            if any(value['environment'].get(key)!=context.environment.get(key) for key in
                    ('HOME','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS')):raise ValueError
            counts[value['executable']]=counts.get(value['executable'],0)+1
            if counts[value['executable']]!=1:raise ValueError
            records.append(value)
        records.sort(key=lambda p:0 if p['executable']=='/usr/bin/kwalletd6' else 1)
        for value in records:
            if _process(root,root/'proc'/str(value['pid']),context.uid,context.gid,DAEMONS)!=value:raise ValueError
        encoded=json.dumps(records,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        return DaemonEvidence(hashlib.sha256(encoded).hexdigest(),tuple(records))
    except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,SessionError):
        raise WalletError('kwallet_daemon_unverified') from None


def stop_daemons(context,evidence,*,root=Path('/')):
    """One pidfd SIGTERM each, after all identities pass; never SIGKILL an app."""
    descriptors=[];dispatched=False
    try:
        if (not isinstance(context,SessionContext) or not isinstance(evidence,DaemonEvidence)
                or len(evidence.records)>2 or len({p['pid'] for p in evidence.records})!=len(evidence.records)):
            raise ValueError
        _revalidate(context);root=Path(root)
        if observe_daemons(context,root=root)!=evidence:raise ValueError
        for value in evidence.records:
            descriptor=os.pidfd_open(value['pid'],0);descriptors.append(descriptor)
            if (_process(root,root/'proc'/str(value['pid']),context.uid,context.gid,DAEMONS)!=value
                    or select.select([descriptor],[],[],0)[0]):raise ValueError
        _revalidate(context)
        if observe_daemons(context,root=root)!=evidence:raise ValueError
        for descriptor in descriptors:
            dispatched=True
            signal.pidfd_send_signal(descriptor,signal.SIGTERM,None,0)
        deadline=time.monotonic()+10
        pending=set(descriptors)
        while pending:
            ready,_,_=select.select(list(pending),[],[],max(0,deadline-time.monotonic()))
            if not ready:raise ValueError
            pending.difference_update(ready)
        for value in evidence.records:
            if _process(root,root/'proc'/str(value['pid']),context.uid,context.gid,DAEMONS) is not None:raise ValueError
        if observe_daemons(context,root=root).records:raise ValueError
    except (OSError,ValueError,TypeError,KeyError,AttributeError,UnicodeError,SessionError,WalletError):
        raise WalletError('kwallet_daemon_exit_unverified' if dispatched else 'kwallet_daemon_unverified') from None
    finally:
        for descriptor in descriptors:os.close(descriptor)


def _rename_at2(oldfd,old,newfd,new,flags):
    # Linux renameat2 RENAME_NOREPLACE / RENAME_EXCHANGE, with no unsafe fallback:
    # https://man7.org/linux/man-pages/man2/rename.2.html
    import ctypes
    try:
        library=ctypes.CDLL(None,use_errno=True)
        function=library.renameat2
        function.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
        function.restype=ctypes.c_int
        if function(oldfd,os.fsencode(old),newfd,os.fsencode(new),flags)!=0:
            error=ctypes.get_errno();raise OSError(error,'Atomic wallet rename failed')
    except AttributeError:raise WalletError('kwallet_atomic_rename_unavailable') from None


def _same_file(actual,expected):
    # A daemon's graceful exit, and rename itself, may change timestamps while
    # leaving every byte, inode, ownership and closed mode unchanged.
    return (actual is not None and expected is not None and actual['sha256']==expected['sha256']
        and actual['identity'][:7]==expected['identity'][:7])


def _owned_folder(parent,name,context,*,closed=False):
    descriptor=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
    info=os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=context.uid or info.st_gid!=context.gid
            or info.st_mode & 0o022 or closed and stat.S_IMODE(info.st_mode)!=0o700):
        os.close(descriptor);raise WalletError('kwallet_ownership_unverified')
    return descriptor


def apply_wallet_files(evidence,operation_sha256,*,root=Path('/')):
    """Internal same-user writer: no daemon activation, password or application IO.

    The root coordinator must first seal its backup, stop only proven old
    daemons, and durably acknowledge this new writer child's identity. Never
    invoke this function directly from a public endpoint or a read-only probe.
    """
    if (not isinstance(evidence,WalletEvidence) or evidence.disposition!='repair'
            or os.geteuid()==0 or os.geteuid()!=evidence.context.uid or os.getegid()!=evidence.context.gid
            or tuple(os.getgroups())!=evidence.context.groups):
        raise WalletError('kwallet_writer_identity_unverified')
    if not isinstance(operation_sha256,str) or not re.fullmatch('[0-9a-f]{64}',operation_sha256):
        raise WalletError('kwallet_writer_identity_unverified')
    root=Path(root);context=evidence.context;descriptors=[];wallet=config=None
    temporary='.alt-wallet-repair-'+operation_sha256
    temp_state=None;created=False
    pairs=list(zip(SOURCES,(evidence.wallet_name+'.kwl',evidence.wallet_name+'.salt',evidence.wallet_name+'_attributes.json')))

    def quiet():
        if observe_daemons(context,root=root).records:raise WalletError('kwallet_daemon_restarted')

    def read(folder,name):return _file(name,context,dir_fd=folder)

    def rollback():
        # Preflight every owned transition before restoring anything. Unknown
        # target bytes, new daemons or a re-created source retain uncertainty.
        quiet();moves=[]
        for old,new in pairs:
            original=read(wallet,old)
            if original is not None:
                if not _same_file(original,evidence.files[old]):raise ValueError
            elif _same_file(read(wallet,new),evidence.files[old]):moves.append((old,new))
            else:raise ValueError
        saved=read(config,temporary) if created else None
        current=read(config,'kwalletrc')
        exchanged=created and _same_file(current,temp_state)
        if exchanged and saved is None:raise ValueError
        if created and not exchanged and not _same_file(saved,temp_state):raise ValueError
        if exchanged:
            quiet()
            # The exchange preserves a concurrent employee edit captured in
            # the old-config slot. Restore those bytes, never an old copy.
            if not _same_file(read(config,'kwalletrc'),temp_state) or not _same_file(read(config,temporary),saved):raise ValueError
            _rename_at2(config,temporary,config,'kwalletrc',2)
            if not _same_file(read(config,'kwalletrc'),saved) or not _same_file(read(config,temporary),temp_state):raise ValueError
            os.fsync(config)
        for old,new in reversed(moves):
            quiet()
            if read(wallet,old) is not None or not _same_file(read(wallet,new),evidence.files[old]):raise ValueError
            _rename_at2(wallet,new,wallet,old,1);os.fsync(wallet)
        for old,_ in pairs:
            if not _same_file(read(wallet,old),evidence.files[old]):raise ValueError
        if created:
            if not _same_file(read(config,temporary),temp_state):raise ValueError
            os.unlink(temporary,dir_fd=config);os.fsync(config)

    try:
        _revalidate(context)
        fresh=inspect_wallet(context,evidence.wallet_name,root=root)
        if (fresh.disposition!='repair' or set(fresh.files)!=set(evidence.files)
                or not _same_file(fresh.configuration_state,evidence.configuration_state)
                or any(not _same_file(fresh.files[name],value) for name,value in evidence.files.items())):
            raise WalletError('kwallet_evidence_changed')
        home=os.open(_inside(root,context.home),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);descriptors.append(home)
        local=_owned_folder(home,'.local',context);descriptors.append(local)
        share=_owned_folder(local,'share',context);descriptors.append(share)
        wallet=_owned_folder(share,'kwalletd',context,closed=True);descriptors.append(wallet)
        config=_owned_folder(home,'.config',context);descriptors.append(config)
        quiet()
        desired=repair_configuration(evidence.configuration,evidence.wallet_name)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                   evidence.configuration_state['mode'],dir_fd=config)
        created=True
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),evidence.configuration_state['mode'])
            stream.write(desired);stream.flush();os.fsync(stream.fileno())
        temp_state=read(config,temporary)
        if temp_state['data']!=desired:raise ValueError
        for old,new in pairs:
            quiet()
            if not _same_file(read(wallet,old),evidence.files[old]):raise ValueError
            _rename_at2(wallet,old,wallet,new,1);os.fsync(wallet)
            if not _same_file(read(wallet,new),evidence.files[old]):raise ValueError
        quiet()
        if not _same_file(read(config,'kwalletrc'),evidence.configuration_state):raise ValueError
        _rename_at2(config,temporary,config,'kwalletrc',2);os.fsync(config)
        if not _same_file(read(config,temporary),evidence.configuration_state) or not _same_file(read(config,'kwalletrc'),temp_state):
            raise ValueError
        for old,new in pairs:
            if read(wallet,old) is not None or not _same_file(read(wallet,new),evidence.files[old]):raise ValueError
        quiet()
        return {'status':'applied','configuration_sha256':temp_state['sha256'],
            'wallet_sha256':{old:evidence.files[old]['sha256'] for old,_ in pairs},
            'configuration_backup':temporary}
    except Exception:
        if wallet is None or config is None:raise WalletError('kwallet_transition_unverified') from None
        try:rollback()
        except Exception:raise WalletError('kwallet_rollback_unverified') from None
        raise WalletError('kwallet_rollback_verified') from None
    finally:
        for descriptor in reversed(descriptors):os.close(descriptor)


def _writer_identity(pid,context,executable):
    process=Path('/proc')/str(pid)
    status=dict(line.split(':',1) for line in _read(process/'status',16384).decode().splitlines() if ':' in line)
    if (status.get('Uid','').split()!=[str(context.uid)]*4
            or status.get('Gid','').split()!=[str(context.gid)]*4
            or int(status.get('PPid','0'))!=os.getpid() or os.readlink(process/'exe')!=executable):raise ValueError
    ticks=int(_read(process/'stat',4096).decode().rsplit(')',1)[1].split()[19])
    if ticks<=0:raise ValueError
    return {'pid':pid,'start_ticks':ticks,'parent_pid':os.getpid(),'uid':context.uid,'gid':context.gid}


def _record(directory,name,value):
    encoded=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    _private_file(directory/name,encoded)
    if _read(directory/name,2097152)!=encoded:raise ValueError
    _sync(directory)


def run_writer(evidence,operation_sha256,directory,*,root=Path('/')):
    """Bound one newly owned child to a durable receipt before dropping the gate."""
    descriptors=[];pid=pidfd=None;reaped=False
    try:
        if (not isinstance(evidence,WalletEvidence) or evidence.disposition!='repair'
                or not isinstance(operation_sha256,str) or not re.fullmatch('[0-9a-f]{64}',operation_sha256)
                or threading.active_count()!=1):raise ValueError
        root=Path(root);context=evidence.context;directory=Path(directory)
        expected=_private_directory(root,'/var/lib/alt-kwallet-empty-name-repair/'+operation_sha256)
        if expected!=directory:raise ValueError
        manifest=json.loads(_read(directory/'manifest.json',2097152))
        if (manifest['operation_sha256']!=operation_sha256 or manifest['snapshot_sha256']!=evidence.snapshot_sha256
                or manifest['uid']!=context.uid or manifest['gid']!=context.gid
                or manifest['helper']['pid']!=os.getpid()):raise ValueError
        if (directory/'writer.json').exists():raise WalletError('kwallet_claim_consumed')
        if os.geteuid()!=0 and (os.geteuid()!=context.uid or os.getegid()!=context.gid
                               or tuple(os.getgroups())!=context.groups):raise ValueError
        executable=_trusted_program([sys.executable])
        gate_reader,gate_writer=os.pipe();ready_reader,ready_writer=os.pipe();result_reader,result_writer=os.pipe()
        descriptors=[gate_reader,gate_writer,ready_reader,ready_writer,result_reader,result_writer]
        inherited=[int(v) for v in os.listdir('/proc/self/fd') if v.isdigit()]
        pid=os.fork()
        if pid==0:
            try:
                for opened in inherited:
                    if opened>2 and opened not in (gate_reader,ready_writer,result_writer):
                        try:os.close(opened)
                        except OSError:pass
                null=os.open('/dev/null',os.O_RDWR)
                for opened in (0,1,2):os.dup2(null,opened)
                if null>2:os.close(null)
                os.umask(0o077)
                for key,value in context.limits.items():resource.setrlimit(key,value)
                if os.geteuid()==0:
                    os.setgroups(context.groups);os.setgid(context.gid);os.setuid(context.uid)
                os.write(ready_writer,b'R');os.close(ready_writer)
                if os.read(gate_reader,1)!=b'1':os._exit(4)
                os.close(gate_reader)
                try:result=apply_wallet_files(evidence,operation_sha256,root=root)
                except WalletError as error:
                    code=str(error)
                    safe={'kwallet_rollback_verified','kwallet_rollback_unverified','kwallet_writer_identity_unverified','kwallet_transition_unverified'}
                    if code not in safe:code='kwallet_transition_unverified'
                    result={'status':'rolled_back_verified' if code=='kwallet_rollback_verified' else 'unknown','code':code}
                raw=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
                if len(raw)>4096 or os.write(result_writer,raw)!=len(raw):os._exit(4)
                os.close(result_writer);os._exit(0)
            except BaseException:os._exit(4)
        for opened in (gate_reader,ready_writer,result_writer):os.close(opened);descriptors.remove(opened)
        pidfd=os.pidfd_open(pid,0)
        if not select.select([ready_reader],[],[],10)[0] or os.read(ready_reader,1)!=b'R':raise ValueError
        identity=_writer_identity(pid,context,executable)
        _record(directory,'writer.json',{'schema_version':1,'operation_sha256':operation_sha256,'boot_id':_boot_id(),
            'snapshot_sha256':evidence.snapshot_sha256,'child':identity})
        if _writer_identity(pid,context,executable)!=identity:raise ValueError
        os.write(gate_writer,b'1');os.close(gate_writer);descriptors.remove(gate_writer)
        os.set_blocking(result_reader,False);deadline=time.monotonic()+30;raw=bytearray()
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([result_reader],[],[],remaining)[0]:raise ValueError
            block=os.read(result_reader,4097-len(raw))
            if not block:break
            raw.extend(block)
            if len(raw)>4096:raise ValueError
        if not select.select([pidfd],[],[],max(0,deadline-time.monotonic()))[0]:raise ValueError
        finished,status=os.waitpid(pid,os.WNOHANG);reaped=finished==pid
        if not reaped or not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0:raise ValueError
        result=json.loads(raw)
        if not isinstance(result,dict):raise ValueError
        if result.get('status')=='applied':
            if (set(result)!={'status','configuration_sha256','wallet_sha256','configuration_backup'}
                    or result['configuration_sha256']!=hashlib.sha256(repair_configuration(evidence.configuration,evidence.wallet_name)).hexdigest()
                    or result['wallet_sha256']!={name:evidence.files[name]['sha256'] for name in SOURCES}
                    or result['configuration_backup']!='.alt-wallet-repair-'+operation_sha256):raise ValueError
        elif (set(result)!={'status','code'} or result['status'] not in ('rolled_back_verified','unknown')
                or result['code'] not in {'kwallet_rollback_verified','kwallet_rollback_unverified',
                    'kwallet_writer_identity_unverified','kwallet_transition_unverified'}):raise ValueError
        _record(directory,'file-result.json',{'schema_version':1,'operation_sha256':operation_sha256,'result':result})
        return result
    except WalletError:raise
    except Exception:raise WalletError('kwallet_writer_outcome_unverified') from None
    finally:
        for descriptor in descriptors:os.close(descriptor)
        if pid and not reaped:
            if pidfd is not None:
                try:signal.pidfd_send_signal(pidfd,signal.SIGKILL,None,0)
                except ProcessLookupError:pass
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                finished,_=os.waitpid(pid,os.WNOHANG)
                if finished==pid:break
                time.sleep(0.02)
        if pidfd is not None:os.close(pidfd)


def verify_wallet_bus(context):
    """Activate/check through the actual graphical user's bus, never SSH env."""
    try:
        started=time.monotonic()
        result=run_session_command(context,['/usr/bin/busctl','--user','--timeout=5','call',
            'org.kde.kwalletd6','/modules/kwalletd6','org.kde.KWallet','isEnabled'],timeout=7)
        if result.returncode or result.stdout.strip()!='b true':raise ValueError
        return {'enabled':True,'latency_ms':max(0,round((time.monotonic()-started)*1000))}
    except Exception:raise WalletError('kwallet_dbus_unverified') from None


@dataclass(frozen=True)
class WalletReadiness:
    disposition: str
    snapshot_sha256: str
    wallet: WalletEvidence = field(repr=False)
    daemons: DaemonEvidence = field(repr=False)


def observe_wallet(context,wallet_name='recovered-wallet',*,root=Path('/')):
    evidence=inspect_wallet(context,wallet_name,root=root)
    daemons=observe_daemons(context,root=root) if evidence.disposition=='repair' else DaemonEvidence(hashlib.sha256(b'[]').hexdigest(),())
    digest=hashlib.sha256(json.dumps({'wallet':evidence.snapshot_sha256,'daemons':daemons.snapshot_sha256},
        sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return WalletReadiness(evidence.disposition,digest,evidence,daemons)


@contextmanager
def _wallet_lock(root):
    import fcntl
    descriptor=None
    try:
        namespace=_private_directory(root,'/var/lib/alt-kwallet-empty-name-repair',create=True)
        descriptor=os.open(namespace/'repair.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        info=os.fstat(descriptor);owner=0 if root==Path('/') else os.getuid()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or info.st_size):raise ValueError
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise WalletError('kwallet_repair_busy') from None
        yield namespace
    except WalletError:raise
    except (OSError,ValueError,SessionError):raise WalletError('kwallet_lock_unverified') from None
    finally:
        if descriptor is not None:os.close(descriptor)


def _boot_id():
    value=_read(Path('/proc/sys/kernel/random/boot_id'),128).decode().strip()
    if not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value):raise ValueError
    return value


def _private_json(path,root):
    info=path.stat();owner=0 if root==Path('/') else os.getuid()
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=owner
            or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):raise ValueError
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError
            result[key]=value
        return result
    return json.loads(_read(path,2097152),object_pairs_hook=unique)


def _recorded_process_alive(value):
    if (not isinstance(value,dict) or any(type(value.get(key)) is not int or value[key]<=0
                                          for key in ('pid','start_ticks'))
            or value['pid']>2147483647):raise ValueError
    try:
        raw=_read(Path('/proc')/str(value['pid'])/'stat',4096).decode()
    except FileNotFoundError:return False
    ticks=int(raw.rsplit(')',1)[1].split()[19])
    # A changed UID, executable or orphaned PPID cannot prove the recorded
    # mutator stopped. Birth time plus this same boot identifies the process.
    return ticks==value['start_ticks']


def guard_previous_mutators(namespace,*,root=Path('/')):
    """A lost parent releases flock, but an acknowledged writer may still live."""
    try:
        root=Path(root);namespace=Path(namespace)
        if namespace!=_private_directory(root,'/var/lib/alt-kwallet-empty-name-repair'):raise ValueError
        paths=list(namespace.iterdir())
        if len(paths)>4096:raise ValueError
        boot=_boot_id()
        for directory in paths:
            if directory.name=='repair.lock':continue
            if not re.fullmatch('[0-9a-f]{64}',directory.name):raise ValueError
            _private_directory(root,'/var/lib/alt-kwallet-empty-name-repair/'+directory.name)
            manifest=_private_json(directory/'manifest.json',root)
            if (type(manifest.get('schema_version')) is not int or manifest['schema_version']!=1
                    or manifest['kind']!='confirmed_empty_wallet_backup'
                    or manifest['operation_sha256']!=directory.name
                    or not isinstance(manifest['boot_id'],str)
                    or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',manifest['boot_id'])):raise ValueError
            if manifest['boot_id']!=boot:continue
            helper=manifest['helper']
            if helper['pid']!=os.getpid() and _recorded_process_alive(helper):
                raise WalletError('kwallet_previous_mutator_active')
            path=directory/'writer.json'
            if path.exists() or path.is_symlink():
                writer=_private_json(path,root)
                if (type(writer.get('schema_version')) is not int or writer['schema_version']!=1
                        or writer['operation_sha256']!=directory.name or writer['boot_id']!=boot
                        or writer['snapshot_sha256']!=manifest['snapshot_sha256']
                        or writer['child']['uid']!=manifest['uid'] or writer['child']['gid']!=manifest['gid']):raise ValueError
                if _recorded_process_alive(writer['child']):raise WalletError('kwallet_previous_mutator_active')
    except WalletError:raise
    except Exception:raise WalletError('kwallet_previous_state_unverified') from None


def _verify_renamed(evidence,*,root,exact):
    context=evidence.context
    configuration=_file(_inside(root,context.home+'/.config/kwalletrc'),context,limit=131072)
    if configuration is None or _configuration(configuration['data']).get('Wallet','Default Wallet',fallback=None)!=evidence.wallet_name:
        raise WalletError('kwallet_postcondition_unverified')
    if exact and configuration['sha256']!=hashlib.sha256(repair_configuration(evidence.configuration,evidence.wallet_name)).hexdigest():
        raise WalletError('kwallet_postcondition_unverified')
    pairs=zip(SOURCES,(evidence.wallet_name+'.kwl',evidence.wallet_name+'.salt',evidence.wallet_name+'_attributes.json'))
    for old,new in pairs:
        if _inside(root,context.home+'/.local/share/kwalletd/'+old).exists():raise WalletError('kwallet_postcondition_unverified')
        value=_file(_inside(root,context.home+'/.local/share/kwalletd/'+new),context)
        if value is None or exact and not _same_file(value,evidence.files[old]):raise WalletError('kwallet_postcondition_unverified')


def repair_wallet(context,wallet_name,expected_snapshot_sha256,operation_sha256,*,root=Path('/'),native_context=None):
    """One claim: backup -> proven stop -> acknowledged writer -> actual GUI bus.

    The fixed CLI/native caller additionally binds machine, boot, helper source
    and confirmed operation context before entering this private coordinator.
    No automatic rollback is attempted after daemon activation is dispatched.
    """
    try:
        root=Path(root)
        if threading.active_count()!=1:raise ValueError
        for value in (expected_snapshot_sha256,operation_sha256):
            if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise ValueError
        if native_context is not None:
            validate_invocation(native_context,{'machine_uuid':native_context.get('machine_uuid')},operation_sha256)
        namespace=_inside(root,'/var/lib/alt-kwallet-empty-name-repair')
        if (namespace/operation_sha256).exists():raise WalletError('kwallet_claim_consumed')
        readiness=observe_wallet(context,wallet_name,root=root)
        if readiness.snapshot_sha256!=expected_snapshot_sha256:raise WalletError('kwallet_readiness_changed')
        if readiness.disposition=='noop' and not namespace.exists():return {'status':'noop','changed':False,'code':None}
        with _wallet_lock(root):
            guard_previous_mutators(namespace,root=root)
            _revalidate(context)
            fresh=observe_wallet(context,wallet_name,root=root)
            if fresh.snapshot_sha256!=expected_snapshot_sha256:raise WalletError('kwallet_readiness_changed')
            if fresh.disposition=='noop':return {'status':'noop','changed':False,'code':None}
            directory=create_backup(fresh.wallet,operation_sha256,root=root)
            _record(directory,'invocation.json',{'schema_version':1,'operation_sha256':operation_sha256,
                'readiness_sha256':fresh.snapshot_sha256,'daemon_sha256':fresh.daemons.snapshot_sha256,
                'uid':context.uid,'gid':context.gid,'snapshot_sha256':fresh.wallet.snapshot_sha256,
                'native_context':native_context})
            effects=False
            try:
                if observe_wallet(context,wallet_name,root=root).snapshot_sha256!=expected_snapshot_sha256:
                    raise WalletError('kwallet_readiness_changed')
                _record(directory,'stop.json',{'schema_version':1,'stage':'stop-requested','operation_sha256':operation_sha256})
                effects=True
                stop_daemons(context,fresh.daemons,root=root)
                _record(directory,'stopped.json',{'schema_version':1,'stage':'stop-confirmed','operation_sha256':operation_sha256})
                _revalidate(context)
                file_result=run_writer(fresh.wallet,operation_sha256,directory,root=root)
                if file_result['status']=='applied':
                    _revalidate(context)
                    _verify_renamed(fresh.wallet,root=root,exact=True)
                    _record(directory,'activation.json',{'schema_version':1,'stage':'activation-requested',
                        'operation_sha256':operation_sha256,'wallet_files_verified':3})
                    bus=verify_wallet_bus(context)
                    _revalidate(context)
                    active=observe_daemons(context,root=root)
                    if {p['executable'] for p in active.records}!=DAEMONS:raise WalletError('kwallet_dbus_unverified')
                    # Exact bytes were sealed above before service activation.
                    # Normal applications may now legitimately add secrets.
                    _verify_renamed(fresh.wallet,root=root,exact=False)
                    result={'status':'repaired','code':None,'changed':True,'wallet_files_verified':3,
                            'dbus_enabled':True,'latency_ms':bus['latency_ms']}
                else:
                    result={'status':file_result['status'],'code':file_result['code'],'changed':True}
            except Exception as error:
                code=str(error) if isinstance(error,WalletError) else ''
                safe={'kwallet_daemon_exit_unverified','kwallet_daemon_unverified','kwallet_writer_outcome_unverified',
                      'kwallet_dbus_unverified','kwallet_postcondition_unverified','kwallet_readiness_changed'}
                result={'status':'unknown' if effects else 'blocked','changed':effects,
                        'code':code if code in safe else 'kwallet_repair_outcome_unverified'}
            try:_record(directory,'result.json',{'schema_version':1,'operation_sha256':operation_sha256,'result':result})
            except Exception:raise WalletError('kwallet_repair_outcome_unverified') from None
            return result
    except WalletError:raise
    except Exception:raise WalletError('kwallet_repair_outcome_unverified') from None


HELPER='/usr/local/libexec/alt-kwallet-empty-name-repair'


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError
        result[key]=value
    return result


def _helper_state(root,expected,previous):
    try:
        if (not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected)
                or not isinstance(previous,list) or len(previous)>32 or len(set(previous))!=len(previous)
                or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in previous)):
            raise ValueError
        target=_inside(root,HELPER)
        if not target.exists():return False,None
        owner=0 if root==Path('/') else os.getuid()
        current=target.parent
        while current!=root:
            info=current.stat()
            if info.st_uid!=owner or info.st_mode & 0o022:raise ValueError
            current=current.parent
        info=target.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700
                or info.st_nlink!=1 or not 0<info.st_size<=1048576):raise ValueError
        digest=hashlib.sha256(_read(target,1048576)).hexdigest()
        if digest not in [expected,*previous]:raise ValueError
        return True,digest
    except Exception:raise WalletError('kwallet_helper_collision') from None


def _collect_target(request,*,root=Path('/'),call=_call,limits_reader=resource.prlimit):
    try:
        if (not isinstance(request,dict) or set(request)!={'schema_version','machine_uuid','hostname','login',
                'wallet_name','helper_sha256','previous_helper_sha256'}
                or type(request['schema_version']) is not int or request['schema_version']!=1
                or not isinstance(request['machine_uuid'],str) or str(uuid.UUID(request['machine_uuid']))!=request['machine_uuid']
                or not uuid.UUID(request['machine_uuid']).int
                or not isinstance(request['hostname'],str) or not re.fullmatch('[a-z][a-z0-9-]{0,62}',request['hostname'])
                or not isinstance(request['login'],str) or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,62}',request['login'])
                or request['login'] in ('root','ansible','osn-admin')):raise ValueError
        validate_wallet_name(request['wallet_name']);root=Path(root)
        machine=_read(root/'sys/class/dmi/id/product_uuid',128).decode().strip().lower()
        boot=_read(_inside(root,'/proc/sys/kernel/random/boot_id'),128).decode().strip()
        rc,hostname=call(['hostname','-s'])
        if (machine!=request['machine_uuid'] or rc or hostname.strip()!=request['hostname']
                or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot)):
            raise WalletError('kwallet_machine_unverified')
        installed,digest=_helper_state(root,request['helper_sha256'],request['previous_helper_sha256'])
        upn=request['login']+'@sosnadmin.local'
        rc,passwd=call(['getent','-s','sss','passwd',upn]);fields=passwd.strip().split(':')
        if (rc or len(passwd.splitlines())!=1 or len(fields)!=7 or fields[0].lower() not in (request['login'],upn)
                or not fields[2].isdigit() or not fields[3].isdigit() or int(fields[2])<=0 or int(fields[3])<=0):
            raise WalletError('kwallet_user_unverified')
        if not _inside(root,fields[5]).exists():raise WalletError('graphical_session_unavailable')
        context=discover_session(int(fields[2]),int(fields[3]),fields[5],root=root,call=call,limits_reader=limits_reader)
        readiness=observe_wallet(context,request['wallet_name'],root=root)
        namespace=_inside(root,'/var/lib/alt-kwallet-empty-name-repair')
        if namespace.exists():guard_previous_mutators(namespace,root=root)
        value={'schema_version':1,'machine_uuid':machine,'hostname':request['hostname'],'boot_id':boot,
            'login':request['login'],'uid':context.uid,'gid':context.gid,
            'wallet_name':request['wallet_name'],'helper_sha256':request['helper_sha256'],
            'installed_helper_sha256':digest,'helper_installed':installed,'disposition':readiness.disposition,
            'readiness_sha256':readiness.snapshot_sha256}
        value['snapshot_sha256']=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if (_read(root/'sys/class/dmi/id/product_uuid',128).decode().strip().lower()!=machine
                or _read(_inside(root,'/proc/sys/kernel/random/boot_id'),128).decode().strip()!=boot):
            raise WalletError('kwallet_machine_unverified')
        return value,readiness
    except WalletError:raise
    except SessionError as error:
        code=str(error) if str(error) in ('graphical_session_unavailable','graphical_session_ambiguous') else 'kwallet_target_unverified'
        raise WalletError(code) from None
    except Exception:raise WalletError('kwallet_target_unverified') from None


def observe_candidate(request,**options):
    return _collect_target(request,**options)[0]


def validate_invocation(context,observation,operation_sha256):
    try:
        if not isinstance(context,dict) or type(context.get('schema_version')) is not int or context['schema_version']!=1:raise ValueError
        kind=context.get('kind')
        if kind=='complete_workstation':
            keys={'schema_version','kind','phase','job_id','claim_sha256','plan_sha256','workflow_policy_sha256',
                  'machine_uuid','source_sha256','policy_sha256'}
            if set(context)!=keys or context['phase']!='user' or context['claim_sha256']!=operation_sha256:raise ValueError
            digests=('claim_sha256','plan_sha256','workflow_policy_sha256','source_sha256','policy_sha256')
        elif kind=='component_wallet_repair':
            keys={'schema_version','kind','job_id','component_id','plan_sha256','machine_uuid','source_sha256','operation_sha256'}
            if (set(context)!=keys or context['component_id']!='desktop.kwallet_repair'
                    or context['operation_sha256']!=operation_sha256):raise ValueError
            digests=('plan_sha256','source_sha256','operation_sha256')
        else:raise ValueError
        if (context['machine_uuid']!=observation['machine_uuid'] or not isinstance(context['machine_uuid'],str)
                or str(uuid.UUID(context['machine_uuid']))!=context['machine_uuid'] or not uuid.UUID(context['machine_uuid']).int
                or not isinstance(context['job_id'],str) or not re.fullmatch('job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',context['job_id'])
                or any(not isinstance(context[key],str) or not re.fullmatch('[0-9a-f]{64}',context[key]) for key in digests)):
            raise ValueError
        return dict(context)
    except Exception:raise WalletError('kwallet_native_context_unverified') from None


def main():
    try:
        if os.geteuid()!=0:raise WalletError('kwallet_privilege_required')
        import argparse
        class Parser(argparse.ArgumentParser):
            def error(self,message):raise WalletError('kwallet_request_unverified')
        parser=Parser(add_help=False,allow_abbrev=False)
        operation=parser.add_mutually_exclusive_group(required=True)
        operation.add_argument('--observe',action='store_true');operation.add_argument('--apply',action='store_true')
        for name in ('machine-uuid','hostname','user','wallet-name','helper-sha256'):parser.add_argument('--'+name,required=True)
        parser.add_argument('--expected-readiness-sha256');parser.add_argument('--operation-sha256')
        args=parser.parse_args()
        if Path(sys.argv[0])!=Path(HELPER):raise WalletError('kwallet_helper_source_unverified')
        request={'schema_version':1,'machine_uuid':args.machine_uuid,'hostname':args.hostname,'login':args.user,
                 'wallet_name':args.wallet_name,'helper_sha256':args.helper_sha256,'previous_helper_sha256':[]}
        observation,readiness=_collect_target(request)
        if observation['installed_helper_sha256']!=args.helper_sha256:raise WalletError('kwallet_helper_source_unverified')
        if args.observe:
            if args.expected_readiness_sha256 is not None or args.operation_sha256 is not None:raise ValueError
            print(json.dumps({'schema_version':1,'status':'ok','observation':observation}));return 0
        raw=sys.stdin.read(8193)
        if len(raw.encode())>8192:raise ValueError
        context=validate_invocation(json.loads(raw,object_pairs_hook=unique),observation,args.operation_sha256)
        if args.expected_readiness_sha256!=readiness.snapshot_sha256:raise WalletError('kwallet_readiness_changed')
        result=repair_wallet(readiness.wallet.context,args.wallet_name,readiness.snapshot_sha256,args.operation_sha256,
                             native_context=context)
        after,_=_collect_target(request)
        if any(after[key]!=observation[key] for key in ('machine_uuid','hostname','boot_id','helper_sha256','installed_helper_sha256')):
            raise WalletError('kwallet_machine_unverified')
        good=result['status'] in ('noop','repaired')
        print(json.dumps({'schema_version':1,'status':'ok' if good else 'blocked','result':result,
                          'helper_sha256':args.helper_sha256,'operation_sha256':args.operation_sha256}))
        return 0 if good else 4
    except Exception as error:
        code=str(error) if isinstance(error,(WalletError,SessionError)) else ''
        if code not in WALLET_CODES:code='kwallet_target_unverified'
        print(json.dumps({'schema_version':1,'status':'blocked','code':code}));return 4
