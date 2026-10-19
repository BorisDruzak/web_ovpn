"""Fixed managed KRFB configuration; values remain private on the target."""
from __future__ import annotations

from dataclasses import dataclass,field
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

from .krfb_user_session import KRFBSessionError,_ini,_configuration_ready,_autostart_ready,_collect,_owned
from .user_session import SessionContext,SessionError,_inside,_read,_trusted_program,_call


_SETTINGS = {
    'MainWindow':{'startMinimized'},
    'FrameBuffer':{'preferredFrameBufferPlugin'},
    'Security':{'allowDesktopControl','allowUnattendedAccess','noWallet','desktopPassword','unattendedPassword'},
    'TCP':{'useDefaultPort','port'},
}


def validate_runtime_request(request):
    """Only a fixed native user-phase request can reach runtime operations."""
    try:
        if (not isinstance(request,dict) or set(request)!={'schema_version','machine_uuid','hostname','login',
                'source_sha256','policy_sha256','expected_snapshot_sha256','policy_helper_sha256',
                'expected_policy_snapshot_sha256','configuration','autostart','context',
                'configuration_template_sha256','autostart_template_sha256'}
                or type(request['schema_version']) is not int or request['schema_version']!=1
                or not isinstance(request['machine_uuid'],str)
                or str(uuid.UUID(request['machine_uuid']))!=request['machine_uuid'] or not uuid.UUID(request['machine_uuid']).int
                or not isinstance(request['hostname'],str) or not re.fullmatch('[a-z][a-z0-9-]{0,62}',request['hostname'])
                or not isinstance(request['login'],str) or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,62}',request['login'])
                or request['login'] in ('root','ansible','osn-admin')):raise ValueError
        for key in ('source_sha256','policy_sha256','expected_snapshot_sha256','policy_helper_sha256','expected_policy_snapshot_sha256',
                    'configuration_template_sha256','autostart_template_sha256'):
            if not isinstance(request[key],str) or not re.fullmatch('[0-9a-f]{64}',request[key]):raise ValueError
        for key,limit in (('configuration',32768),('autostart',4096)):
            if not isinstance(request[key],str) or not 0<len(request[key].encode('utf-8'))<=limit:raise ValueError
            if hashlib.sha256(request[key].encode('utf-8')).hexdigest()!=request[key+'_template_sha256']:raise ValueError
        context = request['context']
        if (not isinstance(context,dict) or set(context)!={'schema_version','kind','phase','job_id','claim_sha256',
                'plan_sha256','workflow_policy_sha256','machine_uuid','source_sha256','policy_sha256'}
                or type(context['schema_version']) is not int or context['schema_version']!=1
                or context['kind']!='complete_workstation' or context['phase']!='user'
                or not isinstance(context['job_id'],str)
                or not re.fullmatch('job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',context['job_id'])
                or any(context[key]!=request[key] for key in ('machine_uuid','source_sha256','policy_sha256'))):raise ValueError
        for key in ('claim_sha256','plan_sha256','workflow_policy_sha256'):
            if not isinstance(context[key],str) or not re.fullmatch('[0-9a-f]{64}',context[key]):raise ValueError
        return True
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError):
        raise KRFBSessionError('krfb_runtime_request_unverified') from None


@dataclass(frozen=True)
class RuntimeAssessment:
    disposition: str
    needs_reload: bool
    snapshot: dict = field(repr=False)
    policy: dict = field(repr=False)
    context: SessionContext = field(repr=False)
    process: dict | None = field(repr=False)
    configuration: bytes = field(repr=False)
    autostart: bytes = field(repr=False)


def read_direct_policy(request,*,root=Path('/'),run=None):
    """Execute only the exact already-installed root policy observer."""
    try:
        root = Path(root)
        target = _inside(root,'/usr/local/libexec/alt-vnc-access-policy')
        info = target.stat();owner = 0 if root==Path('/') else os.getuid()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700
                or info.st_nlink!=1 or info.st_size>65536):raise ValueError
        source = _read(target)
        if hashlib.sha256(source).hexdigest()!=request['policy_helper_sha256']:raise ValueError
        namespace = {'__name__':'_fixed_direct_policy_observer'}
        exec(compile(source,'<fixed-direct-policy-observer>','exec'),namespace)
        options = {} if run is None else {'run':run}
        value = namespace['observe_policy'](root,request['machine_uuid'],request['hostname'],request['source_sha256'],**options)
        if (value['ready'] is not True or value['machine_uuid']!=request['machine_uuid']
                or value['hostname']!=request['hostname'] or value['source_sha256']!=request['source_sha256']
                or value['policy_sha256']!=request['policy_sha256']):raise ValueError
        return value
    except Exception:
        raise KRFBSessionError('krfb_vnc_policy_unverified') from None


def assess_runtime(request,*,root=Path('/'),call=_call,limits_reader=resource.prlimit):
    """Readiness may run before a claim; it has no mutating operation selector."""
    try:
        if (not isinstance(request,dict) or set(request)!={'schema_version','machine_uuid','hostname','login',
                'source_sha256','policy_sha256','policy_helper_sha256','configuration','autostart'}
                or type(request['schema_version']) is not int or request['schema_version']!=1):raise ValueError
        for key in ('source_sha256','policy_sha256','policy_helper_sha256'):
            if not isinstance(request[key],str) or not re.fullmatch('[0-9a-f]{64}',request[key]):raise ValueError
        for key,limit in (('configuration',32768),('autostart',4096)):
            if not isinstance(request[key],str) or not 0<len(request[key].encode())<=limit:raise ValueError
        root = Path(root)
        snapshot,context,process = _collect({key:request[key] for key in ('machine_uuid','hostname','login')},
                                           root=root,call=call,limits_reader=limits_reader)
        policy = read_direct_policy(request,root=root)
        if (policy['ready'] is not True or any(policy[key]!=request[key]
                for key in ('machine_uuid','hostname','source_sha256','policy_sha256'))
                or policy['boot_id']!=snapshot['boot_id']):raise ValueError
        existing = _owned(root,context.home+'/.config/krfbrc',context.uid,context.gid,0o600)
        existing_autostart = _owned(root,context.home+'/.config/autostart/org.sosn.krfb.desktop',context.uid,context.gid,0o644)
        for key,data in (('configuration_sha256',existing),('autostart_sha256',existing_autostart)):
            if (hashlib.sha256(data).hexdigest() if data is not None else None)!=snapshot[key]:raise ValueError
        configuration = prepare_configuration(existing,request['configuration'].encode(),context)
        autostart = validate_autostart(request['autostart'].encode())
        config_changed = configuration!=existing
        changed = config_changed or autostart!=existing_autostart
        disposition = ('noop' if not changed and process is not None and snapshot['listener_present'] else
                       'waiting_vnc_clients' if snapshot['connected_clients'] else 'apply')
        return RuntimeAssessment(disposition,process is not None and config_changed,snapshot,policy,
                                 context,process,configuration,autostart)
    except KRFBSessionError:raise
    except SessionError as error:
        code = str(error) if str(error) in ('graphical_session_unavailable','graphical_session_ambiguous') else 'krfb_graphical_session_unverified'
        raise KRFBSessionError(code) from None
    except Exception:
        raise KRFBSessionError('krfb_runtime_readiness_unverified') from None


def _private_directory(root,absolute,*,create=False):
    target = _inside(root,absolute)
    if create:
        try:target.mkdir(mode=0o700)
        except FileExistsError:pass
    info = target.stat();owner = 0 if root==Path('/') else os.getuid()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError
    return target


def _write_private(path,data):
    descriptor = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream:
        os.fchmod(stream.fileno(),0o600)
        stream.write(data);stream.flush();os.fsync(stream.fileno())


def _sync_directory(path):
    descriptor = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def _self_identity():
    directory = Path('/proc')/str(os.getpid())
    fields = _read(directory/'stat',4096).decode().rsplit(')',1)[1].split()
    ticks = int(fields[19])
    if ticks<=0:raise ValueError
    return {'pid':os.getpid(),'start_ticks':ticks,'uid':os.geteuid(),'gid':os.getegid(),
            'command_sha256':hashlib.sha256(_read(directory/'cmdline',131072)).hexdigest()}


def create_runtime_backup(request,assessment,*,root=Path('/')):
    """Seal the original files and helper identity before the first user effect."""
    try:
        validate_runtime_request(request)
        if (not isinstance(assessment,RuntimeAssessment)
                or assessment.snapshot['snapshot_sha256']!=request['expected_snapshot_sha256']
                or assessment.policy['snapshot_sha256']!=request['expected_policy_snapshot_sha256']
                or assessment.disposition!='apply'):raise ValueError
        root = Path(root);context=assessment.context
        files = {}
        for name,absolute,mode,key in (
            ('krfbrc',context.home+'/.config/krfbrc',0o600,'configuration_sha256'),
            ('autostart.desktop',context.home+'/.config/autostart/org.sosn.krfb.desktop',0o644,'autostart_sha256')):
            data = _owned(root,absolute,context.uid,context.gid,mode)
            if (hashlib.sha256(data).hexdigest() if data is not None else None)!=assessment.snapshot[key]:raise ValueError
            if data is not None:files[name]=data
        namespace = _private_directory(root,'/var/lib/alt-krfb-user-runtime',create=True)
        directory = namespace/request['context']['claim_sha256']
        try:directory.mkdir(mode=0o700)
        except FileExistsError:raise KRFBSessionError('krfb_runtime_claim_consumed') from None
        _private_directory(root,'/var/lib/alt-krfb-user-runtime/'+request['context']['claim_sha256'])
        manifest = {'schema_version':1,'kind':'complete_workstation_krfb_backup',
            'context':request['context'],'helper':_self_identity(),
            'snapshot_sha256':assessment.snapshot['snapshot_sha256'],
            'policy_snapshot_sha256':assessment.policy['snapshot_sha256'],
            'configuration_template_sha256':request['configuration_template_sha256'],
            'autostart_template_sha256':request['autostart_template_sha256'],
            'home':context.home,'uid':context.uid,'gid':context.gid,
            'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()},
            'absent_files':sorted({'krfbrc','autostart.desktop'}-set(files))}
        for name,data in files.items():_write_private(directory/name,data)
        encoded = json.dumps(manifest,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        _write_private(directory/'manifest.json',encoded)
        if _read(directory/'manifest.json')!=encoded:raise ValueError
        for name,digest in manifest['files'].items():
            target=directory/name;info=target.stat();owner=0 if root==Path('/') else os.getuid()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o600
                    or info.st_nlink!=1 or hashlib.sha256(_read(target)).hexdigest()!=digest):raise ValueError
        for parent in (directory,namespace,namespace.parent):_sync_directory(parent)
        return directory
    except KRFBSessionError:raise
    except Exception:
        raise KRFBSessionError('krfb_runtime_backup_unverified') from None


def _password_supported(value):
    if not isinstance(value,str) or not 0<len(value)<=256:return False
    decoded = ''.join(ch if ord(ch)<=0x21 else chr((0x1001f-ord(ch))&0xffff) for ch in value)
    return bool(decoded.strip()) and all(0x20<=ord(ch)<=0x7e for ch in decoded)


def prepare_configuration(existing,desired,context):
    """Patch only published keys, retaining comments and unrelated KDE groups."""
    try:
        if (not isinstance(desired,bytes) or not 0<len(desired)<=32768
                or existing is not None and (not isinstance(existing,bytes) or len(existing)>65536)):
            raise ValueError
        settings = _ini(desired)
        if (not _configuration_ready(desired,context)
                or any(group not in _SETTINGS or not set(settings[group])<=_SETTINGS[group] for group in settings.sections())
                or any(not _password_supported(settings.get('Security',key))
                       for key in ('desktopPassword','unattendedPassword'))):raise ValueError
        current = _ini(existing)
        if current is not None and all(current.get(group,key,fallback=None)==value
                for group in settings.sections() for key,value in settings[group].items()):
            return existing
        remaining = {group:dict(settings[group]) for group in settings.sections()}
        original = '' if existing is None else existing.decode('utf-8')
        newline = '\r\n' if '\r\n' in original else '\n'
        output = [];seen = set();active = None

        def append(line):
            if output and not output[-1].endswith(('\n','\r')):output[-1]+=newline
            output.append(line)

        def finish(group):
            for key,value in remaining.get(group,{}).items():append(key+'='+value+newline)
            if group in remaining:remaining[group]={}

        for line in original.splitlines(keepends=True):
            header = re.fullmatch(r'\[(.+)\]\s*',line.strip())
            if header:
                finish(active);active=header[1];seen.add(active);output.append(line)
                continue
            key,separator,_ = line.partition('=')
            key = key.strip()
            if separator and active in remaining and key in remaining[active]:
                append(line.split('=',1)[0]+'='+remaining[active].pop(key)+newline)
            else:output.append(line)
        finish(active)
        for group in settings.sections():
            if group not in seen:
                append('['+group+']'+newline);finish(group)
        result = ''.join(output).encode('utf-8')
        verified = _ini(result)
        if not _configuration_ready(result,context) or any(verified.get(group,key,fallback=None)!=value
                for group in settings.sections() for key,value in settings[group].items()):raise ValueError
        return result
    except (ValueError,TypeError,KeyError,UnicodeError,configparser.Error,KRFBSessionError):
        raise KRFBSessionError('krfb_configuration_unverified') from None


def validate_autostart(data):
    try:
        if not isinstance(data,bytes) or not 0<len(data)<=4096:raise ValueError
        settings = _ini(data)
        allowed = {'Type','Name','Exec','OnlyShowIn','X-KDE-autostart-after','X-KDE-StartupNotify','Terminal'}
        if (settings.sections()!=['Desktop Entry'] or not set(settings['Desktop Entry'])<=allowed
                or not _autostart_ready(data)
                or settings.get('Desktop Entry','OnlyShowIn',fallback='KDE;')!='KDE;'
                or settings.get('Desktop Entry','Terminal',fallback='false')!='false'):raise ValueError
        return data
    except (ValueError,TypeError,KeyError,UnicodeError,configparser.Error,KRFBSessionError):
        raise KRFBSessionError('krfb_autostart_unverified') from None


def _directory(name,uid,gid,*,parent=None,create=False):
    if create:
        try:os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError:pass
    descriptor = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
    info = os.fstat(descriptor)
    if info.st_uid!=uid or info.st_gid!=gid or info.st_mode & 0o022:
        os.close(descriptor);raise ValueError
    return descriptor


def _current(directory,name,uid,gid,mode):
    try:info = os.stat(name,dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError:return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_gid!=gid
            or stat.S_IMODE(info.st_mode)!=mode or info.st_nlink!=1 or info.st_size>65536):raise ValueError
    descriptor = os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):raise ValueError
        with os.fdopen(descriptor,'rb',closefd=False) as stream:data = stream.read(65537)
        if len(data)>65536:raise ValueError
        return hashlib.sha256(data).hexdigest()
    finally:os.close(descriptor)


def _write_as_user(context,contents,expected,root):
    descriptors = []
    try:
        home = _directory(str(_inside(root,context.home)),context.uid,context.gid);descriptors.append(home)
        config = _directory('.config',context.uid,context.gid,parent=home,create=True);descriptors.append(config)
        autostart = _directory('autostart',context.uid,context.gid,parent=config,create=True);descriptors.append(autostart)
        targets = [(config,'krfbrc',0o600),(autostart,'org.sosn.krfb.desktop',0o644)]
        for directory,name,mode in targets:
            if _current(directory,name,context.uid,context.gid,mode)!=expected[name]:raise ValueError
        for directory,name,mode in targets:
            if hashlib.sha256(contents[name]).hexdigest()==expected[name]:continue
            temporary = '.alt-krfb-'+uuid.uuid4().hex
            descriptor = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=directory)
            try:
                with os.fdopen(descriptor,'wb',closefd=False) as stream:
                    stream.write(contents[name]);stream.flush();os.fchmod(descriptor,mode);os.fsync(descriptor)
                if _current(directory,name,context.uid,context.gid,mode)!=expected[name]:raise ValueError
                os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(descriptor)
                try:os.unlink(temporary,dir_fd=directory)
                except FileNotFoundError:pass
        for directory,name,mode in targets:
            if _current(directory,name,context.uid,context.gid,mode)!=hashlib.sha256(contents[name]).hexdigest():raise ValueError
    finally:
        for descriptor in reversed(descriptors):os.close(descriptor)


def _writer_identity(pid,context,executable):
    directory = Path('/proc')/str(pid)
    status = dict(line.split(':',1) for line in _read(directory/'status',16384).decode().splitlines() if ':' in line)
    if (status.get('Uid','').split()!=[str(context.uid)]*4
            or status.get('Gid','').split()!=[str(context.gid)]*4
            or int(status.get('PPid','0'))!=os.getpid()
            or os.readlink(directory/'exe')!=executable):raise ValueError
    fields = _read(directory/'stat',4096).decode().rsplit(')',1)[1].split()
    ticks = int(fields[19])
    if ticks<=0:raise ValueError
    return {'pid':pid,'start_ticks':ticks,'parent_pid':os.getpid(),'uid':context.uid,'gid':context.gid}


def write_user_configuration(context,contents,expected,*,register_child,root=Path('/')):
    """Write only two fixed files in a bounded new child after dropping root.

    A parent/child handshake prevents writes before the parent owns its pidfd.
    No user application is selected for this writer's deadline cleanup.
    """
    pid = descriptor = reader = writer = ready_reader = ready_writer = None
    reaped = False
    try:
        keys = {'krfbrc','org.sosn.krfb.desktop'}
        if (not isinstance(context,SessionContext) or threading.active_count()!=1 or not callable(register_child)
                or not isinstance(contents,dict) or set(contents)!=keys or not isinstance(expected,dict) or set(expected)!=keys
                or any(not isinstance(data,bytes) or not 0<len(data)<=65536 for data in contents.values())
                or any(value is not None and (not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value))
                       for value in expected.values())
                or os.geteuid()!=0 and (os.geteuid()!=context.uid or os.getegid()!=context.gid
                                      or tuple(os.getgroups())!=context.groups)):raise ValueError
        executable = _trusted_program([sys.executable])
        reader,writer = os.pipe();ready_reader,ready_writer = os.pipe()
        inherited = [int(name) for name in os.listdir('/proc/self/fd') if name.isdigit()]
        pid = os.fork()
        if pid==0:
            try:
                for opened in inherited:
                    if opened>2 and opened not in (reader,ready_writer):
                        try:os.close(opened)
                        except OSError:pass
                null = os.open('/dev/null',os.O_RDWR)
                for opened in (0,1,2):os.dup2(null,opened)
                if null>2:os.close(null)
                os.umask(0o077)
                for key,values in context.limits.items():resource.setrlimit(key,values)
                if os.geteuid()==0:
                    os.setgroups(context.groups);os.setgid(context.gid);os.setuid(context.uid)
                os.write(ready_writer,b'R');os.close(ready_writer)
                if os.read(reader,1)!=b'1':raise ValueError
                os.close(reader)
                _write_as_user(context,contents,expected,Path(root))
                os._exit(0)
            except BaseException:os._exit(4)
        os.close(reader);reader=None
        os.close(ready_writer);ready_writer=None
        descriptor = os.pidfd_open(pid,0)
        if not select.select([ready_reader],[],[],10)[0] or os.read(ready_reader,1)!=b'R':raise ValueError
        identity = _writer_identity(pid,context,executable)
        if register_child(identity) is not True or _writer_identity(pid,context,executable)!=identity:raise ValueError
        os.write(writer,b'1');os.close(writer);writer=None
        if not select.select([descriptor],[],[],10)[0]:
            signal.pidfd_send_signal(descriptor,signal.SIGKILL,None,0)
            raise ValueError
        finished,status = os.waitpid(pid,os.WNOHANG)
        reaped = finished==pid
        if not reaped or not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0:raise ValueError
    except Exception:
        raise KRFBSessionError('krfb_runtime_write_unverified') from None
    finally:
        if reader is not None:os.close(reader)
        if writer is not None:os.close(writer)
        if ready_reader is not None:os.close(ready_reader)
        if ready_writer is not None:os.close(ready_writer)
        if pid and not reaped:
            # Before the handshake, EOF releases a child which cannot write.
            # Afterwards the immutable descriptor identifies only our child.
            if descriptor is not None:
                try:signal.pidfd_send_signal(descriptor,signal.SIGKILL,None,0)
                except ProcessLookupError:pass
            deadline = time.monotonic()+2
            while time.monotonic()<deadline:
                finished,_ = os.waitpid(pid,os.WNOHANG)
                if finished==pid:break
                time.sleep(0.02)
        if descriptor is not None:os.close(descriptor)
