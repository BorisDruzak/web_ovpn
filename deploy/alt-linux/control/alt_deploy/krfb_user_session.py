"""Read-only selected-user KRFB evidence; never emit configuration or pixels."""
from __future__ import annotations

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
import subprocess
import sys
import threading

from .user_session import SessionError, _call, _inside, _process, _read, _revalidate, _trusted_program, discover_session


class KRFBSessionError(Exception):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def _owned(root, absolute, uid, gid, mode):
    path = _inside(root,absolute)
    if not path.exists():return None
    before = path.stat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_gid!=gid
            or stat.S_IMODE(before.st_mode)!=mode or before.st_nlink!=1 or before.st_size>65536):
        raise KRFBSessionError('krfb_configuration_unverified')
    descriptor = os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(descriptor,'rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(65537)
        after = os.fstat(stream.fileno())
    fingerprint = lambda info:(info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns,info.st_size)
    if len(data)>65536 or fingerprint(before)!=fingerprint(opened) or fingerprint(opened)!=fingerprint(after):
        raise KRFBSessionError('krfb_configuration_unverified')
    return data


def _ini(data):
    if data is None:return None
    if b'\0' in data:raise KRFBSessionError('krfb_configuration_unverified')
    # KDE treats [DEFAULT] as an ordinary group; Python's default inheritance
    # would otherwise accept security values that KRFB does not actually read.
    parser = configparser.ConfigParser(interpolation=None,strict=True,default_section='\0')
    parser.optionxform = str
    parser.read_string(data.decode('utf-8'))
    return parser


def _configuration_ready(data, context):
    parser = _ini(data)
    if parser is None:return False
    checks = [('MainWindow','startMinimized','true'),
              ('FrameBuffer','preferredFrameBufferPlugin','xcb' if context.environment['XDG_SESSION_TYPE']=='x11' else 'pw'),
              ('Security','allowDesktopControl','true'),('Security','allowUnattendedAccess','true'),
              ('Security','noWallet','true')]
    return (all(parser.get(group,key,fallback=None)==value for group,key,value in checks)
        and all(bool(parser.get('Security',key,fallback='').strip()) for key in ('desktopPassword','unattendedPassword'))
        and parser.get('TCP','port',fallback='5900')=='5900'
        and parser.get('TCP','useDefaultPort',fallback='true')=='true')


def _autostart_ready(data):
    parser = _ini(data)
    if parser is None:return False
    return (parser.get('Desktop Entry','Type',fallback=None)=='Application'
            and parser.get('Desktop Entry','Exec',fallback=None)=='/usr/bin/krfb'
            and parser.get('Desktop Entry','Hidden',fallback='false')=='false'
            and parser.get('Desktop Entry','X-GNOME-Autostart-enabled',fallback='true')=='true')


def _sockets(root, record, uid):
    rows = []
    for name in ('tcp','tcp6'):
        # /proc/net is normally a symlink. Use this observer's fixed numeric
        # process directory to read the same kernel network namespace safely.
        table = _read(_inside(root,'/proc/'+str(os.getpid())+'/net/'+name),2097152).decode('ascii').splitlines()
        for line in table[1:]:
            fields = line.split()
            if len(fields)<10:raise KRFBSessionError('krfb_listener_unverified')
            address,port = fields[1].split(':')
            if int(port,16)!=5900 or fields[3]=='06':continue
            if (not re.fullmatch('[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}',address)
                    or not re.fullmatch('[0-9A-Fa-f]{2}',fields[3])):
                raise KRFBSessionError('krfb_listener_unverified')
            rows.append((fields[3],int(fields[7]),int(fields[9])))
    if len(rows)>1024:raise KRFBSessionError('krfb_listener_unverified')
    inodes = set()
    if record is not None:
        directory = _inside(root,'/proc/'+str(record['pid'])+'/fd')
        descriptors = list(directory.iterdir())
        if len(descriptors)>65536:raise KRFBSessionError('krfb_listener_unverified')
        for descriptor in descriptors:
            try:target = os.readlink(descriptor)
            except FileNotFoundError:continue
            match = re.fullmatch(r'socket:\[([0-9]+)\]',target)
            if match:inodes.add(int(match[1]))
    if any(owner!=uid or inode not in inodes or inode<=0 for _,owner,inode in rows):
        raise KRFBSessionError('krfb_listener_unverified')
    return any(state=='0A' for state,_,_ in rows),sum(state!='0A' for state,_,_ in rows)


def _collect(request, *, root, call, limits_reader):
    if (not isinstance(request,dict) or set(request)!={'machine_uuid','hostname','login'}
            or not isinstance(request['machine_uuid'],str)
            or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',request['machine_uuid'])
            or not isinstance(request['hostname'],str)
            or not re.fullmatch('[a-z][a-z0-9-]{0,62}',request['hostname'])
            or not isinstance(request['login'],str)
            or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,62}',request['login'])
            or request['login'] in ('root','ansible','osn-admin')):
        raise KRFBSessionError('krfb_user_identity_unverified')
    machine_uuid = _read(root/'sys/class/dmi/id/product_uuid').decode().strip().lower()
    boot = _read(_inside(root,'/proc/sys/kernel/random/boot_id')).decode().strip()
    rc, hostname = call(['hostname','-s'])
    if (rc or machine_uuid!=request['machine_uuid'] or hostname.strip()!=request['hostname']
            or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot)):
        raise KRFBSessionError('krfb_machine_unverified')
    upn = request['login']+'@sosnadmin.local'
    rc, account = call(['getent','-s','sss','passwd',upn])
    fields = account.strip().split(':')
    if (rc or len(account.splitlines())!=1 or len(fields)!=7 or fields[0].lower() not in (request['login'],upn)
            or not fields[2].isdigit() or not fields[3].isdigit()):
        raise KRFBSessionError('krfb_user_identity_unverified')
    uid,gid,home = int(fields[2]),int(fields[3]),fields[5]
    if not _inside(root,home).exists():
        raise KRFBSessionError('graphical_session_unavailable')
    context = discover_session(uid,gid,home,root=root,call=call,limits_reader=limits_reader)
    configuration = _owned(root,home+'/.config/krfbrc',uid,gid,0o600)
    autostart = _owned(root,home+'/.config/autostart/org.sosn.krfb.desktop',uid,gid,0o644)
    records = []
    directories = [p for p in _inside(root,'/proc').iterdir() if p.name.isdigit()]
    if len(directories)>65536:raise KRFBSessionError('krfb_process_unverified')
    for directory in directories:
        record = _process(root,directory,uid,gid,{'/usr/bin/krfb'})
        if record is None:continue
        if any(record['environment'].get(key)!=context.environment.get(key) for key in
               ('HOME','DISPLAY','WAYLAND_DISPLAY','XDG_SESSION_ID','XDG_SESSION_TYPE','XDG_RUNTIME_DIR',
                'DBUS_SESSION_BUS_ADDRESS','KDE_SESSION_VERSION')):
            raise KRFBSessionError('krfb_process_unverified')
        records.append(record)
    if len(records)>1:raise KRFBSessionError('krfb_process_unverified')
    record = records[0] if records else None
    listener, clients = _sockets(root,record,uid)
    if record is not None and _process(root,root/'proc'/str(record['pid']),uid,gid,{'/usr/bin/krfb'})!=record:
        raise KRFBSessionError('krfb_process_unverified')
    if discover_session(uid,gid,home,root=root,call=call,limits_reader=limits_reader)!=context:
        raise KRFBSessionError('krfb_process_unverified')
    if (_read(root/'sys/class/dmi/id/product_uuid').decode().strip().lower()!=machine_uuid
            or _read(_inside(root,'/proc/sys/kernel/random/boot_id')).decode().strip()!=boot):
        raise KRFBSessionError('krfb_machine_unverified')
    # Only digests of private state leave the target; no environment, secret,
    # address of a connected client, desktop name or configuration value.
    private_context = dict(environment=context.environment,limits=context.limits,groups=context.groups,
        home=home,session=context.session_id,pid=context.pid,start=context.start_ticks,
        launcher=context.launcher_pid,launcher_start=context.launcher_start_ticks)
    value = {'schema_version':1,'machine_uuid':machine_uuid,'hostname':request['hostname'],'boot_id':boot,
        'login':request['login'],'uid':uid,'gid':gid,'session_id':context.session_id,
        'session_sha256':_digest(private_context),'krfb_pid':record['pid'] if record else None,
        'krfb_start_ticks':record['start_ticks'] if record else None,'listener_present':listener,
        'connected_clients':clients,'configuration_safe':_configuration_ready(configuration,context),
        'autostart_safe':_autostart_ready(autostart),
        'configuration_sha256':hashlib.sha256(configuration).hexdigest() if configuration is not None else None,
        'autostart_sha256':hashlib.sha256(autostart).hexdigest() if autostart is not None else None}
    value['snapshot_sha256'] = _digest(value)
    return value,context,record


def observe_session(request, *, root=Path('/'),call=_call,limits_reader=resource.prlimit):
    try:
        return _collect(request,root=Path(root),call=call,limits_reader=limits_reader)[0]
    except KRFBSessionError:
        raise
    except SessionError as error:
        code = str(error)
        if code not in ('graphical_session_unavailable','graphical_session_ambiguous'):
            code = 'krfb_graphical_session_unverified'
        raise KRFBSessionError(code) from None
    except (OSError,ValueError,TypeError,KeyError,AttributeError,configparser.Error):
        raise KRFBSessionError('krfb_session_observation_unverified') from None


def stop_krfb(context, record, *, root=Path('/')):
    """One SIGTERM to an immutable pidfd, after fresh GUI/client checks.

    This internal operation is called only inside the claimed target helper's
    lock, after its private backup and approved configuration are durable.
    Existing desktop, RDP and other application processes are never selected.
    """
    descriptor = None
    dispatched = False
    try:
        root = Path(root)
        _revalidate(context)
        if (not isinstance(record,dict) or record.get('executable')!='/usr/bin/krfb'
                or type(record.get('pid')) is not int or record['pid']<=0):
            raise KRFBSessionError('krfb_process_unverified')
        descriptor = os.pidfd_open(record['pid'],0)
        current = _process(root,root/'proc'/str(record['pid']),context.uid,context.gid,{'/usr/bin/krfb'})
        if current!=record or select.select([descriptor],[],[],0)[0]:
            raise KRFBSessionError('krfb_process_unverified')
        _revalidate(context)
        if _sockets(root,record,context.uid)[1]:
            raise KRFBSessionError('krfb_clients_connected')
        dispatched = True
        signal.pidfd_send_signal(descriptor,signal.SIGTERM,None,0)
        if (not select.select([descriptor],[],[],10)[0]
                or _process(root,root/'proc'/str(record['pid']),context.uid,context.gid,{'/usr/bin/krfb'}) is not None):
            raise KRFBSessionError('krfb_runtime_outcome_unverified')
    except KRFBSessionError:
        raise
    except (OSError,ValueError,TypeError,KeyError,AttributeError,SessionError):
        raise KRFBSessionError('krfb_runtime_outcome_unverified' if dispatched else 'krfb_process_unverified') from None
    finally:
        if descriptor is not None:os.close(descriptor)


_DISPATCH_GATE = ('import os,sys\n'
    'if sys.stdin.buffer.read(1)!=b"1": sys.exit(4)\n'
    'os.close(0)\n'
    'os.open("/dev/null",os.O_RDONLY)\n'
    'os.execve(sys.argv[1],sys.argv[1:],os.environ)\n')


def krfb_scope(context):
    if not re.fullmatch('[0-9A-Za-z_-]{1,64}',context.session_id):raise ValueError
    return 'app-alt-krfb-'+str(context.uid)+'-'+context.session_id


def _launch_identity(pid,context,executable,command):
    directory=Path('/proc')/str(pid)
    status=dict(line.split(':',1) for line in _read(directory/'status',16384).decode().splitlines() if ':' in line)
    raw=_read(directory/'cmdline',131072)
    if (status.get('Uid','').split()!=[str(context.uid)]*4
            or status.get('Gid','').split()!=[str(context.gid)]*4
            or int(status.get('PPid','0'))!=os.getpid()
            or os.readlink(directory/'exe')!=executable
            or raw!=b'\0'.join(os.fsencode(part) for part in command)+b'\0'):raise ValueError
    fields=_read(directory/'stat',4096).decode().rsplit(')',1)[1].split()
    ticks=int(fields[19])
    if ticks<=0 or fields[0] in ('Z','X'):raise ValueError
    return {'pid':pid,'start_ticks':ticks,'parent_pid':os.getpid(),'uid':context.uid,'gid':context.gid,
            'boot_id':_read(Path('/proc/sys/kernel/random/boot_id')).decode().strip(),
            'command_sha256':hashlib.sha256(raw).hexdigest()}


def launch_krfb(context,*,register_child):
    """Start only the fixed package program with the real user's GUI context.

    Called by a single-threaded one-shot target helper, after password/policy
    preparation. A user-manager scope outlives the administrative SSH session;
    setsid alone does not escape logind's session cgroup. Scope execution keeps
    the captured graphical environment and process limits. The caller proves
    its selected session/listener and direct RFB result separately; a lost
    launch result must never cause an automatic second launch.
    """
    process=descriptor=None;released=False
    try:
        if threading.active_count()!=1 or not callable(register_child):raise ValueError
        _revalidate(context)
        program = _trusted_program(['/usr/bin/krfb'])
        manager = _trusted_program(['/usr/bin/systemd-run'])
        executable = _trusted_program([sys.executable])
        if os.geteuid()!=0 and (os.geteuid()!=context.uid or os.getegid()!=context.gid
                               or tuple(os.getgroups())!=context.groups):raise ValueError

        def prepare_child():
            os.umask(0o077)
            for key,values in context.limits.items():resource.setrlimit(key,values)
            if os.geteuid()==0:
                os.setgroups(context.groups)
                os.setgid(context.gid)
                os.setuid(context.uid)

        command = [executable,'-I','-c',_DISPATCH_GATE,manager,'--user','--scope','--collect','--quiet',
                   '--unit='+krfb_scope(context),'--',program]
        process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,env=dict(context.environment),cwd=context.home,close_fds=True,
            start_new_session=True,preexec_fn=prepare_child)
        descriptor=os.pidfd_open(process.pid,0)
        identity=_launch_identity(process.pid,context,executable,command)
        # The child cannot contact systemd or launch KRFB before this private
        # birth receipt is durable. Parent death closes stdin without dispatch.
        if (register_child(identity) is not True
                or _launch_identity(process.pid,context,executable,command)!=identity
                or select.select([descriptor],[],[],0)[0]):raise ValueError
        _revalidate(context)
        released=True
        process.stdin.write(b'1');process.stdin.flush();process.stdin.close()
        return identity
    except KRFBSessionError:
        raise
    except (OSError,ValueError,TypeError,KeyError,AttributeError,SessionError,subprocess.SubprocessError):
        raise KRFBSessionError('krfb_runtime_launch_unverified') from None
    finally:
        if process is not None:
            if process.stdin is not None and not process.stdin.closed:process.stdin.close()
            if not released:
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    # Only this unreleased, pidfd-bound gate is eligible. Once
                    # released, uncertainty retains the receipt and never kills
                    # a desktop application or permits a second dispatch.
                    if descriptor is not None:
                        try:signal.pidfd_send_signal(descriptor,signal.SIGKILL,None,0)
                        except ProcessLookupError:pass
                    try:process.wait(timeout=2)
                    except subprocess.TimeoutExpired:pass
        if descriptor is not None:os.close(descriptor)
