"""Read the selected user's actual Plasma environment and process limits.

The session launcher proves logind membership. The matching Plasma shell supplies
the environment after KDE initialization; the launcher's initial environment can
legitimately lack KDE_SESSION_VERSION. Environment and limits remain private.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import resource
import selectors
import stat
import subprocess
import threading
import time


class SessionError(Exception):
    pass


@dataclass(frozen=True)
class SessionContext:
    uid: int
    gid: int
    home: str
    session_id: str
    pid: int
    start_ticks: int
    launcher_pid: int
    launcher_start_ticks: int
    environment: dict = field(repr=False)
    limits: dict = field(repr=False)
    groups: tuple = field(repr=False)


def _read(path, limit=65536):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        data = stream.read(limit+1)
    if len(data)>limit:
        raise SessionError('graphical_session_unverified')
    return data


def _call(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    if len(result.stdout.encode())>262144:
        raise SessionError('graphical_session_unverified')
    return result.returncode, result.stdout


def _inside(root, absolute):
    if not absolute.startswith('/') or any(p in ('.','..') for p in absolute.split('/')[1:]):
        raise SessionError('graphical_session_unverified')
    target = root/absolute.lstrip('/')
    parent = target
    while parent!=root:
        if parent.is_symlink():
            raise SessionError('graphical_session_unverified')
        parent = parent.parent
    return target


def _environment(path):
    result = {}
    for value in _read(path, 1048576).split(b'\0'):
        if not value:
            continue
        key, sep, content = value.partition(b'=')
        if not sep or not re.fullmatch(rb'[A-Za-z_][A-Za-z_0-9]*',key):
            raise SessionError('graphical_session_unverified')
        name = key.decode('ascii')
        if name in result:
            raise SessionError('graphical_session_unverified')
        result[name] = os.fsdecode(content)
    return result


def _process(root, directory, uid, gid, executables):
    try:
        executable = os.readlink(directory/'exe')
    except FileNotFoundError:
        return None
    if executable not in executables:
        return None
    root_uid = 0 if root==Path('/') else os.getuid()
    binary = _inside(root, executable)
    info = binary.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=root_uid
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise SessionError('graphical_session_unverified')
    if directory.stat().st_uid!=uid:
        return None
    status = dict(line.split(':',1) for line in _read(directory/'status',16384).decode().splitlines() if ':' in line)
    if status.get('Uid','').split()!=[str(uid)]*4 or status.get('Gid','').split()!=[str(gid)]*4:
        return None
    fields = _read(directory/'stat',4096).decode().rsplit(')',1)[1].split()
    start = int(fields[19])
    if start<=0:
        raise SessionError('graphical_session_unverified')
    return {'pid':int(directory.name),'start_ticks':start, 'executable':executable,
            'environment':_environment(directory/'environ'),
            'cgroup':_read(directory/'cgroup',16384).decode().splitlines(),
            'groups':tuple(int(g) for g in status['Groups'].split())}


def _normal_limits(pid, reader):
    result = {}
    for name in ('AS','CORE','CPU','DATA','FSIZE','LOCKS','MEMLOCK','MSGQUEUE','NICE',
                 'NOFILE','NPROC','RSS','RTPRIO','RTTIME','SIGPENDING','STACK'):
        key = getattr(resource,'RLIMIT_'+name,None)
        if key is None:
            continue
        values = reader(pid,key)
        if (not isinstance(values,tuple) or len(values)!=2
                or any(type(v) is not int or not -1<=v<=2**63-1 for v in values)
                or (values[1]!=-1 and (values[0]==-1 or values[0]>values[1]))):
            raise SessionError('graphical_session_unverified')
        result[key] = values
    return result


def discover_session(uid, gid, home, *, root=Path('/'), call=_call, limits_reader=resource.prlimit):
    try:
        root = Path(root)
        if (type(uid) is not int or uid<=0 or type(gid) is not int or gid<=0
                or not isinstance(home,str) or not home.startswith('/home/')):
            raise ValueError
        target_home = _inside(root,home)
        if not target_home.is_dir() or target_home.stat().st_uid!=uid:
            raise ValueError
        runtime = _inside(root,f'/run/user/{uid}')
        bus = _inside(root,f'/run/user/{uid}/bus')
        if (not runtime.is_dir() or runtime.stat().st_uid!=uid or runtime.stat().st_mode & 0o077
                or not stat.S_ISSOCK(bus.stat().st_mode) or bus.stat().st_uid!=uid):
            raise ValueError
        rc, listing = call(['loginctl','list-sessions','--no-legend','--no-pager'])
        if rc or len(listing)>262144:
            raise ValueError
        candidates = []
        rows = listing.splitlines()
        if len(rows)>4096:
            raise ValueError
        for row in rows:
            fields = row.split()
            if not fields:
                continue
            sid = fields[0]
            if not re.fullmatch('[A-Za-z0-9_-]{1,64}',sid):
                raise ValueError
            rc, output = call(['loginctl','show-session',sid,'--no-pager','-p','User','-p','Leader',
                              '-p','Type','-p','Class','-p','State','-p','Remote'])
            if rc:
                raise ValueError
            props = dict(line.split('=',1) for line in output.splitlines() if '=' in line)
            if (props.get('User')==str(uid) and props.get('Type') in ('x11','wayland')
                    and props.get('Class')=='user' and props.get('State') in ('active','online')):
                candidates.append((sid,props['Type']))
        if len(candidates)!=1:
            raise SessionError('graphical_session_ambiguous' if candidates else 'graphical_session_unavailable')
        sid, kind = candidates[0]
        proc = _inside(root,'/proc')
        directories = [p for p in proc.iterdir() if p.name.isdigit()]
        if len(directories)>65536:
            raise ValueError
        launcher_name = '/usr/bin/startplasma-'+('x11' if kind=='x11' else 'wayland')
        launchers, shells = [], []
        for directory in directories:
            record = _process(root,directory,uid,gid,{launcher_name,'/usr/bin/plasmashell'})
            if record is None:
                continue
            env = record['environment']
            if (env.get('HOME')!=home or env.get('XDG_SESSION_ID')!=sid
                    or env.get('XDG_SESSION_TYPE')!=kind or env.get('XDG_RUNTIME_DIR')!=f'/run/user/{uid}'
                    or not re.fullmatch(r'unix:path=/run/user/'+str(uid)+r'/bus(?:,guid=[0-9a-f]{32})?',
                                        env.get('DBUS_SESSION_BUS_ADDRESS',''))):
                continue
            if kind=='x11' and not re.fullmatch(r':[0-9]{1,5}(?:\.[0-9]{1,2})?',env.get('DISPLAY','')):
                continue
            if kind=='wayland' and not re.fullmatch('wayland-[0-9]{1,5}',env.get('WAYLAND_DISPLAY','')):
                continue
            if record['executable']==launcher_name:
                scope = f'/user.slice/user-{uid}.slice/session-{sid}.scope'
                if any(line.split(':',2)[-1]==scope for line in record['cgroup']):
                    launchers.append(record)
            elif env.get('KDE_SESSION_VERSION')=='6':
                scope = f'/user.slice/user-{uid}.slice/user@{uid}.service/session.slice/plasma-plasmashell.service'
                if any(line.split(':',2)[-1]==scope for line in record['cgroup']):
                    shells.append(record)
        if len(launchers)!=1 or len(shells)!=1:
            raise SessionError('graphical_session_unverified')
        launcher, shell = launchers[0],shells[0]
        if any(launcher['environment'].get(k)!=shell['environment'].get(k)
               for k in ('DISPLAY','WAYLAND_DISPLAY','XDG_SESSION_ID','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS')):
            raise ValueError
        limits = _normal_limits(shell['pid'],limits_reader)
        if len(shell['groups'])>4096 or any(not 0<=g<=2**32-1 for g in shell['groups']):
            raise ValueError
        # Prove neither process changed identity while its private context was read.
        for record in (launcher,shell):
            again = _process(root,proc/str(record['pid']),uid,gid,{record['executable']})
            if again!=record:
                raise ValueError
        return SessionContext(uid,gid,home,sid,shell['pid'],shell['start_ticks'],
                              launcher['pid'],launcher['start_ticks'],shell['environment'],limits,shell['groups'])
    except SessionError:
        raise
    except (OSError,ValueError,TypeError,KeyError,IndexError,UnicodeError):
        raise SessionError('graphical_session_unverified') from None


@dataclass(frozen=True)
class SessionCommandResult:
    returncode: int
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)


def _revalidate(context):
    if (not isinstance(context,SessionContext)
            or discover_session(context.uid,context.gid,context.home)!=context):
        raise SessionError('graphical_session_unverified')


def _trusted_program(argv):
    if (not isinstance(argv,list) or not 0<len(argv)<=64
            or any(not isinstance(s,str) or '\0' in s for s in argv)
            or sum(len(s) for s in argv)>65536 or not argv[0].startswith('/')):
        raise SessionError('graphical_command_unverified')
    try:
        target = Path(argv[0]).resolve(strict=True)
        info = target.stat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            raise ValueError
        for parent in (target,*target.parents):
            info = parent.stat()
            if info.st_uid!=0 or info.st_mode & 0o022:
                raise ValueError
        return str(target)
    except (OSError,ValueError):
        raise SessionError('graphical_command_unverified') from None


def run_session_command(context, argv, *, timeout=10):
    """Run a fixed internal short command as the user, never through a shell.

    Called only by a one-shot target helper. A web/worker thread must instead
    invoke that helper over the existing pinned administrative transport.
    """
    if type(timeout) not in (int,float) or not 0<timeout<=30 or threading.active_count()!=1:
        raise SessionError('graphical_command_unverified')
    _revalidate(context)
    program = _trusted_program(argv)
    if os.geteuid()!=0 and (os.geteuid()!=context.uid or os.getegid()!=context.gid
                           or tuple(os.getgroups())!=context.groups):
        raise SessionError('graphical_command_identity_unverified')

    def prepare_child():
        # No NSS, imports, subprocesses or locks after fork. Apply the captured
        # GUI limits in this child, then drop root before exec loads its env.
        for key,values in context.limits.items():
            resource.setrlimit(key,values)
        if os.geteuid()==0:
            os.setgroups(context.groups)
            os.setgid(context.gid)
            os.setuid(context.uid)

    process = None
    try:
        process = subprocess.Popen([program,*argv[1:]],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=dict(context.environment),close_fds=True,
            start_new_session=True,preexec_fn=prepare_child)
        deadline = time.monotonic()+timeout
        buffers = {'stdout':bytearray(),'stderr':bytearray()}
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout,selectors.EVENT_READ,'stdout')
            selected.register(process.stderr,selectors.EVENT_READ,'stderr')
            while selected.get_map():
                remaining = deadline-time.monotonic()
                if remaining<=0:
                    raise SessionError('graphical_command_timeout')
                for key,_ in selected.select(remaining):
                    block = os.read(key.fd,8192)
                    if not block:
                        selected.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(block)
                    if sum(len(b) for b in buffers.values())>65536:
                        raise SessionError('graphical_command_output_unverified')
        remaining = deadline-time.monotonic()
        if remaining<=0:
            raise SessionError('graphical_command_timeout')
        process.wait(timeout=remaining)
        return SessionCommandResult(process.returncode,os.fsdecode(bytes(buffers['stdout'])),
                                    os.fsdecode(bytes(buffers['stderr'])))
    except subprocess.TimeoutExpired:
        raise SessionError('graphical_command_timeout') from None
    except (OSError,subprocess.SubprocessError):
        raise SessionError('graphical_command_unverified') from None
    finally:
        if process is not None:
            # Only this newly created probe child is eligible for timeout
            # cleanup. Existing applications, wallet daemons and KDE are never
            # selected or signalled by this routine.
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    raise SessionError('graphical_probe_outcome_unverified') from None
            process.stdout.close()
            process.stderr.close()
