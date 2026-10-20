"""One acknowledged local child per consumed phase, with a pre-exec pipe gate."""
import os
from pathlib import Path
import select
import signal
import time
import re

from .ad_directory import fail
from .locks import assert_owned
from .setup_jobs import publish,service_uid,valid_process
from .setup_plans import digest,private_read
from .setup_worker import process_identity


def _path(job,phase):
    if phase not in ('user','final_dns'):raise ValueError
    return job.job_dir/('phase-'+phase+'-process.json')


def child_quiet(settings,job,phase,claim):
    path=_path(job,phase)
    if not path.exists() and not path.is_symlink():return True
    value=private_read(path,owner_uid=service_uid(settings))
    if (set(value)!={'schema_version','job_id','phase','claim_sha256','worker','child','command_sha256'}
            or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['job_id']!=job.job_id or value['phase']!=phase or value['claim_sha256']!=digest(claim)
            or value['worker']!=claim['process_identity'] or not valid_process(value['child'])
            or not isinstance(value['command_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['command_sha256'])):raise ValueError
    identity=value['child']
    if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=identity['boot_id']:return True
    try:fields=(Path('/proc')/str(identity['pid'])/'stat').read_text().rsplit(')',1)[1].split()
    except FileNotFoundError:return True
    # An unchanged birth remains live even after UID/executable/PPID changes.
    # A different birth or controller boot proves that recorded child exited.
    return int(fields[19])!=identity['start_ticks'] or fields[0] in ('Z','X')


def run_claimed(settings,job,phase,claim,command,*,env,timeout,cwd):
    """Only a persisted child receives GO; EOF before it means no exec.

    A killed/lost parent cannot replay this claim. The recorded birth identity
    remains visible even when the child is reparented. Timeout cleanup signals
    only this exact child through its pidfd; target-side uncertainty remains.
    """
    pid=None;pidfd=None;gate=None;reaped=False
    try:
        from .setup_phases import WorkflowPhaseStore
        assert_owned(settings.lock_file)
        if (os.geteuid()!=service_uid(settings) or process_identity(settings)!=claim['process_identity']
                or WorkflowPhaseStore(settings).records(job)[phase]['claim']!=claim):raise ValueError
        log=job.job_dir/('phase-'+phase+'.log')
        output=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            reader,gate=os.pipe()
            pid=os.fork()
            if pid==0:
                try:
                    os.close(gate)
                    allowed=select.select([reader],[],[],10)[0]
                    go=os.read(reader,1) if allowed else b''
                    os.close(reader)
                    if go!=b'G':os._exit(124)
                    os.dup2(output,1);os.dup2(output,2);os.close(output)
                    os.chdir(cwd);os.execvpe(command[0],command,env)
                except BaseException:os._exit(125)
            os.close(reader)
            pidfd=os.pidfd_open(pid,0)
            child=process_identity(settings,pid=pid)
            publish(_path(job,phase),{'schema_version':1,'job_id':job.job_id,'phase':phase,
                'claim_sha256':digest(claim),'worker':claim['process_identity'],'child':child,
                'command_sha256':digest(command)},create=True)
            # No target command can precede this durable acknowledgement.
            os.write(gate,b'G');os.close(gate);gate=None
        finally:os.close(output)
        deadline=time.monotonic()+timeout
        while True:
            found,status=os.waitpid(pid,os.WNOHANG)
            if found:reaped=True;return os.waitstatus_to_exitcode(status)
            if time.monotonic()>=deadline:
                raise fail('workflow_phase_timeout','The original phase exceeded its execution budget')
            time.sleep(min(.1,max(.001,deadline-time.monotonic())))
    except Exception as error:
        if getattr(error,'code',None)=='workflow_phase_timeout':raise
        raise fail('workflow_phase_command_failed','The original claimed phase could not complete its acknowledged dispatch') from None
    finally:
        if gate is not None:os.close(gate)
        if pid is not None and not reaped:
            if pidfd is not None:
                try:signal.pidfd_send_signal(pidfd,signal.SIGTERM)
                except ProcessLookupError:pass
            deadline=time.monotonic()+2
            while True:
                found,_=os.waitpid(pid,os.WNOHANG)
                if found:reaped=True;break
                if time.monotonic()>=deadline:break
                time.sleep(.02)
            if not reaped and pidfd is not None:
                try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                except ProcessLookupError:pass
                os.waitpid(pid,0)
        if pidfd is not None:os.close(pidfd)
