from __future__ import annotations

import os
import sys
import time

import pytest

from alt_deploy.errors import ControlError


def run(*args, **kwargs):
    from alt_deploy.setup_recovery_process import bounded_recovery_run
    return bounded_recovery_run(*args, environment={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, **kwargs)


def test_inventory_transport_accepts_large_bounded_metadata_without_relaxing_recovery():
    from alt_deploy.setup_recovery_process import bounded_inventory_run,bounded_inventory_command_run
    command=[sys.executable,'-c','import sys; sys.stdout.write("x"*880000)']
    assert len(bounded_inventory_run(command,environment={},timeout=3)[1])==880000
    with pytest.raises(ControlError):run(command,timeout=3)
    small=[sys.executable,'-c','import sys; sys.stdout.write("x"*65536)']
    assert len(bounded_inventory_command_run(small,environment={},timeout=3)[1])==65536
    with pytest.raises(ControlError):bounded_inventory_command_run(command,environment={},timeout=3)


def test_bundle_channel_accepts_one_mib_without_relaxing_native_tools():
    from alt_deploy.setup_recovery_process import bounded_bundle_run
    command=[sys.executable,'-c','import sys; print(len(sys.stdin.buffer.read()))']
    assert bounded_bundle_run(command,environment={},input_text='x'*1048576,timeout=3)==(0,'1048576\n','')
    with pytest.raises(ControlError):run(command,input_text='x'*166880,timeout=3)


@pytest.mark.parametrize('stream',['stdout','stderr'])
def test_bundle_replies_keep_original_sixteen_kib_bound(stream):
    from alt_deploy.setup_recovery_process import bounded_bundle_run
    with pytest.raises(ControlError) as caught:
        bounded_bundle_run([sys.executable,'-c','import sys; sys.'+stream+'.write("SYNTHETIC_SECRET"*4096)'],environment={},timeout=3)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)


def test_bundle_invalid_input_fails_before_spawn(monkeypatch):
    from alt_deploy import setup_recovery_process
    calls=[];monkeypatch.setattr(setup_recovery_process.subprocess,'Popen',lambda *a,**kw:calls.append(True))
    with pytest.raises(ControlError):setup_recovery_process.bounded_bundle_run(['/usr/bin/false'],environment={},input_text='x'*1048577,timeout=1)
    assert calls==[]


def test_bundle_deadline_kills_stalled_large_input_child():
    from alt_deploy.setup_recovery_process import bounded_bundle_run
    started=time.monotonic()
    with pytest.raises(ControlError):bounded_bundle_run([sys.executable,'-c','import time; time.sleep(60)'],
        environment={},input_text='x'*1048576,timeout=0.2)
    assert time.monotonic()-started<4


@pytest.mark.parametrize('kind',['startup','native'])
def test_runtime_default_channel_accepts_source_bundle_while_inner_runner_remains_small(kind):
    from types import SimpleNamespace
    from alt_deploy.setup_recovery_process import bounded_recovery_run
    from alt_deploy.setup_recovery_sssd_start_runtime import RecoverySSSDStartRuntime
    from alt_deploy.setup_recovery_native_runtime import RecoveryNativeRuntime
    inner=SimpleNamespace(runner=bounded_recovery_run,settings=None,attempts=None)
    runtime=(RecoverySSSDStartRuntime(policy_runtime=inner,authorization=lambda *a:None) if kind=='startup'
        else RecoveryNativeRuntime(startup_runtime=inner,authorization=lambda *a:None))
    command=[sys.executable,'-c','import sys; print(len(sys.stdin.buffer.read()))']
    assert runtime.runner(command,environment={},input_text='x'*166880,timeout=3)==(0,'166880\n','')
    with pytest.raises(ControlError):inner.runner(command,environment={},input_text='x'*166880,timeout=3)


@pytest.mark.parametrize('stream',['stdout','stderr'])
def test_inventory_transport_refuses_overflow_and_discards_diagnostics(stream):
    from alt_deploy.setup_recovery_process import bounded_inventory_run
    with pytest.raises(ControlError) as caught:
        bounded_inventory_run([sys.executable,'-c','import sys; sys.'+stream+'.write("SYNTHETIC_SECRET"*400000)'],environment={},timeout=3)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)


def test_stalled_child_cannot_block_large_stdin_past_deadline():
    started = time.monotonic()
    with pytest.raises(ControlError):
        run([sys.executable, '-c', 'import time; time.sleep(60)'], input_text='x'*131072, timeout=0.2)
    assert time.monotonic() - started < 4


def test_normal_input_and_both_outputs_are_bounded():
    assert run([sys.executable, '-c', 'import sys; value=sys.stdin.read(); print(len(value)); print("safe",file=sys.stderr)'],
               input_text='x'*131072, timeout=3) == (0, '131072\n', 'safe\n')


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_excessive_output_is_refused_without_diagnostics(stream):
    with pytest.raises(ControlError) as caught:
        run([sys.executable, '-c', 'import sys,time; sys.'+stream+'.write("SYNTHETIC_SECRET"*4096); sys.'+stream+'.flush(); time.sleep(60)'], timeout=2)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)


def test_descendant_holding_pipes_is_killed_and_refused():
    started = time.monotonic()
    with pytest.raises(ControlError):
        run([sys.executable, '-c', 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])'], timeout=0.2)
    assert time.monotonic() - started < 4


def test_timeout_kills_the_spawned_process_group(tmp_path):
    pidfile = tmp_path/'child.pid'
    program = ('import subprocess,sys,time,pathlib; '
        'child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]); '
        'pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(60)')
    with pytest.raises(ControlError): run([sys.executable, '-c', program, str(pidfile)], timeout=0.5)
    from pathlib import Path
    state = Path('/proc')/pidfile.read_text()/'stat'
    # An unreaped zombie has already stopped; a running/sleeping child has not.
    assert not state.exists() or state.read_text().split(') ', 1)[1].split()[0] == 'Z'


@pytest.mark.parametrize('invalid', ['oversize', 'bytes', 'deadline'])
def test_invalid_input_refuses_before_spawn(monkeypatch, invalid):
    from alt_deploy import setup_recovery_process
    calls = []
    monkeypatch.setattr(setup_recovery_process.subprocess, 'Popen', lambda *a, **kw: calls.append(True))
    with pytest.raises(ControlError):
        run(['/usr/bin/false'], input_text=b'x' if invalid == 'bytes' else 'x'*(131073 if invalid == 'oversize' else 1),
            timeout=0 if invalid == 'deadline' else 1)
    assert calls == []


def test_fixed_source_runs_standalone_with_safe_failures():
    from pathlib import Path
    from alt_deploy import setup_recovery_process
    scope = {'__name__': 'fixed_recovery_process'}
    exec(compile(Path(setup_recovery_process.__file__).read_text(), 'fixed-process', 'exec'), scope)
    standalone = scope['bounded_recovery_run']
    assert standalone([sys.executable, '-c', 'print("safe")'], environment={}, timeout=3) == (0, 'safe\n', '')
    with pytest.raises(ValueError, match='recovery_process_failed'):
        standalone([sys.executable, '-c', 'import time;time.sleep(60)'], environment={}, timeout=0.2)
