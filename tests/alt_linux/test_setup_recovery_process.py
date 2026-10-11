from __future__ import annotations

import os
import sys
import time

import pytest

from alt_deploy.errors import ControlError


def run(*args, **kwargs):
    from alt_deploy.setup_recovery_process import bounded_recovery_run
    return bounded_recovery_run(*args, environment={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, **kwargs)


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
