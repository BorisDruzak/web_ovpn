"""Deadline-controlled pipes for fixed internal recovery commands only."""
from __future__ import annotations

import math
import os
import signal
import subprocess
import time
from threading import Thread

from .ad_directory import fail

MAX_INPUT = 131072
MAX_OUTPUT = 16384


def bounded_recovery_run(command, *, environment, input_text=None, timeout=20):
    try:
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 360
                or (input_text is not None and not isinstance(input_text, str))):
            raise ValueError
        raw = None if input_text is None else input_text.encode('utf-8')
        if raw is not None and len(raw) > MAX_INPUT: raise ValueError
    except Exception:
        raise fail('recovery_process_invalid', 'Fixed recovery input or deadline is invalid') from None
    process = None
    captured, bad = [b'', b''], []
    deadline = time.monotonic() + timeout
    def kill():
        if process is not None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    try:
        process = subprocess.Popen(command, shell=False, env=environment, start_new_session=True,
            stdin=subprocess.PIPE if raw is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def read(index, stream):
            try:
                captured[index] = stream.read(MAX_OUTPUT + 1)
                if len(captured[index]) > MAX_OUTPUT: bad.append(True); kill()
            except OSError:
                bad.append(True); kill()
            finally: stream.close()
        def write():
            try:
                process.stdin.write(raw)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                bad.append(True)
                try: process.stdin.close()
                except OSError: pass
        threads = [Thread(target=read, args=(index, stream), daemon=True)
            for index, stream in enumerate((process.stdout, process.stderr))]
        if raw is not None: threads.append(Thread(target=write, daemon=True))
        for thread in threads: thread.start()
        try:
            process.wait(timeout=max(0, deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            bad.append(True); kill(); process.wait(timeout=1)
        except BaseException:
            kill(); process.wait(timeout=1)
            raise
        finally:
            for thread in threads: thread.join(timeout=max(0, deadline-time.monotonic()))
            if any(thread.is_alive() for thread in threads):
                bad.append(True); kill()
                for thread in threads: thread.join(timeout=0.5)
        if bad or any(thread.is_alive() for thread in threads): raise ValueError
        return process.returncode, captured[0].decode('utf-8'), captured[1].decode('utf-8', errors='replace')
    except Exception:
        kill()
        if process is not None:
            try: process.wait(timeout=1)
            except subprocess.TimeoutExpired: pass
        raise fail('recovery_process_failed', 'Fixed recovery process did not complete within its bounded contract') from None
