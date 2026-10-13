"""Serialized persistent worker: claims survive restart and are never replayed."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time

from .ad_directory import fail
from .config import Settings
from .errors import ControlError
from .jobs import JobRepository, ACTIVE_STATES
from .locks import exclusive_lock
from .setup_jobs import SetupJobRepository, service_uid, valid_process, unresolved_legacy_reservations

EXECUTING = {'preflight', 'running', 'verifying'}


def process_identity(settings, *, pid=None):
    selected = os.getpid() if pid is None else pid
    if type(selected) is not int or selected < 1:
        raise fail('setup_process_identity_invalid', 'Worker PID is invalid')
    directory = Path('/proc')/str(selected)
    if directory.stat().st_uid != service_uid(settings):
        raise fail('setup_process_identity_invalid', 'Worker process is not owned by the Setup service')
    fields = (directory/'stat').read_text().rsplit(') ', 1)[1].split()
    if fields[0] in ('Z', 'X'):
        raise ProcessLookupError
    identity = {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'pid': selected, 'start_ticks': int(fields[19])}
    if not valid_process(identity):
        raise fail('setup_process_identity_invalid', 'Worker process identity is invalid')
    return identity


def process_alive(settings, identity):
    if not valid_process(identity):
        return None
    try:
        return process_identity(settings, pid=identity['pid']) == identity
    except (FileNotFoundError, ProcessLookupError):
        return False
    except (OSError, ValueError, IndexError, ControlError):
        return None


class SetupWorker:
    def __init__(self, settings, *, engine=None, process_probe=None, clock=None):
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.jobs = SetupJobRepository(settings, clock=self.clock)
        self.engine = engine
        self.process_probe = process_probe or (lambda identity: process_alive(settings, identity))

    def _reconcile_unlocked(self):
        changed = []
        for job in self.jobs.list():
            if job.status['claimed'] and job.state in EXECUTING:
                try:
                    alive = self.process_probe(job.status['process_identity'])
                except Exception:
                    alive = None
                if alive is not True:
                    self.jobs.transition(job.job_id, 'unknown_requires_review', stage={'id': 'worker_identity_unverified'})
                    changed.append({'job_id': job.job_id, 'state': 'unknown_requires_review',
                                    'code': 'worker_identity_unverified'})
        return {'status': 'ok', 'changed': changed}

    def reconcile(self):
        with exclusive_lock(self.settings.lock_file):
            return self._reconcile_unlocked()

    def run_once(self):
        with exclusive_lock(self.settings.lock_file):
            self._reconcile_unlocked()
            if any(job.state in ACTIVE_STATES for job in JobRepository(self.settings).list()
                   if job.status.get('kind') != 'setup'):
                return {'status': 'blocked', 'code': 'legacy_job_active'}
            from .setup_retry import reviewed_legacy_runs
            if any(r['run_id'] not in reviewed_legacy_runs(self.settings) for r in unresolved_legacy_reservations(self.settings)):
                return {'status': 'blocked', 'code': 'legacy_execution_unresolved'}
            jobs = self.jobs.list()
            from .setup_retry import reviewed_jobs
            reviewed = reviewed_jobs(self.settings)
            if any(job.state in EXECUTING | {'unknown_requires_review'} and job.job_id not in reviewed for job in jobs):
                return {'status': 'blocked', 'code': 'setup_job_unresolved'}
            queued = sorted((job for job in jobs if job.state == 'queued' and not job.status['claimed']),
                            key=lambda j: j.status['admission_sequence'])
            if not queued:
                return {'status': 'idle'}
            job = self.jobs.claim(queued[0].job_id, process_identity(self.settings))
            try:
                if self.engine is None:
                    from .setup_execution import SetupExecutionEngine
                    self.engine = SetupExecutionEngine(self.settings, jobs=self.jobs)
                self.engine.execute(job.job_id)
            except Exception:
                current = self.jobs.get(job.job_id)
                if current.state in EXECUTING:
                    self.jobs.transition(job.job_id, 'unknown_requires_review', stage={'id': 'execution_outcome_unverified'})
            current = self.jobs.get(job.job_id)
            if current.state in EXECUTING:
                current = self.jobs.transition(job.job_id, 'unknown_requires_review', stage={'id': 'completion_evidence_missing'})
            return {'status': current.state, 'job_id': current.job_id}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='alt-setup-worker')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--once', action='store_true')
    mode.add_argument('--reconcile', action='store_true')
    args = parser.parse_args(argv)
    worker = SetupWorker(Settings.from_env())
    while True:
        try:
            result = worker.reconcile() if args.reconcile else worker.run_once()
        except Exception:
            print(json.dumps({'status': 'blocked', 'code': 'setup_worker_state_unverified'}), flush=True)
            return 1
        if args.once or args.reconcile:
            print(json.dumps(result), flush=True)
            return 0
        # Do not fill journald with unchanged idle/blocked polling states.
        if result.get('job_id'):
            print(json.dumps(result), flush=True)
        time.sleep(2)
