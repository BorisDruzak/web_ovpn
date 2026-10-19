"""Operator-only one-shot local recovery; never joins or resumes old Setup."""
from datetime import datetime, timezone

from .setup_jobs import setup_queue_lock
from .setup_partial_local_state import PartialLocalStore, EFFECTS, claim_key, denied
from .setup_partial_local_runtime import PartialLocalRuntime, validate_local_after, validate_target_result
from .setup_plans import digest


class PartialLocalService:
    def __init__(self, settings, *, observer=None, runtime=None, history=None, clock=None):
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.store = PartialLocalStore(settings, clock=self.clock)
        from .setup_maintenance_review_bridge import closed_failure_service
        self.history = history or closed_failure_service(settings)
        self.observer = observer
        self.runtime = runtime or PartialLocalRuntime(settings, observer=observer)

    def _closed(self, job_id):
        return self.history.load(job_id)

    def _idle(self):
        from .setup_jobs import SetupJobRepository, ACTIVE_SETUP_STATES, unresolved_legacy_reservations
        from .setup_retry import reviewed_jobs, reviewed_legacy_runs
        jobs = SetupJobRepository(self.settings)
        jobs._check_admissions()
        reviewed = reviewed_jobs(self.settings)
        covered_leases = set()
        for job in jobs.jobs.list():
            if job.job_id in reviewed or job.state not in ACTIVE_SETUP_STATES: continue
            if job.status.get('kind') != 'setup' or job.state != 'unknown_requires_review': raise denied()
            covered_leases.update(self._closed(job.job_id)['lease_ids'])
        reviewed_runs = reviewed_legacy_runs(self.settings)
        unresolved = [record for record in unresolved_legacy_reservations(self.settings) if record['run_id'] not in reviewed_runs]
        if ({record['reservation_id'] for record in unresolved} != covered_leases
                or any(record['state'] != 'unknown_requires_review' for record in unresolved)): raise denied()
        if self.store.pending_attempts(): raise denied()

    def _observe(self, closed, mode):
        return (self.observer.observe(closed, mode=mode) if self.observer is not None
                else self.runtime.snapshot(closed, mode=mode))

    def _payload(self, closed):
        fresh = self._observe(closed, 'partial_ad')
        return {**{k: closed[k] for k in ('job_id', 'failed_run_id', 'configuration_run_id', 'machine', 'history_sha256')},
                'evidence': fresh, 'source_sha256': self.runtime.source(),
                'rehearsal': self.runtime.rehearsal(fresh), 'effects': EFFECTS}

    def plan(self, job_id):
        try:
            from .locks import exclusive_lock
            with exclusive_lock(self.settings.lock_file):
                with setup_queue_lock(self.settings): self._idle()
                closed = self._closed(job_id)
                payload = self._payload(closed)
                if self._closed(job_id)['history_sha256'] != closed['history_sha256']: raise denied()
                self.store.retain_closed(closed)
                return self.store.create(payload)
        except Exception: raise denied() from None

    def apply(self, plan_id, sha):
        from .locks import exclusive_lock
        with exclusive_lock(self.settings.lock_file):
            # All denial/drift checks precede the original-failure claim.
            plan = self.store.load(plan_id, sha)
            with setup_queue_lock(self.settings): self._idle()
            closed = self._closed(plan['payload']['job_id'])
            if self._payload(closed) != plan['payload']: raise denied()
            with setup_queue_lock(self.settings):
                self._idle()
                if self._closed(closed['job_id'])['history_sha256'] != closed['history_sha256']: raise denied()
                claim = self.store.claim_once(plan)
            target, after, status = None, None, 'unknown_requires_review'
            try:
                target = validate_target_result(plan, self.runtime.apply(plan, claim))
                if target['status'] != 'successful': raise denied()
                after = validate_local_after(plan['payload'], self.runtime.verify(plan, target))
                if (self.runtime.source() != plan['payload']['source_sha256']
                        or digest(after['partial_local']['native']) != target['after_sha256']): raise denied()
                status = 'successful'
            except Exception:
                # A bad remote reply cannot leak arbitrary fields into private
                # result projections. Valid fixed UNKNOWN diagnostics may remain.
                try:
                    if target is not None: validate_target_result(plan, target)
                except Exception: target = None
                after = None
            result = {'schema_version': 1, 'operation': 'partial_local_result', 'claim_key': claim['claim_key'],
                      'plan_id': plan_id, 'plan_sha256': sha, 'status': status, 'target': target,
                      'after': after, 'finished_at': self.clock().isoformat()}
            return self.store.publish_result(claim, result)

    def status(self, plan_id):
        plan = self.store.load(plan_id, plan_id.removeprefix('partial-local-'), archival=True)
        path = self.store.claims/(claim_key(plan['payload'])+'.json')
        if not path.exists() and not path.is_symlink():
            return {'schema_version': 1, 'operation': 'partial_local_status', 'plan_id': plan_id, 'status': 'planned'}
        claim = self.store._claim(path)
        result = self.store.result_for(claim)
        if result is not None: return result
        return {'schema_version': 1, 'operation': 'partial_local_status', 'plan_id': claim['plan_id'],
                'claim_key': claim['claim_key'], 'status': 'unknown_requires_review'}
