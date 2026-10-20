"""Fresh single-use technical admission for one original post-login phase."""
from datetime import datetime,timezone
import re
import stat

from .setup_compat import control_module
from .setup_closed_failure import ClosedFailureEvidence
from .setup_maintenance_review import MaintenanceReview,native_observe
from .setup_queue_review import QueueAdmissionReview


DIRECTORY='setup-phase-admissions'


def denied():
    return control_module('ad_directory').fail('setup_phase_admission_unverified',
        'Fresh native phase admission is missing, consumed, busy or unverified')


class PhaseAdmissionReview:
    def __init__(self,settings,*,clock=None,readiness=None,observer=None,quiet=None):
        self.settings=settings;self.clock=clock or (lambda:datetime.now(timezone.utc))
        self.readiness=readiness;self.observer=observer or (lambda j:native_observe(settings,j,coverage=True))
        self.jobs=control_module('setup_jobs');self.io=control_module('setup_plans')
        self.quiet=quiet

    def _path(self,job_id,phase):
        self.jobs.SetupJobRepository(self.settings).get(job_id)
        if phase not in ('user','final_dns'):raise denied()
        return self.settings.state_root/DIRECTORY/(job_id+'--'+phase+'.json')

    def read(self,job_id,phase):
        value=self.io.private_read(self._path(job_id,phase),owner_uid=self.jobs.service_uid(self.settings))
        self.validate(value)
        return value

    def validate(self,value):
        try:
            fields={'schema_version','purpose','job_id','phase','ticket_sha256','created_at',
                    'excluded_job_ids','excluded_lease_ids','history_sha256','evidence_sha256','readiness_sha256','validator_sha256','sha256'}
            if (not isinstance(value,dict) or set(value)!=fields or type(value['schema_version']) is not int
                    or value['schema_version']!=1 or value['purpose']!='post_login_phase_only'
                    or value['phase'] not in ('user','final_dns')
                    or not re.fullmatch('job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',value['job_id'])
                    or any(not isinstance(value[k],str) or not re.fullmatch('[0-9a-f]{64}',value[k])
                           for k in ('ticket_sha256','history_sha256','evidence_sha256','readiness_sha256','validator_sha256','sha256'))
                    or self.io.digest({k:v for k,v in value.items() if k!='sha256'})!=value['sha256']):raise ValueError
            self.jobs.timestamp(value['created_at'])
            for field,pattern in (('excluded_job_ids','job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}'),('excluded_lease_ids','[0-9a-f]{32}')):
                if (not isinstance(value[field],list) or value[field]!=sorted(set(value[field]))
                        or any(not isinstance(v,str) or not re.fullmatch(pattern,v) for v in value[field])):raise ValueError
        except Exception:raise denied() from None

    def _closed(self,job,candidate):
        """No old receipt/TTL is authority for this fresh phase admission."""
        if 'workflow' in job.request['plan']['payload']:
            store=control_module('setup_phases').WorkflowPhaseStore(self.settings)
            if store.records(job)['system']['result'] is not None:
                from .setup_workflow_closed import ClosedWorkflowEvidence
                service=ClosedWorkflowEvidence(self.settings);closed=service.load(job.job_id)
                fresh=self.observer(job);MaintenanceReview(self.settings)._validate_joined(closed['original'],fresh)
                if len(fresh['computer']['objects'])!=1 or any(fresh['computer']['objects'][0].get(k)!=v
                        for k,v in closed['computer'].items()):raise denied()
                proof=(self.quiet or service.quiet)(job)
                if (proof.get('quiet') is not True or proof.get('machine_uuid')!=job.machine_uuid
                        or proof.get('boot_id')!=fresh['boot_id']):raise denied()
                QueueAdmissionReview.distinct_candidate(candidate.request['identities'],job.request['identities'],fresh['computer'])
                if service.load(job.job_id)['history_sha256']!=closed['history_sha256']:raise denied()
                return [],closed['history_sha256'],self.io.digest({'fresh':fresh,'processes':proof})
        closed=ClosedFailureEvidence(self.settings,clock=self.clock).load(job.job_id)
        fresh=self.observer(job)
        if 'partial_local' in fresh:
            from .setup_partial_observation import validate_evidence
            validate_evidence(closed,fresh,mode='partial_ad')
        else:MaintenanceReview(self.settings)._validate_joined(closed['original'],fresh)
        QueueAdmissionReview.distinct_candidate(candidate.request['identities'],job.request['identities'],fresh['computer'])
        # Observe first, then prove all immutable old files still match.
        again=ClosedFailureEvidence(self.settings,clock=self.clock).load(job.job_id)
        if again['history_sha256']!=closed['history_sha256']:raise denied()
        return closed['lease_ids'],closed['history_sha256'],self.io.digest(fresh)

    def admit_phase_candidate(self,job_id,phase,ticket_sha256):
        try:
            control_module('locks').assert_owned(self.settings.lock_file)
            repository=self.jobs.SetupJobRepository(self.settings);repository._check_admissions()
            store=control_module('setup_phases').WorkflowPhaseStore(self.settings)
            job=store._actor(repository.get(job_id));records=store.records(job);row=records[phase]
            if (job.state!='queued' or row['ticket'] is None or row['claim'] is not None
                    or self.io.digest(row['ticket'])!=ticket_sha256):raise denied()
            candidates=control_module('setup_phases').eligible_candidates(self.settings,readiness=self.readiness)
            if not candidates or candidates[0][1:]!=(job_id,phase):raise denied()
            from .setup_compat import partial_store
            partial=partial_store(self.settings.state_root)
            if partial is not None and partial.pending_attempts():raise denied()
            if any(j.status.get('kind')!='setup' and j.state in ('queued','running') for j in repository.jobs.list()):raise denied()
            retry=control_module('setup_retry');reviewed=retry.reviewed_jobs(self.settings)
            excluded=[];leases=[];history={};evidence={}
            for old in repository.list():
                if old.job_id==job_id or old.job_id in reviewed:continue
                if old.state in ('preflight','running','verifying'):raise denied()
                if old.state=='unknown_requires_review':
                    ids,sha,proof=self._closed(old,job);excluded.append(old.job_id);leases+=ids;history[old.job_id]=sha;evidence[old.job_id]=proof
            reviewed_runs=retry.reviewed_legacy_runs(self.settings)
            unresolved=[r for r in self.jobs.unresolved_legacy_reservations(self.settings) if r['run_id'] not in reviewed_runs]
            if sorted(r['reservation_id'] for r in unresolved)!=sorted(leases):raise denied()
            observer=self.readiness
            if observer is None:
                observer=control_module('setup_phase_probe').WorkflowReadinessProbe(self.settings).observe
            ready=control_module('setup_phases').validate_ready(job,phase,observer(job,phase),records['system']['result'])
            if ready['scope']!=row['ticket']['readiness']['scope']:raise denied()
            from .setup_maintenance_coverage import MaintenanceCoverage
            body={'schema_version':1,'purpose':'post_login_phase_only','job_id':job_id,'phase':phase,
                'ticket_sha256':ticket_sha256,'created_at':self.clock().isoformat(),
                'excluded_job_ids':sorted(excluded),'excluded_lease_ids':sorted(leases),
                'history_sha256':self.io.digest(history),'evidence_sha256':self.io.digest(evidence),
                'readiness_sha256':self.io.digest(ready),
                'validator_sha256':self.io.digest(MaintenanceCoverage(self.settings)._validators())}
            value=dict(body,sha256=self.io.digest(body));self.validate(value)
            with repository.locked():
                current=repository.get(job_id)
                if current.status!=job.status or store.records(current)!=records:raise denied()
                self.io.private_directory(self.settings.state_root/DIRECTORY)
                self.jobs.publish(self._path(job_id,phase),value,create=True)
            return {'schema_version':1,'job_id':job_id,'phase':phase,'ticket_sha256':ticket_sha256,
                    'review_sha256':value['sha256'],'excluded_job_ids':value['excluded_job_ids'],
                    'excluded_lease_ids':value['excluded_lease_ids'],'readiness':ready}
        except Exception:raise denied() from None


def validate_artifacts(root):
    directory=root/DIRECTORY
    if not directory.exists() and not directory.is_symlink():return
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=root.stat().st_uid or stat.S_IMODE(info.st_mode)!=0o700:raise denied()
    from .setup_compat import setup_settings
    service=PhaseAdmissionReview(setup_settings(root));store=control_module('setup_phases').WorkflowPhaseStore(service.settings)
    for path in directory.iterdir():
        match=re.fullmatch('(job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})--(user|final_dns)[.]json',path.name)
        if not match:raise denied()
        value=service.read(match[1],match[2]);job=service.jobs.SetupJobRepository(service.settings).get(match[1])
        row=store.records(job)[match[2]]
        if row['ticket'] is None or value['ticket_sha256']!=service.io.digest(row['ticket']):raise denied()
        if row['claim'] is not None and row['claim']['admission']['review_sha256']!=value['sha256']:raise denied()
        if row['claim'] is not None and row['claim']['readiness_sha256']!=value['readiness_sha256']:raise denied()
