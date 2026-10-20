"""Version-three controller-only coverage for immutable post-login UNKNOWNs."""
from pathlib import Path
import re

from .setup_compat import control_module,valid_validator_catalog
from .setup_closed_failure import ClosedFailureEvidence
from .setup_workflow_closed import ClosedWorkflowEvidence
from .setup_maintenance_coverage import MaintenanceCoverage
from .setup_maintenance_review import denied


def validate_payload(value):
    fields={'covered','job_ids','lease_ids','history','validators','purpose','execution_window_seconds'}
    if (not isinstance(value,dict) or set(value)!=fields or value['purpose']!='controller_maintenance_only'
            or value['execution_window_seconds']!=21600 or not isinstance(value['covered'],list)
            or not 1<=len(value['covered'])<=1024 or not valid_validator_catalog(value['validators'])
            or value['job_ids']!=sorted(set(value['job_ids'])) or value['lease_ids']!=sorted(set(value['lease_ids']))
            or not isinstance(value['history'],dict) or any(not isinstance(k,str) or Path(k).is_absolute()
                or '..' in Path(k).parts or not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v)
                for k,v in value['history'].items())):raise denied()
    ids=[];leases=[];has_phase=False
    for row in value['covered']:
        if (not isinstance(row,dict) or set(row)!={'job_id','kind','legacy_run_id','configuration_run_id','phase',
                'history_sha256','lease_ids','mode','evidence','process_evidence'}
                or row['kind'] not in ('closed_full_failure','closed_workflow_phase')
                or not isinstance(row['job_id'],str) or not re.fullmatch('job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',row['job_id'])
                or not re.fullmatch('setup-run-[0-9a-f]{32}',row['legacy_run_id'])
                or not re.fullmatch('[0-9a-f]{32}',row['configuration_run_id'])
                or not re.fullmatch('[0-9a-f]{64}',row['history_sha256'])
                or not isinstance(row['evidence'],dict) or not isinstance(row['lease_ids'],list)
                or row['lease_ids']!=sorted(set(row['lease_ids']))):raise denied()
        if row['kind']=='closed_workflow_phase':
            has_phase=True
            proof=row['process_evidence']
            if (row['phase'] not in ('user','final_dns') or row['lease_ids']!=[] or row['mode']!='phase_joined'
                    or not isinstance(proof,dict) or set(proof)!={'schema_version','machine_uuid','hostname','boot_id','quiet'}
                    or type(proof['schema_version']) is not int or proof['schema_version']!=1 or proof['quiet'] is not True
                    or proof['machine_uuid']!=row['evidence']['machine']['uuid']
                    or proof['hostname']!=row['evidence']['machine']['hostname']
                    or proof['boot_id']!=row['evidence']['boot_id']):raise denied()
        elif (row['phase'] is not None or row['process_evidence'] is not None or row['mode'] not in ('joined','partial_ad')
                or len(row['lease_ids'])!=2):raise denied()
        if any(not re.fullmatch('[0-9a-f]{32}',v) for v in row['lease_ids']):raise denied()
        ids.append(row['job_id']);leases+=row['lease_ids']
    if not has_phase or ids!=value['job_ids'] or sorted(leases)!=value['lease_ids']:raise denied()


class WorkflowMaintenanceCoverage(MaintenanceCoverage):
    schema_version=3

    def __init__(self,settings,*,observer=None,clock=None,quiet=None):
        super().__init__(settings,observer=observer,clock=clock)
        self.quiet=quiet or ClosedWorkflowEvidence(settings).quiet

    def _discover(self):
        from .setup_compat import partial_store
        partial=partial_store(self.settings.state_root)
        if partial is not None and partial.pending_attempts():raise denied()
        repository=self.jobs.SetupJobRepository(self.settings);repository._check_admissions()
        retry=control_module('setup_retry');reviewed=retry.reviewed_jobs(self.settings)
        active=[j for j in repository.jobs.list() if j.state in self.jobs.ACTIVE_SETUP_STATES and j.job_id not in reviewed]
        if not active or any(j.status.get('kind')!='setup' or j.state!='unknown_requires_review'
                or not j.status['claimed'] or j.request['operation']!='full_setup' for j in active):raise denied()
        closed=[]
        for job in sorted(active,key=lambda j:j.job_id):
            phase=False
            if 'workflow' in job.request['plan']['payload']:
                phase=control_module('setup_phases').WorkflowPhaseStore(self.settings).records(job)['system']['result'] is not None
            data=(ClosedWorkflowEvidence(self.settings).load(job.job_id) if phase else
                  ClosedFailureEvidence(self.settings,clock=self.clock).load(job.job_id))
            closed.append(dict(data,kind='closed_workflow_phase' if phase else 'closed_full_failure'))
        leases=sorted(identifier for row in closed for identifier in row['lease_ids'])
        actual=[r for r in self.jobs.unresolved_legacy_reservations(self.settings) if r['run_id'] not in retry.reviewed_legacy_runs(self.settings)]
        if (len(set(leases))!=len(leases) or sorted(r['reservation_id'] for r in actual)!=leases
                or any(r['state']!='unknown_requires_review' for r in actual)):raise denied()
        return repository,closed,leases

    def _snapshot_all(self):
        repository,closed,leases=self._discover();history=self._history(closed);validators=self._validators();covered=[]
        for row in closed:
            job=repository.get(row['job_id']);fresh=self.observer(job);process=None;phase=None
            if row['kind']=='closed_workflow_phase':
                self._validate_joined(row['original'],fresh)
                if (len(fresh['computer']['objects'])!=1 or any(fresh['computer']['objects'][0].get(k)!=v
                        for k,v in row['computer'].items())):raise denied()
                process=self.quiet(job);mode='phase_joined';phase=row['phase'];run_id=row['legacy_run_id']
            else:
                run_id=row['failed_run_id']
                if 'partial_local' in fresh:
                    from .setup_partial_observation import validate_evidence
                    validate_evidence(row,fresh,mode='partial_ad');mode='partial_ad'
                else:self._validate_joined(row['original'],fresh);mode='joined'
            covered.append({'job_id':row['job_id'],'kind':row['kind'],'legacy_run_id':run_id,
                'configuration_run_id':row['configuration_run_id'],'phase':phase,'history_sha256':row['history_sha256'],
                'lease_ids':row['lease_ids'],'mode':mode,'evidence':fresh,'process_evidence':process})
        _,after,after_leases=self._discover()
        if ([r['job_id'] for r in after]!=[r['job_id'] for r in closed] or after_leases!=leases
                or self._history(after)!=history or self._validators()!=validators):raise denied()
        value={'covered':covered,'job_ids':[r['job_id'] for r in closed],'lease_ids':leases,'history':history,
               'validators':validators,'purpose':self.purpose,'execution_window_seconds':21600}
        validate_payload(value)
        return value

    def _plan_snapshot(self,payload):
        validate_payload(payload)
        return self._snapshot_all()
