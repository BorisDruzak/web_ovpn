"""Seal a late UNKNOWN without changing its successful original domain run."""
import hashlib
import re
import stat

from .setup_compat import control_module,validate_job,PHASE_DIRECTORIES
from .fs import read_regular_bytes


def denied():
    return control_module('ad_directory').fail('setup_workflow_closed_unverified',
        'Original completed system and consumed phase history are incomplete or unsafe')


class ClosedWorkflowEvidence:
    def __init__(self,settings):
        self.settings=settings;self.io=control_module('setup_plans');self.jobs=control_module('setup_jobs')
        self.uid=self.jobs.service_uid(settings)

    def _read(self,path):return self.io.private_read(path,owner_uid=self.uid)

    def _hash(self,path):
        info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self.uid or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o600):raise denied()
        return hashlib.sha256(read_regular_bytes(path,max_bytes=64*1024*1024)).hexdigest()

    def load(self,job_id):
        try:return self._load(job_id)
        except Exception:raise denied() from None

    def _load(self,job_id):
        root=self.settings.state_root;repository=self.jobs.SetupJobRepository(self.settings)
        repository._check_admissions();job=repository.get(job_id)
        if job.state!='unknown_requires_review' or job.request['operation']!='full_setup' or not job.status['claimed']:raise denied()
        validate_job(job.request,job.status,job.job_dir)
        original=job.request['plan']['payload'];workflow=control_module('full_workflow').archived_workflow(original)
        store=control_module('setup_phases').WorkflowPhaseStore(self.settings);records=store.records(job)
        system=records['system']['result']
        if system is None:raise denied()
        execution=self._read(job.job_dir/'execution.json');run=execution['legacy_run']
        run_id=run['run_id'];configure_id=run['configuration_run_id']
        if (not re.fullmatch('setup-run-[0-9a-f]{32}',run_id) or not re.fullmatch('[0-9a-f]{32}',configure_id)
                or run!=self._read(root/'setup-runs'/(run_id+'.json')) or run['status']!='successful'
                or run['machine_uuid']!=job.machine_uuid or run['plan_id']!=job.status['plan_id']
                or run['plan_sha256']!=job.status['plan_sha256']
                or execution['job_id']!=job_id or execution['plan_sha256']!=job.status['plan_sha256']
                or set(execution['components'])!={c['id'] for c in original['components']}):raise denied()
        created,finished=(self.jobs.timestamp(run[k]) for k in ('created_at','finished_at'))
        if not (self.jobs.timestamp(job.status['created_at'])<=created<=finished<=self.jobs.timestamp(job.status['updated_at'])):raise denied()
        plan=job.request['plan']
        if (self._read(root/'setup-plans'/(plan['plan_id']+'.json'))!=plan
                or self._read(root/'setup-plan-runs'/(plan['plan_id']+'.json'))!={'run_id':run_id}):raise denied()
        request=control_module('configure').historical_setup_request(original,expected_uuid=job.machine_uuid)
        configure=root/'configure-runs'/configure_id
        if self._read(configure/'request.json')!=request.to_dict():raise denied()
        result=control_module('configure')._read_configure_result(self._read(configure/'result.json'),request)
        control_module('full_workflow').validate_system_result(result,workflow)
        if dict(result,run_id=configure_id)!=run['result']:raise denied()
        computer=system['result']['computer']
        if (run['computer'].get('exists') is not True or len(run['computer']['objects'])!=1
                or any(run['computer']['objects'][0].get(k)!=v for k,v in computer.items())):raise denied()
        binding=self._read(root/'domain-assignments'/(job.machine_uuid+'.json'))
        expected=dict(original['binding'],schema_version=1,
            revision=(original.get('existing_assignment') or {}).get('revision',0)+1,
            run_id=run_id,date=run['created_at'],result='successful')
        if binding!=expected:raise denied()
        leases=[r for r in self.jobs.legacy_execution_reservations(self.settings) if r['run_id'] in (run_id,configure_id)]
        if (len(leases)!=2 or {(r['operation'],r['run_id']) for r in leases}!={('full_setup',run_id),('configure',configure_id)}
                or any(r['state']!='completed' or r['machine_uuid']!=job.machine_uuid
                    or r['hostname']!=job.request['identities']['hostname'] for r in leases)):raise denied()
        phase=job.status.get('workflow',{}).get('current_phase','user')
        paths=[p for p in job.job_dir.rglob('*') if not p.is_dir()]
        paths += [root/'setup-runs'/(run_id+'.json'),configure/'request.json',configure/'result.json',
            root/'setup-plans'/(plan['plan_id']+'.json'),root/'setup-plan-runs'/(plan['plan_id']+'.json'),
            root/'domain-assignments'/(job.machine_uuid+'.json'),
            root/'setup-job-plan-claims'/(plan['sha256']+'.json'),root/'setup-job-reservations'/(job_id+'.json')]
        paths += [root/'legacy-setup-reservations'/(r['reservation_id']+'.json') for r in leases]
        for name in PHASE_DIRECTORIES:
            directory=root/name
            if directory.exists():paths+=list(directory.glob(job_id+'--*.json'))
        for name in ('ansible.log',):
            path=configure/name
            if path.exists() or path.is_symlink():paths.append(path)
        for identifier in ('user','final_dns'):
            row=records[identifier]
            if row['claim'] is None and any((job.job_dir/('phase-'+identifier+suffix)).exists()
                    for suffix in ('-vars.json','-result.json','-process.json','.log')):raise denied()
        manifest={str(path.relative_to(root)):self._hash(path) for path in sorted(set(paths))}
        if any(self._hash(root/name)!=sha for name,sha in manifest.items()):raise denied()
        return {'schema_version':1,'kind':'closed_workflow_phase','job_id':job_id,'phase':phase,
            'legacy_run_id':run_id,'configuration_run_id':configure_id,'original':original,'computer':computer,
            'binding':binding,'lease_ids':[],'history_sha256':self.io.digest(manifest),'manifest':manifest}

    def quiet(self,job):
        """Fresh process proof supplements, never rewrites, retained outcomes."""
        records=control_module('setup_phases').WorkflowPhaseStore(self.settings).records(job)
        processes=control_module('workflow_phase_process')
        for phase in ('user','final_dns'):
            claim=records[phase]['claim']
            if claim is not None and not processes.child_quiet(self.settings,job,phase,claim):raise denied()
        machine=control_module('setup').SetupService(self.settings).machines.resolve(job.machine_uuid)
        value=control_module('setup_phase_probe').observe_mutators(self.settings,machine)
        if value['quiet'] is not True:raise denied()
        return value
