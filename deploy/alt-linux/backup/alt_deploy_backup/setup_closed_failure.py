"""Read-only capsule of one original closed full-Setup failure and its leases."""
from datetime import datetime, timezone
import hashlib
import re

from .setup_compat import control_module, validate_job


def denied():
    return control_module('ad_directory').fail('setup_closed_failure_invalid',
        'Original closed Setup history is incomplete, changed or unsafe; no execution is admitted')


class ClosedFailureEvidence:
    def __init__(self, settings, *, clock=None):
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.io = control_module('setup_plans')
        self.jobs = control_module('setup_jobs')
        self.uid = self.jobs.service_uid(settings)

    def _read(self, path):
        return self.io.private_read(path, owner_uid=self.uid)

    def load(self, job_id):
        try:
            return self._load(job_id)
        except Exception:
            raise denied() from None

    def _load(self, job_id):
        root = self.settings.state_root
        repository = self.jobs.SetupJobRepository(self.settings)
        repository._check_admissions()
        job = repository.get(job_id)
        if job.state != 'unknown_requires_review' or job.request['operation'] != 'full_setup' or not job.status['claimed']:
            raise denied()
        validate_job(job.request, job.status, job.job_dir)
        execution = self._read(job.job_dir/'execution.json')
        run_id = execution.get('legacy_error_run_id')
        if not isinstance(run_id, str) or not re.fullmatch('setup-run-[0-9a-f]{32}', run_id):
            raise denied()
        reference = control_module('setup_retry').full_predecessor(self.settings, job_id, job.machine_uuid, run_id)
        ended = datetime.fromisoformat(execution['finished_at'])
        if ended.tzinfo is None or ended > self.clock():
            raise denied()
        run = self._read(root/'setup-runs'/(run_id+'.json'))
        config_id = run.get('configuration_run_id')
        if not isinstance(config_id, str) or not re.fullmatch('[0-9a-f]{32}', config_id):
            raise denied()
        created, finished = (datetime.fromisoformat(run[k]) for k in ('created_at', 'finished_at'))
        if created.tzinfo is None or finished.tzinfo is None or not created <= finished <= ended:
            raise denied()
        original = job.request['plan']['payload']
        request = control_module('configure').historical_setup_request(original, expected_uuid=job.machine_uuid)
        plan = self.io.SetupPlanStore(root, clock=lambda: created).load(run['plan_id'], run['plan_sha256'])
        if plan != job.request['plan']:
            raise denied()
        configure = root/'configure-runs'/config_id
        if self._read(configure/'request.json') != request.to_dict():
            raise denied()
        result = control_module('configure')._read_configure_result(self._read(configure/'result.json'), request)
        if result['status'] != 'failed' or run.get('result') != result:
            raise denied()
        binding = self._read(root/'domain-assignments'/(job.machine_uuid+'.json'))
        expected = dict(original['binding'], schema_version=1,
            revision=(original.get('existing_assignment') or {}).get('revision', 0)+1,
            run_id=run_id, date=run['created_at'], result='failed')
        if (binding != expected or type(binding.get('revision')) is not int
                or binding['revision'] < 1 or type(binding.get('schema_version')) is not int):
            raise denied()
        index = root/'setup-plan-runs'/(run['plan_id']+'.json')
        if self._read(index) != {'run_id': run_id}:
            raise denied()
        leases = [r for r in self.jobs.unresolved_legacy_reservations(self.settings)
                  if r['machine_uuid'] == job.machine_uuid or r['hostname'] == job.request['identities']['hostname']]
        if (len(leases) != 2 or {(r['operation'], r['run_id']) for r in leases} != {('full_setup', run_id), ('configure', config_id)}
                or any(r['machine_uuid'] != job.machine_uuid or r['hostname'] != job.request['identities']['hostname']
                       or r['state'] != 'unknown_requires_review' or r['supersedes'] for r in leases)):
            raise denied()
        paths = [root/'setup-runs'/(run_id+'.json'), configure/'request.json', configure/'result.json',
                 root/'setup-plans'/(plan['plan_id']+'.json'), index,
                 root/'domain-assignments'/(job.machine_uuid+'.json')]
        log = configure/'ansible.log'
        if log.exists() or log.is_symlink(): paths.append(log)
        paths += [root/'legacy-setup-reservations'/(r['reservation_id']+'.json') for r in leases]
        paths += [p for p in job.job_dir.iterdir() if p.name != 'events']
        events = job.job_dir/'events'
        if events.exists(): paths += list(events.iterdir())
        files = {str(p.relative_to(root)): self.io.private_read_bytes(p, owner_uid=self.uid) for p in paths}
        manifest = {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}
        if any(self.io.private_read_bytes(root/name, owner_uid=self.uid) != raw for name, raw in files.items()):
            raise denied()
        return {'schema_version': 1, 'job_id': job_id, 'failed_run_id': run_id, 'configuration_run_id': config_id,
                'machine': original['machine'], 'binding': binding, 'original': original, 'run': run,
                'result': result, 'predecessor_job': reference,
                'lease_ids': sorted(r['reservation_id'] for r in leases), 'history_sha256': self.io.digest(manifest),
                'manifest': manifest, 'files': files}
