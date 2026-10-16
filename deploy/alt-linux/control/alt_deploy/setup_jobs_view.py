"""Bounded public Setup projections; protected requests/results/logs stay private."""
import copy
import re

from .ad_directory import fail
from .setup_jobs import SetupJobRepository, UUID, service_uid, publish, timestamp, queue_check
from .setup_events import SetupEventStore
from .setup_plans import private_read

VERIFY_FIELDS = {'version', 'status', 'installation_status', 'acceptance_status', 'operator_action'}
VERIFY_STATES = {'not_selected', 'compliant', 'missing', 'drifted', 'blocked', 'unknown'}
ACTIONS = {None, 'fresh_verification', 'supported_os_required', 'review_user_identity', 'first_domain_login',
           'verify_dependencies', 'new_confirmed_plan', 'functional_acceptance'}
RECOMMENDATIONS = {'queued': 'watch_job', 'preflight': 'watch_job', 'running': 'watch_job', 'verifying': 'watch_job',
    'waiting_reboot': 'reboot_with_operator_approval_then_verify_continuation',
    'waiting_first_login': 'perform_real_domain_login_then_verify_continuation',
    'unknown_requires_review': 'inspect_fresh_target_before_new_plan', 'failed': 'fix_preflight_then_create_new_plan',
    'degraded': 'verify_then_create_new_plan', 'successful': 'perform_functional_acceptance_if_required'}
EXECUTION_FIELDS = {'schema_version', 'operation', 'job_id', 'machine_uuid', 'plan_id', 'plan_sha256',
    'components', 'original_boot_id', 'reboot_required', 'operator_action_required', 'error_code',
    'created_at', 'finished_at', 'state', 'stage'}
OPTIONAL_EXECUTION_FIELDS = {'verification', 'legacy_run', 'legacy_error_run_id', 'post_error_package_manager', 'post_error_packages'}
CANCEL_STAGE = 'operator_cancelled_before_execution'
CANCEL_FIELDS = {'schema_version', 'operation', 'job_id', 'machine_uuid', 'plan_id', 'plan_sha256',
    'state', 'stage', 'error_code', 'components', 'reboot_required', 'operator_action_required',
    'target_changes_started', 'created_at', 'finished_at'}


def _cancellation(job, result):
    try:
        history = job.status['stage_history']
        if (set(result) != CANCEL_FIELDS or type(result['schema_version']) is not int
                or result['schema_version'] != 2 or result['operation'] != 'setup_job_cancel'
                or any(result[k] != job.status[k] for k in ('job_id', 'machine_uuid', 'plan_id', 'plan_sha256'))
                or result['state'] != 'failed' or result['stage'] != CANCEL_STAGE
                or result['error_code'] != CANCEL_STAGE or result['components'] != {}
                or any(result[k] is not False for k in ('reboot_required', 'operator_action_required', 'target_changes_started'))
                or not job.status['claimed'] or len(history) not in (2, 3)
                or [h['state'] for h in history[:2]] != ['queued', 'preflight']
                or history[1]['stage'] != 'preflight'
                or len(history) == 3 and not (history[2]['state'] == 'unknown_requires_review'
                    or history[2]['state'] == 'failed' and history[2]['stage'] == CANCEL_STAGE)
                or not timestamp(history[1]['at']) <= timestamp(result['created_at']) <= timestamp(result['finished_at'])
                or job.state == 'failed' and timestamp(result['finished_at']) > timestamp(job.status['updated_at'])):
            raise ValueError
        return result
    except (TypeError, ValueError, KeyError) as exc:
        raise _invalid() from exc


def _invalid():
    return fail('setup_execution_result_invalid', 'Setup completion projection is invalid; inspect protected evidence')


def _verification(value, version):
    if value is None:
        return None
    if (not isinstance(value, dict) or not {'version', 'status'} <= set(value) <= VERIFY_FIELDS
            or type(value['version']) is not int or value['version'] != version or value['status'] not in VERIFY_STATES
            or value.get('operator_action') not in ACTIONS
            or value.get('installation_status') not in (None, 'unverified', 'installed_verified')
            or value.get('acceptance_status') not in (None, 'unverified', 'technical_verified', 'functional_verification_required')):
        raise _invalid()
    return copy.deepcopy(value)


class SetupJobsService:
    def __init__(self, settings, *, jobs=None, engine=None):
        self.settings = settings
        self.jobs = jobs or SetupJobRepository(settings)
        self.events = SetupEventStore(settings)
        self.engine = engine

    def _project(self, job):
        status = job.status
        payload = job.request['plan']['payload']
        selected = [payload['component']] if job.request['operation'] == 'component' else payload.get('components', [])
        if (not isinstance(selected, list) or not 1 <= len(selected) <= 256
                or any(not isinstance(c, dict) or not isinstance(c.get('id'), str)
                    or not re.fullmatch('[a-z][a-z0-9_.-]{0,127}', c['id'])
                    or type(c.get('version')) is not int or c['version'] < 1 for c in selected)
                or len({c['id'] for c in selected}) != len(selected)
                or payload.get('catalog_version') is not None and
                    (type(payload['catalog_version']) is not int or payload['catalog_version'] < 1)
                or any(payload.get(k) is not None and (not isinstance(payload[k], str)
                    or not re.fullmatch('[0-9a-f]{64}', payload[k])) for k in ('catalog_sha256', 'source_sha256'))):
            raise _invalid()
        components = {c['id']: {'version': c['version'], 'changed': None, 'verification': None} for c in selected}
        code, reboot, action = None, False, job.state != 'successful'
        if job.state == 'queued':
            check = queue_check(self.settings, job)
            if check is not None:
                code = check['code']
        projected_state = job.state
        path = job.job_dir/'execution.json'
        if path.exists() or path.is_symlink():
            result = private_read(path, owner_uid=service_uid(self.settings))
            if result.get('operation') == 'setup_job_cancel':
                cancelled = _cancellation(job, result)
                result = {k: v for k, v in cancelled.items() if k != 'target_changes_started'}
                result.update(operation='setup_execution', original_boot_id=None,
                    components={c['id']: {'version': c['version'], 'changed': False, 'verification': None}
                                for c in selected})
            try:
                if (not EXECUTION_FIELDS <= set(result) <= EXECUTION_FIELDS | OPTIONAL_EXECUTION_FIELDS
                        or result['schema_version'] != 2 or result['operation'] != 'setup_execution'
                        or any(result[k] != status[k] for k in ('job_id', 'machine_uuid', 'plan_id', 'plan_sha256'))
                        or set(result['components']) != set(components)
                        or type(result['reboot_required']) is not bool or type(result['operator_action_required']) is not bool
                        or (result['error_code'] is not None and (not isinstance(result['error_code'], str)
                            or not re.fullmatch(r'[a-z][a-z0-9_]{1,79}', result['error_code'])))):
                    raise ValueError
                for identifier, component in result['components'].items():
                    if (set(component) != {'version', 'changed', 'verification'}
                            or type(component['version']) is not int or component['version'] != components[identifier]['version']
                            or component['changed'] is not None and type(component['changed']) is not bool):
                        raise ValueError
                    components[identifier] = {'version': component['version'], 'changed': component['changed'],
                        'verification': _verification(component['verification'], component['version'])}
                code, reboot, action = result['error_code'], result['reboot_required'], result['operator_action_required']
                if result['state'] != job.state or result['stage'] != job.stage:
                    code, action = 'setup_completion_record_mismatch', True
                    projected_state = 'unknown_requires_review'
            except (TypeError, ValueError, KeyError) as exc:
                raise _invalid() from exc
        elif job.state in ('successful', 'degraded', 'waiting_reboot', 'waiting_first_login'):
            code, action, projected_state = 'setup_completion_evidence_missing', True, 'unknown_requires_review'
        profile = payload.get('profile')
        if profile is not None:
            if (not isinstance(profile, dict) or not isinstance(profile.get('id'), str)
                    or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,127}', profile['id'])
                    or type(profile.get('version')) is not int or profile['version'] < 1):
                raise _invalid()
            profile = {'id': profile['id'], 'version': profile['version']}
        return {'job_id': job.job_id, 'operation': job.request['operation'], 'machine_uuid': job.machine_uuid,
            'state': projected_state, 'recorded_state': job.state, 'stage': job.stage, 'plan_id': status['plan_id'], 'plan_sha256': status['plan_sha256'],
            'created_at': status['created_at'], 'updated_at': status['updated_at'], 'claimed': status['claimed'],
            'catalog_version': payload.get('catalog_version'), 'profile': profile,
            'catalog_sha256': payload.get('catalog_sha256'), 'source_sha256': payload.get('source_sha256'),
            'components': components, 'error_code': code, 'reboot_required': reboot,
            'operator_action_required': action, 'recommended_action': RECOMMENDATIONS[projected_state],
            'history': copy.deepcopy(status['stage_history'][-100:]), 'history_total': len(status['stage_history'])}

    def list(self, machine_uuid=None, *, offset=0, limit=100):
        if (machine_uuid is not None and (not isinstance(machine_uuid, str) or not UUID.fullmatch(machine_uuid))
                or type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100):
            raise fail('setup_job_query_invalid', 'Use a UUID and bounded job pagination')
        jobs = sorted(self.jobs.list(machine_uuid), key=lambda j: j.status['admission_sequence'], reverse=True)
        return {'schema_version': 2, 'operation': 'setup_jobs_list', 'status': 'ok',
                'jobs': [self._project(j) for j in jobs[offset:offset+limit]], 'total': len(jobs),
                'next_offset': min(len(jobs), offset+limit)}

    def status(self, job_id):
        return {'schema_version': 2, 'operation': 'setup_job_status', 'status': 'ok',
                'job': self._project(self.jobs.get(job_id))}

    def cancel(self, job_id, confirmed_plan_sha):
        from .locks import exclusive_lock
        from .setup_worker import process_identity
        with exclusive_lock(self.settings.lock_file):
            self.jobs._check_admissions()
            job = self.jobs.get(job_id)
            if (not isinstance(confirmed_plan_sha, str) or not re.fullmatch('[0-9a-f]{64}', confirmed_plan_sha)
                    or confirmed_plan_sha != job.status['plan_sha256']):
                raise fail('setup_cancel_plan_mismatch', 'Cancellation requires the exact admitted plan SHA')
            path = job.job_dir/'execution.json'
            if job.state == 'failed' and job.stage == CANCEL_STAGE:
                return copy.deepcopy(_cancellation(job, private_read(path, owner_uid=service_uid(self.settings))))
            if job.state != 'queued' or job.status['claimed'] or path.exists() or path.is_symlink():
                raise fail('setup_cancel_not_permitted', 'Only an unclaimed queued job can be cancelled')
            job = self.jobs.claim(job_id, process_identity(self.settings))
            now = self.jobs.clock().isoformat()
            result = {'schema_version': 2, 'operation': 'setup_job_cancel', 'job_id': job_id,
                'machine_uuid': job.machine_uuid, 'plan_id': job.status['plan_id'],
                'plan_sha256': job.status['plan_sha256'], 'state': 'failed', 'stage': CANCEL_STAGE,
                'error_code': CANCEL_STAGE, 'components': {}, 'reboot_required': False,
                'operator_action_required': False, 'target_changes_started': False,
                'created_at': now, 'finished_at': now}
            publish(path, result, create=True)
            self.jobs.transition(job_id, 'failed', stage={'id': CANCEL_STAGE})
            return copy.deepcopy(result)

    def events_for(self, job_id, *, after=0, limit=100):
        self.jobs.get(job_id)
        result = self.events.read(job_id, after=after, limit=limit)
        return dict(result, schema_version=2, operation='setup_job_events', status='ok')

    def verify_continuation(self, job_id):
        if self.engine is None:
            from .setup_execution import SetupExecutionEngine
            self.engine = SetupExecutionEngine(self.settings)
        self.engine.verify_continuation(job_id)
        return dict(self.status(job_id), operation='setup_job_continuation')
