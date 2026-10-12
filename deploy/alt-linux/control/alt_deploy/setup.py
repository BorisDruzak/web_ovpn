"""Setup orchestration around the existing fixed configuration pipeline."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from .ad_directory import ADDirectory, DOMAIN, fail
from .ad_transport import DirectoryConfig, LDAPTransport
from .configure import ConfigurePlanner, ConfigureRequest, _read_configure_result
from .errors import ControlError
from .locking import exclusive_lock
from .registry import MachineRepository
from .setup_assignments import DomainAssignmentStore
from .setup_plans import SetupPlanStore, digest, private_create, private_read, private_replace

RUN_RE = re.compile(r'^setup-run-[0-9a-f]{32}$')


def computer_matches(computer, hostname, ou):
    return (computer['dn'].casefold() == ('CN=' + hostname + ',' + ou).casefold()
            and computer.get('dns_hostname', '').lower() == hostname.lower() + '.' + DOMAIN)


def observed_computer_matches(observed, computer, hostname):
    identity = observed.get('computer_identity')
    return (isinstance(identity, dict)
            and identity.get('sam_account_name') == hostname.lower() + '$'
            and identity.get('object_guid') == computer.get('object_guid')
            and identity.get('object_sid') == computer.get('object_sid')
            and str(identity.get('dn', '')).casefold() == computer['dn'].casefold()
            and identity.get('dns_hostname') == computer.get('dns_hostname'))


class SetupService:
    def __init__(self, settings, *, directory=None, machines=None, planner=None,
                 approved_ous=None, probe=None, prerequisites=None, clock=None, recovery_terminal_verifier=None):
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        config = DirectoryConfig.load() if directory is None or approved_ous is None else None
        self.directory = directory or ADDirectory(LDAPTransport(config, settings=settings))
        self.approved_ous = tuple(approved_ous if approved_ous is not None else config.approved_ous)
        self.machines = machines or MachineRepository(settings)
        self.planner = planner or ConfigurePlanner(settings, machines=self.machines)
        if probe is None or prerequisites is None:
            from .setup_runtime import SetupRuntime
            runtime = SetupRuntime(settings)
            probe = probe or runtime.probe
            prerequisites = prerequisites or runtime.prerequisites
        self.probe = probe
        self.prerequisites = prerequisites
        self.plans = SetupPlanStore(settings.state_root, clock=self.clock)
        self.assignments = DomainAssignmentStore(settings.state_root)
        from .setup_recovery_resolution import RecoveryResolutionStore
        self.recovery_resolutions = RecoveryResolutionStore(settings, terminal_verifier=recovery_terminal_verifier, clock=self.clock)

    def _snapshot(self, identifier, login, ou, software, remote, *, recovery_resolution=None):
        machine = self.machines.resolve(identifier)
        if machine.registration_state != 'ready':
            raise fail('machine_not_ready', 'Machine registration is not ready')
        if machine.active_job:
            raise fail('setup_active_job', 'Machine has an active incompatible job')
        if machine.assignment:
            raise fail('assignment_conflict', 'Existing local provision assignment requires compatibility review')
        if not ou or ou not in self.approved_ous:
            raise fail('setup_ou_not_approved', 'Select an explicitly approved computer OU from controller configuration')
        ous = [entry for entry in self.directory.ous() if entry['dn'].casefold() == ou.casefold()]
        if len(ous) != 1:
            raise fail('setup_ou_not_found', 'Approved computer OU is missing or ambiguous in AD')
        user = self.directory.user(login)
        if user.get('state') != 'enabled':
            raise fail('ad_user_state_unknown', 'Selected user is not verified as enabled')
        request = ConfigureRequest.from_mapping({
            'machine_uuid': machine.uuid, 'final_hostname': machine.hostname,
            'hostname_mode': 'verify', 'profile': 'standard-domain', 'domain': DOMAIN,
            'realm': 'SOSNADMIN.LOCAL', 'workgroup': 'SOSNADM', 'computer_ou': ou,
            'domain_test_user': user['upn'], 'assigned_domain_user': user['upn'],
            'software_profile': software, 'remote_access_profile': remote,
        }, expected_uuid=machine.uuid)
        binding = self.assignments.identity_binding(machine.uuid, user, ou, software, remote)
        resolution = None
        if recovery_resolution is None:
            existing = self.assignments.check(binding)
        else:
            existing = self.assignments.get(machine.uuid)
            resolution = self.recovery_resolutions.validate(recovery_resolution, existing)
            if any(existing.get(key) != value for key, value in binding.items()):
                raise fail("assignment_conflict", "Recovery continuation identity differs from original binding")
        ready = self.prerequisites(request)
        if ready.get('ready') is not True:
            raise fail('setup_prerequisites_failed', 'Controller setup prerequisites are not ready')
        observed = self.probe(machine, user)
        required_observations = {'uuid', 'hostname', 'domain', 'trust', 'sssd', 'user_lookup', 'local_duplicate', 'home_exists'}
        if (not isinstance(observed, dict) or not required_observations <= observed.keys()
                or any(type(observed[key]) is not bool for key in ('trust', 'sssd', 'user_lookup', 'local_duplicate', 'home_exists'))):
            raise fail('setup_probe_invalid', 'Read-only workstation state cannot be verified')
        if observed['uuid'] != machine.uuid or observed['hostname'].lower() != machine.hostname.lower():
            raise fail('setup_machine_identity_mismatch', 'Observed workstation UUID or hostname differs from registration')
        if observed['domain'] not in ('', DOMAIN):
            raise fail('domain_conflict', 'Workstation belongs to another domain')
        if observed['local_duplicate']:
            raise fail('setup_local_user_conflict', 'A local account duplicates the selected domain login')
        computer = self.directory.computer(machine.hostname)
        objects = computer['objects']
        if observed['trust']:
            if (observed['domain'] != DOMAIN or len(objects) != 1
                    or not computer_matches(objects[0], machine.hostname, ou)
                    or not observed_computer_matches(observed, objects[0], machine.hostname)):
                raise fail('domain_computer_conflict', 'Joined computer identity or OU differs; no reset or move is allowed')
        elif objects or observed['domain']:
            raise fail('domain_computer_conflict', 'Existing computer account or broken domain binding requires recovery review')
        if resolution is not None:
            from .setup_recovery_continuation import validate_continuity
            validate_continuity(resolution, user, ous[0], observed, computer, machine)
        preview = self.planner.preview(machine.uuid, request)
        changes = ['configure_domain_baseline', 'verify_selected_domain_user']
        if not observed['trust']:
            changes.insert(0, 'domain_join')
        if software == 'core-apps':
            changes.append('ensure_core_apps_including_signature_suite')
        if remote == 'krfb':
            changes.append('ensure_opt_in_krfb')
        payload = {'machine': {'uuid': machine.uuid, 'hostname': machine.hostname, 'ip': machine.ip,
                            'registration_sha256': digest(machine.raw)},
                'user': user, 'computer_ou': ou, 'ou_identity': ous[0], 'computer': computer,
                'observed': observed, 'request': request.to_dict(), 'binding': binding,
                'existing_assignment': existing, 'prerequisites': ready, 'changes': changes,
                'actions': preview['actions'], 'warnings': ['delegated_computer_creation_right_not_proven'] if not observed['trust'] else [],
                'deferred_actions': ['user_home_operations_wait_for_first_domain_login'] if not observed['home_exists'] else []}
        if recovery_resolution is not None:
            payload['recovery_resolution'] = recovery_resolution
        return payload

    def plan(self, identifier, login, ou, software='core-apps', remote='none'):
        # Do not create a lock file, assignments or run records during preview.
        payload = self._snapshot(identifier, login, ou, software, remote)
        return self.plans.create(payload)

    def _run_path(self, run_id):
        if not RUN_RE.fullmatch(run_id):
            raise fail('setup_run_invalid', 'Setup run identifier is invalid')
        return self.settings.state_root / 'setup-runs' / (run_id + '.json')

    def status(self, run_id):
        return private_read(self._run_path(run_id))

    def apply(self, plan_id, confirmed_sha):
        with exclusive_lock(self.settings.lock_file):
            plan = self.plans.load(plan_id, confirmed_sha)
            index_path = self.settings.state_root / 'setup-plan-runs' / (plan_id + '.json')
            if index_path.exists() or index_path.is_symlink():
                index = private_read(index_path)
                result = self.status(index['run_id'])
                if result.get('status') in ('running', 'failed', 'interrupted'):
                    raise fail('setup_previous_run_unresolved', 'This plan already has a run requiring manual review; automatic replay is blocked')
                return result
            before = plan['payload']
            request = ConfigureRequest.from_mapping(before['request'], expected_uuid=before['machine']['uuid'])
            current = self._snapshot(request.machine_uuid, before['user']['login'], request.computer_ou,
                                      request.software_profile, request.remote_access_profile,
                                      recovery_resolution=before.get('recovery_resolution'))
            if current != before:
                raise fail('setup_plan_drift', 'Setup identity or prerequisites changed; create a new plan')
            run_id = 'setup-run-' + uuid.uuid4().hex
            date = self.clock().isoformat()
            revision = (current['existing_assignment'] or {}).get('revision', 0) + 1
            run = {'schema_version': 1, 'run_id': run_id, 'plan_id': plan_id, 'plan_sha256': confirmed_sha,
                   'machine_uuid': request.machine_uuid, 'status': 'running', 'created_at': date,
                   'reboot_required': None, 'deferred_actions': current['deferred_actions']}
            private_create(self._run_path(run_id), run)
            private_create(index_path, {'run_id': run_id})
            self.assignments.write(current['binding'], run_id=run_id, result='running', date=date, revision=revision)
            try:
                endpoint = current['prerequisites'].get('directory_uri')
                options = {'setup_directory_uri': endpoint} if endpoint is not None else {}
                result = self.planner.start(request.machine_uuid, request, _lock_held=True, setup_run_id=run_id, **options)
                run.update(configuration_run_id=result['run_id'], result=result,
                           reboot_required=result.get('reboot_required', False))
                private_replace(self._run_path(run_id), run)
                machine = self.machines.get(request.machine_uuid)
                post = self.probe(machine, current['user'])
                fresh_user = self.directory.user(current['user']['login'])
                computer = self.directory.computer(machine.hostname)
                if (fresh_user['object_guid'] != current['user']['object_guid']
                        or fresh_user.get('object_sid') != current['user'].get('object_sid')
                        or fresh_user['upn'] != current['user']['upn']
                        or fresh_user['state'] != 'enabled'
                        or post['uuid'] != request.machine_uuid or post['hostname'] != request.final_hostname
                        or post['domain'] != DOMAIN or not post['trust'] or not post['sssd']
                        or not post['user_lookup'] or post['local_duplicate']
                        or result.get('verification', {}).get('group_policy') is not True
                        or len(computer['objects']) != 1
                        or not computer_matches(computer['objects'][0], machine.hostname, request.computer_ou)
                        or not observed_computer_matches(post, computer['objects'][0], machine.hostname)
                        or (current['computer']['objects'] and any(
                            computer['objects'][0].get(key) != current['computer']['objects'][0].get(key)
                            for key in ('object_guid', 'object_sid')))):
                    raise fail('setup_post_verification_failed', 'Setup did not verify the selected domain identity and computer OU')
                run.update(status=result.get('status', 'successful'), configuration_run_id=result['run_id'],
                           result=result, verification=post, computer=computer,
                           reboot_required=result.get('reboot_required', False), finished_at=self.clock().isoformat())
            except Exception as exc:
                code = exc.code if isinstance(exc, ControlError) else 'setup_execution_failed'
                run.update(status='failed', error={'code': code, 'message': 'Setup execution failed; inspect protected configuration result before any retry'},
                           finished_at=self.clock().isoformat(), partial_failure=True)
                if isinstance(exc, ControlError) and re.fullmatch(r'[0-9a-f]{32}', str(exc.details.get('run_id', ''))):
                    run['configuration_run_id'] = exc.details['run_id']
                    try:
                        configuration_result = _read_configure_result(private_read(
                            self.settings.state_root / 'configure-runs' / exc.details['run_id'] / 'result.json'), request)
                        run.update(result=configuration_result,
                                   reboot_required=configuration_result.get('reboot_required', False))
                    except (ControlError, ValueError, OSError):
                        run['configuration_result_unavailable'] = True
                private_replace(self._run_path(run_id), run)
                self.assignments.write(current['binding'], run_id=run_id, result='failed', date=date, revision=revision)
                raise ControlError('setup_execution_failed', 'Setup failed; manual review is required before retry', 7, {'run_id': run_id}) from None
            private_replace(self._run_path(run_id), run)
            self.assignments.write(current['binding'], run_id=run_id, result=run['status'], date=date, revision=revision)
            return run

    def verify(self, identifier):
        machine = self.machines.resolve(identifier)
        binding = self.assignments.get(machine.uuid)
        if binding is None:
            raise fail('setup_assignment_missing', 'No selected domain user is recorded for this machine')
        user = self.directory.user(binding['login'])
        if user['object_guid'] != binding['object_guid'] or user.get('object_sid') != binding['object_sid']:
            raise fail('assignment_conflict', 'Recorded AD user identity changed')
        observed = self.probe(machine, user)
        computer = self.directory.computer(machine.hostname)
        previous_run = self.status(binding['run_id'])
        previous_computer = previous_run.get('computer', {}).get('objects', [])
        passed = (observed['uuid'] == machine.uuid and observed['hostname'] == machine.hostname
                  and observed['domain'] == DOMAIN and observed['trust'] and observed['sssd']
                  and observed['user_lookup'] and not observed['local_duplicate']
                  and len(computer['objects']) == 1
                  and computer_matches(computer['objects'][0], machine.hostname, binding['computer_ou'])
                  and observed_computer_matches(observed, computer['objects'][0], machine.hostname))
        if (len(previous_computer) != 1 or len(computer['objects']) != 1
                or any(previous_computer[0].get(key) != computer['objects'][0].get(key)
                       for key in ('object_guid', 'object_sid'))):
            passed = False
        return {'status': 'successful' if passed else 'failed', 'machine_uuid': machine.uuid,
                'verification': observed, 'computer': computer, 'run': previous_run,
                'group_policy_last_run': previous_run.get('result', {}).get('verification', {}).get('group_policy'),
                'home_operations_deferred': not observed['home_exists']}
