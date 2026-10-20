"""Setup orchestration around the existing fixed configuration pipeline."""
from __future__ import annotations

import re
import uuid
import time
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
                 approved_ous=None, probe=None, prerequisites=None, clock=None, recovery_terminal_verifier=None, retry_probe=None,
                 catalog=None, component_probe=None, job_waiter=None, join_admission=None):
        self.settings = settings
        self.catalog = catalog
        self.component_probe = component_probe
        self.job_waiter = job_waiter
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
            join_admission = join_admission or runtime.join_admission
        self.probe = probe
        self.prerequisites = prerequisites
        self.join_admission = join_admission
        self.retry_probe = retry_probe
        self.plans = SetupPlanStore(settings.state_root, clock=self.clock)
        self.assignments = DomainAssignmentStore(settings.state_root)
        from .setup_recovery_resolution import RecoveryResolutionStore
        self.recovery_resolutions = RecoveryResolutionStore(settings, terminal_verifier=recovery_terminal_verifier, clock=self.clock)

    def _catalog(self):
        from .component_catalog import ComponentCatalog
        # Injected legacy adapters may use the old interface without an Ansible bundle.
        # Production Settings always supply the fixed, published project directory.
        return self.catalog or (ComponentCatalog.load(self.settings.ansible_project_dir)
                                if hasattr(self.settings, 'ansible_project_dir') else None)

    def _snapshot(self, identifier, login, ou, software, remote, *, recovery_resolution=None, partial_local_resolution=None,
                  own_job_id=None, expected_plan=None, legacy=False):
        from .setup_partial_local_state import assert_no_pending
        assert_no_pending(self.settings)
        if recovery_resolution is not None and partial_local_resolution is not None:
            raise fail('setup_plan_invalid', 'Continuation proof types cannot be combined')
        catalog = None if legacy else self._catalog()
        machine = self.machines.resolve(identifier)
        pending_predecessor = None
        if machine.registration_state != 'ready':
            raise fail('machine_not_ready', 'Machine registration is not ready')
        if machine.active_job:
            active = machine.active_job
            owned = (isinstance(active, dict) and own_job_id is not None and expected_plan is not None
                    and active.get('schema_version') == 2 and active.get('kind') == 'setup'
                    and active.get('job_id') == own_job_id and active.get('machine_uuid') == machine.uuid
                    and active.get('plan_id') == expected_plan['plan_id']
                    and active.get('plan_sha256') == expected_plan['sha256'])
            if not owned:
                binding = self.assignments.get(machine.uuid)
                if (not isinstance(active, dict) or active.get('kind') != 'setup'
                        or active.get('state') != 'unknown_requires_review'
                        or binding is None or binding['result'] != 'failed'):
                    raise fail('setup_active_job', 'Machine has an active incompatible job')
                from .setup_retry import full_predecessor
                pending_predecessor = full_predecessor(self.settings, active['job_id'], machine.uuid, binding['run_id'])
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
        }, expected_uuid=machine.uuid, catalog=catalog)
        workflow=None
        if software=='workstation-full-v1':
            from .full_workflow import build_workflow_plan
            from .vault import VaultHealthChecker
            workflow=build_workflow_plan(catalog,VaultHealthChecker(self.settings).full_workflow_policy())
        binding = self.assignments.identity_binding(machine.uuid, user, ou, software, remote)
        resolution = None
        partial_document = None
        retry_binding = None
        if partial_local_resolution is not None:
            from .setup_partial_local_continuation import validate_resolution
            existing = self.assignments.get(machine.uuid)
            partial_document = validate_resolution(self.settings, partial_local_resolution, existing,
                                                   runtime=getattr(self, 'partial_runtime', None))
            if any(existing.get(key) != value for key, value in binding.items()):
                raise fail('assignment_conflict', 'Partial-local continuation identity differs')
        elif recovery_resolution is None:
            try:
                existing = self.assignments.check(binding)
            except ControlError as exc:
                existing = self.assignments.get(machine.uuid)
                if exc.code != 'setup_previous_run_unresolved' or existing is None or existing.get('result') != 'failed':
                    raise
                retry_binding = existing
        else:
            existing = self.assignments.get(machine.uuid)
            resolution = self.recovery_resolutions.validate(recovery_resolution, existing)
            if any(existing.get(key) != value for key, value in binding.items()):
                raise fail("assignment_conflict", "Recovery continuation identity differs from original binding")
        ready = (self.prerequisites(request,managed_workflow=workflow) if workflow is not None
                 else self.prerequisites(request))
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
        admission = None
        if not observed['trust'] and self.join_admission is not None:
            from .ad_join_preflight import validate_evidence
            admission = validate_evidence(self.join_admission(request))
            if admission['ou_guid'] != ous[0]['object_guid']:
                raise fail('ad_join_ou_changed', 'AD admission OU identity differs from the selected OU')
        if workflow is not None and not observed['trust'] and admission is None:
            raise fail('full_workflow_admission_unverified','The complete workflow requires fresh effective AD creation rights')
        if resolution is not None:
            from .setup_recovery_continuation import validate_continuity
            validate_continuity(resolution, user, ous[0], observed, computer, machine)
        retry = None
        if retry_binding is not None:
            from .setup_prejoin_retry import prejoin_retry_evidence
            from .setup_runtime import SetupRuntime
            retry = prejoin_retry_evidence(self.settings, retry_binding, machine, user, ous[0], observed, computer)
            retry_probe = self.retry_probe or SetupRuntime(self.settings).probe_prejoin
            quiet = retry_probe(machine, retry['configuration_run_id'])
            if (not isinstance(quiet, dict) or quiet.get('uuid') != machine.uuid or quiet.get('hostname') != machine.hostname or
                    quiet.get('credentials_absent') is not True or quiet.get('processes_absent') is not True):
                raise fail('setup_previous_run_unresolved', 'Pre-join processes or credentials are present or cannot be verified')
        preview = self.planner.preview(machine.uuid, request)
        changes = ['configure_domain_baseline', 'verify_selected_domain_user']
        if not observed['trust']:
            changes[0:0] = ['select_approved_p11_package_mirror', 'upgrade_alt_before_domain_join', 'domain_join']
        if software == 'core-apps':
            changes.append('ensure_core_apps_including_signature_suite')
        elif software != 'base':
            changes.append('ensure_published_software_profile')
        if remote == 'krfb' and workflow is None:
            changes.append('ensure_opt_in_krfb')
        elif workflow is not None:
            changes.extend(['prepare_direct_vnc_policy','configure_managed_krfb_after_login','finalize_client_dns'])
        payload = {'machine': {'uuid': machine.uuid, 'hostname': machine.hostname, 'ip': machine.ip,
                            'registration_sha256': digest(machine.raw)},
                'user': user, 'computer_ou': ou, 'ou_identity': ous[0], 'computer': computer,
                'observed': observed, 'request': request.to_dict(), 'binding': binding,
                'existing_assignment': existing, 'prerequisites': ready, 'changes': changes,
                'actions': preview['actions'], 'warnings': ['delegated_computer_creation_right_not_proven'] if not observed['trust'] else [],
                'deferred_actions': ['user_home_operations_wait_for_first_domain_login'] if not observed['home_exists'] else []}
        payload['execution_budget_seconds'] = 5400 if computer['exists'] else 21600
        if workflow is not None:
            payload['workflow']=workflow
            payload['execution_budget_seconds']=workflow['phases'][0]['budget_seconds']
        if admission is not None:
            payload['ad_join_admission'] = admission
            payload['warnings'] = []
        if recovery_resolution is not None:
            payload['recovery_resolution'] = recovery_resolution
        if partial_local_resolution is not None:
            payload['partial_local_resolution'] = partial_local_resolution
            changes.append('continue_after_verified_partial_local_recovery')
        if retry is not None:
            payload['prejoin_retry'] = retry
            changes.append('continue_after_proven_prejoin_timeout')
        if catalog is not None:
            from .component_probe import ComponentProbe, ssh_binding
            from .component_verification import VerificationEngine, valid_evidence, package_health_ready
            profile = catalog.profile(software)
            selection = profile['components'] + (['remote.krfb'] if remote == 'krfb' and 'remote.krfb' not in profile['components'] else [])
            components = catalog.ordered(selection, os_id='alt-kworkstation-11')
            probe = self.component_probe or ComponentProbe(self.settings)
            facts = probe.observe(machine, user, components, allow_unresolved=not observed['trust'], profile_id=software)
            if (not valid_evidence(facts, allow_unresolved=not observed['trust'])
                    or facts['machine']['uuid'] != machine.uuid or facts['machine']['hostname'] != machine.hostname
                    or facts['machine']['os_id'] != 'alt-kworkstation-11'
                    or facts['user']['login'] != user['login']
                    or (facts['user']['uid'] is not None and facts['user']['home_safe'] is not True)
                    or not package_health_ready(facts)):
                raise fail('setup_probe_invalid', 'Full Setup component preflight cannot verify machine or package activity')
            if workflow is not None:
                vnc=facts['components'].get('remote.vnc_policy')
                if (not isinstance(vnc,dict) or vnc.get('error_code') is not None
                        or vnc.get('checks',{}).get('backend_verified') is not True
                        or vnc.get('checks',{}).get('external_policy_clear') is not True):
                    raise fail('full_workflow_vnc_backend_unverified',
                               'The complete workflow requires readable firewall policy before admission')
                try:
                    import hashlib
                    from .final_dns_runtime import validate_observation
                    from .final_dns_program import target_program
                    fact=facts['components']['network.final_dns'];receipt=fact['final_dns']
                    policy=workflow['policy']['final_dns']
                    if (fact['error_code'] is not None or fact['policy']!=policy or fact['policy_sha256']!=digest(policy)
                            or set(receipt)!={'schema_version','status','helper_sha256','observation'}
                            or type(receipt['schema_version']) is not int or receipt['schema_version']!=1
                            or receipt['status']!='ok' or receipt['helper_sha256']!=hashlib.sha256(
                                target_program(self.settings.ansible_project_dir).encode()).hexdigest()):raise ValueError
                    validate_observation(receipt['observation'],machine,expected_boot_id=facts['machine']['boot_id'])
                except Exception:
                    raise fail('full_workflow_dns_backend_unverified','The complete workflow requires a supported owned DNS backend') from None
            from .setup_runtime import source_fingerprint
            from pathlib import Path
            from .component_storage import installation_budget, bind_budget_evidence
            from .component_verification import _package_status
            for selected_component in components:
                if selected_component['verification']['recipe'] != 'package':
                    continue
                artifact = catalog.artifact(selected_component['id'])
                if 'download_size_bytes' not in artifact:
                    continue
                fact = facts['components'].get(selected_component['id'], {})
                if not isinstance(fact, dict):
                    raise fail('component_install_space_unverified', 'Selected package evidence is unavailable')
                checks = fact.get('checks', {})
                installed = (_package_status(artifact, fact) == 'compliant'
                             and fact.get('error_code') is None and isinstance(checks, dict) and bool(checks)
                             and all(value is True for value in checks.values()))
                if not installed:
                    budget = installation_budget(artifact, fact.get('storage'))
                    if budget['ready'] is not True:
                        raise fail(budget['error_code'], 'Selected component installation space is not verified')
                facts['components'][selected_component['id']] = bind_budget_evidence(artifact, fact)
            payload.update(engine_schema_version=2, catalog_version=catalog.version,
                           catalog_sha256=catalog.fingerprint, profile=profile, components=components,
                           component_observed={k: v for k, v in facts.items() if k != 'observed_at'},
                           component_verification=VerificationEngine(catalog).evaluate(facts, selection),
                           ssh_binding=ssh_binding(self.settings, machine),
                           source_sha256=source_fingerprint(self.settings.ansible_project_dir, Path(__file__).parent))
            if remote == 'krfb' and workflow is None:
                from .configure import KRFB_NETWORK_CONFIRMATION_VARIABLE
                import os
                payload['network_restriction_confirmed'] = os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE) == 'true'
            if partial_document is not None:
                from .setup_partial_local_continuation import validate_continuity
                validate_continuity(partial_document, payload)
            prior = (pending_predecessor or (expected_plan or {}).get('payload', {}).get('predecessor_job')
                     or (partial_document['closed']['predecessor_job'] if partial_document is not None else None))
            if prior:
                from .setup_retry import full_predecessor
                proof = retry or recovery_resolution or partial_local_resolution
                if not proof or full_predecessor(self.settings, prior['job_id'], machine.uuid, proof['failed_run_id']) != prior:
                    raise fail('setup_retry_not_permitted', 'Full predecessor requires the original verified continuation gate')
                payload['predecessor_job'] = prior
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

    def apply(self, plan_id, confirmed_sha, *, detach=False):
        plan = self.plans.load(plan_id, confirmed_sha)
        if plan['payload'].get('engine_schema_version') != 2:
            if detach:
                raise fail('setup_legacy_plan_requires_refresh', 'Create a new catalog-bound plan before detached execution')
            with exclusive_lock(self.settings.lock_file):
                return self._execute_locked(plan_id, confirmed_sha)
        from .setup_jobs import SetupJobRepository
        jobs = SetupJobRepository(self.settings, clock=self.clock)
        if plan['payload'].get('partial_local_resolution'):
            with exclusive_lock(self.settings.lock_file):
                self._validate_job_plan(plan, own_job_id=None)
                job = jobs.submit(plan, operation='full_setup')
        else:
            job = jobs.submit(plan, operation='full_setup')
        if detach:
            return {'schema_version': 2, 'operation': 'setup_apply', 'job_id': job.job_id,
                    'machine_uuid': job.machine_uuid, 'state': job.state,
                    'plan_id': plan_id, 'plan_sha256': confirmed_sha}
        if self.job_waiter is not None:
            job = self.job_waiter(job)
        else:
            # The persistent systemd worker owns execution. Exiting this wait never
            # sends a signal to it, its Ansible child or the workstation.
            while job.state in ('queued', 'preflight', 'running', 'verifying'):
                time.sleep(1)
                job = jobs.get(job.job_id)
        if not (job.job_dir/'execution.json').is_file():
            raise ControlError('setup_execution_unverified', 'Setup job has no verified completion evidence',
                               7, {'job_id': job.job_id})
        result = private_read(job.job_dir/'execution.json')
        if result.get('legacy_run') is not None and job.state in ('successful', 'degraded', 'waiting_reboot', 'waiting_first_login'):
            return result['legacy_run']
        details = {'job_id': job.job_id}
        if result.get('legacy_error_run_id'):
            details['run_id'] = result['legacy_error_run_id']
        elif result.get('legacy_run'):
            details['run_id'] = result['legacy_run']['run_id']
        raise ControlError(result.get('error_code') or 'setup_execution_unverified',
                           'Setup job requires review; inspect its safe status', 7, details)

    def _validate_job_plan(self, plan, *, own_job_id):
        self.plans.load(plan['plan_id'], plan['sha256'])
        before = plan['payload']
        if before.get('recovery_resolution') and self.recovery_resolutions.verifier is None:
            from .setup_recovery_operator import operator_for_execution_plan
            reference = before['recovery_resolution']
            resolution = self.recovery_resolutions.load(reference['failed_run_id'], reference['computer_guid'])
            terminal = resolution['terminal']
            self.recovery_resolutions.verifier = operator_for_execution_plan(self.settings,
                terminal['execution_plan_id'], terminal['execution_plan_sha256'])._verify_terminal_locked
        request = ConfigureRequest.from_mapping(before['request'], expected_uuid=before['machine']['uuid'],
                                                catalog=self._catalog())
        current = self._snapshot(request.machine_uuid, before['user']['login'], request.computer_ou,
                                 request.software_profile, request.remote_access_profile,
                                 recovery_resolution=before.get('recovery_resolution'),
                                 partial_local_resolution=before.get('partial_local_resolution'),
                                 own_job_id=own_job_id, expected_plan=plan)
        from .full_workflow import equivalent_payload
        if not equivalent_payload(current,before):
            raise fail('setup_plan_drift', 'Full Setup identity, observed facts or published source changed')
        return current

    def _observe_job_result(self, plan, *, own_job_id):
        from .component_probe import ComponentProbe, ssh_binding
        from .component_verification import VerificationEngine
        from .setup_runtime import source_fingerprint
        from pathlib import Path
        before = plan['payload']
        catalog = self._catalog()
        machine = self.machines.resolve(before['machine']['uuid'])
        identity = self._verify_identity(machine.uuid)
        user = self.directory.user(before['user']['login'])
        if (identity['status'] != 'successful' or user != before['user']
                or digest(machine.raw) != before['machine']['registration_sha256']
                or machine.ip != before['machine']['ip']
                or catalog.fingerprint != before['catalog_sha256']
                or ssh_binding(self.settings, machine) != before['ssh_binding']
                or source_fingerprint(self.settings.ansible_project_dir, Path(__file__).parent) != before['source_sha256']):
            raise fail('setup_post_verification_failed', 'Full Setup current identity or published source differs')
        observed = (self.component_probe or ComponentProbe(self.settings)).observe(machine, user, before['components'],
                                                                                 profile_id=before['profile']['id'])
        return observed, VerificationEngine(catalog).evaluate(observed, [c['id'] for c in before['components']])

    def _execute_locked(self, plan_id, confirmed_sha, *, own_job_id=None):
        plan = self.plans.load(plan_id, confirmed_sha)
        index_path = self.settings.state_root / 'setup-plan-runs' / (plan_id + '.json')
        if index_path.exists() or index_path.is_symlink():
            index = private_read(index_path)
            result = self.status(index['run_id'])
            if result.get('status') in ('running', 'failed', 'interrupted'):
                raise fail('setup_previous_run_unresolved', 'This plan already has a run requiring manual review; automatic replay is blocked')
            return result
        before = plan['payload']
        request = ConfigureRequest.from_mapping(before['request'], expected_uuid=before['machine']['uuid'],
                                               catalog=self._catalog() if before.get('engine_schema_version') == 2 else None)
        current = self._snapshot(request.machine_uuid, before['user']['login'], request.computer_ou,
                                  request.software_profile, request.remote_access_profile,
                                  recovery_resolution=before.get('recovery_resolution'),
                                  partial_local_resolution=before.get('partial_local_resolution'),
                                  own_job_id=own_job_id, expected_plan=plan,
                                  legacy=before.get('engine_schema_version') != 2)
        from .full_workflow import equivalent_payload
        if not equivalent_payload(current,before):
            raise fail('setup_plan_drift', 'Setup identity or prerequisites changed; create a new plan')
        run_id = 'setup-run-' + uuid.uuid4().hex
        from .setup_jobs import legacy_setup_execution
        predecessors = []
        if current.get('prejoin_retry'):
            predecessors = [current['prejoin_retry']['failed_run_id'], current['prejoin_retry']['configuration_run_id']]
        elif current.get('recovery_resolution'):
            failed_id = current['recovery_resolution']['failed_run_id']
            predecessors = [failed_id, self.status(failed_id)['configuration_run_id']]
        elif current.get('partial_local_resolution'):
            proof = current['partial_local_resolution']
            from .setup_retry import reviewed_legacy_runs
            predecessors = sorted({proof['failed_run_id'], proof['configuration_run_id'],
                                   *reviewed_legacy_runs(self.settings)})
        with legacy_setup_execution(self.settings, request.machine_uuid, request.final_hostname,
                                    operation='full_setup', run_id=run_id, reviewed_predecessor_runs=predecessors):
            date = self.clock().isoformat()
            revision = (current['existing_assignment'] or {}).get('revision', 0) + 1
            run = {'schema_version': 1, 'run_id': run_id, 'plan_id': plan_id, 'plan_sha256': confirmed_sha,
                   'machine_uuid': request.machine_uuid, 'status': 'running', 'created_at': date,
                   'reboot_required': None, 'deferred_actions': current['deferred_actions']}
            if current.get('engine_schema_version') == 2:
                run.update(original_boot_id=current['component_observed']['machine']['boot_id'],
                           catalog_version=current['catalog_version'], profile_version=current['profile']['version'],
                           source_sha256=current['source_sha256'])
            private_create(self._run_path(run_id), run)
            private_create(index_path, {'run_id': run_id})
            self.assignments.write(current['binding'], run_id=run_id, result='running', date=date, revision=revision)
            try:
                endpoint = current['prerequisites'].get('directory_uri')
                options = {'setup_directory_uri': endpoint} if endpoint is not None else {}
                if not current['computer']['exists']:
                    options['setup_fresh_install'] = True
                if current.get('ad_join_admission') is not None:
                    options['setup_ad_join_admission'] = current['ad_join_admission']
                if current.get('workflow') is not None:
                    options['setup_workflow']=current['workflow']
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
                    if exc.details.get('phase') in ('upgrade', 'domain_join', 'configuration'):
                        run['failure_phase'] = exc.details['phase']
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


    def _verify_identity(self, identifier):
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

    def verify(self, identifier):
        result = self._verify_identity(identifier)
        catalog = self._catalog()
        if catalog is None:
            return result
        from .component_probe import ComponentProbe
        from .component_verification import VerificationEngine, package_health_ready
        binding = self.assignments.get(result['machine_uuid'])
        selected = catalog.profile(binding['software_profile'])['components']
        if binding['remote_access_profile'] == 'krfb' and 'remote.krfb' not in selected:
            selected = selected+['remote.krfb']
        machine = self.machines.resolve(result['machine_uuid'])
        user = self.directory.user(binding['login'])
        try:
            observed = (self.component_probe or ComponentProbe(self.settings)).observe(
                machine, user, catalog.ordered(selected, os_id='alt-kworkstation-11'), profile_id=binding['software_profile'])
            prior = result['run']
            verification = VerificationEngine(catalog).evaluate(observed, selected,
                reboot_required=prior.get('reboot_required', False) if prior.get('original_boot_id') else False,
                original_boot_id=prior.get('original_boot_id'))
            verification['reboot_evidence'] = 'recorded' if prior.get('original_boot_id') else 'legacy_not_recorded'
            if not package_health_ready(observed):
                verification['overall_status'] = 'unknown_requires_review'
                verification['operator_action_required'] = True
        except ControlError:
            verification = VerificationEngine(catalog).evaluate({}, selected)
        result['component_verification'] = verification
        if result['status'] == 'successful':
            result['status'] = verification['overall_status']
        return result
