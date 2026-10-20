"""Immutable component plans reuse the existing verified employee/domain binding."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat

from .ad_directory import fail
from .component_catalog import ComponentCatalog
from .component_probe import ComponentProbe, ssh_binding
from .component_verification import VerificationEngine, valid_evidence, package_health_ready
from .setup import SetupService
from .setup_plans import SetupPlanStore, digest
from .setup_runtime import source_fingerprint


class ComponentPlanStore(SetupPlanStore):
    prefix = 'setup-component-'
    directory = 'setup-component-plans'
    plan_schema_version = 2
    plan_operation = 'component_plan'


class ComponentSetupService:
    def __init__(self, settings, *, setup=None, catalog=None, probe=None, clock=None, preflight=None):
        self.settings = settings
        self.setup = setup or SetupService(settings)
        self.catalog = catalog
        self.probe = probe or ComponentProbe(settings)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.plans = ComponentPlanStore(settings.state_root, clock=self.clock)
        self.preflight = preflight or self._preflight

    def _preflight(self, component):
        catalog = self.catalog or ComponentCatalog.load(self.settings.ansible_project_dir)
        if component['verification']['recipe'] == 'government_ca':
            from .component_probe import _yaml
            entries = _yaml(self.settings.ansible_project_dir/'roles/government_ca/defaults/main.yml')['government_ca_certificates']
            for entry in entries:
                try:
                    if Path(entry['filename']).name != entry['filename']:
                        raise ValueError
                    certificate = self.settings.ansible_project_dir/'files/government_ca'/entry['filename']
                    if any(p.is_symlink() for p in (certificate, *certificate.parents)):
                        raise ValueError
                    info = certificate.stat()
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
                        raise ValueError
                    payload = certificate.read_bytes()
                    if (len(payload) > 1048576 or b'PRIVATE KEY' in payload
                            or payload.count(b'-----BEGIN CERTIFICATE-----') != 1
                            or hashlib.sha256(payload).hexdigest() != entry['sha256']):
                        raise ValueError
                except (OSError, ValueError, KeyError):
                    return {'ready': False, 'error_code': 'component_certificate_source_unverified'}
        artifact = catalog.artifact(component['id'])
        if artifact and artifact['source'] != 'alt-repository':
            path = Path(artifact['artifact_path'])
            try:
                if any(p.is_symlink() for p in (path, *path.parents)):
                    raise ValueError
                before = path.lstat()
                if not stat.S_ISREG(before.st_mode) or before.st_size > 2147483648:
                    raise ValueError
                descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                value = hashlib.sha256()
                with os.fdopen(descriptor, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError
                    while block := stream.read(1048576):
                        value.update(block)
                if value.hexdigest() != artifact['sha256']:
                    raise ValueError
            except (OSError, ValueError):
                return {'ready': False, 'error_code': 'component_artifact_unverified'}
        if component['preflight']['recipe'] == 'krfb':
            from .configure import KRFB_NETWORK_CONFIRMATION_VARIABLE
            from .vault import VaultHealthChecker
            if os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE) != 'true':
                return {'ready': False, 'error_code': 'remote_access_network_restriction_unconfirmed'}
            VaultHealthChecker(self.settings).check_krfb()
        if component['preflight'].get('artifact_key') == 'cryptopro':
            from .vault import VaultHealthChecker
            import yaml
            try:
                checker = VaultHealthChecker(self.settings)
                if not all(checker._build_checks().values()):
                    raise ValueError
                private = yaml.safe_load(checker._decrypt())
                value = private.get('vault_cryptopro_license') if isinstance(private, dict) else None
                if not isinstance(value, str) or not value.strip():
                    raise ValueError
            except Exception:
                return {'ready': False, 'error_code': 'component_secret_unavailable'}
        return {'ready': True}

    def _snapshot(self, identifier, component_id, *, own_job_id=None, expected_plan=None, after_job=None, read_only=False):
        catalog = self.catalog or ComponentCatalog.load(self.settings.ansible_project_dir)
        component = catalog.component(component_id)
        if component['verification']['recipe']=='final_dns' and not read_only:
            raise fail('full_workflow_required','Final DNS runs only as the last phase of the complete workstation workflow')
        machine = self.setup.machines.resolve(identifier)
        predecessor = None
        if after_job is not None:
            from .setup_retry import predecessor as inspect_predecessor
            predecessor = inspect_predecessor(self.settings, after_job, component, machine.uuid)
        if machine.registration_state != 'ready' or machine.assignment:
            raise fail('component_machine_not_ready', 'Component requires ready registration without a legacy local assignment')
        active = machine.active_job
        if active and not read_only:
            owned = (isinstance(active, dict) and expected_plan is not None and own_job_id is not None
                     and active.get('schema_version') == 2 and active.get('kind') == 'setup'
                     and active.get('job_id') == own_job_id and active.get('machine_uuid') == machine.uuid
                     and active.get('plan_id') == expected_plan['plan_id']
                     and active.get('plan_sha256') == expected_plan['sha256'])
            reviewed = (isinstance(active, dict) and predecessor is not None and active.get('job_id') == after_job
                        and active.get('schema_version') == 2 and active.get('kind') == 'setup'
                        and active.get('state') == 'unknown_requires_review' and active.get('machine_uuid') == machine.uuid)
            if not owned and not reviewed:
                raise fail('setup_active_job', 'Machine has an incompatible active job')
        binding = self.setup.assignments.get(machine.uuid)
        if binding is None or binding['result'] not in ('successful', 'degraded'):
            raise fail('component_setup_required', 'Component requires a resolved existing domain assignment')
        if binding['computer_ou'] not in self.setup.approved_ous:
            raise fail('setup_ou_not_approved', 'Recorded computer OU is no longer approved')
        ous = [entry for entry in self.setup.directory.ous() if entry['dn'].casefold() == binding['computer_ou'].casefold()]
        if len(ous) != 1:
            raise fail('setup_ou_not_found', 'Recorded computer OU is missing or ambiguous')
        profile = catalog.profile(binding['software_profile'])
        if component_id=='remote.krfb' and profile['id']=='workstation-full-v1' and not read_only:
            raise fail('full_workflow_required','Direct KRFB belongs to the original managed user phase; legacy restricted component apply is unavailable')
        user = self.setup.directory.user(binding['login'])
        if (user.get('state') != 'enabled' or user.get('object_guid') != binding['object_guid']
                or user.get('object_sid') != binding['object_sid'] or not user.get('object_sid')):
            raise fail('assignment_conflict', 'Recorded selected employee identity changed')
        identity = self.setup._verify_identity(machine.uuid)
        if identity['status'] != 'successful':
            raise fail('component_identity_unverified', 'Existing machine/domain identity is not verified')
        previous = identity['run']
        if previous.get('status') not in ('successful', 'degraded'):
            raise fail('setup_previous_run_unresolved', 'Original Setup requires review before component changes')
        selected = catalog.ordered([component_id], os_id='alt-kworkstation-11')
        observed = self.probe.observe(machine, user, selected, profile_id=profile['id'])
        if (not valid_evidence(observed) or observed['machine']['uuid'] != machine.uuid
                or observed['machine']['hostname'] != machine.hostname or observed['user']['login'] != user['login']):
            raise fail('component_probe_unverified', 'Current component identity evidence is invalid')
        verification = VerificationEngine(catalog).evaluate(observed, [component_id])
        state = verification['components'][component_id]['status']
        action = {'compliant': 'noop', 'missing': 'install', 'drifted': 'repair'}.get(state, 'blocked')
        preflight = self.preflight(component) if action != 'noop' and not read_only else {'ready': True, 'required': False}
        if action != 'noop' and not read_only and component['verification']['recipe'] == 'package':
            from .component_storage import installation_budget
            fact = observed['components'].get(component_id)
            budget = installation_budget(catalog.artifact(component_id),
                                         fact.get('storage') if isinstance(fact, dict) else None)
            if budget['ready'] is not True:
                preflight = budget
        network_confirmed = None
        if component_id == 'remote.krfb':
            from .configure import KRFB_NETWORK_CONFIRMATION_VARIABLE
            network_confirmed = os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE) == 'true'
            if not network_confirmed:
                preflight = {'ready': False, 'error_code': 'remote_access_network_restriction_unconfirmed'}
        if action != 'noop' and observed['package_manager'].get('source', {}).get('status') != 'approved_p11':
            preflight = {'ready': False, 'error_code': 'component_package_source_unverified'}
        if (not isinstance(preflight, dict) or preflight.get('ready') is not True
                or component['execution'].get('adapter') is not None
                or (action != 'noop' and not package_health_ready(observed))):
            action = 'blocked'
        if predecessor is not None and not package_health_ready(observed):
            raise fail('setup_retry_requires_fresh_health', 'Package health and absence of remote execution are not verified')
        projection = {k: copy.deepcopy(v) for k, v in observed.items() if k != 'observed_at'}
        projection['components'] = {c['id']: projection['components'].get(c['id']) for c in selected}
        from .component_storage import bind_budget_evidence
        for current_component in selected:
            if current_component['verification']['recipe'] == 'package':
                key = current_component['id']
                projection['components'][key] = bind_budget_evidence(
                    catalog.artifact(key), projection['components'].get(key))
        payload = {'operation': 'component', 'machine': {'uuid': machine.uuid, 'hostname': machine.hostname,
                'ip': machine.ip, 'registration_sha256': digest(machine.raw)},
                'user': {'login': user['login'], 'upn': user['upn'], 'object_guid': user['object_guid'], 'object_sid': user['object_sid']},
                'computer': identity['computer'], 'ou_identity': ous[0], 'binding': binding, 'profile': profile,
                'catalog_version': catalog.version, 'catalog_sha256': catalog.fingerprint,
                'component': component, 'components': selected, 'observed': projection,
                'observed_at': observed['observed_at'], 'verification': verification,
                'ssh_binding': ssh_binding(self.settings, machine), 'preflight': preflight,
                'source_sha256': source_fingerprint(self.settings.ansible_project_dir, Path(__file__).parent),
                'action': action, 'execution_budget_seconds': 5400}
        if predecessor is not None:
            payload['predecessor_job'] = predecessor
        if network_confirmed is not None:
            payload['network_restriction_confirmed'] = network_confirmed
        return payload

    def plan(self, identifier: str, component_id: str, *, after_job=None) -> dict:
        return self.plans.create(self._snapshot(identifier, component_id, after_job=after_job))

    def verify(self, identifier: str, component_id: str) -> dict:
        from .component_acceptance import project_acceptance
        return project_acceptance(self.settings, self._snapshot(identifier, component_id, read_only=True))

    def accept(self, plan_id: str, sha256: str, *, confirmed=False) -> dict:
        from .component_acceptance import accept
        return accept(self, plan_id, sha256, confirmed=confirmed)

    def apply(self, plan_id: str, sha256: str) -> dict:
        from .setup_jobs import SetupJobRepository
        plan = self.plans.load(plan_id, sha256)
        job = SetupJobRepository(self.settings, clock=self.clock).submit(plan, operation='component')
        return {'schema_version': 2, 'operation': 'component_apply', 'job_id': job.job_id,
                'machine_uuid': job.machine_uuid, 'state': job.state,
                'plan_id': plan_id, 'plan_sha256': sha256}

    def observe_result(self, plan, *, own_job_id):
        """Allow the expected installed facts to change, never the identity/source."""
        before = plan['payload']
        current = self._snapshot(before['machine']['uuid'], before['component']['id'],
                                 own_job_id=own_job_id, expected_plan=plan, after_job=before.get('predecessor_job', {}).get('job_id'))
        for key in ('machine', 'user', 'computer', 'ou_identity', 'binding', 'profile',
                    'catalog_version', 'catalog_sha256', 'component', 'components',
                    'ssh_binding', 'source_sha256'):
            if current[key] != before[key]:
                raise fail('component_plan_drift', 'Post-apply identity or published source changed')
        return dict(current['observed'], observed_at=current['observed_at']), current['verification']

    def validate(self, plan_id: str, sha256: str, *, own_job_id: str | None=None) -> dict:
        plan = self.plans.load(plan_id, sha256)
        before = plan['payload']
        current = self._snapshot(before['machine']['uuid'], before['component']['id'],
                                 own_job_id=own_job_id, expected_plan=plan, after_job=before.get('predecessor_job', {}).get('job_id'))
        projection = lambda p: {key: value for key, value in p.items() if key != 'observed_at'}
        if projection(before) != projection(current):
            raise fail('component_plan_drift', 'Component identity, source or observed state changed; create a new plan')
        if current['action'] == 'blocked':
            raise fail('component_plan_blocked', 'Component is blocked; inspect current prerequisites and verification')
        return current
