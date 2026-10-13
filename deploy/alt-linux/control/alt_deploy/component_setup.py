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
from .component_verification import VerificationEngine, valid_evidence
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

    def _snapshot(self, identifier, component_id, *, own_job_id=None, expected_plan=None):
        catalog = self.catalog or ComponentCatalog.load(self.settings.ansible_project_dir)
        component = catalog.component(component_id)
        machine = self.setup.machines.resolve(identifier)
        if machine.registration_state != 'ready' or machine.assignment:
            raise fail('component_machine_not_ready', 'Component requires ready registration without a legacy local assignment')
        active = machine.active_job
        if active:
            owned = (isinstance(active, dict) and expected_plan is not None and own_job_id is not None
                     and active.get('schema_version') == 2 and active.get('kind') == 'setup'
                     and active.get('job_id') == own_job_id and active.get('machine_uuid') == machine.uuid
                     and active.get('plan_id') == expected_plan['plan_id']
                     and active.get('plan_sha256') == expected_plan['sha256'])
            if not owned:
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
        user = self.setup.directory.user(binding['login'])
        if (user.get('state') != 'enabled' or user.get('object_guid') != binding['object_guid']
                or user.get('object_sid') != binding['object_sid'] or not user.get('object_sid')):
            raise fail('assignment_conflict', 'Recorded selected employee identity changed')
        identity = self.setup.verify(machine.uuid)
        if identity['status'] != 'successful':
            raise fail('component_identity_unverified', 'Existing machine/domain identity is not verified')
        previous = identity['run']
        if previous.get('status') not in ('successful', 'degraded'):
            raise fail('setup_previous_run_unresolved', 'Original Setup requires review before component changes')
        selected = catalog.ordered([component_id], os_id='alt-kworkstation-11')
        observed = self.probe.observe(machine, user, selected)
        if (not valid_evidence(observed) or observed['machine']['uuid'] != machine.uuid
                or observed['machine']['hostname'] != machine.hostname or observed['user']['login'] != user['login']):
            raise fail('component_probe_unverified', 'Current component identity evidence is invalid')
        verification = VerificationEngine(catalog).evaluate(observed, [component_id])
        state = verification['components'][component_id]['status']
        action = {'compliant': 'noop', 'missing': 'install', 'drifted': 'repair'}.get(state, 'blocked')
        preflight = self.preflight(component) if action != 'noop' else {'ready': True, 'required': False}
        if (not isinstance(preflight, dict) or preflight.get('ready') is not True
                or component['execution'].get('adapter') is not None
                or (action != 'noop' and observed['package_manager'].get('processes_absent') is not True)):
            action = 'blocked'
        projection = {k: copy.deepcopy(v) for k, v in observed.items() if k != 'observed_at'}
        projection['components'] = {c['id']: projection['components'].get(c['id']) for c in selected}
        return {'operation': 'component', 'machine': {'uuid': machine.uuid, 'hostname': machine.hostname,
                'ip': machine.ip, 'registration_sha256': digest(machine.raw)},
                'user': {'login': user['login'], 'upn': user['upn'], 'object_guid': user['object_guid'], 'object_sid': user['object_sid']},
                'computer': identity['computer'], 'ou_identity': ous[0], 'binding': binding, 'profile': profile,
                'catalog_version': catalog.version, 'catalog_sha256': catalog.fingerprint,
                'component': component, 'components': selected, 'observed': projection,
                'observed_at': observed['observed_at'], 'verification': verification,
                'ssh_binding': ssh_binding(self.settings, machine), 'preflight': preflight,
                'source_sha256': source_fingerprint(self.settings.ansible_project_dir, Path(__file__).parent),
                'action': action, 'execution_budget_seconds': 5400}

    def plan(self, identifier: str, component_id: str) -> dict:
        return self.plans.create(self._snapshot(identifier, component_id))

    def verify(self, identifier: str, component_id: str) -> dict:
        return self._snapshot(identifier, component_id)['verification']

    def validate(self, plan_id: str, sha256: str, *, own_job_id: str | None=None) -> dict:
        plan = self.plans.load(plan_id, sha256)
        before = plan['payload']
        current = self._snapshot(before['machine']['uuid'], before['component']['id'],
                                 own_job_id=own_job_id, expected_plan=plan)
        projection = lambda p: {key: value for key, value in p.items() if key != 'observed_at'}
        if projection(before) != projection(current):
            raise fail('component_plan_drift', 'Component identity, source or observed state changed; create a new plan')
        if current['action'] == 'blocked':
            raise fail('component_plan_blocked', 'Component is blocked; inspect current prerequisites and verification')
        return current
