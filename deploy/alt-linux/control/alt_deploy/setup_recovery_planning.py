"""Protected, read-only recovery planning; no execution or reservation API."""
from __future__ import annotations

from datetime import datetime, timezone

from .ad_directory import DOMAIN, fail
from .ad_transport import DirectoryConfig
from .configure import ConfigureRequest
from .registry import MachineRepository
from .setup import computer_matches
from .setup_plans import decode_state_bytes, digest
from .setup_recovery import RecoveryAttemptStore, RecoveryPlanStore, _pair
from .setup_recovery_directory import RecoveryDirectory
from .setup_recovery_history import RecoveryHistoryStore, _timestamp
from .setup_recovery_runtime import RecoveryPlanningRuntime


class RecoveryPlanningService:
    def __init__(self, settings, *, directory=None, machines=None, runtime=None,
                 approved_ous=None, clock=None):
        self.settings = settings
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        config = DirectoryConfig.load() if directory is None or approved_ous is None else None
        self.directory = directory or RecoveryDirectory.from_controller_config(settings, config=config)
        self.approved_ous = tuple(approved_ous if approved_ous is not None else config.approved_ous)
        self.machines = machines or MachineRepository(settings)
        self.runtime = runtime or RecoveryPlanningRuntime(settings)
        self.history = RecoveryHistoryStore(settings.state_root)
        self.plans = RecoveryPlanStore(settings.state_root, clock=self.clock)
        self.attempts = RecoveryAttemptStore(settings.state_root, clock=self.clock)

    def snapshot(self, failed_run_id, computer_guid):
        pair = _pair(failed_run_id, computer_guid)
        return self._snapshot(failed_run_id, computer_guid, guard=lambda: self._unreserved(pair))

    def _unreserved(self, pair):
        claim = self.attempts.claim_path(**pair)
        if claim.exists() or claim.is_symlink():
            raise fail('recovery_attempt_reserved', 'This failed run and computer already have a recovery attempt; retry is prohibited')

    def _snapshot(self, failed_run_id, computer_guid, *, guard):
        # The public path always supplies the exclusion guard.  The separate
        # internal reserved-state adapter supplies exact protected-plan checks,
        # never a CLI bypass flag or an unvalidated replacement claim.
        pair = _pair(failed_run_id, computer_guid)
        guard()
        historical = self.history.load(failed_run_id)
        pinned = historical['identity']
        original = decode_state_bytes(historical['raw_files']['plan'])['payload']
        try:
            machine = self.machines.resolve(pinned['machine_uuid'])
            if (machine.uuid != pinned['machine_uuid'] or machine.hostname != pinned['hostname']
                    or machine.registration_state != 'ready' or machine.active_job or machine.assignment):
                raise ValueError
            registered = {'uuid': machine.uuid, 'hostname': machine.hostname, 'ip': machine.ip,
                          'registration_sha256': digest(machine.raw)}
            ou = pinned['computer_ou']
            if ou not in self.approved_ous:
                raise ValueError
            ous = [entry for entry in self.directory.ous() if entry['dn'].casefold() == ou.casefold()]
            if (len(ous) != 1 or ous[0]['object_guid'] != original['ou_identity']['object_guid']):
                raise ValueError
            user = self.directory.user(pinned['login'])
            if (user['state'] != 'enabled' or user['login'] != pinned['login']
                    or user['upn'] != pinned['login'] + '@' + DOMAIN
                    or user['object_guid'] != pinned['employee_guid'] or user['object_sid'] != pinned['employee_sid']):
                raise ValueError
            computer = self.directory.inspect_computer(machine.hostname, computer_guid)
            created = _timestamp(computer['when_created'])
            # AD whenCreated has second resolution. This window links an initial
            # absence to the failed run, but is NOT proof of object ownership.
            start = _timestamp(pinned['started_at']).replace(microsecond=0)
            finish = _timestamp(pinned['finished_at'])
            if (computer['object_guid'] != computer_guid or not computer_matches(computer, machine.hostname, ou)
                    or not start <= created <= finish or computer['dc']['is_writable'] is not True):
                raise ValueError
            request = ConfigureRequest.from_mapping(original['request'], expected_uuid=machine.uuid)
            prerequisites = self.runtime.prerequisites(request)
            if prerequisites['ready'] is not True:
                raise ValueError
            observed = self.runtime.probe(machine, user)
            if (observed['uuid'] != machine.uuid or observed['hostname'] != machine.hostname
                    or observed['domain'] not in ('', DOMAIN) or observed['trust'] is not False
                    or observed['local_duplicate'] is not False):
                raise ValueError
            facts = self.runtime.facts(machine)
            snapshot = facts['snapshot']
            if (facts['snapshot_sha256'] != digest(snapshot) or snapshot['uuid'] != machine.uuid
                    or snapshot['hostname'] != machine.hostname or snapshot['clock_synchronized'] is not True
                    or snapshot['incompatible_processes'] != []):
                raise ValueError
            # Reads may take time: refuse replacement of the registry or any of
            # the five originals before creating even a non-executable plan.
            current = self.machines.resolve(pinned['machine_uuid'])
            if (digest(current.raw) != registered['registration_sha256'] or current.active_job or current.assignment
                    or current.registration_state != 'ready' or current.uuid != machine.uuid
                    or current.hostname != machine.hostname or current.ip != machine.ip
                    or self.history.load(failed_run_id)['raw_files'] != historical['raw_files']):
                raise ValueError
            guard()
            return dict(pair, machine_uuid=machine.uuid, computer_sid=computer['object_sid'],
                evidence_sha256=pinned['evidence_sha256'], historical_identity=pinned,
                machine=registered, user=user, computer_ou=ou, ou_identity=ous[0], computer=computer,
                request=request.to_dict(), observed=observed, workstation_facts=facts,
                prerequisites=prerequisites, operation='replace_selected_machine_password_once',
                execution_available=False,
                expected_directory_effects=['machine_password', 'password_history', 'pwdLastSet', 'msDS-KeyVersionNumber'],
                required_gates=['reviewed_fixed_provider_and_local_importer', 'durably_sealed_machine_credential',
                    'coordinated_controller_backup_and_private_workstation_snapshot',
                    'lifecycle_lock_and_fresh_drift_checks', 'explicit_operator_approval_of_exact_computer_and_plan_sha'],
                warnings=['creation_window_does_not_prove_object_ownership', 'original_failure_cause_unknown',
                    'read_only_plan_does_not_authorize_execution'])
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
            raise fail('recovery_current_state_invalid', 'Pinned recovery identities, provenance and current state must match') from None

    def plan(self, failed_run_id, computer_guid):
        return self.plans.create(self.snapshot(failed_run_id, computer_guid))
