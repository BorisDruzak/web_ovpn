"""Read-only operational prewrite gate; creates no preparation or AD state."""
from __future__ import annotations

from .ad_directory import fail
from .setup_plans import digest, private_read
from .setup_recovery import RecoveryAttemptStore, RecoveryPlanStore, _pair
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_credential import RecoveryCredentialStore, RecoveryVaultCodec
from .setup_recovery_native import validate_metadata
from .setup_recovery_rehearsal_runtime import RecoveryRehearsalRuntime


class RecoveryPrewriteGate:
    def __init__(self, settings, *, machines, fresh_check, credentials=None, controller=None, runtime=None, plans=None):
        self.machines, self.fresh_check = machines, fresh_check
        self.credentials=credentials or RecoveryCredentialStore(settings.state_root,codec=RecoveryVaultCodec(settings))
        self.attempts=RecoveryAttemptStore(settings.state_root)
        self.plans=plans or RecoveryPlanStore(settings.state_root)
        self.controller=controller or RecoveryControllerBackup(settings,credentials=self.credentials,fresh_check=fresh_check)
        self.runtime=runtime or RecoveryRehearsalRuntime(settings,credentials=self.credentials)

    def path(self,payload):
        return self.attempts._path(**_pair(payload['failed_run_id'],payload['computer_guid']),suffix='.preparation.json')

    def __call__(self,payload,claim,sealed,password):
        try:
            pair=_pair(payload['failed_run_id'],payload['computer_guid'])
            identity=self.credentials._reservation(**pair)
            document=private_read(self.credentials.path(**pair))
            def guard():
                if (self.fresh_check(payload) != payload['snapshot']
                        or self.plans.load(claim['plan_id'],claim['plan_sha256'])['payload'] != payload
                        or private_read(self.attempts.claim_path(**pair)) != claim
                        or self.credentials._reservation(**pair) != identity
                        or private_read(self.credentials.path(**pair)) != document
                        or self.credentials.open(**pair) != password
                        or private_read(self.credentials.path(**pair)) != document
                        or self.credentials._reservation(**pair) != identity
                        or self.fresh_check(payload) != payload['snapshot']
                        or self.plans.load(claim['plan_id'],claim['plan_sha256'])['payload'] != payload): raise ValueError
            guard()
            if sealed != dict(claim_sha256=digest(claim),sealed_sha256=document['sealed_sha256']): raise ValueError
            record=private_read(self.path(payload))
            expected=dict(schema_version=1,plan_sha256=claim['plan_sha256'],claim_sha256=digest(claim),
                snapshot_sha256=digest(payload['snapshot']),sealed_sha256=sealed['sealed_sha256'])
            if (set(record) != set(expected)|{'controller_backup','backup_request','workstation_backup','rehearsal_metadata','local_rehearsal'}
                    or type(record['schema_version']) is not int
                    or any(record[key] != value for key,value in expected.items())): raise ValueError
            machine=self.machines.resolve(payload['machine_uuid'])
            if (machine.uuid != payload['machine_uuid'] or machine.hostname != payload['snapshot']['machine']['hostname']
                    or machine.ip != payload['snapshot']['machine']['ip']): raise ValueError
            facts=payload['snapshot']['workstation_facts']['snapshot']
            request=self.runtime.backup_request(machine,**pair,facts=facts)
            if request != record['backup_request']: raise ValueError
            meta=validate_metadata(record['rehearsal_metadata'])
            dc=payload['snapshot']['computer']['dc']
            for key,value in dict(hostname=machine.hostname,realm='sosnadmin.local',workgroup='SOSNADM',
                    domain_guid=dc['domain_guid'],domain_sid=dc['domain_sid'],dc_hostname=dc['dns_hostname']).items():
                if meta[key] != value: raise ValueError
            if self.controller.verify(payload) != record['controller_backup']: raise ValueError
            if self.runtime.verify_backup(machine,**pair,facts=facts) != record['workstation_backup']: raise ValueError
            if self.runtime.verify_rehearsal(machine,**pair,backup_request=request,
                    backup_receipt=record['workstation_backup'],metadata=meta) != record['local_rehearsal']: raise ValueError
            guard()
            if private_read(self.path(payload)) != record: raise ValueError
            result={key:value for key,value in expected.items() if key!='plan_sha256'}
            return dict(result,controller_backup_verified=True,workstation_backup_verified=True,local_rehearsal_verified=True,
                controller_backup_sha256=digest(record['controller_backup']),
                workstation_backup_sha256=digest(record['workstation_backup']),local_rehearsal_sha256=digest(record['local_rehearsal']))
        except Exception:
            raise fail('recovery_prewrite_invalid','All three attempt-bound preparation artifacts and the exact live plan must remain verified before writing') from None
