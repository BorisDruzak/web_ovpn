"""Fixed preparation coordinator; no directory-password or auth-file writer."""
from __future__ import annotations

import ipaddress
import re

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import digest, private_read
from .setup_recovery import _pair
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_credential import RecoveryCredentialStore, RecoveryVaultCodec
from .setup_recovery_native import validate_metadata
from .setup_recovery_prewrite import RecoveryPrewriteGate
from .setup_recovery_process import bounded_recovery_run
from .setup_recovery_provider import PROVIDER
from .setup_recovery_rehearsal_runtime import RecoveryRehearsalRuntime
from .setup_recovery_reserved_state import RecoveryReservedState


def _resolve_dc(hostname):
    # The hostname comes only from the sealed writable-DC snapshot. No shell,
    # address/path argument, resolver override or environment override exists
    # in an operator interface. Refuse ambiguous IPv4 resolution.
    rc,output,_=bounded_recovery_run(['/usr/bin/getent','ahostsv4',hostname],
        environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text='',timeout=10)
    if rc != 0: raise ValueError
    addresses=set()
    for line in output.splitlines():
        fields=line.split()
        if len(fields) not in (2,3) or fields[1] not in ('STREAM','DGRAM','RAW'): raise ValueError
        addresses.add(str(ipaddress.IPv4Address(fields[0])))
    if len(addresses)!=1: raise ValueError
    return addresses.pop()


class RecoveryPreparationCoordinator:
    def __init__(self,planning,*,credentials=None,controller=None,runtime=None,resolver=None):
        self.planning,self.settings=planning,planning.settings
        self.plans,self.attempts=planning.plans,planning.attempts
        self.credentials=credentials or RecoveryCredentialStore(self.settings.state_root,codec=RecoveryVaultCodec(self.settings))
        self.fresh_check=RecoveryReservedState(planning,credentials=self.credentials)
        self.controller=controller or RecoveryControllerBackup(self.settings,credentials=self.credentials,fresh_check=self.fresh_check)
        self.runtime=runtime or RecoveryRehearsalRuntime(self.settings,credentials=self.credentials)
        self.resolver=resolver or _resolve_dc
        self.gate=RecoveryPrewriteGate(self.settings,machines=planning.machines,credentials=self.credentials,
            fresh_check=self.fresh_check,controller=self.controller,runtime=self.runtime,plans=self.plans)

    def _metadata(self,payload):
        dc=payload['snapshot']['computer']['dc']
        metadata=dict(hostname=payload['snapshot']['machine']['hostname'],realm='sosnadmin.local',workgroup='SOSNADM',
            domain_guid=dc['domain_guid'],domain_sid=dc['domain_sid'],dc_hostname=dc['dns_hostname'])
        if (not isinstance(metadata['dc_hostname'],str) or not re.fullmatch(
                r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.sosnadmin\.local',metadata['dc_hostname'])): raise ValueError
        metadata['dc_address']=self.resolver(metadata['dc_hostname'])
        return validate_metadata(metadata)

    def prepare(self,plan_id,confirmed_sha):
        reserved=False
        try:
            with exclusive_lock(self.settings.lock_file):
                plan=self.plans.load(plan_id,confirmed_sha);payload=plan['payload']
                fields={'failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256',
                        'execution_available','provider','snapshot'}
                if (set(payload)!=fields or payload['execution_available'] is not True or payload['provider']!=PROVIDER
                        or payload['snapshot']['execution_available'] is not False
                        or any(payload[key]!=payload['snapshot'][key] for key in
                            ('failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256'))): raise ValueError
                pair=_pair(payload['failed_run_id'],payload['computer_guid'])
                if self.planning.snapshot(**pair)!=payload['snapshot']: raise ValueError
                metadata=self._metadata(payload)
                if self.plans.load(plan_id,confirmed_sha)!=plan or self.planning.snapshot(**pair)!=payload['snapshot']: raise ValueError
                historical=self.planning.history.load(pair['failed_run_id'])
                claim=self.attempts.reserve(plan_id,confirmed_sha,historical['raw_files']);reserved=True
                sealed=self.credentials.create(**pair)
                document=private_read(self.credentials.path(**pair))
                identity=self.credentials._reservation(**pair)
                expected=dict(schema_version=1,plan_sha256=confirmed_sha,claim_sha256=digest(claim),
                    snapshot_sha256=digest(payload['snapshot']),sealed_sha256=sealed['sealed_sha256'])
                RecoveryControllerBackup._persist(self.attempts._path(**pair,suffix='.preparation-intent.json'),expected)
            def guard():
                if (self.plans.load(plan_id,confirmed_sha)!=plan or self.fresh_check(payload)!=payload['snapshot']
                        or private_read(self.credentials.path(**pair))!=document
                        or self.credentials._reservation(**pair)!=identity
                        or private_read(self.attempts._path(**pair,suffix='.preparation-intent.json'))!=expected): raise ValueError
            guard()
            # Native creation owns the lifecycle lock while freezing and copying
            # the controller; do not recursively hold it across this call.
            controller=self.controller.prepare(payload)
            with exclusive_lock(self.settings.lock_file):
                guard()
                if self._metadata(payload)!=metadata: raise ValueError
                machine=self.planning.machines.resolve(payload['machine_uuid'])
                registered=payload['snapshot']['machine']
                if (machine.uuid!=payload['machine_uuid'] or machine.hostname!=registered['hostname']
                        or machine.ip!=registered['ip'] or digest(machine.raw)!=registered['registration_sha256']): raise ValueError
                facts=payload['snapshot']['workstation_facts']['snapshot']
                request=self.runtime.backup_request(machine,**pair,facts=facts)
                backup=self.runtime.create_backup(machine,**pair,facts=facts)
                guard()
                rehearsal=self.runtime.create_rehearsal(machine,**pair,backup_request=request,backup_receipt=backup,metadata=metadata)
                guard()
                record=dict(expected,controller_backup=controller,backup_request=request,
                    workstation_backup=backup,rehearsal_metadata=metadata,local_rehearsal=rehearsal)
                RecoveryControllerBackup._persist(self.gate.path(payload),record)
                RecoveryControllerBackup._persist(self.attempts._path(**pair,suffix='.preparation-ready.json'),
                    {'schema_version':1,'preparation_sha256':digest(record)})
                password=self.credentials.open(**pair)
                verified=self.gate(payload,claim,sealed,password)
                guard()
                return dict(pair,status='recovery_prepared',plan_id=plan_id,plan_sha256=confirmed_sha,
                    preparation_sha256=digest(record),verification_sha256=digest(verified))
        except Exception:
            if reserved:
                try:self.attempts.finish(**pair,status='failed',error_code='recovery_preparation_failed')
                except Exception:pass
            raise fail('recovery_preparation_failed','Fixed recovery preparation did not produce verified evidence; any reserved attempt remains excluded') from None
