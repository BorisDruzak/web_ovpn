"""Snapshot-bound read-only baseline CLI preparation; never reserves recovery."""
from __future__ import annotations

import copy,ipaddress,re,shlex
from pathlib import Path

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import SetupPlanStore,decode_state_bytes,digest,canonical
from .setup_recovery_prepare import _resolve_dc
from .setup_recovery_process import bounded_bundle_run
from .setup_recovery_runtime import _read_source
from . import setup_recovery_policy_baseline as baseline,setup_recovery_policy_baseline_wire as wire
from . import setup_recovery_backup as backup,setup_recovery_native as native
from . import setup_recovery_sssd_policy as policy,setup_recovery_original_policy as original


def _same(left,right):return canonical(left)==canonical(right)


def _target(machine,snapshot):
    registered=snapshot['machine']
    current=dict(uuid=machine.uuid,hostname=machine.hostname,ip=machine.ip,registration_sha256=digest(machine.raw))
    if not _same(current,registered) or current['uuid']!=snapshot['machine_uuid']:raise ValueError
    return current


def _request(snapshot,metadata,sources):
    facts=copy.deepcopy(snapshot['workstation_facts']['snapshot'])
    if digest(facts)!=snapshot['workstation_facts']['snapshot_sha256']:raise ValueError
    # Compatibility frame only: this hash labels a read-only snapshot context.
    # It is not a reservation claim and is never stored/accepted as one here.
    context=digest(dict(schema_version=1,scope='original_policy_baseline_only',recovery_snapshot_sha256=digest(snapshot)))
    frame=dict(schema_version=1,failed_run_id=snapshot['failed_run_id'],computer_guid=snapshot['computer_guid'],
        claim_sha256=context,machine_uuid=snapshot['machine_uuid'],hostname=snapshot['machine']['hostname'],
        facts=facts,snapshot_sha256=digest(facts),source_sha256=digest(sources))
    request=dict(schema_version=1,backup_request=frame,metadata=copy.deepcopy(metadata),source_sha256=digest(sources))
    baseline._request(request,backup=backup,native=native)
    return request


class RecoveryPolicyBaselineRuntime:
    def __init__(self,settings,*,runner=None):self.settings=settings;self.runner=runner or bounded_bundle_run

    def _sources(self):
        directory=Path(__file__).parent;owner=Path(__file__).lstat().st_uid
        return [_read_source(directory/('setup_recovery_'+name+'.py'),owner=owner) for name in wire.NAMES]

    def capture(self,machine,snapshot,metadata):
        try:
            selected=copy.deepcopy(snapshot);meta=copy.deepcopy(metadata);target=_target(machine,selected)
            address=str(ipaddress.ip_address(target['ip']));sources=self._sources();request=_request(selected,meta,sources)
            script,payload=wire.build(sources,request);remote='sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)
            if len(remote.encode())>=8192:raise ValueError
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','IdentitiesOnly=yes',
                '-o','ConnectTimeout=10','-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),
                '-i',str(self.settings.private_key_file),'ansible@'+address,remote]
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=payload,timeout=150)
            if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>wire.MAX_REPLY_BYTES:raise ValueError
            receipt=decode_state_bytes(out.encode());projection=baseline.projection(receipt,original=original,policy=policy,native=native,meta=meta)
            if (receipt['status']!='original_sssd_policy_baseline' or receipt['request_sha256']!=digest(request)
                    or receipt['original_sha256']!=digest(request['backup_request']['facts']['files']['/etc/sssd/sssd.conf'])
                    or self._sources()!=sources or not _same(_target(machine,selected),target)
                    or not _same(snapshot,selected) or not _same(metadata,meta)):raise ValueError
            return dict(source_sha256=digest(sources),request_sha256=digest(request),receipt=receipt,projection=projection)
        except Exception:
            raise fail('recovery_policy_baseline_failed','Fixed snapshot-bound original policy baseline did not verify') from None


class BaselinePlanStore(SetupPlanStore):
    prefix='recovery-policy-baseline-'
    directory='setup-recovery-policy-baseline-plans'


class RecoveryPolicyBaselineService:
    def __init__(self,planning,*,runtime=None,resolver=None):
        self.planning=planning;self.runtime=runtime or RecoveryPolicyBaselineRuntime(planning.settings)
        self.resolver=resolver or _resolve_dc
        self.plans=BaselinePlanStore(planning.settings.state_root,clock=planning.clock)

    def _metadata(self,snapshot):
        dc=snapshot['computer']['dc']
        if not isinstance(dc['dns_hostname'],str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.sosnadmin\.local',dc['dns_hostname']):
            raise ValueError('Invalid fixed baseline DC hostname')
        return native.validate_metadata(dict(hostname=snapshot['machine']['hostname'],realm='sosnadmin.local',workgroup='SOSNADM',
            domain_guid=dc['domain_guid'],domain_sid=dc['domain_sid'],dc_hostname=dc['dns_hostname'],
            dc_address=self.resolver(dc['dns_hostname'])))

    def plan(self,failed_run_id,computer_guid):
        try:
            with exclusive_lock(self.planning.settings.lock_file):
                snapshot=copy.deepcopy(self.planning.snapshot(failed_run_id,computer_guid));metadata=self._metadata(snapshot)
                if not _same(self.planning.snapshot(failed_run_id,computer_guid),snapshot):raise ValueError
                machine=self.planning.machines.resolve(snapshot['machine_uuid'])
                result=self.runtime.capture(machine,snapshot,metadata)
                current=copy.deepcopy(self.planning.snapshot(failed_run_id,computer_guid))
                if (not _same(current,snapshot) or not _same(self._metadata(current),metadata)
                        or digest(self.runtime._sources())!=result['source_sha256']):raise ValueError
                payload=dict(schema_version=1,kind='original_policy_baseline_only',failed_run_id=failed_run_id,
                    computer_guid=computer_guid,machine=snapshot['machine'],recovery_snapshot_sha256=digest(snapshot),
                    metadata=metadata,source_sha256=result['source_sha256'],request_sha256=result['request_sha256'],
                    receipt=result['receipt'],projection=result['projection'],execution_available=False,
                    review_requirements=['runtime_default_semantics','source_target_approval_binding','startup_effects_review','terminal_handoff'])
                plan=self.plans.create(payload)
                if (not _same(self.planning.snapshot(failed_run_id,computer_guid),snapshot)
                        or not _same(self.plans.load(plan['plan_id'],plan['sha256']),plan)
                        or digest(self.runtime._sources())!=result['source_sha256']):raise ValueError
                return plan
        except Exception:
            raise fail('recovery_policy_baseline_failed','Read-only baseline planning did not verify; no recovery attempt was reserved') from None
