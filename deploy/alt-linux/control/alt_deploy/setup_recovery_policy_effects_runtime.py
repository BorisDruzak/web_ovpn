"""Fresh snapshot-bound effect inventory transport/plans; no reservation or apply."""
from __future__ import annotations

import copy,ipaddress,re,shlex
from pathlib import Path

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import SetupPlanStore,decode_state_bytes,digest
from .setup_recovery_runtime import _read_source
from .setup_recovery_policy_baseline_runtime import RecoveryPolicyBaselineRuntime,RecoveryPolicyBaselineService,_same,_target,_request
from . import setup_recovery_policy_effects_wire as wire,setup_recovery_policy_effects as effects
from . import setup_recovery_policy_baseline as baseline,setup_recovery_original_policy as original
from . import setup_recovery_sssd_policy as policy,setup_recovery_native as native,setup_recovery_probe as probe


def _receipt(pair,request,metadata):
    if not isinstance(pair,dict) or set(pair)!={'baseline_receipt','effect_receipt'}:raise ValueError
    old=pair['baseline_receipt'];value=pair['effect_receipt']
    projection=baseline.projection(old,original=original,policy=policy,native=native,meta=metadata)
    if (old['status']!='original_sssd_policy_baseline' or old['request_sha256']!=digest(request)
            or old['original_sha256']!=digest(request['backup_request']['facts']['files']['/etc/sssd/sssd.conf'])):raise ValueError
    effect_request=dict(schema_version=1,baseline_request=request,baseline_receipt=old,source_sha256=request['source_sha256'])
    fields={'schema_version','status','request_sha256','baseline_projection_sha256','source_sha256','runtime_dependencies',
            'configured','key_inventory','unreviewed_keys','defaults_reviewed','effects_reviewed','execution_authorized'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['status']!='original_policy_effect_inventory'
            or any(value[key] is not False for key in ('defaults_reviewed','effects_reviewed','execution_authorized'))
            or value['request_sha256']!=digest(effect_request) or value['baseline_projection_sha256']!=digest(projection)
            or value['source_sha256']!=request['source_sha256'] or not isinstance(value['runtime_dependencies'],dict)
            or set(value['runtime_dependencies'])!=set(effects.DEPENDENCIES)):raise ValueError
    for path,package in effects.DEPENDENCIES.items():
        info=value['runtime_dependencies'][path]
        if (not isinstance(info,dict) or set(info)!={'present','sha256','size','uid','gid','mode','package'}
                or info['present'] is not True or info['package']!=package
                or any(type(info[key]) is not int for key in ('size','uid','gid','mode'))
                or info['uid']!=0 or info['gid']!=0 or not 0<info['size']<=probe.MAX_TOOL_BYTES
                or info['mode'] not in ((0o644,0o755) if path.endswith('.so') else (0o755,))
                or not isinstance(info['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',info['sha256'])):raise ValueError
    data,unknown=effects._values(dict(configured=value['configured'],key_inventory=value['key_inventory'],domains=metadata['realm'].upper()),metadata)
    if value['unreviewed_keys']!=unknown:raise ValueError
    for key,expected in projection['configured_values'].items():
        actual=data['domains'] if key=='domains' else data['configured'][key]['value']
        if actual!=expected:raise ValueError
    return projection


class RecoveryPolicyEffectsRuntime(RecoveryPolicyBaselineRuntime):
    def _sources(self):
        directory=Path(__file__).parent;owner=Path(__file__).lstat().st_uid
        return [_read_source(directory/('setup_recovery_'+name+'.py'),owner=owner) for name in wire.NAMES]

    def capture(self,machine,snapshot,metadata):
        try:
            selected=copy.deepcopy(snapshot);meta=copy.deepcopy(metadata);target=_target(machine,selected)
            address=str(ipaddress.ip_address(target['ip']));sources=self._sources();request=_request(selected,meta,sources)
            request['backup_request']['claim_sha256']=digest(dict(schema_version=1,scope='original_policy_effect_inventory_only',recovery_snapshot_sha256=digest(selected)))
            script,payload=wire.build(sources,request);remote='sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)
            if len(remote.encode())>=8192:raise ValueError
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','IdentitiesOnly=yes',
                '-o','ConnectTimeout=10','-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),
                '-i',str(self.settings.private_key_file),'ansible@'+address,remote]
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=payload,timeout=210)
            if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>wire.MAX_REPLY_BYTES:raise ValueError
            receipt=decode_state_bytes(out.encode());projection=_receipt(receipt,request,meta)
            if (self._sources()!=sources or not _same(_target(machine,selected),target)
                    or not _same(snapshot,selected) or not _same(metadata,meta)):raise ValueError
            return dict(source_sha256=digest(sources),request_sha256=digest(request),receipt=receipt,projection=projection)
        except Exception:
            raise fail('recovery_policy_effects_failed','Fixed snapshot-bound original effect inventory did not verify') from None


class EffectsPlanStore(SetupPlanStore):
    prefix='recovery-policy-effects-'
    directory='setup-recovery-policy-effects-plans'


class RecoveryPolicyEffectsService(RecoveryPolicyBaselineService):
    def __init__(self,planning,*,runtime=None,resolver=None):
        super().__init__(planning,runtime=runtime or RecoveryPolicyEffectsRuntime(planning.settings),resolver=resolver)
        self.plans=EffectsPlanStore(planning.settings.state_root,clock=planning.clock)

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
                inventory=result['receipt']['effect_receipt']
                payload=dict(schema_version=1,kind='original_policy_effect_inventory_only',failed_run_id=failed_run_id,
                    computer_guid=computer_guid,machine=snapshot['machine'],recovery_snapshot_sha256=digest(snapshot),
                    metadata=metadata,source_sha256=result['source_sha256'],request_sha256=result['request_sha256'],
                    receipt=result['receipt'],projection=result['projection'],effect_inventory_sha256=digest(inventory),
                    unreviewed_key_count=len(inventory['unreviewed_keys']),execution_available=False,
                    defaults_reviewed=False,effects_reviewed=False,
                    review_requirements=['unknown_configured_keys','runtime_default_semantics','source_target_approval_binding',
                                         'normal_policy_effects_manifest','terminal_handoff'])
                plan=self.plans.create(payload)
                if (not _same(self.planning.snapshot(failed_run_id,computer_guid),snapshot)
                        or not _same(self.plans.load(plan['plan_id'],plan['sha256']),plan)
                        or digest(self.runtime._sources())!=result['source_sha256']):raise ValueError
                return plan
        except Exception:
            raise fail('recovery_policy_effects_failed','Read-only effect planning did not verify; no recovery attempt was reserved') from None
