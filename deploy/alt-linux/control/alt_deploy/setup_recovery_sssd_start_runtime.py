"""Fixed startup transport under caller-supplied exact execution authorization.

No CLI/coordinator or authority default exists. The mandatory read-only
authorization gate must derive its unit/effects/approval binding from the
operator-approved protected plan. It runs under the lifecycle lock and must
not prompt or mutate state. This runtime never opens Vault or writes AD.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re
import shlex

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import canonical,digest,decode_state_bytes,private_read
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_runtime import _read_source
from . import setup_recovery_backup as backup
from . import setup_recovery_kerberos as kerberos
from . import setup_recovery_services as services
from . import setup_recovery_sssd_policy as policy
from . import setup_recovery_sssd_start as start
from . import setup_recovery_start_wire as wire
from .setup_recovery_process import bounded_bundle_run


def _same(left,right):return canonical(left)==canonical(right)


class RecoverySSSDStartRuntime:
    def __init__(self,*,policy_runtime,authorization,runner=None):
        if not callable(authorization):raise ValueError('Explicit startup authorization gate required')
        self.policy_runtime=policy_runtime;self.authorization=authorization
        self.settings=policy_runtime.settings;self.attempts=policy_runtime.attempts
        self.runner=bounded_bundle_run if runner is None else runner

    def _sources(self):
        directory=Path(__file__).parent;owner=Path(__file__).lstat().st_uid
        return self.policy_runtime._sources()+[_read_source(directory/('setup_recovery_'+name+'.py'),owner=owner)
            for name in ('start_graph','sssd_start')]

    def _context(self,plan_id,confirmed_sha):
        previous=self.policy_runtime;bound=copy.deepcopy(previous._context(plan_id,confirmed_sha));pair=bound['pair']
        sources=self._sources()
        if (len(sources)!=len(wire.NAMES) or sources[:10]!=bound['sources']
                or bound['request']['source_sha256']!=digest(sources[:10])):raise ValueError
        intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=confirmed_sha,request_sha256=digest(bound['request']),
            kerberos_receipt_sha256=digest(bound['request']['kerberos_receipt']),services_receipt_sha256=digest(bound['service_receipt']))
        intent_path=self.attempts._path(**pair,suffix='.sssd-policy-intent.json')
        result_path=self.attempts._path(**pair,suffix='.sssd-policy-result.json')
        if not _same(private_read(intent_path),intended):raise ValueError
        result=private_read(result_path);previous._receipt(bound['request'],result)
        postwrite=previous.kerberos_runtime.import_runtime.postwrite
        payload=bound['kerberos_context']['import_context']['protected']['payload']
        plans=postwrite.service_gate.preparation.plans
        plan=copy.deepcopy(plans.load(plan_id,confirmed_sha))
        if (plan['plan_id']!=plan_id or plan['sha256']!=confirmed_sha or not _same(plan['payload'],payload)
                or postwrite.fingerprint()!=payload['snapshot']['prerequisites']['source_sha256']):raise ValueError
        approved=copy.deepcopy(self.authorization(plan_id,confirmed_sha,digest(sources)))
        fields={'schema_version','plan_id','plan_sha256','source_sha256','sssd_unit','effects_ledger_sha256','approval_sha256'}
        if (not isinstance(approved,dict) or set(approved)!=fields or type(approved['schema_version']) is not int
                or approved['schema_version']!=1 or approved['plan_id']!=plan_id or approved['plan_sha256']!=confirmed_sha
                or approved['source_sha256']!=digest(sources)):raise ValueError
        request=dict(schema_version=1,policy_request=bound['request'],policy_receipt=result,
            service_request=bound['service_request'],service_receipt=bound['service_receipt'],sssd_unit=approved['sssd_unit'],
            source_sha256=digest(sources),effects_ledger_sha256=approved['effects_ledger_sha256'],approval_sha256=approved['approval_sha256'],
            plan_id=plan_id,plan_sha256=confirmed_sha,plan_created_at=plan['created_at'],plan_expires_at=plan['expires_at'])
        start._request(request,backup=backup,policy=policy,kerberos=kerberos,services=services)
        # End source/DNS/authorization work with protected history and a fresh
        # source fingerprint and plan load. No inactive-only workstation read.
        if (not _same(previous._context(plan_id,confirmed_sha),bound) or self._sources()!=sources
                or not _same(self.authorization(plan_id,confirmed_sha,digest(sources)),approved)
                or not _same(private_read(intent_path),intended) or not _same(private_read(result_path),result)):raise ValueError
        fresh={key:value for key,value in postwrite.load(plan_id,confirmed_sha).items() if key!='machine'}
        if (not _same(fresh,bound['kerberos_context']['import_context']['protected'])
                or postwrite.fingerprint()!=payload['snapshot']['prerequisites']['source_sha256']
                or not _same(plans.load(plan_id,confirmed_sha),plan)):raise ValueError
        return dict(pair=pair,address=bound['address'],request=request,sources=sources,policy_context=bound,authorization=approved)

    @staticmethod
    def _receipt(request,result):
        if (not isinstance(result,dict) or any(type(result.get(key)) is not int for key in ('schema_version','main_pid','n_restarts','kvno'))
                or not 1<=result['main_pid']<=2147483647 or result['n_restarts']!=0
                or not isinstance(result.get('invocation_id'),str) or not re.fullmatch('[0-9a-f]{32}',result['invocation_id'])
                or int(result['invocation_id'],16)==0 or result['invocation_id']==request['sssd_unit']['properties']['InvocationID']):raise ValueError
        state=copy.deepcopy(request['sssd_unit'])
        state['properties'].update(ActiveState='active',SubState='running',MainPID=str(result['main_pid']),InvocationID=result['invocation_id'])
        if not _same(start._receipt(request,state,backup),result):raise ValueError

    def start_once(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('start',plan_id,confirmed_sha)

    def verify(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('verify',plan_id,confirmed_sha)

    def _operate(self,action,plan_id,confirmed_sha):
        entered=False;pair=None
        try:
            context=self._context(plan_id,confirmed_sha);pair=context['pair'];request=context['request']
            intent_path=self.attempts._path(**pair,suffix='.sssd-start-intent.json')
            result_path=self.attempts._path(**pair,suffix='.sssd-start-result.json')
            intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=confirmed_sha,request_sha256=digest(request),
                policy_receipt_sha256=digest(request['policy_receipt']),services_receipt_sha256=digest(request['service_receipt']),
                approval_sha256=request['approval_sha256'],effects_ledger_sha256=request['effects_ledger_sha256'])
            receipt=None
            if action=='start':
                if any(path.exists() or path.is_symlink() for path in (intent_path,result_path)):raise ValueError
            else:
                if not _same(private_read(intent_path),intended):raise ValueError
                receipt=private_read(result_path);self._receipt(request,receipt)
            script,encoded=wire.build(action,context['sources'],request,receipt=receipt)
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10',
                '-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),
                'ansible@'+context['address'],'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)]
            if action=='start':entered=True;RecoveryControllerBackup._persist(intent_path,intended)
            if not _same(self._context(plan_id,confirmed_sha),context) or not _same(private_read(intent_path),intended):raise ValueError
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=encoded,timeout=150)
            if type(rc) is not int or rc!=0 or not isinstance(out,str) or len(out.encode())>wire.MAX_REPLY_BYTES:raise ValueError
            result=decode_state_bytes(out.encode());self._receipt(request,result)
            if not _same(self._context(plan_id,confirmed_sha),context) or not _same(private_read(intent_path),intended):raise ValueError
            if action=='start':RecoveryControllerBackup._persist(result_path,result)
            elif not _same(private_read(result_path),result):raise ValueError
            if (not _same(self._context(plan_id,confirmed_sha),context) or not _same(private_read(intent_path),intended)
                    or not _same(private_read(result_path),result)):raise ValueError
            return result
        except Exception:
            if entered and pair is not None:
                try:self.attempts.finish(**pair,status='failed',error_code='recovery_sssd_start_failed')
                except Exception:pass
            raise fail('recovery_sssd_start_failed','Bound SSSD start did not verify; retained attempts cannot be replayed') from None
