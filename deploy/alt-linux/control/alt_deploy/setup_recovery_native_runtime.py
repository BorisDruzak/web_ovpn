"""Fixed native check transport with mandatory caller-owned exact authorization.

Internal only. The authorization callback must verify protected deployment,
plan and reviewed effects provenance; there is no authority default or CLI.
This runtime neither opens Vault nor writes AD or starts/stops services.
"""
from __future__ import annotations

import copy,re,shlex
from pathlib import Path

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import canonical,digest,decode_state_bytes,private_read
from .setup_recovery_runtime import _read_source
from .setup_recovery_controller_backup import RecoveryControllerBackup
from . import setup_recovery_backup as backup
from . import setup_recovery_native_testjoin as worker
from . import setup_recovery_native_wire as wire


def _same(left,right):return canonical(left)==canonical(right)


class RecoveryNativeRuntime:
    def __init__(self,*,startup_runtime,authorization,runner=None):
        if not callable(authorization):raise ValueError('Explicit native-check authorization required')
        self.startup_runtime=startup_runtime;self.authorization=authorization
        self.settings=startup_runtime.settings;self.attempts=startup_runtime.attempts
        self.runner=runner or startup_runtime.runner

    def _sources(self):
        path=Path(__file__).parent/'setup_recovery_native_testjoin.py'
        return self.startup_runtime._sources()+[_read_source(path,owner=Path(__file__).lstat().st_uid)]

    def _context(self,plan_id,sha):
        startup=self.startup_runtime;bound=copy.deepcopy(startup._context(plan_id,sha))
        pair=bound['pair'];request=bound['request'];sources=self._sources()
        if len(sources)!=len(wire.NAMES) or sources[:-1]!=bound['sources']:raise ValueError
        intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,request_sha256=digest(request),
            policy_receipt_sha256=digest(request['policy_receipt']),services_receipt_sha256=digest(request['service_receipt']),
            approval_sha256=request['approval_sha256'],effects_ledger_sha256=request['effects_ledger_sha256'])
        intent_path=self.attempts._path(**pair,suffix='.sssd-start-intent.json')
        result_path=self.attempts._path(**pair,suffix='.sssd-start-result.json')
        if not _same(private_read(intent_path),intended):raise ValueError
        started=private_read(result_path);startup._receipt(request,started)
        approved=copy.deepcopy(self.authorization(plan_id,sha,digest(sources),digest(request),digest(started)))
        expected=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=digest(sources),
            startup_request_sha256=digest(request),startup_receipt_sha256=digest(started),
            startup_approval_sha256=request['approval_sha256'],effects_ledger_sha256=request['effects_ledger_sha256'])
        if (not isinstance(approved,dict) or set(approved)!=set(expected)|{'approval_sha256'}
                or not isinstance(approved['approval_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',approved['approval_sha256'])
                or not _same({key:approved[key] for key in expected},expected)):raise ValueError
        if (self._sources()!=sources
                or not _same(self.authorization(plan_id,sha,digest(sources),digest(request),digest(started)),approved)
                or not _same(startup._context(plan_id,sha),bound)
                or not _same(private_read(intent_path),intended) or not _same(private_read(result_path),started)):raise ValueError
        # End callback-producing startup checks with an exact native approval
        # reread, then protected local sources/history and current plan TTL.
        if (not _same(self.authorization(plan_id,sha,digest(sources),digest(request),digest(started)),approved)
                or self._sources()!=sources):raise ValueError
        postwrite=startup.policy_runtime.kerberos_runtime.import_runtime.postwrite
        protected=bound['policy_context']['kerberos_context']['import_context']['protected'];payload=protected['payload']
        plans=postwrite.service_gate.preparation.plans
        current_plan=plans.load(plan_id,sha)
        if (not _same(postwrite._protected(plan_id,sha)[0],protected)
                or postwrite.fingerprint()!=payload['snapshot']['prerequisites']['source_sha256']
                or any(current_plan[key]!=value for key,value in dict(plan_id=plan_id,sha256=sha,
                    created_at=request['plan_created_at'],expires_at=request['plan_expires_at']).items())
                or not _same(current_plan['payload'],payload)
                or not _same(private_read(intent_path),intended) or not _same(private_read(result_path),started)):raise ValueError
        return dict(pair=pair,address=bound['address'],request=request,started=started,sources=sources,authorization=approved)

    @staticmethod
    def _receipt(request,started,result):
        facts=request['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
        tools={path:dict(facts['tools'][path.rsplit('/',1)[1]],package=package) for path,package in worker.TOOLS.items()}
        if not _same(result,worker._receipt(request,started,tools,backup)):raise ValueError

    def testjoin_once(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('testjoin',plan_id,confirmed_sha)

    def verify(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('verify',plan_id,confirmed_sha)

    def _operate(self,action,plan_id,sha):
        entered=False;pair=None
        try:
            context=self._context(plan_id,sha);pair=context['pair'];request=context['request'];started=context['started']
            intent_path=self.attempts._path(**pair,suffix='.native-testjoin-intent.json')
            result_path=self.attempts._path(**pair,suffix='.native-testjoin-result.json')
            failed_path=self.attempts._path(**pair,suffix='.native-testjoin-failed.json')
            if failed_path.exists() or failed_path.is_symlink():raise ValueError
            intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,request_sha256=digest(request),
                startup_receipt_sha256=digest(started),sources_sha256=digest(context['sources']),
                authorization_sha256=digest(context['authorization']))
            receipt=None
            if action=='testjoin':
                if any(path.exists() or path.is_symlink() for path in (intent_path,result_path)):raise ValueError
            else:
                if not _same(private_read(intent_path),intended):raise ValueError
                receipt=private_read(result_path);self._receipt(request,started,receipt)
            script,encoded=wire.build(action,context['sources'],request,started,receipt=receipt)
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10',
                '-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),
                'ansible@'+context['address'],'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)]
            if action=='testjoin':entered=True;RecoveryControllerBackup._persist(intent_path,intended)
            if (not _same(self._context(plan_id,sha),context) or not _same(private_read(intent_path),intended)
                    or failed_path.exists() or failed_path.is_symlink()):raise ValueError
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=encoded,timeout=150)
            if type(rc) is not int or rc!=0 or not isinstance(out,str) or len(out.encode())>wire.MAX_REPLY_BYTES:raise ValueError
            result=decode_state_bytes(out.encode());self._receipt(request,started,result)
            if not _same(self._context(plan_id,sha),context) or not _same(private_read(intent_path),intended):raise ValueError
            if action=='testjoin':RecoveryControllerBackup._persist(result_path,result)
            elif not _same(private_read(result_path),result):raise ValueError
            if (not _same(self._context(plan_id,sha),context) or not _same(private_read(intent_path),intended)
                    or not _same(private_read(result_path),result) or failed_path.exists() or failed_path.is_symlink()):raise ValueError
            return result
        except Exception:
            if entered and pair is not None:
                try:RecoveryControllerBackup._persist(self.attempts._path(**pair,suffix='.native-testjoin-failed.json'),
                    dict(schema_version=1,error_code='recovery_native_testjoin_failed'))
                except Exception:pass
                try:self.attempts.finish(**pair,status='failed',error_code='recovery_native_testjoin_failed')
                except Exception:pass
            raise fail('recovery_native_testjoin_failed','Bound native check did not verify; retained attempts cannot be replayed') from None
