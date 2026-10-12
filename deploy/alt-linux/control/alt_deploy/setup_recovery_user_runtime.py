"""Fixed controller user transport with mandatory caller-owned exact authority.

The production coordinator must supply RecoveryUserAuthorization; no gate or
CLI authority default exists. No directory write, Vault opening or service action.
"""
from __future__ import annotations

import copy,re,shlex
from pathlib import Path

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import canonical,digest,decode_state_bytes,private_read
from .setup_recovery_runtime import _read_source
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_process import bounded_bundle_run
from .setup_recovery_user_authorization import native_records
from . import setup_recovery_user_check as worker,setup_recovery_user_wire as wire,setup_recovery_backup as backup


def _same(left,right):return canonical(left)==canonical(right)


def _sha(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None


class RecoveryUserRuntime:
    def __init__(self,*,native_runtime,authorization,runner=None):
        if not callable(authorization):raise ValueError('Explicit user authorization required')
        self.native_runtime=native_runtime;self.authorization=authorization
        self.settings=native_runtime.settings;self.attempts=native_runtime.attempts
        self.runner=bounded_bundle_run if runner is None else runner

    def _sources(self):
        path=Path(__file__).with_name('setup_recovery_user_check.py')
        return self.native_runtime._sources()+[_read_source(path,owner=Path(__file__).lstat().st_uid)]

    def _context(self,plan_id,sha):
        native=self.native_runtime;bound=copy.deepcopy(native._context(plan_id,sha))
        result=native_records(native,bound,plan_id,sha);sources=self._sources()
        postwrite=native.startup_runtime.policy_runtime.kerberos_runtime.import_runtime.postwrite
        protected=copy.deepcopy(postwrite._protected(plan_id,sha)[0]);payload=protected['payload']
        if len(sources)!=len(wire.NAMES) or sources[:-1]!=bound['sources']:raise ValueError
        args=(plan_id,sha,digest(sources),digest(bound['request']),digest(bound['started']),digest(result))
        approved=copy.deepcopy(self.authorization(*args))
        expected=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,source_sha256=args[2],
            startup_request_sha256=args[3],startup_receipt_sha256=args[4],native_receipt_sha256=args[5],
            approval_sha256=bound['request']['approval_sha256'])
        if (not isinstance(approved,dict) or set(approved)!=set(expected)|{'employee','user_scope_sha256'}
                or not _sha(approved['user_scope_sha256']) or not _sha(approved['approval_sha256'])
                or not _same({key:approved[key] for key in expected},expected)):raise ValueError
        worker.employee(approved['employee'])
        request=dict(schema_version=1,startup_request=bound['request'],startup_receipt=bound['started'],native_receipt=result,
            employee=approved['employee'],source_sha256=args[2],approval_sha256=approved['approval_sha256'])
        worker._request(request)
        if (not _same(native._context(plan_id,sha),bound) or not _same(self.authorization(*args),approved)):raise ValueError
        # End all directory/authority callbacks with protected local rereads.
        plans=postwrite.service_gate.preparation.plans;plan=plans.load(plan_id,sha)
        if (self._sources()!=sources or not _same(native_records(native,bound,plan_id,sha),result)
                or not _same(postwrite._protected(plan_id,sha)[0],protected)
                or postwrite.fingerprint()!=payload['snapshot']['prerequisites']['source_sha256']
                or not _same(plan['payload'],payload)
                or any(plan[key]!=value for key,value in dict(plan_id=plan_id,sha256=sha,
                    created_at=bound['request']['plan_created_at'],expires_at=bound['request']['plan_expires_at']).items())):raise ValueError
        return dict(pair=bound['pair'],address=bound['address'],request=request,sources=sources,authorization=approved)

    @staticmethod
    def _receipt(request,result):
        if (not isinstance(result,dict) or any(type(result.get(key)) is not int or not 1<=result[key]<=4294967294 for key in ('uid','gid'))
                or not _sha(result.get('local_passwd_sha256'))):raise ValueError
        facts=request['startup_request']['policy_request']['kerberos_request']['import_request']['rehearsal_request']['backup_request']['facts']
        tools={key:dict(facts['tools'][key],package=package) for key,package in (('getent',worker.PACKAGE),('nss_sss',worker.NSS_PACKAGE))}
        expected=worker._receipt(request,{key:result[key] for key in ('uid','gid')},tools,{},backup)
        # Only the genuine remote worker can observe this passwd metadata hash.
        expected['local_passwd_sha256']=result['local_passwd_sha256']
        if not _same(result,expected):raise ValueError

    def check_once(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('check',plan_id,confirmed_sha)

    def verify(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('verify',plan_id,confirmed_sha)

    def _operate(self,action,plan_id,sha):
        entered=False;pair=None
        try:
            context=self._context(plan_id,sha);pair=context['pair'];request=context['request']
            intent_path=self.attempts._path(**pair,suffix='.user-check-intent.json')
            result_path=self.attempts._path(**pair,suffix='.user-check-result.json')
            failed_path=self.attempts._path(**pair,suffix='.user-check-failed.json')
            if failed_path.exists() or failed_path.is_symlink():raise ValueError
            intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,request_sha256=digest(request),
                sources_sha256=digest(context['sources']),authorization_sha256=digest(context['authorization']))
            receipt=None
            if action=='check':
                if any(path.exists() or path.is_symlink() for path in (intent_path,result_path)):raise ValueError
            else:
                if not _same(private_read(intent_path),intended):raise ValueError
                receipt=private_read(result_path);self._receipt(request,receipt)
            script,encoded=wire.build(action,context['sources'],request,receipt=receipt)
            remote='sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)
            if len(remote.encode())>=8192:raise ValueError
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10',
                '-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),
                'ansible@'+context['address'],remote]
            if action=='check':entered=True;RecoveryControllerBackup._persist(intent_path,intended)
            if (not _same(self._context(plan_id,sha),context) or not _same(private_read(intent_path),intended)
                    or failed_path.exists() or failed_path.is_symlink()):raise ValueError
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=encoded,timeout=150)
            if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>wire.MAX_REPLY_BYTES:raise ValueError
            result=decode_state_bytes(out.encode());self._receipt(request,result)
            if not _same(self._context(plan_id,sha),context) or not _same(private_read(intent_path),intended):raise ValueError
            if action=='check':RecoveryControllerBackup._persist(result_path,result)
            elif not _same(private_read(result_path),result):raise ValueError
            if (not _same(self._context(plan_id,sha),context) or not _same(private_read(intent_path),intended)
                    or not _same(private_read(result_path),result) or failed_path.exists() or failed_path.is_symlink()):raise ValueError
            return result
        except Exception:
            if entered and pair is not None:
                try:RecoveryControllerBackup._persist(self.attempts._path(**pair,suffix='.user-check-failed.json'),
                    dict(schema_version=1,error_code='recovery_user_check_failed'))
                except Exception:pass
                try:self.attempts.finish(**pair,status='failed',error_code='recovery_user_check_failed')
                except Exception:pass
            raise fail('recovery_user_check_failed','Bound user observation did not verify; entered checks cannot be replayed') from None
