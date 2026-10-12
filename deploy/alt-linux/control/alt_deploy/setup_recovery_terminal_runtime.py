"""Exact caller-owned terminal authority and fresh AD continuity transport."""
import copy,shlex
from pathlib import Path
from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import canonical,digest,private_read,decode_state_bytes
from .setup_recovery_runtime import _read_source
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_process import bounded_bundle_run
from . import setup_recovery_terminal as worker,setup_recovery_terminal_wire as wire

def _same(left,right):return canonical(left)==canonical(right)

class RecoveryTerminalRuntime:
    def __init__(self,*,user_runtime,authorization,identity,runner=None):
        if not callable(authorization) or not callable(identity):raise ValueError('Explicit terminal authority and fresh directory identity required')
        self.user_runtime=user_runtime;self.authorization=authorization;self.identity=identity
        self.settings=user_runtime.settings;self.attempts=user_runtime.attempts;self.runner=bounded_bundle_run if runner is None else runner

    def _sources(self):
        return self.user_runtime._sources()+[_read_source(Path(__file__).with_name('setup_recovery_'+n+'.py'),owner=Path(__file__).lstat().st_uid) for n in ('original_policy','policy_baseline','terminal')]

    def _history(self,pair):
        values={}
        for prefix in ('local-import','kerberos','sssd-policy','sssd-start','native-testjoin','user-check'):
            for kind in ('intent','result','failed'):
                suffix='.'+prefix+'-'+kind+'.json';path=self.attempts._path(**pair,suffix=suffix)
                values[suffix]=private_read(path) if path.exists() or path.is_symlink() else None
                if kind=='failed' and values[suffix] is not None:raise ValueError
        return values

    def _context(self,plan_id,sha):
        previous=self.user_runtime;bound=copy.deepcopy(previous._context(plan_id,sha));pair=bound['pair'];sources=self._sources()
        postwrite=previous.native_runtime.startup_runtime.policy_runtime.kerberos_runtime.import_runtime.postwrite
        protected=copy.deepcopy(postwrite._protected(plan_id,sha)[0]);payload=protected['payload'];plans=postwrite.service_gate.preparation.plans
        history=self._history(pair)
        if len(sources)!=len(wire.NAMES) or sources[:14]!=bound['sources']:raise ValueError
        intent_path=self.attempts._path(**pair,suffix='.user-check-intent.json');result_path=self.attempts._path(**pair,suffix='.user-check-result.json');failed=self.attempts._path(**pair,suffix='.user-check-failed.json')
        intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=sha,request_sha256=digest(bound['request']),sources_sha256=digest(bound['sources']),authorization_sha256=digest(bound['authorization']))
        if failed.exists() or failed.is_symlink() or not _same(private_read(intent_path),intended):raise ValueError
        result=private_read(result_path);previous._receipt(bound['request'],result)
        approved=copy.deepcopy(self.authorization(plan_id,sha,digest(sources)));identity=copy.deepcopy(self.identity(plan_id,sha))
        fields={'schema_version','plan_id','plan_sha256','source_sha256','approval_sha256','baseline','effects_sha256','terminal_units','runtime_dependencies','environment_files','credential_cache','daemon_links'}
        if (not isinstance(approved,dict) or set(approved)!=fields or type(approved['schema_version']) is not int or approved['schema_version']!=1
            or approved['plan_id']!=plan_id or approved['plan_sha256']!=sha or approved['source_sha256']!=digest(sources) or not isinstance(identity,dict)):raise ValueError
        request=dict(schema_version=1,user_request=bound['request'],user_receipt=result,baseline=approved['baseline'],effects_sha256=approved['effects_sha256'],source_sha256=digest(sources),approval_sha256=approved['approval_sha256'],identity_sha256=digest(identity),terminal_units=approved['terminal_units'],runtime_dependencies=approved['runtime_dependencies'],environment_files=approved['environment_files'],credential_cache=approved['credential_cache'],daemon_links=approved['daemon_links']);worker._request(request)
        if (self._sources()!=sources or not _same(previous._context(plan_id,sha),bound)):raise ValueError
        # Close all upstream callbacks with final terminal authority/identity,
        # then read only protected local history, source fingerprint and TTL.
        if not _same(self.authorization(plan_id,sha,digest(sources)),approved) or not _same(self.identity(plan_id,sha),identity):raise ValueError
        current_plan=plans.load(plan_id,sha);startup=bound['request']['startup_request']
        if (self._sources()!=sources or not _same(self._history(pair),history) or not _same(postwrite._protected(plan_id,sha)[0],protected)
            or postwrite.fingerprint()!=payload['snapshot']['prerequisites']['source_sha256']
            or not _same(current_plan['payload'],payload) or any(current_plan[k]!=v for k,v in dict(plan_id=plan_id,sha256=sha,created_at=startup['plan_created_at'],expires_at=startup['plan_expires_at']).items())
            or not _same(private_read(intent_path),intended) or not _same(private_read(result_path),result) or failed.exists() or failed.is_symlink()):raise ValueError
        return dict(pair=pair,address=bound['address'],request=request,sources=sources,authorization=approved,identity=identity)

    def _receipt(self,request,result):
        original=request['user_request']['startup_request']['policy_request']['kerberos_request']['import_request']['directory_result']
        fields={'failed_run_id','computer_guid','computer_sid','machine_uuid','kvno','schema_version','status','request_sha256','identity_sha256','invocation_id','main_pid','n_restarts','services_sha256','unit_sha256','trust_tools_sha256','nss_tools_sha256','local_passwd_sha256','employee','uid','gid','native_trust_verified','native_peer_pinning_verified','credential_continuity','temporary_policy_retained','login_verified','online_user_authentication_verified'}
        import re
        if (not isinstance(result,dict) or set(result)!=fields or any(result[k]!=original[k] for k in ('failed_run_id','computer_guid','computer_sid','machine_uuid','kvno'))
            or type(result['schema_version']) is not int or result['schema_version']!=1 or type(result['kvno']) is not int or result['status']!='normal_policy_handoff_succeeded'
            or result['request_sha256']!=digest(request) or result['identity_sha256']!=request['identity_sha256'] or result['employee']!=request['user_request']['employee']
            or result['native_trust_verified'] is not True or any(result[k] is not False for k in ('native_peer_pinning_verified','temporary_policy_retained','login_verified','online_user_authentication_verified'))
            or result['credential_continuity']!='unchanged' or type(result['n_restarts']) is not int or result['n_restarts']!=0
            or any(type(result[k]) is not int or not 1<=result[k]<=4294967294 for k in ('main_pid','uid','gid'))
            or result['main_pid']>2147483647
            or not isinstance(result['invocation_id'],str) or not re.fullmatch('[0-9a-f]{32}',result['invocation_id']) or int(result['invocation_id'],16)==0
            or result['invocation_id']==request['user_request']['startup_receipt']['invocation_id']
            or any(not isinstance(result[k],str) or not re.fullmatch('[0-9a-f]{64}',result[k]) for k in fields if k.endswith('_sha256'))):raise ValueError

    def handoff_once(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('handoff',plan_id,confirmed_sha)

    def verify(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('verify',plan_id,confirmed_sha)

    def _operate(self,action,plan_id,sha):
        entered=False;pair=None
        try:
            context=self._context(plan_id,sha);pair=context['pair'];request=context['request']
            paths={k:self.attempts._path(**pair,suffix='.terminal-'+k+'.json') for k in ('intent','result','failed')}
            if paths['failed'].exists() or paths['failed'].is_symlink():raise ValueError
            intended=dict(schema_version=1,request_sha256=digest(request),sources_sha256=digest(context['sources']),authorization_sha256=digest(context['authorization']),identity_sha256=request['identity_sha256'])
            receipt=None
            if action=='handoff':
                if any(paths[k].exists() or paths[k].is_symlink() for k in ('intent','result')):raise ValueError
            else:
                if not _same(private_read(paths['intent']),intended):raise ValueError
                receipt=private_read(paths['result']);self._receipt(request,receipt)
            script,encoded=wire.build(action,context['sources'],request,receipt=receipt)
            remote='sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)
            if len(remote.encode())>=8192:raise ValueError
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),'ansible@'+context['address'],remote]
            if action=='handoff':entered=True;RecoveryControllerBackup._persist(paths['intent'],intended)
            if not _same(self._context(plan_id,sha),context) or not _same(private_read(paths['intent']),intended) or paths['failed'].exists() or paths['failed'].is_symlink():raise ValueError
            entered=True
            rc,out,_=self.runner(command,environment=dict(worker.ENVIRONMENT),input_text=encoded,timeout=150)
            if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>wire.MAX_REPLY_BYTES:raise ValueError
            result=decode_state_bytes(out.encode());self._receipt(request,result)
            if not _same(self._context(plan_id,sha),context) or not _same(private_read(paths['intent']),intended):raise ValueError
            if action=='handoff':RecoveryControllerBackup._persist(paths['result'],result)
            elif not _same(private_read(paths['result']),result):raise ValueError
            if not _same(self._context(plan_id,sha),context) or not _same(private_read(paths['result']),result) or paths['failed'].exists() or paths['failed'].is_symlink():raise ValueError
            return result
        except Exception:
            if entered and pair is not None:
                try:RecoveryControllerBackup._persist(self.attempts._path(**pair,suffix='.terminal-failed.json'),dict(schema_version=1,status='UNKNOWN',error_code='recovery_terminal_failed'))
                except Exception:pass
                try:self.attempts.finish(**pair,status='failed',error_code='recovery_terminal_failed')
                except Exception:pass
            raise fail('recovery_terminal_failed','Terminal UNKNOWN; entered attempts permanently excluded, no automatic retry or rollback') from None
