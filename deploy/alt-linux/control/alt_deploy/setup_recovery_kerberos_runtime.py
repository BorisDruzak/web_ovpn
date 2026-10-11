"""Bound one-attempt machine proof transport; execution approval is caller-owned.

No Vault opening, AD write, credential replacement, service start or CLI route.
Verification checks retained proof only and never repeats authentication.
"""
from __future__ import annotations

from pathlib import Path
import re
import shlex

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import canonical,decode_state_bytes,digest,private_read
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_import_runtime import NAMES as IMPORT_NAMES
from .setup_recovery_prepare import _resolve_dc
from .setup_recovery_runtime import _read_source
from . import setup_recovery_backup as backup
from . import setup_recovery_kerberos as kerberos

NAMES=IMPORT_NAMES+('kerberos',)


class RecoveryKerberosRuntime:
    def __init__(self,*,import_runtime,runner=None,resolver=None):
        self.import_runtime=import_runtime;self.settings=import_runtime.settings
        self.attempts=import_runtime.attempts;self.runner=runner or import_runtime.runner
        self.resolver=resolver or _resolve_dc

    def _sources(self):
        path=Path(__file__).parent/'setup_recovery_kerberos.py'
        return self.import_runtime._sources()+[_read_source(path,owner=Path(__file__).lstat().st_uid)]

    def _context(self,plan_id,confirmed_sha):
        bound=self.import_runtime._context(plan_id,confirmed_sha);pair=bound['pair']
        request=bound['request']
        intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=confirmed_sha,request_sha256=digest(request),
            directory_result_sha256=digest(request['directory_result']),services_receipt_sha256=digest(bound['service_receipt']))
        if private_read(self.attempts._path(**pair,suffix='.local-import-intent.json'))!=intended:raise ValueError
        result=private_read(self.attempts._path(**pair,suffix='.local-import-result.json'))
        self.import_runtime._receipt(request,result)
        meta=request['rehearsal_request']['metadata']
        if self.resolver(meta['dc_hostname'])!=meta['dc_address']:raise ValueError
        sources=self._sources()
        if sources[:8]!=bound['sources']:raise ValueError
        proof=dict(schema_version=1,import_request=request,import_receipt=result,source_sha256=digest(sources))
        kerberos._request(proof,backup=backup)
        # DNS and source reads may take time. Revalidate their original protected
        # inputs afterwards, then end with the complete deployment fingerprint
        # and a current-time plan load, without another resolver/transport call.
        if (self.import_runtime._context(plan_id,confirmed_sha)!=bound or self._sources()!=sources
                or private_read(self.attempts._path(**pair,suffix='.local-import-intent.json'))!=intended
                or private_read(self.attempts._path(**pair,suffix='.local-import-result.json'))!=result):raise ValueError
        postwrite=self.import_runtime.postwrite;payload=bound['protected']['payload']
        if (postwrite.fingerprint()!=payload['snapshot']['prerequisites']['source_sha256']
                or postwrite.service_gate.preparation.plans.load(plan_id,confirmed_sha)['payload']!=payload):raise ValueError
        return dict(pair=pair,address=bound['address'],request=proof,service_request=bound['service_request'],
            service_receipt=bound['service_receipt'],sources=sources,import_context=bound,import_intent=intended)

    @staticmethod
    def _receipt(request,result):
        if (not isinstance(result,dict) or not isinstance(result.get('tools_sha256'),str)
                or not re.fullmatch('[0-9a-f]{64}',result['tools_sha256'])):raise ValueError
        expected=kerberos._receipt(request,{},request['import_request']['rehearsal_request']['metadata'],backup)
        expected['tools_sha256']=result['tools_sha256']
        if result!=expected or type(result['schema_version']) is not int or result['trust_verified'] is not False:raise ValueError

    @staticmethod
    def _script(action,sources,source_sha,wire_hashes):
        script='import json, sys, types\n'
        for name,source in zip(NAMES,sources):
            alias='importer' if name=='import' else name
            script+=alias+'_scope = {"__name__": "fixed_recovery_'+name+'", "__package__": None}\n'
            script+='exec(compile('+repr(source)+', "fixed_recovery_'+name+'", "exec"), '+alias+'_scope)\n'
            script+=alias+' = types.SimpleNamespace(**'+alias+'_scope)\n'
        script+='''def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError()
        result[key] = value
    return result
try:
    raw = sys.stdin.buffer.read(131073)
    if len(raw) > 131072: raise ValueError()
    wire = json.loads(raw, object_pairs_hook=unique)
    if set(wire) != {'request','service_request','service_receipt'}: raise ValueError()
    request = wire['request']
'''
        script+='    if request["source_sha256"] != '+repr(source_sha)+': raise ValueError()\n'
        script+='    if any(backup.digest(wire[key]) != value for key,value in '+repr(wire_hashes)+'.items()): raise ValueError()\n'
        script+='''    expected = wire['service_request']['services']
    for unit in services._active(wire['service_request']):
        expected = services._stopped(expected, unit)
    def guarded_runner(command, **options):
        if command == ['/usr/bin/systemctl', 'is-active', 'sssd', 'smb', 'nmb', 'winbind']:
            if services.snapshot(backup=backup, probe=probe, collect=probe.collect, runner=process.bounded_recovery_run) != expected:
                raise ValueError()
        return process.bounded_recovery_run(command, **options)
'''
        function='prove_once' if action=='prove' else 'verify'
        script+='    result = kerberos.'+function+'(request, backup=backup, importer=importer, probe=probe, native=native, collect=probe.collect, runner=guarded_runner)\n'
        script+='''    print(json.dumps(result, sort_keys=True))
except Exception:
    print(json.dumps({'schema_version':1,'error_code':'recovery_kerberos_failed'}))
    sys.exit(1)
'''
        return script

    def prove_once(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('prove',plan_id,confirmed_sha)

    def verify(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('verify',plan_id,confirmed_sha)

    def _operate(self,action,plan_id,confirmed_sha):
        entered=False;pair=None
        try:
            context=self._context(plan_id,confirmed_sha);pair=context['pair'];request=context['request']
            intent_path=self.attempts._path(**pair,suffix='.kerberos-intent.json')
            result_path=self.attempts._path(**pair,suffix='.kerberos-result.json')
            intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=confirmed_sha,request_sha256=digest(request),
                import_receipt_sha256=digest(request['import_receipt']),services_receipt_sha256=digest(context['service_receipt']))
            if action=='prove':
                if any(path.exists() or path.is_symlink() for path in (intent_path,result_path)):raise ValueError
                entered=True;RecoveryControllerBackup._persist(intent_path,intended)
            else:
                if private_read(intent_path)!=intended:raise ValueError
                self._receipt(request,private_read(result_path))
            wire={key:context[key] for key in ('request','service_request','service_receipt')}
            hashes={key:digest(value) for key,value in wire.items()}
            script=self._script(action,context['sources'],request['source_sha256'],hashes)
            encoded=canonical(wire).decode('utf-8')
            if len(encoded.encode('utf-8'))>131072:raise ValueError
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10',
                '-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),
                'ansible@'+context['address'],'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)]
            if self._context(plan_id,confirmed_sha)!=context or private_read(intent_path)!=intended:raise ValueError
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=encoded,timeout=360)
            if type(rc) is not int or rc!=0:raise ValueError
            result=decode_state_bytes(out.encode('utf-8'));self._receipt(request,result)
            if self._context(plan_id,confirmed_sha)!=context or private_read(intent_path)!=intended:raise ValueError
            if action=='prove':RecoveryControllerBackup._persist(result_path,result)
            elif private_read(result_path)!=result:raise ValueError
            if (self._context(plan_id,confirmed_sha)!=context or private_read(intent_path)!=intended
                    or private_read(result_path)!=result):raise ValueError
            return result
        except Exception:
            if entered and pair is not None:
                try:self.attempts.finish(**pair,status='failed',error_code='recovery_kerberos_failed')
                except Exception:pass
            raise fail('recovery_kerberos_failed','Bound machine proof did not verify; retained attempts cannot be replayed') from None
