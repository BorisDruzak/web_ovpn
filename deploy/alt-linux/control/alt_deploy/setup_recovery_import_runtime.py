"""Fixed, permanent-attempt SSH importer; final execution approval is caller-owned.

Inputs are derived from RecoveryPostwriteState, never operator-supplied result,
password, worker, path or command. No CLI, directory writer or service startup.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import shlex

from .ad_directory import fail
from .setup_recovery_source_stdin import build_source_stdin, MAX_REPLY_BYTES
from .setup_recovery_process import bounded_bundle_run
from .locking import exclusive_lock
from .setup_plans import canonical, decode_state_bytes, digest, private_read
from .setup_recovery import RecoveryAttemptStore, _pair
from .setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
from .setup_recovery_controller_backup import RecoveryControllerBackup
from .setup_recovery_runtime import _read_source
from . import setup_recovery_backup as backup
from . import setup_recovery_import as importer
from . import setup_recovery_native as native
from . import setup_recovery_rehearsal as rehearsal
from . import setup_recovery_services as services

NAMES=('probe','backup','native','process','rehearsal','keytab','import','services')


class RecoveryImportRuntime(RecoveryWorkstationBackupRuntime):
    def __init__(self, settings, *, postwrite, runner=None):
        super().__init__(settings,runner=bounded_bundle_run if runner is None else runner,credentials=postwrite.service_gate.preparation.credentials)
        self.postwrite=postwrite
        self.attempts=RecoveryAttemptStore(settings.state_root)

    def _sources(self):
        directory=Path(__file__).parent;owner=Path(__file__).lstat().st_uid
        return [_read_source(directory/('setup_recovery_'+name+'.py'),owner=owner) for name in NAMES]

    @staticmethod
    def _backup_receipt(bound):
        result={key:bound[key] for key in ('schema_version','failed_run_id','computer_guid','claim_sha256',
            'machine_uuid','snapshot_sha256','source_sha256')}
        pair={key:bound[key] for key in ('failed_run_id','computer_guid')}
        result['backup_id']='backup-'+digest(pair)
        result['manifest_sha256']=digest(dict(schema_version=1,request=bound,backup_id=result['backup_id']))
        return result

    def _context(self,plan_id,confirmed_sha):
        context=self.postwrite.load(plan_id,confirmed_sha);machine=context['machine'];payload=context['payload']
        pair=_pair(payload['failed_run_id'],payload['computer_guid'])
        address=str(ipaddress.ip_address(machine.ip));record=context['preparation'];sources=self._sources()
        bound=self.backup_request(machine,**pair,facts=payload['snapshot']['workstation_facts']['snapshot'])
        receipt=self._backup_receipt(bound)
        if record['backup_request']!=bound or record['workstation_backup']!=receipt:raise ValueError
        meta=native.validate_metadata(record['rehearsal_metadata']);dc=payload['snapshot']['computer']['dc']
        for key,value in dict(hostname=machine.hostname,realm='sosnadmin.local',workgroup='SOSNADM',
                domain_guid=dc['domain_guid'],domain_sid=dc['domain_sid'],dc_hostname=dc['dns_hostname']).items():
            if meta[key]!=value:raise ValueError
        original=dict(schema_version=1,backup_request=bound,backup_receipt=receipt,metadata=meta,
            credential_sha256=context['credential_document']['sealed_sha256'],source_sha256=digest(sources[:5]))
        rehearsal._request(original,backup=backup,native=native)
        if record['local_rehearsal']!=rehearsal._receipt(original,backup=backup):raise ValueError
        saved=context['services_preparation']
        service_request=dict(schema_version=1,backup_request=bound,backup_receipt=receipt,services=saved['services'],
            services_sha256=saved['services_sha256'],source_sha256=digest([sources[i] for i in (0,1,3,6,7)]))
        services._request(service_request,backup=backup)
        if context['services_receipt']!=services._receipt(service_request,backup=backup):raise ValueError
        request=dict(schema_version=1,rehearsal_request=original,rehearsal_receipt=record['local_rehearsal'],
            directory_result=context['directory_result'],source_sha256=digest(sources))
        importer._request(request,backup=backup,rehearsal=rehearsal,native=native)
        protected={key:value for key,value in context.items() if key!='machine'}
        return dict(pair=pair,address=address,request=request,service_request=service_request,
            service_receipt=context['services_receipt'],protected=protected,sources=sources)

    @staticmethod
    def _receipt(request,result):
        files=result['files']
        if not isinstance(files,dict) or set(files)!=set(importer.FILES):raise ValueError
        for path,value in files.items():
            original=request['rehearsal_request']['backup_request']['facts']['files'][path]
            if (set(value)!={'present','sha256','size','uid','gid','mode'} or value['present'] is not True
                    or any(type(value[key]) is not int for key in ('size','uid','gid','mode'))
                    or not 0<value['size']<=2097152 or value['uid']!=0 or value['mode']!=0o600
                    or value['gid']!=original.get('gid',0)
                    or not isinstance(value['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',value['sha256'])):
                raise ValueError
        if (result!=importer._receipt(request,files,backup=backup) or type(result['schema_version']) is not int
                or result['trust_verified'] is not False):raise ValueError

    @staticmethod
    def _script(action,sources,source_sha,wire_hashes):
        if action not in ('install','verify') or len(sources)!=len(NAMES):raise ValueError
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
'''
        script+='    if set(wire) != '+repr({'request','service_request','service_receipt','password'} if action=='install' else {'request','service_request','service_receipt'})+': raise ValueError()\n'
        script+='    request = wire["request"]\n'
        script+='    if request["source_sha256"] != '+repr(source_sha)+': raise ValueError()\n'
        script+='    if any(backup.digest(wire[key]) != value for key,value in '+repr(wire_hashes)+'.items()): raise ValueError()\n'
        script+='''    expected = wire["service_request"]["services"]
    for unit in services._active(wire["service_request"]):
        expected = services._stopped(expected, unit)
    def guarded_runner(command, **options):
        if command == ['/usr/bin/systemctl', 'is-active', 'sssd', 'smb', 'nmb', 'winbind']:
            if services.snapshot(backup=backup, probe=probe, collect=probe.collect, runner=process.bounded_recovery_run) != expected:
                raise ValueError()
        return process.bounded_recovery_run(command, **options)
'''
        if action=='install':
            script+='''    if services.verify(wire["service_request"], backup=backup, probe=probe, collect=probe.collect, runner=process.bounded_recovery_run) != wire["service_receipt"]:
        raise ValueError()
    result = importer.install_once(request, wire["password"], backup=backup, native=native, keytab=keytab,
        rehearsal=rehearsal, probe=probe, collect=probe.collect, runner=guarded_runner)
'''
        else:
            script+='''    importer._inactive(guarded_runner)
    result = importer.verify(request, backup=backup, probe=probe, collect=probe.collect)
'''
        script+='''    print(json.dumps(result, sort_keys=True))
except Exception:
    print(json.dumps({"schema_version": 1, "error_code": "recovery_local_import_failed"}))
    sys.exit(1)
'''
        return script

    def install_once(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('install',plan_id,confirmed_sha)

    def verify(self,plan_id,confirmed_sha):
        with exclusive_lock(self.settings.lock_file):return self._operate('verify',plan_id,confirmed_sha)

    def _operate(self,action,plan_id,confirmed_sha):
        entered=False;pair=None
        try:
            context=self._context(plan_id,confirmed_sha);pair=context['pair'];request=context['request']
            intent_path=self.attempts._path(**pair,suffix='.local-import-intent.json')
            result_path=self.attempts._path(**pair,suffix='.local-import-result.json')
            intended=dict(schema_version=1,plan_id=plan_id,plan_sha256=confirmed_sha,request_sha256=digest(request),
                directory_result_sha256=digest(request['directory_result']),services_receipt_sha256=digest(context['service_receipt']))
            wire={key:context[key] for key in ('request','service_request','service_receipt')}
            if action=='install':
                if any(path.exists() or path.is_symlink() for path in (intent_path,result_path)):raise ValueError
                entered=True
                RecoveryControllerBackup._persist(intent_path,intended)
                wire['password']=self.credentials.open(**pair)
            else:
                if private_read(intent_path)!=intended:raise ValueError
            if self._context(plan_id,confirmed_sha)!=context or private_read(intent_path)!=intended:raise ValueError
            hashes={key:digest(context[key]) for key in ('request','service_request','service_receipt')}
            worker=self._script(action,context['sources'],request['source_sha256'],hashes)
            script,encoded=build_source_stdin(worker,wire)
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10',
                '-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),'-i',str(self.settings.private_key_file),
                'ansible@'+context['address'],'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)]
            rc,out,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},input_text=encoded,timeout=360)
            if type(rc) is not int or rc!=0 or not isinstance(out,str) or len(out.encode())>MAX_REPLY_BYTES:raise ValueError
            result=decode_state_bytes(out.encode('utf-8'));self._receipt(request,result)
            if self._context(plan_id,confirmed_sha)!=context or private_read(intent_path)!=intended:raise ValueError
            if action=='install':RecoveryControllerBackup._persist(result_path,result)
            elif private_read(result_path)!=result:raise ValueError
            return result
        except Exception:
            if entered and pair is not None:
                try:self.attempts.finish(**pair,status='failed',error_code='recovery_local_import_failed')
                except Exception:pass
            raise fail('recovery_local_import_failed','Bound local import did not verify; retained attempts cannot be replayed') from None
