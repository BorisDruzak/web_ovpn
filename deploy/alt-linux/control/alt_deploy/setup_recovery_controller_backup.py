"""Attempt-bound native controller backup preparation; no recovery writer.

Preparation runs before the password provider owns the lifecycle lock. The
read-only native eligibility check takes only its nonblocking operation lock.
"""
from __future__ import annotations

import re

from .ad_directory import fail
from .setup_plans import decode_state_bytes, digest, private_create, private_read
from .setup_recovery import RecoveryAttemptStore, _pair, _sync_directory
from .setup_recovery_credential import RecoveryCredentialStore
from .setup_recovery_process import bounded_recovery_run

_BACKUP = re.compile(r'backup-\d{8}T\d{6}Z-[0-9a-f]{8}')
_SHA = re.compile(r'[0-9a-f]{64}')

# Deliberate native JSON boundary: the controller package has no runtime import
# dependency on the separately installed backup package. Contract tests bind the
# two validators; never persist native messages, details, commands or stderr.
_REASONS={'UNKNOWN','archive_command_failed','archive_command_unavailable','stderr_limit','deadline_exceeded',
    'source_changed','controller_sources_changed','archive_publication_failed','archive_hash_failed','archive_destination_failed','bundle_publication_failed'}
_COMPONENTS={'runtime','systemd','ansible','controller_state','registration_state','deployment_assets'}
_SIGNALS={'file_changed','permission_denied','no_space','cannot_stat','file_removed'}

def _safe_diagnostic(value):
    if (not isinstance(value,dict) or set(value)!={'component','reason','tar_returncode','zstd_returncode','signals'}
            or value['component'] is not None and (not isinstance(value['component'],str) or value['component'] not in _COMPONENTS)
            or not isinstance(value['reason'],str) or value['reason'] not in _REASONS
            or any(v is not None and (type(v) is not int or not -255<=v<=255) for v in (value['tar_returncode'],value['zstd_returncode']))
            or not isinstance(value['signals'],list) or len(value['signals'])>5
            or any(not isinstance(v,str) or v not in _SIGNALS for v in value['signals'])
            or value['signals']!=sorted(set(value['signals']))):raise ValueError
    return dict(value,signals=list(value['signals']))

class _NativeFailure(ValueError):
    def __init__(self,summary):self.summary=summary;super().__init__('Native backup failed')


class RecoveryControllerBackup:
    def __init__(self, settings, *, credentials=None, fresh_check=None, runner=None):
        self.failure_root=settings.state_root/'setup-recovery-backup-failures'
        self.attempts = RecoveryAttemptStore.for_settings(settings)
        self.credentials = credentials or RecoveryCredentialStore(settings.state_root, codec=None,attempts=self.attempts)
        self.fresh_check = fresh_check
        self.runner = runner or bounded_recovery_run

    def path(self, payload, suffix):
        return self.attempts._path(**_pair(payload['failed_run_id'], payload['computer_guid']),
                                   suffix='.controller-backup'+suffix)

    def failure_diagnostic_path(self,payload):
        key=dict(pair=_pair(payload['failed_run_id'],payload['computer_guid']),context=self.attempts.context)
        return self.failure_root/(digest(key)+'.json')

    def _identity(self, payload):
        if self.fresh_check is None or self.fresh_check(payload) != payload['snapshot']: raise ValueError
        pair = _pair(payload['failed_run_id'], payload['computer_guid'])
        identity = self.credentials._reservation(**pair)
        document = private_read(self.credentials.path(**pair))
        ready = private_read(self.credentials._ready_path(**pair))
        if (set(document) != set(identity) | {'ciphertext', 'sealed_sha256'}
                or any(document[key] != value for key,value in identity.items())
                or not isinstance(document['sealed_sha256'],str) or not _SHA.fullmatch(document['sealed_sha256'])
                or ready != dict(schema_version=1,claim_sha256=identity['claim_sha256'],
                    sealed_sha256=document['sealed_sha256'],document_sha256=digest(document))):
            raise ValueError
        return dict(identity, snapshot_sha256=digest(payload['snapshot']),
                    sealed_sha256=document['sealed_sha256'],document_sha256=digest(document))

    def _native(self, operation, backup_id=None):
        if operation not in ('guard','create','verify','rehearse','rehearse-status'): raise ValueError
        command=['/usr/bin/sudo','-n','/usr/local/sbin/alt-deploy-backup',operation]
        if operation in ('verify','rehearse','rehearse-status'):
            if not isinstance(backup_id,str) or not _BACKUP.fullmatch(backup_id): raise ValueError
            command.append(backup_id)
        elif backup_id is not None: raise ValueError
        # Native rehearsal invokes ansible-core, which requires a UTF-8 locale.
        try:
            rc,output,_=self.runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C.UTF-8'},
                                    input_text='',timeout=360)
        except Exception:
            raise _NativeFailure(dict(schema_version=1,operation=operation,native_returncode=None,error_code='UNKNOWN',diagnostic=None)) from None
        if type(rc) is not int or rc != 0:
            summary=dict(schema_version=1,operation=operation,native_returncode=rc if type(rc) is int and -255<=rc<=255 else None,error_code='UNKNOWN',diagnostic=None)
            try:
                error=decode_state_bytes(output.encode('utf-8'))
                if error['status']!='error':raise ValueError
                value=error['error'];code=value['code']
                if code in {'backup_component_failed','backup_preflight_failed','backup_integrity_failed','backup_rehearsal_failed','backup_lock_busy','backup_path_unsafe','backup_not_root','backup_not_found','backup_usage','restore_secret_mismatch'}:
                    summary['error_code']=code
                    if 'diagnostic' in value:summary['diagnostic']=_safe_diagnostic(value['diagnostic'])
            except Exception:pass
            raise _NativeFailure(summary)
        result=decode_state_bytes(output.encode('utf-8'))
        if result.get('status') != 'ok': raise ValueError
        expected={'guard':'control_plane_allowed','create':'backup_created','verify':'backup_verified',
                  'rehearse':'backup_rehearsed','rehearse-status':'backup_rehearsed'}
        fields={'status','result'}
        if operation != 'guard':
            fields |= {'backup_id','manifest_sha256'}
            if not isinstance(result.get('backup_id'),str) or not _BACKUP.fullmatch(result['backup_id']): raise ValueError
            if not isinstance(result.get('manifest_sha256'),str) or not _SHA.fullmatch(result['manifest_sha256']): raise ValueError
            if backup_id is not None and result['backup_id'] != backup_id: raise ValueError
        if operation in ('create','verify'):
            fields |= {'component_count','services_restored' if operation=='create' else 'evidence_written'}
            if type(result.get('component_count')) is not int or result['component_count'] != 6: raise ValueError
            if result.get('services_restored' if operation=='create' else 'evidence_written') is not True: raise ValueError
        elif operation=='rehearse':
            fields |= {'check_count','rehearsal_passed'}
            if type(result.get('check_count')) is not int or result['check_count'] != 11 or result.get('rehearsal_passed') is not True: raise ValueError
        elif operation=='rehearse-status':
            fields.add('verification_sha256')
            if not isinstance(result.get('verification_sha256'),str) or not _SHA.fullmatch(result['verification_sha256']): raise ValueError
        if set(result) != fields or result['result'] != expected[operation]: raise ValueError
        return result

    @staticmethod
    def _persist(path,document):
        private_create(path,document)
        _sync_directory(path.parent)
        for parent in path.parent.parents: _sync_directory(parent)
        if private_read(path) != document: raise ValueError

    def prepare(self,payload):
        try:
            identity=self._identity(payload)
            intent=self.path(payload,'.intent.json')
            # Persist exclusion before the first external operation. This is
            # included in the native controller-state snapshot, not regenerated.
            self._persist(intent,identity)
        except Exception:
            raise fail('recovery_controller_backup_invalid','Controller backup requires an exact fresh reservation and an unused preparation') from None
        try:
            self._native('guard')
            created=self._native('create')
            backup_id=created['backup_id'];manifest=created['manifest_sha256']
            for operation in ('verify','rehearse','rehearse-status'):
                result=self._native(operation,backup_id)
                if result['manifest_sha256'] != manifest: raise ValueError
            self._native('guard')
            if self._identity(payload) != identity or private_read(intent) != identity: raise ValueError
            receipt=dict(identity,backup_id=backup_id,manifest_sha256=manifest,
                         verification_sha256=result['verification_sha256'])
            self._persist(self.path(payload,'.receipt.json'),receipt)
            failed=self.path(payload,'.failed.json')
            if (self._identity(payload) != identity or private_read(intent) != identity
                    or failed.exists() or failed.is_symlink()): raise ValueError
            return receipt
        except Exception as exc:
            if isinstance(exc,_NativeFailure):
                try:self._persist(self.failure_diagnostic_path(payload),dict(schema_version=1,identity=identity,failure=exc.summary))
                except Exception:pass
            try:self._persist(self.path(payload,'.failed.json'),{'schema_version':1,'status':'failed'})
            except Exception:pass
            raise fail('recovery_controller_backup_failed','Native controller backup did not produce verified evidence; preparation remains excluded') from None

    def verify(self,payload):
        try:
            failed=self.path(payload,'.failed.json')
            if failed.exists() or failed.is_symlink(): raise ValueError
            identity=self._identity(payload)
            if private_read(self.path(payload,'.intent.json')) != identity: raise ValueError
            receipt=private_read(self.path(payload,'.receipt.json'))
            if set(receipt) != set(identity)|{'backup_id','manifest_sha256','verification_sha256'}: raise ValueError
            if any(receipt[key] != value for key,value in identity.items()): raise ValueError
            self._native('guard')
            result=self._native('rehearse-status',receipt['backup_id'])
            if any(result[key] != receipt[key] for key in ('backup_id','manifest_sha256','verification_sha256')): raise ValueError
            if self._identity(payload) != identity or private_read(self.path(payload,'.receipt.json')) != receipt: raise ValueError
            if private_read(self.path(payload,'.intent.json')) != identity or failed.exists() or failed.is_symlink(): raise ValueError
            return receipt
        except Exception:
            raise fail('recovery_controller_backup_invalid','Native controller backup eligibility and protected attempt evidence must remain unchanged') from None
