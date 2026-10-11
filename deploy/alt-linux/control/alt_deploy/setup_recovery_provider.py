"""One GUID-only machine-password Modify; not exposed as an operator command.

Concrete fixed prewrite/fresh-state producers remain mandatory dependencies.
Without them this provider refuses before any mutation. LDAP success is only
directory-password evidence, never a trust-recovered or Setup-success receipt.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from pathlib import Path

from .ad_directory import fail
from .ad_transport import bounded_run
from .locking import exclusive_lock
from .setup_plans import digest, private_create, private_read
from .setup_recovery import RecoveryAttemptStore, RecoveryPlanStore, _pair, _sync_directory
from .setup_recovery_credential import RecoveryCredentialStore, RecoveryVaultCodec
from .setup_runtime import source_fingerprint

PROVIDER = 'guid_only_unicodepwd_v1'


class RecoveryPasswordProvider:
    def __init__(self, settings, *, directory=None, credentials=None, fresh_check=None,
                 prewrite=None, runner=None, fingerprint=None, clock=None):
        self.settings = settings
        self.directory = directory
        self.credentials = credentials or RecoveryCredentialStore(settings.state_root, codec=RecoveryVaultCodec(settings))
        self.fresh_check, self.prewrite = fresh_check, prewrite
        self.runner = runner or bounded_run
        self.fingerprint = fingerprint or (lambda: source_fingerprint(settings.ansible_project_dir, Path(__file__).parent))
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.plans = RecoveryPlanStore(settings.state_root, clock=self.clock)
        self.attempts = RecoveryAttemptStore(settings.state_root, clock=self.clock)

    def intent_path(self, failed_run_id, computer_guid):
        return self.attempts._path(**_pair(failed_run_id, computer_guid), suffix='.ad-write-intent.json')

    def _credential_unchanged(self, pair, document, password):
        # Pin ciphertext as well as plaintext: preparation receipts name this
        # exact sealed document, which the later local importer must consume.
        path = self.credentials.path(**pair)
        if (private_read(path) != document
                or self.credentials.open(**pair) != password
                or private_read(path) != document):
            raise ValueError

    def _fresh(self, payload):
        expected = payload['snapshot']
        config = self.directory.transport.config
        if (digest(self.fresh_check(payload)) != digest(expected)
                or self.fingerprint() != expected['prerequisites']['source_sha256']
                or config.auth != 'gssapi' or config.credential_source != 'join-vault'
                or self.directory.transport.minimum_ssf < 128
                or config.uri != expected['computer']['dc']['uri']
                or expected['computer']['dc']['is_writable'] is not True
                or not re.fullmatch(r'ldaps?://[a-z0-9][a-z0-9-]{0,62}\.sosnadmin\.local(?::(?:389|636))?', config.uri)
                or self.directory.inspect_computer(expected['machine']['hostname'], payload['computer_guid']) != expected['computer']):
            raise ValueError

    @staticmethod
    def _preparation(payload, claim, sealed, prepared):
        fields = {'schema_version', 'claim_sha256', 'sealed_sha256', 'snapshot_sha256',
            'controller_backup_verified', 'workstation_backup_verified', 'local_rehearsal_verified',
            'controller_backup_sha256', 'workstation_backup_sha256', 'local_rehearsal_sha256'}
        if (not isinstance(prepared, dict) or set(prepared) != fields
                or type(prepared['schema_version']) is not int or prepared['schema_version'] != 1
                or prepared['claim_sha256'] != digest(claim) or prepared['sealed_sha256'] != sealed['sealed_sha256']
                or prepared['snapshot_sha256'] != digest(payload['snapshot'])
                or any(prepared[name] is not True for name in ('controller_backup_verified', 'workstation_backup_verified', 'local_rehearsal_verified'))
                or any(not isinstance(prepared[name], str) or not re.fullmatch('[0-9a-f]{64}', prepared[name])
                    for name in ('controller_backup_sha256', 'workstation_backup_sha256', 'local_rehearsal_sha256'))):
            raise ValueError

    def write_once(self, plan_id, confirmed_sha):
        if self.directory is None or self.fresh_check is None or self.prewrite is None:
            raise fail('recovery_prewrite_unavailable', 'Reviewed fixed recovery preparation and fresh-state producers are required')
        with exclusive_lock(self.settings.lock_file):
            plan = self.plans.load(plan_id, confirmed_sha)
            payload = plan['payload']
            try:
                fields = {'failed_run_id', 'computer_guid', 'machine_uuid', 'computer_sid',
                          'evidence_sha256', 'execution_available', 'provider', 'snapshot'}
                if (set(payload) != fields or payload['execution_available'] is not True
                        or payload['provider'] != PROVIDER or payload['snapshot']['execution_available'] is not False
                        or any(payload[name] != payload['snapshot'][name] for name in
                            ('failed_run_id', 'computer_guid', 'machine_uuid', 'computer_sid', 'evidence_sha256'))
                        or payload['snapshot']['computer']['object_guid'] != payload['computer_guid']
                        or payload['snapshot']['computer']['object_sid'] != payload['computer_sid']):
                    raise ValueError
                pair = _pair(payload['failed_run_id'], payload['computer_guid'])
            except (ValueError, KeyError, TypeError):
                raise fail('recovery_execution_plan_invalid', 'Recovery requires an explicit executable one-object provider plan') from None
            intent_path = self.intent_path(**pair)
            if intent_path.exists() or intent_path.is_symlink():
                raise fail('recovery_write_already_attempted', 'Directory write was already intended; replay is prohibited')
            identity = self.credentials._reservation(**pair)
            if identity['plan_sha256'] != confirmed_sha:
                raise fail('recovery_execution_plan_invalid', 'Recovery reservation belongs to another plan')
            entered = False
            try:
                self._fresh(payload)
                claim = private_read(self.attempts.claim_path(**pair))
                document = private_read(self.credentials.path(**pair))
                password = self.credentials.open(**pair)
                self._credential_unchanged(pair, document, password)
                sealed = {'claim_sha256': identity['claim_sha256'], 'sealed_sha256': document['sealed_sha256']}
                prepared = self.prewrite(payload, claim, sealed, password)
                self._preparation(payload, claim, sealed, prepared)
                self._fresh(payload)
                self.plans.load(plan_id, confirmed_sha)
                if self.credentials._reservation(**pair) != identity: raise ValueError
                self._credential_unchanged(pair, document, password)
                expected = payload['snapshot']['computer']
                environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LDAPNOINIT': '1'}
                transport = self.directory.transport
                with transport._credentials(environment) as (environment, authentication):
                    if authentication or environment.get('LDAPNOINIT') != '1': raise ValueError
                    self._fresh(payload)
                    self.plans.load(plan_id, confirmed_sha)
                    if self.credentials._reservation(**pair) != identity: raise ValueError
                    self._credential_unchanged(pair, document, password)
                    intent = dict(pair, schema_version=1, status='write_intended', provider=PROVIDER,
                        plan_sha256=confirmed_sha, claim_sha256=identity['claim_sha256'],
                        sealed_sha256=sealed['sealed_sha256'], preparation_sha256=digest(prepared),
                        created_at=self.clock().isoformat())
                    private_create(intent_path, intent)
                    _sync_directory(intent_path.parent)
                    for parent in intent_path.parent.parents: _sync_directory(parent)
                    value = base64.b64encode(('"' + password + '"').encode('utf-16-le')).decode('ascii')
                    ldif = ('dn: <GUID=' + pair['computer_guid'] + '>\nchangetype: modify\n'
                            'replace: unicodePwd\nunicodePwd:: ' + value + '\n-\n\n')
                    command = ['/usr/bin/ldapmodify', '-Q', '-Y', 'GSSAPI', '-O', 'minssf=128',
                               '-o', 'nettimeout=10', '-H', transport.config.uri]
                    # One process and one LDIF record. No continue, referrals,
                    # loop, name fallback, reauthentication replay or retry.
                    self._credential_unchanged(pair, document, password)
                    self.plans.load(plan_id, confirmed_sha)
                    entered = True
                    rc, _, _ = self.runner(command, environment=environment, input_text=ldif, timeout=30)
                    if type(rc) is not int or rc != 0: raise ValueError
                    after = self.directory.inspect_computer(payload['snapshot']['machine']['hostname'], pair['computer_guid'])
                    changed = {'kvno', 'pwd_last_set'}
                    if (set(after) != set(expected) or any(after[key] != value for key, value in expected.items() if key not in changed)
                            or type(after['kvno']) is not int or after['kvno'] != expected['kvno'] + 1
                            or type(after['pwd_last_set']) is not int or after['pwd_last_set'] <= expected['pwd_last_set']):
                        raise ValueError
                    result = dict(pair, schema_version=1, status='directory_password_written',
                        machine_uuid=payload['machine_uuid'], computer_sid=payload['computer_sid'],
                        claim_sha256=identity['claim_sha256'], intent_sha256=digest(intent),
                        sealed_sha256=sealed['sealed_sha256'], kvno=after['kvno'], pwd_last_set=after['pwd_last_set'])
                    private_create(self.attempts._path(**pair, suffix='.ad-write-result.json'), result)
                    _sync_directory(intent_path.parent)
                return result
            except Exception:
                code = 'recovery_write_ambiguous' if entered else 'recovery_write_failed'
                try: self.attempts.finish(**pair, status='ambiguous' if entered else 'failed', error_code=code)
                except Exception: pass
                raise fail(code, 'Recovery directory operation did not produce verified evidence; the attempt remains excluded') from None
