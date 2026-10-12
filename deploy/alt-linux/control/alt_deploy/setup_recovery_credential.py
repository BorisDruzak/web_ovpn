"""Durably sealed machine credential bound to an existing recovery attempt.

No AD or workstation writer. No CLI arguments accept credential material.
The Vault key exists only in protected source storage and sealed memory FDs;
the new machine password is retained on disk only inside Ansible ciphertext.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import os
import re
import secrets
import signal
import subprocess
import tempfile
import uuid
from datetime import datetime
from threading import Thread

from .ad_directory import fail
from .setup_plans import (canonical, decode_state_bytes, digest, private_create,
                          private_read, private_read_bytes)
from .setup_recovery import (RecoveryAttemptStore, RecoveryPlanStore, _pair,
                             _sync_directory, evidence_document)
from .setup_recovery_probe import _signature
from .vault import VaultHealthChecker

MAX_VAULT_BYTES = 16384


def _ciphertext(value):
    if (not isinstance(value, str) or len(value) > MAX_VAULT_BYTES
            or not re.fullmatch(r'\$ANSIBLE_VAULT;1\.1;AES256\n(?:[0-9a-f]{1,80}\n)+', value)):
        raise ValueError
    return value


def _run_vault(command, *, input_text, password_fd):
    with tempfile.TemporaryDirectory(prefix='alt-recovery-vault-config-') as directory:
        os.chmod(directory, 0o700)
        config = directory + '/ansible.cfg'
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(b'[defaults]\n')
        return _vault_process(command, input_text=input_text, password_fd=password_fd,
                              config=config, directory=directory)


def _vault_process(command, *, input_text, password_fd, config, directory):
    if not isinstance(input_text, str) or len(input_text.encode('utf-8')) > MAX_VAULT_BYTES:
        raise ValueError
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8',
        'ANSIBLE_CONFIG': config, 'PYTHONSAFEPATH': '1', 'PYTHONNOUSERSITE': '1',
        'PYTHONDONTWRITEBYTECODE': '1'}
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=False, env=environment, pass_fds=(password_fd,),
        start_new_session=True, cwd=directory)
    captured, bad = [b'', b''], []
    def kill():
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
    def read(index, stream):
        try:
            captured[index] = stream.read(MAX_VAULT_BYTES + 1)
            if len(captured[index]) > MAX_VAULT_BYTES:
                bad.append(True); kill()
        except OSError:
            bad.append(True); kill()
        finally: stream.close()
    readers = [Thread(target=read, args=(index, stream), daemon=True)
        for index, stream in enumerate((process.stdout, process.stderr))]
    for reader in readers: reader.start()
    # Input writing is threaded too: a stalled child cannot defeat the timeout.
    def write():
        try: process.stdin.write(input_text.encode('utf-8'))
        except (BrokenPipeError, OSError): bad.append(True)
        finally: process.stdin.close()
    writer = Thread(target=write, daemon=True); writer.start()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        kill(); process.wait(); bad.append(True)
    finally:
        for thread in (writer, *readers): thread.join(timeout=2)
        if any(thread.is_alive() for thread in (writer, *readers)):
            kill(); bad.append(True)
    if bad or process.returncode:
        raise ValueError
    return captured[0].decode('utf-8')


class RecoveryVaultCodec:
    def __init__(self, settings, *, checker=None, runner=None):
        self.checker = checker or VaultHealthChecker(settings)
        self.runner = runner or _run_vault

    def _operation(self, operation, value):
        fd = None
        try:
            if self.checker._service_uid() != os.geteuid():
                raise ValueError
            path = self.checker.password_file
            before = path.lstat()
            raw = private_read_bytes(path)
            if not raw or len(raw) > 4096 or _signature(path.lstat()) != _signature(before):
                raise ValueError
            fd = os.memfd_create('alt-recovery-vault-key', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw): offset += os.write(fd, raw[offset:])
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            command = ['/usr/bin/ansible-vault', operation, '--output', '-',
                       '--vault-password-file', '/proc/self/fd/' + str(fd)]
            return self.runner(command, input_text=value, password_fd=fd)
        except Exception:
            raise fail('recovery_vault_failed', 'Recovery credential sealing could not be verified') from None
        finally:
            if fd is not None: os.close(fd)

    def seal(self, plaintext):
        try: return _ciphertext(self._operation('encrypt', plaintext))
        except Exception:
            raise fail('recovery_vault_failed', 'Recovery credential sealing could not be verified') from None

    def unseal(self, ciphertext):
        try: return self._operation('decrypt', _ciphertext(ciphertext))
        except Exception:
            raise fail('recovery_vault_failed', 'Recovery credential sealing could not be verified') from None


class RecoveryCredentialStore:
    @classmethod
    def for_settings(cls,settings,*,codec):
        return cls(settings.state_root,codec=codec,attempts=RecoveryAttemptStore.for_settings(settings))

    def __init__(self, state_root, *, codec,attempts=None):
        self.attempts = attempts or RecoveryAttemptStore(state_root)
        self.codec = codec

    def path(self, failed_run_id, computer_guid):
        return self.attempts._path(**_pair(failed_run_id, computer_guid), suffix='.credential.json')

    def _ready_path(self, failed_run_id, computer_guid):
        return self.attempts._path(**_pair(failed_run_id, computer_guid), suffix='.credential-verified.json')

    def _reservation(self, failed_run_id, computer_guid):
        pair = _pair(failed_run_id, computer_guid)
        try:
            terminal = self.attempts._path(**pair, suffix='.receipt.json')
            if terminal.exists() or terminal.is_symlink(): raise ValueError
            claim = private_read(self.attempts.claim_path(**pair))
            fields = {'schema_version', 'status', 'failed_run_id', 'computer_guid', 'plan_id',
                      'plan_sha256', 'evidence_sha256', 'created_at'}
            if (set(claim) != fields or type(claim['schema_version']) is not int or claim['schema_version'] != 1
                    or claim['status'] != 'reserved' or any(claim[key] != value for key, value in pair.items())):
                raise ValueError
            reserved = datetime.fromisoformat(claim['created_at'])
            plan = RecoveryPlanStore(self.attempts.plans.root.parent, clock=lambda: reserved).load(
                claim['plan_id'], claim['plan_sha256'])
            self.attempts.assert_plan_context(plan)
            preserved = private_read(self.attempts.evidence_path(**pair))
            raw = {key: base64.b64decode(value['bytes_b64'], validate=True) for key, value in preserved['files'].items()}
            if (evidence_document(raw) != preserved or digest(preserved) != claim['evidence_sha256']
                    or plan['payload']['evidence_sha256'] != claim['evidence_sha256']
                    or any(plan['payload'][key] != value for key, value in pair.items())):
                raise ValueError
            machine = plan['payload']['machine_uuid']; sid = plan['payload']['computer_sid']
            if (str(uuid.UUID(machine)) != machine or not isinstance(sid, str)
                    or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', sid)):
                raise ValueError
            return dict(pair, schema_version=1, claim_sha256=digest(claim), plan_sha256=claim['plan_sha256'],
                        evidence_sha256=claim['evidence_sha256'], machine_uuid=machine, computer_sid=sid)
        except Exception:
            raise fail('recovery_credential_invalid', 'Recovery credential requires an unchanged reserved attempt and protected evidence') from None

    def create(self, failed_run_id, computer_guid):
        identity = self._reservation(failed_run_id, computer_guid)
        path = self.path(failed_run_id, computer_guid)
        if path.exists() or path.is_symlink():
            raise fail('recovery_credential_exists', 'Recovery credential cannot be regenerated or replaced')
        try:
            password = 'Aa9!' + secrets.token_urlsafe(48)
            plaintext = canonical(dict(identity, machine_password=password)).decode('ascii')
            ciphertext = _ciphertext(self.codec.seal(plaintext))
            document = dict(identity, ciphertext=ciphertext,
                            sealed_sha256=hashlib.sha256(ciphertext.encode('ascii')).hexdigest())
            private_create(path, document)
            _sync_directory(path.parent)
            for parent in path.parent.parents: _sync_directory(parent)
            if self._decode(failed_run_id, computer_guid, identity, private_read(path)) != password: raise ValueError
            ready = {'schema_version': 1, 'claim_sha256': identity['claim_sha256'],
                     'sealed_sha256': document['sealed_sha256'], 'document_sha256': digest(document)}
            private_create(self._ready_path(failed_run_id, computer_guid), ready)
            _sync_directory(path.parent)
            return {'claim_sha256': identity['claim_sha256'], 'sealed_sha256': document['sealed_sha256']}
        except Exception:
            # Credential preparation failed before any provider write. Close
            # the reserved attempt append-only; never remove its exclusion.
            # If storage itself is unavailable, the original claim still
            # prohibits every new apply and no caller receives success.
            try:
                self.attempts.finish(failed_run_id, computer_guid, status='failed',
                                     error_code='recovery_credential_failed')
            except Exception:
                pass
            raise fail('recovery_credential_failed', 'Recovery credential was not durably verified; the attempt remains excluded') from None

    def open(self, failed_run_id, computer_guid):
        identity = self._reservation(failed_run_id, computer_guid)
        try:
            document = private_read(self.path(failed_run_id, computer_guid))
            ready = private_read(self._ready_path(failed_run_id, computer_guid))
            expected = {'schema_version': 1, 'claim_sha256': identity['claim_sha256'],
                        'sealed_sha256': document['sealed_sha256'], 'document_sha256': digest(document)}
            if ready != expected or type(ready['schema_version']) is not int: raise ValueError
            _sync_directory(self.path(failed_run_id, computer_guid).parent)
            return self._decode(failed_run_id, computer_guid, identity, document)
        except Exception:
            raise fail('recovery_credential_invalid', 'Recovery credential integrity or identity could not be verified') from None

    def _decode(self, failed_run_id, computer_guid, identity, document):
        try:
            if (set(document) != set(identity) | {'ciphertext', 'sealed_sha256'}
                    or any(document[key] != value for key, value in identity.items())
                    or hashlib.sha256(_ciphertext(document['ciphertext']).encode('ascii')).hexdigest() != document['sealed_sha256']):
                raise ValueError
            decrypted = decode_state_bytes(self.codec.unseal(document['ciphertext']).encode('utf-8'))
            if (set(decrypted) != set(identity) | {'machine_password'}
                    or any(decrypted[key] != value for key, value in identity.items())
                    or not isinstance(decrypted['machine_password'], str)
                    or not re.fullmatch(r'Aa9![a-zA-Z0-9_-]{64}', decrypted['machine_password'])):
                raise ValueError
            if self._reservation(failed_run_id, computer_guid) != identity: raise ValueError
            return decrypted['machine_password']
        except Exception:
            raise fail('recovery_credential_invalid', 'Recovery credential integrity or identity could not be verified') from None
