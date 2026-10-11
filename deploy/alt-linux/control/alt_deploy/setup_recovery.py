"""Protected recovery preparation state; no directory or workstation writer.

A durable claim excludes all subsequent attempts for the same original failed
run and immutable computer GUID, independently of plan IDs or terminal status.
Historical bytes are copied separately; original Setup records are never edited.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .ad_directory import fail
from .errors import ControlError
from .setup_plans import (MAX_STATE_BYTES, SetupPlanStore, canonical,
                          decode_state_bytes, digest, private_create, private_read)

EVIDENCE_LABELS = frozenset({'plan', 'run', 'index', 'binding', 'configuration_result'})
RUN_RE = re.compile(r'^setup-run-[0-9a-f]{32}$')
SHA_RE = re.compile(r'^[0-9a-f]{64}$')


class RecoveryPlanStore(SetupPlanStore):
    prefix = 'recovery-'
    directory = 'setup-recovery-plans'


def evidence_document(raw_files):
    try:
        if not isinstance(raw_files, dict) or set(raw_files) != EVIDENCE_LABELS:
            raise ValueError
        files = {}
        for label, raw in raw_files.items():
            decode_state_bytes(raw)
            files[label] = {'sha256': hashlib.sha256(raw).hexdigest(),
                            'bytes_b64': base64.b64encode(raw).decode('ascii')}
        result = {'schema_version': 1, 'files': files}
        if len(canonical(result)) + 1 > MAX_STATE_BYTES:
            raise ValueError
        return result
    except (ControlError, ValueError, TypeError) as exc:
        raise fail('recovery_evidence_invalid', 'Recovery requires bounded, valid protected historical evidence') from exc


def _pair(failed_run_id, computer_guid):
    try:
        if (not isinstance(failed_run_id, str) or not RUN_RE.fullmatch(failed_run_id)
                or not isinstance(computer_guid, str)
                or str(uuid.UUID(computer_guid)) != computer_guid):
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise fail('recovery_identity_invalid', 'Recovery requires the original failed run and canonical computer GUID') from exc
    return {'failed_run_id': failed_run_id, 'computer_guid': computer_guid}


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RecoveryAttemptStore:
    def __init__(self, state_root: Path, *, clock=None):
        self.root = state_root / 'setup-recovery-attempts'
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.plans = RecoveryPlanStore(state_root, clock=self.clock)

    def _path(self, failed_run_id, computer_guid, suffix):
        return self.root / (digest(_pair(failed_run_id, computer_guid)) + suffix)

    def claim_path(self, failed_run_id, computer_guid):
        return self._path(failed_run_id, computer_guid, '.claim.json')

    def evidence_path(self, failed_run_id, computer_guid):
        return self._path(failed_run_id, computer_guid, '.evidence.json')

    def reserve(self, plan_id, confirmed_sha, raw_files):
        plan = self.plans.load(plan_id, confirmed_sha)
        payload = plan['payload']
        pair = _pair(payload.get('failed_run_id'), payload.get('computer_guid'))
        preserved = evidence_document(raw_files)
        if payload.get('evidence_sha256') != digest(preserved):
            raise fail('recovery_evidence_drift', 'Historical recovery evidence changed; no attempt was reserved')
        claim = dict(pair, schema_version=1, status='reserved', plan_id=plan_id,
                     plan_sha256=confirmed_sha, evidence_sha256=digest(preserved),
                     created_at=self.clock().isoformat())
        try:
            # Exclusive create is the cross-plan/cross-process exclusion. An
            # incomplete or corrupt existing claim still blocks every retry.
            private_create(self.claim_path(**pair), claim)
        except FileExistsError:
            raise fail('recovery_attempt_reserved', 'This failed run and computer already have a recovery attempt; retry is prohibited') from None
        except OSError:
            raise fail('recovery_state_failed', 'Recovery reservation could not be written safely') from None
        try:
            _sync_directory(self.root)
            # private_create may have initialized previously absent ancestors.
            # Persist the whole directory chain before authorizing any external
            # mutation, so loss of the first directory cannot erase exclusion.
            for parent in self.root.parents:
                _sync_directory(parent)
            private_create(self.evidence_path(**pair), preserved)
            _sync_directory(self.root)
        except (OSError, ControlError):
            # Never remove the exclusion after a storage failure. The caller
            # receives no successful reservation and must perform no mutation.
            raise fail('recovery_state_failed', 'Recovery evidence could not be preserved; the attempt remains excluded') from None
        return claim

    def finish(self, failed_run_id, computer_guid, *, status, error_code=None, verification=None):
        pair = _pair(failed_run_id, computer_guid)
        if (status not in ('failed', 'ambiguous', 'trust_recovered')
                or (error_code is not None and (not isinstance(error_code, str)
                    or not re.fullmatch(r'[a-z][a-z0-9_]{0,95}', error_code)))):
            raise fail('recovery_receipt_invalid', 'Recovery receipt requires a bounded safe classification')
        claim = private_read(self.claim_path(**pair))
        preserved = private_read(self.evidence_path(**pair))
        expected_fields = {'failed_run_id', 'computer_guid', 'schema_version', 'status',
                           'plan_id', 'plan_sha256', 'evidence_sha256', 'created_at'}
        if (set(claim) != expected_fields or any(claim.get(key) != value for key, value in pair.items())
                or type(claim['schema_version']) is not int or claim['schema_version'] != 1
                or claim['status'] != 'reserved' or digest(preserved) != claim['evidence_sha256']):
            raise fail('recovery_receipt_invalid', 'Recovery reservation or historical evidence is invalid')
        try:
            reserved_at = datetime.fromisoformat(claim['created_at'])
            if reserved_at.tzinfo is None:
                raise ValueError
            # Validate the original plan at the durable reservation time. A
            # completed operation may finish after its planning TTL; this does
            # not authorize a new attempt or replay an expired plan.
            historical_plans = RecoveryPlanStore(self.plans.root.parent, clock=lambda: reserved_at)
            plan = historical_plans.load(claim['plan_id'], claim['plan_sha256'])
            if (any(plan['payload'].get(key) != value for key, value in pair.items())
                    or plan['payload'].get('evidence_sha256') != claim['evidence_sha256']):
                raise ValueError
            if status == 'trust_recovered':
                fields = {'machine_uuid', 'computer_guid', 'computer_sid', 'trust',
                          'keytab', 'sssd', 'user_lookup', 'local_duplicate'}
                if (error_code is not None or not isinstance(verification, dict)
                        or set(verification) != fields
                        or verification['machine_uuid'] != plan['payload'].get('machine_uuid')
                        or str(uuid.UUID(verification['machine_uuid'])) != verification['machine_uuid']
                        or verification['computer_guid'] != pair['computer_guid']
                        or verification['computer_sid'] != plan['payload'].get('computer_sid')
                        or not isinstance(verification['computer_sid'], str)
                        or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', verification['computer_sid'])
                        or any(verification[key] is not True for key in ('trust', 'keytab', 'sssd', 'user_lookup'))
                        or verification['local_duplicate'] is not False):
                    raise ValueError
            elif verification is not None:
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, ControlError):
            raise fail('recovery_receipt_invalid', 'Recovery proof or pinned reservation plan is invalid') from None
        receipt = dict(pair, schema_version=1, status=status, error_code=error_code,
                       claim_sha256=digest(claim), evidence_sha256=claim['evidence_sha256'],
                       verification=verification,
                       finished_at=self.clock().isoformat())
        try:
            private_create(self._path(**pair, suffix='.receipt.json'), receipt)
            _sync_directory(self.root)
        except (OSError, ControlError):
            raise fail('recovery_receipt_invalid', 'Recovery terminal receipt cannot be replaced or written safely') from None
        return receipt
