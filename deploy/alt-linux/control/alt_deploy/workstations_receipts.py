"""Durable request identities; interrupted controller calls are never replayed."""
from __future__ import annotations

import copy
import re
import uuid
from datetime import datetime, timezone

from .ad_directory import fail
from .errors import ControlError
from .locks import exclusive_lock
from .setup_jobs import fsync_directory
from .setup_plans import canonical, digest, private_create, private_directory, private_read, private_replace


def request_uuid(value):
    try:
        parsed = uuid.UUID(value)
        if not isinstance(value, str) or str(parsed) != value or not parsed.int:
            raise ValueError
        return value
    except (ValueError, TypeError, AttributeError) as exc:
        raise fail('workstations_request_invalid', 'Request identifier must be a canonical UUID') from exc


class GatewayReceiptStore:
    def __init__(self, state_root, *, recover=None):
        self.root = state_root / 'workstations-gateway-receipts'
        self.recover = recover

    def _path(self, request_id):
        return self.root / (request_uuid(request_id) + '.json')

    def _load(self, path):
        record = private_read(path)
        if (record.get('schema_version') != 1 or record.get('request_id') != path.stem
                or record.get('state') not in ('pending', 'successful', 'error', 'unknown')
                or digest(record.get('intent')) != record.get('intent_sha256')):
            raise fail('workstations_receipt_invalid', 'Controller request receipt requires review')
        return record

    def _public(self, record):
        state = 'unknown' if record['state'] == 'pending' else record['state']
        return {'request_id': record['request_id'], 'state': state, 'data': copy.deepcopy(record.get('data')),
                'error_code': 'workstations_request_unresolved' if state == 'unknown' else record.get('error_code')}

    def _recovered(self, record, path):
        if record['state'] in ('pending', 'unknown') and self.recover is not None:
            try:
                data = self.recover(record['intent'])
            except Exception:
                data = None
            if data is not None:
                record.update(state='successful', data=data, error_code=None)
                private_replace(path, record)
                fsync_directory(self.root)
        return self._public(record)

    def status(self, request_id):
        path = self._path(request_id)
        if not path.exists() and not path.is_symlink():
            return {'request_id': request_id, 'state': 'not_found', 'data': None, 'error_code': None}
        # Status must not wait for an executing callback. A proven native claim
        # may resolve a pending receipt, but status itself never writes/replays.
        record = self._load(path)
        if record['state'] in ('pending', 'unknown') and self.recover is not None:
            try:
                data = self.recover(record['intent'])
            except Exception:
                data = None
            if data is not None:
                return {'request_id': request_id, 'state': 'successful', 'data': data, 'error_code': None}
        return self._public(record)

    def execute(self, request_id, intent, operation):
        path = self._path(request_id)
        if not isinstance(intent, dict) or len(canonical(intent)) > 32768:
            raise fail('workstations_request_invalid', 'Request intent exceeds its bound')
        fingerprint = digest(intent)
        private_directory(self.root)
        with exclusive_lock(self.root / (request_id + '.lock')):
            if path.exists() or path.is_symlink():
                record = self._load(path)
                if record['intent_sha256'] != fingerprint:
                    raise fail('workstations_request_conflict', 'Request identifier already belongs to another action')
                return self._recovered(record, path)
            record = {'schema_version': 1, 'request_id': request_id, 'intent': copy.deepcopy(intent),
                      'intent_sha256': fingerprint, 'state': 'pending', 'data': None, 'error_code': None,
                      'created_at': datetime.now(timezone.utc).isoformat()}
            private_create(path, record)
            fsync_directory(self.root)  # Burn the request before the callback.
            try:
                data = operation()
                record.update(state='successful', data=data)
            except ControlError as exc:
                code = exc.code if re.fullmatch(r'(?:ad|setup|component|workstations|directory)_[a-z0-9_]{1,90}', exc.code) else 'workstations_controller_error'
                record.update(state='unknown' if intent.get('operation') == 'plans.apply' else 'error', error_code=code)
                private_replace(path, record)
                fsync_directory(self.root)
                raise fail(code, 'Controller rejected the request; inspect its safe error code') from exc
            except Exception as exc:
                # Keep the original error private; only native admission evidence
                # can resolve an uncertain mutation. No callback retries.
                record.update(state='unknown', error_code='workstations_request_unresolved')
                private_replace(path, record)
                fsync_directory(self.root)
                raise fail('workstations_request_unresolved', 'Request outcome requires receipt or job verification') from exc
            private_replace(path, record)
            fsync_directory(self.root)
            return self._public(record)
