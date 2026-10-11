"""Read-only fresh-state adapter for one exact, unexpired reserved plan.

Public recovery planning retains unconditional claim exclusion.  This internal
adapter does not reserve, create plans, decrypt credentials or perform writes.
"""
from __future__ import annotations

from .ad_directory import fail
from .setup_plans import digest, private_read
from .setup_recovery import _pair
from .setup_recovery_credential import RecoveryCredentialStore
from .setup_recovery_provider import PROVIDER


class RecoveryReservedState:
    def __init__(self, planning, *, credentials=None):
        self.planning = planning
        # Only the existing protected reservation validator is used.  No Vault
        # operation or credential preparation is required for a fresh read.
        self.credentials = credentials or RecoveryCredentialStore(planning.settings.state_root, codec=None)

    def __call__(self, payload):
        try:
            fields = {'failed_run_id', 'computer_guid', 'machine_uuid', 'computer_sid',
                      'evidence_sha256', 'execution_available', 'provider', 'snapshot'}
            if (not isinstance(payload, dict) or set(payload) != fields
                    or payload['execution_available'] is not True or payload['provider'] != PROVIDER
                    or payload['snapshot']['execution_available'] is not False
                    or any(payload[key] != payload['snapshot'][key] for key in
                        ('failed_run_id', 'computer_guid', 'machine_uuid', 'computer_sid', 'evidence_sha256'))):
                raise ValueError
            pair = _pair(payload['failed_run_id'], payload['computer_guid'])
            claim = private_read(self.planning.attempts.claim_path(**pair))
            identity = self.credentials._reservation(**pair)
            def guard():
                if (private_read(self.planning.attempts.claim_path(**pair)) != claim
                        or self.credentials._reservation(**pair) != identity
                        or digest(claim) != identity['claim_sha256']
                        or identity['machine_uuid'] != payload['machine_uuid']
                        or identity['computer_sid'] != payload['computer_sid']
                        or identity['evidence_sha256'] != payload['evidence_sha256']):
                    raise ValueError
                # Load at current time, not reservation time: reserving an old
                # plan does not extend its authorization lifetime.
                plan = self.planning.plans.load(claim['plan_id'], claim['plan_sha256'])
                if plan['payload'] != payload: raise ValueError
                historical = self.planning.history.load(pair['failed_run_id'])
                if historical['identity']['evidence_sha256'] != identity['evidence_sha256']:
                    raise ValueError
                for suffix in ('.ad-write-intent.json', '.ad-write-result.json'):
                    path = self.planning.attempts._path(**pair, suffix=suffix)
                    if path.exists() or path.is_symlink(): raise ValueError
            current = self.planning._snapshot(**pair, guard=guard)
            if digest(current) != digest(payload['snapshot']): raise ValueError
            guard()
            return current
        except Exception:
            raise fail('recovery_reserved_state_invalid', 'The exact reserved plan, history and fresh state must remain unchanged before recovery writing') from None
