"""Read-only provenance checks for an initial, partially failed domain join.

History inspection does not authorize a reset, prove ownership of the current
AD object, extend the original plan TTL or resolve the failed Setup binding.
All paths derive from validated protected IDs, never operator-supplied paths.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime
from pathlib import Path

from .ad_directory import DOMAIN, fail
from .configure import ConfigureRequest, _read_configure_result, historical_setup_request
from .errors import ControlError
from .setup_assignments import DomainAssignmentStore
from .setup_plans import SetupPlanStore, decode_state_bytes, digest, private_read_bytes
from .setup_recovery import RUN_RE, evidence_document


def _timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError
    return parsed


def _guid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError
    return value


class RecoveryHistoryStore:
    def __init__(self, state_root: Path):
        self.root = state_root

    def _partial_local_revision(self, payload, binding, plan_created):
        """Read one separately proven local recovery before this new first join."""
        import pwd
        from types import SimpleNamespace
        from .setup_partial_local_continuation import load_resolution
        if any(key in payload for key in ('prejoin_retry', 'recovery_resolution')): raise ValueError
        settings = SimpleNamespace(state_root=self.root, jobs_dir=self.root/'jobs',
                                   service_user=pwd.getpwuid(self.root.stat().st_uid).pw_name)
        document = load_resolution(settings, payload['partial_local_resolution'], archival=True)
        closed = document['closed']
        prior = payload['existing_assignment']
        identity = {key: binding.get(key) for key in closed['original']['binding']}
        metadata = {'schema_version', 'revision', 'run_id', 'date', 'result'}
        if set(binding) not in (set(identity), set(identity) | metadata): raise ValueError
        if (prior != closed['binding'] or type(prior.get('schema_version')) is not int or prior['schema_version'] != 1
                or type(prior.get('revision')) is not int or prior['revision'] != 1
                or payload['machine'] != closed['machine'] or identity != closed['original']['binding']
                or payload['ou_identity'] != closed['original']['ou_identity']
                or any(payload['user'].get(k) != closed['original']['user'].get(k)
                       for k in ('object_guid', 'object_sid', 'upn', 'login'))
                or not _timestamp(closed['run']['finished_at']) <= _timestamp(document['result']['finished_at']) <= plan_created):
            raise ValueError
        expected = dict(identity, schema_version=1, revision=1, run_id=closed['failed_run_id'],
                        date=closed['run']['created_at'], result='failed')
        if prior != expected: raise ValueError
        return 2

    def _prejoin_revision(self, payload, binding, plan_created):
        """Admit exactly one closed initial upgrade timeout before this join.

        The original five-file recovery envelope remains unchanged. Its plan
        already seals the prior evidence hashes; revalidate those protected
        files on every live history read, without consuming or rewriting them.
        """
        from .setup_prejoin_retry import historical_prejoin_retry_evidence
        prior = payload['existing_assignment']
        proof = payload['prejoin_retry']
        if (not isinstance(prior, dict) or type(prior.get('schema_version')) is not int
                or prior['schema_version'] != 1 or type(prior.get('revision')) is not int
                or prior['revision'] != 1):
            raise ValueError
        verified = historical_prejoin_retry_evidence(
            self.root, prior, payload['machine'], payload['user'], payload['ou_identity'],
            payload['observed'], payload['computer'])
        if proof != verified:
            raise ValueError
        raw_run = private_read_bytes(self.root/'setup-runs'/(verified['failed_run_id']+'.json'))
        if hashlib.sha256(raw_run).hexdigest() != verified['evidence_sha256']['run']:
            raise ValueError
        old_run = decode_state_bytes(raw_run)
        if _timestamp(old_run['finished_at']) > plan_created:
            raise ValueError
        expected = dict(binding, schema_version=1, revision=1, run_id=old_run['run_id'],
                        date=old_run['created_at'], result='failed')
        if prior != expected:
            raise ValueError
        raw_plan = private_read_bytes(self.root/'setup-plans'/(old_run['plan_id']+'.json'))
        if hashlib.sha256(raw_plan).hexdigest() != verified['evidence_sha256']['plan']:
            raise ValueError
        old_payload = decode_state_bytes(raw_plan)['payload']
        if old_payload['existing_assignment'] is not None or 'prejoin_retry' in old_payload:
            raise ValueError
        old_index = decode_state_bytes(private_read_bytes(
            self.root/'setup-plan-runs'/(old_run['plan_id']+'.json')))
        if old_index != {'run_id': old_run['run_id']}:
            raise ValueError
        return 2

    def load(self, failed_run_id):
        try:
            if not isinstance(failed_run_id, str) or not RUN_RE.fullmatch(failed_run_id):
                raise ValueError
            raw = {'run': private_read_bytes(self.root / 'setup-runs' / (failed_run_id + '.json'))}
            run = decode_state_bytes(raw['run'])
            machine_uuid = _guid(run['machine_uuid'])
            config_id = run['configuration_run_id']
            if (type(run['schema_version']) is not int or run['schema_version'] != 1
                    or run['run_id'] != failed_run_id or run['status'] != 'failed'
                    or run['partial_failure'] is not True
                    or 'configuration_result_unavailable' in run
                    or not isinstance(config_id, str) or not re.fullmatch('[0-9a-f]{32}', config_id)):
                raise ValueError
            created = _timestamp(run['created_at'])
            finished = _timestamp(run['finished_at'])
            if finished < created:
                raise ValueError
            # Validate hash/schema/TTL at the original creation instant. This
            # historical lookup is never passed to normal Setup apply.
            plan_id, sha = run['plan_id'], run['plan_sha256']
            if not isinstance(plan_id, str) or not re.fullmatch('setup-[0-9a-f]{64}', plan_id):
                raise ValueError
            raw['plan'] = private_read_bytes(self.root / 'setup-plans' / (plan_id + '.json'))
            stored_plan = decode_state_bytes(raw['plan'])
            historical_clock = _timestamp(stored_plan['created_at'])
            plan = SetupPlanStore(self.root, clock=lambda: historical_clock).load(plan_id, sha)
            # Detect replacement between reading evidence and envelope checking.
            if plan != stored_plan or not historical_clock <= created < _timestamp(plan['expires_at']):
                raise ValueError
            payload = plan['payload']
            machine, user = payload['machine'], payload['user']
            request = historical_setup_request(payload, expected_uuid=machine_uuid)
            _guid(user['object_guid'])
            if (not isinstance(user['object_sid'], str)
                    or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', user['object_sid'])
                    or user['state'] != 'enabled' or machine['uuid'] != machine_uuid
                    or machine['hostname'] != request.final_hostname
                    or not isinstance(machine['registration_sha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', machine['registration_sha256'])
                    or request.profile != 'standard-domain' or request.hostname_mode != 'verify'
                    or request.domain != DOMAIN or request.realm != 'SOSNADMIN.LOCAL'
                    or request.workgroup != 'SOSNADM'
                    or request.assigned_domain_user != user['upn'] or request.domain_test_user != user['upn']
                    or request.computer_ou != payload['computer_ou']
                    or payload['ou_identity']['dn'] != request.computer_ou
                    or 'domain_join' not in payload['changes']):
                raise ValueError
            _guid(payload['ou_identity']['object_guid'])
            observed, computer = payload['observed'], payload['computer']
            if (observed['uuid'] != machine_uuid or observed['hostname'] != request.final_hostname
                    or observed['domain'] != '' or observed['trust'] is not False
                    or observed['local_duplicate'] is not False
                    or any(type(observed[key]) is not bool for key in ('sssd', 'user_lookup', 'home_exists'))
                    or computer['hostname'] != request.final_hostname
                    or computer['exists'] is not False or computer['objects'] != []):
                raise ValueError
            binding = DomainAssignmentStore.identity_binding(machine_uuid, user, request.computer_ou,
                                                            request.software_profile, request.remote_access_profile)
            if payload['binding'] != binding:
                raise ValueError
            revision = 1
            if payload['existing_assignment'] is not None:
                revision = (self._partial_local_revision(payload, binding, historical_clock)
                            if 'partial_local_resolution' in payload else self._prejoin_revision(payload, binding, historical_clock))
            elif 'prejoin_retry' in payload or 'partial_local_resolution' in payload:
                raise ValueError
            raw['index'] = private_read_bytes(self.root / 'setup-plan-runs' / (plan_id + '.json'))
            if decode_state_bytes(raw['index']) != {'run_id': failed_run_id}:
                raise ValueError
            raw['binding'] = private_read_bytes(self.root / 'domain-assignments' / (machine_uuid + '.json'))
            assignment = decode_state_bytes(raw['binding'])
            expected_assignment = dict(binding, schema_version=1, revision=revision,
                                       run_id=failed_run_id, date=run['created_at'], result='failed')
            # Strict validated assignment schema rejects bool-as-int metadata.
            validated = DomainAssignmentStore(self.root).get(machine_uuid)
            if assignment != validated or assignment != expected_assignment:
                raise ValueError
            raw['configuration_result'] = private_read_bytes(
                self.root / 'configure-runs' / config_id / 'result.json')
            result = _read_configure_result(decode_state_bytes(raw['configuration_result']), request)
            if (result.get('schema_version') != 1 or result.get('status') != 'failed'
                    or result.get('phase') != 'domain_join' or result.get('recovered') is not False
                    or result.get('error', {}).get('code') != 'configure_critical_phase_failed'
                    or run.get('error', {}).get('code') != 'domain_join_failed'
                    or run['result'] != result or run['reboot_required'] is not result['reboot_required']):
                raise ValueError
            preserved = evidence_document(raw)
            identity = {'failed_run_id': failed_run_id, 'configuration_run_id': config_id,
                        'original_plan_id': plan_id, 'original_plan_sha256': sha,
                        'machine_uuid': machine_uuid, 'hostname': request.final_hostname,
                        'employee_guid': user['object_guid'], 'employee_sid': user['object_sid'],
                        'login': user['login'], 'computer_ou': request.computer_ou,
                        'software_profile': request.software_profile,
                        'remote_access_profile': request.remote_access_profile,
                        'started_at': run['created_at'], 'finished_at': run['finished_at'],
                        'evidence_sha256': digest(preserved)}
            return {'identity': identity, 'raw_files': raw}
        except (ControlError, KeyError, TypeError, ValueError, AttributeError, OverflowError):
            raise fail('recovery_history_invalid', 'Recovery requires consistent protected evidence of one initial failed domain join') from None
