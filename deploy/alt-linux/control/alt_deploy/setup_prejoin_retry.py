"""Evidence for a new plan after a confirmed pre-join upgrade timeout.

No replay, reset, history rewrite, or assignment deletion. The new immutable
plan retains the previous binding and hashes its closed execution evidence.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime

from .ad_directory import fail
from .configure import historical_setup_request
from .setup_plans import SetupPlanStore, digest, private_read, private_read_bytes


def prejoin_retry_evidence(settings, binding, machine, user, ou_identity, observed, computer):
    snapshot = {'uuid': machine.uuid, 'hostname': machine.hostname, 'ip': machine.ip,
                'registration_sha256': digest(machine.raw)}
    return historical_prejoin_retry_evidence(settings.state_root, binding, snapshot, user,
                                            ou_identity, observed, computer)


def historical_prejoin_retry_evidence(root, binding, machine, user, ou_identity, observed, computer):
    """Revalidate closed evidence against an immutable machine snapshot.

    This historical read is not a fresh absence/process probe or execution
    authorization. Normal Setup separately supplies its live observations.
    """
    try:
        run_id = binding['run_id']
        if binding['result'] != 'failed' or not re.fullmatch(r'setup-run-[0-9a-f]{32}', run_id):
            raise ValueError
        paths = {'run': root/'setup-runs'/(run_id+'.json')}
        raw_run = private_read_bytes(paths['run'])
        run = private_read(paths['run'])
        if (type(run.get('schema_version')) is not int or run.get('schema_version') != 1 or run.get('run_id') != run_id or
                run.get('machine_uuid') != machine['uuid'] or run.get('status') != 'failed' or
                run.get('partial_failure') is not True or run.get('configuration_result_unavailable') is not True or
                run.get('error', {}).get('code') not in ('domain_join_timeout', 'setup_upgrade_timeout')):
            raise ValueError
        config_id = run['configuration_run_id']
        if not re.fullmatch(r'[0-9a-f]{32}', config_id):
            raise ValueError
        created = datetime.fromisoformat(run['created_at'])
        finished = datetime.fromisoformat(run['finished_at'])
        if created.tzinfo is None or finished.tzinfo is None or finished < created:
            raise ValueError
        # Validate the original plan at the original apply instant, never replay it.
        plan = SetupPlanStore(root, clock=lambda: created).load(run['plan_id'], run['plan_sha256'])
        old = plan['payload']
        request = historical_setup_request(old, expected_uuid=machine['uuid'])
        if (any(binding.get(k) != v for k, v in old['binding'].items()) or
                old['machine'] != machine or
                any(old['user'].get(k) != user.get(k) for k in ('object_guid', 'object_sid', 'login', 'upn')) or
                old['user'].get('state') != 'enabled' or user.get('state') != 'enabled' or
                old['ou_identity'] != ou_identity or old['computer'].get('exists') is not False or
                old['computer'].get('objects') != [] or computer.get('exists') is not False or computer.get('objects') != [] or
                any(old['observed'].get(k) for k in ('domain', 'trust', 'sssd', 'computer_identity')) or
                any(observed.get(k) for k in ('domain', 'trust', 'sssd', 'computer_identity'))):
            raise ValueError
        config = root/'configure-runs'/config_id
        result_path = config/'result.json'
        if result_path.exists() or result_path.is_symlink():
            raise ValueError
        paths.update(plan=root/'setup-plans'/(run['plan_id']+'.json'), request=config/'request.json', log=config/'ansible.log')
        raw = {k: private_read_bytes(p) for k, p in paths.items()}
        if raw['run'] != raw_run or private_read(paths['request']) != request.to_dict():
            raise ValueError
        if old.get('engine_schema_version') == 2:
            from types import SimpleNamespace
            from .setup_events import SetupEventStore
            from .setup_jobs import SetupJobRepository
            import pwd
            settings = SimpleNamespace(state_root=root, jobs_dir=root/'jobs',
                                       service_user=pwd.getpwuid(root.stat().st_uid).pw_name)
            candidates = [j for j in SetupJobRepository(settings).list() if j.request['operation'] == 'full_setup'
                          and j.request['plan'] == plan]
            if len(candidates) != 1 or candidates[0].state != 'unknown_requires_review':
                raise ValueError
            job = candidates[0]
            outcome = private_read(job.job_dir/'execution.json')
            events = SetupEventStore(settings)._read(job)
            tasks = [e for e in events if e['type'].startswith('task_')]
            if (outcome.get('legacy_error_run_id') != run_id or not tasks
                    or tasks[-1]['component_id'] != 'domain.ready'
                    or tasks[-1]['stage'] not in ('upgrade', 'download', 'transaction')
                    or any(e['stage'] == 'domain_join' or e['component_id'] not in ('domain.ready', 'system.base') for e in tasks)):
                raise ValueError
            # Preserve original log hashes while also sealing every safe event.
            for path in sorted((job.job_dir/'events').glob('*.json')):
                raw['event_'+path.stem] = private_read_bytes(path)
        else:
            log = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw['log'].decode('utf-8'))
            labels = [line for line in log.splitlines() if line.startswith('TASK [')]
            if (not labels or not labels[-1].startswith('TASK [prejoin_upgrade :') or
                    any(line.startswith('TASK [domain_join :') for line in labels)):
                raise ValueError
        return {'failed_run_id': run_id, 'configuration_run_id': config_id,
                'binding_sha256': digest(binding),
                'evidence_sha256': {k: hashlib.sha256(v).hexdigest() for k, v in raw.items()}}
    except Exception as exc:
        raise fail('setup_previous_run_unresolved', 'Previous setup is not proven to have stopped safely before join') from exc
