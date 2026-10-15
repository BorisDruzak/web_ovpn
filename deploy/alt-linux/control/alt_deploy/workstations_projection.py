"""Allowlisted projections for the Workstations gateway, never raw state files."""
from __future__ import annotations

import copy
import re

from .ad_directory import fail
from .setup_plans import digest

MACHINE_FIELDS = ('uuid', 'hostname', 'ip', 'mac', 'registered_at', 'registration_state', 'status')
USER_FIELDS = ('object_guid', 'object_sid', 'login', 'upn', 'display_name', 'department', 'state')
ASSIGNMENT_FIELDS = ('machine_uuid', 'object_guid', 'object_sid', 'login', 'software_profile',
                     'remote_access_profile', 'revision', 'run_id', 'date', 'result')
JOB_FIELDS = ('job_id', 'operation', 'machine_uuid', 'state', 'recorded_state', 'stage', 'plan_id', 'plan_sha256',
              'created_at', 'updated_at', 'claimed', 'catalog_version', 'profile', 'catalog_sha256', 'source_sha256',
              'components', 'error_code', 'reboot_required', 'operator_action_required', 'recommended_action',
              'history', 'history_total')


def fields(value, allowed):
    if not isinstance(value, dict):
        raise fail('workstations_projection_invalid', 'Controller projection has an invalid shape')
    return {name: copy.deepcopy(value[name]) for name in allowed if name in value}


def public_plan(plan):
    payload = plan['payload']
    components = [payload['component']] if 'component' in payload else payload.get('components', [])
    value = fields(plan, ('plan_id', 'sha256', 'created_at', 'expires_at'))
    value.update(machine=fields(payload.get('machine', {}), MACHINE_FIELDS),
                 user=fields(payload.get('user', {}), USER_FIELDS),
                 components=[fields(item, ('id', 'version')) for item in components],
                 profile=fields(payload.get('profile', {}), ('id', 'version', 'name')),
                 action=payload.get('action'), changes=payload.get('changes', []),
                 warnings=payload.get('warnings', []), deferred_actions=payload.get('deferred_actions', []))
    verification = payload.get('verification', payload.get('component_verification', {}))
    rows = verification.get('components', verification)
    value['verification'] = {key: fields(row, ('version', 'status', 'installation_status', 'acceptance_status', 'operator_action'))
                             for key, row in rows.items() if re.fullmatch(r'[a-z][a-z0-9_.-]{0,127}', key) and isinstance(row, dict)}
    if 'computer_ou' in payload:
        value['ou_id'] = digest(payload['computer_ou'])
    return value


def project(operation, data):
    if operation == 'machines.list':
        return {'machines': [fields(row, MACHINE_FIELDS) for row in data['machines']],
                'total': data['total'], 'next_offset': data.get('next_offset')}
    if operation == 'machines.show':
        return {'machine': fields(data['machine'], MACHINE_FIELDS)}
    if operation == 'directory.search':
        return {'schema_version': 1, 'users': [fields(row, USER_FIELDS) for row in data['users']], 'truncated': data['truncated']}
    if operation in ('plans.create', 'component_plans.create'):
        return public_plan(data)
    if operation == 'assignments.show':
        return {'assignment': fields(data['assignment'], ASSIGNMENT_FIELDS) if data['assignment'] is not None else None}
    if operation in ('jobs.status', 'jobs.verify'):
        return dict(fields(data, ('schema_version', 'status', 'operation')), job=fields(data['job'], JOB_FIELDS))
    if operation == 'jobs.list':
        return dict(fields(data, ('schema_version', 'status', 'operation', 'total', 'next_offset')),
                    jobs=[fields(row, JOB_FIELDS) for row in data['jobs']])
    if operation == 'plans.apply':
        return fields(data, ('schema_version', 'operation', 'job_id', 'machine_uuid', 'state', 'plan_id', 'plan_sha256'))
    # Other cases are constructed exclusively by the typed backend (catalog,
    # source snapshots, safe native events, queue summary and receipt status).
    return copy.deepcopy(data)
