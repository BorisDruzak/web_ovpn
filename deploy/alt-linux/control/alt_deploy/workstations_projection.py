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
              'history', 'history_total', 'queue_position')


def fields(value, allowed):
    if not isinstance(value, dict):
        raise fail('workstations_projection_invalid', 'Controller projection has an invalid shape')
    return {name: copy.deepcopy(value[name]) for name in allowed if name in value}


def public_machine(value):
    result = fields(value, MACHINE_FIELDS)
    assignment = value.get('domain_assignment')
    result['domain_assignment'] = fields(assignment, ASSIGNMENT_FIELDS) if assignment is not None else None
    return result


def _invalid_workflow():
    return fail('workstations_projection_invalid','The public workflow declaration is invalid')


def _phase_components(value):
    if (not isinstance(value,list) or not 1<=len(value)<=256 or len(set(value))!=len(value)
            or any(not isinstance(item,str) or not re.fullmatch('[a-z][a-z0-9_.-]{0,127}',item) for item in value)):
        raise _invalid_workflow()
    return copy.deepcopy(value)


def public_workflow_plan(value):
    from .full_workflow import BUDGETS
    from .final_dns_policy import validate
    from .krfb_runtime import DIRECT_POLICY
    try:
        if (not isinstance(value,dict) or value.get('kind')!='complete_workstation'
                or type(value.get('schema_version')) is not int or value['schema_version']!=1):raise ValueError
        policy=value['policy']
        if (not isinstance(policy,dict) or set(policy)!={'vnc','final_dns'} or policy['vnc']!=DIRECT_POLICY
                or not isinstance(policy['vnc'],dict) or set(policy['vnc'])!=set(DIRECT_POLICY)
                or type(policy['vnc']['port']) is not int
                or not isinstance(policy['final_dns'],dict) or set(policy['final_dns'])!={'servers'}):raise ValueError
        dns=validate(policy['final_dns']['servers'])
        if dns!=policy['final_dns']:raise ValueError
        phases=value['phases']
        if not isinstance(phases,list) or len(phases)!=3:raise ValueError
        rows=[];components=[]
        for (name,budget),row in zip(BUDGETS.items(),phases):
            if (not isinstance(row,dict) or set(row)!={'id','component_ids','budget_seconds'} or row['id']!=name
                    or type(row['budget_seconds']) is not int or row['budget_seconds']!=budget):raise ValueError
            selected=_phase_components(row['component_ids']);components+=selected
            rows.append({'id':name,'component_ids':selected,'budget_seconds':budget})
        if len(set(components))!=len(components):raise ValueError
        return {'kind':'complete_workstation','phases':rows,'policy':{'vnc':copy.deepcopy(DIRECT_POLICY),'final_dns':dns}}
    except Exception:raise _invalid_workflow() from None


def public_workflow_job(value):
    from .full_workflow import BUDGETS
    from .setup_phases import PHASE_CODES
    from .setup_waiting import WAIT_CODES
    from .setup_jobs import STATES
    try:
        if (not isinstance(value,dict) or set(value)!={'schema_version','kind','phase','waiting_reason','phases'}
                or type(value['schema_version']) is not int or value['schema_version']!=1
                or value['kind']!='complete_workstation' or value['phase'] not in BUDGETS
                or value['waiting_reason'] is not None and value['waiting_reason'] not in WAIT_CODES|{'workflow_final_verification_unavailable'}
                or not isinstance(value['phases'],dict) or set(value['phases'])!=set(BUDGETS)):raise ValueError
        phases={};components=[]
        for name,budget in BUDGETS.items():
            row=value['phases'][name]
            if (not isinstance(row,dict) or set(row)!={'state','component_ids','budget_seconds','error_code','admission_sequence'}
                    or row['state'] not in STATES|{'pending'} or type(row['budget_seconds']) is not int or row['budget_seconds']!=budget
                    or row['error_code'] is not None and row['error_code'] not in PHASE_CODES
                    or row['admission_sequence'] is not None and (type(row['admission_sequence']) is not int or row['admission_sequence']<1)):raise ValueError
            selected=_phase_components(row['component_ids']);components+=selected
            phases[name]=dict(row,component_ids=selected)
        if len(set(components))!=len(components):raise ValueError
        return dict(value,phases=phases)
    except Exception:raise _invalid_workflow() from None


def public_job(value):
    result=fields(value,JOB_FIELDS)
    if 'workflow' in value:result['workflow']=public_workflow_job(value['workflow'])
    return result


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
    preflight = payload.get('preflight')
    if isinstance(preflight, dict):
        value['preflight'] = {key: preflight[key] for key in ('ready', 'required') if type(preflight.get(key)) is bool}
        code = preflight.get('error_code')
        if isinstance(code, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,127}', code):
            value['preflight']['error_code'] = code
    if 'computer_ou' in payload:
        value['ou_id'] = digest(payload['computer_ou'])
    if 'workflow' in payload:
        value['workflow']=public_workflow_plan(payload['workflow'])
    return value


def project(operation, data):
    if operation == 'machines.list':
        return {'machines': [public_machine(row) for row in data['machines']],
                'total': data['total'], 'next_offset': data.get('next_offset'), 'generation': data.get('generation')}
    if operation == 'machines.show':
        return {'machine': public_machine(data['machine'])}
    if operation == 'directory.search':
        return {'schema_version': 1, 'users': [fields(row, USER_FIELDS) for row in data['users']], 'truncated': data['truncated']}
    if operation in ('plans.create', 'component_plans.create'):
        return public_plan(data)
    if operation == 'assignments.show':
        return {'assignment': fields(data['assignment'], ASSIGNMENT_FIELDS) if data['assignment'] is not None else None}
    if operation in ('jobs.status', 'jobs.verify'):
        return dict(fields(data, ('schema_version', 'status', 'operation')), job=public_job(data['job']))
    if operation == 'jobs.list':
        return dict(fields(data, ('schema_version', 'status', 'operation', 'total', 'next_offset')),
                    jobs=[public_job(row) for row in data['jobs']])
    if operation == 'plans.apply':
        return fields(data, ('schema_version', 'operation', 'job_id', 'machine_uuid', 'state', 'plan_id', 'plan_sha256'))
    # Other cases are constructed exclusively by the typed backend (catalog,
    # source snapshots, safe native events, queue summary and receipt status).
    return copy.deepcopy(data)
