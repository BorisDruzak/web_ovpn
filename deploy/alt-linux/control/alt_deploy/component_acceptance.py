"""Explicit operator attestation; installation never implies functional acceptance."""
import copy
import os
import re

from .ad_directory import fail
from .setup_jobs import service_uid, setup_queue_lock, timestamp
from .setup_plans import digest, private_create, private_read


def _proof(payload):
    identifier = payload['component']['id']
    return {'machine': payload['machine'], 'user': payload['user'], 'computer': payload['computer'],
            'binding': payload['binding'], 'ssh_binding': payload['ssh_binding'],
            'component': payload['component'], 'catalog_sha256': payload['catalog_sha256'],
            'source_sha256': payload['source_sha256'], 'profile': payload['profile'],
            'user_home': payload['observed']['user'], 'facts': payload['observed']['components'],
            'selected': identifier}


def _path(settings, payload):
    return settings.state_root/'setup-functional-acceptance'/(digest(_proof(payload))+'.json')


def project_acceptance(settings, payload):
    result = copy.deepcopy(payload['verification'])
    identifier = payload['component']['id']
    component = result['components'][identifier]
    if component['acceptance_status'] != 'functional_verification_required':
        return result
    path = _path(settings, payload)
    if not path.exists() and not path.is_symlink():
        return result
    record = private_read(path, owner_uid=service_uid(settings))
    if (not isinstance(record, dict) or set(record) != {'schema_version', 'operation', 'machine_uuid',
            'component_id', 'component_version', 'proof_sha256', 'plan_id', 'plan_sha256',
            'accepted_at', 'confirmed_functional', 'operator_uid'}
            or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['operation'] != 'component_functional_acceptance'
            or record['machine_uuid'] != payload['machine']['uuid']
            or record['component_id'] != identifier or record['component_version'] != component['version']
            or record['proof_sha256'] != path.stem or record['confirmed_functional'] is not True
            or type(record['operator_uid']) is not int or record['operator_uid'] < 0
            or not isinstance(record['plan_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', record['plan_sha256'])
            or record['plan_id'] != 'setup-component-'+record['plan_sha256']):
        raise fail('component_acceptance_invalid', 'Retained functional acceptance is invalid')
    timestamp(record['accepted_at'])
    component.update(acceptance_status='accepted', operator_action=None)
    result['operator_action_required'] = result['reboot_required'] or any(
        c.get('operator_action') is not None for c in result['components'].values() if c['status'] != 'not_selected')
    return result


def accept(service, plan_id, sha256, *, confirmed):
    if confirmed is not True:
        raise fail('component_functional_confirmation_required', 'Confirm the completed real user workflow explicitly')
    with setup_queue_lock(service.settings):
        payload = service.validate(plan_id, sha256)
        identifier = payload['component']['id']
        from .component_verification import package_health_ready
        if (payload['action'] != 'noop' or not package_health_ready(payload['observed'])
                or payload['component']['verification']['functional_verification_required'] is not True):
            raise fail('component_acceptance_blocked', 'Functional acceptance requires a fresh technically compliant component')
        path = _path(service.settings, payload)
        record = {'schema_version': 1, 'operation': 'component_functional_acceptance',
                  'machine_uuid': payload['machine']['uuid'], 'component_id': identifier,
                  'component_version': payload['component']['version'], 'proof_sha256': path.stem,
                  'plan_id': plan_id, 'plan_sha256': sha256, 'accepted_at': service.clock().isoformat(),
                  'confirmed_functional': True, 'operator_uid': os.geteuid()}
        try:
            private_create(path, record)
        except FileExistsError:
            project_acceptance(service.settings, payload)
        return {'schema_version': 2, 'operation': 'component_acceptance', 'machine_uuid': record['machine_uuid'],
                'component_id': identifier, 'component_version': record['component_version'],
                'acceptance_status': 'accepted', 'proof_sha256': path.stem}
