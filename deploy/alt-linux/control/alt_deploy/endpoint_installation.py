"""Validate the protected installation correlation carried in a component plan."""

import re
from uuid import UUID

from .ad_directory import fail

_UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
_ASSIGNMENT = re.compile(rf'inventory-(?P<asset>{_UUID})-(?P<machine>{_UUID})-[0-9a-f]{{32}}')


def installation_matches_machine(installation_id, machine_uuid):
    match = _ASSIGNMENT.fullmatch(installation_id) if isinstance(installation_id, str) else None
    return bool(match and match['machine'] == machine_uuid and UUID(match['asset']).int and UUID(match['machine']).int)


def validate_inventory_installation(component_id, machine_uuid, installation_id):
    from .component_catalog import ENDPOINT_AGENT_COMPONENT

    if component_id != ENDPOINT_AGENT_COMPONENT:
        if installation_id is not None:
            raise fail('endpoint_installation_assignment_invalid', 'Installation assignment is scoped to Endpoint Agent')
        return
    if not installation_matches_machine(installation_id, machine_uuid):
        raise fail('endpoint_installation_assignment_invalid', 'Endpoint Agent requires the assignment for this machine')
