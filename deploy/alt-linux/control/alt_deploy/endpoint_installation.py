"""Validate the protected installation correlation carried in a component plan."""

import re
from uuid import UUID

from .ad_directory import fail
from .component_catalog import ENDPOINT_AGENT_COMPONENT

_UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
_ASSIGNMENT = re.compile(rf'inventory-(?P<asset>{_UUID})-(?P<machine>{_UUID})-[0-9a-f]{{32}}')


def validate_inventory_installation(component_id, machine_uuid, installation_id):
    if component_id != ENDPOINT_AGENT_COMPONENT:
        if installation_id is not None:
            raise fail('endpoint_installation_assignment_invalid', 'Installation assignment is scoped to Endpoint Agent')
        return
    match = _ASSIGNMENT.fullmatch(installation_id) if isinstance(installation_id, str) else None
    if not match or match['machine'] != machine_uuid or UUID(match['asset']).int == 0:
        raise fail('endpoint_installation_assignment_invalid', 'Endpoint Agent requires the assignment for this machine')
