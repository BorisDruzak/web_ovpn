"""Validate complete source generations before local reconciliation publication."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone

from ..inventory.netctl_bindings import saved_observation
from ..inventory.netctl_sync import read_current_snapshot

MAX_OBJECTS = 10000
MAX_BYTES = 16 * 1024 * 1024
MAX_AGE = timedelta(minutes=15)


class SourceError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def timestamp(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise SourceError('workstations_source_timestamp_invalid') from None


def valid_uuid(value):
    try:
        parsed = uuid.UUID(value)
        if not isinstance(value, str) or str(parsed) != value or not parsed.int:
            raise ValueError
        return value
    except (ValueError, TypeError, AttributeError):
        raise SourceError('workstations_source_identity_invalid') from None


def validate_payload(name, data, now):
    try:
        if (not isinstance(data, dict) or type(data.get('schema_version')) is not int or data['schema_version'] != 1
                or data.get('complete') is not True or len(json.dumps(data, allow_nan=False).encode()) > MAX_BYTES
                or not isinstance(data.get('generation'), str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,128}', data['generation'])):
            raise SourceError('workstations_source_incomplete')
        observed = timestamp(data.get('generated_at'))
        if not timedelta(0) <= now - observed <= MAX_AGE:
            raise SourceError('workstations_source_stale')
        arrays = {'ad': ('users', 'computers'), 'dns': ('records',), 'controller': ('machines',), 'netctl': ('hosts',)}[name]
        if any(not isinstance(data.get(key), list) for key in arrays) or sum(len(data[key]) for key in arrays) > MAX_OBJECTS:
            raise SourceError('workstations_source_limit')
        seen = set()
        for key in arrays:
            for row in data[key]:
                if not isinstance(row, dict):
                    raise SourceError('workstations_source_incomplete')
                if name in ('ad', 'controller'):
                    identity = valid_uuid(row.get('uuid' if name == 'controller' else 'object_guid'))
                    if identity in seen:
                        raise SourceError('workstations_source_identity_ambiguous')
                    seen.add(identity)
                if name == 'ad':
                    if not isinstance(row.get('object_sid'), str) or not re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+)+', row['object_sid']):
                        raise SourceError('workstations_source_identity_invalid')
                    if row.get('state') not in ('enabled', 'disabled', 'locked', 'expired', 'password_expired', 'unknown'):
                        raise SourceError('workstations_source_identity_invalid')
                if name == 'dns':
                    if row.get('type') not in ('A', 'AAAA', 'CNAME', 'PTR') or any(not isinstance(row.get(field), str)
                            or len(row[field]) > 253 or any(ord(c) < 32 for c in row[field]) for field in ('name', 'value')):
                        raise SourceError('workstations_source_dns_invalid')
        return data
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise SourceError('workstations_source_incomplete') from None


def read_controller(client, now):
    rows, generation, offset, expected_total = [], None, 0, None
    while True:
        page = client.call('machines.list', {'offset': offset, 'limit': 100}, request_id=str(uuid.uuid4()))
        current, total, next_offset = page.get('machines'), page.get('total'), page.get('next_offset')
        if (not isinstance(current, list) or len(current) > 100 or type(total) is not int or not 0 <= total <= MAX_OBJECTS
                or type(next_offset) is not int or next_offset != offset + len(current) or next_offset > total):
            raise SourceError('workstations_registry_incomplete')
        if generation is None:
            generation, expected_total = page.get('generation'), total
        if page.get('generation') != generation or total != expected_total or not current and offset < total:
            raise SourceError('workstations_registry_changed')
        rows.extend(current)
        if next_offset == total:
            break
        offset = next_offset
    return {'schema_version': 1, 'complete': True, 'generation': generation, 'generated_at': now.isoformat(), 'machines': rows}


def collect_source(name, *, client, netctl_call, clock):
    if name == 'controller':
        data = read_controller(client, clock())
    elif name in ('ad', 'dns'):
        data = client.call('directory.snapshot', {'source': name}, request_id=str(uuid.uuid4()))
    else:
        snapshot = read_current_snapshot(netctl_call)
        data = {'schema_version': 1, 'complete': True, 'generation': str(snapshot.snapshot_id),
                'generated_at': snapshot.generated_at.isoformat(), 'hosts': [saved_observation(dict(row)) for row in snapshot.hosts]}
    return validate_payload(name, data, clock())
