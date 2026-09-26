"""Bounded transient relation states; no physical-card details enter Netctl."""
import json
import re

MAX_BYTES = 2 * 1024 * 1024
MAX_KEYS = 50_000
FILTERS = {'all','linked','unlinked','candidates','conflicts'}
STATES = {'linked','unlinked','candidate','ambiguous'}
KEY = re.compile(r'mac:(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\Z')


def validate_projection(value):
    if not isinstance(value,dict) or set(value) != {'schema_version','revision','states'}:
        raise ValueError('invalid inventory projection envelope')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('unsupported inventory projection schema')
    if type(value['revision']) is not int or not 0 <= value['revision'] <= 2**63-1:
        raise ValueError('invalid inventory projection revision')
    states = value['states']
    if not isinstance(states,dict) or len(states)>MAX_KEYS:
        raise ValueError('inventory projection exceeds key budget')
    for key,state in states.items():
        if not isinstance(key,str) or not KEY.fullmatch(key) or key == 'mac:00:00:00:00:00:00' or int(key[4:6],16)&1:
            raise ValueError('invalid inventory projection identity')
        if not isinstance(state,str) or state not in STATES:
            raise ValueError('invalid inventory projection state')
    encoded = json.dumps(value,separators=(',',':'),ensure_ascii=True)
    if len(encoded.encode('utf-8')) > MAX_BYTES:
        raise ValueError('inventory projection exceeds byte budget')
    return states


def read_projection(stream):
    data = stream.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES:
        raise ValueError('inventory projection exceeds byte budget')
    def unique_pairs(pairs):
        result = {}
        for key,value in pairs:
            if key in result:
                raise ValueError('duplicate inventory projection key')
            result[key] = value
        return result
    try:
        value = json.loads(data,object_pairs_hook=unique_pairs)
    except (TypeError,UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise ValueError('invalid inventory projection JSON') from exc
    validate_projection(value)
    return value
