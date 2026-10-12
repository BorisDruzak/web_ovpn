"""Fixed eight-source original-policy inventory; no execution authority."""
from __future__ import annotations

import hashlib

from .setup_plans import canonical,digest
from . import setup_recovery_policy_baseline_wire as common
from . import setup_recovery_policy_baseline as worker,setup_recovery_backup as backup,setup_recovery_native as native

NAMES=common.NAMES+('policy_effects',)
MAX_SOURCE_BYTES=common.MAX_SOURCE_BYTES
MAX_REQUEST_BYTES=common.MAX_REQUEST_BYTES
MAX_REPLY_BYTES=common.MAX_REPLY_BYTES
MAX_WIRE_BYTES=common.MAX_WIRE_BYTES


def _script(wire_sha,hashes):
    return common._script(wire_sha,hashes,effects=True)


def build(sources,request):
    try:
        if (not isinstance(sources,list) or len(sources)!=len(NAMES)
                or any(not isinstance(source,str) or len(source.encode())>MAX_SOURCE_BYTES for source in sources)
                or not isinstance(request,dict) or request.get('source_sha256')!=digest(sources)
                or len(canonical(request))>MAX_REQUEST_BYTES):raise ValueError
        worker._request(request,backup=backup,native=native)
        if request['backup_request']['source_sha256']!=request['source_sha256']:raise ValueError
        raw=canonical(dict(schema_version=1,sources=dict(zip(NAMES,sources)),request=request))
        if len(raw)>MAX_WIRE_BYTES:raise ValueError
        hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(NAMES,sources)}
        return _script(hashlib.sha256(raw).hexdigest(),hashes),raw.decode()
    except Exception:
        raise ValueError('Invalid fixed original effect inventory transport') from None
