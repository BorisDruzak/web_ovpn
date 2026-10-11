"""Bounded stdin bundle for the fixed startup worker; no execution authority.

The caller owns approval, source provenance, lifecycle locking and target/AD
checks. This builder performs no transport, service or directory operation.
Source text is carried on stdin, never appended to the remote argv string.
"""
from __future__ import annotations

import hashlib
import re

from .setup_plans import canonical,digest
from . import setup_recovery_backup as backup
from . import setup_recovery_kerberos as kerberos
from . import setup_recovery_services as services
from . import setup_recovery_sssd_policy as policy
from . import setup_recovery_sssd_start as start

NAMES=('probe','backup','native','process','rehearsal','keytab','import','services',
       'kerberos','sssd_policy','start_graph','sssd_start')
REQUEST_FIELDS=('schema_version','policy_request','policy_receipt','service_request','service_receipt','sssd_unit',
    'source_sha256','effects_ledger_sha256','plan_id','plan_sha256','approval_sha256','plan_created_at','plan_expires_at')
MAX_SOURCE_BYTES=131072
MAX_REQUEST_BYTES=131072
MAX_REPLY_BYTES=16384
MAX_WIRE_BYTES=1048576


def _script(action,wire_sha,source_hashes):
    if (action not in ('start','verify') or not isinstance(wire_sha,str) or not re.fullmatch('[0-9a-f]{64}',wire_sha)
            or not isinstance(source_hashes,dict) or set(source_hashes)!=set(NAMES)
            or any(not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value) for value in source_hashes.values())):
        raise ValueError('Invalid fixed bootstrap binding')
    bindings=repr(dict(action=action,wire_sha=wire_sha,source_hashes=source_hashes,names=NAMES,request_fields=REQUEST_FIELDS,
        max_wire=MAX_WIRE_BYTES,max_source=MAX_SOURCE_BYTES,max_request=MAX_REQUEST_BYTES,max_reply=MAX_REPLY_BYTES))
    return 'BINDING = '+bindings+'\n'+'''import hashlib, json, sys, types
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError()
        result[key] = value
    return result
def invalid_constant(value):
    raise ValueError()
def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
try:
    raw = sys.stdin.buffer.read(BINDING['max_wire'] + 1)
    if len(raw) > BINDING['max_wire'] or hashlib.sha256(raw).hexdigest() != BINDING['wire_sha']: raise ValueError()
    wire = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    if (not isinstance(wire, dict) or set(wire) != {'schema_version', 'action', 'sources', 'request', 'receipt'}
            or type(wire['schema_version']) is not int or wire['schema_version'] != 1
            or wire['action'] != BINDING['action']): raise ValueError()
    sources = wire['sources']; request = wire['request']; receipt = wire['receipt']
    if (not isinstance(sources, dict) or set(sources) != set(BINDING['names'])
            or not isinstance(request, dict) or set(request) != set(BINDING['request_fields'])
            or type(request['schema_version']) is not int or request['schema_version'] != 1
            or len(encoded(request)) > BINDING['max_request']): raise ValueError()
    ordered = []
    for name in BINDING['names']:
        source = sources[name]
        if not isinstance(source, str): raise ValueError()
        data = source.encode('utf-8')
        if len(data) > BINDING['max_source'] or hashlib.sha256(data).hexdigest() != BINDING['source_hashes'][name]: raise ValueError()
        ordered.append(source)
    if hashlib.sha256(encoded(ordered)).hexdigest() != request['source_sha256']: raise ValueError()
    if wire['action'] == 'start':
        if receipt is not None: raise ValueError()
    elif (not isinstance(receipt, dict) or len(encoded(receipt)) > BINDING['max_reply']): raise ValueError()
    # No source is compiled/executed before every envelope/module check above.
    modules = {}
    for name in BINDING['names']:
        scope = {'__name__': 'fixed_recovery_' + name, '__package__': None}
        exec(compile(sources[name], 'fixed_recovery_' + name, 'exec'), scope)
        modules[name] = types.SimpleNamespace(**scope)
    args = {key: modules[name] for key, name in (
        ('backup','backup'), ('probe','probe'), ('native','native'), ('kerberos','kerberos'),
        ('importer','import'), ('policy','sssd_policy'), ('services','services'), ('graph','start_graph'))}
    args.update(collect=modules['probe'].collect, runner=modules['process'].bounded_recovery_run)
    worker = modules['sssd_start']
    if wire['action'] == 'start': result = worker.start_once(request, **args)
    else: result = worker.verify_started(request, receipt, **args)
    if not isinstance(result, dict) or len(encoded(result)) > BINDING['max_reply']: raise ValueError()
    print(json.dumps(result, sort_keys=True, allow_nan=False))
except Exception:
    print(json.dumps({'schema_version': 1, 'error_code': 'recovery_start_wire_invalid'}))
    sys.exit(1)
'''


def build(action,sources,request,*,receipt=None):
    try:
        if (action not in ('start','verify') or not isinstance(sources,list) or len(sources)!=len(NAMES)
                or any(not isinstance(value,str) or len(value.encode())>MAX_SOURCE_BYTES for value in sources)
                or not isinstance(request,dict) or request.get('source_sha256')!=digest(sources)
                or len(canonical(request))>MAX_REQUEST_BYTES
                or (action=='start' and receipt is not None)
                or (action=='verify' and (not isinstance(receipt,dict) or len(canonical(receipt))>MAX_REPLY_BYTES))):raise ValueError
        start._request(request,backup=backup,policy=policy,kerberos=kerberos,services=services)
        hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(NAMES,sources)}
        raw=canonical(dict(schema_version=1,action=action,sources=dict(zip(NAMES,sources)),request=request,receipt=receipt))
        if len(raw)>MAX_WIRE_BYTES:raise ValueError
        return _script(action,hashlib.sha256(raw).hexdigest(),hashes),raw.decode('utf-8')
    except Exception:raise ValueError('Invalid fixed startup transport bundle') from None
