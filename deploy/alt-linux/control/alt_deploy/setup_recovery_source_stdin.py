"""Small SHA-bound bootstrap for fixed private recovery worker source on stdin.

Internal transport only: callers retain fixed actions, approval and provenance
checks. The worker and its original request are validated before any compilation.
"""
from __future__ import annotations
import hashlib
import shlex
from .setup_plans import canonical

MAX_SOURCE_BYTES=131072
MAX_REQUEST_BYTES=131072
MAX_ENVELOPE_BYTES=1048576
MAX_REPLY_BYTES=16384
MAX_QUOTED_ARGV_BYTES=8192


def _script(envelope_sha,worker_sha,wire_sha,fields):
    import re
    if (any(not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value)
            for value in (envelope_sha,worker_sha,wire_sha)) or not isinstance(fields,tuple)
            or any(not isinstance(field,str) for field in fields) or '_worker' in fields
            or len(set(fields))!=len(fields)):
        raise ValueError('Invalid fixed source binding')
    binding=repr(dict(envelope_sha=envelope_sha,worker_sha=worker_sha,wire_sha=wire_sha,fields=fields))
    return 'BINDING = '+binding+'\n'+'''import hashlib,io,json,sys
def unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result: raise ValueError()
        result[key]=value
    return result
def invalid_constant(value):
    raise ValueError()
def encoded(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('utf-8')
try:
    raw=sys.stdin.buffer.read(1048577)
    if len(raw)>1048576 or hashlib.sha256(raw).hexdigest()!=BINDING['envelope_sha']: raise ValueError()
    frame=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid_constant)
    if not isinstance(frame,dict) or set(frame)!=set(BINDING['fields'])|{'_worker'}: raise ValueError()
    worker=frame['_worker']
    if not isinstance(worker,str): raise ValueError()
    source=worker.encode('utf-8')
    if len(source)>131072 or hashlib.sha256(source).hexdigest()!=BINDING['worker_sha']: raise ValueError()
    wire={key:frame[key] for key in BINDING['fields']}
    if not wire or ('request' in wire and not isinstance(wire['request'],dict)): raise ValueError()
    data=encoded(wire)
    if len(data)>131072 or hashlib.sha256(data).hexdigest()!=BINDING['wire_sha']: raise ValueError()
    # Every frame and source check finishes before any worker compilation.
    previous_stdin=sys.stdin
    try:
        sys.stdin=io.TextIOWrapper(io.BytesIO(data),encoding='utf-8')
        exec(compile(worker,'fixed_recovery_worker','exec'),globals())
    finally:
        sys.stdin=previous_stdin
except Exception:
    print(json.dumps({'schema_version':1,'error_code':'recovery_source_stdin_invalid'}))
    sys.exit(1)
'''


def build_source_stdin(worker,wire):
    try:
        if (not isinstance(worker,str) or len(worker.encode())>MAX_SOURCE_BYTES
                or not isinstance(wire,dict) or '_worker' in wire
                or not wire or ('request' in wire and not isinstance(wire['request'],dict)) or len(canonical(wire))>MAX_REQUEST_BYTES):raise ValueError
        raw=canonical(dict(wire,_worker=worker))
        if len(raw)>MAX_ENVELOPE_BYTES:raise ValueError
        script=_script(hashlib.sha256(raw).hexdigest(),hashlib.sha256(worker.encode()).hexdigest(),
            hashlib.sha256(canonical(wire)).hexdigest(),tuple(sorted(wire)))
        if len(shlex.quote(script).encode())>=MAX_QUOTED_ARGV_BYTES:raise ValueError
        return script,raw.decode('utf-8')
    except Exception:
        raise ValueError('Invalid bounded fixed recovery transport') from None

def build(program_source,request_wire):
    """Strict JSON-string adapter; supplies no execution or approval authority."""
    from .setup_plans import decode_state_bytes
    try:
        if not isinstance(request_wire,str) or len(request_wire.encode())>MAX_REQUEST_BYTES:raise ValueError
        return build_source_stdin(program_source,decode_state_bytes(request_wire.encode()))
    except Exception:
        raise ValueError('Invalid bounded fixed recovery transport') from None
