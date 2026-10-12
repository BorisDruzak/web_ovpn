"""Fixed user-observation stdin bundle; caller owns authority and transport.

Preserves the original twelve-source startup binding and fourteen-source user
binding. No SSH, service operation, directory write or authority default.
"""
from __future__ import annotations

import hashlib,re

from .setup_plans import canonical,digest
from . import setup_recovery_native_wire as native_wire
from . import setup_recovery_user_check as worker

NAMES=native_wire.NAMES+('user_check',)
REQUEST_FIELDS=('schema_version','startup_request','startup_receipt','native_receipt','employee','source_sha256','approval_sha256')
MAX_SOURCE_BYTES=native_wire.MAX_SOURCE_BYTES
MAX_REQUEST_BYTES=native_wire.MAX_REQUEST_BYTES
MAX_REPLY_BYTES=native_wire.MAX_REPLY_BYTES
MAX_WIRE_BYTES=native_wire.MAX_WIRE_BYTES


def _proof(request):
    started=request['startup_receipt'];native=request['native_receipt'];startup=request['startup_request']
    if (not isinstance(native,dict) or len(canonical(native))>MAX_REPLY_BYTES
            or native.get('schema_version')!=1 or type(native.get('schema_version')) is not int
            or native.get('status')!='native_testjoin_succeeded'
            or native.get('request_sha256')!=digest(startup) or native.get('startup_receipt_sha256')!=digest(started)
            or native.get('trust_verified') is not False or native.get('native_testjoin_peer_pinning_verified') is not False
            or native.get('temporary_policy_retained') is not True):raise ValueError


def _script(action,wire_sha,source_hashes):
    if (action not in ('check','verify') or not isinstance(wire_sha,str) or not re.fullmatch('[0-9a-f]{64}',wire_sha)
            or not isinstance(source_hashes,dict) or set(source_hashes)!=set(NAMES)
            or any(not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value) for value in source_hashes.values())):raise ValueError
    binding=canonical(dict(action=action,wire_sha=wire_sha,hashes=source_hashes,names=NAMES,fields=REQUEST_FIELDS,
        startup_fields=native_wire.REQUEST_FIELDS,max_wire=MAX_WIRE_BYTES,max_source=MAX_SOURCE_BYTES,
        max_request=MAX_REQUEST_BYTES,max_reply=MAX_REPLY_BYTES)).decode('utf-8')
    return 'BINDING = '+binding+'\n'+'''import hashlib,json,re,sys,types,uuid
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError()
        result[key]=value
    return result
def invalid(value): raise ValueError()
def encoded(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('utf-8')
def digest(value): return hashlib.sha256(encoded(value)).hexdigest()
try:
    raw=sys.stdin.buffer.read(BINDING['max_wire']+1)
    if len(raw)>BINDING['max_wire'] or hashlib.sha256(raw).hexdigest()!=BINDING['wire_sha']: raise ValueError()
    wire=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
    if (not isinstance(wire,dict) or set(wire)!={'schema_version','action','sources','request','receipt'}
            or type(wire['schema_version']) is not int or wire['schema_version']!=1
            or wire['action']!=BINDING['action']): raise ValueError()
    sources=wire['sources'];request=wire['request'];receipt=wire['receipt']
    if (not isinstance(sources,dict) or set(sources)!=set(BINDING['names'])
            or not isinstance(request,dict) or set(request)!=set(BINDING['fields'])
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or len(encoded(request))>BINDING['max_request']): raise ValueError()
    ordered=[]
    for name in BINDING['names']:
        source=sources[name]
        if not isinstance(source,str): raise ValueError()
        data=source.encode('utf-8')
        if len(data)>BINDING['max_source'] or hashlib.sha256(data).hexdigest()!=BINDING['hashes'][name]: raise ValueError()
        ordered.append(source)
    startup=request['startup_request'];started=request['startup_receipt'];native=request['native_receipt'];employee=request['employee']
    if (request['source_sha256']!=digest(ordered) or not isinstance(startup,dict)
            or set(startup)!=set(BINDING['startup_fields']) or type(startup['schema_version']) is not int
            or startup['schema_version']!=1 or startup['source_sha256']!=digest(ordered[:12])
            or not isinstance(started,dict) or len(encoded(started))>BINDING['max_reply']
            or started.get('status')!='sssd_started' or started.get('request_sha256')!=digest(startup)
            or not isinstance(native,dict) or len(encoded(native))>BINDING['max_reply']
            or type(native.get('schema_version')) is not int or native.get('schema_version')!=1
            or native.get('status')!='native_testjoin_succeeded' or native.get('request_sha256')!=digest(startup)
            or native.get('startup_receipt_sha256')!=digest(started) or native.get('trust_verified') is not False
            or native.get('native_testjoin_peer_pinning_verified') is not False or native.get('temporary_policy_retained') is not True
            or not isinstance(request['approval_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',request['approval_sha256'])
            or request['approval_sha256']!=startup['approval_sha256']): raise ValueError()
    if (not isinstance(employee,dict) or set(employee)!={'object_guid','object_sid','login','upn'}
            or any(not isinstance(value,str) for value in employee.values())
            or str(uuid.UUID(employee['object_guid']))!=employee['object_guid']
            or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',employee['object_sid'])
            or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}',employee['login'])
            or employee['upn']!=employee['login']+'@sosnadmin.local'): raise ValueError()
    if wire['action']=='check':
        if receipt is not None: raise ValueError()
    elif not isinstance(receipt,dict) or len(encoded(receipt))>BINDING['max_reply']: raise ValueError()
    # Every envelope/source/proof binding is checked before source execution.
    modules={}
    for name in BINDING['names']:
        scope={'__name__':'fixed_recovery_'+name,'__package__':None}
        exec(compile(sources[name],'fixed_recovery_'+name,'exec'),scope)
        modules[name]=types.SimpleNamespace(**scope)
    args={key:modules[name] for key,name in (('backup','backup'),('probe','probe'),('native','native'),
        ('kerberos','kerberos'),('importer','import'),('policy','sssd_policy'),('services','services'),
        ('graph','start_graph'),('start','sssd_start'),('checker','native_testjoin'))}
    args.update(collect=modules['probe'].collect,runner=modules['process'].bounded_recovery_run)
    worker=modules['user_check']
    if wire['action']=='check': result=worker.check_once(request,**args)
    else: result=worker.verify(request,receipt,**args)
    if not isinstance(result,dict) or len(encoded(result))>BINDING['max_reply']: raise ValueError()
    print(json.dumps(result,sort_keys=True,allow_nan=False))
except Exception:
    print(json.dumps({'schema_version':1,'error_code':'recovery_user_wire_invalid'}))
    sys.exit(1)
'''


def build(action,sources,request,*,receipt=None):
    try:
        if (action not in ('check','verify') or not isinstance(sources,list) or len(sources)!=len(NAMES)
                or any(not isinstance(value,str) or len(value.encode())>MAX_SOURCE_BYTES for value in sources)
                or not isinstance(request,dict) or request.get('source_sha256')!=digest(sources)
                or len(canonical(request))>MAX_REQUEST_BYTES
                or (action=='check' and receipt is not None)
                or (action=='verify' and (not isinstance(receipt,dict) or len(canonical(receipt))>MAX_REPLY_BYTES))):raise ValueError
        worker._request(request);_proof(request)
        native_wire.build('verify',sources[:13],request['startup_request'],request['startup_receipt'],receipt=request['native_receipt'])
        raw=canonical(dict(schema_version=1,action=action,sources=dict(zip(NAMES,sources)),request=request,receipt=receipt))
        if len(raw)>MAX_WIRE_BYTES:raise ValueError
        hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(NAMES,sources)}
        return _script(action,hashlib.sha256(raw).hexdigest(),hashes),raw.decode('utf-8')
    except Exception:raise ValueError('Invalid fixed user transport bundle') from None
