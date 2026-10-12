"""Hash-bound fixed terminal sources over bounded stdin, never shell data."""
import hashlib
from .setup_plans import canonical,digest
from . import setup_recovery_user_wire as user_wire,setup_recovery_terminal as worker
NAMES=user_wire.NAMES+('original_policy','policy_baseline','terminal')
MAX_SOURCE_BYTES=user_wire.MAX_SOURCE_BYTES
MAX_REQUEST_BYTES=user_wire.MAX_REQUEST_BYTES
MAX_REPLY_BYTES=user_wire.MAX_REPLY_BYTES
MAX_WIRE_BYTES=user_wire.MAX_WIRE_BYTES

def build(action,sources,request,*,receipt=None):
    try:
        if (action not in ('handoff','verify') or not isinstance(sources,list) or len(sources)!=len(NAMES)
            or any(not isinstance(s,str) or len(s.encode())>MAX_SOURCE_BYTES for s in sources)
            or len(canonical(request))>MAX_REQUEST_BYTES or request.get('source_sha256')!=digest(sources)
            or (action=='handoff' and receipt is not None) or (action=='verify' and (not isinstance(receipt,dict) or len(canonical(receipt))>MAX_REPLY_BYTES))):raise ValueError
        worker._request(request)
        user_wire.build('verify',sources[:14],request['user_request'],receipt=request['user_receipt'])
        raw=canonical(dict(schema_version=1,action=action,sources=dict(zip(NAMES,sources)),request=request,receipt=receipt))
        if len(raw)>MAX_WIRE_BYTES:raise ValueError
        binding=dict(action=action,wire_sha256=hashlib.sha256(raw).hexdigest(),hashes={n:hashlib.sha256(s.encode()).hexdigest() for n,s in zip(NAMES,sources)},names=NAMES,fields=sorted(worker.FIELDS),max_wire=MAX_WIRE_BYTES,max_source=MAX_SOURCE_BYTES,max_request=MAX_REQUEST_BYTES,max_reply=MAX_REPLY_BYTES)
        script='B='+canonical(binding).decode()+'\n'+'''import hashlib,json,sys,types
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError()
  d[k]=v
 return d
def invalid(v):raise ValueError()
def encoded(v):return json.dumps(v,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
try:
 raw=sys.stdin.buffer.read(B['max_wire']+1)
 if len(raw)>B['max_wire'] or hashlib.sha256(raw).hexdigest()!=B['wire_sha256']:raise ValueError()
 envelope=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
 if set(envelope)!={'schema_version','action','sources','request','receipt'} or type(envelope['schema_version']) is not int or envelope['schema_version']!=1 or envelope['action']!=B['action']:raise ValueError()
 sources=envelope['sources'];request=envelope['request'];receipt=envelope['receipt']
 if set(sources)!=set(B['names']) or set(request)!=set(B['fields']) or len(encoded(request))>B['max_request']:raise ValueError()
 ordered=[]
 for name in B['names']:
  source=sources[name]
  if not isinstance(source,str) or len(source.encode())>B['max_source'] or hashlib.sha256(source.encode()).hexdigest()!=B['hashes'][name]:raise ValueError()
  ordered.append(source)
 if request['source_sha256']!=digest(ordered) or request['user_request']['source_sha256']!=digest(ordered[:14]) or request['user_request']['startup_request']['source_sha256']!=digest(ordered[:12]):raise ValueError()
 if B['action']=='handoff' and receipt is not None:raise ValueError()
 if B['action']=='verify' and (not isinstance(receipt,dict) or len(encoded(receipt))>B['max_reply']):raise ValueError()
 modules={}
 for name in B['names']:
  scope={'__name__':'fixed_recovery_'+name,'__package__':None}
  exec(compile(sources[name],'fixed_recovery_'+name,'exec'),scope)
  modules[name]=types.SimpleNamespace(**scope)
 args={k:modules[n] for k,n in [('backup','backup'),('probe','probe'),('native','native'),('kerberos','kerberos'),('importer','import'),('policy','sssd_policy'),('services','services'),('graph','start_graph'),('start','sssd_start'),('checker','native_testjoin'),('user','user_check'),('original','original_policy'),('baseline','policy_baseline')]}
 args.update(collect=modules['probe'].collect,runner=modules['process'].bounded_recovery_run)
 if B['action']=='handoff':result=modules['terminal'].handoff_once(request,**args)
 else:result=modules['terminal'].verify(request,receipt,**args)
 if not isinstance(result,dict) or len(encoded(result))>B['max_reply']:raise ValueError()
 print(json.dumps(result,sort_keys=True,allow_nan=False))
except Exception:
 print(json.dumps({'schema_version':1,'status':'UNKNOWN','error_code':'recovery_terminal_wire_invalid'}))
 sys.exit(1)
'''
        if len(script.encode())>7000:raise ValueError
        return script,raw.decode()
    except Exception:raise ValueError('Invalid fixed terminal bundle') from None
