"""Fixed read-only baseline envelope; no transport or approval authority."""
from __future__ import annotations

import ast,hashlib,io,json,re,tokenize

from .setup_plans import canonical,digest
from . import setup_recovery_policy_baseline as worker,setup_recovery_backup as backup,setup_recovery_native as native

NAMES=('probe','backup','native','process','sssd_policy','original_policy','policy_baseline')
MAX_SOURCE_BYTES=131072
MAX_REQUEST_BYTES=131072
MAX_REPLY_BYTES=16384
MAX_WIRE_BYTES=1048576


def _quote_safe(script):
    # Fixed literal tokens use JSON/Python-compatible double quoting. Keeping
    # single quotes out of the script avoids repeated POSIX shell quote escapes.
    tokens=[]
    for item in tokenize.generate_tokens(io.StringIO(script).readline):
        value=json.dumps(ast.literal_eval(item.string),ensure_ascii=True) if item.type==tokenize.STRING else item.string
        tokens.append((item.type,value))
    return tokenize.untokenize(tokens)


def _script(wire_sha,hashes,*,effects=False):
    if type(effects) is not bool:raise ValueError
    names=NAMES+('policy_effects',) if effects else NAMES
    if (not isinstance(wire_sha,str) or not re.fullmatch('[0-9a-f]{64}',wire_sha)
            or not isinstance(hashes,dict) or set(hashes)!=set(names)
            or any(not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value) for value in hashes.values())):raise ValueError
    binding=canonical(dict(wire_sha=wire_sha,hashes=hashes,names=names,auth_files=backup.AUTH_FILES,
        kind='effects' if effects else 'baseline',deadline_seconds=180 if effects else 120,
        error_code='recovery_policy_effects_wire_invalid' if effects else 'recovery_policy_baseline_wire_invalid',
        max_wire=MAX_WIRE_BYTES,max_source=MAX_SOURCE_BYTES,max_request=MAX_REQUEST_BYTES,max_reply=MAX_REPLY_BYTES)).decode()
    return _quote_safe('BINDING='+binding+'\n'+r'''import hashlib,ipaddress,json,re,sys,time,types,uuid
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError()
        result[key]=value
    return result
def invalid(value):raise ValueError()
def encoded(value):return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def sha(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None
try:
    raw=sys.stdin.buffer.read(BINDING['max_wire']+1)
    if len(raw)>BINDING['max_wire'] or hashlib.sha256(raw).hexdigest()!=BINDING['wire_sha']:raise ValueError()
    wire=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
    if (not isinstance(wire,dict) or set(wire)!={'schema_version','sources','request'}
            or type(wire['schema_version']) is not int or wire['schema_version']!=1):raise ValueError()
    sources=wire['sources'];request=wire['request']
    if (not isinstance(sources,dict) or set(sources)!=set(BINDING['names'])
            or not isinstance(request,dict) or set(request)!={'schema_version','backup_request','metadata','source_sha256'}
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or len(encoded(request))>BINDING['max_request']):raise ValueError()
    ordered=[]
    for name in BINDING['names']:
        source=sources[name]
        if (not isinstance(source,str) or len(source.encode())>BINDING['max_source']
                or hashlib.sha256(source.encode()).hexdigest()!=BINDING['hashes'][name]):raise ValueError()
        ordered.append(source)
    if request['source_sha256']!=digest(ordered):raise ValueError()
    bound=request['backup_request'];meta=request['metadata']
    if BINDING['kind']=='effects' and (not isinstance(bound,dict) or bound.get('source_sha256')!=request['source_sha256']):raise ValueError()
    if (not isinstance(bound,dict) or set(bound)!={'schema_version','failed_run_id','computer_guid','claim_sha256',
            'machine_uuid','hostname','facts','snapshot_sha256','source_sha256'}
            or type(bound['schema_version']) is not int or bound['schema_version']!=1
            or not isinstance(bound['failed_run_id'],str) or not re.fullmatch('setup-run-[0-9a-f]{32}',bound['failed_run_id'])
            or any(not sha(bound[key]) for key in ('claim_sha256','snapshot_sha256','source_sha256'))
            or not isinstance(bound['hostname'],str) or not re.fullmatch(r'(?:lin|alt|win|deb)-[a-z][0-9]?-(?:pc[1-9][0-9]*)',bound['hostname'])):raise ValueError()
    for key in ('computer_guid','machine_uuid'):
        if not isinstance(bound[key],str) or str(uuid.UUID(bound[key]))!=bound[key] or uuid.UUID(bound[key]).int==0:raise ValueError()
    facts=bound['facts']
    if (not isinstance(facts,dict) or digest(facts)!=bound['snapshot_sha256'] or facts.get('uuid')!=bound['machine_uuid']
            or facts.get('hostname')!=bound['hostname'] or facts.get('clock_synchronized') is not True
            or facts.get('incompatible_processes')!=[] or not isinstance(facts.get('files'),dict)
            or set(facts['files'])!=set(BINDING['auth_files'])):raise ValueError()
    if (not isinstance(meta,dict) or set(meta)!={'hostname','realm','workgroup','domain_guid','domain_sid','dc_hostname','dc_address'}
            or any(not isinstance(value,str) for value in meta.values()) or meta['hostname']!=bound['hostname']
            or len(meta['hostname'])>15 or not re.fullmatch('[a-z][a-z0-9]*(?:-[a-z0-9]+)*',meta['hostname'])
            or meta['realm']!='sosnadmin.local' or meta['workgroup']!='SOSNADM'
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.sosnadmin\.local',meta['dc_hostname'])
            or not re.fullmatch(r'S-1-5-21-(?:[1-9][0-9]*-){2}[1-9][0-9]*',meta['domain_sid'])
            or any(int(item)>4294967295 for item in meta['domain_sid'].split('-')[4:])
            or str(uuid.UUID(meta['domain_guid']))!=meta['domain_guid']):raise ValueError()
    address=ipaddress.IPv4Address(meta['dc_address'])
    if str(address)!=meta['dc_address'] or address.is_multicast or address.is_unspecified:raise ValueError()
    # All envelope/source/request bindings are checked before source execution.
    modules={}
    for name in BINDING['names']:
        scope={'__name__':'fixed_baseline_'+name,'__package__':None}
        exec(compile(sources[name],'fixed_baseline_'+name,'exec'),scope)
        modules[name]=types.SimpleNamespace(**scope)
    deadline=time.monotonic()+BINDING['deadline_seconds']
    def runner(command,**options):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError()
        options['timeout']=min(options.get('timeout',15),remaining)
        result=modules['process'].bounded_recovery_run(command,**options)
        if time.monotonic()>deadline:raise ValueError()
        return result
    def read_command(command):
        rc,out,_=runner(command,environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=15)
        if type(rc) is not int or rc or not isinstance(out,str) or len(out.encode())>16384:raise ValueError()
        return out.strip()
    def collect():return modules['probe'].collect(runner=read_command)
    args={key:modules[name] for key,name in (('original','original_policy'),('policy','sssd_policy'),
        ('backup','backup'),('probe','probe'),('native','native'))}
    result=modules['policy_baseline'].observe(request,collect=collect,runner=runner,**args)
    if BINDING['kind']=='effects':
        effect_request=dict(schema_version=1,baseline_request=request,baseline_receipt=result,source_sha256=request['source_sha256'])
        effect_result=modules['policy_effects'].observe(effect_request,baseline=modules['policy_baseline'],collect=collect,runner=runner,**args)
        result=dict(baseline_receipt=result,effect_receipt=effect_result)
    raw=encoded(result)
    if not isinstance(result,dict) or len(raw)>BINDING['max_reply']:raise ValueError()
    sys.stdout.buffer.write(raw)
except Exception:
    sys.stdout.write(json.dumps(dict(schema_version=1,error_code=BINDING['error_code']),sort_keys=True,separators=(',',':')))
    sys.exit(1)
''')


def build(sources,request):
    try:
        if (not isinstance(sources,list) or len(sources)!=len(NAMES)
                or any(not isinstance(source,str) or len(source.encode())>MAX_SOURCE_BYTES for source in sources)
                or not isinstance(request,dict) or request.get('source_sha256')!=digest(sources)
                or len(canonical(request))>MAX_REQUEST_BYTES):raise ValueError
        worker._request(request,backup=backup,native=native)
        raw=canonical(dict(schema_version=1,sources=dict(zip(NAMES,sources)),request=request))
        if len(raw)>MAX_WIRE_BYTES:raise ValueError
        hashes={name:hashlib.sha256(source.encode()).hexdigest() for name,source in zip(NAMES,sources)}
        return _script(hashlib.sha256(raw).hexdigest(),hashes),raw.decode()
    except Exception:raise ValueError('Invalid fixed original baseline transport') from None
