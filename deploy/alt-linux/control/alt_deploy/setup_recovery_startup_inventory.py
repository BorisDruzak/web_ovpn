"""Operator read-only inventory; no reservation, credential import or service action.

Large graph evidence uses its own bounded immutable chunk store. The existing
Setup state limit and execution-process receipt limits are not enlarged.
Opaque commands/environments leave the worker only as hashes. Inventory is
provenance for later effects review, never an execution or trust approval.
"""
from __future__ import annotations

import hashlib,ipaddress,json,os,re,shlex,stat
from pathlib import Path

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import SetupPlanStore,canonical,digest,private_create,private_directory,private_read
from .setup_recovery import _sync_directory
from .setup_recovery_process import bounded_inventory_run
from .setup_recovery_runtime import _read_source
from . import setup_recovery_start_graph as graph

MAX_BYTES=graph.MAX_INVENTORY_BYTES
NAMES=('probe','process','start_graph')
ENVIRONMENT={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


def _decode(raw,maximum):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError
            result[key]=value
        return result
    def invalid(value):raise ValueError
    if not isinstance(raw,bytes) or len(raw)>maximum:raise ValueError
    value=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
    if not isinstance(value,dict):raise ValueError
    return value


class InventoryStore:
    def __init__(self,state_root):self.root=state_root/'setup-recovery-startup-inventories'

    def path(self,sha):
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise ValueError
        return self.root/sha

    def create(self,value):
        try:
            raw=canonical(value)
            if not isinstance(value,dict) or len(raw)>MAX_BYTES:raise ValueError
            reference=dict(schema_version=1,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
            leaf=self.path(reference['sha256']);private_directory(self.root)
            if leaf.exists() or leaf.is_symlink():
                if self.load(reference)!=value:raise ValueError
                return reference
            leaf.mkdir(mode=0o700);parts=[]
            for index,offset in enumerate(range(0,len(raw),131072)):
                data=raw[offset:offset+131072].decode('ascii');name=f'part-{index:03d}.json'
                private_create(leaf/name,{'data':data});parts.append(dict(name=name,sha256=digest({'data':data})))
            private_create(leaf/'manifest.json',dict(reference,parts=parts));_sync_directory(leaf)
            for parent in (self.root,*self.root.parents):_sync_directory(parent)
            if self.load(reference)!=value:raise ValueError
            return reference
        except Exception:
            raise fail('recovery_inventory_state_invalid','Private inventory evidence is incomplete, unsafe or changed') from None

    def load(self,reference):
        try:
            if (not isinstance(reference,dict) or set(reference)!={'schema_version','sha256','bytes'}
                    or type(reference['schema_version']) is not int or reference['schema_version']!=1
                    or type(reference['bytes']) is not int or not 2<=reference['bytes']<=MAX_BYTES):raise ValueError
            leaf=self.path(reference['sha256'])
            # Read validation never creates a path, even when it disappears
            # between metadata reads. Ancestor redirects are always refused.
            for path in (*reversed(leaf.parents),leaf):
                metadata=path.lstat()
                if not stat.S_ISDIR(metadata.st_mode):raise ValueError
            if stat.S_IMODE(metadata.st_mode)!=0o700 or metadata.st_uid!=os.geteuid():raise ValueError
            manifest=private_read(leaf/'manifest.json')
            if (set(manifest)!=set(reference)|{'parts'} or canonical({key:manifest[key] for key in reference})!=canonical(reference)
                    or not isinstance(manifest['parts'],list) or not 1<=len(manifest['parts'])<=32):raise ValueError
            names={'manifest.json'};chunks=[];size=0
            for index,part in enumerate(manifest['parts']):
                name=f'part-{index:03d}.json'
                if not isinstance(part,dict) or set(part)!={'name','sha256'} or part['name']!=name:raise ValueError
                data=private_read(leaf/name)
                if (set(data)!={'data'} or not isinstance(data['data'],str) or digest(data)!=part['sha256']
                        or not 1<=len(data['data'])<=131072):raise ValueError
                chunk=data['data'].encode('ascii');size+=len(chunk)
                if size>MAX_BYTES:raise ValueError
                chunks.append(chunk);names.add(name)
            if {path.name for path in leaf.iterdir()}!=names:raise ValueError
            raw=b''.join(chunks)
            if size!=reference['bytes'] or hashlib.sha256(raw).hexdigest()!=reference['sha256']:raise ValueError
            value=_decode(raw,MAX_BYTES)
            if canonical(value)!=raw:raise ValueError
            return value
        except Exception:
            raise fail('recovery_inventory_state_invalid','Private inventory evidence is incomplete, unsafe or changed') from None


def bootstrap(sources):
    if (not isinstance(sources,list) or len(sources)!=3
            or any(not isinstance(source,str) or len(source.encode())>131072 for source in sources)):raise ValueError
    wire=dict(schema_version=1,sources=dict(zip(NAMES,sources)))
    payload=canonical(wire).decode('ascii')
    if len(payload)>1048576:raise ValueError
    binding=dict(wire_sha256=digest(wire),source_hashes={name:hashlib.sha256(source.encode()).hexdigest()
        for name,source in zip(NAMES,sources)},names=NAMES)
    script='BINDING='+repr(binding)+'\n'+'''import hashlib,json,sys,types
def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError()
        result[key]=value
    return result
def invalid(value):raise ValueError()
def encoded(value):return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()
try:
    raw=sys.stdin.buffer.read(1048577)
    if len(raw)>1048576 or hashlib.sha256(raw).hexdigest()!=BINDING['wire_sha256']:raise ValueError()
    wire=json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)
    if (set(wire)!={'schema_version','sources'} or type(wire['schema_version']) is not int
            or wire['schema_version']!=1 or set(wire['sources'])!=set(BINDING['names'])):raise ValueError()
    for name in BINDING['names']:
        source=wire['sources'][name]
        if (not isinstance(source,str) or len(source.encode())>131072
                or hashlib.sha256(source.encode()).hexdigest()!=BINDING['source_hashes'][name]):raise ValueError()
    modules={}
    for name in BINDING['names']:
        scope={'__name__':'fixed_inventory_'+name,'__package__':None}
        exec(compile(wire['sources'][name],'fixed_inventory_'+name,'exec'),scope)
        modules[name]=types.SimpleNamespace(**scope)
    value=modules['start_graph'].capture(probe=modules['probe'],collect=modules['probe'].collect,
        runner=modules['process'].bounded_inventory_command_run)
    raw=encoded(value)
    if len(raw)>4194304:raise ValueError()
    sys.stdout.buffer.write(raw)
except Exception:
    sys.stdout.write('{"error_code":"recovery_startup_inventory_failed"}')
    sys.exit(1)
'''
    return script,payload


class RecoveryStartupInventoryRuntime:
    def __init__(self,settings,*,runner=None):self.settings=settings;self.runner=runner or bounded_inventory_run

    def _sources(self):
        directory=Path(__file__).parent;owner=Path(__file__).lstat().st_uid
        return [_read_source(directory/('setup_recovery_'+name+'.py'),owner=owner) for name in NAMES]

    def capture(self,machine,expected_facts):
        try:
            address=str(ipaddress.ip_address(machine.ip));sources=self._sources();script,payload=bootstrap(sources)
            command=['/usr/bin/ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no',
                '-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','UserKnownHostsFile='+str(self.settings.known_hosts_file),
                '-i',str(self.settings.private_key_file),'ansible@'+address,
                'sudo -n /usr/bin/python3 -I -B -c '+shlex.quote(script)]
            if len(command[-1].encode())>8192:raise ValueError
            rc,out,_=self.runner(command,environment=dict(ENVIRONMENT),input_text=payload,timeout=60)
            if type(rc) is not int or rc or not isinstance(out,str):raise ValueError
            value=_decode(out.encode(),MAX_BYTES)
            fields={'units','aliases','device_inventory','unresolved','unit_lookup_paths','possibilities','edges',
                'schema_version','status','execution_authorized','semantics','review_requirements','facts','systemctl','systemd_package'}
            if (set(value)!=fields or type(value['schema_version']) is not int or value['schema_version']!=1
                    or value['status']!='startup_inventory_only' or value['execution_authorized'] is not False
                    or value['semantics']!='conservative_effect_inventory_without_pruning'
                    or value['facts']!=expected_facts or expected_facts['uuid']!=machine.uuid
                    or expected_facts['hostname']!=machine.hostname or value['systemd_package']!='systemd 258.9-alt1'
                    or not isinstance(value['units'],dict) or not 1<=len(value['units'])<=graph.MAX_UNITS
                    or not isinstance(value['device_inventory'],dict) or len(value['device_inventory'])>graph.MAX_UNITS
                    or not isinstance(value['possibilities'],list) or len(value['possibilities'])>graph.MAX_PAIRS
                    or not isinstance(value['edges'],list) or len(value['edges'])>graph.MAX_EDGES
                    or value['unit_lookup_paths']!=list(graph.UNIT_PATHS) or self._sources()!=sources):raise ValueError
            return dict(source_sha256=digest(sources),inventory=value)
        except Exception:
            raise fail('recovery_startup_inventory_failed','Fixed read-only startup inventory did not verify') from None


class InventoryPlanStore(SetupPlanStore):
    prefix='recovery-inventory-'
    directory='setup-recovery-inventory-plans'


class RecoveryStartupInventoryService:
    def __init__(self,planning,*,runtime=None):
        self.planning=planning;self.runtime=runtime or RecoveryStartupInventoryRuntime(planning.settings)
        self.store=InventoryStore(planning.settings.state_root)
        self.plans=InventoryPlanStore(planning.settings.state_root,clock=planning.clock)

    def plan(self,failed_run_id,computer_guid):
        try:
            with exclusive_lock(self.planning.settings.lock_file):
                snapshot=self.planning.snapshot(failed_run_id,computer_guid)
                machine=self.planning.machines.resolve(snapshot['machine_uuid'])
                result=self.runtime.capture(machine,snapshot['workstation_facts']['snapshot'])
                if self.planning.snapshot(failed_run_id,computer_guid)!=snapshot:raise ValueError
                reference=self.store.create(result['inventory'])
                if (self.store.load(reference)!=result['inventory']
                        or self.planning.snapshot(failed_run_id,computer_guid)!=snapshot):raise ValueError
                return self.plans.create(dict(schema_version=1,failed_run_id=failed_run_id,computer_guid=computer_guid,
                    machine=snapshot['machine'],recovery_snapshot_sha256=digest(snapshot),
                    inventory=reference,source_sha256=result['source_sha256'],execution_available=False,
                    unit_count=len(result['inventory']['units']),possible_job_count=len(result['inventory']['possibilities']),
                    review_requirements=result['inventory']['review_requirements']))
        except Exception:
            raise fail('recovery_startup_inventory_failed','Pinned inventory planning did not verify; no recovery attempt was reserved') from None
