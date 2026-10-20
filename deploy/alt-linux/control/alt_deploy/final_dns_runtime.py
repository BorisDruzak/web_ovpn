"""Read-only fixed final-DNS observation over pinned administrative SSH."""
import hashlib
import ipaddress
import json
import re
import shlex

from .ad_directory import fail
from .final_dns_policy import validate
from .final_dns_program import target_program
from .target_transport import ssh_prefix


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError
        result[key]=value
    return result


def validate_observation(value,machine,*,expected_boot_id=None):
    keys={'schema_version','machine_uuid','hostname','boot_id','backend','interface','connection_uuid',
          'servers','persistent_servers','configuration_sha256','network_sha256','snapshot_sha256'}
    if (not isinstance(value,dict) or set(value)!=keys or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['machine_uuid']!=machine.uuid or value['hostname']!=machine.hostname
            or value['backend'] not in ('nm_etcnet','nm_keyfile','etcnet')
            or not isinstance(value['interface'],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',value['interface'])
            or not isinstance(value['boot_id'],str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id'])
            or expected_boot_id is not None and value['boot_id']!=expected_boot_id):raise ValueError
    if value['backend']=='etcnet':
        if value['connection_uuid'] is not None:raise ValueError
    elif not isinstance(value['connection_uuid'],str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['connection_uuid']):raise ValueError
    for key in ('servers','persistent_servers'):
        entries=value[key]
        if (not isinstance(entries,list) or len(entries)>16 or key=='servers' and not entries
                or any(not isinstance(v,str) or '%' in v or str(ipaddress.ip_address(v))!=v for v in entries)
                or len(set(entries))!=len(entries)):raise ValueError
    for key in ('configuration_sha256','network_sha256','snapshot_sha256'):
        if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):raise ValueError
    if hashlib.sha256(canonical({k:v for k,v in value.items() if k!='snapshot_sha256'})).hexdigest()!=value['snapshot_sha256']:
        raise ValueError
    return value


def observe(settings,machine,policy,*,expected_boot_id=None,runner=None):
    try:
        from .ad_transport import bounded_run
        runner=runner or bounded_run
        if not isinstance(policy,dict) or set(policy)!={'servers'}:raise ValueError
        policy=validate(policy['servers'])
        expected=hashlib.sha256(target_program(settings.ansible_project_dir).encode()).hexdigest()
        request=dict(policy,schema_version=1,machine_uuid=machine.uuid,hostname=machine.hostname)
        args=ssh_prefix(settings,machine)+['sudo -n /usr/bin/python3 -I -B -c '+
             shlex.quote(target_program(settings.ansible_project_dir,observer=True))]
        rc,raw,_=runner(args,input_text=json.dumps(request),timeout=60,max_bytes=65536,
            environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        if not isinstance(raw,str) or len(raw.encode())>65536:raise ValueError
        reply=json.loads(raw,object_pairs_hook=unique)
        if not isinstance(reply,dict) or type(reply.get('schema_version')) is not int or reply['schema_version']!=1:raise ValueError
        if set(reply)=={'schema_version','status','code'} and reply['status']=='blocked':
            # Match only a narrow fixed target class, never arbitrary stdout.
            allowed={'final_dns_'+v for v in ('request_unverified','identity_unverified','backend_unverified',
                'ownership_unverified','configuration_changed','outcome_unverified')}
            if reply['code'] not in allowed:raise ValueError
            return {'status':'blocked','code':reply['code']}
        if (rc or set(reply)!={'schema_version','status','helper_sha256','observation'}
                or reply['status']!='ok' or reply['helper_sha256']!=expected):raise ValueError
        validate_observation(reply['observation'],machine,expected_boot_id=expected_boot_id)
        return reply
    except Exception:raise fail('final_dns_probe_unverified','Read-only final DNS evidence is unavailable') from None
