"""Read only the selected user's wallet readiness through a fixed receiver."""
import hashlib
import json
from pathlib import Path
import re
import shlex

import yaml

from .ad_directory import fail
from .component_catalog import _regular,_StrictLoader
from .kwallet_program import target_program
from .target_transport import ssh_prefix
from .wallet_codes import WALLET_CODES


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError
        result[key]=value
    return result


def specification(project):
    try:
        path=Path(project)/'roles/kwallet_empty_name_repair/defaults/main.yml';_regular(path)
        values=yaml.load(path.read_text(encoding='utf-8'),Loader=_StrictLoader)
        name=values['kwallet_repair_new_name'];previous=values['kwallet_repair_previous_helper_sha256']
        if (not isinstance(name,str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}',name)
                or not isinstance(previous,list) or len(previous)>32 or len(set(previous))!=len(previous)
                or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in previous)):raise ValueError
        return {'wallet_name':name,'previous_helper_sha256':list(previous),
                'helper_sha256':hashlib.sha256(target_program(project).encode()).hexdigest()}
    except Exception:raise fail('kwallet_specification_unverified','Published wallet repair settings are invalid') from None


def validate_observation(value,request,expected_boot_id=None):
    if (not isinstance(value,dict) or set(value)!={'schema_version','machine_uuid','hostname','boot_id','login',
            'uid','gid','wallet_name','helper_sha256','installed_helper_sha256','helper_installed',
            'disposition','readiness_sha256','snapshot_sha256'}
            or type(value['schema_version']) is not int or value['schema_version']!=1
            or any(value[k]!=request[k] for k in ('machine_uuid','hostname','login','wallet_name','helper_sha256'))
            or type(value['helper_installed']) is not bool or value['disposition'] not in ('noop','repair')
            or any(type(value[k]) is not int or value[k]<=0 for k in ('uid','gid'))
            or not isinstance(value['boot_id'],str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['boot_id'])
            or expected_boot_id is not None and value['boot_id']!=expected_boot_id):raise ValueError
    for key in ('readiness_sha256','snapshot_sha256'):
        if not isinstance(value[key],str) or not re.fullmatch('[0-9a-f]{64}',value[key]):raise ValueError
    if value['helper_installed']:
        if value['installed_helper_sha256'] not in [request['helper_sha256'],*request['previous_helper_sha256']]:raise ValueError
    elif value['installed_helper_sha256'] is not None:raise ValueError
    if hashlib.sha256(canonical({k:v for k,v in value.items() if k!='snapshot_sha256'})).hexdigest()!=value['snapshot_sha256']:
        raise ValueError
    return value


def observe(settings,machine,user,*,expected_boot_id=None,runner=None):
    try:
        if (not isinstance(user,dict) or not isinstance(user.get('login'),str)
                or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,62}',user['login'])
                or user.get('upn')!=user['login']+'@sosnadmin.local'):raise ValueError
        if runner is None:
            from .ad_transport import bounded_run
            runner=bounded_run
        request=dict(specification(settings.ansible_project_dir),schema_version=1,machine_uuid=machine.uuid,
                     hostname=machine.hostname,login=user['login'])
        command=ssh_prefix(settings,machine)+['sudo -n /usr/bin/python3 -I -B -c '+
            shlex.quote(target_program(settings.ansible_project_dir,observer=True))]
        rc,raw,_=runner(command,input_text=json.dumps(request),timeout=60,max_bytes=65536,
                        environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        if not isinstance(raw,str) or len(raw.encode())>65536:raise ValueError
        document=json.loads(raw,object_pairs_hook=unique)
        if not isinstance(document,dict) or type(document.get('schema_version')) is not int or document['schema_version']!=1:raise ValueError
        if set(document)=={'schema_version','status','code'} and document['status']=='blocked':
            if not isinstance(document['code'],str) or document['code'] not in WALLET_CODES:raise ValueError
            return {'status':'blocked','code':document['code']}
        if rc or set(document)!={'schema_version','status','observation'} or document['status']!='ok':raise ValueError
        value=validate_observation(document['observation'],request,expected_boot_id)
        return {'status':'ok','observation':value}
    except Exception:raise fail('kwallet_probe_unverified','Read-only selected-user wallet evidence is unavailable') from None
