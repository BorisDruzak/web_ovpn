"""Read only fixed root-owned invocation/results; no GUI, mutation or selector."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat


FIELDS={'schema_version','component_id','job_id','machine_uuid','plan_sha256','operation_sha256','context_sha256','helper_sha256'}
TARGETS={'desktop.kwallet_repair':('alt-kwallet-empty-name-repair','invocation.json'),
         'remote.krfb':('alt-krfb-user-runtime','manifest.json'),
         'network.final_dns':('alt-workstation-final-dns','invocation.json')}
OUTCOMES={'noop','repaired','configured','blocked','unknown','waiting','applied_verified','rolled_back_verified','outcome_unverified'}


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def _read(path,root,*,mode,limit=65536):
    owner=0 if root==Path('/') else os.getuid()
    for parent in path.parents:
        if not stat.S_ISDIR(parent.lstat().st_mode):raise ValueError
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=mode
                or info.st_nlink!=1):raise ValueError
        raw=stream.read(limit+1)
        if len(raw)>limit:raise ValueError
        return raw


def _unique(pairs):
    value={}
    for k,v in pairs:
        if k in value:raise ValueError
        value[k]=v
    return value


def read_diagnostic(scope,codes,*,root=Path('/')):
    if (not isinstance(scope,dict) or set(scope)!=FIELDS or type(scope['schema_version']) is not int
            or scope['schema_version']!=1 or scope['component_id'] not in TARGETS
            or not isinstance(scope['job_id'],str) or not re.fullmatch('job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',scope['job_id'])
            or not isinstance(scope['machine_uuid'],str) or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',scope['machine_uuid'])
            or any(not isinstance(scope[k],str) or not re.fullmatch('[0-9a-f]{64}',scope[k])
                for k in ('plan_sha256','operation_sha256','context_sha256','helper_sha256'))):raise ValueError
    unavailable=dict(scope,recorded=False,outcome='outcome_unverified',code='workflow_helper_diagnostic_unavailable')
    try:
        root=Path(root);component=scope['component_id'];name,first=TARGETS[component]
        directory=root/'var/lib'/name/scope['operation_sha256'];owner=0 if root==Path('/') else os.getuid()
        for path in (directory.parent,directory):
            info=path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError
        if component!='remote.krfb':
            helper=root/'usr/local/libexec'/name
            if hashlib.sha256(_read(helper,root,mode=0o700,limit=262144)).hexdigest()!=scope['helper_sha256']:raise ValueError
        invocation=json.loads(_read(directory/first,root,mode=0o600),object_pairs_hook=_unique)
        context=invocation['native_context' if component=='desktop.kwallet_repair' else 'context']
        if (not isinstance(context,dict) or _digest(context)!=scope['context_sha256']
                or any(context.get(k)!=scope[k] for k in ('job_id','machine_uuid','plan_sha256'))
                or context.get('claim_sha256',context.get('operation_sha256'))!=scope['operation_sha256']):raise ValueError
        value=json.loads(_read(directory/'result.json',root,mode=0o600),object_pairs_hook=_unique)
        if component=='desktop.kwallet_repair':
            if value['operation_sha256']!=scope['operation_sha256']:raise ValueError
            result=value['result']
        elif component=='remote.krfb':
            if value['context']!=context:raise ValueError
            result=value['result']
        else:result=value
        outcome=result['status'];code=result.get('code')
        if outcome not in OUTCOMES or code is not None and code not in codes[component]:raise ValueError
        if outcome not in ('noop','repaired','configured','applied_verified') and code is None:raise ValueError
        if component=='network.final_dns':
            try:raw_failure=_read(directory/'failure.json',root,mode=0o600)
            except FileNotFoundError:
                if (directory/'failure.json').is_symlink():raise ValueError
                raw_failure=None
            if raw_failure is not None:
                failure=json.loads(raw_failure,object_pairs_hook=_unique)
                if (not isinstance(failure,dict) or set(failure)!={'schema_version','stage','code','rollback_code'}
                        or type(failure['schema_version']) is not int or failure['schema_version']!=1
                        or failure['stage'] not in ('exchange','activate','observe_after','verify_after')
                        or failure['code'] not in codes[component]
                        or failure['rollback_code'] is not None and failure['rollback_code'] not in codes[component]
                        or outcome not in ('rolled_back_verified','outcome_unverified')):raise ValueError
                code=failure['code']
        return dict(scope,recorded=True,outcome=outcome,code=code)
    except Exception:return unavailable
