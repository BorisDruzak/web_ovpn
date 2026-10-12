"""Pre-reservation original configured-policy baseline, without future receipts.

No AD/contact/authentication/service action or persistent workstation artifact.
Only private isolated parser scratch is written and removed. Defaults and
normal-policy effects require a separate reviewed manifest and terminal approval.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import tempfile

def _sha(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None


def _request(request,*,backup,native):
    if (not isinstance(request,dict) or set(request)!={'schema_version','backup_request','metadata','source_sha256'}
            or type(request['schema_version']) is not int or request['schema_version']!=1 or not _sha(request['source_sha256'])):
        raise ValueError('Invalid original policy baseline request')
    backup._request(request['backup_request']);meta=native.validate_metadata(request['metadata'])
    if meta['hostname']!=request['backup_request']['hostname']:raise ValueError('Baseline hostname differs from selected facts')
    return meta


def _protected(facts,*,policy,backup,probe,root,owner):
    if set(facts['files'])!=set(probe.AUTH_FILES) or set(facts['tools'])!=set(probe.TOOLS):
        raise ValueError('Incomplete original baseline dependencies')
    for path,private in probe.AUTH_FILES.items():
        if probe._file(root,path,private=private,owner=owner)!=facts['files'][path]:
            raise ValueError('Changed original baseline authentication files')
    for name,path in probe.TOOLS.items():
        metadata={key:value for key,value in facts['tools'][name].items() if key!='package'}
        if probe._file(root,path,maximum=probe.MAX_TOOL_BYTES,owner=owner)!=metadata:
            raise ValueError('Changed original baseline executable')
    policy._directory(root,owner,set())
    main=probe._file(root,'/etc/sssd/sssd.conf',private=True,owner=owner)
    if main.get('present') is not True or main.get('gid')!=owner:raise ValueError('Original baseline main configuration unavailable')
    return dict(main=main,content=backup._read(root/'etc/sssd/sssd.conf',main,root=root,owner=owner))


def projection(receipt,*,original,policy,native,meta):
    """Stable fields shared by the before-write baseline and post-install receipt."""
    base={'schema_version','status','request_sha256','original_sha256','tools_sha256','configured_values',
        'defaults_verified','running_policy_verified','trust_verified'}
    if not isinstance(receipt,dict):raise ValueError('Invalid original baseline projection')
    status=receipt.get('status');fields=base|({'policy_receipt_sha256'} if status=='original_sssd_policy_observed' else set())
    if (status not in ('original_sssd_policy_baseline','original_sssd_policy_observed') or set(receipt)!=fields
            or type(receipt['schema_version']) is not int or receipt['schema_version']!=1
            or any(receipt[key] is not False for key in ('defaults_verified','running_policy_verified','trust_verified'))
            or any(not _sha(receipt[key]) for key in fields if key.endswith('_sha256'))):
        raise ValueError('Invalid original baseline projection')
    values=original._values(copy.deepcopy(receipt['configured_values']),native.validate_metadata(meta),policy)
    return dict(schema_version=1,original_sha256=receipt['original_sha256'],tools_sha256=receipt['tools_sha256'],
        configured_values=values,defaults_verified=False,running_policy_verified=False,trust_verified=False)


def observe(request,*,original,policy,backup,probe,native,collect,runner,root=Path('/'),owner=0):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root original baseline observation required')
    bound=copy.deepcopy(request);meta=_request(bound,backup=backup,native=native)
    facts=bound['backup_request']['facts']
    if backup.digest(collect())!=backup.digest(facts):raise ValueError('Stale original policy baseline facts')
    args=dict(policy=policy,backup=backup,probe=probe,root=root,owner=owner)
    state=_protected(facts,**args);tools=policy._tools(probe=probe,runner=runner,root=root,owner=owner)
    if any(tools[path]!=facts['tools'][name] for name,path in (('sssd','/usr/sbin/sssd'),('bwrap','/usr/bin/bwrap'))):
        raise ValueError('Changed planned original baseline parser')
    if _protected(facts,**args)!=state:raise ValueError('Changed original baseline during dependency read')
    # This directory is unrelated to future recovery/import records and is
    # removed on every exit. Its ancestry is verified before creating scratch.
    parent=root/'var/lib';backup._ancestry(parent/'baseline-scratch',root,owner)
    with tempfile.TemporaryDirectory(prefix='alt-original-policy-',dir=parent) as temporary:
        leaf=Path(temporary);backup._directory(leaf,owner)
        values=original._parse(dict(state,meta=meta),tools,policy=policy,backup=backup,probe=probe,
            native=native,runner=runner,root=root,owner=owner,leaf=leaf)
    if backup.digest(collect())!=backup.digest(facts):raise ValueError('Changed final original baseline facts')
    # End all native/collector callbacks with local reads of every planned
    # authentication file/tool, parser module and original snippet condition.
    policy._unchanged_tools(tools,probe=probe,root=root,owner=owner)
    if _protected(facts,**args)!=state or backup.digest(request)!=backup.digest(bound):
        raise ValueError('Changed original baseline during observation')
    result=dict(schema_version=1,status='original_sssd_policy_baseline',request_sha256=backup.digest(bound),
        original_sha256=backup.digest(state['main']),tools_sha256=backup.digest(tools),configured_values=values,
        defaults_verified=False,running_policy_verified=False,trust_verified=False)
    projection(result,original=original,policy=policy,native=native,meta=meta)
    return result
