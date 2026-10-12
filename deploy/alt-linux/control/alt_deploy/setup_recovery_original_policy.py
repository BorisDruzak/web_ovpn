"""Offline original-policy observation; no snippet removal or service action.

The future terminal approval must bind this receipt before any handoff. Missing
configured attributes are not interpreted as verified defaults. Running policy,
renewal behavior, DNS effects and trust require separate terminal acceptance.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import tempfile


def _request(request,*,policy,backup,kerberos):
    if (not isinstance(request,dict) or set(request)!={'schema_version','policy_request','policy_receipt','source_sha256'}
            or type(request['schema_version']) is not int or request['schema_version']!=1
            or not isinstance(request['source_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',request['source_sha256'])):
        raise ValueError('Invalid fixed original policy request')
    policy._request(request['policy_request'],backup=backup,kerberos=kerberos)


def _local(request,tools,*,policy,backup,probe,native,root,owner,restored):
    bound=request['policy_request'];leaf=policy.path_for(bound,backup=backup,root=root)
    backup._ancestry(leaf,root,owner);backup._directory(leaf,owner)
    if {path.name for path in leaf.iterdir()}!={'request.json','intent.json','original.json','original.conf','verified.json'}:
        raise ValueError('Incomplete retained original policy')
    meta=native.validate_metadata(bound['kerberos_request']['import_request']['rehearsal_request']['metadata'])
    snippet=policy._snippet(meta);policy._directory(root,owner,set() if restored else {Path(policy.SNIPPET).name})
    if not restored:
        info=probe._file(root,policy.SNIPPET,private=True,owner=owner)
        if info.get('gid')!=owner or backup._read(root/policy.SNIPPET.lstrip('/'),info,root=root,owner=owner)!=snippet:
            raise ValueError('Changed retained temporary policy')
    main=probe._file(root,'/etc/sssd/sssd.conf',private=True,owner=owner)
    stored=backup._json(leaf/'original.json',root=root,owner=owner)
    if main!=stored:raise ValueError('Changed original policy metadata')
    original=probe._file(leaf,'/original.conf',private=True,owner=owner)
    content=backup._read(leaf/'original.conf',original,root=leaf,owner=owner)
    if content!=backup._read(root/'etc/sssd/sssd.conf',main,root=root,owner=owner):
        raise ValueError('Changed original policy bytes')
    receipt=policy._receipt(bound,tools,snippet,backup)
    intent=dict(schema_version=1,request_sha256=backup.digest(bound),tools_sha256=backup.digest(tools),
        original_sha256=backup.digest(stored),snippet_sha256=receipt['snippet_sha256'])
    for name,value in (('request.json',bound),('intent.json',intent),('verified.json',receipt)):
        if backup.digest(backup._json(leaf/name,root=root,owner=owner))!=backup.digest(value):raise ValueError('Changed retained policy records')
    if backup.digest(receipt)!=backup.digest(request['policy_receipt']):raise ValueError('Changed requested policy receipt')
    policy._unchanged_tools(tools,probe=probe,root=root,owner=owner)
    return dict(main=main,original=original,content=content,meta=meta,receipt=receipt)


def _values(value,meta,policy):
    if (not isinstance(value,dict) or set(value)!=set(policy._values(meta))
            or any(not isinstance(item,str) or len(item)>1024 or not re.fullmatch('[ -~]*',item) for item in value.values())
            or value['domains']!=meta['realm'].upper() or value['id_provider']!='ad'
            or value['auth_provider'] not in ('','ad') or value['access_provider'] not in ('','ad')
            or value['dyndns_update'] not in ('','true','false')
            or value['ad_enable_dns_sites'] not in ('','true','false')
            or (value['ad_maximum_machine_account_password_age'] and not re.fullmatch('[0-9]{1,6}',value['ad_maximum_machine_account_password_age']))
            or (value['ad_enabled_domains'] and value['ad_enabled_domains'].lower()!=meta['realm'].lower())
            or any(not re.fullmatch(r'[A-Za-z0-9.,_ :\-]*',value[key]) for key in ('ad_server','ad_backup_server'))):
        raise ValueError('Invalid original configured policy')
    return value


def _parse(state,tools,*,policy,backup,probe,native,runner,root,owner,leaf):
    modules=policy._modules(probe=probe,runner=runner,root=root,owner=owner)
    if modules!=tools['ldb_modules']:raise ValueError('Changed original policy modules')
    with tempfile.TemporaryDirectory(prefix='original-policy-',dir=leaf) as temporary:
        work=Path(temporary)
        for path in ('config','config/conf.d','sss','sss/db','sss/pubconf','sss/pipes'):(work/path).mkdir(mode=0o700)
        files={'/config/sssd.conf':state['content'],**policy.SANDBOX_NSS}
        for path,content in files.items():backup._write(work/path.lstrip('/'),content)
        metadata={path:probe._file(work,path,private=True,owner=owner) for path in files}
        def guard():
            if list((work/'config/conf.d').iterdir()):raise ValueError('Unexpected isolated original snippet')
            for path,content in files.items():
                if (probe._file(work,path,private=True,owner=owner)!=metadata[path]
                        or backup._read(work/path.lstrip('/'),metadata[path],root=work,owner=owner)!=content):
                    raise ValueError('Changed isolated original policy')
            policy._unchanged_tools(tools,probe=probe,root=root,owner=owner)
        output=None;database=None
        for index,command in enumerate(policy._commands(work,state['meta'],native=native,owner=owner)):
            guard()
            if database is not None and probe._file(work,'/sss/db/config.ldb',private=True,owner=owner)!=database:
                raise ValueError('Changed isolated original database')
            output=policy._run(runner,command);guard()
            if index==1:
                database=probe._file(work,'/sss/db/config.ldb',private=True,owner=owner)
                if not database['present'] or not database['size']:raise ValueError('Original database missing')
            elif index==2 and probe._file(work,'/sss/db/config.ldb',private=True,owner=owner)!=database:
                raise ValueError('Changed isolated original database during read')
        def unique(pairs):
            value={}
            for key,item in pairs:
                if key in value:raise ValueError('Duplicate original policy field')
                value[key]=item
            return value
        return _values(json.loads(output,object_pairs_hook=unique),state['meta'],policy)


def _observe(request,*,policy,backup,probe,native,kerberos,importer,collect,runner,root,owner,restored):
    if os.geteuid()!=owner or not root.is_absolute():raise ValueError('Fixed root original policy observation required')
    bound=copy.deepcopy(request);_request(bound,policy=policy,backup=backup,kerberos=kerberos)
    lower=bound['policy_request']['kerberos_request']
    if kerberos.verify_artifacts(lower,backup=backup,probe=probe,native=native,importer=importer,
            collect=collect,runner=runner,root=root,owner=owner)!=bound['policy_request']['kerberos_receipt']:
        raise ValueError('Changed retained original machine evidence')
    tools=policy._tools(probe=probe,runner=runner,root=root,owner=owner)
    planned=lower['import_request']['rehearsal_request']['backup_request']['facts']['tools']
    if any(tools[path]!=planned[name] for name,path in (('sssd','/usr/sbin/sssd'),('bwrap','/usr/bin/bwrap'))):
        raise ValueError('Changed planned original policy executable')
    args=dict(policy=policy,backup=backup,probe=probe,native=native,root=root,owner=owner,restored=restored)
    state=_local(bound,tools,**args)
    leaf=policy.path_for(bound['policy_request'],backup=backup,root=root)
    values=_parse(state,tools,policy=policy,backup=backup,probe=probe,native=native,runner=runner,root=root,owner=owner,leaf=leaf)
    # Close native/collector callbacks before the last protected policy rereads.
    if kerberos._verify_artifacts(lower,backup=backup,probe=probe,native=native,importer=importer,
            collect=collect,root=root,owner=owner)!=bound['policy_request']['kerberos_receipt']:
        raise ValueError('Changed final retained original machine evidence')
    if _local(bound,tools,**args)!=state or backup.digest(request)!=backup.digest(bound):raise ValueError('Changed original policy during observation')
    return dict(schema_version=1,status='original_sssd_policy_observed',request_sha256=backup.digest(bound),
        policy_receipt_sha256=backup.digest(state['receipt']),original_sha256=backup.digest(state['main']),
        tools_sha256=backup.digest(tools),configured_values=values,defaults_verified=False,
        running_policy_verified=False,trust_verified=False)


def observe(request,*,policy,backup,probe,native,kerberos,importer,collect,runner,root=Path('/'),owner=0):
    return _observe(request,policy=policy,backup=backup,probe=probe,native=native,kerberos=kerberos,
        importer=importer,collect=collect,runner=runner,root=root,owner=owner,restored=False)


def verify_restored(request,expected,*,policy,backup,probe,native,kerberos,importer,collect,runner,root=Path('/'),owner=0):
    approved=copy.deepcopy(expected)
    result=_observe(request,policy=policy,backup=backup,probe=probe,native=native,kerberos=kerberos,
        importer=importer,collect=collect,runner=runner,root=root,owner=owner,restored=True)
    if backup.digest(result)!=backup.digest(approved) or backup.digest(expected)!=backup.digest(approved):
        raise ValueError('Original policy differs from approved observation')
    return result
