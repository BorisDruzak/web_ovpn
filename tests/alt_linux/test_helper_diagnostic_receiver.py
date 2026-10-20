"""Diagnostic scope comes from the fixed invocation, never arbitrary stdout."""
import hashlib
import json
import os

import pytest


@pytest.mark.parametrize('component',['desktop.kwallet_repair','remote.krfb','network.final_dns'])
@pytest.mark.parametrize('fault',['none','foreign_context','foreign_result','unsafe','missing','private_code'])
def test_fixed_reader_only_returns_allowlisted_original_claim_diagnostic(tmp_path,component,fault):
    from alt_deploy.helper_diagnostic_target import read_diagnostic
    from alt_deploy.setup_plans import digest
    from alt_deploy.wallet_codes import WALLET_CODES
    from alt_deploy.krfb_program import TARGET_CODES
    from alt_deploy.final_dns_policy import CODES
    nonce='1'*64
    context={'schema_version':1,'kind':'complete_workstation','phase':'final_dns' if component=='network.final_dns' else 'user',
        'job_id':'job-20261020T000000Z-12345678','claim_sha256':nonce,'plan_sha256':'2'*64,
        'machine_uuid':'11111111-2222-3333-4444-555555555555','source_sha256':'3'*64,'policy_sha256':'4'*64,'workflow_policy_sha256':'5'*64}
    scope={'schema_version':1,'component_id':component,'job_id':context['job_id'],'machine_uuid':context['machine_uuid'],
        'plan_sha256':context['plan_sha256'],'operation_sha256':nonce,'context_sha256':digest(context),'helper_sha256':hashlib.sha256(b'published').hexdigest()}
    names={'desktop.kwallet_repair':('alt-kwallet-empty-name-repair','invocation.json','kwallet_dbus_unverified'),
           'remote.krfb':('alt-krfb-user-runtime','manifest.json','krfb_runtime_outcome_unverified'),
           'network.final_dns':('alt-workstation-final-dns','invocation.json','final_dns_rollback_unverified')}
    name,invocation,code=names[component];directory=tmp_path/'var/lib'/name/nonce;directory.mkdir(mode=0o700,parents=True)
    directory.parent.chmod(0o700)
    if component!='remote.krfb':
        helper=tmp_path/'usr/local/libexec'/name;helper.parent.mkdir(parents=True);helper.write_bytes(b'published');helper.chmod(0o700)
    actual=dict(context)
    if fault=='foreign_context':actual['job_id']='job-20261020T000000Z-87654321'
    if fault=='private_code':code='PRIVATE-SENTINEL'
    request={'schema_version':1,'operation_sha256':nonce,'native_context':actual} if component=='desktop.kwallet_repair' else {'schema_version':1,'context':actual}
    result={'status':'unknown' if component!='network.final_dns' else 'outcome_unverified','code':code}
    record={'schema_version':1,'operation_sha256':nonce,'result':result} if component=='desktop.kwallet_repair' else {'schema_version':1,'context':actual,'result':result} if component=='remote.krfb' else result
    if fault=='foreign_result':
        if component=='network.final_dns':record['status']='arbitrary'
        else:record['operation_sha256' if component=='desktop.kwallet_repair' else 'context']='wrong'
    for name,value in ((invocation,request),('result.json',record)):
        path=directory/name;path.write_text(json.dumps(value));path.chmod(0o600)
    if fault=='unsafe':(directory/invocation).chmod(0o666)
    if fault=='missing':(directory/invocation).unlink()
    allowed={'desktop.kwallet_repair':WALLET_CODES,'remote.krfb':TARGET_CODES,'network.final_dns':CODES}
    value=read_diagnostic(scope,allowed,root=tmp_path)
    assert {k:value[k] for k in scope}==scope
    assert 'SENTINEL' not in json.dumps(value)
    if fault=='none':assert value['recorded'] is True and value['code']==code
    else:assert value['recorded'] is False and value['code']=='workflow_helper_diagnostic_unavailable'
