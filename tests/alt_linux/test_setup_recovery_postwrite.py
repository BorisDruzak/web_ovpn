from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest, private_read, private_replace
from test_setup_recovery_service_gate import scenario


def written(root):
    from alt_deploy.setup_recovery_postwrite import RecoveryPostwriteState
    gate,args,record,snapshot,receipt,calls,paths=scenario(root)
    gate.prepare(*args);gate.quiesce(*args)
    payload,claim,sealed,password=args
    proof=gate(*args)
    intent=dict(schema_version=1,failed_run_id=payload['failed_run_id'],computer_guid=payload['computer_guid'],
        status='write_intended',provider='guid_only_unicodepwd_v1',plan_sha256=claim['plan_sha256'],
        claim_sha256=digest(claim),sealed_sha256=sealed['sealed_sha256'],preparation_sha256=digest(proof),
        created_at='2026-10-11T12:00:00+00:00')
    result={key:payload[key] for key in ('failed_run_id','computer_guid','machine_uuid','computer_sid')}
    computer=copy.deepcopy(payload['snapshot']['computer'])
    computer['kvno']+=1;computer['pwd_last_set']+=10000000
    result.update(schema_version=1,status='directory_password_written',claim_sha256=digest(claim),
        sealed_sha256=sealed['sealed_sha256'],intent_sha256=digest(intent),kvno=computer['kvno'],pwd_last_set=computer['pwd_last_set'])
    for suffix,value in (('.ad-write-intent.json',intent),('.ad-write-result.json',result)):
        private_replace(gate.path(payload,suffix),value)
    directory=SimpleNamespace(transport=SimpleNamespace(minimum_ssf=128,config=SimpleNamespace(auth='gssapi',
        credential_source='join-vault',uri=computer['dc']['uri'])),inspect_computer=lambda *a:copy.deepcopy(computer))
    state=RecoveryPostwriteState(service_gate=gate,directory=directory,
        fingerprint=lambda:payload['snapshot']['prerequisites']['source_sha256'])
    return state,gate,args,record,result,computer,paths


def test_loads_only_protected_one_write_result_without_vault_or_mutation(tmp_path):
    state,gate,args,record,result,computer,paths=written(tmp_path)
    before={key:path.read_bytes() for key,path in paths.items()}
    gate.preparation.credentials.open=lambda **kw:pytest.fail('readonly postwrite state opened Vault')
    current=state.load(args[1]['plan_id'],args[1]['plan_sha256'])
    assert current['directory_result']==result
    assert current['preparation']==record
    assert current['machine'].uuid==args[0]['machine_uuid']
    assert args[3] not in str(current)
    assert {key:path.read_bytes() for key,path in paths.items()}==before


@pytest.mark.parametrize('change',['cipher','identity','extra'])
def test_preexisting_cipher_corruption_with_updated_ready_marker_is_refused(tmp_path,change):
    state,gate,args,record,result,computer,paths=written(tmp_path)
    pair={key:args[0][key] for key in ('failed_run_id','computer_guid')}
    credentials=gate.preparation.credentials
    path=credentials.path(**pair);document=private_read(path)
    if change=='cipher':document['ciphertext']='$ANSIBLE_VAULT;1.1;AES256\nffff\n'
    elif change=='identity':document['machine_uuid']='00000000-0000-0000-0000-000000000001'
    else:document['extra']='SYNTHETIC_SECRET'
    private_replace(path,document)
    marker=private_read(credentials._ready_path(**pair));marker['document_sha256']=digest(document)
    private_replace(credentials._ready_path(**pair),marker)
    with pytest.raises(ControlError):state.load(args[1]['plan_id'],args[1]['plan_sha256'])


@pytest.mark.parametrize('change',['missing_result','missing_intent','result_extra','result_guid','result_sid',
    'result_kvno','result_timestamp','result_intent','intent_extra','intent_proof','intent_provider',
    'missing_preparation_ready','missing_service_ready','history','source','directory','transport','expired'])
def test_unbound_or_changed_postwrite_evidence_is_refused(tmp_path,change):
    state,gate,args,record,result,computer,paths=written(tmp_path)
    payload=args[0]
    if change.startswith('missing_'):
        suffix={'missing_result':'.ad-write-result.json','missing_intent':'.ad-write-intent.json',
            'missing_preparation_ready':'.preparation-ready.json','missing_service_ready':'.services-ready.json'}[change]
        gate.path(payload,suffix).unlink()
    elif change.startswith('result_'):
        value=private_read(gate.path(payload,'.ad-write-result.json'))
        field={'result_extra':'extra','result_guid':'computer_guid','result_sid':'computer_sid',
            'result_kvno':'kvno','result_timestamp':'pwd_last_set','result_intent':'intent_sha256'}[change]
        value[field]=0 if field in ('kvno','pwd_last_set') else 'f'*64
        private_replace(gate.path(payload,'.ad-write-result.json'),value)
    elif change.startswith('intent_'):
        value=private_read(gate.path(payload,'.ad-write-intent.json'))
        field={'intent_extra':'extra','intent_proof':'preparation_sha256','intent_provider':'provider'}[change]
        value[field]='f'*64
        private_replace(gate.path(payload,'.ad-write-intent.json'),value)
        result['intent_sha256']=digest(value);private_replace(gate.path(payload,'.ad-write-result.json'),result)
    elif change=='history':
        value=private_read(paths['run']);value['reboot_required']=False;private_replace(paths['run'],value)
    elif change=='source':state.fingerprint=lambda:'f'*64
    elif change=='directory':computer['object_sid']='S-1-5-21-1-2-3-999'
    elif change=='transport':state.directory.transport.minimum_ssf=127
    else:
        from datetime import timedelta
        original=gate.preparation.plans.clock
        gate.preparation.plans.clock=lambda:original()+timedelta(hours=1)
    with pytest.raises(ControlError):state.load(args[1]['plan_id'],args[1]['plan_sha256'])


@pytest.mark.parametrize('change',['cipher','result','history','source','transport','expired','terminal'])
def test_remote_read_drift_is_rechecked_without_returning_a_context(tmp_path,change):
    state,gate,args,record,result,computer,paths=written(tmp_path)
    original=state.directory.inspect_computer
    def changed(*a):
        current=original(*a)
        if change=='cipher':
            pair={key:args[0][key] for key in ('failed_run_id','computer_guid')}
            path=gate.preparation.credentials.path(**pair);value=private_read(path)
            value['ciphertext']='SYNTHETIC_SECRET';private_replace(path,value)
        elif change=='result':
            result['kvno']+=1;private_replace(gate.path(args[0],'.ad-write-result.json'),result)
        elif change=='history':
            value=private_read(paths['run']);value['reboot_required']=False;private_replace(paths['run'],value)
        elif change=='source':state.fingerprint=lambda:'f'*64
        elif change=='transport':state.directory.transport.config.uri='ldap://other.sosnadmin.local'
        elif change=='expired':
            from datetime import timedelta
            clock=gate.preparation.plans.clock
            gate.preparation.plans.clock=lambda:clock()+timedelta(hours=1)
        else:
            gate.preparation.attempts.finish(args[0]['failed_run_id'],args[0]['computer_guid'],
                status='ambiguous',error_code='recovery_write_ambiguous')
        return current
    state.directory.inspect_computer=changed
    with pytest.raises(ControlError) as caught:state.load(args[1]['plan_id'],args[1]['plan_sha256'])
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
