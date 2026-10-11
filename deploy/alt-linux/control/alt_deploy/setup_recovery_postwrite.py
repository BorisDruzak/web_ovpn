"""Protected post-write inputs for a future fixed local importer.

Read-only: no Vault opening, claim creation, directory write, service action or
credential installation. Callers must hold the controller lifecycle lock and
must separately verify current local service/configuration/install state.
The general prewrite fresh-state exclusion remains unchanged.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import re

from .ad_directory import fail
from .setup_plans import digest, private_read
from .setup_recovery import _pair
from .setup_recovery_credential import _ciphertext
from .setup_recovery_provider import PROVIDER, RecoveryPasswordProvider


class RecoveryPostwriteState:
    def __init__(self, *, service_gate, directory, fingerprint):
        self.service_gate=service_gate
        self.directory=directory
        self.fingerprint=fingerprint

    def _protected(self, plan_id, confirmed_sha):
        gate=self.service_gate;base=gate.preparation
        plan=base.plans.load(plan_id,confirmed_sha)
        payload=plan['payload']
        fields={'failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256',
            'execution_available','provider','snapshot'}
        if (set(payload)!=fields or payload['execution_available'] is not True or payload['provider']!=PROVIDER
                or payload['snapshot']['execution_available'] is not False
                or any(payload[key]!=payload['snapshot'][key] for key in
                    ('failed_run_id','computer_guid','machine_uuid','computer_sid','evidence_sha256'))
                or payload['snapshot']['computer']['object_guid']!=payload['computer_guid']
                or payload['snapshot']['computer']['object_sid']!=payload['computer_sid']
                or self.fingerprint()!=payload['snapshot']['prerequisites']['source_sha256']):raise ValueError
        pair=_pair(payload['failed_run_id'],payload['computer_guid'])
        claim=private_read(base.attempts.claim_path(**pair))
        identity=base.credentials._reservation(**pair)
        document=private_read(base.credentials.path(**pair))
        if identity['plan_sha256']!=confirmed_sha or claim['plan_id']!=plan_id or claim['plan_sha256']!=confirmed_sha:
            raise ValueError
        if (set(document)!=set(identity)|{'ciphertext','sealed_sha256'}
                or type(document['schema_version']) is not int
                or any(document[key]!=value for key,value in identity.items())
                or hashlib.sha256(_ciphertext(document['ciphertext']).encode('ascii')).hexdigest()!=document['sealed_sha256']):
            raise ValueError
        sealed=dict(claim_sha256=digest(claim),sealed_sha256=document['sealed_sha256'])
        record=private_read(base.path(payload))
        initial=dict(schema_version=1,plan_sha256=confirmed_sha,claim_sha256=digest(claim),
            snapshot_sha256=digest(payload['snapshot']),sealed_sha256=document['sealed_sha256'])
        if (set(record)!=set(initial)|{'controller_backup','backup_request','workstation_backup','rehearsal_metadata','local_rehearsal'}
                or type(record['schema_version']) is not int
                or any(record[key]!=value for key,value in initial.items())):raise ValueError
        proof={key:value for key,value in initial.items() if key!='plan_sha256'}
        proof.update(controller_backup_verified=True,workstation_backup_verified=True,local_rehearsal_verified=True,
            controller_backup_sha256=digest(record['controller_backup']),
            workstation_backup_sha256=digest(record['workstation_backup']),local_rehearsal_sha256=digest(record['local_rehearsal']))
        # Light context validates protected evidence after intent; it neither
        # invokes the prewrite snapshot nor asserts live service verification.
        _,current,machine,services=gate._load((payload,claim,sealed,None),proof)
        if current!=record:raise ValueError
        if private_read(gate.path(payload,'.services-stop-intent.json'))!={
                'schema_version':1,'services_preparation_sha256':digest(services)}:raise ValueError
        receipt=private_read(gate.path(payload,'.services-quiesced.json'))
        gate._receipt(payload,record,services,receipt)
        proof.update(services_quiesced_verified=True,services_quiesced_sha256=digest(receipt))
        RecoveryPasswordProvider._preparation(payload,claim,sealed,proof)
        intent=private_read(gate.path(payload,'.ad-write-intent.json'))
        intended=dict(pair,schema_version=1,status='write_intended',provider=PROVIDER,
            plan_sha256=confirmed_sha,claim_sha256=digest(claim),sealed_sha256=document['sealed_sha256'],
            preparation_sha256=digest(proof))
        if (set(intent)!=set(intended)|{'created_at'} or type(intent['schema_version']) is not int
                or any(intent[key]!=value for key,value in intended.items())
                or not isinstance(intent['created_at'],str)
                or datetime.fromisoformat(intent['created_at']).utcoffset() is None):raise ValueError
        result=private_read(gate.path(payload,'.ad-write-result.json'))
        expected=dict(pair,schema_version=1,status='directory_password_written',machine_uuid=payload['machine_uuid'],
            computer_sid=payload['computer_sid'],claim_sha256=digest(claim),intent_sha256=digest(intent),
            sealed_sha256=document['sealed_sha256'])
        computer=payload['snapshot']['computer']
        if (set(result)!=set(expected)|{'kvno','pwd_last_set'} or type(result['schema_version']) is not int
                or any(result[key]!=value for key,value in expected.items())
                or type(result['kvno']) is not int or result['kvno']!=computer['kvno']+1
                or not 1<=result['kvno']<=2147483647
                or type(result['pwd_last_set']) is not int or not computer['pwd_last_set']<result['pwd_last_set']<2**63):
            raise ValueError
        return dict(payload=payload,claim=claim,credential_document=document,reservation=identity,
            preparation=record,services_preparation=services,services_receipt=receipt,directory_intent=intent,
            directory_result=result),machine

    def _directory_config(self, expected):
        transport=self.directory.transport;config=transport.config
        current=(config.auth,config.credential_source,transport.minimum_ssf,config.uri)
        if (current[0]!='gssapi' or current[1]!='join-vault' or current[2]<128
                or current[3]!=expected['dc']['uri'] or expected['dc']['is_writable'] is not True
                or not re.fullmatch(r'ldaps?://[a-z0-9][a-z0-9-]{0,62}\.sosnadmin\.local(?::(?:389|636))?',current[3])):
            raise ValueError
        return current

    def load(self, plan_id, confirmed_sha):
        try:
            context,machine=self._protected(plan_id,confirmed_sha)
            payload=context['payload'];expected=payload['snapshot']['computer']
            config=self._directory_config(expected)
            actual=self.directory.inspect_computer(machine.hostname,payload['computer_guid'])
            after=dict(expected,kvno=context['directory_result']['kvno'],pwd_last_set=context['directory_result']['pwd_last_set'])
            if (actual!=after or self._protected(plan_id,confirmed_sha)[0]!=context
                    or self._directory_config(expected)!=config):raise ValueError
            return dict(context,machine=machine)
        except Exception:
            raise fail('recovery_postwrite_invalid',
                'Protected one-write evidence and the pinned directory identity must remain unchanged') from None
