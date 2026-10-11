"""Bound service preparation/quiescence and read-only password-write gate.

Mutating methods own the controller lifecycle lock. Their future caller must
require exact live execution authorization. No CLI route, password writer or
service restart. The read-only callable runs under the provider's lock.
"""
from __future__ import annotations

import re

from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import digest, private_read
from .setup_recovery import _pair, evidence_document
from .setup_recovery_controller_backup import RecoveryControllerBackup
from . import setup_recovery_backup as backup
from . import setup_recovery_services as services


class RecoveryServiceGate:
    def __init__(self, settings, preparation, *, runtime):
        # Explicit injection prevents an accidentally unconfigured live caller.
        # Production coordinator must construct RecoveryServicesRuntime using
        # the same settings and credential store as preparation.
        self.preparation, self.runtime = preparation, runtime
        self.settings=settings

    def path(self, payload, suffix):
        return self.preparation.attempts._path(**_pair(payload['failed_run_id'],payload['computer_guid']),suffix=suffix)

    def _context(self, args, proof=None):
        payload,claim,sealed,password=args
        if proof is None:
            proof=self.preparation(*args)
        else:
            # The writer's durable intent intentionally excludes the general
            # reserved-state gate. Revalidate only protected evidence here;
            # never remove/ignore that intent or reopen Vault after the final
            # provider credential check. The remote service check follows.
            pair=_pair(payload['failed_run_id'],payload['computer_guid'])
            identity=self.preparation.credentials._reservation(**pair)
            document=private_read(self.preparation.credentials.path(**pair))
            if (private_read(self.preparation.attempts.claim_path(**pair))!=claim
                    or identity['claim_sha256']!=digest(claim) or identity['machine_uuid']!=payload['machine_uuid']
                    or self.preparation.plans.load(claim['plan_id'],claim['plan_sha256'])['payload']!=payload
                    or sealed!=dict(claim_sha256=digest(claim),sealed_sha256=document['sealed_sha256'])
                    or private_read(self.preparation.credentials._ready_path(**pair))!=dict(schema_version=1,
                        claim_sha256=digest(claim),sealed_sha256=document['sealed_sha256'],document_sha256=digest(document))
                    or digest(evidence_document(self.preparation.fresh_check.planning.history.load(pair['failed_run_id'])['raw_files']))
                        !=payload['evidence_sha256']):raise ValueError
        record=private_read(self.preparation.path(payload))
        machine=self.preparation.machines.resolve(payload['machine_uuid'])
        registered=payload['snapshot']['machine']
        if (machine.uuid!=payload['machine_uuid'] or machine.hostname!=registered['hostname'] or machine.ip!=registered['ip']
                or digest(machine.raw)!=registered['registration_sha256']):raise ValueError
        expected=dict(schema_version=1,plan_sha256=claim['plan_sha256'],claim_sha256=digest(claim),
            snapshot_sha256=digest(payload['snapshot']),sealed_sha256=sealed['sealed_sha256'],preparation_sha256=digest(record))
        if any(record[key]!=value for key,value in expected.items() if key!='preparation_sha256'):
            raise ValueError
        pair=_pair(payload['failed_run_id'],payload['computer_guid'])
        if (private_read(self.preparation.attempts._path(**pair,suffix='.preparation-intent.json'))
                !={key:value for key,value in expected.items() if key!='preparation_sha256'}
                or private_read(self.preparation.attempts._path(**pair,suffix='.preparation-ready.json'))
                    !={'schema_version':1,'preparation_sha256':digest(record)}):raise ValueError
        return proof,record,machine,expected

    def _load(self, args, proof=None):
        proof,record,machine,expected=self._context(args,proof);payload=args[0]
        document=private_read(self.path(payload,'.services-preparation.json'))
        if (set(document)!=set(expected)|{'services','services_sha256'} or type(document['schema_version']) is not int
                or any(document[key]!=value for key,value in expected.items())
                or document['services_sha256']!=digest(document['services'])):
            raise ValueError
        services._request(dict(schema_version=1,backup_request=record['backup_request'],backup_receipt=record['workstation_backup'],
            services=document['services'],services_sha256=document['services_sha256'],source_sha256='0'*64),backup=backup)
        if private_read(self.path(payload,'.services-ready.json'))!={'schema_version':1,'services_preparation_sha256':digest(document)}:
            raise ValueError
        return proof,record,machine,document

    def _unchanged(self,args,expected,proof=None):
        current=self._load(args,proof)
        if current[:2]!=expected[:2] or current[3]!=expected[3]:raise ValueError

    @staticmethod
    def _receipt(payload,record,document,receipt):
        expected={key:record['backup_request'][key] for key in ('failed_run_id','computer_guid','machine_uuid','claim_sha256')}
        expected.update(schema_version=1,status='services_quiesced',services_sha256=document['services_sha256'],
            active_services=services._active({'services':document['services']}))
        if (not isinstance(receipt,dict) or set(receipt)!=set(expected)|{'request_sha256'}
                or type(receipt['schema_version']) is not int or any(receipt[key]!=value for key,value in expected.items())
                or not isinstance(receipt['request_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',receipt['request_sha256'])):
            raise ValueError

    def _terminal(self,payload):
        try:self.preparation.attempts.finish(**_pair(payload['failed_run_id'],payload['computer_guid']),
            status='failed',error_code='recovery_services_failed')
        except Exception:pass

    def prepare(self,payload,claim,sealed,password):
        with exclusive_lock(self.settings.lock_file):
            return self._prepare(payload,claim,sealed,password)

    def _prepare(self,payload,claim,sealed,password):
        args=(payload,claim,sealed,password);entered=False
        try:
            context=self._context(args);proof,record,machine,expected=context
            path=self.path(payload,'.services-preparation.json')
            if path.exists() or path.is_symlink() or self.path(payload,'.services-ready.json').exists():raise ValueError
            pair=_pair(payload['failed_run_id'],payload['computer_guid'])
            snapshot=self.runtime.capture_services(machine,**pair,backup_request=record['backup_request'],backup_receipt=record['workstation_backup'])
            if self._context(args)[:2]!=context[:2]:raise ValueError
            document=dict(expected,services=snapshot,services_sha256=digest(snapshot))
            services._request(dict(schema_version=1,backup_request=record['backup_request'],backup_receipt=record['workstation_backup'],
                services=snapshot,services_sha256=document['services_sha256'],source_sha256='0'*64),backup=backup)
            entered=True
            RecoveryControllerBackup._persist(path,document)
            RecoveryControllerBackup._persist(self.path(payload,'.services-ready.json'),
                {'schema_version':1,'services_preparation_sha256':digest(document)})
            self._load(args)
            return dict(pair,status='recovery_services_prepared',services_preparation_sha256=digest(document))
        except Exception:
            if entered:self._terminal(payload)
            raise fail('recovery_services_preparation_failed','Service preparation requires unchanged protected evidence; retained attempts cannot be replayed') from None

    def quiesce(self,payload,claim,sealed,password):
        with exclusive_lock(self.settings.lock_file):
            return self._quiesce(payload,claim,sealed,password)

    def _quiesce(self,payload,claim,sealed,password):
        args=(payload,claim,sealed,password);entered=False
        try:
            context=self._load(args);proof,record,machine,document=context
            intent=self.path(payload,'.services-stop-intent.json');result=self.path(payload,'.services-quiesced.json')
            if any(path.exists() or path.is_symlink() for path in (intent,result)):raise ValueError
            entered=True
            intended={'schema_version':1,'services_preparation_sha256':digest(document)}
            RecoveryControllerBackup._persist(intent,intended)
            self._unchanged(args,context)
            if private_read(intent)!=intended:raise ValueError
            pair=_pair(payload['failed_run_id'],payload['computer_guid'])
            receipt=self.runtime.quiesce_services(machine,**pair,backup_request=record['backup_request'],
                backup_receipt=record['workstation_backup'],snapshot=document['services'])
            self._receipt(payload,record,document,receipt)
            self._unchanged(args,context)
            RecoveryControllerBackup._persist(result,receipt)
            self(*args)
            return receipt
        except Exception:
            if entered:self._terminal(payload)
            raise fail('recovery_services_failed','Service quiescence did not produce current verified evidence; restart and replay are prohibited') from None

    def __call__(self,payload,claim,sealed,password):
        return self._verify((payload,claim,sealed,password))

    def last_service_check(self,payload,claim,sealed,password,prepared):
        proof={key:value for key,value in prepared.items() if key not in ('services_quiesced_verified','services_quiesced_sha256')}
        result=self._verify((payload,claim,sealed,password),proof)
        if result!=prepared:raise fail('recovery_service_prewrite_invalid','Service evidence changed before the directory write')
        return result

    def _verify(self,args,proof=None):
        payload=args[0]
        try:
            context=self._load(args,proof);current_proof,record,machine,document=context
            intent=private_read(self.path(payload,'.services-stop-intent.json'))
            if intent!={'schema_version':1,'services_preparation_sha256':digest(document)}:raise ValueError
            receipt=private_read(self.path(payload,'.services-quiesced.json'))
            self._receipt(payload,record,document,receipt)
            pair=_pair(payload['failed_run_id'],payload['computer_guid'])
            if self.runtime.verify_services(machine,**pair,backup_request=record['backup_request'],
                    backup_receipt=record['workstation_backup'],snapshot=document['services'])!=receipt:raise ValueError
            self._unchanged(args,context,proof)
            if (private_read(self.path(payload,'.services-stop-intent.json'))!=intent
                    or private_read(self.path(payload,'.services-quiesced.json'))!=receipt):raise ValueError
            return dict(current_proof,services_quiesced_verified=True,services_quiesced_sha256=digest(receipt))
        except Exception:
            raise fail('recovery_service_prewrite_invalid','Current attempt-bound service quiescence must verify before the directory password write') from None
