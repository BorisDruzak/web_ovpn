"""One additive successor after a positively verified prewrite backup failure."""
from __future__ import annotations
import copy,hashlib,re,secrets
from datetime import datetime
from .ad_directory import fail
from .locking import exclusive_lock
from .setup_plans import canonical,digest,private_read,private_create,private_read_bytes
from .setup_recovery import RecoveryAttemptStore,RecoveryPlanStore,_pair,_sync_directory,evidence_document
from .setup_recovery_attempt_context import predecessor_inventory,validate_context
from .setup_recovery_operator import OperatorPlanStore,TerminalPlanStore,reviewed_projection
from .setup_recovery_startup_authorization import StartupPlanStore
from .setup_recovery_credential import _ciphertext
from .setup_recovery_planning import RecoveryPlanningService

SUFFIXES=('.operator-intent.json','.operator-ready.json','.operator-failed.json',
 '.execution-coordinator-intent.json','.execution-coordinator-failed.json','.execution-coordinator-phase-bind.json',
 '.execution-approval.json','.execution-approval-ready.json','.claim.json','.evidence.json','.credential.json',
 '.credential-verified.json','.preparation-intent.json','.controller-backup.intent.json','.controller-backup.failed.json','.receipt.json')

def _equal(left,right):
    if canonical(left)!=canonical(right):raise ValueError('Predecessor evidence mismatch')

def validate_predecessor(settings,pair,sha,*,clock):
    """Archival integrity only; never load expired plans as current authority."""
    return _validate_closed_preparation(settings,pair,sha,clock=clock)

def _validate_closed_preparation(settings,pair,sha,*,clock,context=None):
    """Internal exact closed-chain verifier; callers select a fixed family."""
    if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha):raise ValueError
    if getattr(settings,'recovery_attempt_context',None)!=context:raise ValueError('Mixed closed context')
    store=RecoveryAttemptStore(settings.state_root,context=context)
    read=lambda suffix:private_read(store._path(**pair,suffix=suffix))
    inventory=predecessor_inventory(settings.state_root,pair,context=context)
    if set(inventory)!=set(digest(pair)+suffix for suffix in SUFFIXES):raise ValueError('Unexpected predecessor footprint')
    intended=read('.operator-intent.json');approved=datetime.fromisoformat(intended['approved_at'])
    if approved.tzinfo is None or approved>clock():raise ValueError
    historical=lambda:approved
    operator=OperatorPlanStore(settings.state_root,clock=historical).load('recovery-operator-'+sha,sha)
    p=operator['payload']
    _equal(intended,dict(pair,schema_version=1,operator_plan_id=operator['plan_id'],operator_plan_sha256=sha,approved_at=intended['approved_at'],status='operator_execution_intended'))
    _equal(read('.operator-ready.json'),dict(schema_version=1,intent_sha256=digest(intended),operator_plan_id=operator['plan_id'],operator_plan_sha256=sha))
    _equal(read('.operator-failed.json'),dict(schema_version=1,status='UNKNOWN',error_code='recovery_operator_failed'))
    for key,value in pair.items():_equal(p[key],value)
    fields={'failed_run_id','computer_guid','operation','execution_available','machine','computer_sid','computer_ou','employee','recovery','startup','terminal','snapshot_sha256','review_sha256','manual_password_writes','renewal_policy','setup_continuation'}
    if context is not None:fields.add('recovery_attempt_context')
    _equal(p.get('recovery_attempt_context'),context)
    if (set(p)!=fields or p['operation']!='selected_recovery_then_normal_policy_once' or p['execution_available'] is not True
            or type(p['manual_password_writes']) is not int or p['manual_password_writes']!=1
            or p['renewal_policy']!='any_change_UNKNOWN_no_retry' or p['setup_continuation']!='separate_fresh_normal_plan_after_current_terminal_proof'):raise ValueError
    for ref in (p['recovery'],p['startup'],p['terminal']):
        if not isinstance(ref,dict) or set(ref)!={'plan_id','sha256'}:raise ValueError
    base=RecoveryPlanStore(settings.state_root,clock=historical).load(**dict(plan_id=p['recovery']['plan_id'],confirmed_sha=p['recovery']['sha256']))
    startup=StartupPlanStore(settings.state_root,clock=historical).load(p['startup']['plan_id'],p['startup']['sha256'])
    terminal=TerminalPlanStore(settings.state_root,clock=historical).load(p['terminal']['plan_id'],p['terminal']['sha256'])
    snapshot=base['payload']['snapshot'];attachment=startup['payload'];tp=terminal['payload']
    _equal(snapshot.get('recovery_attempt_context'),context)
    _equal(digest(snapshot),p['snapshot_sha256'])
    for key in ('machine','computer_sid','computer_ou'):_equal(p[key],snapshot[key])
    _equal(p['employee'],{key:snapshot['user'][key] for key in ('login','object_guid','object_sid','upn')})
    _equal(tp['recovery'],p['recovery']);_equal(tp['startup'],p['startup'])
    for key,value in pair.items():_equal(tp[key],value);_equal(base['payload'][key],value)
    _equal(attachment['recovery_plan_id'],base['plan_id']);_equal(attachment['recovery_plan_sha256'],base['sha256'])
    _equal(attachment['recovery_payload_sha256'],digest(base['payload']))
    _equal(p['review_sha256'],digest(reviewed_projection(dict(unit=attachment['sssd_unit'],ledger=attachment['effects_ledger'],review=tp['review'],terminal_units=tp['terminal_units']))))
    expected_identity=dict(pair,machine_uuid=snapshot['machine_uuid'],computer_sid=snapshot['computer_sid'],evidence_sha256=snapshot['evidence_sha256'],
        registration_sha256=snapshot['machine']['registration_sha256'],employee_guid=snapshot['user']['object_guid'],employee_sid=snapshot['user']['object_sid'],computer_ou=snapshot['computer_ou'],ou_identity=snapshot['ou_identity'],dc=snapshot['computer']['dc'])
    _equal(attachment['identity'],expected_identity)
    binding=dict(schema_version=1,recovery_plan_id=base['plan_id'],recovery_plan_sha256=base['sha256'],startup_plan_id=startup['plan_id'],startup_plan_sha256=startup['sha256'],identity=expected_identity,
        recovery_payload_sha256=digest(base['payload']),startup_payload_sha256=digest(attachment),source_sha256=attachment['source_sha256'],sssd_unit_sha256=digest(attachment['sssd_unit']),effects_ledger_sha256=digest(attachment['effects_ledger']))
    _equal(read('.execution-approval.json'),binding)
    _equal(read('.execution-approval-ready.json'),dict(schema_version=1,status='approval_bound',binding_sha256=digest(binding)))
    _equal(read('.execution-coordinator-phase-bind.json'),dict(schema_version=1,phase='bind',receipt_sha256=digest(binding)))
    _equal(read('.execution-coordinator-intent.json'),dict(pair,schema_version=1,plan_id=base['plan_id'],plan_sha256=base['sha256'],status='execution_intended',last_verified_phase='not_started'))
    _equal(read('.execution-coordinator-failed.json'),dict(pair,schema_version=1,status='failed',failed_stage='prepare',last_verified_phase='bind',error_code='recovery_execution_failed'))
    claim=read('.claim.json');reserved=datetime.fromisoformat(claim['created_at'])
    if reserved.tzinfo is None or not approved<=reserved<=clock():raise ValueError
    _equal(claim,dict(pair,schema_version=1,status='reserved',plan_id=base['plan_id'],plan_sha256=base['sha256'],evidence_sha256=base['payload']['evidence_sha256'],created_at=claim['created_at']))
    RecoveryPlanStore(settings.state_root,clock=lambda:reserved).load(base['plan_id'],base['sha256'])
    evidence=read('.evidence.json');_equal(digest(evidence),claim['evidence_sha256'])
    identity=dict(pair,schema_version=1,claim_sha256=digest(claim),plan_sha256=base['sha256'],evidence_sha256=claim['evidence_sha256'],machine_uuid=snapshot['machine_uuid'],computer_sid=snapshot['computer_sid'])
    document=read('.credential.json');ciphertext=_ciphertext(document['ciphertext']);sealed_sha=hashlib.sha256(ciphertext.encode('ascii')).hexdigest()
    _equal(document,dict(identity,ciphertext=ciphertext,sealed_sha256=sealed_sha))
    _equal(read('.credential-verified.json'),dict(schema_version=1,claim_sha256=digest(claim),sealed_sha256=sealed_sha,document_sha256=digest(document)))
    _equal(read('.preparation-intent.json'),dict(schema_version=1,plan_sha256=base['sha256'],claim_sha256=digest(claim),snapshot_sha256=digest(snapshot),sealed_sha256=sealed_sha))
    _equal(read('.controller-backup.intent.json'),dict(identity,snapshot_sha256=digest(snapshot),sealed_sha256=sealed_sha,document_sha256=digest(document)))
    _equal(read('.controller-backup.failed.json'),dict(schema_version=1,status='failed'))
    receipt=read('.receipt.json');finished=datetime.fromisoformat(receipt['finished_at'])
    if finished.tzinfo is None or not reserved<=finished<=clock():raise ValueError
    _equal(receipt,dict(pair,schema_version=1,status='failed',error_code='recovery_preparation_failed',claim_sha256=digest(claim),evidence_sha256=claim['evidence_sha256'],verification=None,finished_at=receipt['finished_at']))
    envelopes={}
    for kind,plan,directory in [('operator',operator,'setup-recovery-operator-plans'),('recovery',base,'setup-recovery-plans'),('startup',startup,'setup-recovery-startup-plans'),('terminal',terminal,'setup-recovery-terminal-plans')]:
        path=settings.state_root/directory/(plan['plan_id']+'.json');_equal(private_read(path),plan)
        envelopes[kind]=dict(plan_id=plan['plan_id'],sha256=plan['sha256'],raw_sha256=hashlib.sha256(private_read_bytes(path)).hexdigest())
    _equal(predecessor_inventory(settings.state_root,pair,context=context),inventory)
    return dict(inventory=inventory,envelopes=envelopes,snapshot=snapshot,evidence=evidence,approved_at=approved.isoformat(),finished_at=finished.isoformat())

class RecoverySuccessorService:
    def __init__(self,settings,*,planning=None,runtime=None):
        if getattr(settings,'recovery_attempt_context',None) is not None:raise ValueError('Admission requires legacy context')
        self.settings=settings;self.planning=planning or RecoveryPlanningService(settings)
        if runtime is None:
            from .setup_recovery_successor_runtime import RecoverySuccessorRuntime
            runtime=RecoverySuccessorRuntime(settings)
        self.runtime=runtime

    def prepare(self,failed_run_id,computer_guid,predecessor_sha):
        try:
            pair=_pair(failed_run_id,computer_guid)
            with exclusive_lock(self.settings.lock_file):
                old=validate_predecessor(self.settings,pair,predecessor_sha,clock=self.planning.clock)
                def guard():_equal(predecessor_inventory(self.settings.state_root,pair),old['inventory'])
                # Fixed closed-attempt read adapter. Public snapshot retains its
                # unconditional claim exclusion; no execution authority here.
                current=self.planning._snapshot(**pair,guard=guard)
                expected=copy.deepcopy(old['snapshot'])
                expected['prerequisites']['source_sha256']=current['prerequisites']['source_sha256']
                _equal(current,expected)
                originals=self.planning.history.load(pair['failed_run_id'])['raw_files']
                _equal(evidence_document(originals),old['evidence'])
                machine=self.planning.machines.resolve(current['machine_uuid'])
                absence=self.runtime.inspect(machine,pair)
                _equal(absence,dict(schema_version=1,machine_uuid=machine.uuid,hostname=machine.hostname,pair=pair,footprints_absent=True,no_active_recovery=True))
                controller=self.runtime.controller(approved_at=old['approved_at'],finished_at=old['finished_at'])
                if (set(controller)!={'schema_version','native_guard','readiness','no_active_recovery','capacity','backup_audit'}
                        or type(controller['schema_version']) is not int or controller['schema_version']!=1
                        or any(controller[key] is not True for key in ('native_guard','readiness','no_active_recovery'))
                        or controller['backup_audit'].get('preflight_failed') is not True):raise ValueError
                capacity=controller['capacity']
                if (set(capacity)!={'required_free_bytes','actual_free_bytes'} or any(type(value) is not int or value<0 for value in capacity.values())
                        or capacity['required_free_bytes']==0 or capacity['actual_free_bytes']<capacity['required_free_bytes']):raise ValueError
                _equal(self.planning._snapshot(**pair,guard=guard),current);guard()
                relation=self.settings.state_root/'setup-recovery-successor-relations'/(digest(pair)+'.json')
                if relation.exists() or relation.is_symlink():
                    reference=private_read(relation);doc=validate_context(self.settings.state_root,reference,pair)
                    if (doc['predecessor_sha256']!=predecessor_sha or doc['proof']['source_sha256']!=current['prerequisites']['source_sha256']):raise ValueError
                    successor=RecoveryAttemptStore(self.settings.state_root,context=reference)
                    if any(successor._path(**pair,suffix=suffix).exists() for suffix in ('.operator-intent.json','.claim.json')):raise ValueError
                    return reference
                attempt='successor-'+secrets.token_hex(32)
                proof=dict(source_sha256=current['prerequisites']['source_sha256'],snapshot_sha256=digest(current),absence=absence,controller=controller,envelopes=old['envelopes'])
                document=dict(schema_version=1,status='admitted_prewrite_successor',attempt_id=attempt,pair=pair,predecessor_sha256=predecessor_sha,predecessor_files=old['inventory'],proof=proof)
                reference=dict(pair,attempt_id=attempt,admission_sha256=digest(document))
                # The exclusive relation is the permanent single-successor
                # reservation, even if later descriptor persistence fails.
                private_create(relation,reference);_sync_directory(relation.parent)
                private_create(self.settings.state_root/'setup-recovery-successor-admissions'/(attempt+'.json'),document)
                _sync_directory(self.settings.state_root/'setup-recovery-successor-admissions')
                for parent in relation.parent.parents:_sync_directory(parent)
                validate_context(self.settings.state_root,reference,pair);guard()
                return reference
        except Exception:
            raise fail('recovery_successor_admission_refused','A closed unchanged prewrite backup failure, fresh capacity and one intact successor relation are required') from None
