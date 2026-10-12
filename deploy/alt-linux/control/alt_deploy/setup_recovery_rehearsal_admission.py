"""Fixed archival B selection; no authority to resume a closed attempt."""
from __future__ import annotations
import re,copy,secrets
from datetime import datetime,timezone
from .ad_directory import fail
from .setup_plans import private_read,private_create,canonical,digest
from .setup_recovery import RecoveryAttemptStore,_pair,_sync_directory,evidence_document
from .setup_recovery_attempt_context import with_context,lineage_documents,predecessor_inventory,validate_context,validate_envelopes
from .setup_recovery_successor import _validate_closed_preparation
from .locking import exclusive_lock

def closed_predecessor(settings,operator_id,sha,*,clock=None):
    try:
        if (getattr(settings,'recovery_attempt_context',None) is not None
                or not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{64}',sha)
                or operator_id!='recovery-operator-'+sha):raise ValueError
        raw=private_read(settings.state_root/'setup-recovery-operator-plans'/(operator_id+'.json'))
        payload=raw['payload'];context=payload['recovery_attempt_context']
        if not isinstance(context,dict) or not isinstance(context.get('attempt_id'),str) or not re.fullmatch('successor-[0-9a-f]{64}',context['attempt_id']):raise ValueError('No corrective descendant')
        pair=_pair(payload['failed_run_id'],payload['computer_guid'])
        selected=with_context(settings,context)
        previous=_validate_closed_preparation(selected,pair,sha,clock=clock or (lambda:datetime.now(timezone.utc)),context=context)
        return dict(previous,pair=pair,context=context,lineage_documents=lineage_documents(settings.state_root,context))
    except Exception:
        raise fail('recovery_rehearsal_predecessor_invalid','One exact closed prewrite successor and all frozen ancestor evidence are required') from None

def _equal(left,right):
    if canonical(left)!=canonical(right):raise ValueError('Corrective evidence changed')

class RecoveryRehearsalAdmissionService:
    def __init__(self,settings,*,planning_factory=None,runtime=None,clock=None):
        if getattr(settings,'recovery_attempt_context',None) is not None:raise ValueError('Admission starts from explicit protected predecessor')
        from .setup_recovery_planning import RecoveryPlanningService
        from .setup_recovery_rehearsal_successor_runtime import RecoveryRehearsalSuccessorRuntime
        self.settings=settings;self.clock=clock or (lambda:datetime.now(timezone.utc))
        self.planning_factory=planning_factory or RecoveryPlanningService
        self.runtime=runtime or RecoveryRehearsalSuccessorRuntime(settings)

    def prepare(self,operator_id,sha):
        try:
            with exclusive_lock(self.settings.lock_file):
                previous=closed_predecessor(self.settings,operator_id,sha,clock=self.clock)
                pair=previous['pair'];parent=previous['context']
                planning=self.planning_factory(with_context(self.settings,parent))
                if planning.attempts.context!=parent:raise ValueError
                def guard():
                    _equal(predecessor_inventory(self.settings.state_root,pair,context=parent),previous['inventory'])
                    _equal(lineage_documents(self.settings.state_root,parent),previous['lineage_documents'])
                    validate_envelopes(self.settings.state_root,previous['envelopes'])
                current=planning._snapshot(**pair,guard=guard)
                expected=copy.deepcopy(previous['snapshot'])
                expected['prerequisites']['source_sha256']=current['prerequisites']['source_sha256']
                _equal(current,expected)
                _equal(evidence_document(planning.history.load(pair['failed_run_id'])['raw_files']),previous['evidence'])
                machine=planning.machines.resolve(current['machine_uuid'])
                absence=self.runtime.inspect(machine,pair)
                _equal(absence,dict(schema_version=1,pair=pair,machine_uuid=machine.uuid,hostname=machine.hostname,footprints_absent=True,no_active_recovery=True))
                controller=self.runtime.controller(approved_at=previous['approved_at'],finished_at=previous['finished_at'])
                if (set(controller)!={'schema_version','native_guard','readiness','no_active_recovery','capacity','backup_audit','retained'}
                        or type(controller['schema_version']) is not int or controller['schema_version']!=1
                        or any(controller[k] is not True for k in ('native_guard','readiness','no_active_recovery'))):raise ValueError
                capacity=controller['capacity']
                if (set(capacity)!={'required_free_bytes','actual_free_bytes'} or any(type(v) is not int or v<0 for v in capacity.values())
                        or capacity['required_free_bytes']==0 or capacity['actual_free_bytes']<capacity['required_free_bytes']):raise ValueError
                audit=controller['backup_audit'];retained=controller['retained']
                if (set(audit)!={'backup_id','rehearsal_failed','operation_sha256'} or audit['rehearsal_failed'] is not True
                        or not isinstance(audit['backup_id'],str) or not re.fullmatch('backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',audit['backup_id'])
                        or not re.fullmatch('[0-9a-f]{64}',audit['operation_sha256'])
                        or set(retained)!={'backup_id','manifest_sha256','verification_sha256','tree_sha256','locale','protected_metadata_sha256'}
                        or retained['backup_id']!=audit['backup_id']
                        or any(not isinstance(retained[k],str) or not re.fullmatch('[0-9a-f]{64}',retained[k]) for k in ('manifest_sha256','verification_sha256','tree_sha256','protected_metadata_sha256'))):raise ValueError
                locale=retained['locale']
                if (set(locale)!={'old_locale_refused','corrected_locale_passed','tool_sources_sha256'}
                        or locale['old_locale_refused'] is not True or locale['corrected_locale_passed'] is not True
                        or not re.fullmatch('[0-9a-f]{64}',locale['tool_sources_sha256'])):raise ValueError
                interval=dict(approved_at=previous['approved_at'],finished_at=previous['finished_at'])
                _equal(self.runtime.bound(retained,**interval,operation_sha256=audit['operation_sha256']),dict(schema_version=1,retained_evidence_unchanged=True,protected_metadata_sha256=retained['protected_metadata_sha256']))
                _equal(planning._snapshot(**pair,guard=guard),current);guard()
                relation=self.settings.state_root/'setup-recovery-rehearsal-successor-relations'/(digest(pair)+'.json')
                if relation.exists() or relation.is_symlink():
                    reference=private_read(relation);document=validate_context(self.settings.state_root,reference,pair)
                    if (document['predecessor_sha256']!=sha or document['proof']['source_sha256']!=current['prerequisites']['source_sha256']
                            or document['proof']['predecessor_context']!=parent or document['proof']['controller']['retained']!=retained):raise ValueError
                    store=RecoveryAttemptStore(self.settings.state_root,context=reference)
                    if any(store._path(**pair,suffix=s).exists() for s in ('.operator-intent.json','.claim.json')):raise ValueError
                    return reference
                attempt='rehearsal-successor-'+secrets.token_hex(32)
                proof=dict(source_sha256=current['prerequisites']['source_sha256'],snapshot_sha256=digest(current),absence=absence,
                    controller=controller,native_interval=interval,envelopes=previous['envelopes'],predecessor_context=parent,lineage_documents=previous['lineage_documents'])
                document=dict(schema_version=1,status='admitted_rehearsal_successor',attempt_id=attempt,pair=pair,
                    predecessor_sha256=sha,predecessor_files=previous['inventory'],proof=proof)
                reference=dict(pair,attempt_id=attempt,admission_sha256=digest(document))
                private_create(relation,reference);_sync_directory(relation.parent)
                private_create(self.settings.state_root/'setup-recovery-rehearsal-successor-admissions'/(attempt+'.json'),document)
                _sync_directory(self.settings.state_root/'setup-recovery-rehearsal-successor-admissions')
                for path in relation.parent.parents:_sync_directory(path)
                validate_context(self.settings.state_root,reference,pair);guard()
                return reference
        except Exception:
            raise fail('recovery_rehearsal_admission_refused','One intact closed locale-rehearsal failure, fresh immutable state and exclusive corrective admission are required') from None
