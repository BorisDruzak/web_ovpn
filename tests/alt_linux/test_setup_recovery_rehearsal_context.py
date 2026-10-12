import hashlib
from types import SimpleNamespace
import pytest
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_create,private_replace,digest,private_read
from alt_deploy.setup_recovery import RecoveryAttemptStore
from test_setup_recovery_attempt_context import context as initial_context,PAIR

def context(root):
    parent,_=initial_context(root)
    previous=RecoveryAttemptStore(root,context=parent)
    record=previous._path(**PAIR,suffix='.operator-failed.json')
    private_create(record,dict(schema_version=1,status='UNKNOWN',error_code='recovery_operator_failed'))
    from alt_deploy.setup_recovery_operator import OperatorPlanStore,TerminalPlanStore
    from alt_deploy.setup_recovery_startup_authorization import StartupPlanStore
    from alt_deploy.setup_recovery import RecoveryPlanStore
    envelopes={}
    for name,store in [('operator',OperatorPlanStore(root)),('recovery',RecoveryPlanStore(root)),('startup',StartupPlanStore(root)),('terminal',TerminalPlanStore(root))]:
        plan=store.create({'fixture':'B '+name});path=store.root/(plan['plan_id']+'.json')
        envelopes[name]=dict(plan_id=plan['plan_id'],sha256=plan['sha256'],raw_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    lineage={
        'admission':hashlib.sha256((root/'setup-recovery-successor-admissions'/(parent['attempt_id']+'.json')).read_bytes()).hexdigest(),
        'relation':hashlib.sha256((root/'setup-recovery-successor-relations'/(digest(PAIR)+'.json')).read_bytes()).hexdigest()}
    attempt='rehearsal-successor-'+'4'*64
    document=dict(schema_version=1,status='admitted_rehearsal_successor',attempt_id=attempt,pair=PAIR,
        predecessor_sha256=envelopes['operator']['sha256'],predecessor_files={record.name:hashlib.sha256(record.read_bytes()).hexdigest()},
        proof=dict(predecessor_context=parent,lineage_documents=lineage,envelopes=envelopes))
    reference=dict(PAIR,attempt_id=attempt,admission_sha256=digest(document))
    private_create(root/'setup-recovery-rehearsal-successor-admissions'/(attempt+'.json'),document)
    private_create(root/'setup-recovery-rehearsal-successor-relations'/(digest(PAIR)+'.json'),reference)
    return reference,parent,record

def test_corrective_context_uses_distinct_fixed_namespace(tmp_path):
    reference,parent,record=context(tmp_path)
    corrective=RecoveryAttemptStore.for_settings(SimpleNamespace(state_root=tmp_path,recovery_attempt_context=reference))
    predecessor=RecoveryAttemptStore(tmp_path,context=parent)
    assert corrective.root==tmp_path/'setup-recovery-rehearsal-successor-attempts'/reference['attempt_id']
    assert corrective.claim_path(**PAIR)!=predecessor.claim_path(**PAIR)
    assert corrective.plans.root==predecessor.plans.root
    assert record.exists()

@pytest.mark.parametrize('change',['B_record','B_descriptor_bytes','B_relation_bytes','A_record','wrong_parent_family','wrong_pair','C_relation'])
def test_changed_lineage_refuses_before_corrective_attempt_file(tmp_path,change):
    reference,parent,record=context(tmp_path)
    if change=='B_record':private_replace(record,{'changed':True})
    elif change in ('B_descriptor_bytes','B_relation_bytes'):
        path=(tmp_path/'setup-recovery-successor-admissions'/(parent['attempt_id']+'.json')) if change=='B_descriptor_bytes' else (tmp_path/'setup-recovery-successor-relations'/(digest(PAIR)+'.json'))
        path.write_bytes(path.read_bytes()+b'\n')
    elif change=='A_record':
        path=next((tmp_path/'setup-recovery-attempts').glob('*.operator-failed.json'));private_replace(path,{'changed':True})
    elif change=='wrong_pair':reference=dict(reference,computer_guid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    elif change=='C_relation':private_replace(tmp_path/'setup-recovery-rehearsal-successor-relations'/(digest(PAIR)+'.json'),{'changed':True})
    else:
        path=tmp_path/'setup-recovery-rehearsal-successor-admissions'/(reference['attempt_id']+'.json')
        document=private_read(path);document['proof']['predecessor_context']=reference
        private_replace(path,document)
    with pytest.raises(ControlError):RecoveryAttemptStore(tmp_path,context=reference).claim_path(**PAIR)
    assert not (tmp_path/'setup-recovery-rehearsal-successor-attempts').exists()
