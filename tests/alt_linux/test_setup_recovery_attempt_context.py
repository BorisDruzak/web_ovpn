import hashlib
from types import SimpleNamespace
import pytest
from alt_deploy.setup_plans import private_create, private_replace, digest
from alt_deploy.setup_recovery import RecoveryAttemptStore
from alt_deploy.errors import ControlError

PAIR = dict(failed_run_id='setup-run-'+'1'*32, computer_guid='11111111-2222-3333-4444-555555555555')

def context(root):
    legacy=RecoveryAttemptStore(root)
    previous=legacy._path(**PAIR,suffix='.operator-failed.json')
    private_create(previous,dict(schema_version=1,status='UNKNOWN',error_code='recovery_operator_failed'))
    attempt='successor-'+'2'*64
    from alt_deploy.setup_recovery_operator import OperatorPlanStore,TerminalPlanStore
    from alt_deploy.setup_recovery_startup_authorization import StartupPlanStore
    from alt_deploy.setup_recovery import RecoveryPlanStore
    envelopes={}
    for name,store in [('operator',OperatorPlanStore(root)),('recovery',RecoveryPlanStore(root)),('startup',StartupPlanStore(root)),('terminal',TerminalPlanStore(root))]:
        plan=store.create({'fixture':name});path=store.root/(plan['plan_id']+'.json')
        envelopes[name]=dict(plan_id=plan['plan_id'],sha256=plan['sha256'],raw_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    document=dict(schema_version=1,status='admitted_prewrite_successor',attempt_id=attempt,pair=PAIR,
        predecessor_sha256='3'*64,predecessor_files={previous.name:hashlib.sha256(previous.read_bytes()).hexdigest()},
        proof={'fixture':'validated admission','envelopes':envelopes})
    reference=dict(PAIR,attempt_id=attempt,admission_sha256=digest(document))
    private_create(root/'setup-recovery-successor-admissions'/(attempt+'.json'),document)
    private_create(root/'setup-recovery-successor-relations'/(digest(PAIR)+'.json'),reference)
    return reference,previous

def test_replaced_predecessor_envelope_refuses_new_attempt_paths(tmp_path):
    reference,_=context(tmp_path)
    from alt_deploy.setup_recovery_operator import OperatorPlanStore
    plan=OperatorPlanStore(tmp_path).create({'fixture':'old operator'})
    path=tmp_path/'setup-recovery-operator-plans'/(plan['plan_id']+'.json')
    admission=tmp_path/'setup-recovery-successor-admissions'/(reference['attempt_id']+'.json')
    from alt_deploy.setup_plans import private_read
    document=private_read(admission);document['proof']['envelopes']['operator']=dict(plan_id=plan['plan_id'],sha256=plan['sha256'],raw_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    private_replace(admission,document);reference['admission_sha256']=digest(document)
    private_replace(tmp_path/'setup-recovery-successor-relations'/(digest(PAIR)+'.json'),reference)
    private_replace(path,{'replaced':True})
    with pytest.raises(ControlError):RecoveryAttemptStore.for_settings(SimpleNamespace(state_root=tmp_path,recovery_attempt_context=reference))

def test_explicit_context_separates_paths_and_preserves_legacy(tmp_path):
    reference,previous=context(tmp_path)
    settings=SimpleNamespace(state_root=tmp_path,recovery_attempt_context=reference)
    successor=RecoveryAttemptStore.for_settings(settings)
    old=RecoveryAttemptStore(tmp_path)
    assert successor.claim_path(**PAIR)!=old.claim_path(**PAIR)
    assert successor.plans.root==old.plans.root
    assert previous.exists()
    assert successor.root==tmp_path/'setup-recovery-successor-attempts'/reference['attempt_id']

def test_legacy_has_no_ambient_successor_routing(tmp_path):
    reference,previous=context(tmp_path)
    old=RecoveryAttemptStore(tmp_path)
    assert old._path(**PAIR,suffix='.operator-failed.json')==previous

@pytest.mark.parametrize('change',['relation','descriptor','predecessor','extra_predecessor','pair','id','symlink'])
def test_changed_context_or_predecessor_refuses_before_new_file(tmp_path,change):
    reference,previous=context(tmp_path)
    if change=='relation':private_replace(tmp_path/'setup-recovery-successor-relations'/(digest(PAIR)+'.json'),dict(reference,admission_sha256='0'*64))
    elif change=='descriptor':private_replace(tmp_path/'setup-recovery-successor-admissions'/(reference['attempt_id']+'.json'),{'changed':True})
    elif change=='predecessor':private_replace(previous,{'changed':True})
    elif change=='extra_predecessor':private_create(previous.with_name(digest(PAIR)+'.ad-write-intent.json'),{'entered':True})
    elif change=='pair':reference=dict(reference,computer_guid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    elif change=='id':reference=dict(reference,attempt_id='../escape')
    else:
        path=tmp_path/'setup-recovery-successor-admissions'/(reference['attempt_id']+'.json')
        target=path.with_suffix('.moved');path.rename(target);path.symlink_to(target)
    with pytest.raises(ControlError):
        RecoveryAttemptStore.for_settings(SimpleNamespace(state_root=tmp_path,recovery_attempt_context=reference)).claim_path(**PAIR)
    assert not (tmp_path/'setup-recovery-successor-attempts').exists()

def test_wrong_pair_refuses_even_with_valid_context(tmp_path):
    reference,_=context(tmp_path)
    store=RecoveryAttemptStore.for_settings(SimpleNamespace(state_root=tmp_path,recovery_attempt_context=reference))
    with pytest.raises(ControlError):store.claim_path(PAIR['failed_run_id'],'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')

@pytest.mark.parametrize('component',['provider','prewrite','backup'])
def test_default_component_credentials_use_explicit_context(tmp_path,component):
    reference,_=context(tmp_path);settings=SimpleNamespace(state_root=tmp_path,recovery_attempt_context=reference)
    if component=='provider':
        from alt_deploy.setup_recovery_provider import RecoveryPasswordProvider
        instance=RecoveryPasswordProvider(settings)
    elif component=='prewrite':
        from alt_deploy.setup_recovery_prewrite import RecoveryPrewriteGate
        instance=RecoveryPrewriteGate(settings,machines=None,fresh_check=None)
    else:
        from alt_deploy.setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
        instance=RecoveryWorkstationBackupRuntime(settings)
    assert instance.credentials.attempts.context==reference
