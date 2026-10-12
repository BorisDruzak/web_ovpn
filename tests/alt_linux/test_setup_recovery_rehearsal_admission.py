import copy,json
from types import SimpleNamespace
import pytest
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_create,private_read,private_replace,digest
from alt_deploy.setup_recovery import RecoveryAttemptStore
from alt_deploy.setup_recovery_attempt_context import with_context
from test_setup_recovery_successor import scenario as initial
from test_setup_recovery_credential import codec_fixture

def scenario(root):
    from alt_deploy.setup_recovery_operator import OperatorPlanStore,TerminalPlanStore
    from alt_deploy.setup_recovery_startup_authorization import StartupPlanStore,RecoveryStartupPlans,RecoveryStartupAuthorization
    from alt_deploy.setup_recovery_prepare import RecoveryPreparationCoordinator
    from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    admission,legacy,pair,original,paths=initial(root)
    parent=admission.prepare(**pair,predecessor_sha=original['sha256'])
    planning=copy.copy(legacy);planning.settings=with_context(legacy.settings,parent)
    planning.attempts=RecoveryAttemptStore.for_settings(planning.settings,clock=planning.clock)
    oldbase=planning.plans.load(original['payload']['recovery']['plan_id'],original['payload']['recovery']['sha256'])
    payload=copy.deepcopy(oldbase['payload']);payload['snapshot']['recovery_attempt_context']=parent
    base=planning.plans.create(payload)
    oldstartup=StartupPlanStore(planning.settings.state_root,clock=planning.clock).load(original['payload']['startup']['plan_id'],original['payload']['startup']['sha256'])
    startups=RecoveryStartupPlans(planning,fingerprint=lambda:base['payload']['snapshot']['prerequisites']['source_sha256'])
    startup=startups.create(base['plan_id'],base['sha256'],sssd_unit=oldstartup['payload']['sssd_unit'],effects_ledger=oldstartup['payload']['effects_ledger'])
    refs=dict(recovery=dict(plan_id=base['plan_id'],sha256=base['sha256']),startup=dict(plan_id=startup['plan_id'],sha256=startup['sha256']))
    oldterminal=TerminalPlanStore(planning.settings.state_root,clock=planning.clock).load(original['payload']['terminal']['plan_id'],original['payload']['terminal']['sha256'])
    terminal=TerminalPlanStore(planning.settings.state_root,clock=planning.clock).create(dict(oldterminal['payload'],**refs))
    op=OperatorPlanStore(planning.settings.state_root,clock=planning.clock).create(dict(original['payload'],**refs,recovery_attempt_context=parent,terminal=dict(plan_id=terminal['plan_id'],sha256=terminal['sha256']),snapshot_sha256=digest(payload['snapshot'])))
    store=planning.attempts
    intended=dict(pair,schema_version=1,operator_plan_id=op['plan_id'],operator_plan_sha256=op['sha256'],approved_at=planning.clock().isoformat(),status='operator_execution_intended')
    private_create(store._path(**pair,suffix='.operator-intent.json'),intended)
    private_create(store._path(**pair,suffix='.operator-ready.json'),dict(schema_version=1,intent_sha256=digest(intended),operator_plan_id=op['plan_id'],operator_plan_sha256=op['sha256']))
    private_create(store._path(**pair,suffix='.execution-coordinator-intent.json'),dict(pair,schema_version=1,plan_id=base['plan_id'],plan_sha256=base['sha256'],status='execution_intended',last_verified_phase='not_started'))
    codec,_,_=codec_fixture(root)
    credentials=RecoveryCredentialStore(planning.settings.state_root,codec=codec,attempts=store)
    preparation=RecoveryPreparationCoordinator(planning,credentials=credentials,resolver=lambda host:'192.0.2.11')
    gate=RecoveryStartupAuthorization(preparation=preparation,postwrite=SimpleNamespace(),startup_plan_id=startup['plan_id'],confirmed_startup_sha=startup['sha256'],plans=startups)
    binding=gate.bind_once(base['plan_id'],base['sha256'])
    private_create(store._path(**pair,suffix='.execution-coordinator-phase-bind.json'),dict(schema_version=1,phase='bind',receipt_sha256=digest(binding)))
    def native(command,**kwargs):
        name=command[3]
        if name=='rehearse':return 4,json.dumps(dict(status='error',error=dict(code='backup_rehearsal_failed'))),''
        if name=='guard':value=dict(status='ok',result='control_plane_allowed')
        else:
            value=dict(status='ok',result='backup_created' if name=='create' else 'backup_verified',backup_id='backup-20261011T123456Z-12345678',manifest_sha256='a'*64,component_count=6)
            value.update(services_restored=True) if name=='create' else value.update(evidence_written=True)
        return 0,json.dumps(value),''
    preparation.controller.runner=native
    with pytest.raises(ControlError):preparation.prepare(base['plan_id'],base['sha256'])
    private_create(store._path(**pair,suffix='.execution-coordinator-failed.json'),dict(pair,schema_version=1,status='failed',failed_stage='prepare',last_verified_phase='bind',error_code='recovery_execution_failed'))
    private_create(store._path(**pair,suffix='.operator-failed.json'),dict(schema_version=1,status='UNKNOWN',error_code='recovery_operator_failed'))
    return planning,pair,op,parent,legacy,paths

def test_exact_closed_rehearsal_predecessor_is_archival_only(tmp_path):
    from alt_deploy.setup_recovery_rehearsal_admission import closed_predecessor
    planning,pair,op,parent,legacy,paths=scenario(tmp_path)
    before={p.name:p.read_bytes() for p in planning.attempts.root.iterdir()}
    result=closed_predecessor(legacy.settings,op['plan_id'],op['sha256'],clock=planning.clock)
    assert result['context']==parent and result['snapshot']['recovery_attempt_context']==parent
    assert len(result['inventory'])==16
    assert {p.name:p.read_bytes() for p in planning.attempts.root.iterdir()}==before
    with pytest.raises(ControlError):planning.snapshot(**pair)

@pytest.mark.parametrize('change',['extra_phase','missing','binding','wrong_sha','B_envelope','A_evidence'])
def test_changed_closed_rehearsal_predecessor_refuses(tmp_path,change):
    from alt_deploy.setup_recovery_rehearsal_admission import closed_predecessor
    planning,pair,op,parent,legacy,paths=scenario(tmp_path)
    if change=='extra_phase':private_create(planning.attempts._path(**pair,suffix='.ad-write-intent.json'),{'entered':True})
    elif change=='missing':planning.attempts._path(**pair,suffix='.controller-backup.failed.json').unlink()
    elif change=='binding':private_replace(planning.attempts._path(**pair,suffix='.execution-approval-ready.json'),{'changed':True})
    elif change=='wrong_sha':op['sha256']='0'*64
    elif change=='B_envelope':private_replace(planning.plans.root/(op['payload']['recovery']['plan_id']+'.json'),{'changed':True})
    else:private_replace(legacy.attempts._path(**pair,suffix='.operator-failed.json'),{'changed':True})
    with pytest.raises(ControlError):closed_predecessor(legacy.settings,op['plan_id'],op['sha256'],clock=planning.clock)

def admission_fixture(root):
    from alt_deploy.setup_recovery_rehearsal_admission import RecoveryRehearsalAdmissionService
    planning,pair,op,parent,legacy,paths=scenario(root)
    snapshot=planning.plans.load(op['payload']['recovery']['plan_id'],op['payload']['recovery']['sha256'])['payload']['snapshot']
    class Runtime:
        def inspect(self,machine,selected):return dict(schema_version=1,pair=selected,machine_uuid=machine.uuid,hostname=machine.hostname,footprints_absent=True,no_active_recovery=True)
        def controller(self,**kw):return dict(schema_version=1,native_guard=True,readiness=True,no_active_recovery=True,capacity=dict(required_free_bytes=100,actual_free_bytes=200),backup_audit=dict(backup_id='backup-20261011T123456Z-12345678',rehearsal_failed=True,operation_sha256='a'*64),retained=dict(backup_id='backup-20261011T123456Z-12345678',manifest_sha256='b'*64,verification_sha256='c'*64,tree_sha256='d'*64,protected_metadata_sha256='e'*64,locale=dict(old_locale_refused=True,corrected_locale_passed=True,tool_sources_sha256='f'*64)))
        def bound(self,retained,**kw):return dict(schema_version=1,retained_evidence_unchanged=True,protected_metadata_sha256=retained['protected_metadata_sha256'])
    service=RecoveryRehearsalAdmissionService(legacy.settings,planning_factory=lambda settings:planning,runtime=Runtime(),clock=planning.clock)
    return service,planning,pair,op,parent,legacy,paths

def test_exact_rehearsal_failure_creates_one_C_without_mutating_A_or_B(tmp_path):
    service,planning,pair,op,parent,legacy,paths=admission_fixture(tmp_path)
    prior={str(p):p.read_bytes() for root in (legacy.attempts.root,planning.attempts.root) for p in root.iterdir()}
    original={key:path.read_bytes() for key,path in paths.items()}
    reference=service.prepare(op['plan_id'],op['sha256'])
    assert reference['attempt_id'].startswith('rehearsal-successor-')
    store=RecoveryAttemptStore(planning.settings.state_root,context=reference)
    assert not store.claim_path(**pair).exists()
    assert service.prepare(op['plan_id'],op['sha256'])==reference
    assert {str(p):p.read_bytes() for root in (legacy.attempts.root,planning.attempts.root) for p in root.iterdir()}==prior
    assert {key:path.read_bytes() for key,path in paths.items()}==original

@pytest.mark.parametrize('change',['computer','absence','capacity','locale','bound'])
def test_current_proof_refusal_never_creates_C_relation(tmp_path,change):
    service,planning,pair,op,parent,legacy,paths=admission_fixture(tmp_path)
    if change=='computer':
        read=planning.directory.inspect_computer;planning.directory.inspect_computer=lambda *a:dict(read(*a),kvno=99)
    elif change=='absence':service.runtime.inspect=lambda *a:{'footprints_absent':False}
    elif change=='bound':service.runtime.bound=lambda *a,**kw:{'retained_evidence_unchanged':False}
    else:
        read=service.runtime.controller
        def modified(**kw):
            proof=read(**kw)
            if change=='capacity':proof['capacity']['actual_free_bytes']=1
            else:proof['retained']['locale']['corrected_locale_passed']=False
            return proof
        service.runtime.controller=modified
    with pytest.raises(ControlError):service.prepare(op['plan_id'],op['sha256'])
    assert not (planning.settings.state_root/'setup-recovery-rehearsal-successor-relations').exists()

def test_partial_corrective_descriptor_keeps_permanent_relation(tmp_path,monkeypatch):
    import alt_deploy.setup_recovery_rehearsal_admission as module
    service,planning,pair,op,parent,legacy,paths=admission_fixture(tmp_path);create=module.private_create
    def failure(path,document):
        if path.parent.name=='setup-recovery-rehearsal-successor-admissions':raise OSError('SYNTHETIC_SECRET')
        return create(path,document)
    monkeypatch.setattr(module,'private_create',failure)
    with pytest.raises(ControlError) as error:service.prepare(op['plan_id'],op['sha256'])
    assert 'SYNTHETIC_SECRET' not in str(error.value)
    relation=planning.settings.state_root/'setup-recovery-rehearsal-successor-relations'/(digest(pair)+'.json');before=relation.read_bytes()
    monkeypatch.setattr(module,'private_create',create)
    with pytest.raises(ControlError):service.prepare(op['plan_id'],op['sha256'])
    assert relation.read_bytes()==before

def test_concurrent_corrective_admission_allocates_one_context(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    service,planning,pair,op,parent,legacy,paths=admission_fixture(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(lambda _:service.prepare(op['plan_id'],op['sha256']),range(8)))
    assert all(result==results[0] for result in results)
    assert len(list((planning.settings.state_root/'setup-recovery-rehearsal-successor-admissions').glob('*.json')))==1

def test_corrective_entry_excludes_fresh_planning_and_descendant(tmp_path):
    from alt_deploy.setup_recovery_rehearsal_admission import closed_predecessor
    from alt_deploy.setup_recovery_operator import OperatorPlanStore
    service,planning,pair,op,parent,legacy,paths=admission_fixture(tmp_path)
    reference=service.prepare(op['plan_id'],op['sha256'])
    store=RecoveryAttemptStore(planning.settings.state_root,context=reference)
    private_create(store._path(**pair,suffix='.operator-intent.json'),{'entered':True})
    with pytest.raises(ControlError):service.prepare(op['plan_id'],op['sha256'])
    descendant=OperatorPlanStore(planning.settings.state_root,clock=planning.clock).create(dict(op['payload'],recovery_attempt_context=reference))
    with pytest.raises(ControlError):closed_predecessor(legacy.settings,descendant['plan_id'],descendant['sha256'],clock=planning.clock)
