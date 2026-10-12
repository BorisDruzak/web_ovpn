import copy
from types import SimpleNamespace
import pytest
from alt_deploy.setup_plans import private_create,private_read,private_replace,digest,canonical
from alt_deploy.setup_recovery import RecoveryAttemptStore
from alt_deploy.errors import ControlError
from test_setup_recovery_startup_authorization import scenario as startup_fixture

def scenario(root):
    from alt_deploy.setup_recovery_operator import OperatorPlanStore,TerminalPlanStore,reviewed_projection
    gate,startups,preparation,planning,base,startup,paths,ledger,unit,_=startup_fixture(root)
    s=planning.settings;pair={k:base['payload'][k] for k in ('failed_run_id','computer_guid')};snapshot=base['payload']['snapshot']
    refs=dict(recovery=dict(plan_id=base['plan_id'],sha256=base['sha256']),startup=dict(plan_id=startup['plan_id'],sha256=startup['sha256']))
    captured=dict(unit=unit,ledger=ledger,review={'fixture':'review'},terminal_units={})
    terminal=TerminalPlanStore(s.state_root,clock=planning.clock).create(dict(pair,**refs,source_sha256='c'*64,review=captured['review'],terminal_units={}))
    operator=OperatorPlanStore(s.state_root,clock=planning.clock).create(dict(pair,**refs,terminal=dict(plan_id=terminal['plan_id'],sha256=terminal['sha256']),
        operation='selected_recovery_then_normal_policy_once',execution_available=True,machine=snapshot['machine'],computer_sid=snapshot['computer_sid'],computer_ou=snapshot['computer_ou'],employee={k:snapshot['user'][k] for k in ('login','object_guid','object_sid','upn')},snapshot_sha256=digest(snapshot),review_sha256=digest(reviewed_projection(captured)),manual_password_writes=1,renewal_policy='any_change_UNKNOWN_no_retry',setup_continuation='separate_fresh_normal_plan_after_current_terminal_proof'))
    store=planning.attempts
    intended=dict(pair,schema_version=1,operator_plan_id=operator['plan_id'],operator_plan_sha256=operator['sha256'],approved_at=planning.clock().isoformat(),status='operator_execution_intended')
    private_create(store._path(**pair,suffix='.operator-intent.json'),intended)
    private_create(store._path(**pair,suffix='.operator-ready.json'),dict(schema_version=1,intent_sha256=digest(intended),operator_plan_id=operator['plan_id'],operator_plan_sha256=operator['sha256']))
    private_create(store._path(**pair,suffix='.execution-coordinator-intent.json'),dict(pair,schema_version=1,plan_id=base['plan_id'],plan_sha256=base['sha256'],status='execution_intended',last_verified_phase='not_started'))
    bound=gate.bind_once(base['plan_id'],base['sha256'])
    private_create(store._path(**pair,suffix='.execution-coordinator-phase-bind.json'),dict(schema_version=1,phase='bind',receipt_sha256=digest(bound)))
    original=preparation.controller.runner
    def failed_create(command,**kwargs):
        if command[3]=='create':return 4,'{"status":"error","error":{"code":"backup_preflight_failed"}}',''
        return original(command,**kwargs)
    preparation.controller.runner=failed_create
    with pytest.raises(ControlError):preparation.prepare(base['plan_id'],base['sha256'])
    private_create(store._path(**pair,suffix='.execution-coordinator-failed.json'),dict(pair,schema_version=1,status='failed',failed_stage='prepare',last_verified_phase='bind',error_code='recovery_execution_failed'))
    private_create(store._path(**pair,suffix='.operator-failed.json'),dict(schema_version=1,status='UNKNOWN',error_code='recovery_operator_failed'))
    class Runtime:
        def controller(self,**kwargs):return dict(schema_version=1,native_guard=True,readiness=True,no_active_recovery=True,capacity=dict(required_free_bytes=100,actual_free_bytes=200),backup_audit=dict(preflight_failed=True))
        def inspect(self,*args,**kwargs):return dict(schema_version=1,machine_uuid=snapshot['machine']['uuid'],hostname=snapshot['machine']['hostname'],pair=pair,footprints_absent=True,no_active_recovery=True)
    from alt_deploy.setup_recovery_successor import RecoverySuccessorService
    service=RecoverySuccessorService(s,planning=planning,runtime=Runtime())
    return service,planning,pair,operator,paths

def test_real_prewrite_failure_creates_one_isolated_successor_and_preserves_every_byte(tmp_path):
    service,planning,pair,old,paths=scenario(tmp_path)
    legacy={path.name:path.read_bytes() for path in planning.attempts.root.iterdir()}
    originals={k:p.read_bytes() for k,p in paths.items()}
    reference=service.prepare(**pair,predecessor_sha=old['sha256'])
    successor=RecoveryAttemptStore(planning.settings.state_root,context=reference)
    assert not successor.claim_path(**pair).exists()
    assert planning.attempts.claim_path(**pair).exists()
    assert {p.name:p.read_bytes() for p in planning.attempts.root.iterdir()}==legacy
    assert {k:p.read_bytes() for k,p in paths.items()}==originals
    assert service.prepare(**pair,predecessor_sha=old['sha256'])==reference
    with pytest.raises(ControlError):planning.snapshot(**pair)

@pytest.mark.parametrize('change',['missing','phase','write_intent','write_result','controller_receipt','credential','binding','wrong_sha','computer','runtime','capacity','active','audit'])
def test_invalid_admission_does_not_create_relation_or_namespace(tmp_path,change):
    service,planning,pair,old,_=scenario(tmp_path)
    if change=='missing':planning.attempts._path(**pair,suffix='.operator-failed.json').unlink()
    elif change=='phase':private_replace(planning.attempts._path(**pair,suffix='.execution-coordinator-failed.json'),dict(pair,schema_version=1,status='failed',failed_stage='import',last_verified_phase='password_write',error_code='recovery_execution_failed'))
    elif change=='write_intent':private_create(planning.attempts._path(**pair,suffix='.ad-write-intent.json'),{'entered':True})
    elif change=='write_result':private_create(planning.attempts._path(**pair,suffix='.ad-write-result.json'),{'written':True})
    elif change=='controller_receipt':private_create(planning.attempts._path(**pair,suffix='.controller-backup.receipt.json'),{'verified':True})
    elif change=='credential':private_replace(planning.attempts._path(**pair,suffix='.credential-verified.json'),{'changed':True})
    elif change=='binding':private_replace(planning.attempts._path(**pair,suffix='.execution-approval-ready.json'),{'changed':True})
    elif change=='wrong_sha':old['sha256']='0'*64
    elif change=='computer':
        inspect=planning.directory.inspect_computer
        planning.directory.inspect_computer=lambda *a:dict(inspect(*a),kvno=999)
    elif change=='runtime':service.runtime.inspect=lambda *a,**kw:{'footprints_absent':False}
    else:
        controller=service.runtime.controller
        def changed(**kwargs):
            proof=controller(**kwargs)
            if change=='capacity':proof['capacity']['actual_free_bytes']=1
            elif change=='active':proof['no_active_recovery']=False
            else:proof['backup_audit']['preflight_failed']=False
            return proof
        service.runtime.controller=changed
    with pytest.raises(ControlError):service.prepare(**pair,predecessor_sha=old['sha256'])
    assert not (planning.settings.state_root/'setup-recovery-successor-relations').exists()
    assert not (planning.settings.state_root/'setup-recovery-successor-attempts').exists()

def test_concurrent_readonly_planning_can_allocate_only_one_successor(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    service,planning,pair,old,_=scenario(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(lambda _:service.prepare(**pair,predecessor_sha=old['sha256']),range(8)))
    assert all(result==results[0] for result in results)
    assert len(list((planning.settings.state_root/'setup-recovery-successor-relations').glob('*.json')))==1
    assert len(list((planning.settings.state_root/'setup-recovery-successor-admissions').glob('*.json')))==1

def test_descriptor_persistence_failure_keeps_permanent_successor_exclusion(tmp_path,monkeypatch):
    import alt_deploy.setup_recovery_successor as module
    service,planning,pair,old,_=scenario(tmp_path);create=module.private_create
    def failure(path,document):
        if path.parent.name=='setup-recovery-successor-admissions':raise OSError('SYNTHETIC_SECRET')
        return create(path,document)
    monkeypatch.setattr(module,'private_create',failure)
    with pytest.raises(ControlError) as error:service.prepare(**pair,predecessor_sha=old['sha256'])
    assert 'SYNTHETIC_SECRET' not in str(error.value)
    relation=planning.settings.state_root/'setup-recovery-successor-relations'/(digest(pair)+'.json');before=relation.read_bytes()
    monkeypatch.setattr(module,'private_create',create)
    with pytest.raises(ControlError):service.prepare(**pair,predecessor_sha=old['sha256'])
    assert relation.read_bytes()==before
