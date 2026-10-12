import copy
from types import SimpleNamespace
import pytest
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_read
from alt_deploy.setup_recovery import RecoveryAttemptStore
from test_setup_recovery_successor import scenario

def fixture(root):
    from alt_deploy.setup_recovery_attempt_context import with_context
    from alt_deploy.setup_recovery_operator import RecoveryOperatorService
    admission,planning,pair,old,paths=scenario(root)
    reference=admission.prepare(**pair,predecessor_sha=old['sha256'])
    scoped=copy.copy(planning);scoped.settings=with_context(planning.settings,reference);scoped.attempts=RecoveryAttemptStore.for_settings(scoped.settings,clock=scoped.clock)
    operator=RecoveryOperatorService(scoped.settings,planning=scoped)
    operator._capture=lambda snapshot:dict(unit={},ledger={},review={'fixture':'review'},terminal_units={})
    class Startup:
        def create(self,*a,**kw):return operator.store.create({'fixture':'startup'})
        def load(self,plan_id,sha,*a):return dict(attachment=operator.store.load(plan_id,sha))
    operator.startup_plans=Startup();calls=[]
    operator.pipeline_factory=lambda *a,**kw:SimpleNamespace(terminal=SimpleNamespace(_sources=lambda:['fixed']),execute=lambda *args:(calls.append('execute') or {'status':'normal_policy_handoff_succeeded'}))
    return operator,planning,pair,reference,old,calls

def test_successor_plan_binds_context_and_does_not_hide_original_failure(tmp_path):
    operator,legacy,pair,reference,old,calls=fixture(tmp_path)
    original={p.name:p.read_bytes() for p in legacy.attempts.root.iterdir()}
    plan=operator.plan(**pair)
    assert plan['payload']['recovery_attempt_context']==reference
    base=operator.planning.plans.load(plan['payload']['recovery']['plan_id'],plan['payload']['recovery']['sha256'])
    assert base['payload']['snapshot']['recovery_attempt_context']==reference
    assert calls==[]
    assert {p.name:p.read_bytes() for p in legacy.attempts.root.iterdir()}==original
    assert private_read(legacy.attempts._path(**pair,suffix='.operator-failed.json'))['status']=='UNKNOWN'

def test_exact_successor_plan_enters_once_and_never_rewrites_predecessor(tmp_path):
    operator,legacy,pair,reference,old,calls=fixture(tmp_path)
    original={p.name:p.read_bytes() for p in legacy.attempts.root.iterdir()}
    plan=operator.plan(**pair)
    operator.apply(plan['plan_id'],plan['sha256'])
    with pytest.raises(ControlError):operator.apply(plan['plan_id'],plan['sha256'])
    assert calls==['execute'] and operator.status(**pair)['status']=='successful'
    assert {p.name:p.read_bytes() for p in legacy.attempts.root.iterdir()}==original

def test_wrong_context_rejects_plan_before_intent(tmp_path):
    operator,legacy,pair,reference,old,calls=fixture(tmp_path)
    plan=operator.plan(**pair)
    operator.planning.attempts=legacy.attempts
    with pytest.raises(ControlError):operator.apply(plan['plan_id'],plan['sha256'])
    assert calls==[]

def test_production_coordinator_components_all_share_the_successor(tmp_path):
    from alt_deploy.setup_recovery_execution import RecoveryExecutionCoordinator
    operator,legacy,pair,reference,old,calls=fixture(tmp_path)
    coordinator=RecoveryExecutionCoordinator(operator.planning,startup_plan_id='fixture',confirmed_startup_sha='a'*64,terminal_authorization=lambda *a:True,identity=lambda *a:True,operator_guard=lambda:True)
    for store in (coordinator.preparation.attempts,coordinator.preparation.credentials.attempts,coordinator.preparation.controller.attempts,coordinator.preparation.gate.attempts,coordinator.provider.attempts,coordinator.importer.attempts):
        assert store.context==reference
        assert store.claim_path(**pair)!=legacy.attempts.claim_path(**pair)

def test_factory_uses_protected_plan_context_and_refuses_wrong_selected_pair(tmp_path,monkeypatch):
    import alt_deploy.setup_recovery_operator as module
    operator,legacy,pair,reference,old,calls=fixture(tmp_path);plan=operator.plan(**pair)
    seen=[]
    monkeypatch.setattr(module,'RecoveryOperatorService',lambda settings:(seen.append(settings) or SimpleNamespace(settings=settings)))
    selected=module.operator_for_plan(legacy.settings,plan['plan_id'],plan['sha256'],expected_pair=pair,clock=legacy.clock)
    assert selected.settings.recovery_attempt_context==reference
    assert getattr(legacy.settings,'recovery_attempt_context',None) is None
    wrong=dict(pair,computer_guid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    with pytest.raises(ControlError):module.operator_for_plan(legacy.settings,plan['plan_id'],plan['sha256'],expected_pair=wrong,clock=legacy.clock)
    assert len(seen)==1

def test_native_cli_supports_successor_plan_and_explicit_archival_selector():
    from alt_deploy import cli
    args=cli.build_parser().parse_args(['setup','recovery','successor-plan','--failed-run','run','--computer-guid','guid','--predecessor-sha256','a'*64])
    assert args.recovery_action=='successor-plan' and args.predecessor_sha256=='a'*64
    selected=cli.build_parser().parse_args(['setup','recovery','status','--failed-run','run','--computer-guid','guid','--operator-plan','recovery-operator-'+'b'*64])
    assert selected.operator_plan.endswith('b'*64)

def test_genuine_preparation_reserves_successor_without_opening_legacy_attempt(tmp_path):
    import json
    from alt_deploy.setup_recovery_prepare import RecoveryPreparationCoordinator
    from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    from alt_deploy.setup_recovery_reserved_state import RecoveryReservedState
    from alt_deploy.setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
    from test_setup_recovery_credential import codec_fixture
    operator,legacy,pair,reference,old,calls=fixture(tmp_path)
    previous={p.name:p.read_bytes() for p in legacy.attempts.root.iterdir()}
    envelope=operator.plan(**pair);ref=envelope['payload']['recovery']
    codec,_,_=codec_fixture(tmp_path)
    credentials=RecoveryCredentialStore(operator.settings.state_root,codec=codec,attempts=operator.planning.attempts)
    fresh=RecoveryReservedState(operator.planning,credentials=credentials)
    def native(command,**kwargs):
        name=command[3]
        if name=='guard':result=dict(status='ok',result='control_plane_allowed')
        else:
            result=dict(status='ok',backup_id='backup-20261011T123456Z-12345678',manifest_sha256='a'*64)
            if name=='create':result.update(result='backup_created',component_count=6,services_restored=True)
            elif name=='verify':result.update(result='backup_verified',component_count=6,evidence_written=True)
            elif name=='rehearse':result.update(result='backup_rehearsed',check_count=11,rehearsal_passed=True)
            else:result.update(result='backup_rehearsed',verification_sha256='b'*64)
        return 0,json.dumps(result),''
    controller=RecoveryControllerBackup(operator.settings,credentials=credentials,fresh_check=fresh,runner=native)
    base=RecoveryWorkstationBackupRuntime(operator.settings,credentials=credentials)
    class Runtime:
        backup_request=base.backup_request
        def create_backup(self,*a,**kw):return {'manifest_sha256':'c'*64}
        verify_backup=create_backup
        def create_rehearsal(self,*a,**kw):return {'request_sha256':'d'*64}
        verify_rehearsal=create_rehearsal
    preparation=RecoveryPreparationCoordinator(operator.planning,credentials=credentials,controller=controller,runtime=Runtime(),resolver=lambda host:'192.0.2.11')
    result=preparation.prepare(ref['plan_id'],ref['sha256'])
    assert result['status']=='recovery_prepared'
    claim=private_read(operator.planning.attempts.claim_path(**pair))
    assert claim['plan_sha256']==ref['sha256']
    assert {p.name:p.read_bytes() for p in legacy.attempts.root.iterdir()}==previous
    assert private_read(legacy.attempts._path(**pair,suffix='.receipt.json'))['status']=='failed'
    with pytest.raises(ControlError):preparation.prepare(ref['plan_id'],ref['sha256'])

def test_legacy_reservation_cannot_consume_a_successor_execution_plan(tmp_path):
    operator,legacy,pair,reference,old,calls=fixture(tmp_path)
    plan=operator.plan(**pair);ref=plan['payload']['recovery']
    raw=legacy.history.load(pair['failed_run_id'])['raw_files']
    with pytest.raises(ControlError) as error:legacy.attempts.reserve(ref['plan_id'],ref['sha256'],raw)
    assert error.value.code=='recovery_attempt_context_mismatch'
