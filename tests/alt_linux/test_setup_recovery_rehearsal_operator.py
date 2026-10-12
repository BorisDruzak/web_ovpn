import copy
from types import SimpleNamespace
import pytest
from alt_deploy.errors import ControlError
from alt_deploy.setup_recovery import RecoveryAttemptStore
from alt_deploy.setup_recovery_attempt_context import with_context
from test_setup_recovery_rehearsal_admission import admission_fixture

def fixture(root,monkeypatch):
    from alt_deploy.setup_recovery_operator import RecoveryOperatorService
    from alt_deploy.setup_recovery_rehearsal_successor_runtime import RecoveryRehearsalSuccessorRuntime
    admission,previous,pair,closed,parent,legacy,paths=admission_fixture(root)
    reference=admission.prepare(closed['plan_id'],closed['sha256'])
    planning=copy.copy(previous);planning.settings=with_context(legacy.settings,reference)
    planning.attempts=RecoveryAttemptStore.for_settings(planning.settings,clock=planning.clock)
    operator=RecoveryOperatorService(planning.settings,planning=planning)
    operator._capture=lambda snapshot:dict(unit={},ledger={},review={'fixture':'review'},terminal_units={})
    class Startup:
        def create(self,*a,**kw):return operator.store.create({'fixture':'startup'})
        def load(self,plan_id,sha,*a):return dict(attachment=operator.store.load(plan_id,sha))
    operator.startup_plans=Startup();calls=[];bound=[]
    def check(self,retained,**kw):
        bound.append((retained,kw));return dict(schema_version=1,retained_evidence_unchanged=True,protected_metadata_sha256=retained['protected_metadata_sha256'])
    monkeypatch.setattr(RecoveryRehearsalSuccessorRuntime,'bound',check)
    operator.pipeline_factory=lambda *a,**kw:SimpleNamespace(terminal=SimpleNamespace(_sources=lambda:['fixed']),execute=lambda *args:(calls.append('execute') or {'status':'normal_policy_handoff_succeeded'}))
    return operator,previous,legacy,pair,reference,calls,bound

def test_corrective_plan_checks_bound_root_evidence_without_execution(tmp_path,monkeypatch):
    operator,previous,legacy,pair,reference,calls,bound=fixture(tmp_path,monkeypatch)
    before={str(p):p.read_bytes() for root in (previous.attempts.root,legacy.attempts.root) for p in root.iterdir()}
    plan=operator.plan(**pair)
    assert plan['payload']['recovery_attempt_context']==reference and calls==[]
    assert bound and all(call[1]['operation_sha256']=='a'*64 for call in bound)
    assert {str(p):p.read_bytes() for root in (previous.attempts.root,legacy.attempts.root) for p in root.iterdir()}==before

def test_changed_bound_evidence_refuses_apply_before_operator_intent(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_rehearsal_successor_runtime import RecoveryRehearsalSuccessorRuntime
    operator,previous,legacy,pair,reference,calls,bound=fixture(tmp_path,monkeypatch)
    plan=operator.plan(**pair)
    monkeypatch.setattr(RecoveryRehearsalSuccessorRuntime,'bound',lambda *a,**kw:False)
    with pytest.raises(ControlError):operator.apply(plan['plan_id'],plan['sha256'])
    assert calls==[] and operator.status(**pair)['status']=='not_started'

def test_native_cli_exposes_only_protected_closed_operator_selector():
    from alt_deploy import cli
    parsed=cli.build_parser().parse_args(['setup','recovery','rehearsal-failure-plan',
        '--predecessor-operator','recovery-operator-'+'a'*64,'--predecessor-sha256','a'*64])
    assert parsed.recovery_action=='rehearsal-failure-plan'
    assert not hasattr(parsed,'machine') and not hasattr(parsed,'computer_guid')

def test_corrective_apply_is_once_only_and_preserves_both_closed_chains(tmp_path,monkeypatch):
    operator,previous,legacy,pair,reference,calls,bound=fixture(tmp_path,monkeypatch)
    prior={str(p):p.read_bytes() for root in (previous.attempts.root,legacy.attempts.root) for p in root.iterdir()}
    plan=operator.plan(**pair);operator.apply(plan['plan_id'],plan['sha256'])
    with pytest.raises(ControlError):operator.apply(plan['plan_id'],plan['sha256'])
    assert calls==['execute']
    assert {str(p):p.read_bytes() for root in (previous.attempts.root,legacy.attempts.root) for p in root.iterdir()}==prior

def test_genuine_corrective_preparation_preserves_A_and_B_claims(tmp_path,monkeypatch):
    import json
    from alt_deploy.setup_recovery_prepare import RecoveryPreparationCoordinator
    from alt_deploy.setup_recovery_credential import RecoveryCredentialStore
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    from alt_deploy.setup_recovery_reserved_state import RecoveryReservedState
    from alt_deploy.setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
    from test_setup_recovery_credential import codec_fixture
    operator,previous,legacy,pair,reference,calls,bound=fixture(tmp_path,monkeypatch)
    prior={str(p):p.read_bytes() for root in (previous.attempts.root,legacy.attempts.root) for p in root.iterdir()}
    envelope=operator.plan(**pair);ref=envelope['payload']['recovery']
    codec,_,_=codec_fixture(tmp_path)
    credentials=RecoveryCredentialStore(operator.settings.state_root,codec=codec,attempts=operator.planning.attempts)
    fresh=RecoveryReservedState(operator.planning,credentials=credentials)
    def native(command,**kw):
        name=command[3]
        if name=='guard':value=dict(status='ok',result='control_plane_allowed')
        else:
            value=dict(status='ok',backup_id='backup-20261011T123456Z-12345678',manifest_sha256='a'*64)
            if name=='create':value.update(result='backup_created',component_count=6,services_restored=True)
            elif name=='verify':value.update(result='backup_verified',component_count=6,evidence_written=True)
            elif name=='rehearse':value.update(result='backup_rehearsed',check_count=11,rehearsal_passed=True)
            else:value.update(result='backup_rehearsed',verification_sha256='b'*64)
        return 0,json.dumps(value),''
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
    assert result['status']=='recovery_prepared' and operator.planning.attempts.claim_path(**pair).exists()
    assert {str(p):p.read_bytes() for root in (previous.attempts.root,legacy.attempts.root) for p in root.iterdir()}==prior
    with pytest.raises(ControlError):preparation.prepare(ref['plan_id'],ref['sha256'])
