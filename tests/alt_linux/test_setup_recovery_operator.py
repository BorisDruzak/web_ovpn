import copy
from types import SimpleNamespace
import pytest
from alt_deploy.setup_plans import digest,private_read
from alt_deploy.errors import ControlError
from test_setup_recovery_prepare import scenario as preparation_fixture

def fixture(root,monkeypatch):
    from alt_deploy.setup_recovery_operator import RecoveryOperatorService
    preparation,planning,base,*_=preparation_fixture(root)
    calls=[]
    service=RecoveryOperatorService(planning.settings,planning=planning)
    review=dict(baseline={'fixture':'baseline'},effects={'fixture':'review'},effects_sha256=digest({'fixture':'review'}),runtime_dependencies={},environment_files={})
    service._capture=lambda snapshot:copy.deepcopy(dict(review=review,unit={},ledger={},terminal_units={}))
    class Startup:
        def create(self,*args,**kwargs):return service.store.create({'fixture':'startup'})
        def load(self,startid,startsha,*args):return dict(attachment=service.store.load(startid,startsha))
    service.startup_plans=Startup()
    def pipeline(*args,**kwargs):
        def execute(*args):calls.append('execute');return {'status':'normal_policy_handoff_succeeded'}
        return SimpleNamespace(terminal=SimpleNamespace(_sources=lambda:['fixed terminal source']),execute=execute)
    service.pipeline_factory=pipeline
    return service,planning,base,calls

def test_plan_has_all_exact_children_and_does_not_execute(tmp_path,monkeypatch):
    service,planning,old,calls=fixture(tmp_path,monkeypatch);pair={k:old['payload'][k] for k in ('failed_run_id','computer_guid')}
    plan=service.plan(**pair);assert calls==[]
    payload=plan['payload'];assert payload['execution_available'] is True
    assert payload['operation']=='selected_recovery_then_normal_policy_once'
    assert payload['terminal']['sha256'] and payload['startup']['sha256'] and payload['recovery']['sha256']
    assert not planning.attempts.claim_path(**pair).exists()

def test_wrong_top_sha_cannot_enter_any_stage(tmp_path,monkeypatch):
    service,_,old,calls=fixture(tmp_path,monkeypatch);plan=service.plan(old['payload']['failed_run_id'],old['payload']['computer_guid'])
    with pytest.raises(ControlError):service.apply(plan['plan_id'],'0'*64)
    assert calls==[]

def test_exact_confirmation_one_execution_and_permanent_replay_exclusion(tmp_path,monkeypatch):
    service,_,old,calls=fixture(tmp_path,monkeypatch);plan=service.plan(old['payload']['failed_run_id'],old['payload']['computer_guid'])
    result=service.apply(plan['plan_id'],plan['sha256']);assert result['status']=='normal_policy_handoff_succeeded'
    with pytest.raises(ControlError):service.apply(plan['plan_id'],plan['sha256'])
    assert calls==['execute']

def test_review_drift_refuses_before_operator_intent(tmp_path,monkeypatch):
    service,_,old,calls=fixture(tmp_path,monkeypatch);plan=service.plan(old['payload']['failed_run_id'],old['payload']['computer_guid'])
    capture=service._capture
    def drift(snapshot):result=capture(snapshot);result['review']['effects_sha256']='0'*64;return result
    service._capture=drift
    with pytest.raises(ControlError):service.apply(plan['plan_id'],plan['sha256'])
    assert calls==[]

def test_replaced_operator_intent_during_persistence_cannot_enter_pipeline(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_operator import RecoveryControllerBackup
    from alt_deploy.setup_plans import private_replace
    service,_,old,calls=fixture(tmp_path,monkeypatch);plan=service.plan(old['payload']['failed_run_id'],old['payload']['computer_guid'])
    original=RecoveryControllerBackup._persist
    def replaced(path,value):
        original(path,value)
        if path.name.endswith('.operator-intent.json'):private_replace(path,dict(value,status='replaced'))
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',replaced)
    with pytest.raises(ControlError):service.apply(plan['plan_id'],plan['sha256'])
    assert calls==[]

def test_diagnostic_graph_change_does_not_expand_or_revoke_seed_authority(tmp_path,monkeypatch):
    service,_,old,calls=fixture(tmp_path,monkeypatch);capture=service._capture
    def initial(snapshot):result=capture(snapshot);result['ledger']['inventory_sha256']='a'*64;return result
    service._capture=initial;plan=service.plan(old['payload']['failed_run_id'],old['payload']['computer_guid'])
    def changed(snapshot):result=capture(snapshot);result['ledger']['inventory_sha256']='b'*64;return result
    service._capture=changed
    service.apply(plan['plan_id'],plan['sha256']);assert calls==['execute']

def test_operator_result_changed_by_terminal_callback_cannot_support_continuation(tmp_path,monkeypatch):
    from alt_deploy.setup_plans import private_replace
    service,_,old,calls=fixture(tmp_path,monkeypatch);plan=service.plan(old['payload']['failed_run_id'],old['payload']['computer_guid'])
    returned=service.apply(plan['plan_id'],plan['sha256']);pair={key:old['payload'][key] for key in ('failed_run_id','computer_guid')}
    original=service.pipeline_factory
    def pipeline(*args,**kwargs):
        value=original(*args,**kwargs)
        def verify(*args):
            path=service._path(pair,'result');private_replace(path,dict(private_read(path),status='UNKNOWN'));return returned
        value.terminal._operate=verify;return value
    service.pipeline_factory=pipeline
    with pytest.raises(ControlError):service._verify_terminal_locked(**pair)
