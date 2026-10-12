from __future__ import annotations
import copy
from datetime import timedelta
from types import SimpleNamespace
import pytest
from alt_deploy.errors import ControlError
from test_setup_recovery_history import scenario as history_scenario, RUN, UUID, NOW, OU
from test_setup_service import scenario as service_scenario

GUID = 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa'

def scenario(root):
    _, paths = history_scenario(root)
    service, machine, user, observed, computer, calls = service_scenario(root)
    original = __import__('alt_deploy.setup_plans', fromlist=['private_read']).private_read(paths['plan'])['payload']
    user.update(original['user'])
    observed.update(domain='sosnadmin.local', trust=True, sssd=True, user_lookup=True)
    computer.update(exists=True, objects=[dict(object_guid=GUID, object_sid='S-1-5-21-111-222-333-1002',
        dn='CN=alt-a1-pc3,'+OU, dns_hostname='alt-a1-pc3.sosnadmin.local')])
    terminal = dict(status='successful', terminal_id='terminal-synthetic', failed_run_id=RUN,
        computer_guid=GUID, computer_sid=computer['objects'][0]['object_sid'], machine_uuid=UUID,
        computer_ou=OU, domain='sosnadmin.local', employee_guid=user['object_guid'], employee_sid=user['object_sid'],
        finished_at=NOW.isoformat(), terminal_receipt_sha256='a'*64, execution_plan_id='recovery-'+'b'*64,
        execution_plan_sha256='b'*64, evidence_sha256=__import__('alt_deploy.setup_recovery_history',fromlist=['RecoveryHistoryStore']).RecoveryHistoryStore(root).load(RUN)['identity']['evidence_sha256'])
    original_start = service.planner.start
    def start(*args, **kwargs):
        result = original_start(*args, **kwargs)
        computer['objects'][0]['object_sid'] = terminal['computer_sid']
        return result
    service.planner.start = start
    service.clock = lambda: NOW + timedelta(minutes=1)
    service.plans.clock = service.clock
    return service, paths, user, observed, computer, calls, terminal

def build(service, terminal, verifier=True):
    from alt_deploy.setup_recovery_continuation import RecoveryContinuationService
    return RecoveryContinuationService(service.settings, setup=service,
        terminal_verifier=(lambda failed_run_id, computer_guid: copy.deepcopy(terminal)) if verifier else None)

def test_resolution_missing_verifier_fails_closed(tmp_path):
    service, paths, *_, terminal = scenario(tmp_path)
    with pytest.raises(ControlError, match='terminal'):
        build(service, terminal, False).plan(RUN, GUID)
    assert not (tmp_path/'setup-recovery-resolutions').exists()

def test_new_normal_plan_applies_and_preserves_original_history(tmp_path):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    before = {key:path.read_bytes() for key,path in paths.items()}
    continuation = build(service, terminal)
    plan = continuation.plan(RUN, GUID)
    assert plan['plan_id'].startswith('setup-')
    assert 'domain_join' not in plan['payload']['changes']
    assert calls == []
    assert {key:path.read_bytes() for key,path in paths.items()} == before
    result = service.apply(plan['plan_id'], plan['sha256'])
    assert result['status'] == 'successful'
    assert result['run_id'] != RUN
    assert service.assignments.get(UUID)['revision'] == 2
    preserved = continuation.resolutions.load(RUN, GUID)['evidence']['files']
    import base64
    assert {key:base64.b64decode(value['bytes_b64']) for key,value in preserved.items()} == before
    assert {key:path.read_bytes() for key,path in paths.items() if key != 'binding'} == {key:value for key,value in before.items() if key != 'binding'}
    with pytest.raises(ControlError): service.apply(__import__('alt_deploy.setup_plans', fromlist=['private_read']).private_read(paths['plan'])['plan_id'], __import__('alt_deploy.setup_plans', fromlist=['private_read']).private_read(paths['plan'])['sha256'])
    assert len(calls) == 1

@pytest.mark.parametrize('change', ['failed','employee_guid','employee_sid','computer_guid','computer_sid','computer_ou','stale','future','trust','user_guid','user_sid','ou_guid'])
def test_drift_and_invalid_terminal_fail_closed(tmp_path, change):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    if change == 'failed': terminal['status']='failed'
    elif change == 'stale': terminal['finished_at']=(NOW-timedelta(hours=1)).isoformat()
    elif change == 'future': terminal['finished_at']=(NOW+timedelta(hours=1)).isoformat()
    elif change == 'trust': observed['trust']=False
    elif change == 'user_guid': user['object_guid']=GUID
    elif change == 'user_sid': user['object_sid']='S-1-5-21-111-222-333-1234'
    elif change == 'ou_guid': service.directory.ous=lambda: [dict(dn=OU,object_guid=GUID)]
    else: terminal[change]='forged'
    before={key:path.read_bytes() for key,path in paths.items()}
    with pytest.raises(ControlError): build(service,terminal).plan(RUN,GUID)
    assert calls == []
    assert {key:path.read_bytes() for key,path in paths.items()} == before

def test_apply_revalidates_terminal_and_trust_without_execution(tmp_path):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    plan=build(service,terminal).plan(RUN,GUID)
    terminal['status']='failed'
    with pytest.raises(ControlError): service.apply(plan['plan_id'],plan['sha256'])
    assert calls == []
    assert service.assignments.get(UUID)['result']=='failed'

def test_apply_rechecks_fresh_machine_trust_before_binding_revision(tmp_path):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    plan=build(service,terminal).plan(RUN,GUID)
    before=paths['binding'].read_bytes()
    observed['trust']=False
    with pytest.raises(ControlError): service.apply(plan['plan_id'],plan['sha256'])
    assert calls == [] and paths['binding'].read_bytes()==before

@pytest.mark.parametrize('field', ['terminal_receipt_sha256','execution_plan_sha256','execution_plan_id','evidence_sha256'])
def test_forged_provenance_blocks_without_resolution(tmp_path, field):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    terminal[field]='forged'
    with pytest.raises(ControlError): build(service,terminal).plan(RUN,GUID)
    assert not (tmp_path/'setup-recovery-resolutions').exists()
    assert calls == []

@pytest.mark.parametrize('label',['plan','run','index','configuration_result','binding'])
def test_original_history_drift_after_plan_cannot_execute(tmp_path,label):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    plan=build(service,terminal).plan(RUN,GUID)
    # Semantically equivalent but byte-different evidence must still fail.
    paths[label].write_bytes(paths[label].read_bytes()+b' ')
    with pytest.raises(ControlError): service.apply(plan['plan_id'],plan['sha256'])
    assert calls == []

def test_repeated_plan_reuses_immutable_resolution_without_replay(tmp_path):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    continuation=build(service,terminal)
    first=continuation.plan(RUN,GUID)
    terminal['finished_at']=(NOW+timedelta(seconds=30)).isoformat()
    assert continuation.plan(RUN,GUID)==first
    terminal['terminal_receipt_sha256']='c'*64
    with pytest.raises(ControlError): continuation.plan(RUN,GUID)
    assert calls == []

def test_normal_setup_pipeline_restart_does_not_reuse_old_terminal_invocation(tmp_path):
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    continuation=build(service,terminal)
    plan=continuation.plan(RUN,GUID)
    original_start=service.planner.start
    def configure(*args,**kwargs):
        result=original_start(*args,**kwargs)
        # A legitimate ordinary pipeline restart retires the old terminal
        # invocation. Re-verifying that invocation after dispatch must fail.
        terminal['status']='retired_invocation'
        return result
    service.planner.start=configure
    result=service.apply(plan['plan_id'],plan['sha256'])
    assert result['status']=='successful'
    assert service.assignments.get(UUID)['revision']==2
    assert service.verify(UUID)['status']=='successful'
    assert len(calls)==1

def test_terminal_callback_uses_caller_owned_flock_without_nested_acquire(tmp_path):
    import fcntl
    service, paths, user, observed, computer, calls, terminal = scenario(tmp_path)
    from alt_deploy.setup_recovery_continuation import RecoveryContinuationService
    operations=[]
    class RetainedTerminal:
        def _operate(self,action,plan_id,sha):
            # A separate open file description cannot acquire the lifecycle
            # lock while continuation plan/apply owns it.
            with service.settings.lock_file.open('r+') as stream:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            operations.append((action,plan_id,sha))
            return copy.deepcopy(terminal)
    runtime=RetainedTerminal()
    def verify_locked(**pair):
        assert pair=={'failed_run_id':RUN,'computer_guid':GUID}
        # Matches the production trusted lock-held terminal adapter: invoke
        # retained verification internally, without TerminalRuntime.verify's
        # second exclusive_lock acquisition.
        return runtime._operate('verify','recovery-'+'b'*64,'b'*64)
    continuation=RecoveryContinuationService(service.settings,setup=service,terminal_verifier=verify_locked)
    plan=continuation.plan(RUN,GUID)
    result=service.apply(plan['plan_id'],plan['sha256'])
    assert result['status']=='successful'
    assert len(operations)==3
    assert all(item==('verify','recovery-'+'b'*64,'b'*64) for item in operations)
