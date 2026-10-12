from __future__ import annotations
import copy
from types import SimpleNamespace
import pytest
from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import private_read,private_create,digest
from test_setup_recovery_prepare import scenario as prepare_scenario

STAGES=['bind','prepare','services_prepare','quiesce','password_write','import','kerberos','policy','startup','native','user','terminal']

def scenario(root,monkeypatch,*,failure=None):
    from alt_deploy.setup_recovery_execution import RecoveryExecutionCoordinator
    preparation,planning,plan,*_=prepare_scenario(root)
    coordinator=RecoveryExecutionCoordinator(planning,startup_plan_id='recovery-startup-'+'b'*64,
        confirmed_startup_sha='b'*64,terminal_authorization=lambda *args:{},identity=lambda *args:{},operator_guard=lambda:None)
    coordinator.fingerprint=lambda:plan['payload']['snapshot']['prerequisites']['source_sha256']
    # Preserve real protected credential preparation and its read-only gate.
    coordinator.preparation=preparation
    coordinator.services.preparation=preparation.gate
    coordinator.services.runtime.credentials=preparation.credentials
    calls=[]
    def stage(name,result=None):
        def run(*args):
            calls.append(name)
            if name==failure:raise RuntimeError('SYNTHETIC_SECRET')
            if name in ('services_prepare','quiesce'):
                assert args[3]==preparation.credentials.open(**{key:plan['payload'][key] for key in ('failed_run_id','computer_guid')})
                assert args[2]['claim_sha256']==digest(args[1])
            return result or {'status':name}
        return run
    original_prepare=preparation.prepare
    def prepare(*args):
        calls.append('prepare')
        if failure=='prepare':raise RuntimeError('SYNTHETIC_SECRET')
        return original_prepare(*args)
    preparation.prepare=prepare
    coordinator.startup_authorization.bind_once=stage('bind')
    coordinator.services.prepare=stage('services_prepare')
    coordinator.services.quiesce=stage('quiesce')
    coordinator.provider.write_once=stage('password_write')
    coordinator.importer.install_once=stage('import')
    coordinator.kerberos.prove_once=stage('kerberos')
    coordinator.policy.install_once=stage('policy')
    coordinator.startup.start_once=stage('startup')
    coordinator.native.testjoin_once=stage('native')
    coordinator.user.check_once=stage('user')
    receipt={'schema_version':1,'status':'normal_policy_handoff_succeeded','synthetic_receipt':'private-only'}
    coordinator.terminal.handoff_once=stage('terminal',receipt)
    return coordinator,planning,plan,calls,receipt

def test_factory_composes_genuine_shared_authority_and_credential_chain(tmp_path):
    from alt_deploy.setup_recovery_execution import RecoveryExecutionCoordinator
    _,planning,plan,*_=prepare_scenario(tmp_path)
    authority=lambda *args:{};identity=lambda *args:{}
    coordinator=RecoveryExecutionCoordinator(planning,startup_plan_id='startup',confirmed_startup_sha='b'*64,
        terminal_authorization=authority,identity=identity,operator_guard=lambda:None)
    assert coordinator.preparation.planning is planning
    assert coordinator.services.preparation is coordinator.preparation.gate
    assert coordinator.services.runtime.credentials is coordinator.preparation.credentials
    assert coordinator.provider.credentials is coordinator.preparation.credentials
    assert coordinator.provider.directory is planning.directory
    assert coordinator.provider.fresh_check is coordinator.preparation.fresh_check
    assert coordinator.provider.prewrite is coordinator.services
    assert coordinator.importer.postwrite is coordinator.postwrite
    assert coordinator.postwrite.service_gate is coordinator.services
    assert coordinator.postwrite.fingerprint is coordinator.provider.fingerprint
    assert coordinator.startup.authorization is coordinator.startup_authorization
    assert coordinator.native.authorization.startup_runtime is coordinator.startup
    assert coordinator.user.authorization.native_runtime is coordinator.native
    assert coordinator.terminal.user_runtime is coordinator.user
    assert coordinator.terminal.authorization is authority and coordinator.terminal.identity is identity
    assert not (tmp_path/'setup-recovery-attempts').exists()

def test_execution_exact_order_returns_terminal_receipt_and_never_replays(tmp_path,monkeypatch):
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch)
    result=coordinator.execute(plan['plan_id'],plan['sha256'])
    assert result==receipt and calls==STAGES
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==STAGES

@pytest.mark.parametrize('failure',STAGES)
def test_stage_failure_excludes_every_later_stage_and_replay(tmp_path,monkeypatch,failure):
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch,failure=failure)
    with pytest.raises(ControlError) as caught:coordinator.execute(plan['plan_id'],plan['sha256'])
    assert 'SYNTHETIC_SECRET' not in str(caught.value)
    expected=STAGES[:STAGES.index(failure)+1]
    assert calls==expected
    status=coordinator.status(plan['payload']['failed_run_id'],plan['payload']['computer_guid'])
    assert status['failed_stage']==failure
    assert status['last_verified_phase']==(STAGES[STAGES.index(failure)-1] if STAGES.index(failure) else 'not_started')
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==expected

def test_invalid_authority_refuses_factory_before_execution(tmp_path):
    from alt_deploy.setup_recovery_execution import RecoveryExecutionCoordinator
    _,planning,*_=prepare_scenario(tmp_path)
    with pytest.raises(ValueError):RecoveryExecutionCoordinator(planning,startup_plan_id='startup',confirmed_startup_sha='a'*64,
        terminal_authorization=None,identity=lambda *args:{},operator_guard=lambda:None)

def test_source_drift_after_quiescence_blocks_password_write(tmp_path,monkeypatch):
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch)
    original=coordinator.services.quiesce
    def quiesce(*args):
        result=original(*args)
        coordinator.fingerprint=lambda:'f'*64
        return result
    coordinator.services.quiesce=quiesce
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==STAGES[:4]
    status=coordinator.status(plan['payload']['failed_run_id'],plan['payload']['computer_guid'])
    assert status['last_verified_phase']=='quiesce' and status['failed_stage']=='password_write'

@pytest.mark.parametrize('changed',['ready','document','history'])
def test_shadow_credential_or_history_drift_blocks_service_action(tmp_path,monkeypatch,changed):
    from alt_deploy.setup_plans import private_replace
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch)
    original=coordinator.preparation.prepare
    pair={key:plan['payload'][key] for key in ('failed_run_id','computer_guid')}
    def prepare(*args):
        result=original(*args)
        credentials=coordinator.preparation.credentials
        if changed=='ready':private_replace(credentials._ready_path(**pair),{'schema_version':1})
        elif changed=='document':private_replace(credentials.path(**pair),{'schema_version':1})
        else:
            path=planning.settings.state_root/'setup-runs'/(pair['failed_run_id']+'.json')
            path.write_bytes(path.read_bytes()+b' ')
        return result
    coordinator.preparation.prepare=prepare
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==['bind','prepare']
    assert coordinator.status(**pair)['failed_stage']=='services_prepare'


def test_phase_storage_failure_excludes_replay_without_cleanup(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch)
    original=RecoveryControllerBackup._persist
    def persist(path,payload):
        if str(path).endswith('.execution-coordinator-phase-quiesce.json'):raise OSError('private fixture disk failure')
        return original(path,payload)
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(persist))
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==STAGES[:4]
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==STAGES[:4]
    assert coordinator.status(plan['payload']['failed_run_id'],plan['payload']['computer_guid'])['last_verified_phase']=='services_prepare'


def test_last_current_plan_load_after_terminal_must_pass(tmp_path,monkeypatch):
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch)
    original=coordinator.terminal.handoff_once
    def terminal(*args):
        result=original(*args)
        planning.plans.load=lambda *args: (_ for _ in ()).throw(ValueError('expired'))
        return result
    coordinator.terminal.handoff_once=terminal
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==STAGES
    assert coordinator.status(plan['payload']['failed_run_id'],plan['payload']['computer_guid'])['last_verified_phase']=='terminal'


def test_operator_revocation_after_execution_intent_blocks_binding_and_reservation(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch)
    revoked=False
    def guard():
        if revoked:raise ValueError('Revoked protected operator intent')
    coordinator.operator_guard=guard
    original=RecoveryControllerBackup._persist
    def persist(path,document):
        nonlocal revoked
        result=original(path,document)
        if str(path).endswith('.execution-coordinator-intent.json'):revoked=True
        return result
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(persist))
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert calls==[]
    pair={key:plan['payload'][key] for key in ('failed_run_id','computer_guid')}
    assert not planning.attempts.claim_path(**pair).exists()


def test_operator_revocation_at_provider_dispatch_blocks_ldap_runner(tmp_path,monkeypatch):
    coordinator,planning,plan,calls,receipt=scenario(tmp_path,monkeypatch)
    actual=[];revoked=False
    def guard():
        if revoked:raise ValueError('Revoked protected operator intent')
    coordinator.operator_guard=guard
    protected=coordinator._guarded_runner(lambda *args,**kwargs: actual.append(args))
    def provider(*args):
        nonlocal revoked
        revoked=True
        with __import__('alt_deploy.locking',fromlist=['exclusive_lock']).exclusive_lock(coordinator.settings.lock_file):
            return protected(['/usr/bin/ldapmodify'],environment={},input_text='fixture-only',timeout=30)
    coordinator.provider.write_once=provider
    with pytest.raises(ControlError):coordinator.execute(plan['plan_id'],plan['sha256'])
    assert actual==[] and calls==STAGES[:4]


def test_missing_operator_guard_is_rejected_by_production_factory(tmp_path):
    from alt_deploy.setup_recovery_execution import RecoveryExecutionCoordinator
    _,planning,*_=prepare_scenario(tmp_path)
    with pytest.raises((TypeError,ValueError)):
        RecoveryExecutionCoordinator(planning,startup_plan_id='startup',confirmed_startup_sha='a'*64,
            terminal_authorization=lambda *args:{},identity=lambda *args:{})
