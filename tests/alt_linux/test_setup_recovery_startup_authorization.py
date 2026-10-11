from __future__ import annotations

import copy
from datetime import timedelta
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest,private_read,private_replace
from test_setup_recovery_prepare import scenario as preparation_fixture
from test_setup_recovery_sssd_start import scenario as startup_fixture


def ledger_fixture(unit):
    return dict(schema_version=1,operation='fixed_sssd_start_once',systemd_package='systemd 258.9-alt1',
        controller_start=['/usr/bin/systemctl','start','sssd.service','--job-mode=ignore-requirements'],
        inventory_sha256='a'*64,unit_sha256=digest(unit),
        automatic_restart='stock_on_abnormal_with_temporary_sssd_policy',
        dependency_effects='conservative_inventory_not_transaction_prediction',
        manager_interference='observed_without_exclusive_manager_lease',
        temporary_policy='retained_until_separate_verified_restoration',
        reviewed_effects=[dict(unit='sssd.service',trigger='fixed_controller_start',
            effect='Stock SSSD launches with the temporary recovery policy.',source_sha256='b'*64)],
        unresolved_effects=['Other manager clients can act between observations.'])


def scenario(root):
    from alt_deploy.setup_recovery_startup_authorization import RecoveryStartupPlans,RecoveryStartupAuthorization
    preparation,planning,recovery,paths,_,_=preparation_fixture(root/'controller')
    _,request,_,_,_=startup_fixture(root/'workstation')
    unit=request['sssd_unit'];ledger=ledger_fixture(unit)
    plans=RecoveryStartupPlans(planning,fingerprint=lambda:recovery['payload']['snapshot']['prerequisites']['source_sha256'])
    attachment=plans.create(recovery['plan_id'],recovery['sha256'],sssd_unit=unit,effects_ledger=ledger)
    protected=dict(payload=copy.deepcopy(recovery['payload']),claim=dict(plan_id=recovery['plan_id'],plan_sha256=recovery['sha256']))
    postwrite=SimpleNamespace(load=lambda *a:dict(copy.deepcopy(protected),machine=SimpleNamespace()))
    gate=RecoveryStartupAuthorization(preparation=preparation,postwrite=postwrite,
        startup_plan_id=attachment['plan_id'],confirmed_startup_sha=attachment['sha256'],plans=plans)
    return gate,plans,preparation,planning,recovery,attachment,paths,ledger,unit,protected


def reserve(gate,recovery,protected):
    raw=gate.preparation.planning.history.load(recovery['payload']['failed_run_id'])['raw_files']
    protected['claim']=gate.preparation.attempts.reserve(recovery['plan_id'],recovery['sha256'],raw)


def test_confirmed_pair_is_bound_before_reservation_and_readonly_gate_returns_exact_attachment(tmp_path):
    gate,plans,preparation,planning,recovery,attachment,paths,ledger,unit,protected=scenario(tmp_path)
    before={key:path.read_bytes() for key,path in paths.items()}
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))
    binding=gate.bind_once(recovery['plan_id'],recovery['sha256'])
    assert not preparation.attempts.claim_path(**gate._pair(recovery)).exists()
    reserve(gate,recovery,protected)
    result=gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))
    assert result==dict(schema_version=1,plan_id=recovery['plan_id'],plan_sha256=recovery['sha256'],
        source_sha256=digest(plans._sources()),sssd_unit=unit,effects_ledger_sha256=digest(ledger),approval_sha256=attachment['sha256'])
    result['sssd_unit']['properties']['MainPID']='999'
    assert gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))['sssd_unit']==unit
    assert private_read(gate.binding_path(recovery))==binding
    assert {key:path.read_bytes() for key,path in paths.items()}==before
    with pytest.raises(ControlError):gate.bind_once(recovery['plan_id'],recovery['sha256'])


@pytest.mark.parametrize('change',['schema','extra','unit','unit_oversized','ledger_extra','ledger_schema',
    'ledger_operation','ledger_hash','ledger_restart','ledger_effects_empty','ledger_effects_extra',
    'ledger_notes_size','ledger_nan','recovery_nonexecutable','source'])
def test_invalid_attachment_inputs_fail_before_plan_or_binding(tmp_path,change,monkeypatch):
    gate,plans,_,_,recovery,attachment,_,ledger,unit,_=scenario(tmp_path)
    before=set(plans.store.root.iterdir())
    if change=='schema':ledger['schema_version']=True
    elif change=='extra':unit['extra']='SYNTHETIC_SECRET'
    elif change=='unit':unit['properties']['Restart']='always'
    elif change=='unit_oversized':unit['properties']['Environment']='x'*131073
    elif change=='ledger_extra':ledger['command']='restart'
    elif change=='ledger_schema':ledger['schema_version']='1'
    elif change=='ledger_operation':ledger['controller_start'][1]='restart'
    elif change=='ledger_hash':ledger['unit_sha256']='0'*64
    elif change=='ledger_restart':ledger['automatic_restart']='no_restart_possible'
    elif change=='ledger_effects_empty':ledger['reviewed_effects']=[]
    elif change=='ledger_effects_extra':ledger['reviewed_effects'][0]['command']='anything'
    elif change=='ledger_notes_size':ledger['unresolved_effects']=['x'*4097]
    elif change=='ledger_nan':ledger['reviewed_effects'][0]['effect']=float('nan')
    elif change=='recovery_nonexecutable':
        payload=copy.deepcopy(recovery['payload']);payload['execution_available']=False
        recovery=plans.planning.plans.create(payload)
    else:monkeypatch.setattr(plans,'_sources',lambda:['changed']*11)
    with pytest.raises(ControlError):plans.create(recovery['plan_id'],recovery['sha256'],sssd_unit=unit,effects_ledger=ledger)
    assert set(plans.store.root.iterdir())==before
    assert not gate.binding_path(recovery).exists()


@pytest.mark.parametrize('change',['startup_sha','startup_prefix','recovery_sha','input_sources','binding',
    'history','registry','fingerprint','source','startup_expired','recovery_expired','protected_payload','protected_claim'])
def test_changed_approved_inputs_never_return_authorization(tmp_path,change,monkeypatch):
    gate,plans,_,planning,recovery,attachment,paths,_,_,protected=scenario(tmp_path)
    gate.bind_once(recovery['plan_id'],recovery['sha256']);source_sha=digest(plans._sources())
    reserve(gate,recovery,protected)
    if change=='startup_sha':gate.confirmed_startup_sha='0'*64
    elif change=='startup_prefix':gate.startup_plan_id='setup-'+attachment['sha256']
    elif change=='recovery_sha':recovery['sha256']='0'*64
    elif change=='input_sources':source_sha='0'*64
    elif change=='binding':private_replace(gate.binding_path(recovery),{'schema_version':True})
    elif change=='history':
        value=private_read(paths['run']);value['reboot_required']=False;private_replace(paths['run'],value)
    elif change=='registry':planning.machines.resolve('ignored').raw['changed']=True
    elif change=='fingerprint':plans.fingerprint=lambda:'0'*64
    elif change=='source':monkeypatch.setattr(plans,'_sources',lambda:['changed']*12)
    elif change=='startup_expired':plans.store.clock=lambda:planning.clock()+timedelta(hours=1)
    elif change=='recovery_expired':planning.plans.clock=lambda:planning.clock()+timedelta(hours=1)
    elif change=='protected_payload':protected['payload']['computer_sid']='S-1-5-21-1-2-3-999'
    else:protected['claim']['plan_sha256']='0'*64
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],source_sha)


def test_reserved_attempt_cannot_bind_a_replacement_attachment(tmp_path):
    gate,plans,preparation,planning,recovery,_,_,ledger,unit,_=scenario(tmp_path)
    raw=planning.history.load(recovery['payload']['failed_run_id'])['raw_files']
    preparation.attempts.reserve(recovery['plan_id'],recovery['sha256'],raw)
    with pytest.raises(ControlError):gate.bind_once(recovery['plan_id'],recovery['sha256'])
    with pytest.raises(ControlError):plans.create(recovery['plan_id'],recovery['sha256'],sssd_unit=unit,effects_ledger=ledger)


def test_last_source_callback_history_drift_refuses_authorization(tmp_path,monkeypatch):
    gate,plans,_,_,recovery,_,paths,_,_,protected=scenario(tmp_path)
    gate.bind_once(recovery['plan_id'],recovery['sha256']);source_sha=digest(plans._sources())
    reserve(gate,recovery,protected)
    original=plans._sources;calls=[]
    def changed():
        value=original();calls.append(True)
        if len(calls)==2:
            record=private_read(paths['run']);record['reboot_required']=False;private_replace(paths['run'],record)
        return value
    monkeypatch.setattr(plans,'_sources',changed)
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],source_sha)


def test_duplicate_binding_fields_are_refused(tmp_path):
    gate,plans,_,_,recovery,_,_,_,_,protected=scenario(tmp_path)
    gate.bind_once(recovery['plan_id'],recovery['sha256']);path=gate.binding_path(recovery)
    reserve(gate,recovery,protected)
    raw=path.read_bytes().rstrip();path.write_bytes(raw[:-1]+b',"schema_version":1}\n')
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))


@pytest.mark.parametrize('failure',['binding_sync','ready_sync','history_after_binding','history_after_ready'])
def test_failed_binding_persistence_never_becomes_authorization(tmp_path,monkeypatch,failure):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    gate,plans,preparation,planning,recovery,_,paths,_,_,protected=scenario(tmp_path)
    original={key:path.read_bytes() for key,path in paths.items()}
    persist=RecoveryControllerBackup._persist
    def interrupted(path,value):
        persist(path,value)
        is_binding=path.name.endswith('.execution-approval.json')
        is_ready=path.name.endswith('.execution-approval-ready.json')
        if (failure=='binding_sync' and is_binding) or (failure=='ready_sync' and is_ready):raise OSError('SYNTHETIC_SECRET')
        if (failure=='history_after_binding' and is_binding) or (failure=='history_after_ready' and is_ready):
            record=private_read(paths['run']);record['reboot_required']=False;private_replace(paths['run'],record)
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(interrupted))
    with pytest.raises(ControlError):gate.bind_once(recovery['plan_id'],recovery['sha256'])
    for label,path in paths.items():path.write_bytes(original[label])
    raw=planning.history.load(recovery['payload']['failed_run_id'])['raw_files']
    protected['claim']=preparation.attempts.reserve(recovery['plan_id'],recovery['sha256'],raw)
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))


def test_unreserved_context_cannot_authorize_even_with_a_binding(tmp_path):
    gate,plans,_,_,recovery,_,_,_,_,_=scenario(tmp_path)
    gate.bind_once(recovery['plan_id'],recovery['sha256'])
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))


def test_postready_failure_is_excluded_before_lifecycle_lock_release(tmp_path,monkeypatch):
    from contextlib import contextmanager
    from alt_deploy import setup_recovery_startup_authorization as module
    gate,_,_,_,recovery,_,paths,_,_,_=scenario(tmp_path)
    persist=module.RecoveryControllerBackup._persist;lock=module.exclusive_lock;released=[]
    def changed(path,value):
        persist(path,value)
        if path.name.endswith('.execution-approval-ready.json'):
            record=private_read(paths['run']);record['reboot_required']=False;private_replace(paths['run'],record)
    @contextmanager
    def observed(path):
        with lock(path):
            try:yield
            finally:released.append(gate._marker(recovery,'failed').is_file())
    monkeypatch.setattr(module.RecoveryControllerBackup,'_persist',staticmethod(changed))
    monkeypatch.setattr(module,'exclusive_lock',observed)
    with pytest.raises(ControlError):gate.bind_once(recovery['plan_id'],recovery['sha256'])
    assert released==[True]


def test_failed_marker_storage_error_revokes_exact_ready_without_losing_evidence(tmp_path,monkeypatch):
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    gate,plans,_,_,recovery,_,paths,_,_,protected=scenario(tmp_path)
    persist=RecoveryControllerBackup._persist;original={key:path.read_bytes() for key,path in paths.items()};ready_bytes=[]
    def broken(path,value):
        if path.name.endswith('.execution-approval-failed.json'):raise OSError('SYNTHETIC_QUOTA')
        persist(path,value)
        if path.name.endswith('.execution-approval-ready.json'):
            ready_bytes.append(path.read_bytes())
            record=private_read(paths['run']);record['reboot_required']=False;private_replace(paths['run'],record)
    monkeypatch.setattr(RecoveryControllerBackup,'_persist',staticmethod(broken))
    with pytest.raises(ControlError):gate.bind_once(recovery['plan_id'],recovery['sha256'])
    for label,path in paths.items():path.write_bytes(original[label])
    reserve(gate,recovery,protected)
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))
    assert gate._marker(recovery,'revoked').read_bytes()==ready_bytes[0]
    assert not gate._marker(recovery,'ready').exists()
    assert gate.binding_path(recovery).is_file()
    from alt_deploy.setup_recovery_startup_authorization import RecoveryStartupAuthorization
    reloaded=RecoveryStartupAuthorization(preparation=gate.preparation,postwrite=gate.postwrite,
        startup_plan_id=gate.startup_plan_id,confirmed_startup_sha=gate.confirmed_startup_sha,plans=plans)
    with pytest.raises(ControlError):reloaded(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))


@pytest.mark.parametrize('failure',['failed_sync','revoked_sync','rename'])
def test_unconfirmed_exclusion_durability_requires_manual_recovery(tmp_path,monkeypatch,failure):
    from alt_deploy import setup_recovery_startup_authorization as module
    from pathlib import Path
    gate,plans,_,_,recovery,_,paths,_,_,_=scenario(tmp_path)
    persist=module.RecoveryControllerBackup._persist;sync=module._sync_directory;rename=Path.rename
    excluding=[]
    def broken(path,value):
        if path.name.endswith('.execution-approval-failed.json'):
            if failure=='failed_sync':persist(path,value)
            excluding.append(True);raise OSError('SYNTHETIC_QUOTA')
        persist(path,value)
        if path.name.endswith('.execution-approval-ready.json'):
            record=private_read(paths['run']);record['reboot_required']=False;private_replace(paths['run'],record)
    def broken_sync(path):
        if excluding and failure in ('failed_sync','revoked_sync'):raise OSError('SYNTHETIC_SYNC')
        return sync(path)
    def broken_rename(path,target):
        if failure=='rename' and path.name.endswith('.execution-approval-ready.json'):raise OSError('SYNTHETIC_RENAME')
        return rename(path,target)
    monkeypatch.setattr(module.RecoveryControllerBackup,'_persist',staticmethod(broken))
    monkeypatch.setattr(module,'_sync_directory',broken_sync)
    monkeypatch.setattr(Path,'rename',broken_rename)
    with pytest.raises(ControlError) as error:gate.bind_once(recovery['plan_id'],recovery['sha256'])
    assert error.value.code=='recovery_startup_approval_ambiguous'
    assert 'SYNTHETIC_' not in str(error.value)
    with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))


@pytest.mark.parametrize('changed',['none','kvno','guid','sid','ou','terminal'])
@pytest.mark.parametrize('native_check',[False,True])
def test_genuine_postwrite_continuity_accepts_only_the_recorded_password_version(tmp_path,changed,native_check):
    from test_setup_recovery_postwrite import written
    from alt_deploy.setup_recovery_startup_authorization import RecoveryStartupPlans,RecoveryStartupAuthorization
    from alt_deploy.setup_recovery_controller_backup import RecoveryControllerBackup
    state,service_gate,args,_,_,computer,paths=written(tmp_path/'controller')
    planning=service_gate.preparation.controller.fresh_check.planning
    preparation=SimpleNamespace(planning=planning,settings=planning.settings,attempts=planning.attempts)
    plans=RecoveryStartupPlans(planning,fingerprint=state.fingerprint)
    recovery=planning.plans.load(args[1]['plan_id'],args[1]['plan_sha256'])
    _,request,_,_,_=startup_fixture(tmp_path/'workstation')
    unit=request['sssd_unit'];ledger=ledger_fixture(unit);base=plans._base(recovery['plan_id'],recovery['sha256'])
    # This fixture represents a retained pre-write approval. It installs only
    # private fixture records, since the genuine postwrite fixture is reserved.
    # bind_once's pre-reservation path is covered independently above.
    attachment_payload=dict(schema_version=1,scope='one_fixed_sssd_start_with_retained_temporary_policy',
        recovery_plan_id=recovery['plan_id'],recovery_plan_sha256=recovery['sha256'],
        recovery_payload_sha256=digest(recovery['payload']),identity=base['identity'],source_sha256=base['source_sha256'],
        sssd_unit=unit,effects_ledger=ledger)
    if native_check:
        attachment_payload['scope']='one_fixed_sssd_start_and_native_check_with_retained_temporary_policy'
        attachment_payload['native_check']=plans._native_scope(base)
    attachment=plans.store.create(attachment_payload)
    gate=RecoveryStartupAuthorization(preparation=preparation,postwrite=state,startup_plan_id=attachment['plan_id'],
        confirmed_startup_sha=attachment['sha256'],plans=plans)
    expected=gate._expected(gate._load(recovery['plan_id'],recovery['sha256']))
    RecoveryControllerBackup._persist(gate.binding_path(recovery),expected)
    RecoveryControllerBackup._persist(gate._marker(recovery,'ready'),dict(schema_version=1,status='approval_bound',binding_sha256=digest(expected)))
    original={key:path.read_bytes() for key,path in paths.items()}
    service_gate.preparation.credentials.open=lambda **kw:pytest.fail('Authorization opened Vault')
    if changed=='kvno':computer['kvno']+=1
    elif changed=='guid':computer['object_guid']='00000000-0000-0000-0000-000000000001'
    elif changed=='sid':computer['object_sid']='S-1-5-21-1-2-3-999'
    elif changed=='ou':computer['dn']='CN=alt-a1-pc3,OU=Other,DC=sosnadmin,DC=local'
    elif changed=='terminal':
        planning.attempts.finish(recovery['payload']['failed_run_id'],recovery['payload']['computer_guid'],
            status='failed',error_code='synthetic_failure')
    if changed=='none':
        approved=gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))
        assert approved['approval_sha256']==attachment['sha256']
    else:
        with pytest.raises(ControlError):gate(recovery['plan_id'],recovery['sha256'],digest(plans._sources()))
    assert {key:path.read_bytes() for key,path in paths.items()}==original
